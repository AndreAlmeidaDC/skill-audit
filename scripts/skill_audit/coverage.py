"""Explicit bounded coverage; no opaque or skipped bytes count as reviewed."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

MAX_PATHS = 10_000
MAX_TOTAL_BYTES = 128_000_000
MAX_HASH_BYTES = 16_000_000
MAX_TEXT_BYTES = 2_000_000
MAX_LINE_CHARS = 8192
ARCHIVES = {".zip", ".jar", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz"}


def is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def collect_coverage(root: Path) -> dict[str, Any]:
    hashes: dict[str, str | None] = {}
    unexamined: list[dict[str, str]] = []
    total = count = 0
    aborted = False
    def skipped(path: str, reason: str) -> None:
        unexamined.append({"path": path, "reason": reason})
    def walk_error(error: OSError) -> None:
        nonlocal aborted
        aborted = True
        skipped("<package>", "directory_read_error")
    for current, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        base = Path(current)
        for name in list(dirs):
            p = base / name
            if name == ".git" or is_link(p):
                skipped(p.relative_to(root).as_posix(), "repository_metadata" if name == ".git" else "link")
                dirs.remove(name)
        count += len(dirs) + len(files)
        if count > MAX_PATHS:
            skipped("<package>", "path_count_limit")
            aborted = True
            break
        for name in sorted(files):
            path = base / name
            rel = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                if is_link(path) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    skipped(rel, "link_or_special_file")
                    continue
                total += info.st_size
                if total > MAX_TOTAL_BYTES:
                    skipped("<package>", "total_size_limit")
                    aborted = True
                    break
                if info.st_size > MAX_HASH_BYTES:
                    hashes[rel] = None
                    skipped(rel, "hash_size_limit")
                    continue
                with path.open("rb") as handle:
                    data = handle.read(MAX_HASH_BYTES + 1)
                if len(data) != info.st_size or path.stat().st_mtime_ns != info.st_mtime_ns:
                    hashes[rel] = None
                    skipped(rel, "changed_during_inventory")
                    continue
                hashes[rel] = hashlib.sha256(data).hexdigest()
                if path.suffix.lower() in ARCHIVES:
                    skipped(rel, "archive_content_not_scanned")
                elif len(data) > MAX_TEXT_BYTES:
                    skipped(rel, "text_size_limit")
                else:
                    try:
                        text = data.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        skipped(rel, "binary_or_invalid_utf8")
                        continue
                    if "\x00" in text:
                        skipped(rel, "binary_or_invalid_utf8")
                    elif any(len(line) > MAX_LINE_CHARS for line in text.splitlines()):
                        skipped(rel, "line_length_limit")
            except OSError:
                hashes[rel] = None
                skipped(rel, "file_read_error")
                aborted = True
        if aborted:
            break
    return {"complete": not unexamined, "inventory_complete": not aborted, "abort_scan": aborted,
            "file_hashes_sha256": hashes, "unexamined": unexamined, "total_bytes_observed": total,
            "limits": {"paths": MAX_PATHS, "total_bytes": MAX_TOTAL_BYTES,
                       "hash_file_bytes": MAX_HASH_BYTES, "text_file_bytes": MAX_TEXT_BYTES,
                       "line_characters": MAX_LINE_CHARS}}
