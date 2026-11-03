#!/usr/bin/env python3
"""Produce inspectable, reproducible development archives using only stdlib.

This does not sign, publish or claim that a development package is stable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile

SLUG = "fortress-security-ultimate"
ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOTS = (f"{SLUG}.php", "src", "assets", "languages", "readme.txt", "LICENSE", "CHANGELOG.md")
SOURCE_ROOTS = RUNTIME_ROOTS + (
    "README.md", "SECURITY.md", "composer.json", "composer.lock", "phpunit.xml.dist",
    "phpstan.neon.dist", "phpcs.xml.dist", ".gitignore", ".gitattributes",
    "docs", "tests", "scripts", ".github",
)
FORBIDDEN = {".env", "vendor", "node_modules", ".git", "dist", "logs", "private", ".phpunit.cache", ".phpstan-cache", "__pycache__"}


def git(*arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *arguments], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def gather(roots: tuple[str, ...]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for name in roots:
        base = ROOT / name
        if base.is_symlink():
            raise ValueError(f"Symlinked package root cannot be packaged: {name}")
        if not base.exists():
            if name in {f"{SLUG}.php", "src", "readme.txt", "LICENSE", "CHANGELOG.md"}:
                raise ValueError(f"Required runtime file missing: {name}")
            continue
        candidates = sorted(base.rglob("*")) if base.is_dir() else [base]
        for path in candidates:
            relative = path.relative_to(ROOT)
            if any(part in FORBIDDEN for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"Symlinks cannot be packaged: {relative}")
            if not path.is_file():
                continue
            if path.name.startswith(".env") or path.suffix.lower() in {".pem", ".key", ".log", ".jsonl", ".sqlite", ".zip", ".pyc"}:
                raise ValueError(f"Private or generated file cannot be packaged: {relative}")
            data = path.read_bytes()
            # Detect commonly accidental credentials. This is an additional gate,
            # never a substitute for reviewing staged source and secret scanning.
            if re.search(rb"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", data):
                raise ValueError(f"Potential secret found: {relative}")
            files[relative.as_posix()] = data
    return files


def verify_snapshot(files: dict[str, bytes], roots: tuple[str, ...], commit: str) -> None:
    """Prove every packaged byte and file name belongs to the expected Git commit.

    Git status alone intentionally ignores ignored files, and can be affected by
    index flags. A release must also compare its complete whitelist to Git objects.
    """
    listed = subprocess.run(
        ["git", "-C", str(ROOT), "ls-tree", "-r", "--name-only", "-z", commit, "--", *roots],
        capture_output=True, check=True,
    ).stdout
    tracked = {name.decode("utf-8") for name in listed.split(b"\0") if name}
    if tracked != set(files):
        difference = ", ".join(sorted(tracked.symmetric_difference(files)))
        raise ValueError(f"Package whitelist differs from the committed snapshot: {difference}")
    for name, data in files.items():
        stored = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "blob", f"{commit}:{name}"],
            capture_output=True, check=True,
        ).stdout
        if data != stored:
            raise ValueError(f"Packaged bytes differ from the committed snapshot: {name}")


def validate_revision(expected_commit: str | None, require_clean: bool) -> tuple[str, bool]:
    """Reject mismatched revisions and dirty release working trees."""
    commit = git("rev-parse", "HEAD")
    if expected_commit is not None:
        if re.fullmatch(r"[a-f0-9]{40}", expected_commit) is None or commit != expected_commit:
            raise ValueError("HEAD does not match the expected full Git commit SHA")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    if require_clean and dirty:
        raise ValueError("Release packaging requires a clean Git working tree")
    return commit, dirty


def archive(path: Path, files: dict[str, bytes], metadata: dict[str, object], epoch: int) -> dict[str, object]:
    package_files = dict(files)
    package_files["build-info.json"] = (json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    stamp = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, data in sorted(package_files.items()):
            info = zipfile.ZipInfo(f"{SLUG}/{name}", stamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, data)
    with zipfile.ZipFile(path) as check:
        if check.testzip() is not None:
            raise ValueError(f"ZIP CRC verification failed: {path.name}")
        names = check.namelist()
        if len(set(names)) != len(names) or any(".." in Path(name).parts or name.startswith("/") for name in names):
            raise ValueError("Unsafe archive member")
        entries = {name: hashlib.sha256(check.read(name)).hexdigest() for name in names}
    return {"filename": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "entries": entries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--require-clean", action="store_true", help="Require a clean tree and exact correspondence with committed Git objects")
    parser.add_argument("--expected-commit", help="Require HEAD to match this full 40-character Git commit SHA")
    arguments = parser.parse_args()
    header = (ROOT / f"{SLUG}.php").read_text()
    match = re.search(r"^\s*\*?\s*Version:\s*([^\s]+)", header, re.M)
    if match is None or match.group(1) != "1.0.0-dev":
        raise ValueError("Phase 1 packaging permits only version 1.0.0-dev; release gates are not complete")
    version = match.group(1)
    commit, dirty = validate_revision(arguments.expected_commit, arguments.require_clean)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", git("show", "-s", "--format=%ct", "HEAD")))
    if epoch < 315532800 or epoch > 4354819199:
        raise ValueError("SOURCE_DATE_EPOCH outside ZIP timestamp range")
    metadata = {"product": "Fortress Security Ultimate", "version": version, "channel": "dev", "git_commit": commit, "working_tree_dirty": dirty, "source_date_epoch": epoch, "stable": False}
    arguments.output.mkdir(parents=True, exist_ok=True)
    reports = []
    for kind, roots in (("", RUNTIME_ROOTS), ("-source", SOURCE_ROOTS)):
        destination = arguments.output / f"{SLUG}-{version}{kind}.zip"
        files = gather(roots)
        if arguments.require_clean:
            verify_snapshot(files, roots, commit)
        reports.append(archive(destination, files, metadata, epoch))
    (arguments.output / "SHA256SUMS").write_text("".join(f"{item['sha256']}  {item['filename']}\n" for item in reports))
    (arguments.output / "package-report.json").write_text(json.dumps({"build": metadata, "archives": reports}, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"build": metadata, "archives": [{k: v for k, v in item.items() if k != "entries"} for item in reports]}, indent=2))


if __name__ == "__main__":
    main()
