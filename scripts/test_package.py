#!/usr/bin/env python3
"""Archive security and reproducibility regression tests (stdlib only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
import subprocess

SPEC = importlib.util.spec_from_file_location("fsu_package", Path(__file__).with_name("package.py"))
assert SPEC and SPEC.loader
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PackageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="fsu-package-test-")
        self.original_root = PACKAGE.ROOT
        PACKAGE.ROOT = Path(self.temporary.name)

    def tearDown(self) -> None:
        PACKAGE.ROOT = self.original_root
        self.temporary.cleanup()

    def test_archive_is_deterministic_and_scoped(self) -> None:
        first = Path(self.temporary.name) / "first.zip"
        second = Path(self.temporary.name) / "second.zip"
        files = {"src/Example.php": b"<?php // fixture\n", "assets/admin.css": b"body {}\n"}
        metadata = {"channel": "dev", "stable": False}
        report = PACKAGE.archive(first, files, metadata, 1762214400)
        PACKAGE.archive(second, dict(reversed(list(files.items()))), metadata, 1762214400)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(3, len(report["entries"]))
        with zipfile.ZipFile(first) as archive:
            self.assertIsNone(archive.testzip())
            self.assertTrue(all(name.startswith("fortress-security-ultimate/") for name in archive.namelist()))
            self.assertIn(b'"stable": false', archive.read("fortress-security-ultimate/build-info.json"))

    def test_root_symlink_cannot_escape_whitelist(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "data.php").write_text("private")
        (Path(self.temporary.name) / "src").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlinked"):
            PACKAGE.gather(("src",))

    def test_broken_optional_root_symlink_is_rejected(self) -> None:
        (Path(self.temporary.name) / "languages").symlink_to(Path(self.temporary.name) / "missing", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlinked"):
            PACKAGE.gather(("languages",))

    def test_nested_symlink_is_rejected(self) -> None:
        source = Path(self.temporary.name) / "src"
        source.mkdir()
        (source / "Example.php").symlink_to(Path(self.temporary.name) / "missing")
        with self.assertRaisesRegex(ValueError, "Symlinks"):
            PACKAGE.gather(("src",))

    def test_secret_file_is_rejected(self) -> None:
        source = Path(self.temporary.name) / "src"
        source.mkdir()
        (source / "token.php").write_text("sk_" + "test_" + "A" * 20)
        with self.assertRaisesRegex(ValueError, "Potential secret"):
            PACKAGE.gather(("src",))

    def test_environment_file_is_rejected(self) -> None:
        source = Path(self.temporary.name) / "src"
        source.mkdir()
        (source / ".env.production").write_text("API_TOKEN=example")
        with self.assertRaisesRegex(ValueError, "Private or generated"):
            PACKAGE.gather(("src",))

    def test_missing_required_entry_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Required runtime file"):
            PACKAGE.gather(("fortress-security-ultimate.php",))

    def fixture_commit(self) -> str:
        subprocess.run(["git", "init", "-q", "-b", "main", self.temporary.name], check=True)
        subprocess.run(["git", "-C", self.temporary.name, "config", "user.name", "FSU test fixture"], check=True)
        subprocess.run(["git", "-C", self.temporary.name, "config", "user.email", "ci@example.invalid"], check=True)
        source = Path(self.temporary.name) / "src"
        source.mkdir()
        (source / "Example.php").write_text("<?php // committed fixture\n")
        (Path(self.temporary.name) / ".gitignore").write_text("src/ignored.php\n")
        subprocess.run(["git", "-C", self.temporary.name, "add", "."], check=True)
        subprocess.run(["git", "-C", self.temporary.name, "commit", "-q", "-m", "fixture"], check=True)
        return PACKAGE.git("rev-parse", "HEAD")

    def test_release_snapshot_matches_committed_bytes(self) -> None:
        commit = self.fixture_commit()
        self.assertEqual((commit, False), PACKAGE.validate_revision(commit, True))
        PACKAGE.verify_snapshot(PACKAGE.gather(("src",)), ("src",), commit)

    def test_release_rejects_dirty_tree(self) -> None:
        commit = self.fixture_commit()
        (Path(self.temporary.name) / "src" / "Example.php").write_text("changed")
        with self.assertRaisesRegex(ValueError, "clean Git"):
            PACKAGE.validate_revision(commit, True)

    def test_release_rejects_wrong_commit(self) -> None:
        self.fixture_commit()
        with self.assertRaisesRegex(ValueError, "expected full Git commit"):
            PACKAGE.validate_revision("0" * 40, True)

    def test_release_rejects_ignored_untracked_package_file(self) -> None:
        commit = self.fixture_commit()
        (Path(self.temporary.name) / "src" / "ignored.php").write_text("<?php // ignored fixture")
        self.assertEqual((commit, False), PACKAGE.validate_revision(commit, True))
        with self.assertRaisesRegex(ValueError, "whitelist differs"):
            PACKAGE.verify_snapshot(PACKAGE.gather(("src",)), ("src",), commit)

    def test_release_rejects_index_hidden_modifications(self) -> None:
        commit = self.fixture_commit()
        subprocess.run(["git", "-C", self.temporary.name, "update-index", "--assume-unchanged", "src/Example.php"], check=True)
        (Path(self.temporary.name) / "src" / "Example.php").write_text("changed but status hidden")
        self.assertEqual((commit, False), PACKAGE.validate_revision(commit, True))
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            PACKAGE.verify_snapshot(PACKAGE.gather(("src",)), ("src",), commit)

    def test_release_rejects_index_hidden_deletion(self) -> None:
        commit = self.fixture_commit()
        subprocess.run(["git", "-C", self.temporary.name, "update-index", "--skip-worktree", "src/Example.php"], check=True)
        (Path(self.temporary.name) / "src" / "Example.php").unlink()
        self.assertEqual((commit, False), PACKAGE.validate_revision(commit, True))
        with self.assertRaisesRegex(ValueError, "whitelist differs"):
            PACKAGE.verify_snapshot(PACKAGE.gather(("src",)), ("src",), commit)


if __name__ == "__main__":
    unittest.main()
