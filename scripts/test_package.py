#!/usr/bin/env python3
"""Archive security and reproducibility regression tests (stdlib only)."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
import subprocess
import contextlib
import io
from unittest.mock import patch

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

    def fixture_project(self) -> None:
        self.fixture_commit()
        root = Path(self.temporary.name)
        for name, content in {
            "fortress-security-ultimate.php": "<?php\n/*\n * Version: 1.0.0-dev.1\n */\n",
            "readme.txt": "Fixture\n", "LICENSE": "Fixture\n", "CHANGELOG.md": "Fixture\n",
        }.items():
            (root / name).write_text(content)
        (root / ".gitignore").write_text("src/ignored.php\n/dist/\n")
        (root / "docs").mkdir()
        (root / "docs" / "note.md").write_text("Clean fixture\n")
        subprocess.run(["git", "-C", self.temporary.name, "add", "."], check=True)
        subprocess.run(["git", "-C", self.temporary.name, "commit", "-q", "-m", "project fixture"], check=True)

    def build_fixture(self) -> Path:
        destination = Path(self.temporary.name) / "dist"
        with contextlib.redirect_stdout(io.StringIO()):
            PACKAGE.main(["--output", str(destination)])
        return destination

    def test_archive_output_symlink_cannot_overwrite_target(self) -> None:
        root = Path(self.temporary.name)
        victim = root / "victim.txt"
        victim.write_bytes(b"unchanged private fixture")
        destination = root / "package.zip"
        destination.symlink_to(victim)
        with self.assertRaisesRegex(ValueError, "Output paths cannot contain symlinks"):
            PACKAGE.archive(destination, {"src/Example.php": b"fixture"}, {}, 1762214400)
        self.assertEqual(b"unchanged private fixture", victim.read_bytes())
        self.assertTrue(destination.is_symlink())

    def test_archive_output_parent_symlink_is_rejected(self) -> None:
        root = Path(self.temporary.name)
        actual = root / "actual"
        actual.mkdir()
        linked = root / "linked"
        linked.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Output paths cannot contain symlinks"):
            PACKAGE.archive(linked / "package.zip", {"src/Example.php": b"fixture"}, {}, 1762214400)
        self.assertFalse((actual / "package.zip").exists())

    def test_portable_member_names_are_validated_before_creating_zip(self) -> None:
        root = Path(self.temporary.name)
        for name in (r"src\..\..\escaped.php", "../escaped.php", "/absolute.php", "C:/escaped.php", r"\\host\file.php", "src/file.php.", "src/file.php ", "src/CON.php", "src/LPT1.txt", "src/COM¹.txt", "src/LPT².txt", "src/evil:stream", "src/double//file", "src/./file", "src/line\nname"):
            with self.subTest(member=name):
                destination = root / "unsafe.zip"
                with self.assertRaisesRegex(ValueError, "portable archive member"):
                    PACKAGE.archive(destination, {name: b"fixture"}, {}, 1762214400)
                self.assertFalse(destination.exists())

    def test_portable_member_collisions_are_rejected(self) -> None:
        for files in ({"src/Example.php": b"a", "src/example.php": b"b"}, {"BUILD-INFO.JSON": b"a"}, {"build-info.json/child.php": b"a"}, {"src/file": b"a", "src/file/nested.php": b"b"}, {"src/caf\u00e9.php": b"a", "src/cafe\u0301.php": b"b"}):
            with self.subTest(members=list(files)):
                with self.assertRaisesRegex(ValueError, "[Cc]olli"):
                    PACKAGE.archive(Path(self.temporary.name) / "collision.zip", files, {}, 1762214400)

    def test_all_four_bundle_destinations_refuse_symlinks_before_writing(self) -> None:
        self.fixture_project()
        output = self.build_fixture()
        baseline = {path.name: path.read_bytes() for path in output.iterdir()}
        victim = Path(self.temporary.name) / "victim.txt"
        victim.write_bytes(b"private fixture")
        for name in baseline:
            with self.subTest(destination=name):
                destination = output / name
                destination.unlink()
                destination.symlink_to(victim)
                with self.assertRaisesRegex(ValueError, "Output paths cannot contain symlinks"):
                    self.build_fixture()
                self.assertEqual(b"private fixture", victim.read_bytes())
                for other in baseline.keys() - {name}:
                    self.assertEqual(baseline[other], (output / other).read_bytes())
                destination.unlink()
                destination.write_bytes(baseline[name])

    def test_source_validation_failure_preserves_complete_existing_bundle(self) -> None:
        self.fixture_project()
        output = self.build_fixture()
        baseline = {path.name: path.read_bytes() for path in output.iterdir()}
        (Path(self.temporary.name) / "src" / "Example.php").write_text("changed runtime fixture")
        (Path(self.temporary.name) / "docs" / "secret.key").write_text("harmless secret-file fixture")
        with self.assertRaisesRegex(ValueError, "Private or generated"):
            self.build_fixture()
        self.assertEqual(baseline, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_source_archive_failure_preserves_complete_existing_bundle(self) -> None:
        self.fixture_project()
        output = self.build_fixture()
        baseline = {path.name: path.read_bytes() for path in output.iterdir()}
        (Path(self.temporary.name) / "src" / "Example.php").write_text("changed runtime fixture")
        original = PACKAGE.archive

        def fail_source(path, files, metadata, epoch):
            if path.name.endswith("-source.zip"):
                raise RuntimeError("simulated compression failure")
            return original(path, files, metadata, epoch)

        with patch.object(PACKAGE, "archive", side_effect=fail_source):
            with self.assertRaisesRegex(RuntimeError, "simulated compression failure"):
                self.build_fixture()
        self.assertEqual(baseline, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_only_bounded_development_versions_are_accepted(self) -> None:
        for version in ("1.0.0-dev", "1.0.0-dev.1", "1.0.0-dev.999"):
            self.assertEqual(version, PACKAGE.read_version(f" * Version: {version}\n"))
        for version in ("1.0.0", "1.0.0-rc.1", "1.0.0-dev.0", "1.0.0-dev.01", "1.0.0-dev.1000", "1.0.1-dev.1", "1.0.0-dev.1+build", "1.0.0-dev.1 Stable", "../../escape"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "Packaging permits only"):
                PACKAGE.read_version(f" * Version: {version}\n")
        with self.assertRaisesRegex(ValueError, "Packaging permits only"):
            PACKAGE.read_version(" * Version: 1.0.0-dev.1\n * Version: 1.0.0-dev.2\n")


if __name__ == "__main__":
    unittest.main()
