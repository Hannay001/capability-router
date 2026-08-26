"""Tests for harness discovery, init bindings, and doctor."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPOSITORY_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import cap_setup  # noqa: E402


class DiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cap-setup-")
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)

    def test_known_harness_with_skills_is_detected(self) -> None:
        (self.home / ".claude" / "skills" / "demo").mkdir(parents=True)
        (self.home / ".claude" / "skills" / "demo" / "SKILL.md").write_text("---\nname: demo\n---\n")
        with mock.patch.object(cap_setup, "HOME", self.home):
            found = {h.name: h for h in cap_setup.detect_harnesses()}
        self.assertTrue(found["claude"].present)
        self.assertEqual(len(found["claude"].skill_roots), 1)

    def test_unknown_harness_is_auto_detected_by_generic_scan(self) -> None:
        future = self.home / ".superfuture" / "skills"
        future.mkdir(parents=True)
        with mock.patch.object(cap_setup, "HOME", self.home):
            found = {h.name: h for h in cap_setup.detect_harnesses()}
        self.assertIn("superfuture", found)
        self.assertTrue(found["superfuture"].present)
        self.assertFalse(found["superfuture"].known)

    def test_absent_harness_reports_not_detected(self) -> None:
        with mock.patch.object(cap_setup, "HOME", self.home):
            found = {h.name: h for h in cap_setup.detect_harnesses()}
        self.assertFalse(found["claude"].present)


class InitBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cap-init-")
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name) / "home"
        repo = Path(self._tmp.name) / "repo"
        (repo / "config").mkdir(parents=True)
        (self.home / ".codex" / "skills" / "x").mkdir(parents=True)
        self.repo = repo
        patcher = mock.patch.object(cap_setup, "HOME", self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        root_patcher = mock.patch.object(cap_setup, "_repo_root", lambda: repo)
        root_patcher.start()
        self.addCleanup(root_patcher.stop)

    def test_init_writes_local_bindings_for_detected_harnesses(self) -> None:
        import contextlib
        from io import StringIO

        with contextlib.redirect_stdout(StringIO()):
            rc = cap_setup.main(["init"])
        self.assertEqual(rc, 0)
        local = self.repo / "config" / "local.toml"
        self.assertTrue(local.is_file())
        text = local.read_text(encoding="utf-8")
        self.assertIn("extra_skill_roots", text)
        self.assertIn(".codex/skills", text.replace("\\", "/").replace("//", "/"))

    def test_init_unknown_runtime_fails_without_force(self) -> None:
        import contextlib
        from io import StringIO

        with contextlib.redirect_stdout(StringIO()):
            rc = cap_setup.main(["init", "--runtimes", "doesnotexist"])
        self.assertEqual(rc, 1)
        self.assertFalse((self.repo / "config" / "local.toml").exists())


class DoctorTest(unittest.TestCase):
    def test_doctor_lists_detected_and_missing(self) -> None:
        from io import StringIO

        home_root = Path(tempfile.mkdtemp(prefix="cap-doctor-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home_root, True))
        home = home_root / "home"
        (home / ".claude" / "skills").mkdir(parents=True)
        repo = home_root / "repo"
        repo.mkdir()
        with mock.patch.object(cap_setup, "HOME", home), mock.patch.object(
            cap_setup, "_repo_root", lambda: repo
        ), mock.patch("sys.stdout", new=StringIO()) as out:
            rc = cap_setup.main(["doctor"])
        text = out.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("[x] claude", text)
        self.assertIn("[ ] codex", text)


if __name__ == "__main__":
    unittest.main()
