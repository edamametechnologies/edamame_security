#!/usr/bin/env python3
"""Headless tests for the EDAMAME Attack Simulator (tools/attack_simulator/app.py).

No Tk window and no real triggers run: these exercise the testable pieces of
the app -- catalog loading and validation, the check -> expectation mapping,
cleanup-line classification, the streaming helper with its timeout watchdog,
state-dir agreement with the triggers' own _common, and the absent-trigger
(hidden scenario) behaviour.

The catalog and triggers are found through EDAMAME_TRIGGERS_DIR, falling back to
../edamame_posture/tests/security/triggers relative to the edamame_security
repo root.

    python3 -m unittest discover -s tests/attack_simulator

tkinter is imported because app.py imports it at module load; the embedded
runtime the app ships with always has it. The consistency of the catalog
against the CI gate is tested separately in
edamame_posture/tests/security/test_trigger_catalog.py.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APP_DIR = REPO / "tools" / "attack_simulator"
sys.path.insert(0, str(APP_DIR))


def triggers_dir() -> Path:
    env = os.environ.get("EDAMAME_TRIGGERS_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return (REPO.parent / "edamame_posture" / "tests" / "security" / "triggers").resolve()


TRIGGERS_DIR = triggers_dir()

try:
    import tkinter  # noqa: F401  (app.py imports it at module load)
except Exception as exc:  # pragma: no cover - environment without Tk
    raise unittest.SkipTest(f"tkinter unavailable: {exc}")

import app  # noqa: E402  (from APP_DIR, after sys.path insert)


def _load_real_catalog():
    if not (TRIGGERS_DIR / "catalog.json").is_file():
        raise unittest.SkipTest(f"catalog.json not found at {TRIGGERS_DIR}")
    return app.load_catalog(TRIGGERS_DIR)


class CatalogLoads(unittest.TestCase):
    def setUp(self):
        self.catalog = _load_real_catalog()

    def test_has_scenarios(self):
        self.assertGreaterEqual(len(self.catalog.scenarios), 20)

    def test_required_fields_present_and_nonempty(self):
        for key, s in self.catalog.scenarios.items():
            self.assertTrue(s.title.strip(), key)
            self.assertTrue(s.one_liner.strip(), key)
            self.assertTrue(s.see_in_edamame.strip(), key)
            self.assertTrue(s.appears_within.strip(), key)
            self.assertTrue(s.talk_track.strip(), key)
            self.assertTrue(s.reference.name.strip(), key)
            self.assertTrue(s.reference.url.strip(), key)
            self.assertTrue(s.expected_checks, key)
            self.assertIsInstance(s.needs_admin, bool)

    def test_platforms_are_a_valid_subset(self):
        allowed = {"macos", "windows", "linux"}
        for key, s in self.catalog.scenarios.items():
            self.assertTrue(s.platforms, key)
            self.assertTrue(set(s.platforms) <= allowed, (key, s.platforms))

    def test_every_scenario_trigger_exists_on_disk(self):
        # The app resolves each catalog trigger against the triggers dir; in a
        # full checkout every one must be present (absent ones are hidden).
        for key, s in self.catalog.scenarios.items():
            self.assertTrue((TRIGGERS_DIR / s.trigger).is_file(), f"{key}: {s.trigger}")
            self.assertTrue(s.available, key)

    def test_terms_resolve_to_glossary(self):
        for key, s in self.catalog.scenarios.items():
            for term in s.terms:
                self.assertIn(term, self.catalog.glossary, f"{key}: {term}")

    def test_themes_and_demo_reference_real_scenarios(self):
        for theme in self.catalog.themes:
            for sid in theme.scenarios:
                self.assertIn(sid, self.catalog.scenarios, (theme.id, sid))
        for step in self.catalog.demo_steps:
            self.assertIn(step.scenario, self.catalog.scenarios, step.scenario)

    def test_safety_block_present(self):
        self.assertTrue(self.catalog.safety_headline.strip())
        self.assertTrue(self.catalog.safety_points)

    def test_every_screen_says_it_is_a_simulation_on_test_data(self):
        # Frank, 2026-10-13: the simulator must say plainly that no real
        # attack is carried out and that the scenarios run on test data.
        for text in (self.catalog.safety_headline, self.catalog.safety_summary):
            self.assertTrue(text.strip())
        self.assertIn("no real attack", self.catalog.safety_headline.lower())
        self.assertIn("test data", self.catalog.safety_summary.lower())
        self.assertIn("test data", self.catalog.safety_scenario_note.lower())


class ExpectationMapping(unittest.TestCase):
    def setUp(self):
        self.catalog = _load_real_catalog()

    def test_blacklisted_sessions_maps_to_blacklist(self):
        exps = app.expectations_for(self.catalog.scenarios["blacklist_comm"])
        kinds = {e.kind for e in exps}
        self.assertIn(app.KIND_BLACKLIST, kinds)
        # blacklist_comm also carries the skill_supply_chain finding.
        self.assertIn(app.KIND_FINDING, kinds)

    def test_divergence_categories_map_to_divergence(self):
        for key in ("divergence", "goal_drift", "daemon_lineage_egress"):
            exps = app.expectations_for(self.catalog.scenarios[key])
            self.assertTrue(exps, key)
            self.assertTrue(all(e.kind == app.KIND_DIVERGENCE for e in exps), key)
            self.assertTrue(all(e.check.startswith(("correlation:", "policy:")) for e in exps), key)

    def test_plain_checks_map_to_finding(self):
        exps = app.expectations_for(self.catalog.scenarios["cve_token_exfil"])
        self.assertEqual([(e.kind, e.check) for e in exps], [(app.KIND_FINDING, "token_exfiltration")])


class CatalogValidation(unittest.TestCase):
    """A missing or invalid catalog raises a clear CatalogError, never a crash."""

    def _write_catalog(self, tmp: Path, data) -> Path:
        (tmp / "catalog.json").write_text(json.dumps(data), encoding="utf-8")
        return tmp

    def test_missing_catalog_is_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(app.CatalogError) as cm:
                app.load_catalog(Path(d))
            self.assertIn("catalog.json", str(cm.exception))

    def test_malformed_json_is_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "catalog.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(app.CatalogError):
                app.load_catalog(Path(d))

    def test_term_not_in_glossary_is_error(self):
        data = _minimal_catalog()
        data["scenarios"]["demo_one"]["terms"] = ["not_a_real_term"]
        with tempfile.TemporaryDirectory() as d:
            self._write_catalog(Path(d), data)
            with self.assertRaises(app.CatalogError):
                app.load_catalog(Path(d))

    def test_theme_referencing_unknown_scenario_is_error(self):
        data = _minimal_catalog()
        data["themes"][0]["scenarios"] = ["does_not_exist"]
        with tempfile.TemporaryDirectory() as d:
            self._write_catalog(Path(d), data)
            with self.assertRaises(app.CatalogError):
                app.load_catalog(Path(d))

    def test_missing_required_field_is_error(self):
        data = _minimal_catalog()
        del data["scenarios"]["demo_one"]["talk_track"]
        with tempfile.TemporaryDirectory() as d:
            self._write_catalog(Path(d), data)
            with self.assertRaises(app.CatalogError):
                app.load_catalog(Path(d))


class AbsentTriggerIsHidden(unittest.TestCase):
    """A scenario whose trigger file is absent loads but is marked unavailable."""

    def test_absent_trigger_marks_scenario_unavailable(self):
        data = _minimal_catalog()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "catalog.json").write_text(json.dumps(data), encoding="utf-8")
            # No trigger_demo_one.py on disk.
            catalog = app.load_catalog(tmp)
            self.assertFalse(catalog.scenarios["demo_one"].available)
            # Now add the trigger script; it becomes available.
            (tmp / "trigger_demo_one.py").write_text(
                "import argparse\n"
                "p = argparse.ArgumentParser()\n"
                "p.add_argument('--duration', type=float, default=0.0)\n"
                "p.add_argument('--agent-type')\n"
                "p.add_argument('--state-dir')\n"
                "p.parse_args()\n",
                encoding="utf-8",
            )
            catalog2 = app.load_catalog(tmp)
            self.assertTrue(catalog2.scenarios["demo_one"].available)


class TermLabels(unittest.TestCase):
    def test_known_abbreviations(self):
        self.assertEqual(app.term_label("mcp"), "MCP")
        self.assertEqual(app.term_label("c2"), "C2")
        self.assertEqual(app.term_label("dns_tunnel"), "DNS tunnel")

    def test_fallback_is_title_case(self):
        self.assertEqual(app.term_label("sandbox_escape"), "Sandbox escape")


class ClassifyCleanupLine(unittest.TestCase):
    def test_removed(self):
        self.assertEqual(app.classify_cleanup_line("  removed /tmp/x"), "removed")

    def test_blocked(self):
        for line in (
            "  cannot remove /usr/local/bin/standin: Permission denied",
            "  could not kill pid=5 (x.pid): permission denied",
            "  cannot kill pid=7 (permission denied)",
            "  left /tmp/x/.env: its content changed since the trigger wrote it",
        ):
            self.assertEqual(app.classify_cleanup_line(line), "blocked", line)

    def test_info(self):
        self.assertEqual(app.classify_cleanup_line("Cleaning up demo state in /tmp/x"), "info")


class RunAndStream(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / f"as-test-{os.getpid()}"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_streams_lines_and_returns_code(self):
        script = self._write(
            "fake_cleanup.py",
            "import sys\n"
            "print('Cleaning up demo state in /tmp/x')\n"
            "print('  removed /tmp/x/a')\n"
            "print('  removed /tmp/x/b')\n"
            "print('  cannot remove /usr/local/bin/s: Permission denied')\n"
            "sys.exit(0)\n",
        )
        lines = []
        code, timed_out = app.run_and_stream([sys.executable, str(script)], self.tmp, lines.append, timeout_secs=30)
        self.assertEqual(code, 0)
        self.assertFalse(timed_out)
        self.assertEqual(sum(1 for l in lines if app.classify_cleanup_line(l) == "removed"), 2)
        self.assertEqual(sum(1 for l in lines if app.classify_cleanup_line(l) == "blocked"), 1)

    def test_timeout_kills_a_silent_hang(self):
        script = self._write("hang.py", "import time\ntime.sleep(600)\n")
        started = time.monotonic()
        code, timed_out = app.run_and_stream([sys.executable, str(script)], self.tmp, lambda _l: None, timeout_secs=2)
        self.assertTrue(timed_out)
        self.assertLess(time.monotonic() - started, 20, "watchdog did not stop the hang promptly")


class StateDir(unittest.TestCase):
    def test_matches_triggers_common(self):
        common_path = TRIGGERS_DIR / "_common.py"
        if not common_path.is_file():
            self.skipTest("triggers _common.py not found")
        spec = importlib.util.spec_from_file_location("_common_under_test", common_path)
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        for agent in app.AGENT_TYPES:
            self.assertEqual(
                str(app.state_dir_for(agent, TRIGGERS_DIR)),
                str(common.state_dir_for(agent)),
                agent,
            )


class AppTexts(unittest.TestCase):
    def test_returns_required_keys(self):
        texts = app.load_app_texts()
        for key in ("name", "tagline", "where_to_look", "admin_note"):
            self.assertIn(key, texts)
        self.assertTrue(texts["name"].strip())


def _minimal_catalog() -> dict:
    """A small, structurally valid catalog for the validation tests."""
    return {
        "catalog_version": "test",
        "glossary": {"exfiltration": "Stealing data off a machine."},
        "scenarios": {
            "demo_one": {
                "trigger": "trigger_demo_one.py",
                "title": "Demo one",
                "one_liner": "A demo scenario.",
                "reference": {"name": "Ref", "year": "2026", "url": "https://example.com/", "kind": "technique"},
                "see_in_edamame": "Security > Detections shows a finding.",
                "appears_within": "a few minutes",
                "talk_track": "This is a demo.",
                "terms": ["exfiltration"],
                "needs_admin": False,
                "platforms": ["macos", "windows", "linux"],
                "expected_checks": ["token_exfiltration"],
                "gate_scenarios": ["demo_one"],
            }
        },
        "themes": [{"id": "t1", "title": "Theme one", "summary": "s", "scenarios": ["demo_one"]}],
        "demo_path": {"title": "Demo", "intro": "i", "steps": [{"scenario": "demo_one", "note": "n"}], "closing": "c"},
        "safety": {
            "headline": "Simulation only.",
            "summary": "Test data only.",
            "scenario_note": "Simulation on test data.",
            "points": ["Local only."],
        },
    }


if __name__ == "__main__":
    unittest.main()
