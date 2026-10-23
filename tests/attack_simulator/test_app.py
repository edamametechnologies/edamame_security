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


CORE_API_AGENTIC = REPO.parent / "edamame_core" / "src" / "api" / "api_agentic.rs"


def _scenario(key: str = "demo_one", check: str = "token_exfiltration") -> "app.Scenario":
    return app.Scenario(
        key=key, trigger=f"trigger_{key}.py", title=f"Title {key}", one_liner="o",
        reference=app.Reference(name="r", year="", url="https://example.com/", kind=""),
        see_in_edamame="s", appears_within="a", talk_track="t", terms=(), needs_admin=False,
        platforms=("macos", "windows", "linux"), expected_checks=(check,), gate_scenarios=(),
    )


def _iso(epoch: float) -> str:
    """RFC 3339 the way EDAMAME writes it: UTC, nanoseconds, a Z."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


def _hit(key: str, first_detected=None, **extra) -> dict:
    hit = {
        "key": key, "kind": app.KIND_FINDING, "finding_key": key, "check": "token_exfiltration",
        "first_detected": first_detected, "subject": "curl \u2192 example.com:443",
        "process_name": "curl", "severity": "HIGH", "alertable": True, "dismissed": False, "text": "",
    }
    hit.update(extra)
    return hit


def _demo(key: str, severity: str = "HIGH", origin: str = app.ORIGIN_SESSION) -> "app.DemoFinding":
    return app.DemoFinding(key=key, check="token_exfiltration", severity=severity,
                           subject="curl \u2192 example.com:443", origin=origin,
                           scenario="Title demo_one", process_name="curl")


class ParseRfc3339(unittest.TestCase):
    def test_reads_edamame_timestamps(self):
        self.assertAlmostEqual(app.parse_rfc3339("2026-10-23T08:00:00.123456789Z"), 1792742400.123456, places=5)
        self.assertEqual(app.parse_rfc3339("2026-10-23T08:00:00Z"), 1792742400.0)
        self.assertEqual(app.parse_rfc3339("2026-10-23T10:00:00+02:00"), 1792742400.0)

    def test_unreadable_is_none(self):
        for value in (None, "", "yesterday", 1792742400, "2026-10-23"):
            self.assertIsNone(app.parse_rfc3339(value), value)


class ConfirmedKeyTracking(unittest.TestCase):
    """Which findings the watch attributes to a run (run_caused) and records."""

    START = 1_800_000_000.0

    def test_first_detected_after_the_start_is_the_runs(self):
        self.assertTrue(app.run_caused(_hit("k", _iso(self.START + 30)), self.START, True, False))

    def test_first_detected_before_the_start_is_not(self):
        # Even when the baseline missed it, EDAMAME's own date wins.
        self.assertFalse(app.run_caused(_hit("k", _iso(self.START - 120)), self.START, False, True))

    def test_without_a_date_only_a_reliable_baseline_decides(self):
        self.assertTrue(app.run_caused(_hit("k"), self.START, in_baseline=False, baseline_reliable=True))
        self.assertFalse(app.run_caused(_hit("k"), self.START, in_baseline=True, baseline_reliable=True))
        self.assertFalse(app.run_caused(_hit("k"), self.START, in_baseline=False, baseline_reliable=False))

    def test_dismissed_keyless_and_other_kinds_are_never_recorded(self):
        late = _iso(self.START + 30)
        self.assertFalse(app.run_caused(_hit("k", late, dismissed=True), self.START, False, True))
        self.assertFalse(app.run_caused(_hit("k", late, finding_key=""), self.START, False, True))
        self.assertFalse(app.run_caused(_hit("k", late, kind=app.KIND_DIVERGENCE), self.START, False, True))
        self.assertFalse(app.run_caused(_hit("k", late, kind=app.KIND_BLACKLIST), self.START, False, True))

    def test_the_window_records_only_the_runs_findings(self):
        run = app.TriggerRun(scenario=_scenario(), agent_type="openclaw", state_dir=Path("."),
                             duration=60.0, duration_arg=None, started_epoch=self.START)
        run.detection.baseline = {"token_exfiltration|old"}
        run.detection.baseline_reliable = True
        holder = type("Holder", (), {})()
        holder.session_findings = {}
        hits = [
            _hit("new", _iso(self.START + 40), severity="CRITICAL"),
            _hit("old", _iso(self.START - 3600)),
            _hit("undated-old"),
            _hit("undated-new"),
            _hit("gone", _iso(self.START + 40), dismissed=True),
        ]
        hits[2]["key"] = "old"  # the baseline holds it under this key
        app.AttackSimulator._remember_demo_findings(holder, run, "token_exfiltration", hits)
        self.assertEqual(sorted(holder.session_findings), ["new", "undated-new"])
        recorded = holder.session_findings["new"]
        self.assertEqual((recorded.origin, recorded.severity, recorded.scenario),
                         (app.ORIGIN_SESSION, "CRITICAL", "Title demo_one"))

    def test_watch_hits_carry_what_the_tracking_needs(self):
        if not (TRIGGERS_DIR / "_finding_match.py").is_file():
            self.skipTest("triggers _finding_match.py not found")
        watch = object.__new__(app.EdamameWatch)
        watch._match_module = app.load_trigger_module(TRIGGERS_DIR, "_finding_match")
        finding = {
            "check": "token_exfiltration", "severity": "HIGH", "finding_key": "fk-1",
            "dismissed": False, "description": "d", "first_detected": "2026-10-23T08:00:00Z",
            "process_name": "curl", "destination_domain": "example.com", "destination_port": 443,
        }
        other = dict(finding, check="credential_harvest", finding_key="fk-2")
        hits = watch._hits(app.Expectation(app.KIND_FINDING, "token_exfiltration"), [finding, other], [], {})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["finding_key"], "fk-1")
        self.assertEqual(hits[0]["kind"], app.KIND_FINDING)
        self.assertEqual(hits[0]["first_detected"], "2026-10-23T08:00:00Z")
        self.assertEqual(hits[0]["subject"], "curl \u2192 example.com:443")


class OnlyDemoFindingsAreOffered(unittest.TestCase):
    def setUp(self):
        self.root = app._norm_path(Path("/opt/edamame-sim-test/triggers"))
        self.roots = (self.root,)

    def _finding(self, key, **extra):
        finding = {"finding_key": key, "check": "token_exfiltration", "severity": "HIGH",
                   "dismissed": False, "process_name": "curl", "process_path": "/usr/bin/curl"}
        finding.update(extra)
        return finding

    def test_only_recorded_keys_and_simulator_lineage(self):
        findings = [
            self._finding("recorded"),
            self._finding("unrelated", parent_process_path="/usr/bin/zsh"),
            self._finding("recorded-but-dismissed", dismissed=True),
            self._finding("lineage", severity="LOW", parent_script_path="/opt/edamame-sim-test/triggers/trigger_x.py"),
            self._finding("sibling-dir", parent_script_path="/opt/edamame-sim-test/triggers2/trigger_x.py"),
            self._finding("", parent_script_path="/opt/edamame-sim-test/triggers/trigger_x.py"),
            self._finding("recorded"),
            "not a finding",
        ]
        recorded = {"recorded": _demo("recorded"), "recorded-but-dismissed": _demo("recorded-but-dismissed"),
                    "recorded-but-gone": _demo("recorded-but-gone")}
        offered = app.select_demo_findings(findings, recorded, self.roots)
        self.assertEqual([(f.key, f.origin) for f in offered],
                         [("recorded", app.ORIGIN_SESSION), ("lineage", app.ORIGIN_LINEAGE)])

    def test_nothing_recorded_and_no_lineage_offers_nothing(self):
        findings = [self._finding("a"), self._finding("b", severity="CRITICAL")]
        self.assertEqual(app.select_demo_findings(findings, {}, self.roots), [])
        self.assertEqual(app.select_demo_findings(findings, {}, ()), [])

    def test_most_severe_first(self):
        findings = [self._finding("low", severity="LOW"), self._finding("crit", severity="critical"),
                    self._finding("high")]
        recorded = {k: _demo(k) for k in ("low", "crit", "high")}
        self.assertEqual([f.key for f in app.select_demo_findings(findings, recorded, ())], ["crit", "high", "low"])

    def test_lineage_roots_never_cover_the_home_folder(self):
        home = app._norm_path(Path.home())
        for triggers in (Path.home(), Path.home().parent, Path(Path.home().anchor or "/")):
            for root in app.simulator_roots(triggers):
                self.assertFalse(home == root or home.startswith(root + "/"), (triggers, root))
        # The real triggers dir (inside the checkout or the bundle) is a root.
        self.assertIn(app._norm_path(TRIGGERS_DIR.resolve()), app.simulator_roots(TRIGGERS_DIR))

    def test_lineage_reads_only_process_fields(self):
        inside = "/opt/edamame-sim-test/triggers/trigger_x.py"
        self.assertTrue(app.has_simulator_lineage({"process_path": inside}, self.roots))
        self.assertTrue(app.has_simulator_lineage({"parent_process_path": inside}, self.roots))
        self.assertFalse(app.has_simulator_lineage({"subject_path": inside, "open_files": [inside]}, self.roots))
        self.assertFalse(app.has_simulator_lineage({"process_path": inside}, ()))


class DismissRpcPayload(unittest.TestCase):
    def test_argument_object_uses_the_wire_name(self):
        args = json.loads(app.dismiss_rpc_args(_demo("fk-1")))
        self.assertEqual(list(args), ["request_json"])
        self.assertIsInstance(args["request_json"], str)
        request = json.loads(args["request_json"])
        self.assertEqual(request["domain"], "vulnerability")
        self.assertEqual(request["scope"], "finding")
        self.assertEqual(request["finding_key"], "fk-1")
        self.assertEqual(request["reason"], "Attack Simulator demo")
        self.assertEqual(request["severity_ceiling"], "high_and_below")
        self.assertIsInstance(request["ttl_secs"], int)
        self.assertNotIn("matcher", request)  # the exact key, never a broader rule
        self.assertEqual(request["source_context"]["check_or_category"], "token_exfiltration")

    def test_critical_needs_the_critical_capable_ceiling(self):
        request = app.dismiss_request(_demo("fk-2", severity="CRITICAL"))
        self.assertEqual(request["severity_ceiling"], "critical_capable")

    def test_matches_the_core_rpc_declaration(self):
        if not CORE_API_AGENTIC.is_file():
            self.skipTest(f"edamame_core not found at {CORE_API_AGENTIC}")
        import re
        source = CORE_API_AGENTIC.read_text(encoding="utf-8")
        match = re.search(r"rpc!\(\s*agentic_dismiss_with_scope\s*\(\s*(\w+)\s*:\s*String\s*\)", source)
        self.assertIsNotNone(match, "rpc!(agentic_dismiss_with_scope(...)) not found")
        self.assertEqual(app.DISMISS_RPC_METHOD, "agentic_dismiss_with_scope")
        self.assertEqual(match.group(1), app.DISMISS_RPC_ARG)
        body = source[match.end(): source.index("pub fn agentic_dismiss_with_scope(", match.end())]
        for key in app.dismiss_request(_demo("fk-1")):
            self.assertIn(f'"{key}"', body, f"the core does not read request field '{key}'")
        for key in ("finding_title", "check_or_category", "process_name", "severity", "details"):
            self.assertIn(f'"{key}"', body, key)

    def test_cli_command_line_and_envelope(self):
        import subprocess
        from unittest import mock

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout='Result: "{\\"success\\": true}"\n', stderr="")

        def parse(raw):
            text = raw.strip()[len("Result: "):]
            value = json.loads(text)
            return json.loads(value) if isinstance(value, str) else value

        with mock.patch.object(app.subprocess, "run", fake_run):
            result = app.dismiss_demo_finding(
                lambda method, args: app.run_cli_rpc("edamame_cli", method, args, parse), _demo("fk-3"))
        self.assertEqual(result, (True, "", False))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["edamame_cli", "rpc", "agentic_dismiss_with_scope"])
        self.assertEqual(json.loads(json.loads(calls[0][3])["request_json"])["finding_key"], "fk-3")

    def test_failures_are_reported(self):
        import subprocess

        self.assertEqual(app.parse_dismiss_envelope({"success": False, "error": "at capacity"}), (False, "at capacity"))
        self.assertFalse(app.parse_dismiss_envelope({"success": "true"})[0])
        self.assertFalse(app.parse_dismiss_envelope(None)[0])

        def refused(method, args):
            raise RuntimeError("transport error")

        def silent(method, args):
            raise subprocess.TimeoutExpired("edamame_cli", 40)

        self.assertEqual(app.dismiss_demo_finding(refused, _demo("k")), (False, "transport error", False))
        ok, _error, fatal = app.dismiss_demo_finding(silent, _demo("k"))
        self.assertFalse(ok)
        self.assertTrue(fatal)


class NothingIsDismissedWithoutConfirmation(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def _dismiss(self, finding):
        self.calls.append(finding.key)
        return True, "", False

    def test_nothing_happens_until_begin(self):
        offer = app.DemoDismissal([_demo("a"), _demo("b")], self._dismiss)
        self.assertEqual(offer.state, app.DemoDismissal.PENDING)
        with self.assertRaises(RuntimeError):
            offer.run()
        self.assertEqual(self.calls, [])

    def test_keep_closes_the_offer(self):
        offer = app.DemoDismissal([_demo("a")], self._dismiss)
        self.assertTrue(offer.keep())
        self.assertFalse(offer.begin())
        with self.assertRaises(RuntimeError):
            offer.run()
        self.assertEqual(self.calls, [])

    def test_confirmed_dismisses_each_listed_finding_once(self):
        offer = app.DemoDismissal([_demo("a"), _demo("b")], self._dismiss)
        self.assertTrue(offer.begin())
        self.assertFalse(offer.begin())  # a second press does nothing
        seen = []
        offer.run(lambda f, ok, err: seen.append((f.key, ok)))
        self.assertEqual(self.calls, ["a", "b"])
        self.assertEqual(seen, [("a", True), ("b", True)])
        self.assertFalse(offer.keep())
        self.assertEqual(offer.state, app.DemoDismissal.DONE)

    def test_no_answer_stops_the_rest(self):
        def silent(finding):
            self.calls.append(finding.key)
            return False, "EDAMAME did not answer in time", True

        offer = app.DemoDismissal([_demo("a"), _demo("b")], silent)
        offer.begin()
        results = offer.run()
        self.assertEqual(self.calls, ["a"])
        self.assertEqual([ok for _f, ok, _e in results], [False, False])
        self.assertTrue(results[1][2].startswith("not tried"))

    def test_an_empty_offer_cannot_begin(self):
        self.assertFalse(app.DemoDismissal([], self._dismiss).begin())


class FindingSubject(unittest.TestCase):
    def test_process_and_object(self):
        self.assertEqual(app.finding_subject({"process_name": "python3", "subject_path": "/Users/x/.cursor/mcp.json"}),
                         "python3 \u2192 \u2026/.cursor/mcp.json")
        self.assertEqual(app.finding_subject({"process_path": "C:\\Tools\\curl.exe", "destination_ip": "1.2.3.4",
                                              "destination_port": 53}), "curl.exe \u2192 1.2.3.4:53")
        self.assertEqual(app.finding_subject({"open_files": ["/tmp/a/b/c.txt"]}), "\u2026/b/c.txt")
        self.assertEqual(app.finding_subject({}), "")

    def test_long_subjects_are_shortened(self):
        text = app.finding_subject({"process_name": "p" * 200})
        self.assertLessEqual(len(text), 96)
        self.assertTrue(text.endswith("\u2026"))


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
