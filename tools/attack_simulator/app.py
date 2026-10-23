#!/usr/bin/env python3
"""
EDAMAME Attack Simulator: a cross-platform demo tool that safely reproduces the
host-visible behaviour of real-world attack techniques so a viewer can watch
EDAMAME detect them.

It is a thin wrapper: it starts and stops EDAMAME's own detection-test trigger
scripts (tests/security/triggers) and renders the sales catalog that ships
beside them (catalog.json). It changes nothing about how detection works and
makes no network connections of its own.

Standard library only (tkinter / ttk), Python 3.9+, macOS / Windows / Linux.
For authorized local security demos and testing only.
"""

from __future__ import annotations

import collections
import dataclasses
import importlib.util
import itertools
import json
import os
import platform
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
import traceback
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_MACOS = SYSTEM == "Darwin"
PLATFORM_KEY = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(SYSTEM, "")

AGENT_TYPES = ("openclaw", "cursor", "claude_code", "claude_desktop", "codex", "hermes")
DEFAULT_AGENT_TYPE = "openclaw"

EVENT_DRAIN_MS = 80
TICK_MS = 1000
PID_SCAN_MS = 2000
STOP_ESCALATE_MS = 8000
LOG_MAX_LINES = 3000
CLEANUP_TIMEOUT_SECS = 120

# EDAMAME watch: how often the simulator asks EDAMAME for its findings while a
# scenario it started is running, and for how long after it ended (findings can
# land a few detector ticks after the stimulus stops).
WATCH_INTERVAL_S = 15.0
WATCH_AFTER_FINISH_S = 600.0
# A finding EDAMAME already holds when the first check after a start runs
# (within this window) predates the run: reported as "already reported", not a
# fresh detection.
BASELINE_WINDOW_S = 25.0
# edamame_cli builds before core 2.0.5 rewrite the shared secret store when they
# start, which can remove a running EDAMAME app's stored credentials. The
# simulator never runs an older one.
MIN_SAFE_CLI_VERSION = (2, 0, 5)
CLI_TIMEOUT_S = 40.0

# Bump when the one-time confirmation's wording changes materially, so users
# are asked to re-confirm. Persisted per user under the cache dir.
CONSENT_VERSION = 1

RUN_FOR_CHOICES = (
    ("Script default", None),
    ("1 minute", 60),
    ("2 minutes", 120),
    ("5 minutes", 300),
    ("10 minutes", 600),
    ("Until stopped", 0),
)

# Friendlier labels for glossary term chips (fallback: Title Case).
TERM_LABELS = {
    "mcp": "MCP",
    "c2": "C2",
    "rat": "RAT",
    "fim": "FIM",
    "oidc_token": "OIDC token",
    "dns_tunnel": "DNS tunnel",
    "ntp_tunnel": "NTP tunnel",
}


def term_label(term: str) -> str:
    if term in TERM_LABELS:
        return TERM_LABELS[term]
    return term.replace("_", " ").capitalize()


# ---------------------------------------------------------------------------
# Bundle layout and the Python that runs the triggers
# ---------------------------------------------------------------------------


def app_resources_dir() -> Path:
    """Directory holding app.py and the bundled ``python`` / ``triggers``.

    macOS: ``App.app/Contents/Resources``; Windows / Linux: the directory the
    launcher ships app.py in. In every bundle layout this is simply the
    directory app.py lives in.
    """
    return Path(__file__).resolve().parent


def resolve_triggers_dir() -> Path:
    env = os.environ.get("EDAMAME_TRIGGERS_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()

    here = app_resources_dir()
    candidates = [
        here / "triggers",
        # Development checkout: tools/attack_simulator -> ../edamame_posture.
        here.parent.parent.parent / "edamame_posture" / "tests" / "security" / "triggers",
        here.parent.parent / "tests" / "security" / "triggers",
        Path.cwd() / "tests" / "security" / "triggers",
    ]
    for candidate in candidates:
        if (candidate / "cleanup.py").is_file():
            return candidate.resolve()
    raise SystemExit(
        "Could not find the EDAMAME trigger scripts.\n\n"
        "Set EDAMAME_TRIGGERS_DIR, or run from the edamame_posture checkout."
    )


def _path_inside_app_bundle(path: Path) -> bool:
    """True when a process path would look like a packaged macOS app.

    The triggers run from a standalone interpreter, the way the attack tools
    they model run, never from inside an app bundle.
    """
    normalized = str(path).replace("\\", "/").lower()
    return ".app/" in normalized or normalized.endswith(".app")


def _usable_python(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return (
        resolved.is_file()
        and os.access(str(resolved), os.X_OK)
        and not _path_inside_app_bundle(resolved)
    )


def _bundled_python_executable(root: Path) -> Path:
    if IS_WINDOWS:
        return root / "python.exe"
    return root / "bin" / "python3"


def _cache_root() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / "edamame-attack-simulator"
    if IS_MACOS:
        return Path.home() / "Library" / "Caches" / "edamame-attack-simulator"
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "edamame-attack-simulator"


def _relocated_bundled_python(bundled_root: Path) -> Path:
    """Copy the embedded runtime to a path that is not inside a ``.app``.

    Only needed on macOS: a process whose path is inside a ``.app`` is
    classified as the app reading its own files and the findings are dropped.
    """
    dest = _cache_root() / "python"
    marker = dest / ".bundle-source"
    source_id = str(bundled_root.resolve())
    python = _bundled_python_executable(dest)
    if (
        python.is_file()
        and marker.is_file()
        and marker.read_text(encoding="utf-8").strip() == source_id
    ):
        return python
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundled_root, dest, symlinks=True)
    marker.write_text(source_id + "\n", encoding="utf-8")
    return python


_RUNTIME_LOCK = threading.Lock()
_RUNTIME_PYTHON: Optional[str] = None


def runtime_python() -> str:
    """Python used to launch trigger and cleanup scripts.

    The bundle always uses the Python it shipped with. On macOS that runtime
    lives inside the ``.app``, so it is copied out first: a process path inside
    a ``.app`` is classified as the app reading its own files and the findings
    the triggers raise are dropped. On Windows / Linux the bundled interpreter's
    path is used in place. A checkout without the embedded runtime falls back to
    another interpreter whose path is also outside an app bundle.
    """
    global _RUNTIME_PYTHON
    with _RUNTIME_LOCK:
        if _RUNTIME_PYTHON is None:
            _RUNTIME_PYTHON = _resolve_runtime_python()
        return _RUNTIME_PYTHON


def _resolve_runtime_python() -> str:
    bundled_root = app_resources_dir() / "python"
    bundled = _bundled_python_executable(bundled_root)
    if bundled.is_file():
        if _path_inside_app_bundle(bundled):
            relocated = _relocated_bundled_python(bundled_root)
            if _usable_python(relocated):
                return str(relocated.resolve())
        elif _usable_python(bundled):
            return str(bundled.resolve())

    if IS_WINDOWS:
        system_candidates = (
            Path(sys.base_prefix) / "python.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python" / "python.exe",
        )
    else:
        system_candidates = (
            Path("/opt/homebrew/bin/python3"),
            Path("/usr/local/bin/python3"),
            Path("/usr/bin/python3"),
        )
    for candidate in system_candidates:
        if _usable_python(candidate):
            return str(candidate.resolve())
    return sys.executable


_MODULE_LOCK = threading.Lock()
_MODULE_CACHE: Dict[Tuple[str, str], Any] = {}


def load_trigger_module(triggers_dir: Path, name: str) -> Any:
    """Import ``<triggers_dir>/<name>.py`` (``_common``, ``_edamame_cli``,
    ``_finding_match``) once, under a private module name, so the simulator uses
    the triggers' own helpers rather than copies of them."""
    cache_key = (str(triggers_dir), name)
    with _MODULE_LOCK:
        if cache_key in _MODULE_CACHE:
            return _MODULE_CACHE[cache_key]
        path = triggers_dir / f"{name}.py"
        spec = importlib.util.spec_from_file_location(
            f"_edamame_sim_{name.strip('_')}", str(path)
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULE_CACHE[cache_key] = module
        return module


def state_dir_for(agent_type: str, triggers_dir: Path) -> Path:
    """Demo state directory for ``agent_type``. Matches the triggers' own
    ``_common.state_dir_for``; falls back to the same logic inline."""
    try:
        return Path(load_trigger_module(triggers_dir, "_common").state_dir_for(agent_type))
    except Exception:
        pass
    # Fallback only if the triggers' _common cannot be loaded; keep it in step
    # with _common.state_dir_for (per-owner leaf on POSIX; %TEMP% is already
    # per-user on Windows).
    if IS_WINDOWS:
        return Path(os.environ.get("TEMP", "C:\\Temp")) / f"edamame_{agent_type}_demo"
    return Path(f"/tmp/edamame_{agent_type}_demo_{os.geteuid()}")


def file_prefix_for(agent_type: str) -> str:
    return f"demo_{agent_type}"


def _strip_prefix(value: str, prefix: str) -> str:
    return value[len(prefix):] if value.startswith(prefix) else value


def _strip_suffix(value: str, suffix: str) -> str:
    return value[: -len(suffix)] if value.endswith(suffix) else value


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


class CatalogError(Exception):
    pass


@dataclass(frozen=True)
class Reference:
    name: str
    year: str
    url: str
    kind: str

    @property
    def display(self) -> str:
        if self.year:
            return f"{self.name} ({self.year})"
        return self.name


@dataclass(frozen=True)
class Scenario:
    key: str
    trigger: str
    title: str
    one_liner: str
    reference: Reference
    see_in_edamame: str
    appears_within: str
    talk_track: str
    terms: Tuple[str, ...]
    needs_admin: bool
    platforms: Tuple[str, ...]
    expected_checks: Tuple[str, ...]
    gate_scenarios: Tuple[str, ...]
    # Resolved at load time against the triggers dir on disk.
    script: Optional[Path] = None
    default_duration: float = 0.0
    accepts_duration: bool = False
    pid_file_name: str = ""

    @property
    def available(self) -> bool:
        return self.script is not None and self.script.is_file()

    @property
    def supported(self) -> bool:
        return (not PLATFORM_KEY) or (PLATFORM_KEY in self.platforms)

    def pid_file(self, state_dir: Path) -> Path:
        return state_dir / (self.pid_file_name or f"{self.key}.pid")


@dataclass
class Theme_:
    id: str
    title: str
    summary: str
    scenarios: Tuple[str, ...]


@dataclass
class DemoStep:
    scenario: str
    note: str


@dataclass
class Catalog:
    version: str
    scenarios: Dict[str, Scenario]
    themes: List[Theme_]
    glossary: Dict[str, str]
    demo_title: str
    demo_intro: str
    demo_steps: List[DemoStep]
    demo_closing: str
    safety_headline: str
    # Shown on every screen: no real attack, test data only (catalog.json).
    safety_summary: str
    safety_scenario_note: str
    safety_points: List[str]


def _script_metadata(path: Path) -> Tuple[float, bool, Optional[str]]:
    """(--duration default, accepts --duration, PID_FILE) read from the
    trigger source with ``ast`` -- nothing is executed."""
    import ast

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, ValueError):
        return 0.0, False, None

    pid_file = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "PID_FILE" for t in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                pid_file = node.value.value

    accepts = False
    default = 0.0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "--duration"
        ):
            accepts = True
            for keyword in node.keywords:
                if keyword.arg == "default":
                    try:
                        default = float(ast.literal_eval(keyword.value))
                    except (ValueError, TypeError, SyntaxError):
                        default = 0.0
    return max(default, 0.0), accepts, pid_file


def _require(obj: dict, key: str, where: str) -> Any:
    if key not in obj:
        raise CatalogError(f"{where}: missing '{key}'")
    value = obj[key]
    if isinstance(value, str) and not value.strip():
        raise CatalogError(f"{where}: '{key}' is empty")
    if isinstance(value, (list, dict)) and not value and key not in ("gate_scenarios",):
        raise CatalogError(f"{where}: '{key}' is empty")
    return value


def load_catalog(triggers_dir: Path) -> Catalog:
    """Load and validate catalog.json from the triggers directory, resolving
    each scenario against the trigger script on disk. Raises CatalogError with
    a human-readable message on any structural problem."""
    path = triggers_dir / "catalog.json"
    if not path.is_file():
        raise CatalogError(
            f"catalog.json was not found next to the trigger scripts\n({path})."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalogError(f"catalog.json could not be read: {exc}")
    if not isinstance(raw, dict):
        raise CatalogError("catalog.json is not a JSON object.")

    glossary = _require(raw, "glossary", "catalog")
    if not isinstance(glossary, dict):
        raise CatalogError("catalog: 'glossary' must be an object")

    scenarios_raw = _require(raw, "scenarios", "catalog")
    if not isinstance(scenarios_raw, dict):
        raise CatalogError("catalog: 'scenarios' must be an object")

    scenarios: Dict[str, Scenario] = {}
    for key, entry in scenarios_raw.items():
        where = f"scenario '{key}'"
        if not isinstance(entry, dict):
            raise CatalogError(f"{where}: not an object")
        ref_raw = _require(entry, "reference", where)
        reference = Reference(
            name=str(_require(ref_raw, "name", f"{where} reference")),
            year=str(ref_raw.get("year", "")),
            url=str(_require(ref_raw, "url", f"{where} reference")),
            kind=str(ref_raw.get("kind", "")),
        )
        terms = tuple(str(t) for t in entry.get("terms", []))
        for term in terms:
            if term not in glossary:
                raise CatalogError(f"{where}: term '{term}' is not in the glossary")
        checks = tuple(str(c) for c in _require(entry, "expected_checks", where))
        platforms = tuple(str(p) for p in _require(entry, "platforms", where))
        trigger = str(_require(entry, "trigger", where))
        script = triggers_dir / trigger
        duration, accepts, pid_name = (0.0, False, None)
        if script.is_file():
            duration, accepts, pid_name = _script_metadata(script)
        scenarios[key] = Scenario(
            key=key,
            trigger=trigger,
            title=str(_require(entry, "title", where)),
            one_liner=str(_require(entry, "one_liner", where)),
            reference=reference,
            see_in_edamame=str(_require(entry, "see_in_edamame", where)),
            appears_within=str(_require(entry, "appears_within", where)),
            talk_track=str(_require(entry, "talk_track", where)),
            terms=terms,
            needs_admin=bool(entry.get("needs_admin", False)),
            platforms=platforms,
            expected_checks=checks,
            gate_scenarios=tuple(str(g) for g in entry.get("gate_scenarios", [])),
            script=script if script.is_file() else None,
            default_duration=duration,
            accepts_duration=accepts,
            pid_file_name=pid_name or f"{key}.pid",
        )

    themes_raw = _require(raw, "themes", "catalog")
    themes: List[Theme_] = []
    for t in themes_raw:
        ids = tuple(str(s) for s in _require(t, "scenarios", "theme"))
        for sid in ids:
            if sid not in scenarios:
                raise CatalogError(f"theme '{t.get('id')}' references unknown scenario '{sid}'")
        themes.append(
            Theme_(
                id=str(_require(t, "id", "theme")),
                title=str(_require(t, "title", "theme")),
                summary=str(t.get("summary", "")),
                scenarios=ids,
            )
        )

    demo = _require(raw, "demo_path", "catalog")
    steps = []
    for s in demo.get("steps", []):
        sid = str(_require(s, "scenario", "demo step"))
        if sid not in scenarios:
            raise CatalogError(f"demo_path references unknown scenario '{sid}'")
        steps.append(DemoStep(scenario=sid, note=str(s.get("note", ""))))

    safety = _require(raw, "safety", "catalog")
    return Catalog(
        version=str(raw.get("catalog_version", "")),
        scenarios=scenarios,
        themes=themes,
        glossary=glossary,
        demo_title=str(demo.get("title", "Guided demo")),
        demo_intro=str(demo.get("intro", "")),
        demo_steps=steps,
        demo_closing=str(demo.get("closing", "")),
        safety_headline=str(_require(safety, "headline", "safety")),
        safety_summary=str(_require(safety, "summary", "safety")),
        safety_scenario_note=str(_require(safety, "scenario_note", "safety")),
        safety_points=[str(p) for p in _require(safety, "points", "safety")],
    )


def load_app_texts() -> Dict[str, str]:
    path = app_resources_dir() / "app_texts.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (OSError, ValueError):
        pass
    return {
        "name": "EDAMAME Attack Simulator",
        "tagline": "Watch EDAMAME catch real-world attack techniques on this machine, safely.",
        "intro": "",
        "requirements": "",
        "where_to_look": "Open EDAMAME Security and go to Security > Detections.",
        "admin_note": "",
    }


# ---------------------------------------------------------------------------
# Expectations: what EDAMAME should raise, derived from the catalog's checks
# ---------------------------------------------------------------------------

KIND_FINDING = "finding"
KIND_BLACKLIST = "blacklisted_session"
KIND_DIVERGENCE = "divergence"


@dataclass(frozen=True)
class Expectation:
    kind: str
    check: str = ""  # finding check, or divergence evidence category

    @property
    def label(self) -> str:
        if self.kind == KIND_BLACKLIST:
            return "blacklisted_sessions"
        return self.check or "finding"


def expectations_for(scenario: Scenario) -> Tuple[Expectation, ...]:
    out: List[Expectation] = []
    for check in scenario.expected_checks:
        if check == "blacklisted_sessions":
            out.append(Expectation(KIND_BLACKLIST))
        elif check.startswith(("correlation:", "policy:")):
            out.append(Expectation(KIND_DIVERGENCE, check=check))
        else:
            out.append(Expectation(KIND_FINDING, check=check))
    return tuple(out)


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------


def read_pid(pid_file: Optional[Path]) -> Optional[int]:
    if pid_file is None or not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _windows_process_alive(pid: int) -> bool:
    import ctypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) == 0:
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def process_alive(pid: int) -> bool:
    if IS_WINDOWS:
        try:
            return _windows_process_alive(pid)
        except OSError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _unlink(path: Optional[Path]) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _no_window_kwargs() -> Dict[str, Any]:
    if IS_WINDOWS:
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def _windows_kill_tree(pid: int) -> str:
    result = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False, **_no_window_kwargs(),
    )
    if result.returncode == 0:
        return f"stopped pid {pid} tree"
    detail = (result.stderr or result.stdout or "").strip().replace("\n", " ")
    return f"could not stop pid {pid}: {detail}" if detail else f"already stopped (pid {pid})"


def kill_pid(pid: int, pid_file: Optional[Path]) -> str:
    if IS_WINDOWS:
        detail = _windows_kill_tree(pid)
        _unlink(pid_file)
        return detail
    try:
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            _unlink(pid_file)
            return f"already stopped (pid {pid})"
        if pgid == pid and pgid != os.getpgrp():
            os.killpg(pgid, signal.SIGTERM)
            detail = f"stopped process group {pgid}"
        else:
            os.kill(pid, signal.SIGTERM)
            detail = f"stopped pid {pid}"
    except ProcessLookupError:
        detail = f"already stopped (pid {pid})"
    except PermissionError:
        return f"permission denied killing pid {pid}"
    except OSError as exc:
        return f"could not stop pid {pid}: {exc}"
    _unlink(pid_file)
    return detail


def kill_process_group(proc: "subprocess.Popen[str]", force: bool = False) -> str:
    if proc.poll() is not None:
        return f"already stopped (pid {proc.pid})"
    if IS_WINDOWS:
        return _windows_kill_tree(proc.pid)
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        return f"already stopped (pid {proc.pid})"
    except PermissionError:
        return f"permission denied stopping pid {proc.pid}"
    except OSError as exc:
        return f"could not stop pid {proc.pid}: {exc}"
    return f"{'killed' if force else 'stopped'} process group {proc.pid}"


# ---------------------------------------------------------------------------
# Cleanup streaming (unit-testable, UI-free)
# ---------------------------------------------------------------------------


def classify_cleanup_line(line: str) -> str:
    """Tag a cleanup.py output line: 'removed', 'blocked', or 'info'.

    'blocked' is a file/process cleanup could not touch as the current user
    (usually something a trigger installed as root). Surfaced so an incomplete
    cleanup is visible instead of looking silently stuck."""
    stripped = line.strip().lower()
    if stripped.startswith("removed ") or " removed " in stripped:
        return "removed"
    if (
        "cannot remove" in stripped
        or "could not" in stripped
        or "permission denied" in stripped
        or "cannot kill" in stripped
        or stripped.startswith("left ")
        or "cannot restore" in stripped
        or "cannot read" in stripped
    ):
        return "blocked"
    return "info"


def _terminate_process_tree(proc: "subprocess.Popen") -> None:
    try:
        if IS_WINDOWS:
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def run_and_stream(cmd, cwd, on_line, timeout_secs=CLEANUP_TIMEOUT_SECS):
    """Run ``cmd``, deliver each output line to ``on_line``, enforce a timeout.

    A watchdog kills the process group after ``timeout_secs`` even when the
    child produces no output (a silent hang), so the read loop always ends.
    Returns ``(returncode, timed_out)``. Pure of UI, so it is unit-testable."""
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        start_new_session=not IS_WINDOWS, **_no_window_kwargs(),
    )
    timed_out = threading.Event()

    def _watchdog() -> None:
        timed_out.set()
        _terminate_process_tree(proc)

    watchdog = threading.Timer(timeout_secs, _watchdog)
    watchdog.daemon = True
    watchdog.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            text = line.rstrip()
            if text:
                on_line(text)
        returncode = proc.wait()
    finally:
        watchdog.cancel()
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
    return returncode, timed_out.is_set()


# ---------------------------------------------------------------------------
# Run state
# ---------------------------------------------------------------------------


class Phase:
    STARTING = "starting"
    ACTIVE = "active"
    STOPPING = "stopping"
    FINISHED = "finished"
    FAILED = "failed"
    LIVE = (STARTING, ACTIVE, STOPPING)


DET_PENDING = "pending"
DET_UNREACHABLE = "unreachable"
DET_WAITING = "waiting"
DET_EARLIER = "earlier"
DET_BELOW = "below"
DET_DETECTED = "detected"
DET_RANK = {
    DET_PENDING: 0, DET_UNREACHABLE: 1, DET_WAITING: 2,
    DET_EARLIER: 3, DET_BELOW: 4, DET_DETECTED: 5,
}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class ExpectationStatus:
    status: str = DET_PENDING
    severity: str = ""
    detail: str = ""
    detected_after: Optional[float] = None


@dataclass
class Detection:
    per_expectation: Dict[str, ExpectationStatus] = field(default_factory=dict)
    checks: int = 0
    last_checked: Optional[float] = None
    baseline: Optional[Set[str]] = None
    error: str = ""

    def overall(self) -> ExpectationStatus:
        best = ExpectationStatus()
        for status in self.per_expectation.values():
            if DET_RANK[status.status] > DET_RANK[best.status]:
                best = status
        return best

    def all_detected(self, expectations: Sequence[Expectation]) -> bool:
        return bool(expectations) and all(
            self.per_expectation.get(e.label, ExpectationStatus()).status == DET_DETECTED
            for e in expectations
        )


_RUN_SERIAL = itertools.count(1)


@dataclass
class TriggerRun:
    scenario: Scenario
    agent_type: str
    state_dir: Path
    duration: float
    duration_arg: Optional[int]
    serial: int = field(default_factory=lambda: next(_RUN_SERIAL))
    command: List[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)
    started_wall: datetime = field(default_factory=datetime.now)
    phase: str = Phase.STARTING
    proc: Optional["subprocess.Popen[str]"] = None
    pid: Optional[int] = None
    banner_seen: bool = False
    last_line: str = ""
    lines: int = 0
    exit_code: Optional[int] = None
    ended_at: Optional[float] = None
    stop_reason: str = ""
    error: str = ""
    detection: Detection = field(default_factory=Detection)
    logged_detection: Dict[str, str] = field(default_factory=dict)

    @property
    def live(self) -> bool:
        return self.phase in Phase.LIVE

    def elapsed(self, now: Optional[float] = None) -> float:
        end = self.ended_at if self.ended_at is not None else (now or time.monotonic())
        return max(0.0, end - self.started_at)

    def fraction(self, now: Optional[float] = None) -> Optional[float]:
        if self.duration <= 0:
            return None
        return min(1.0, self.elapsed(now) / self.duration)


def fmt_clock(seconds: float) -> str:
    total = int(max(0.0, seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def fmt_span(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 60 and seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute" + ("s" if minutes != 1 else "")
    return f"{seconds} s"


def classify_output(text: str) -> str:
    low = text.lower()
    if (
        "traceback" in low or low.startswith("error") or " error" in low
        or "refused" in low or "failed" in low or "permission denied" in low
        or "cannot " in low
    ):
        return "err"
    if "[warn]" in low or "warning" in low or "[skip]" in low or "skipped" in low:
        return "warn"
    return "out"


# ---------------------------------------------------------------------------
# EDAMAME watch: read-only checks through edamame_cli
# ---------------------------------------------------------------------------


def locate_edamame_cli(cli_module: Any) -> Optional[str]:
    for var in ("EDAMAME_CLI_BIN", "EDAMAME_CLI"):
        value = os.environ.get(var, "").strip()
        if value and os.path.isfile(value) and os.access(value, os.X_OK):
            return value
    if cli_module is not None:
        try:
            return str(cli_module.find_cli_binary())
        except (FileNotFoundError, OSError):
            pass
    for name in ("edamame_cli", "edamame-cli"):
        found = shutil.which(name)
        if found:
            return found
    if not IS_WINDOWS:
        for directory in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"):
            for name in ("edamame_cli", "edamame-cli"):
                candidate = os.path.join(directory, name)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return candidate
    return None


def edamame_cli_version(cli: str) -> Optional[Tuple[int, int, int]]:
    import re

    try:
        result = subprocess.run(
            [cli, "--version"], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=15, check=False, **_no_window_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def probe_environment(triggers_dir: Path) -> Dict[str, Any]:
    """Best-effort, read-only look at how EDAMAME is deployed here, so the
    simulator can warn before running demos on a managed / Hub-connected
    device. Uses only read-only RPCs (get_connection,
    get_managed_configuration_status). Never raises."""
    info: Dict[str, Any] = {
        "available": False, "connected": False, "domain": "",
        "managed": False, "organization": "",
    }
    try:
        cli_mod = load_trigger_module(triggers_dir, "_edamame_cli")
    except Exception:
        return info

    def rpc(method: str) -> Any:
        try:
            return cli_mod.cli_rpc(method, timeout=10.0, retries=0)
        except Exception:
            return None

    conn = rpc("get_connection")
    if isinstance(conn, dict):
        info["available"] = True
        info["connected"] = bool(conn.get("is_connected"))
        info["domain"] = str(conn.get("connected_domain") or "")
    managed = rpc("get_managed_configuration_status")
    if isinstance(managed, dict):
        info["available"] = True
        info["managed"] = bool(managed.get("managed"))
        info["organization"] = str(managed.get("organization_name") or "")
    return info


@dataclass(frozen=True)
class WatchTarget:
    key: str
    serial: int
    expectations: Tuple[Expectation, ...]


class EdamameWatch:
    """Background reader of EDAMAME's findings for the scenarios being run.

    Only read-only RPCs are used (findings, blacklisted sessions, divergence
    verdict, protection status). The simulator never clears or dismisses
    anything in EDAMAME: that is the operator's call, in the EDAMAME app."""

    def __init__(self, triggers_dir: Path, post: Callable[[tuple], None]) -> None:
        self.triggers_dir = triggers_dir
        self._post = post
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._enabled = True
        self._targets: List[WatchTarget] = []
        self._cli: Optional[str] = None
        self._cli_module: Any = None
        self._match_module: Any = None
        self._polls = 0
        threading.Thread(target=self._run, name="edamame-watch", daemon=True).start()

    def configure(self, enabled: bool, targets: List[WatchTarget]) -> None:
        with self._lock:
            turned_on = enabled and not self._enabled
            self._enabled = enabled
            self._targets = list(targets)
        if turned_on:
            self._wake.set()

    def poke(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        if not self._probe():
            return
        while True:
            self._wake.wait(WATCH_INTERVAL_S)
            self._wake.clear()
            with self._lock:
                enabled = self._enabled
                targets = list(self._targets)
            if enabled and targets:
                try:
                    self._poll(targets)
                except Exception as exc:
                    self._post(("watch_result", {}, None, [f"internal error: {exc}"]))

    def _unavailable(self, reason: str, cli: str = "") -> bool:
        self._post(("watch_status", False, reason, cli))
        return False

    def _probe(self) -> bool:
        try:
            self._cli_module = load_trigger_module(self.triggers_dir, "_edamame_cli")
            self._match_module = load_trigger_module(self.triggers_dir, "_finding_match")
        except Exception as exc:
            return self._unavailable(f"the triggers' helper modules did not load ({exc})")
        cli = locate_edamame_cli(self._cli_module)
        if not cli:
            return self._unavailable(
                "edamame_cli not found -- watch in the EDAMAME app instead"
            )
        version = edamame_cli_version(cli)
        if version is None:
            return self._unavailable(f"could not read the version of {cli}", cli)
        shown = ".".join(str(part) for part in version)
        if version < MIN_SAFE_CLI_VERSION:
            minimum = ".".join(str(part) for part in MIN_SAFE_CLI_VERSION)
            return self._unavailable(
                f"edamame_cli {shown} is older than {minimum}; update it to watch from here", cli
            )
        self._cli = cli
        self._post(("watch_status", True, f"edamame_cli {shown}", cli))
        return True

    def _rpc(self, method: str) -> Any:
        assert self._cli is not None
        result = subprocess.run(
            [self._cli, "rpc", method], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=CLI_TIMEOUT_S, check=False, **_no_window_kwargs(),
        )
        if result.returncode != 0:
            lines = (result.stderr or result.stdout or "").strip().splitlines()
            message = lines[-1] if lines else f"exit code {result.returncode}"
            raise RuntimeError(message[:200])
        return self._cli_module._parse_cli_output(result.stdout or "")

    def _poll(self, targets: List[WatchTarget]) -> None:
        kinds = {e.kind for t in targets for e in t.expectations}
        errors: Dict[str, str] = {}
        findings: List[Any] = []
        sessions: List[Any] = []
        verdict: Dict[str, Any] = {}

        def fetch(kind: str, method: str) -> Any:
            try:
                return self._rpc(method)
            except subprocess.TimeoutExpired:
                errors[kind] = f"{method} timed out"
            except Exception as exc:
                errors[kind] = f"{method}: {exc}"
            return None

        if KIND_FINDING in kinds:
            findings = self._match_module.findings_of(fetch(KIND_FINDING, "get_attack_pattern_findings"))
        if KIND_BLACKLIST in kinds:
            value = fetch(KIND_BLACKLIST, "get_blacklisted_sessions")
            sessions = value if isinstance(value, list) else []
        if KIND_DIVERGENCE in kinds:
            value = fetch(KIND_DIVERGENCE, "get_divergence_verdict")
            verdict = value if isinstance(value, dict) else {}

        protection = None
        if self._polls % 4 == 0:
            try:
                value = self._rpc("agentic_get_protection_status")
                protection = value if isinstance(value, dict) else None
            except Exception:
                protection = None
        self._polls += 1

        results: Dict[Tuple[str, int], Dict[str, Dict[str, Any]]] = {}
        for target in targets:
            per: Dict[str, Dict[str, Any]] = {}
            for exp in target.expectations:
                if exp.kind in errors:
                    per[exp.label] = {"hits": [], "error": errors[exp.kind]}
                else:
                    per[exp.label] = {"hits": self._hits(exp, findings, sessions, verdict), "error": ""}
            results[(target.key, target.serial)] = per
        self._post(("watch_result", results, protection, sorted(set(errors.values()))))

    def _hits(self, exp: Expectation, findings, sessions, verdict) -> List[Dict[str, Any]]:
        match = self._match_module
        hits: List[Dict[str, Any]] = []
        if exp.kind == KIND_FINDING:
            for finding in findings:
                if not match.matches(finding, exp.check, (), ()):
                    continue
                hits.append({
                    "key": str(finding.get("finding_key") or finding.get("description") or ""),
                    "severity": match.normalize_severity(finding),
                    "alertable": match.is_alertable(finding),
                    "dismissed": match.is_dismissed(finding),
                    "text": " ".join(str(finding.get("description") or "").split())[:220],
                })
        elif exp.kind == KIND_BLACKLIST:
            for item in sessions:
                if not isinstance(item, dict):
                    continue
                session = item.get("session") or {}
                status = item.get("status") or {}
                if status.get("active"):
                    dst = session.get("dst_ip")
                    hits.append({
                        "key": f"session:{item.get('uid') or dst}",
                        "severity": "", "alertable": True, "dismissed": False,
                        "text": f"active session to {dst}:{session.get('dst_port')}",
                    })
        elif exp.kind == KIND_DIVERGENCE:
            deterministic = str(verdict.get("deterministic_verdict") or "").strip().upper()
            for evidence in verdict.get("evidence") or []:
                if not isinstance(evidence, dict):
                    continue
                if exp.check and str(evidence.get("category") or "") != exp.check:
                    continue
                description = str(evidence.get("description") or "")
                severity = str(evidence.get("severity") or "").strip().upper()
                dismissed = bool(evidence.get("dismissed"))
                hits.append({
                    "key": str(evidence.get("finding_key") or description),
                    "severity": severity,
                    "alertable": deterministic == "DIVERGENCE" and not dismissed
                    and severity in match.ALERTABLE_SEVERITIES,
                    "dismissed": dismissed,
                    "text": " ".join(description.split())[:220],
                })
        return hits


# ---------------------------------------------------------------------------
# Look and feel
# ---------------------------------------------------------------------------


class Theme:
    # Dark only, fixed rather than derived from the OS appearance, so the
    # simulator looks the same on macOS, Windows and Linux (the configurable
    # ``clam`` ttk theme is styled explicitly). Slate surfaces, one teal
    # accent; text and glyphs on a filled color use the ON_* inks.
    BG = "#0E1116"
    SURFACE = "#161B22"
    SURFACE_ALT = "#1C222B"
    BORDER = "#2A313C"
    BORDER_STRONG = "#3D4652"
    TEXT = "#E6EDF3"
    MUTED = "#9DA7B3"
    SUBTLE = "#848D97"
    PRIMARY = "#2BD6C6"
    PRIMARY_HOVER = "#5BE3D6"
    PRIMARY_PRESSED = "#1F9E93"
    PRIMARY_SOFT = "#0F2D2A"
    SUCCESS = "#3FB950"
    SUCCESS_SOFT = "#12261A"
    WARNING = "#D29922"
    WARNING_SOFT = "#2A2111"
    DANGER = "#F85149"
    DANGER_HOVER = "#FF7B72"
    DANGER_SOFT = "#2D1517"
    DANGER_FILL = "#DA3633"
    DANGER_FILL_HOVER = "#B62324"
    INFO = "#58A6FF"
    INFO_SOFT = "#121D33"
    SELECTED = "#13302C"
    TRACK = "#262D37"
    LOG_BG = "#0B0E13"
    LINK = "#2BD6C6"
    ON_PRIMARY = "#06211E"
    ON_FILL = "#0D1117"
    ON_DANGER = "#FFFFFF"
    TOOLTIP_BG = "#2D333B"
    TOOLTIP_FG = "#E6EDF3"

    MONO_PREFERENCES = (
        "SF Mono", "Menlo", "Cascadia Mono", "Consolas", "DejaVu Sans Mono",
        "Liberation Mono", "Ubuntu Mono",
    )

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        try:
            dpi = float(root.winfo_fpixels("1i"))
        except tk.TclError:
            dpi = 96.0
        self.scale = 1.0 if IS_MACOS else max(1.0, dpi / 96.0)
        self._build_fonts()
        self._build_styles()

    def px(self, value: float) -> int:
        return int(round(value * self.scale))

    def _build_fonts(self) -> None:
        default = tkfont.nametofont("TkDefaultFont")
        family = default.actual("family")
        size = int(default.cget("size")) or 10
        fixed = tkfont.nametofont("TkFixedFont")
        fixed_size = int(fixed.cget("size")) or size
        try:
            available = set(tkfont.families(self.root))
        except tk.TclError:
            available = set()
        mono_family = next((f for f in self.MONO_PREFERENCES if f in available), fixed.actual("family"))

        def grow(base: int, delta: int) -> int:
            if base > 0:
                return max(8, base + delta)
            return min(-10, base - round(delta * 4 / 3))

        def make(sz: int, weight: str = "normal", fam: str = family) -> tkfont.Font:
            return tkfont.Font(root=self.root, family=fam, size=sz, weight=weight)

        self.body = make(size)
        self.body_bold = make(size, "bold")
        self.small = make(grow(size, -1))
        self.small_bold = make(grow(size, -1), "bold")
        self.caption = make(grow(size, -2), "bold")
        self.h3 = make(grow(size, 2), "bold")
        self.h2 = make(grow(size, 4), "bold")
        self.title = make(grow(size, 7), "bold")
        self.logo = make(grow(size, 6), "bold")
        self.mono = make(grow(fixed_size, -1), fam=mono_family)
        self.mono_small = make(grow(fixed_size, -2), fam=mono_family)
        self.link = make(size, "normal")
        self.link.configure(underline=True)
        self.root.option_add("*Font", self.body)

    def _build_styles(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.style = style
        c = self

        style.configure(
            ".", background=c.BG, foreground=c.TEXT, font=self.body,
            bordercolor=c.BORDER, darkcolor=c.BG, lightcolor=c.BG, troughcolor=c.TRACK,
            focuscolor=c.PRIMARY, selectbackground=c.PRIMARY_SOFT, selectforeground=c.TEXT,
            insertcolor=c.TEXT,
        )
        style.configure("TFrame", background=c.BG)
        style.configure("TLabel", background=c.BG, foreground=c.TEXT)
        style.configure("TSeparator", background=c.BORDER)

        def flat(name, base, hover, pressed, fg, border, disabled_bg, font, padding):
            style.configure(
                name, background=base, foreground=fg, bordercolor=border,
                lightcolor=base, darkcolor=base, relief="solid", borderwidth=1,
                padding=padding, font=font, focusthickness=1, focuscolor=hover, anchor="center",
            )
            states = [("disabled", disabled_bg), ("pressed", pressed), ("active", hover)]
            style.map(
                name, background=states, lightcolor=states, darkcolor=states,
                foreground=[("disabled", c.SUBTLE)],
                bordercolor=[("disabled", c.BORDER), ("focus", c.PRIMARY), ("active", border)],
            )

        pad = (self.px(14), self.px(6))
        small_pad = (self.px(10), self.px(3))
        flat("TButton", c.SURFACE, c.SURFACE_ALT, c.TRACK, c.TEXT, c.BORDER_STRONG, c.SURFACE_ALT, self.body, pad)
        flat("Primary.TButton", c.PRIMARY, c.PRIMARY_HOVER, c.PRIMARY_PRESSED, c.ON_PRIMARY, c.PRIMARY, c.TRACK, self.body_bold, pad)
        flat("Danger.TButton", c.DANGER_FILL, c.DANGER_FILL_HOVER, c.DANGER_FILL_HOVER, c.ON_DANGER, c.DANGER_FILL, c.TRACK, self.body_bold, pad)
        flat("DangerOutline.TButton", c.SURFACE, c.DANGER_SOFT, c.DANGER_SOFT, c.DANGER, c.DANGER, c.SURFACE_ALT, self.body_bold, pad)
        flat("Ghost.TButton", c.SURFACE, c.PRIMARY_SOFT, c.PRIMARY_SOFT, c.PRIMARY, c.SURFACE, c.SURFACE, self.body, (self.px(10), self.px(6)))
        flat("Small.Primary.TButton", c.PRIMARY, c.PRIMARY_HOVER, c.PRIMARY_PRESSED, c.ON_PRIMARY, c.PRIMARY, c.TRACK, self.small_bold, small_pad)
        flat("Small.Danger.TButton", c.DANGER_FILL, c.DANGER_FILL_HOVER, c.DANGER_FILL_HOVER, c.ON_DANGER, c.DANGER_FILL, c.TRACK, self.small_bold, small_pad)
        flat("Small.TButton", c.SURFACE, c.SURFACE_ALT, c.TRACK, c.TEXT, c.BORDER_STRONG, c.SURFACE_ALT, self.small, small_pad)

        for name, color in (
            ("Accent", c.PRIMARY), ("Success", c.SUCCESS), ("Warning", c.WARNING),
            ("Danger", c.DANGER), ("Muted", c.SUBTLE),
        ):
            style.configure(
                f"{name}.Horizontal.TProgressbar", troughcolor=c.TRACK, background=color,
                bordercolor=c.TRACK, lightcolor=color, darkcolor=color, thickness=self.px(6),
            )

        style.configure(
            "TCombobox", fieldbackground=c.SURFACE, background=c.SURFACE, foreground=c.TEXT,
            arrowcolor=c.MUTED, bordercolor=c.BORDER_STRONG, lightcolor=c.SURFACE,
            darkcolor=c.SURFACE, padding=(self.px(8), self.px(4)),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", c.SURFACE), ("disabled", c.SURFACE_ALT)],
            background=[("disabled", c.SURFACE_ALT), ("active", c.SURFACE)],
            foreground=[("disabled", c.SUBTLE)],
            bordercolor=[("focus", c.PRIMARY), ("active", c.PRIMARY)],
            lightcolor=[("focus", c.SURFACE)],
            selectbackground=[("readonly", c.SURFACE)],
            selectforeground=[("readonly", c.TEXT)],
            arrowcolor=[("disabled", c.SUBTLE)],
        )
        self.root.option_add("*TCombobox*Listbox.background", c.SURFACE)
        self.root.option_add("*TCombobox*Listbox.foreground", c.TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", c.PRIMARY_SOFT)
        self.root.option_add("*TCombobox*Listbox.selectForeground", c.TEXT)
        self.root.option_add("*TCombobox*Listbox.font", self.body)

        style.configure("TEntry", fieldbackground=c.SURFACE, foreground=c.TEXT, bordercolor=c.BORDER_STRONG, lightcolor=c.SURFACE, darkcolor=c.SURFACE, padding=(self.px(8), self.px(5)))
        style.map("TEntry", bordercolor=[("focus", c.PRIMARY)], lightcolor=[("focus", c.PRIMARY_SOFT)])

        style.configure(
            "Surface.TCheckbutton", background=c.SURFACE, foreground=c.TEXT,
            indicatorbackground=c.SURFACE, indicatorforeground=c.ON_PRIMARY,
            upperbordercolor=c.BORDER_STRONG, lowerbordercolor=c.BORDER_STRONG, focuscolor=c.SURFACE,
        )
        style.map(
            "Surface.TCheckbutton", background=[("active", c.SURFACE)],
            indicatorbackground=[("disabled", c.SURFACE_ALT), ("selected", c.PRIMARY)],
            upperbordercolor=[("selected", c.PRIMARY)], lowerbordercolor=[("selected", c.PRIMARY)],
            foreground=[("disabled", c.SUBTLE)],
        )

        style.configure(
            "Vertical.TScrollbar", background=c.BORDER, troughcolor=c.SURFACE, bordercolor=c.SURFACE,
            lightcolor=c.BORDER, darkcolor=c.BORDER, arrowcolor=c.MUTED, gripcount=0,
        )
        style.map("Vertical.TScrollbar", background=[("active", c.BORDER_STRONG)])
        style.configure("Panel.Vertical.TScrollbar", troughcolor=c.BG, bordercolor=c.BG)
        style.configure("Surface.Vertical.TScrollbar", troughcolor=c.SURFACE, bordercolor=c.SURFACE)

        style.configure("TPanedwindow", background=c.BG)
        style.configure("Sash", sashthickness=self.px(10), gripcount=0, background=c.BG, lightcolor=c.BG, darkcolor=c.BG, bordercolor=c.BG)


def make_card(parent: tk.Misc, theme: Theme) -> tk.Frame:
    return tk.Frame(
        parent, bg=theme.SURFACE, highlightthickness=1, highlightbackground=theme.BORDER,
        highlightcolor=theme.BORDER, bd=0,
    )


def round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw) -> int:
    points = [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
        x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kw)


class Tooltip:
    """Hover tooltip for any widget (glossary terms, buttons, status chips)."""

    def __init__(self, widget: tk.Widget, text: str, theme: Theme, delay: int = 450) -> None:
        self.widget = widget
        self.text = text
        self.theme = theme
        self.delay = delay
        self._after: Optional[str] = None
        self._tip: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def set_text(self, text: str) -> None:
        self.text = text

    def _schedule(self, _e: Any = None) -> None:
        self._cancel()
        self._after = self.widget.after(self.delay, self._show)

    def _show(self) -> None:
        if self._tip is not None or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + self.theme.px(10)
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + self.theme.px(4)
        except tk.TclError:
            return
        self._tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        try:
            tw.wm_attributes("-topmost", True)
        except tk.TclError:
            pass
        tw.wm_geometry(f"+{x}+{y}")
        outer = tk.Frame(tw, bg=self.theme.BORDER_STRONG, bd=0)
        outer.pack()
        tk.Label(
            outer, text=self.text, bg=self.theme.TOOLTIP_BG, fg=self.theme.TOOLTIP_FG, font=self.theme.small,
            justify="left", wraplength=self.theme.px(300),
            padx=self.theme.px(9), pady=self.theme.px(7),
        ).pack(padx=1, pady=1)

    def _hide(self, _e: Any = None) -> None:
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except tk.TclError:
                pass
            self._tip = None

    def _cancel(self) -> None:
        if self._after is not None:
            try:
                self.widget.after_cancel(self._after)
            except tk.TclError:
                pass
            self._after = None


class Dot(tk.Canvas):
    def __init__(self, parent: tk.Misc, theme: Theme, bg: str) -> None:
        size = theme.px(10)
        super().__init__(parent, width=size + 4, height=size + 4, bg=bg, highlightthickness=0, bd=0)
        self._oval = self.create_oval(2, 2, size + 2, size + 2, fill=theme.BORDER_STRONG, outline="")
        self._color = theme.BORDER_STRONG

    def set(self, color: str) -> None:
        if color != self._color:
            self._color = color
            self.itemconfigure(self._oval, fill=color)


class StepIcon(tk.Canvas):
    def __init__(self, parent: tk.Misc, theme: Theme, bg: str) -> None:
        self.theme = theme
        self._size = theme.px(20)
        super().__init__(parent, width=self._size, height=self._size, bg=bg, highlightthickness=0, bd=0)
        self._state = ""
        self.set("pending")

    def set(self, state: str) -> None:
        if state == self._state:
            return
        self._state = state
        t = self.theme
        self.delete("all")
        width = max(2, t.px(2))
        if state == "pending":
            self.create_oval(3, 3, 17, 17, outline=t.BORDER_STRONG, width=width)
        elif state == "active":
            self.create_oval(2, 2, 18, 18, outline=t.PRIMARY, width=width)
            self.create_oval(7, 7, 13, 13, fill=t.PRIMARY, outline="")
        elif state == "done":
            self.create_oval(1, 1, 19, 19, fill=t.SUCCESS, outline="")
            self.create_line(6, 10.5, 9, 13.5, 14.5, 7, fill=t.ON_FILL, width=width, capstyle="round", joinstyle="round")
        elif state == "warn":
            self.create_oval(1, 1, 19, 19, fill=t.WARNING, outline="")
            self.create_line(10, 5.5, 10, 11.5, fill=t.ON_FILL, width=width, capstyle="round")
            self.create_oval(9, 13.5, 11, 15.5, fill=t.ON_FILL, outline="")
        elif state == "failed":
            self.create_oval(1, 1, 19, 19, fill=t.DANGER, outline="")
            self.create_line(7, 7, 13, 13, fill=t.ON_FILL, width=width, capstyle="round")
            self.create_line(13, 7, 7, 13, fill=t.ON_FILL, width=width, capstyle="round")
        elif state == "info":
            self.create_oval(1, 1, 19, 19, fill=t.INFO, outline="")
            self.create_oval(9, 4.5, 11, 6.5, fill=t.ON_FILL, outline="")
            self.create_line(10, 9, 10, 15, fill=t.ON_FILL, width=width, capstyle="round")
        else:  # skipped
            self.create_oval(1, 1, 19, 19, fill=t.TRACK, outline="")
            self.create_line(6.5, 10, 13.5, 10, fill=t.SUBTLE, width=width, capstyle="round")
        factor = self._size / 20.0
        if factor != 1.0:
            self.scale("all", 0, 0, factor, factor)


# ---------------------------------------------------------------------------
# Scenario card (left column)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CardView:
    dot: str
    status: str
    status_color: str
    bar: Optional[str] = None
    bar_value: float = 0.0
    bar_style: str = "Accent.Horizontal.TProgressbar"
    button_text: str = "Start"
    button_style: str = "Small.Primary.TButton"
    button_enabled: bool = True


class ScenarioCard:
    def __init__(self, parent: tk.Misc, app: "AttackSimulator", scenario: Scenario) -> None:
        t = app.theme
        self.app = app
        self.scenario = scenario
        self.theme = t
        self.selected = False
        self._view: Optional[CardView] = None
        self._bar_mode: Optional[str] = None

        self.frame = tk.Frame(
            parent, bg=t.SURFACE, highlightthickness=1, highlightbackground=t.BORDER,
            highlightcolor=t.BORDER, padx=t.px(13), pady=t.px(11), cursor="hand2",
        )
        self.frame.columnconfigure(1, weight=1)
        self.dot = Dot(self.frame, t, t.SURFACE)
        self.dot.grid(row=0, column=0, rowspan=3, sticky="n", padx=(0, t.px(10)), pady=(t.px(3), 0))

        titlebar = tk.Frame(self.frame, bg=t.SURFACE)
        titlebar.grid(row=0, column=1, sticky="ew")
        self.title = tk.Label(titlebar, text=scenario.title, font=t.body_bold, bg=t.SURFACE, fg=t.TEXT, anchor="w", justify="left")
        self.title.pack(side="left", anchor="w")
        if scenario.needs_admin:
            self.admin = tk.Label(titlebar, text="needs admin", font=t.caption, bg=t.WARNING_SOFT, fg=t.WARNING, padx=t.px(6), pady=t.px(1))
            self.admin.pack(side="left", padx=(t.px(8), 0))
            Tooltip(self.admin, app.texts.get("admin_note", "Needs an administrator password."), t)
        self.one_liner = tk.Label(self.frame, text=scenario.one_liner, font=t.small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left")
        self.one_liner.grid(row=1, column=1, sticky="ew", pady=(t.px(2), 0))

        self.status = tk.Label(self.frame, text="Ready", font=t.small_bold, bg=t.SURFACE, fg=t.SUBTLE, anchor="e")
        self.status.grid(row=0, column=2, sticky="e", padx=(t.px(10), t.px(10)))
        self.bar = ttk.Progressbar(self.frame, length=t.px(120), mode="determinate", maximum=100, style="Accent.Horizontal.TProgressbar")
        self.bar.grid(row=1, column=2, sticky="e", padx=(t.px(10), t.px(10)), pady=(t.px(4), 0))
        self.bar.grid_remove()
        self.button = ttk.Button(self.frame, text="Start", width=6, style="Small.Primary.TButton", command=self._on_button)
        self.button.grid(row=0, column=3, rowspan=3, sticky="e")

        for w in (self.frame, self.dot, self.title, self.one_liner, self.status):
            w.bind("<Button-1>", self._on_click)
        self.frame.bind("<Configure>", self._on_resize, add="+")
        self._wrap = 0

    def _on_resize(self, event: Any) -> None:
        # Wrap the title and one-liner to the text column so nothing clips at
        # the card edge, at any pane width down to a 13" laptop.
        t = self.theme
        wrap = max(t.px(170), event.width - t.px(270))
        if abs(wrap - self._wrap) < 4:
            return
        self._wrap = wrap
        self.title.configure(wraplength=wrap)
        self.one_liner.configure(wraplength=wrap)

    def matches(self, needle: str) -> bool:
        # A scenario whose trigger script is absent from this build is hidden
        # from the catalog unless Engineer details is on (then it shows as
        # "Not in this build" so an engineer can see what is missing).
        if not self.scenario.available and not self.app.engineer_var.get():
            return False
        if not needle:
            return True
        s = self.scenario
        haystack = " ".join((s.title, s.key, s.one_liner, " ".join(s.terms), s.reference.name)).lower()
        return needle in haystack

    def _on_click(self, _e: Any = None) -> None:
        self.app.select(self.scenario.key)

    def _on_button(self) -> None:
        self.app.select(self.scenario.key)
        self.app.toggle_scenario(self.scenario.key)

    def set_selected(self, selected: bool) -> None:
        if selected == self.selected:
            return
        self.selected = selected
        t = self.theme
        bg = t.SELECTED if selected else t.SURFACE
        self.frame.configure(bg=bg, highlightbackground=t.PRIMARY if selected else t.BORDER, highlightcolor=t.PRIMARY if selected else t.BORDER)
        for w in (self.dot, self.title, self.one_liner, self.status):
            w.configure(bg=bg)
        for child in self.frame.winfo_children():
            if isinstance(child, tk.Frame):
                child.configure(bg=bg)
                for g in child.winfo_children():
                    if isinstance(g, tk.Label) and g.cget("text") != "needs admin":
                        g.configure(bg=bg)

    def update(self, view: CardView) -> None:
        if view == self._view:
            return
        self._view = view
        self.dot.set(view.dot)
        self.status.configure(text=view.status, fg=view.status_color)
        if view.bar is None:
            if self._bar_mode == "indeterminate":
                self.bar.stop()
            self.bar.grid_remove()
            self._bar_mode = None
        else:
            if view.bar != self._bar_mode:
                if self._bar_mode == "indeterminate":
                    self.bar.stop()
                self.bar.configure(mode=view.bar)
                if view.bar == "indeterminate":
                    self.bar.start(30)
                self._bar_mode = view.bar
                self.bar.grid()
            self.bar.configure(style=view.bar_style)
            if view.bar == "determinate":
                self.bar.configure(value=view.bar_value)
        self.button.configure(text=view.button_text, style=view.button_style)
        self.button.state(["!disabled"] if view.button_enabled else ["disabled"])


class CatalogList:
    """Scrollable, searchable catalog of scenario cards, grouped by theme."""

    def __init__(self, parent: tk.Misc, app: "AttackSimulator") -> None:
        t = app.theme
        self.app = app
        self.theme = t
        self.outer = tk.Frame(parent, bg=t.BG)

        top = tk.Frame(self.outer, bg=t.BG)
        top.pack(fill="x", pady=(0, t.px(8)))
        tk.Label(top, text="Scenarios", font=t.h2, bg=t.BG, fg=t.TEXT).pack(side="left")
        self.count = tk.Label(top, text="", font=t.small, bg=t.BG, fg=t.SUBTLE)
        self.count.pack(side="left", padx=(t.px(8), 0), pady=(t.px(4), 0))
        self.search_var = tk.StringVar()
        search = ttk.Entry(top, textvariable=self.search_var, width=24)
        search.pack(side="right")
        tk.Label(top, text="Filter", font=t.small, bg=t.BG, fg=t.MUTED).pack(side="right", padx=(0, t.px(6)))
        self.search_var.trace_add("write", lambda *_: self.apply_filter())

        body = tk.Frame(self.outer, bg=t.BG)
        body.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(body, bg=t.BG, highlightthickness=0, bd=0, yscrollincrement=t.px(18))
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.canvas.yview, style="Panel.Vertical.TScrollbar")
        self.inner = tk.Frame(self.canvas, bg=t.BG)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._window, width=e.width))
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y", padx=(t.px(6), 0))

        self.cards: Dict[str, ScenarioCard] = {}
        self.groups: "collections.OrderedDict[str, Tuple[Theme_, List[ScenarioCard]]]" = collections.OrderedDict()
        self.group_labels: Dict[str, tk.Frame] = {}
        for theme in app.catalog.themes:
            card_list: List[ScenarioCard] = []
            for sid in theme.scenarios:
                scenario = app.catalog.scenarios[sid]
                card = ScenarioCard(self.inner, app, scenario)
                self.cards[sid] = card
                card_list.append(card)
            self.groups[theme.id] = (theme, card_list)
            header = tk.Frame(self.inner, bg=t.BG)
            lbl = tk.Label(header, text=theme.title.upper(), font=t.caption, bg=t.BG, fg=t.SUBTLE, anchor="w")
            lbl.pack(side="left")
            cnt = tk.Label(header, text="", font=t.caption, bg=t.BG, fg=t.SUBTLE, anchor="w")
            cnt.pack(side="left", padx=(t.px(8), 0))
            if theme.summary:
                Tooltip(lbl, theme.summary, t)
            self.group_labels[theme.id] = header
            header._count = cnt  # type: ignore[attr-defined]
        self.empty = tk.Label(self.inner, text="No scenario matches the filter.", font=t.body, bg=t.BG, fg=t.MUTED)
        self.apply_filter()

    def apply_filter(self) -> None:
        t = self.theme
        needle = self.search_var.get().strip().lower()
        for header in self.group_labels.values():
            header.pack_forget()
        for card in self.cards.values():
            card.frame.pack_forget()
        self.empty.pack_forget()
        shown = 0
        first = True
        for theme_id, (theme, cards) in self.groups.items():
            visible = [c for c in cards if c.matches(needle)]
            if not visible:
                continue
            header = self.group_labels[theme_id]
            header._count.configure(text=str(len(visible)))  # type: ignore[attr-defined]
            header.pack(fill="x", pady=(t.px(2) if first else t.px(14), t.px(6)))
            first = False
            for card in visible:
                card.frame.pack(fill="x", pady=(0, t.px(6)))
            shown += len(visible)
        if not shown:
            self.empty.pack(fill="x", pady=t.px(24))
        total = len(self.cards)
        self.count.configure(text=f"{total}" if shown == total else f"{shown} of {total}")
        self.canvas.yview_moveto(0.0)

    def contains(self, widget: Optional[tk.Misc]) -> bool:
        while widget is not None:
            if widget is self.canvas:
                return True
            widget = getattr(widget, "master", None)
        return False

    def scroll(self, units: int) -> None:
        if self.canvas.yview() != (0.0, 1.0):
            self.canvas.yview_scroll(units, "units")


# ---------------------------------------------------------------------------
# Detail pane (right column) -- the sales surface
# ---------------------------------------------------------------------------


class DetailPane:
    STEPS = (
        ("launch", "Launch"),
        ("setup", "Set up"),
        ("activity", "Generate activity"),
        ("detection", "EDAMAME detection"),
        ("finish", "Finish"),
    )

    def __init__(self, parent: tk.Misc, app: "AttackSimulator") -> None:
        t = app.theme
        self.app = app
        self.theme = t
        self.frame = make_card(parent, t)

        # Scrollable body.
        holder = tk.Frame(self.frame, bg=t.SURFACE)
        holder.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(holder, bg=t.SURFACE, highlightthickness=0, bd=0, yscrollincrement=t.px(18))
        sb = ttk.Scrollbar(holder, orient="vertical", command=self.canvas.yview, style="Surface.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        body = tk.Frame(self.canvas, bg=t.SURFACE, padx=t.px(22), pady=t.px(18))
        self._window = self.canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._on_canvas)
        self.body = body

        head = tk.Frame(body, bg=t.SURFACE)
        head.pack(fill="x")
        self.title_label = tk.Label(head, font=t.h2, bg=t.SURFACE, fg=t.TEXT, anchor="w", justify="left")
        self.title_label.pack(side="left", fill="x", expand=True)
        self.admin_chip = tk.Label(head, text="needs admin", font=t.small_bold, bg=t.WARNING_SOFT, fg=t.WARNING, padx=t.px(8), pady=t.px(2))

        self.simulation_note = tk.Label(body, text="\U0001F6E1  " + app.catalog.safety_scenario_note, font=t.small_bold, bg=t.SURFACE, fg=t.SUCCESS, anchor="w", justify="left")
        self.simulation_note.pack(fill="x", pady=(t.px(4), 0))
        self.one_liner = tk.Label(body, font=t.body, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left")
        self.one_liner.pack(fill="x", pady=(t.px(6), t.px(12)))

        # Live detection banner (the demo's climax).
        self.detect_banner = tk.Frame(body, bg=t.SUCCESS_SOFT)
        self.detect_icon = tk.Label(self.detect_banner, text="\u2713", font=t.h2, bg=t.SUCCESS_SOFT, fg=t.SUCCESS)
        self.detect_icon.pack(side="left", padx=(t.px(12), t.px(10)), pady=t.px(10))
        self.detect_text = tk.Label(self.detect_banner, font=t.h3, bg=t.SUCCESS_SOFT, fg=t.SUCCESS, anchor="w", justify="left")
        self.detect_text.pack(side="left", fill="x", expand=True, pady=t.px(10), padx=(0, t.px(12)))

        self._section(body, "What you'll see in EDAMAME")
        self.see_label = tk.Label(body, font=t.body, bg=t.SURFACE, fg=t.TEXT, anchor="w", justify="left")
        self.see_label.pack(fill="x")
        self.appears_label = tk.Label(body, font=t.small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left")
        self.appears_label.pack(fill="x", pady=(t.px(4), t.px(0)))

        self._divider(body)
        self._section(body, "Real-world reference")
        self.ref_label = tk.Label(body, font=t.link, bg=t.SURFACE, fg=t.LINK, anchor="w", justify="left", cursor="hand2")
        self.ref_label.pack(fill="x")
        self.ref_label.bind("<Button-1>", lambda _e: self._open_reference())
        self.ref_hint = tk.Label(body, text="Opens the public write-up in your browser.", font=t.caption, bg=t.SURFACE, fg=t.SUBTLE, anchor="w")
        self.ref_hint.pack(fill="x", pady=(t.px(2), 0))

        self._divider(body)
        self._section(body, "Talk track")
        talk_wrap = tk.Frame(body, bg=t.SURFACE)
        talk_wrap.pack(fill="x")
        self.talk_label = tk.Label(talk_wrap, font=t.body, bg=t.SURFACE, fg=t.TEXT, anchor="w", justify="left")
        self.talk_label.pack(fill="x")
        self.copy_talk_btn = ttk.Button(body, text="Copy talk track", style="Ghost.TButton", command=self._copy_talk)
        self.copy_talk_btn.pack(anchor="w", pady=(t.px(8), 0))

        self.terms_header_frame = tk.Frame(body, bg=t.SURFACE)
        self.terms_frame = tk.Frame(body, bg=t.SURFACE)

        # Progress steps.
        self._divider(body)
        self._section(body, "Progress")
        steps = tk.Frame(body, bg=t.SURFACE)
        steps.pack(fill="x")
        steps.columnconfigure(1, weight=1)
        self.step_widgets: Dict[str, Tuple[StepIcon, tk.Label, tk.Label]] = {}
        for index, (key, name) in enumerate(self.STEPS):
            icon = StepIcon(steps, t, t.SURFACE)
            icon.grid(row=2 * index, column=0, rowspan=2, sticky="n", padx=(0, t.px(12)), pady=(t.px(1), 0))
            label = tk.Label(steps, text=name, font=t.body_bold, bg=t.SURFACE, fg=t.TEXT, anchor="w")
            label.grid(row=2 * index, column=1, sticky="ew")
            detail = tk.Label(steps, text="", font=t.small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left")
            detail.grid(row=2 * index + 1, column=1, sticky="ew", pady=(t.px(1), t.px(10)))
            self.step_widgets[key] = (icon, label, detail)

        progress = tk.Frame(body, bg=t.SURFACE)
        progress.pack(fill="x", pady=(t.px(2), 0))
        self.bar = ttk.Progressbar(progress, mode="determinate", maximum=100, style="Accent.Horizontal.TProgressbar")
        self.bar.pack(side="left", fill="x", expand=True)
        self.time_label = tk.Label(progress, font=t.small_bold, bg=t.SURFACE, fg=t.MUTED, anchor="e")
        self.time_label.pack(side="right", padx=(t.px(12), 0))
        self._bar_mode = "determinate"

        self._divider(body)
        actions = tk.Frame(body, bg=t.SURFACE)
        actions.pack(fill="x")
        self.action_button = ttk.Button(actions, text="Start", style="Primary.TButton", width=12, command=self._on_action)
        self.action_button.pack(side="left")
        Tooltip(self.action_button, "Start or stop this scenario on this machine.", t)

        # Engineer details (hidden unless toggled).
        self._eng_divider = tk.Frame(body, bg=t.BORDER, height=1)
        self.eng_frame = tk.Frame(body, bg=t.SURFACE)
        tk.Label(self.eng_frame, text="ENGINEER DETAILS", font=t.caption, bg=t.SURFACE, fg=t.SUBTLE, anchor="w").pack(fill="x", pady=(0, t.px(6)))
        self.eng_meta = tk.Label(self.eng_frame, font=t.mono_small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left")
        self.eng_meta.pack(fill="x")
        eng_actions = tk.Frame(self.eng_frame, bg=t.SURFACE)
        eng_actions.pack(fill="x", pady=(t.px(8), 0))
        self.output_button = ttk.Button(eng_actions, text="Show its output", style="Ghost.TButton", command=self._on_output)
        self.output_button.pack(side="left")
        self.copy_cmd_button = ttk.Button(eng_actions, text="Copy command", style="Ghost.TButton", command=self._on_copy_cmd)
        self.copy_cmd_button.pack(side="left", padx=(t.px(6), 0))

        self._shown_key: Optional[str] = None
        self._wrap = 420
        self._eng_visible = False

    def _on_canvas(self, event: Any) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
        wrap = max(240, event.width - self.theme.px(52))
        if abs(wrap - self._wrap) < 4:
            return
        self._wrap = wrap
        self._apply_wraps()

    def _apply_wraps(self) -> None:
        w = self._wrap
        for lbl in (self.one_liner, self.see_label, self.appears_label, self.ref_label,
                    self.talk_label, self.eng_meta, self.detect_text, self.title_label,
                    self.simulation_note):
            lbl.configure(wraplength=w)
        for _i, _l, detail in self.step_widgets.values():
            detail.configure(wraplength=w - self.theme.px(32))

    def _section(self, parent: tk.Misc, text: str) -> None:
        t = self.theme
        tk.Label(parent, text=text.upper(), font=t.caption, bg=t.SURFACE, fg=t.SUBTLE, anchor="w").pack(fill="x", pady=(0, t.px(6)))

    def _divider(self, parent: tk.Misc) -> None:
        tk.Frame(parent, bg=self.theme.BORDER, height=1).pack(fill="x", pady=self.theme.px(14))

    def _on_action(self) -> None:
        if self._shown_key:
            self.app.toggle_scenario(self._shown_key)

    def _on_output(self) -> None:
        self.app.show_engineer_output()

    def _on_copy_cmd(self) -> None:
        if self._shown_key:
            self.app.copy_command(self._shown_key)

    def _copy_talk(self) -> None:
        if self._shown_key:
            self.app.copy_talk_track(self._shown_key)

    def _open_reference(self) -> None:
        if self._shown_key:
            self.app.open_reference(self._shown_key)

    def set_engineer_visible(self, visible: bool) -> None:
        self._eng_visible = visible
        if visible:
            self._eng_divider.pack(fill="x", pady=self.theme.px(14))
            self.eng_frame.pack(fill="x")
        else:
            self._eng_divider.pack_forget()
            self.eng_frame.pack_forget()

    def _rebuild_static(self, scenario: Scenario) -> None:
        t = self.theme
        self.title_label.configure(text=scenario.title)
        if scenario.needs_admin:
            self.admin_chip.pack(side="right")
        else:
            self.admin_chip.pack_forget()
        self.one_liner.configure(text=scenario.one_liner)
        self.see_label.configure(text=scenario.see_in_edamame)
        self.appears_label.configure(text=f"Appears {scenario.appears_within}.")
        self.ref_label.configure(text=scenario.reference.display)
        self.talk_label.configure(text=scenario.talk_track)
        Tooltip(self.ref_label, scenario.reference.url, t)

        for child in self.terms_frame.winfo_children():
            child.destroy()
        for child in self.terms_header_frame.winfo_children():
            child.destroy()
        if scenario.terms:
            self.terms_header_frame.pack(fill="x", after=self.copy_talk_btn, pady=(t.px(14), 0))
            tk.Label(self.terms_header_frame, text="JARGON", font=t.caption, bg=t.SURFACE, fg=t.SUBTLE, anchor="w").pack(fill="x", pady=(0, t.px(6)))
            self.terms_frame.pack(fill="x", after=self.terms_header_frame)
            row = tk.Frame(self.terms_frame, bg=t.SURFACE)
            row.pack(fill="x", anchor="w")
            for term in scenario.terms:
                chip = tk.Label(row, text=term_label(term), font=t.small_bold, bg=t.PRIMARY_SOFT, fg=t.PRIMARY, padx=t.px(9), pady=t.px(3), cursor="hand2")
                chip.pack(side="left", padx=(0, t.px(6)), pady=(0, t.px(4)))
                Tooltip(chip, self.app.catalog.glossary.get(term, term), t)
        else:
            self.terms_header_frame.pack_forget()
            self.terms_frame.pack_forget()
        self._apply_wraps()

    def show(self, scenario: Scenario, steps, bar, time_text, action, detect, meta, copy_cmd_enabled) -> None:
        if scenario.key != self._shown_key:
            self._shown_key = scenario.key
            self._rebuild_static(scenario)
        t = self.theme

        # Detection banner.
        if detect is not None:
            text, color, soft = detect
            self.detect_banner.configure(bg=soft)
            self.detect_icon.configure(bg=soft, fg=color)
            self.detect_text.configure(text=text, bg=soft, fg=color)
            if not self.detect_banner.winfo_ismapped():
                self.detect_banner.pack(fill="x", pady=(0, t.px(12)), after=self.one_liner)
        else:
            self.detect_banner.pack_forget()

        for key, (state, detail) in steps.items():
            icon, label, detail_label = self.step_widgets[key]
            icon.set(state)
            label.configure(fg=t.SUBTLE if state == "pending" else t.TEXT)
            detail_label.configure(text=detail)

        mode, value, style = bar
        if mode is None:
            mode, value = "determinate", 0.0
        if mode != self._bar_mode:
            if self._bar_mode == "indeterminate":
                self.bar.stop()
            self.bar.configure(mode=mode)
            if mode == "indeterminate":
                self.bar.start(25)
            self._bar_mode = mode
        self.bar.configure(style=style)
        if mode == "determinate":
            self.bar.configure(value=value)
        self.time_label.configure(text=time_text)

        atext, astyle, aenabled = action
        self.action_button.configure(text=atext, style=astyle)
        self.action_button.state(["!disabled"] if aenabled else ["disabled"])
        self.eng_meta.configure(text=meta)
        self.copy_cmd_button.state(["!disabled"] if copy_cmd_enabled else ["disabled"])


# ---------------------------------------------------------------------------
# Activity log (engineer surface)
# ---------------------------------------------------------------------------


class ActivityLog:
    FILTER_ALL = "All scenarios"
    FILTER_SELECTED = "Selected scenario only"

    def __init__(self, parent: tk.Misc, app: "AttackSimulator") -> None:
        t = app.theme
        self.app = app
        self.theme = t
        self.frame = make_card(parent, t)
        header = tk.Frame(self.frame, bg=t.SURFACE, padx=t.px(14), pady=t.px(8))
        header.pack(fill="x")
        tk.Label(header, text="Activity", font=t.body_bold, bg=t.SURFACE, fg=t.TEXT).pack(side="left")
        self.count = tk.Label(header, text="", font=t.small, bg=t.SURFACE, fg=t.SUBTLE)
        self.count.pack(side="left", padx=(t.px(8), 0))
        ttk.Button(header, text="Clear", style="Ghost.TButton", command=self.clear).pack(side="right")
        self.filter_var = tk.StringVar(value=self.FILTER_ALL)
        combo = ttk.Combobox(header, textvariable=self.filter_var, state="readonly", width=22, values=(self.FILTER_ALL, self.FILTER_SELECTED))
        combo.pack(side="right", padx=(0, t.px(6)))
        combo.bind("<<ComboboxSelected>>", lambda _e: self.rerender())
        tk.Frame(self.frame, bg=t.BORDER, height=1).pack(fill="x")

        text_frame = tk.Frame(self.frame, bg=t.LOG_BG)
        text_frame.pack(fill="both", expand=True)
        self.text = tk.Text(
            text_frame, wrap="word", font=t.mono_small, bg=t.LOG_BG, fg=t.TEXT, bd=0,
            highlightthickness=0, padx=t.px(12), pady=t.px(8), height=7, state="disabled",
            selectbackground=t.PRIMARY_SOFT, selectforeground=t.TEXT, insertwidth=0,
        )
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        self.text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for tag, color in (("ts", t.SUBTLE), ("src", t.PRIMARY), ("srcsys", t.INFO), ("out", t.TEXT),
                           ("cmd", t.MUTED), ("sys", t.INFO), ("ok", t.SUCCESS), ("warn", t.WARNING), ("err", t.DANGER)):
            self.text.tag_configure(tag, foreground=color)
        self.records: "collections.deque[Tuple[str, Optional[str], str, str, str]]" = collections.deque(maxlen=LOG_MAX_LINES)

    def _passes(self, key: Optional[str]) -> bool:
        if self.filter_var.get() != self.FILTER_SELECTED:
            return True
        return key is None or key == self.app.selected_key

    def add(self, key, source, message, level="out") -> None:
        record = (time.strftime("%H:%M:%S"), key, source, message.rstrip(), level)
        self.records.append(record)
        if self._passes(key):
            self._insert([record])
        self.count.configure(text=f"{len(self.records)} lines")

    def _insert(self, records) -> None:
        at_end = self.text.yview()[1] >= 0.999
        self.text.configure(state="normal")
        for stamp, key, source, message, level in records:
            label = source if len(source) <= 26 else source[:25] + "~"
            self.text.insert("end", f"{stamp}  ", "ts")
            self.text.insert("end", f"{label:<27}", "src" if key else "srcsys")
            self.text.insert("end", message + "\n", level)
        excess = int(self.text.index("end-1c").split(".")[0]) - LOG_MAX_LINES
        if excess > 0:
            self.text.delete("1.0", f"{excess + 1}.0")
        self.text.configure(state="disabled")
        if at_end:
            self.text.see("end")

    def rerender(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self._insert([r for r in self.records if self._passes(r[1])])
        self.text.see("end")

    def clear(self) -> None:
        self.records.clear()
        self.rerender()
        self.count.configure(text="")

    def show_selected(self) -> None:
        self.filter_var.set(self.FILTER_SELECTED)
        self.rerender()


# ---------------------------------------------------------------------------
# Cleanup dialog
# ---------------------------------------------------------------------------


class CleanupDialog(tk.Toplevel):
    STEPS = (
        ("stop", "Stop running scenarios"),
        ("restore", "Put back configs the scenarios replaced"),
        ("remove", "Remove files the scenarios created"),
        ("state", "Remove the demo state directory"),
    )

    def __init__(self, app: "AttackSimulator", agent_type: str, state_dir: Path) -> None:
        super().__init__(app)
        t = app.theme
        self.app = app
        self.theme = t
        self.state_dir = state_dir
        self.title("Run cleanup")
        self.configure(bg=t.SURFACE)
        self.transient(app)
        self.minsize(t.px(480), t.px(440))
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        body = tk.Frame(self, bg=t.SURFACE, padx=t.px(22), pady=t.px(18))
        body.pack(fill="both", expand=True)
        self.heading = tk.Label(body, text="Cleaning up", font=t.h2, bg=t.SURFACE, fg=t.TEXT, anchor="w")
        self.heading.pack(fill="x")
        tk.Label(body, text=f"Agent type {agent_type}  \u00b7  {state_dir}", font=t.small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left", wraplength=t.px(460)).pack(fill="x", pady=(t.px(4), t.px(14)))

        steps = tk.Frame(body, bg=t.SURFACE)
        steps.pack(fill="x")
        steps.columnconfigure(1, weight=1)
        self.step_widgets: Dict[str, Tuple[StepIcon, tk.Label]] = {}
        for index, (key, name) in enumerate(self.STEPS):
            icon = StepIcon(steps, t, t.SURFACE)
            icon.grid(row=index, column=0, sticky="w", padx=(0, t.px(12)), pady=t.px(4))
            tk.Label(steps, text=name, font=t.body, bg=t.SURFACE, fg=t.TEXT, anchor="w").grid(row=index, column=1, sticky="w")
            count = tk.Label(steps, text="", font=t.small_bold, bg=t.SURFACE, fg=t.MUTED, anchor="e")
            count.grid(row=index, column=2, sticky="e")
            self.step_widgets[key] = (icon, count)

        self.bar = ttk.Progressbar(body, mode="indeterminate", style="Accent.Horizontal.TProgressbar")
        self.bar.pack(fill="x", pady=(t.px(14), t.px(6)))
        self.bar.start(15)
        self.status = tk.Label(body, text="Running cleanup.py...", font=t.small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left", wraplength=t.px(460))
        self.status.pack(fill="x")

        output = tk.Frame(body, bg=t.LOG_BG, highlightthickness=1, highlightbackground=t.BORDER)
        output.pack(fill="both", expand=True, pady=(t.px(12), t.px(12)))
        self.output = tk.Text(output, height=8, wrap="word", font=t.mono_small, bg=t.LOG_BG, fg=t.TEXT, bd=0, highlightthickness=0, padx=t.px(10), pady=t.px(6), state="disabled")
        self.output.pack(fill="both", expand=True)
        self.output.tag_configure("warn", foreground=t.WARNING)

        footer = tk.Frame(body, bg=t.SURFACE)
        footer.pack(fill="x")
        self.close_button = ttk.Button(footer, text="Close", style="Primary.TButton", command=self._on_close)
        self.close_button.pack(side="right")
        self.close_button.state(["disabled"])

        self.counts = {key: 0 for key, _ in self.STEPS}
        self.problems = {key: 0 for key, _ in self.STEPS}
        self.current = "stop"
        self.nothing_to_do = False
        self.done = False
        self._set_states()
        self.update_idletasks()
        x = app.winfo_rootx() + max(0, (app.winfo_width() - self.winfo_reqwidth()) // 2)
        y = app.winfo_rooty() + max(0, (app.winfo_height() - self.winfo_reqheight()) // 3)
        self.geometry(f"+{x}+{y}")

    def _classify(self, line: str) -> Tuple[Optional[str], bool]:
        text = line.strip()
        if text.startswith("killed "):
            return "stop", False
        if text.startswith(("could not kill", "cannot kill")):
            return "stop", True
        if text.startswith(("restored ", "backup missing")):
            return "restore", False
        if text.startswith("cannot restore"):
            return "restore", True
        if text == f"removed {self.state_dir}":
            return "state", False
        if text.startswith("state dir not empty"):
            return "state", True
        if text.startswith(("removed ",)):
            return "remove", False
        if text.startswith(("left ", "cannot remove", "cannot read")):
            return "remove", True
        return None, False

    def feed(self, line: str) -> None:
        if "nothing to clean up" in line.lower():
            self.nothing_to_do = True
        step, problem = self._classify(line)
        order = [key for key, _ in self.STEPS]
        if step is not None:
            if order.index(step) > order.index(self.current):
                self.current = step
            if problem:
                self.problems[step] += 1
            else:
                self.counts[step] += 1
        self.output.configure(state="normal")
        self.output.insert("end", line.rstrip() + "\n", "warn" if problem else ())
        self.output.see("end")
        self.output.configure(state="disabled")
        self._set_states()

    def _count_text(self, key: str) -> str:
        done, problems = self.counts[key], self.problems[key]
        noun = {"stop": "stopped", "restore": "restored", "remove": "removed", "state": "removed"}[key]
        parts = []
        if done:
            parts.append(f"{done} {noun}" if key != "state" else "removed")
        if problems:
            parts.append(f"{problems} left")
        return ", ".join(parts)

    def _set_states(self) -> None:
        order = [key for key, _ in self.STEPS]
        current_index = order.index(self.current)
        for index, key in enumerate(order):
            icon, count = self.step_widgets[key]
            if self.done:
                if self.problems[key]:
                    state = "warn"
                elif self.counts[key]:
                    state = "done"
                else:
                    state = "skipped"
            elif index < current_index:
                state = "warn" if self.problems[key] else "done"
            elif index == current_index:
                state = "active"
            else:
                state = "pending"
            icon.set(state)
            text = self._count_text(key)
            if self.done and not text:
                text = "nothing to do"
            count.configure(text=text, fg=self.theme.WARNING if self.problems[key] else self.theme.MUTED)

    def finish(self, code: Optional[int], error: str = "") -> None:
        t = self.theme
        self.done = True
        self.bar.stop()
        problems = sum(self.problems.values())
        if error or (code not in (0, None)):
            style, heading = "Danger.Horizontal.TProgressbar", "Cleanup failed"
            summary = error or f"cleanup.py exited with code {code}. See its output below."
            color = t.DANGER
        elif self.nothing_to_do:
            style, heading = "Success.Horizontal.TProgressbar", "Nothing to clean up"
            summary = "No demo state directory exists for this agent type."
            color = t.SUCCESS
        elif problems:
            style, heading = "Warning.Horizontal.TProgressbar", "Cleanup finished, with items left"
            summary = (f"{problems} item(s) were left in place. Cleanup never removes a file whose content "
                       "changed since a scenario wrote it; anything a scenario installed with administrator "
                       "rights is listed above for you to remove with 'sudo'.")
            color = t.WARNING
        else:
            style, heading = "Success.Horizontal.TProgressbar", "Cleanup complete"
            summary = (f"{self.counts['stop']} scenario(s) stopped, {self.counts['restore']} config(s) put back, "
                       f"{self.counts['remove']} file(s) removed.")
            color = t.SUCCESS
        self.bar.configure(mode="determinate", value=100, style=style)
        self.heading.configure(text=heading)
        self.status.configure(text=summary, fg=color)
        self._set_states()
        self.close_button.state(["!disabled"])
        self.close_button.focus_set()

    def _on_close(self) -> None:
        if self.done:
            self.destroy()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


class AttackSimulator(tk.Tk):
    def __init__(self, triggers_dir: Path, catalog: Catalog, texts: Dict[str, str]) -> None:
        super().__init__()
        self.withdraw()
        self.triggers_dir = triggers_dir
        self.catalog = catalog
        self.texts = texts
        self.cleanup_script = triggers_dir / "cleanup.py"
        self.theme = Theme(self)

        self.scenarios = catalog.scenarios
        self.ordered_keys = [sid for th in catalog.themes for sid in th.scenarios]
        self.runs: Dict[str, TriggerRun] = {}
        self.external: Dict[str, int] = {}
        self.events: "queue.Queue[tuple]" = queue.Queue()
        available_keys = [k for k in self.ordered_keys if self.scenarios[k].available]
        self.selected_key: Optional[str] = (
            (available_keys or self.ordered_keys)[0] if self.ordered_keys else None
        )
        self._busy = False
        self._dirty = False
        self.cleanup_dialog: Optional[CleanupDialog] = None

        # Consent + a persistent record of which agent types have been run, in
        # the per-user cache dir so it survives a reboot that clears the temp
        # state dir. Lets the quit prompt still offer cleanup afterwards.
        self._consented = False
        self._consent_dir = _cache_root()
        self._ran_ledger = self._consent_dir / "ran_agents.json"
        self._quit_after_cleanup = False

        self.watch_available: Optional[bool] = None
        self.watch_reason = "checking for edamame_cli..."
        self.watch_errors: List[str] = []
        self._last_watch_error = ""
        self.protection: Optional[Dict[str, Any]] = None

        self.agent_type = tk.StringVar(value=DEFAULT_AGENT_TYPE)
        self.run_for = tk.StringVar(value=RUN_FOR_CHOICES[0][0])
        self.watch_var = tk.BooleanVar(value=True)
        self.engineer_var = tk.BooleanVar(value=False)

        # Demo mode.
        self.demo_active = False
        self.demo_index = 0

        self.title(texts.get("name", "EDAMAME Attack Simulator"))
        t = self.theme
        self.geometry(f"{t.px(1280)}x{t.px(820)}")
        self.minsize(t.px(1040), t.px(680))
        self.configure(bg=t.BG)
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind_all("<MouseWheel>", self._on_wheel, add="+")
        self.bind_all("<Button-4>", self._on_wheel, add="+")
        self.bind_all("<Button-5>", self._on_wheel, add="+")

        self.watch = EdamameWatch(triggers_dir, self.events.put)
        if self.selected_key:
            self.select(self.selected_key)
        self._apply_engineer_visibility()
        missing = [k for k, s in self.scenarios.items() if not s.available]
        self.log_line(None, "simulator", f"{len(self.scenarios)} scenarios loaded from {triggers_dir}", "sys")
        if missing:
            self.log_line(None, "simulator", f"{len(missing)} scenario(s) have no trigger script in this build and are hidden", "warn")
        self.deiconify()
        self.after(60, self._init_sashes)
        self.after(EVENT_DRAIN_MS, self._drain_events)
        self.after(TICK_MS, self._tick)
        self.after(300, self._scan_pid_files)
        self.after(200, self._require_consent)

    # -- layout ---------------------------------------------------------

    def _build_ui(self) -> None:
        t = self.theme
        tk.Frame(self, bg=t.PRIMARY, height=t.px(3)).pack(fill="x")
        header = tk.Frame(self, bg=t.SURFACE, padx=t.px(22), pady=t.px(14))
        header.pack(fill="x")
        tk.Frame(self, bg=t.BORDER, height=1).pack(fill="x")

        size = t.px(46)
        logo = tk.Canvas(header, width=size, height=size, bg=t.SURFACE, highlightthickness=0, bd=0)
        round_rect(logo, 1, 1, size - 1, size - 1, t.px(12), fill=t.PRIMARY, outline="")
        logo.create_text(size / 2, size / 2, text="E", fill=t.ON_PRIMARY, font=t.logo)
        logo.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, t.px(14)))
        tk.Label(header, text=self.texts.get("name", "EDAMAME Attack Simulator"), font=t.title, bg=t.SURFACE, fg=t.TEXT, anchor="w").grid(row=0, column=1, sticky="sw")
        tk.Label(header, text=self.texts.get("tagline", ""), font=t.small, bg=t.SURFACE, fg=t.MUTED, anchor="w", justify="left", wraplength=t.px(560)).grid(row=1, column=1, sticky="nw", pady=(t.px(2), 0))
        header.columnconfigure(1, weight=1)

        controls = tk.Frame(header, bg=t.SURFACE)
        controls.grid(row=0, column=2, rowspan=2, sticky="e")
        actions = tk.Frame(controls, bg=t.SURFACE)
        actions.pack(anchor="e")
        self.demo_button = ttk.Button(actions, text="Start 10-minute demo", style="Primary.TButton", command=self.toggle_demo)
        self.demo_button.pack(side="left")
        Tooltip(self.demo_button, "Walk the recommended sequence of scenarios, one step at a time.", t)
        self.stop_all_button = ttk.Button(actions, text="Stop all", command=self.stop_all)
        self.stop_all_button.pack(side="left", padx=(t.px(8), 0))
        Tooltip(self.stop_all_button, "Stop every scenario that is running.", t)
        self.cleanup_button = ttk.Button(actions, text="Run cleanup", style="DangerOutline.TButton", command=self.run_cleanup)
        self.cleanup_button.pack(side="left", padx=(t.px(8), 0))
        Tooltip(self.cleanup_button, "Stop everything and remove the demo files the scenarios created.", t)

        options = tk.Frame(controls, bg=t.SURFACE)
        options.pack(anchor="e", pady=(t.px(10), 0))
        self.watch_check = ttk.Checkbutton(options, text="Watch EDAMAME", variable=self.watch_var, style="Surface.TCheckbutton", command=self._on_watch_toggle)
        self.watch_check.pack(side="left")
        Tooltip(self.watch_check, "Poll EDAMAME (via edamame_cli) and confirm each detection here, live.", t)
        self.engineer_check = ttk.Checkbutton(options, text="Engineer details", variable=self.engineer_var, style="Surface.TCheckbutton", command=self._apply_engineer_visibility)
        self.engineer_check.pack(side="left", padx=(t.px(16), 0))
        Tooltip(self.engineer_check, "Show the script, check names, pid, raw output, agent type and run duration.", t)

        # Engineer-only controls (agent type, run duration) revealed on toggle.
        self.eng_controls = tk.Frame(options, bg=t.SURFACE)
        tk.Label(self.eng_controls, text="Agent", font=t.small, bg=t.SURFACE, fg=t.MUTED).pack(side="left", padx=(t.px(16), 0))
        self.agent_combo = ttk.Combobox(self.eng_controls, textvariable=self.agent_type, values=AGENT_TYPES, state="readonly", width=14)
        self.agent_combo.pack(side="left", padx=(t.px(6), t.px(12)))
        self.agent_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_agent_change())
        tk.Label(self.eng_controls, text="Run for", font=t.small, bg=t.SURFACE, fg=t.MUTED).pack(side="left")
        self.run_for_combo = ttk.Combobox(self.eng_controls, textvariable=self.run_for, values=[c[0] for c in RUN_FOR_CHOICES], state="readonly", width=13)
        self.run_for_combo.pack(side="left", padx=(t.px(6), 0))

        # Safety banner.
        safety = tk.Frame(self, bg=t.SUCCESS_SOFT)
        safety.pack(fill="x")
        inner = tk.Frame(safety, bg=t.SUCCESS_SOFT, padx=t.px(22), pady=t.px(8))
        inner.pack(fill="x")
        tk.Label(inner, text="\U0001F6E1", font=t.h3, bg=t.SUCCESS_SOFT, fg=t.SUCCESS).pack(side="left", padx=(0, t.px(8)), anchor="n")
        self.safety_toggle = ttk.Button(inner, text="Why it's safe", style="Ghost.TButton", command=self._show_safety)
        self.safety_toggle.pack(side="right", anchor="n")
        texts = tk.Frame(inner, bg=t.SUCCESS_SOFT)
        texts.pack(side="left", fill="x", expand=True)
        tk.Label(texts, text=self.catalog.safety_headline, font=t.body_bold, bg=t.SUCCESS_SOFT, fg=t.SUCCESS, anchor="w", justify="left").pack(fill="x")
        self.safety_summary_label = tk.Label(texts, text=self.catalog.safety_summary, font=t.small, bg=t.SUCCESS_SOFT, fg=t.SUCCESS, anchor="w", justify="left")
        self.safety_summary_label.pack(fill="x")
        texts.bind("<Configure>", lambda e: self.safety_summary_label.configure(wraplength=max(t.px(200), e.width - t.px(8))))

        # Demo bar (hidden until demo mode).
        self.demo_bar = tk.Frame(self, bg=t.PRIMARY_SOFT)
        self.demo_inner = tk.Frame(self.demo_bar, bg=t.PRIMARY_SOFT, padx=t.px(22), pady=t.px(9))
        self.demo_inner.pack(fill="x")
        self.demo_step_label = tk.Label(self.demo_inner, font=t.small_bold, bg=t.PRIMARY_SOFT, fg=t.PRIMARY, anchor="w", justify="left")
        self.demo_step_label.pack(side="left", fill="x", expand=True)
        # Button attributes are suffixed _btn so they do not shadow the
        # demo_next / demo_prev methods of the same name.
        self.demo_prev_btn = ttk.Button(self.demo_inner, text="Back", style="Small.TButton", command=self.demo_prev)
        self.demo_prev_btn.pack(side="right", padx=(t.px(6), 0))
        self.demo_next_btn = ttk.Button(self.demo_inner, text="Next step", style="Small.Primary.TButton", command=self.demo_next)
        self.demo_next_btn.pack(side="right", padx=(t.px(6), 0))
        self.demo_exit_btn = ttk.Button(self.demo_inner, text="Exit demo", style="Small.TButton", command=self.exit_demo)
        self.demo_exit_btn.pack(side="right", padx=(t.px(6), 0))

        # Status chips.
        strip = tk.Frame(self, bg=t.BG, padx=t.px(22), pady=t.px(10))
        strip.pack(fill="x")
        self.chip_running = self._chip(strip)
        self.chip_detected = self._chip(strip)
        self.chip_watch = self._chip(strip)
        self.chip_protection = self._chip(strip)
        for chip in (self.chip_running, self.chip_detected, self.chip_watch):
            chip.pack(side="left", padx=(0, t.px(8)))
        Tooltip(self.chip_watch, "Whether the simulator can read EDAMAME's findings live through edamame_cli.", t)
        Tooltip(self.chip_detected, "How many running scenarios EDAMAME has already reported.", t)

        footer = tk.Frame(self, bg=t.BG, padx=t.px(22), pady=t.px(6))
        footer.pack(fill="x", side="bottom")
        self.footer = tk.Label(footer, text="", font=t.small, bg=t.BG, fg=t.SUBTLE, anchor="w")
        self.footer.pack(fill="x")

        self.hpane = ttk.Panedwindow(self, orient="horizontal")
        self.hpane.pack(fill="both", expand=True, padx=t.px(22), pady=(0, t.px(4)))
        self.left = ttk.Panedwindow(self.hpane, orient="vertical")
        self.catalog_list = CatalogList(self.left, self)
        self.activity = ActivityLog(self.left, self)
        self.left.add(self.catalog_list.outer, weight=3)
        self.detail = DetailPane(self.hpane, self)
        self.hpane.add(self.left, weight=3)
        self.hpane.add(self.detail.frame, weight=2)
        self._update_footer()

    def _chip(self, parent: tk.Misc) -> tk.Label:
        t = self.theme
        return tk.Label(parent, text="", font=t.small_bold, bg=t.TRACK, fg=t.MUTED, padx=t.px(10), pady=t.px(4))

    def _init_sashes(self) -> None:
        self.update_idletasks()
        try:
            self.hpane.sashpos(0, int(self.hpane.winfo_width() * 0.54))
            self.left.sashpos(0, int(self.left.winfo_height() * 0.66))
        except tk.TclError:
            pass

    def _apply_engineer_visibility(self) -> None:
        on = bool(self.engineer_var.get())
        if on:
            self.eng_controls.pack(side="left")
            if not self.activity.frame.winfo_ismapped():
                try:
                    self.left.add(self.activity.frame, weight=2)
                    self.after(10, self._init_sashes)
                except tk.TclError:
                    pass
        else:
            self.eng_controls.pack_forget()
            if self.activity.frame.winfo_ismapped():
                try:
                    self.left.forget(self.activity.frame)
                except tk.TclError:
                    pass
        self.detail.set_engineer_visible(on)
        # Hidden (absent-trigger) scenarios appear only in engineer mode.
        self.catalog_list.apply_filter()
        self._update_detail()
        self._update_footer()

    def _show_safety(self) -> None:
        points = "\n\n".join(f"\u2022  {p}" for p in self.catalog.safety_points)
        body = self.catalog.safety_headline + "\n\n" + self.catalog.safety_summary + "\n\n" + points
        if self.texts.get("requirements"):
            body += "\n\n" + self.texts["requirements"]
        messagebox.showinfo("Safe by design", body, parent=self)

    def _on_wheel(self, event: Any) -> None:
        try:
            widget = self.winfo_containing(event.x_root, event.y_root)
        except (KeyError, tk.TclError):
            return
        target = None
        if self.catalog_list.contains(widget):
            target = self.catalog_list.canvas
        elif self._in_detail(widget):
            target = self.detail.canvas
        if target is None:
            return
        if getattr(event, "num", None) == 4:
            units = -1
        elif getattr(event, "num", None) == 5:
            units = 1
        elif IS_MACOS and abs(event.delta) < 120:
            units = -int(event.delta)
        else:
            units = -int(event.delta / 120) or (-1 if event.delta > 0 else 1)
        if units and target.yview() != (0.0, 1.0):
            target.yview_scroll(units, "units")

    def _in_detail(self, widget: Optional[tk.Misc]) -> bool:
        while widget is not None:
            if widget is self.detail.canvas:
                return True
            widget = getattr(widget, "master", None)
        return False

    # -- state helpers --------------------------------------------------

    def current_state_dir(self) -> Path:
        return state_dir_for(self.agent_type.get(), self.triggers_dir)

    # -- pid identity / demo-remnant tracking ---------------------------

    def _common_module(self) -> Any:
        try:
            return load_trigger_module(self.triggers_dir, "_common")
        except Exception:
            return None

    def _pid_trustworthy(self, pid: int, pid_file: Path) -> bool:
        """True unless there is positive evidence the live pid is not the one
        the trigger recorded (reused after a reboot, or by another process).
        Defaults to True when the triggers' helper is unavailable."""
        mod = self._common_module()
        fn = getattr(mod, "pid_file_is_trustworthy", None)
        if fn is None:
            return True
        try:
            return bool(fn(pid, pid_file))
        except Exception:
            return True

    def _record_agent_ran(self, agent: str) -> None:
        try:
            self._consent_dir.mkdir(parents=True, exist_ok=True)
            seen = set()
            if self._ran_ledger.is_file():
                data = json.loads(self._ran_ledger.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    seen = {str(x) for x in data}
            seen.add(agent)
            self._ran_ledger.write_text(json.dumps(sorted(seen)), encoding="utf-8")
        except (OSError, ValueError):
            pass

    def _clear_ran_ledger(self) -> None:
        try:
            self._ran_ledger.unlink()
        except OSError:
            pass

    def _has_demo_remnants(self) -> bool:
        """Whether demo files may still be on this machine: either the current
        state dir exists, or a scenario has been run (the persistent ledger),
        which still holds after a reboot that wiped the temp state dir."""
        try:
            if self.current_state_dir().exists():
                return True
        except OSError:
            pass
        try:
            if self._ran_ledger.is_file() and self._ran_ledger.stat().st_size > 2:
                return True
        except OSError:
            pass
        return False

    # -- one-time consent -----------------------------------------------

    def _consent_accepted(self) -> bool:
        try:
            data = json.loads((self._consent_dir / "consent.json").read_text(encoding="utf-8"))
            return int(data.get("accepted_version", 0)) >= CONSENT_VERSION
        except (OSError, ValueError, TypeError):
            return False

    def _save_consent(self) -> None:
        try:
            self._consent_dir.mkdir(parents=True, exist_ok=True)
            (self._consent_dir / "consent.json").write_text(
                json.dumps({"accepted_version": CONSENT_VERSION}), encoding="utf-8")
        except OSError:
            pass

    def _require_consent(self) -> None:
        """Show the one-time confirmation listing the real-home writes and the
        outbound destinations, plus a warning when this device is Hub-connected
        or under a managed policy. Blocks scenario launches until accepted."""
        if self._consented:
            return
        if self._consent_accepted():
            self._consented = True
            return

        env = probe_environment(self.triggers_dir)
        lines = [
            "The Attack Simulator runs real, attack-shaped behaviour on THIS "
            "machine so you can watch EDAMAME detect it. Before you start, please "
            "confirm you understand what it does here:",
            "",
            "On this machine it will:",
            "  • Write throwaway decoy credential and config files into your "
            "real home folders (for example .ssh, .aws, .gnupg, .kube, .cursor, "
            ".codex, .claude). One scenario adds a demo entry to .cursor/mcp.json "
            "after backing up your real file; cleanup restores it.",
            "  • Send simulated traffic to public test endpoints (for example "
            "portquiz.net) and well-known sinkhole ranges. One scenario connects to "
            "addresses listed on public threat-intel blocklists — it sends only "
            "harmless filler, never a secret.",
            "  • Ask for an administrator password for two scenarios.",
            "",
            "No real secret ever leaves this machine. Press Run cleanup when you are "
            "done and it removes the demo files (and restores anything it replaced).",
        ]
        warn_bits = []
        if env.get("connected") and env.get("domain"):
            warn_bits.append(f"connected to the EDAMAME Hub domain '{env['domain']}'")
        if env.get("managed"):
            org = env.get("organization") or "your organization"
            warn_bits.append(f"under a managed policy from {org}")
        if warn_bits:
            lines += [
                "",
                "IMPORTANT: this device is " + " and ".join(warn_bits) + ". The "
                "findings you raise here are real and may be visible to your "
                "administrator. Only continue if you are authorized to run a "
                "security demo on this device.",
            ]
        accepted = messagebox.askokcancel(
            "Before you start", "\n".join(lines), parent=self, icon="warning")
        if accepted:
            self._consented = True
            self._save_consent()
            self.log_line(None, "simulator", "confirmation accepted; scenarios enabled", "sys")
        else:
            self.log_line(None, "simulator",
                          "confirmation declined; start a scenario to see it again", "warn")

    def _run_for_seconds(self) -> Optional[int]:
        label = self.run_for.get()
        for name, seconds in RUN_FOR_CHOICES:
            if name == label:
                return seconds
        return None

    def _live_runs(self) -> List[TriggerRun]:
        return [run for run in self.runs.values() if run.live]

    def _event_run(self, key: str, serial: int) -> Optional[TriggerRun]:
        run = self.runs.get(key)
        return run if run is not None and run.serial == serial else None

    def log_line(self, key, source, message, level="out") -> None:
        self.activity.add(key, source, message, level)

    def _source(self, key: str) -> str:
        scenario = self.scenarios.get(key)
        return scenario.title if scenario else key

    def mark_dirty(self) -> None:
        self._dirty = True

    # -- user actions ---------------------------------------------------

    def select(self, key: str) -> None:
        self.selected_key = key
        for ck, card in self.catalog_list.cards.items():
            card.set_selected(ck == key)
        if self.activity.filter_var.get() == ActivityLog.FILTER_SELECTED:
            self.activity.rerender()
        self._update_detail()

    def show_engineer_output(self) -> None:
        if not self.engineer_var.get():
            self.engineer_var.set(True)
            self._apply_engineer_visibility()
        self.activity.show_selected()

    def copy_command(self, key: str) -> None:
        run = self.runs.get(key)
        if not run or not run.command:
            return
        self.clipboard_clear()
        self.clipboard_append(
            subprocess.list2cmdline(run.command) if IS_WINDOWS
            else " ".join(_shell_quote(p) for p in run.command)
        )
        self.log_line(key, self._source(key), "command copied to the clipboard", "sys")

    def copy_talk_track(self, key: str) -> None:
        scenario = self.scenarios.get(key)
        if not scenario:
            return
        self.clipboard_clear()
        self.clipboard_append(scenario.talk_track)
        self.log_line(key, scenario.title, "talk track copied to the clipboard", "sys")

    def open_reference(self, key: str) -> None:
        scenario = self.scenarios.get(key)
        if not scenario or not scenario.reference.url:
            return
        try:
            webbrowser.open(scenario.reference.url)
            self.log_line(key, scenario.title, f"opened {scenario.reference.url}", "sys")
        except Exception as exc:
            self.log_line(key, scenario.title, f"could not open the reference: {exc}", "warn")

    def toggle_scenario(self, key: str) -> None:
        run = self.runs.get(key)
        if (run is not None and run.live) or key in self.external:
            self.stop_scenario(key)
        else:
            self.start_scenario(key)

    def start_scenario(self, key: str) -> None:
        if self._busy:
            return
        if not self._consented:
            self._require_consent()
            if not self._consented:
                return
        scenario = self.scenarios[key]
        if not scenario.available:
            messagebox.showinfo("Not in this build", f"{scenario.title} has no trigger script in this build.", parent=self)
            return
        if not scenario.supported:
            messagebox.showinfo("Not available", f"{scenario.title} is not available on {SYSTEM}.", parent=self)
            return
        existing = self.runs.get(key)
        if existing is not None and existing.live:
            return
        if key in self.external:
            messagebox.showinfo("Already running", f"{scenario.title} is already running (pid {self.external[key]}), started outside this app.", parent=self)
            return
        choice = self._run_for_seconds()
        if choice is None or not scenario.accepts_duration:
            duration, duration_arg = scenario.default_duration, None
        else:
            duration, duration_arg = float(choice), int(choice)
        run = TriggerRun(
            scenario=scenario, agent_type=self.agent_type.get(), state_dir=self.current_state_dir(),
            duration=duration, duration_arg=duration_arg,
        )
        self.runs[key] = run
        self.external.pop(key, None)
        self._record_agent_ran(run.agent_type)
        plan = f"runs for {fmt_span(duration)}" if duration > 0 else "runs until you stop it"
        self.log_line(key, scenario.title, f"starting ({plan}, agent type {run.agent_type})", "sys")
        threading.Thread(target=self._launch_worker, args=(run,), daemon=True).start()
        self._sync_watch()
        self.watch.poke()
        self._update_all()

    def _launch_worker(self, run: TriggerRun) -> None:
        key, serial, post = run.scenario.key, run.serial, self.events.put
        try:
            python = runtime_python()
        except (OSError, shutil.Error) as exc:
            post(("spawn_failed", key, serial, f"could not prepare the bundled Python: {exc}"))
            return
        cmd = [python, str(run.scenario.script), "--agent-type", run.agent_type, "--state-dir", str(run.state_dir)]
        if run.duration_arg is not None:
            cmd += ["--duration", str(run.duration_arg)]
        post(("command", key, serial, cmd))
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(self.triggers_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", start_new_session=True, env=env,
            )
        except OSError as exc:
            post(("spawn_failed", key, serial, str(exc)))
            return
        post(("spawned", key, serial, proc))
        assert proc.stdout is not None
        for line in proc.stdout:
            post(("line", key, serial, line.rstrip("\r\n")))
        post(("exit", key, serial, proc.wait()))

    def stop_scenario(self, key: str, reason: str = "user") -> None:
        scenario = self.scenarios[key]
        run = self.runs.get(key)
        live = run if run is not None and run.live else None
        state_dir = live.state_dir if live else self.current_state_dir()
        proc = live.proc if live else None
        if live is not None:
            if live.phase == Phase.STOPPING:
                self._escalate_stop(live)
                return
            live.stop_reason = reason
            live.phase = Phase.STOPPING
            self.after(STOP_ESCALATE_MS, lambda r=live: self._escalate_stop(r))
        self.log_line(key, scenario.title, "stopping...", "sys")
        threading.Thread(target=self._stop_worker, args=(key, scenario.pid_file(state_dir), proc), daemon=True).start()
        self._update_all()

    def _stop_worker(self, key, pid_file, proc) -> None:
        details = []
        pid = read_pid(pid_file)
        if pid is not None:
            if self._pid_trustworthy(pid, pid_file):
                details.append(kill_pid(pid, pid_file))
            else:
                _unlink(pid_file)
                details.append(f"ignored stale pid {pid} (reused or pre-reboot)")
                pid = None
        if proc is not None and proc.poll() is None and pid != proc.pid:
            details.append(kill_process_group(proc))
        self.events.put(("stopped", key, "; ".join(details) or "it was not running"))

    def _escalate_stop(self, run: TriggerRun) -> None:
        if run.phase != Phase.STOPPING or run.proc is None or run.proc.poll() is not None:
            return
        proc = run.proc

        def worker() -> None:
            detail = kill_process_group(proc, force=True)
            self.events.put(("stopped", run.scenario.key, f"did not stop in time; {detail}"))

        threading.Thread(target=worker, daemon=True).start()

    def stop_all(self) -> None:
        keys = [run.scenario.key for run in self._live_runs() if run.phase != Phase.STOPPING]
        keys += [key for key in self.external if key not in keys]
        if not keys:
            self.log_line(None, "simulator", "no scenario is running", "sys")
            return
        for key in keys:
            self.stop_scenario(key)

    def run_cleanup(self) -> None:
        if self._busy:
            return
        agent = self.agent_type.get()
        state_dir = self.current_state_dir()
        if not messagebox.askyesno(
            "Run cleanup",
            f"Stop every running scenario and remove the demo files for agent type '{agent}'?\n\n"
            f"State directory: {state_dir}",
            parent=self,
        ):
            return
        for run in self._live_runs():
            if run.agent_type == agent:
                run.stop_reason = run.stop_reason or "cleanup"
        self._busy = True
        self.cleanup_dialog = CleanupDialog(self, agent, state_dir)
        self.log_line(None, "cleanup", f"running cleanup.py for agent type {agent}", "sys")

        def worker() -> None:
            try:
                python = runtime_python()
                cmd = [python, str(self.cleanup_script), "--agent-type", agent,
                       "--state-dir", str(state_dir), "--sweep"]
                self.events.put(("cleanup_line", "$ " + " ".join(_shell_quote(p) for p in cmd), "cmd"))
                code, timed_out = run_and_stream(
                    cmd, self.triggers_dir,
                    lambda line: self.events.put(("cleanup_line", line, "out")),
                )
                if timed_out:
                    self.events.put(("cleanup_done", None, "cleanup timed out and was stopped."))
                else:
                    self.events.put(("cleanup_done", code, ""))
            except (OSError, shutil.Error) as exc:
                self.events.put(("cleanup_done", None, f"cleanup could not start: {exc}"))

        threading.Thread(target=worker, daemon=True).start()
        self._update_all()

    # -- demo mode ------------------------------------------------------

    def toggle_demo(self) -> None:
        if self.demo_active:
            self.exit_demo()
        else:
            self.enter_demo()

    def enter_demo(self) -> None:
        if not self.catalog.demo_steps:
            messagebox.showinfo("No guided demo", "This catalog has no guided demo.", parent=self)
            return
        self.demo_active = True
        self.demo_index = 0
        self.demo_button.configure(text="Exit demo")
        if not self.demo_bar.winfo_ismapped():
            self.demo_bar.pack(fill="x", after=self.winfo_children()[3])  # after safety banner
        self._apply_demo_step()

    def exit_demo(self) -> None:
        self.demo_active = False
        self.demo_button.configure(text="Start 10-minute demo")
        if self.demo_bar.winfo_ismapped():
            self.demo_bar.pack_forget()

    def _apply_demo_step(self) -> None:
        steps = self.catalog.demo_steps
        if not (0 <= self.demo_index < len(steps)):
            return
        step = steps[self.demo_index]
        scenario = self.scenarios.get(step.scenario)
        total = len(steps)
        n = self.demo_index + 1
        title = scenario.title if scenario else step.scenario
        self.demo_step_label.configure(text=f"Demo {n}/{total}  \u00b7  {title}  —  {step.note}")
        self.demo_prev_btn.state(["!disabled"] if self.demo_index > 0 else ["disabled"])
        self.demo_next_btn.configure(text="Next step" if n < total else "Finish")
        if scenario:
            self.select(scenario.key)

    def demo_next(self) -> None:
        if self.demo_index + 1 < len(self.catalog.demo_steps):
            self.demo_index += 1
            self._apply_demo_step()
        else:
            self.exit_demo()
            if self.catalog.demo_closing:
                messagebox.showinfo("Demo finished", self.catalog.demo_closing, parent=self)

    def demo_prev(self) -> None:
        if self.demo_index > 0:
            self.demo_index -= 1
            self._apply_demo_step()

    # -- toggles --------------------------------------------------------

    def _on_agent_change(self) -> None:
        self.external.clear()
        self._scan_pid_files(reschedule=False)
        self._update_footer()
        self._update_all()

    def _on_watch_toggle(self) -> None:
        state = "on" if self.watch_var.get() else "off"
        self.log_line(None, "EDAMAME", f"watch turned {state}", "sys")
        self._sync_watch()
        self._update_all()

    def on_close(self) -> None:
        live = self._live_runs()
        if live:
            answer = messagebox.askyesnocancel(
                "Quit",
                f"{len(live)} scenario(s) started here are still running.\n\n"
                "Yes: stop them, then quit.\n"
                "No: quit and leave them running (run cleanup later).",
                parent=self,
            )
            if answer is None:
                return
            if answer:
                for run in live:
                    pid_file = run.scenario.pid_file(run.state_dir)
                    pid = read_pid(pid_file)
                    if pid is not None and self._pid_trustworthy(pid, pid_file):
                        kill_pid(pid, pid_file)
                    elif pid is not None:
                        _unlink(pid_file)
                    if run.proc is not None and run.proc.poll() is None and pid != run.proc.pid:
                        kill_process_group(run.proc)
        # Demo files a scenario created may still be on this machine even with
        # nothing running (and even after a reboot cleared the temp state dir).
        # Offer cleanup before quitting rather than leaving them behind silently.
        if not self._busy and self._has_demo_remnants():
            choice = messagebox.askyesnocancel(
                "Remove demo files?",
                "Some demo files the scenarios created may still be on this "
                "machine (decoy credentials in your home folders, agent config "
                "entries).\n\n"
                "Yes: run cleanup now, then quit.\n"
                "No: quit and leave them (run cleanup later).",
                parent=self,
            )
            if choice is None:
                return
            if choice:
                self._quit_after_cleanup = True
                self.run_cleanup()
                return
        self.destroy()

    def report_callback_exception(self, exc: Any, val: Any, tb: Any) -> None:
        traceback.print_exception(exc, val, tb)
        try:
            self.log_line(None, "simulator", f"internal error: {val!r}", "err")
        except Exception:
            pass

    # -- events from worker threads -------------------------------------

    def _drain_events(self) -> None:
        try:
            for _ in range(500):
                try:
                    event = self.events.get_nowait()
                except queue.Empty:
                    break
                self._handle_event(event)
            if self._dirty:
                self._dirty = False
                self._update_all()
        finally:
            self.after(EVENT_DRAIN_MS, self._drain_events)

    def _handle_event(self, event: tuple) -> None:
        kind = event[0]
        if kind == "command":
            _, key, serial, cmd = event
            run = self._event_run(key, serial)
            if run:
                run.command = cmd
                self.log_line(key, run.scenario.title, "$ " + " ".join(_shell_quote(p) for p in cmd), "cmd")
        elif kind == "spawned":
            _, key, serial, proc = event
            run = self._event_run(key, serial)
            if run:
                run.proc, run.pid = proc, proc.pid
                self.log_line(key, run.scenario.title, f"launched, pid {proc.pid}", "sys")
                self.mark_dirty()
        elif kind == "line":
            _, key, serial, text = event
            run = self._event_run(key, serial)
            if run:
                self._on_output_line(run, text)
        elif kind == "exit":
            _, key, serial, code = event
            run = self._event_run(key, serial)
            if run:
                self._on_exit(run, code)
        elif kind == "spawn_failed":
            _, key, serial, message = event
            run = self._event_run(key, serial)
            if run:
                run.phase, run.error, run.ended_at = Phase.FAILED, message, time.monotonic()
                self.log_line(key, run.scenario.title, f"could not start: {message}", "err")
                self.mark_dirty()
        elif kind == "stopped":
            _, key, detail = event
            self.log_line(key, self._source(key), detail, "sys")
            if key in self.external:
                self.external.pop(key, None)
            self.mark_dirty()
        elif kind == "watch_status":
            _, available, reason, cli = event
            self.watch_available, self.watch_reason = available, reason
            if available:
                self.log_line(None, "EDAMAME", f"watching through {reason} ({cli})", "sys")
            else:
                self.log_line(None, "EDAMAME", f"watch unavailable: {reason}", "warn")
            self.mark_dirty()
        elif kind == "watch_result":
            _, results, protection, errors = event
            self._apply_watch_result(results, protection, errors)
        elif kind == "cleanup_line":
            _, text, level = event
            if self.cleanup_dialog is not None and level != "cmd":
                self.cleanup_dialog.feed(text)
            self.log_line(None, "cleanup", text, level if level == "cmd" else classify_output(text))
        elif kind == "cleanup_done":
            _, code, error = event
            self._busy = False
            if self.cleanup_dialog is not None:
                self.cleanup_dialog.finish(code, error)
            if error:
                self.log_line(None, "cleanup", error, "err")
            else:
                self.log_line(None, "cleanup", f"finished (exit code {code})", "ok" if code == 0 else "err")
            if not error and code == 0:
                # A clean sweep removed the demo files, so the persistent
                # "scenarios were run" record no longer points at anything.
                self._clear_ran_ledger()
            self._scan_pid_files(reschedule=False)
            self.mark_dirty()
            if getattr(self, "_quit_after_cleanup", False):
                # Cleanup was started from the quit prompt: show its result
                # briefly, then close.
                self.after(2000, self.destroy)

    def _on_output_line(self, run: TriggerRun, text: str) -> None:
        run.lines += 1
        stripped = text.strip()
        if stripped:
            run.last_line = stripped
        if not run.banner_seen and ("active" in text.lower() or "wrapper_pid=" in text):
            run.banner_seen = True
            if run.phase == Phase.STARTING:
                run.phase = Phase.ACTIVE
            self.mark_dirty()
        self.log_line(run.scenario.key, run.scenario.title, text, classify_output(text))

    def _on_exit(self, run: TriggerRun, code: int) -> None:
        run.exit_code = code
        run.ended_at = time.monotonic()
        if run.stop_reason or code == 0:
            run.phase = Phase.FINISHED
        else:
            run.phase = Phase.FAILED
        reason = {
            "user": "stopped by you", "cleanup": "stopped by cleanup", "quit": "stopped on quit",
        }.get(run.stop_reason, "finished" if code == 0 else f"exited with code {code}")
        level = "err" if run.phase == Phase.FAILED else "sys"
        self.log_line(run.scenario.key, run.scenario.title, f"{reason} after {fmt_clock(run.elapsed())}", level)
        self.mark_dirty()

    def _apply_watch_result(self, results, protection, errors) -> None:
        now = time.monotonic()
        if protection is not None:
            self.protection = protection
        self.watch_errors = list(errors)
        joined = "; ".join(errors)
        if joined and joined != self._last_watch_error:
            self.log_line(None, "EDAMAME", f"could not read EDAMAME: {joined}", "warn")
        elif not joined and self._last_watch_error:
            self.log_line(None, "EDAMAME", "reachable again", "sys")
        self._last_watch_error = joined

        for (key, serial), per in results.items():
            run = self._event_run(key, serial)
            if run is None:
                continue
            detection = run.detection
            detection.checks += 1
            detection.last_checked = now
            detection.error = "; ".join(r["error"] for r in per.values() if r.get("error"))
            seen = {f"{label}|{hit['key']}" for label, r in per.items() for hit in r.get("hits", [])}
            if detection.baseline is None:
                recent = (now - run.started_at) <= BASELINE_WINDOW_S
                detection.baseline = seen if recent else set()
            for label, result in per.items():
                status = detection.per_expectation.setdefault(label, ExpectationStatus())
                if status.status == DET_DETECTED:
                    continue
                if result.get("error"):
                    if status.status in (DET_PENDING, DET_UNREACHABLE):
                        status.status, status.detail = DET_UNREACHABLE, result["error"]
                    continue
                hits = result.get("hits", [])
                fresh = [h for h in hits if f"{label}|{h['key']}" not in detection.baseline]
                alerting = [h for h in fresh if h["alertable"]]
                if alerting:
                    best = max(alerting, key=lambda h: SEVERITY_RANK.get(h["severity"], 0))
                    status.status, status.severity, status.detail = DET_DETECTED, best["severity"], best["text"]
                    status.detected_after = run.elapsed(now)
                elif fresh:
                    best = max(fresh, key=lambda h: SEVERITY_RANK.get(h["severity"], 0))
                    status.status, status.severity = DET_BELOW, best["severity"]
                    status.detail = ("dismissed in EDAMAME: " if best["dismissed"] else "") + best["text"]
                elif hits:
                    status.status, status.severity, status.detail = DET_EARLIER, hits[0]["severity"], hits[0]["text"]
                else:
                    status.status, status.detail = DET_WAITING, ""
                self._log_detection(run, label, status)
        self.mark_dirty()

    def _log_detection(self, run: TriggerRun, label: str, status: ExpectationStatus) -> None:
        if run.logged_detection.get(label) == status.status or status.status in (DET_WAITING, DET_PENDING):
            return
        run.logged_detection[label] = status.status
        sev = f"{status.severity} " if status.severity else ""
        if status.status == DET_DETECTED:
            after = fmt_clock(status.detected_after or 0.0)
            message, level = f"EDAMAME reported {sev}after {after}: {status.detail}", "ok"
        elif status.status == DET_BELOW:
            message, level = f"EDAMAME reported {sev}below alert level: {status.detail}", "warn"
        elif status.status == DET_EARLIER:
            message, level = "EDAMAME already held a matching finding from before this run", "warn"
        else:
            message, level = f"could not read EDAMAME: {status.detail}", "warn"
        self.log_line(run.scenario.key, run.scenario.title, message, level)

    def _sync_watch(self) -> None:
        now = time.monotonic()
        targets = []
        for run in self.runs.values():
            scenario = run.scenario
            exps = expectations_for(scenario)
            if not exps or run.detection.all_detected(exps):
                continue
            if run.phase == Phase.FAILED and not run.banner_seen:
                continue
            recent = run.ended_at is not None and now - run.ended_at < WATCH_AFTER_FINISH_S
            if run.live or recent:
                targets.append(WatchTarget(key=scenario.key, serial=run.serial, expectations=exps))
        self.watch.configure(bool(self.watch_var.get()), targets)

    # -- periodic refresh -----------------------------------------------

    def _tick(self) -> None:
        try:
            self._sync_watch()
            self._update_all()
        finally:
            self.after(TICK_MS, self._tick)

    def _scan_pid_files(self, reschedule: bool = True) -> None:
        try:
            state_dir = self.current_state_dir()
            for scenario in self.scenarios.values():
                if not scenario.available:
                    continue
                run = self.runs.get(scenario.key)
                if run is not None and run.live:
                    self.external.pop(scenario.key, None)
                    if run.phase == Phase.STARTING and run.pid is not None:
                        pid = read_pid(scenario.pid_file(run.state_dir))
                        if pid is not None and process_alive(pid):
                            run.banner_seen = True
                            run.phase = Phase.ACTIVE
                            self.mark_dirty()
                    continue
                pid_file = scenario.pid_file(state_dir)
                pid = read_pid(pid_file)
                if pid is not None and process_alive(pid) and not self._pid_trustworthy(pid, pid_file):
                    # A pid reused after a reboot (or by an unrelated process):
                    # do not adopt it as a running scenario, and drop the file.
                    self.external.pop(scenario.key, None)
                    _unlink(pid_file)
                    pid = None
                if pid is not None and process_alive(pid):
                    if self.external.get(scenario.key) != pid:
                        self.external[scenario.key] = pid
                        self.log_line(scenario.key, scenario.title, f"running outside this app (pid {pid})", "sys")
                        self.mark_dirty()
                else:
                    if scenario.key in self.external:
                        self.external.pop(scenario.key, None)
                        self.mark_dirty()
                    if pid is not None:
                        _unlink(pid_file)
        finally:
            if reschedule:
                self.after(PID_SCAN_MS, self._scan_pid_files)

    def _update_all(self) -> None:
        for scenario in self.scenarios.values():
            card = self.catalog_list.cards.get(scenario.key)
            if card is not None:
                card.update(self._card_view(scenario))
        self._update_detail()
        self._update_header()

    def _update_footer(self) -> None:
        # File-system paths are engineer material, not part of a demo.
        if self.engineer_var.get():
            text = f"Scenarios  {self.triggers_dir}      State  {self.current_state_dir()}"
        else:
            text = ""
        self.footer.configure(text=text)

    def _update_header(self) -> None:
        t = self.theme
        live = self._live_runs()
        running = len(live) + len(self.external)
        if running:
            self.chip_running.configure(text=f"\u25CF  {running} running", bg=t.PRIMARY_SOFT, fg=t.PRIMARY)
        else:
            self.chip_running.configure(text="No scenario running", bg=t.TRACK, fg=t.MUTED)
        detected = sum(1 for run in self.runs.values() if run.detection.overall().status == DET_DETECTED)
        if detected:
            self.chip_detected.configure(text=f"\u2713  {detected} detected by EDAMAME", bg=t.SUCCESS_SOFT, fg=t.SUCCESS)
        else:
            self.chip_detected.configure(text="No detection yet", bg=t.TRACK, fg=t.MUTED)

        if self.watch_available is None:
            self.chip_watch.configure(text="EDAMAME watch: checking...", bg=t.TRACK, fg=t.MUTED)
        elif not self.watch_available:
            self.chip_watch.configure(text="Watch in the EDAMAME app: Security > Detections", bg=t.WARNING_SOFT, fg=t.WARNING)
        elif not self.watch_var.get():
            self.chip_watch.configure(text="EDAMAME watch off", bg=t.TRACK, fg=t.MUTED)
        elif self.watch_errors:
            self.chip_watch.configure(text="EDAMAME not reachable", bg=t.WARNING_SOFT, fg=t.WARNING)
        else:
            self.chip_watch.configure(text=f"Watching EDAMAME  \u00b7  {self.watch_reason}", bg=t.INFO_SOFT, fg=t.INFO)

        protection = self.protection if (self.watch_available and self.watch_var.get()) else None
        if protection is None:
            self.chip_protection.pack_forget()
        else:
            if protection.get("enabled"):
                self.chip_protection.configure(text="Protection on", bg=t.SUCCESS_SOFT, fg=t.SUCCESS)
            else:
                self.chip_protection.configure(text="Protection off: turn it on in EDAMAME to detect", bg=t.DANGER_SOFT, fg=t.DANGER)
            if not self.chip_protection.winfo_ismapped():
                self.chip_protection.pack(side="left", padx=(0, t.px(8)))

        self.agent_combo.configure(state="disabled" if live else "readonly")
        self.stop_all_button.state(["!disabled"] if (running and not self._busy) else ["disabled"])
        self.cleanup_button.state(["disabled"] if self._busy else ["!disabled"])

    # -- view models ------------------------------------------------------

    def _card_view(self, scenario: Scenario) -> CardView:
        t = self.theme
        run = self.runs.get(scenario.key)
        start = dict(button_text="Start", button_style="Small.Primary.TButton", button_enabled=not self._busy)
        stop = dict(button_text="Stop", button_style="Small.Danger.TButton", button_enabled=True)
        if not scenario.available:
            return CardView(dot=t.TRACK, status="Not in this build", status_color=t.SUBTLE, button_text="Start", button_enabled=False)
        if not scenario.supported:
            return CardView(dot=t.TRACK, status=f"Not on {SYSTEM}", status_color=t.SUBTLE, button_text="Start", button_enabled=False)
        if (run is None or not run.live) and scenario.key in self.external:
            return CardView(dot=t.INFO, status="Running elsewhere", status_color=t.INFO, **stop)
        if run is None:
            return CardView(dot=t.BORDER_STRONG, status="Ready", status_color=t.SUBTLE, **start)

        now = time.monotonic()
        overall = run.detection.overall()
        detected = overall.status == DET_DETECTED
        detected_text = f"Detected \u00b7 {overall.severity}" if overall.severity else "Detected"
        fraction = run.fraction(now)
        clock = fmt_clock(run.elapsed(now))
        if run.phase == Phase.STARTING:
            return CardView(dot=t.WARNING, status="Starting...", status_color=t.WARNING, bar="indeterminate", **stop)
        if run.phase == Phase.ACTIVE:
            if fraction is not None:
                status = f"{clock} / {fmt_clock(run.duration)}"
                bar, value = "determinate", fraction * 100
            else:
                status, bar, value = f"Running {clock}", "indeterminate", 0.0
            if detected:
                return CardView(dot=t.SUCCESS, status=detected_text, status_color=t.SUCCESS, bar=bar, bar_value=value, bar_style="Success.Horizontal.TProgressbar", **stop)
            return CardView(dot=t.PRIMARY, status=status, status_color=t.PRIMARY, bar=bar, bar_value=value, **stop)
        if run.phase == Phase.STOPPING:
            return CardView(dot=t.WARNING, status="Stopping...", status_color=t.WARNING, bar="indeterminate", bar_style="Muted.Horizontal.TProgressbar", button_text="Stop", button_style="Small.Danger.TButton", button_enabled=True)
        if run.phase == Phase.FAILED:
            text = f"Failed (exit {run.exit_code})" if run.exit_code is not None else "Failed to start"
            return CardView(dot=t.DANGER, status=text, status_color=t.DANGER, **start)
        if detected:
            return CardView(dot=t.SUCCESS, status=detected_text, status_color=t.SUCCESS, **start)
        text = "Stopped" if run.stop_reason else "Completed"
        return CardView(dot=t.MUTED, status=f"{text} \u00b7 {clock}", status_color=t.MUTED, **start)

    def _update_detail(self) -> None:
        if not self.selected_key:
            return
        scenario = self.scenarios[self.selected_key]
        run = self.runs.get(scenario.key)
        external_pid = self.external.get(scenario.key) if (run is None or not run.live) else None
        now = time.monotonic()

        steps = self._steps(scenario, run, external_pid, now)
        if run is not None and run.live:
            fraction = run.fraction(now)
            style = "Success.Horizontal.TProgressbar" if run.detection.overall().status == DET_DETECTED else "Accent.Horizontal.TProgressbar"
            if run.phase == Phase.STOPPING:
                bar = ("indeterminate", 0.0, "Muted.Horizontal.TProgressbar")
            elif fraction is not None and run.phase == Phase.ACTIVE:
                bar = ("determinate", fraction * 100, style)
            else:
                bar = ("indeterminate", 0.0, style)
            if run.duration > 0:
                remaining = max(0.0, run.duration - run.elapsed(now))
                time_text = f"{fmt_clock(run.elapsed(now))} elapsed  \u00b7  {fmt_clock(remaining)} left"
            else:
                time_text = f"{fmt_clock(run.elapsed(now))} elapsed"
        elif run is not None:
            ok = run.phase == Phase.FINISHED
            bar = ("determinate", 100.0 if run.banner_seen else 0.0, "Success.Horizontal.TProgressbar" if ok else "Danger.Horizontal.TProgressbar")
            time_text = f"ran {fmt_clock(run.elapsed(now))}"
        elif external_pid is not None:
            bar = ("indeterminate", 0.0, "Accent.Horizontal.TProgressbar")
            time_text = "started elsewhere"
        else:
            bar = (None, 0.0, "Accent.Horizontal.TProgressbar")
            time_text = self._planned_text(scenario)

        if not scenario.available:
            action = ("Not in this build", "Primary.TButton", False)
        elif not scenario.supported:
            action = ("Start", "Primary.TButton", False)
        elif (run is not None and run.live) or external_pid is not None:
            action = ("Stop", "Danger.TButton", True)
        else:
            action = ("Start again" if run is not None else "Start", "Primary.TButton", not self._busy)

        detect = self._detect_banner(scenario, run)
        state_dir = run.state_dir if run is not None else self.current_state_dir()
        if scenario.available:
            checks = ", ".join(scenario.expected_checks)
            meta = (f"script {scenario.trigger}   \u00b7   check {checks}   \u00b7   "
                    f"pid file {scenario.pid_file_name}   \u00b7   platforms {', '.join(scenario.platforms)}\n"
                    f"state {state_dir}")
            if scenario.gate_scenarios:
                meta += f"\nCI gate: {', '.join(scenario.gate_scenarios)}"
            if run is not None and run.pid is not None:
                meta += f"\npid {run.pid}" + (f"   \u00b7   started as {run.agent_type}" if run.agent_type != self.agent_type.get() else "")
        else:
            meta = f"No trigger script named {scenario.trigger} in this build."
        self.detail.show(scenario, steps, bar, time_text, action, detect, meta, bool(run and run.command))

    def _detect_banner(self, scenario: Scenario, run: Optional[TriggerRun]):
        t = self.theme
        if run is None:
            return None
        overall = run.detection.overall()
        if overall.status == DET_DETECTED:
            after = fmt_clock(overall.detected_after or 0.0)
            sev = overall.severity or "a finding"
            return (f"Detected by EDAMAME  \u00b7  {sev}  \u00b7  after {after}", t.SUCCESS, t.SUCCESS_SOFT)
        if overall.status == DET_BELOW:
            return (f"EDAMAME reported this at {overall.severity or 'a low severity'}, below alert level", t.WARNING, t.WARNING_SOFT)
        return None

    def _planned_text(self, scenario: Scenario) -> str:
        choice = self._run_for_seconds()
        duration = scenario.default_duration if (choice is None or not scenario.accepts_duration) else float(choice)
        return f"will run {fmt_span(duration)}" if duration > 0 else "runs until stopped"

    def _steps(self, scenario, run, external_pid, now):
        if not scenario.available:
            return {k: ("skipped", "") for k, _ in DetailPane.STEPS}
        if run is None and external_pid is not None:
            return {
                "launch": ("done", f"Started outside this app (pid {external_pid})"),
                "setup": ("done", "Its PID file is in place"),
                "activity": ("active", "Running; its output goes wherever it was started from"),
                "detection": self._detection_step(scenario, None, now),
                "finish": ("pending", "Stop it here, or run cleanup"),
            }
        if run is None:
            choice = self._run_for_seconds()
            duration = scenario.default_duration if (choice is None or not scenario.accepts_duration) else float(choice)
            runs = f"Runs for {fmt_span(duration)}" if duration > 0 else "Runs until you stop it"
            return {
                "launch": ("pending", "Starts the scenario with the bundled Python"),
                "setup": ("pending", "Writes its test fixtures, then reports itself active"),
                "activity": ("pending", f"{runs}, producing the behaviour EDAMAME should catch"),
                "detection": self._detection_step(scenario, None, now),
                "finish": ("pending", "Stops on its own when its time is up, when you stop it, or on cleanup" if duration > 0 else "Stops when you stop it or run cleanup"),
            }

        steps: Dict[str, Tuple[str, str]] = {}
        started = run.started_wall.strftime("%H:%M:%S")
        if run.pid is not None:
            steps["launch"] = ("done", f"pid {run.pid}, started {started}  \u00b7  agent type {run.agent_type}")
        elif run.phase == Phase.FAILED:
            steps["launch"] = ("failed", run.error or "Could not start")
        else:
            steps["launch"] = ("active", "Starting the bundled Python...")

        if run.banner_seen:
            steps["setup"] = ("done", "Reported active, fixtures in place")
        elif not run.live:
            steps["setup"] = ("failed" if run.phase == Phase.FAILED else "skipped", "Ended before it reported active")
        elif run.pid is not None:
            steps["setup"] = ("active", "Writing its test fixtures...")
        else:
            steps["setup"] = ("pending", "Writes its test fixtures, then reports itself active")

        latest = f"\nLatest output: {run.last_line[:150]}" if (run.last_line and self.engineer_var.get()) else ""
        elapsed = fmt_clock(run.elapsed(now))
        if run.banner_seen and run.live:
            if run.duration > 0:
                remaining = fmt_clock(max(0.0, run.duration - run.elapsed(now)))
                text = f"{elapsed} elapsed, {remaining} left"
            else:
                text = f"{elapsed} elapsed, runs until you stop it"
            steps["activity"] = ("active", f"{text}{latest}")
        elif run.banner_seen:
            steps["activity"] = ("done", f"Ran for {elapsed}{latest}")
        elif run.live:
            steps["activity"] = ("pending", "Starts once set up is done")
        else:
            steps["activity"] = ("skipped", f"Did not run{latest}")

        steps["detection"] = self._detection_step(scenario, run, now)

        if run.phase == Phase.STOPPING:
            steps["finish"] = ("active", "Stopping...")
        elif run.live:
            if run.duration > 0:
                left = fmt_clock(max(0.0, run.duration - run.elapsed(now)))
                steps["finish"] = ("pending", f"Stops on its own in {left}")
            else:
                steps["finish"] = ("pending", "Stop it here, or run cleanup when you are done")
        elif run.phase == Phase.FINISHED:
            reason = {"user": "Stopped by you", "cleanup": "Stopped by cleanup", "quit": "Stopped on quit"}.get(run.stop_reason, "Completed its run")
            steps["finish"] = ("done", f"{reason} after {elapsed}. Run cleanup to remove the files it left.")
        else:
            code = f"exit code {run.exit_code}" if run.exit_code is not None else "no process"
            steps["finish"] = ("failed", f"Failed ({code}). Turn on Engineer details for its output.")
        return steps

    def _engine_off(self, scenario: Scenario) -> Optional[str]:
        protection = self.protection
        if not protection or not self.watch_var.get():
            return None
        if protection.get("detection_available") is False:
            return "EDAMAME has no detection engines on this platform"
        divergence = any(c.startswith(("correlation:", "policy:")) for c in scenario.expected_checks)
        if divergence:
            if protection.get("divergence_detection") is False:
                return "EDAMAME's divergence detection is off: turn protection on in EDAMAME"
        elif protection.get("attack_pattern_detection") is False:
            return "EDAMAME's attack pattern detection is off: turn protection on in EDAMAME"
        return None

    def _detection_step(self, scenario, run, now) -> Tuple[str, str]:
        what = scenario.see_in_edamame
        if not self.watch_available or not self.watch_var.get():
            where = self.texts.get("where_to_look", "Open EDAMAME Security and go to Security > Detections.")
            if self.watch_available is None:
                return ("info", f"{what}\n(Checking for edamame_cli; otherwise {where})")
            return ("info", f"{what}\n{where}")
        if run is None:
            return ("pending", f"The simulator checks EDAMAME every {int(WATCH_INTERVAL_S)} s and confirms the detection here.")

        detection = run.detection
        overall = detection.overall()
        if overall.status == DET_DETECTED:
            sev = f"{overall.severity} " if overall.severity else ""
            after = fmt_clock(overall.detected_after or 0.0)
            detail = f"\n{overall.detail}" if (overall.detail and self.engineer_var.get()) else ""
            return ("done", f"EDAMAME reported {sev}after {after}.{detail}")
        engine_off = self._engine_off(scenario)
        if engine_off:
            return ("warn", f"{engine_off}, then start the scenario again.")
        if overall.status == DET_BELOW:
            sev = overall.severity or "a severity"
            return ("warn", f"EDAMAME reported it at {sev}, below alert level (alerts need HIGH or CRITICAL).")
        if overall.status == DET_EARLIER:
            return ("warn", "EDAMAME already held this finding before this run. Dismiss it in EDAMAME to see it raised again.")
        if overall.status == DET_UNREACHABLE:
            return ("warn", f"Could not read EDAMAME: {overall.detail or detection.error}")
        if detection.checks == 0:
            return ("active" if run.live else "pending", "First check of EDAMAME in a moment...")
        checked = f"checked {detection.checks} time{'s' if detection.checks != 1 else ''}"
        recent = run.ended_at is not None and now - run.ended_at < WATCH_AFTER_FINISH_S
        if run.live:
            return ("active", f"Waiting for EDAMAME  \u00b7  {checked}. It evaluates on its own schedule; allow a few minutes.")
        if recent:
            left = fmt_clock(WATCH_AFTER_FINISH_S - (now - (run.ended_at or now)))
            return ("active", f"Still watching for {left}: findings can land after the scenario stops  \u00b7  {checked}.")
        return ("skipped", f"Not reported within {fmt_span(WATCH_AFTER_FINISH_S)} after the scenario ended. Check Security > Detections in EDAMAME.")


def _shell_quote(part: str) -> str:
    if part and all(ch.isalnum() or ch in "-_./:=@+,%" for ch in part):
        return part
    return "'" + part.replace("'", "'\"'\"'") + "'"


def _enable_windows_dpi_awareness() -> None:
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()  # type: ignore[attr-defined]
    except Exception:
        pass


def main() -> int:
    _enable_windows_dpi_awareness()
    try:
        triggers_dir = resolve_triggers_dir()
    except SystemExit as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("EDAMAME Attack Simulator", str(exc))
        return 1

    texts = load_app_texts()
    try:
        catalog = load_catalog(triggers_dir)
    except CatalogError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "EDAMAME Attack Simulator",
            "The scenario catalog could not be loaded.\n\n"
            f"{exc}\n\nThe simulator needs catalog.json beside the trigger scripts.",
        )
        return 1

    app = AttackSimulator(triggers_dir, catalog, texts)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
