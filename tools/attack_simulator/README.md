# EDAMAME Attack Simulator

> **Simulation only: no real attack is carried out.** Every scenario is a
> simulation built on test data: decoy credentials and files, harmless test
> processes, and public test endpoints.

A small, self-contained demo app that safely reproduces the host-visible
behaviour of real-world attack techniques — the kind used against developer
laptops, CI runners and AI coding agents — so you can **watch EDAMAME detect
them on your own machine**.

Each card runs one scenario. Start it, then switch to EDAMAME and watch the
finding land in **Security > Detections**. When you are done, press **Run
cleanup**: it stops every scenario and removes the files they created.

Each download bundles its own Python runtime, so you do **not** need Python
installed.

## Safe by design

- **Everything runs locally.** No real malware is downloaded or executed.
- **No real secrets leave the machine.** Where a scenario needs a credential
  file it writes a throwaway fake one and reads only that. A few scenarios open
  a real file read-only for a single byte and send nothing from it.
- **Simulated network traffic goes to public test endpoints** (for example
  portquiz.net) or to well-known sinkhole ranges — never to a real attacker.
- **Each scenario tracks what it created** under a folder in your temporary
  directory. **Run cleanup** stops everything and removes those files; anything
  a scenario had to place in a system location is listed so you can remove it
  with administrator rights.

Two scenarios need an administrator password (they are marked **needs admin**).
Every other scenario runs as you.

## What you need

A **running EDAMAME** to detect the activity — the simulator only produces it:

- the **EDAMAME Security** app with protection turned on, or
- the **EDAMAME Posture** daemon with detection enabled.

The app can confirm each detection for you, live. When `edamame_cli` is on your
PATH, the simulator polls EDAMAME and shows "Detected by EDAMAME · HIGH · after
0:42" on the scenario. If it is not available, the simulator tells you where to
look instead: **Security > Detections** in the EDAMAME Security app.

## Download

Latest version:

| Platform | Download | SHA-256 |
|---|---|---|
| macOS (Apple silicon) | [edamame-attack-simulator-macos-arm64-latest.zip](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/edamame-attack-simulator-macos-arm64-latest.zip) | [.sha256](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/edamame-attack-simulator-macos-arm64-latest.zip.sha256) |
| Windows (x64) | [edamame-attack-simulator-windows-x64-latest.zip](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/edamame-attack-simulator-windows-x64-latest.zip) | [.sha256](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/edamame-attack-simulator-windows-x64-latest.zip.sha256) |
| Linux (x64) | [edamame-attack-simulator-linux-x64-latest.tar.gz](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/edamame-attack-simulator-linux-x64-latest.tar.gz) | [.sha256](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/edamame-attack-simulator-linux-x64-latest.tar.gz.sha256) |

[`LATEST`](https://edamame.s3.eu-west-1.amazonaws.com/attack-simulator/LATEST)
holds the version these links serve. To check a download, run
`shasum -a 256 -c <file>.sha256` in the folder holding both files.

A specific version is attached to each
[release of this repository](https://github.com/edamametechnologies/edamame_security/releases),
as `edamame-attack-simulator-<platform>-<version>.zip` (`.tar.gz` on Linux),
each with its `.sha256` sidecar.

## Opening it

### macOS

The app is signed with EDAMAME's Developer ID and notarized by Apple, so
Gatekeeper accepts it. Unzip and double-click **EDAMAME Attack Simulator.app**.
If macOS still hesitates on first launch (for example after copying between
machines), right-click the app and choose **Open**, then **Open** in the
dialog.

### Windows

The launcher is Authenticode-signed by EDAMAME. Unzip the folder and run
**EDAMAME Attack Simulator.exe**. If SmartScreen shows a "Windows protected
your PC" notice, choose **More info -> Run anyway**. Keep the folder intact; the
launcher expects `python\` and `triggers\` beside it.

### Linux

Extract the archive and run the launcher:

```sh
tar xf edamame-attack-simulator-linux-x64-<version>.tar.gz
./edamame-attack-simulator/run.sh
```

A graphical session with Tk support is required (the bundle ships its own
Tcl/Tk).

## Using it

1. Pick a scenario from the catalog, grouped by theme. Each card shows a
   plain-language description, the real-world incident or technique it is based
   on (with a link), what EDAMAME will show, and a talk track you can copy.
2. Press **Start**. The scenario reports its progress step by step.
3. Switch to EDAMAME and watch the finding appear in **Security > Detections**.
   Detections land at EDAMAME's next detection tick, so allow a minute or two.
4. Press **Run cleanup** when you are done. When the simulator can read
   EDAMAME, cleanup then lists the detections its scenarios raised and offers
   to dismiss them in EDAMAME, so the demo leaves no alert behind. Only those
   detections are listed, and nothing is dismissed unless you choose
   **Dismiss**: **Keep**, the default, leaves them in **Security >
   Detections**.

A guided **10-minute demo** walks a recommended sequence of scenarios in order.
An **Engineer details** toggle reveals the script, the detector check, the
process id, the raw output, the agent-type selector and the run duration for a
technical audience.

## Building from source

You need [`uv`](https://github.com/astral-sh/uv) (it fetches the standalone
CPython that gets bundled). Point `EDAMAME_TRIGGERS_DIR` at the EDAMAME trigger
scripts, which carry the scenario catalog:

```sh
export EDAMAME_TRIGGERS_DIR=/path/to/edamame_posture/tests/security/triggers

tools/attack_simulator/build_macos_app.sh   out_dir               # macOS
tools/attack_simulator/build_linux.sh        out_dir              # Linux
pwsh tools/attack_simulator/build_windows.ps1 -DistDir out_dir    # Windows
```

Each script embeds a standalone CPython, copies in the triggers and their
`catalog.json`, and prints the produced artifact path as `ARTIFACT=...`.
