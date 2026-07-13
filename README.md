# DLL Hijacking Detection Tool

[![CI](https://github.com/carbon-evolution/dll-hijacking-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/carbon-evolution/dll-hijacking-detection/actions/workflows/ci.yml)

A defensive Windows security tool that detects **DLL hijacking conditions** on a
running system — not just DLLs loaded from odd folders, but the actual situations
an attacker exploits: a system DLL shadowed from a writable directory, a plantable
load path, or a missing import that a dropped DLL would satisfy first
(MITRE ATT&CK [T1574.001 / T1574.002](https://attack.mitre.org/techniques/T1574/001/)).

Runs straight from a clone — no external binaries to download.

## Features

- **DLL Hijacking Detection** (MITRE ATT&CK T1574.001/002): flags the actual hijacking conditions, not just odd file locations —
  - *Shadowing*: a System32 DLL name loaded from a non-system directory (a search-order hijack that already happened)
  - *Writable location*: a loaded DLL sitting in a directory a normal user can overwrite (the surface an attacker needs)
  - *Phantom imports*: an executable importing a DLL that is missing from the system, where its own writable folder would load a planted copy first
  - KnownDLLs are correctly excluded (they always load from System32 and can't be hijacked)
- **Signature Verification**: Checks if DLLs have valid digital signatures from their expected publisher (catalog-signed OS DLLs included)
- **Application-Specific Analysis**: Identifies which application each DLL belongs to and verifies appropriate signatures
- **Suspicious Import Detection**: Identifies DLLs that import functions often used in malicious code
- **Hash Verification**: Generates SHA256 hashes for DLLs to allow verification against known-good versions
- **VirusTotal Integration**: Checks suspicious DLLs against VirusTotal database (optional API key)
- **Detailed Reporting**: Generates comprehensive reports in TXT and CSV formats

Findings are ranked by severity and shown in the console and the saved report:
**HIGH** = a System32 DLL name loaded from a user-writable non-system directory (a hijack that likely already happened);
**MEDIUM** = the same name from a non-writable location, or a phantom import opportunity;
**LOW** = a non-system DLL merely sitting in a writable directory (surface only).
Windows apiset stubs (`api-ms-win-*`) and common redistributables (VC++, UCRT, .NET, WebView2) are excluded to avoid false positives.

## Requirements

- **Windows** (the tool inspects Windows DLLs and processes)
- **Python 3.7+** — get it from [python.org](https://www.python.org/downloads/) and tick *"Add Python to PATH"* during install

No external downloads are needed. Earlier versions required the Sysinternals
tools (`Listdlls.exe`, `sigcheck.exe`); the tool now uses `psutil` for DLL
enumeration and Windows' built-in PowerShell for signature checks, so it runs
straight from a clone.

## Quick start (easiest)

1. Download this repository (green **Code** button → **Download ZIP**) and unzip it.
2. Double-click **`run.bat`**.

That's it. It installs the dependencies the first time and runs the scan.
For the most complete results, right-click `run.bat` → **Run as administrator**
(this lets it see DLLs loaded by system and other-user processes).

## Quick start (command line)

```bash
git clone https://github.com/carbon-evolution/dll-hijacking-detection.git
cd dll-hijacking-detection
pip install -r requirements.txt
python find_suspicious_dlls.py
```

The script will:
1. List every DLL loaded by running processes
2. Flag those loaded from non-standard locations
3. Verify digital signatures and scan for suspicious imports
4. Save reports (TXT + CSV) in the `reports` folder

## Options

Everything works with no arguments. Optional flags:

```bash
python find_suspicious_dlls.py --max 40           # analyze more suspicious DLLs
python find_suspicious_dlls.py --vt-key <KEY>     # enable VirusTotal lookups
python find_suspicious_dlls.py --sigcheck sigcheck64.exe   # enhanced mode
```

- **VirusTotal (optional):** get a free key at [virustotal.com](https://www.virustotal.com/),
  then pass `--vt-key` or set the `VT_API_KEY` environment variable. Never paste a key into the source.
- **Enhanced Sysinternals mode (optional):** if you point `--listdlls` / `--sigcheck`
  at the Sysinternals binaries, the tool uses them for richer output. Not required.
- **Known-app signers:** edit the `EXPECTED_SIGNERS` dictionary in the script to
  add applications you want signature-verified.

## Example output

```
🔍 Scanning for Suspicious DLLs...
Enumerating loaded DLLs via psutil...
  Collected 1061 unique DLLs from 214 accessible processes.
Found 205 suspicious DLLs, prioritizing 20 for detailed analysis

🎯 Checking for DLL hijacking conditions...

⚠️  1 potential hijacking condition(s) found (1 HIGH):
  [HIGH] SHADOW: version.dll - System DLL name 'version.dll' loaded from
         non-system path in a USER-WRITABLE directory
```

Full findings (with MITRE technique IDs), the signature-verification table, and
suspect imports are written to `reports/suspicious_dlls_<timestamp>.txt` and `.csv`.

## Scope & limitations

- **Windows only**, and it inspects **currently running** processes — plant-and-exit
  attacks that have already unloaded won't appear. Run periodically or after launching
  the apps you care about.
- Run **as Administrator** for full coverage; without elevation you only see DLLs in
  your own processes.
- Severity is tuned to keep false positives low (apisets and common redistributables
  are excluded), but findings are *indicators*, not proof — verify HIGH results by
  checking the DLL's publisher and location before acting.

## Running the tests

The detectors have cross-platform tests (no Windows needed) — also run on every push
via GitHub Actions, including a live scan on a real Windows runner:

```bash
python -m pytest -q                       # if pytest is installed
python tests/test_hijack_detection.py     # or run standalone
```

## License

MIT License - See LICENSE file for details

## Security Disclaimer

This tool is provided for educational and defensive security purposes only. Always follow responsible disclosure practices when identifying security issues.