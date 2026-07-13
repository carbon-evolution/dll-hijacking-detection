# DLL Hijacking Detection Tool

A security tool designed to identify potential DLL hijacking vulnerabilities by analyzing suspicious DLLs loaded by applications.

## Features

- **Signature Verification**: Checks if DLLs have valid digital signatures from their expected publisher
- **Application-Specific Analysis**: Identifies which application each DLL belongs to and verifies appropriate signatures
- **Suspicious Import Detection**: Identifies DLLs that import functions often used in malicious code
- **Hash Verification**: Generates SHA256 hashes for DLLs to allow verification against known-good versions
- **VirusTotal Integration**: Checks suspicious DLLs against VirusTotal database (requires API key)
- **Detailed Reporting**: Generates comprehensive reports in TXT and CSV formats

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

## License

MIT License - See LICENSE file for details

## Security Disclaimer

This tool is provided for educational and defensive security purposes only. Always follow responsible disclosure practices when identifying security issues.