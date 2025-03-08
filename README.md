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

- Python 3.7+
- Windows operating system
- Required Python packages:
  - `pefile`
  - `requests`
  - `tabulate`

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dll-hijacking-detection.git

# Install required dependencies
pip install pefile requests tabulate
```

## Usage

```bash
python find_suspicious_dlls.py
```

The script will:
1. Scan for DLLs loaded from non-standard locations
2. Analyze suspicious DLLs for missing/invalid signatures
3. Check for malicious imports and other security issues
4. Generate a detailed report in the `reports` directory

## Configuration

- Edit `EXPECTED_SIGNERS` dictionary to add known application signers
- Add your VirusTotal API key to enable online checking
- Adjust `MAX_SUSPICIOUS_TO_ANALYZE` to control how many DLLs are deeply analyzed

## License

MIT License - See LICENSE file for details

## Security Disclaimer

This tool is provided for educational and defensive security purposes only. Always follow responsible disclosure practices when identifying security issues.