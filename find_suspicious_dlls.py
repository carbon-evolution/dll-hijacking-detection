import os
import subprocess
import re
import datetime
import csv
import hashlib
import platform
import time
import json
import shutil
import argparse

try:
    import pefile
except ImportError:
    pefile = None

try:
    import requests
except ImportError:
    requests = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

# Optional Sysinternals tools. Left as None by default: the tool works without
# them using psutil (DLL enumeration) + PowerShell (signature checks), so a
# fresh clone runs with no external downloads. If these binaries are found on
# PATH or set via --listdlls / --sigcheck, they are used as an enhanced mode.
LISTDLLS_PATH = None
SIGCHECK_PATH = None

# Define safe DLL directories
SAFE_PATHS = [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\WinSxS",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]

# Define expected signers for known applications
EXPECTED_SIGNERS = {
    # Format: ("Path pattern", "Expected signer")
    "Vivaldi": (r"C:\\Users\\.*\\AppData\\Local\\Vivaldi\\", "Vivaldi Technologies AS"),
    "Chrome": (r"C:\\Users\\.*\\AppData\\Local\\Google\\Chrome\\", "Google LLC"),
    "Edge": (r"C:\\Users\\.*\\AppData\\Local\\Microsoft\\Edge\\", "Microsoft Corporation"),
    "OneDrive": (r"C:\\Users\\.*\\AppData\\Local\\Microsoft\\OneDrive\\", "Microsoft Corporation"),
    "Firefox": (r"C:\\Users\\.*\\AppData\\Local\\Mozilla Firefox\\", "Mozilla Corporation"),
    "Cursor": (r"C:\\Users\\.*\\AppData\\Local\\Programs\\cursor\\", "Unknown Signer"),  # Update with actual signer if known
    "VSCode": (r"C:\\Users\\.*\\AppData\\Local\\Programs\\Microsoft VS Code\\", "Microsoft Corporation"),
    "Discord": (r"C:\\Users\\.*\\AppData\\Local\\Discord\\", "Discord Inc."),
    "Teams": (r"C:\\Users\\.*\\AppData\\Local\\Microsoft\\Teams\\", "Microsoft Corporation"),
    "Slack": (r"C:\\Users\\.*\\AppData\\Local\\Slack\\", "Slack Technologies, Inc.")
}

# Define output file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "reports")
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"suspicious_dlls_{TIMESTAMP}.txt")
CSV_OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"suspicious_dlls_{TIMESTAMP}.csv")
HTML_REPORT_FILE = os.path.join(OUTPUT_DIR, f"suspicious_dlls_{TIMESTAMP}.html")

# Performance settings
MAX_SUSPICIOUS_TO_ANALYZE = 20   # Increased to 20 to check more files
MAX_FILE_SIZE_FOR_ANALYSIS = 100 * 1024 * 1024  # Skip files larger than 100MB for deep analysis
ANALYSIS_TIMEOUT = 30  # Seconds

# VirusTotal API settings.
# The key is read from the VT_API_KEY environment variable or the --vt-key flag.
# Never hardcode a key in source. Get a free one at https://www.virustotal.com/
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
VIRUSTOTAL_ANALYSIS_LIMIT = 10  # Increased from 4 to 10 to match MAX_SUSPICIOUS_TO_ANALYZE

# List of suspicious API functions to check for
SUSPICIOUS_IMPORTS = [
    "OpenProcess", "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
    "RegCreateKey", "RegSetValue", "RegOpenKey", "RegSetValueEx",
    "InternetOpenUrl", "WinHttpOpen", "URLDownloadToFile", "HttpOpenRequest",
    "CreateProcess", "ShellExecute", "WinExec", "CreateService",
    "ReadProcessMemory", "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "FindWindow", "FindWindowEx", "GetForegroundWindow", "GetWindowText"
]

def is_suspicious_dll(dll_path):
    """Check if a DLL is loaded from a non-standard directory."""
    if not dll_path:
        return False
    return not any(dll_path.lower().startswith(path.lower()) for path in SAFE_PATHS)


# ---------------------------------------------------------------------------
# DLL hijacking detection
#
# The checks above only inventory DLLs loaded from odd locations. The functions
# below look for the actual hijacking conditions (MITRE ATT&CK T1574.001/002):
#   * shadowing  - a System32 DLL name loaded from a non-system directory
#                  (a sideload/search-order hijack that already happened)
#   * writable   - a suspicious DLL sitting in a directory a normal user can
#                  overwrite (the surface an attacker needs)
#   * phantom    - an imported DLL that is missing from the system, where the
#                  app's own (writable) folder would satisfy the load first
# ---------------------------------------------------------------------------

_WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
_SYSTEM_DIRS = [os.path.join(_WINDIR, "System32"), os.path.join(_WINDIR, "SysWOW64")]


def get_system_dll_index():
    """Return a set of lowercased DLL basenames present in System32 / SysWOW64."""
    names = set()
    for d in _SYSTEM_DIRS:
        try:
            for f in os.listdir(d):
                if f.lower().endswith(".dll"):
                    names.add(f.lower())
        except OSError:
            continue
    return names


def get_known_dlls():
    """Return the set of KnownDLLs, which are always loaded from System32 and
    therefore cannot be hijacked. Read from the registry on Windows."""
    known = set()
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs")
        i = 0
        while True:
            try:
                _, value, _ = winreg.EnumValue(key, i)
                if isinstance(value, str) and value.lower().endswith(".dll"):
                    known.add(value.lower())
                i += 1
            except OSError:
                break
    except Exception:
        pass
    return known


def is_user_writable(directory):
    """Best-effort test of whether the current (non-elevated) user can write to
    a directory - i.e. whether an attacker of the same privilege could plant a DLL."""
    if not directory or not os.path.isdir(directory):
        return False
    try:
        test = os.path.join(directory, f".__hijack_probe_{os.getpid()}")
        with open(test, "w"):
            pass
        os.remove(test)
        return True
    except OSError:
        return False


def detect_shadow_and_writable(dll_paths, system_index, known_dlls):
    """Findings for DLLs already loaded: system-name shadowing and writable dirs."""
    findings = []
    seen_dirs = {}
    for path in dll_paths:
        base = os.path.basename(path).lower()
        directory = os.path.dirname(path)
        in_system = any(path.lower().startswith(s.lower()) for s in _SYSTEM_DIRS)

        # KnownDLLs are always loaded from System32 and cannot be hijacked - skip entirely.
        if base in known_dlls:
            continue

        # Shadowing: a System32 DLL name loaded from somewhere else.
        if base in system_index and not in_system:
            writable = seen_dirs.setdefault(directory, is_user_writable(directory))
            findings.append({
                "type": "SHADOW",
                "severity": "HIGH" if writable else "MEDIUM",
                "dll": path,
                "detail": f"System DLL name '{base}' loaded from non-system path"
                          + (" in a USER-WRITABLE directory" if writable else ""),
                "technique": "T1574.001 (DLL Search-Order Hijacking)",
            })
        # Writable location for any non-system DLL is a hijack surface.
        elif not in_system:
            writable = seen_dirs.setdefault(directory, is_user_writable(directory))
            if writable:
                findings.append({
                    "type": "WRITABLE",
                    "severity": "MEDIUM",
                    "dll": path,
                    "detail": "Loaded from a user-writable directory (plantable)",
                    "technique": "T1574.002 (DLL Sideloading)",
                })
    return findings


def detect_phantom_opportunities(system_index, known_dlls, max_procs=200):
    """Findings for missing imports: an exe importing a DLL that is absent from
    the system, where its own writable folder would satisfy the load first."""
    findings = []
    if psutil is None or pefile is None:
        return findings
    checked_exes = set()
    writable_cache = {}
    count = 0
    for proc in psutil.process_iter():
        if count >= max_procs:
            break
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, Exception):
            continue
        if not exe or exe.lower() in checked_exes or not exe.lower().endswith(".exe"):
            continue
        checked_exes.add(exe.lower())
        exe_dir = os.path.dirname(exe)
        # Only app dirs outside Program Files are realistically user-writable.
        try:
            pe = pefile.PE(exe, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        except Exception:
            continue
        count += 1
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            continue
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                name = entry.dll.decode("utf-8", "ignore")
            except Exception:
                continue
            low = name.lower()
            if not low.endswith(".dll") or low in known_dlls or low in system_index:
                continue
            # Imported DLL not resolvable from the system: phantom candidate.
            local_copy = os.path.join(exe_dir, name)
            if os.path.exists(local_copy):
                continue  # ships its own copy in-folder; only risky if that folder is writable
            writable = writable_cache.setdefault(exe_dir, is_user_writable(exe_dir))
            if writable:
                findings.append({
                    "type": "PHANTOM",
                    "severity": "HIGH",
                    "dll": local_copy,
                    "detail": f"{os.path.basename(exe)} imports '{name}' which is missing from "
                              f"the system; its writable folder would load a planted copy first",
                    "technique": "T1574.001 (Phantom DLL Hijacking)",
                })
    return findings


def format_hijack_findings(findings):
    """Render hijacking findings as a text block for the report."""
    if not findings:
        return "DLL HIJACKING FINDINGS:\n  None detected.\n\n"
    lines = ["DLL HIJACKING FINDINGS:\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f['severity']}] {f['type']} - {f['technique']}")
        lines.append(f"   DLL:    {f['dll']}")
        lines.append(f"   Detail: {f['detail']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def run_hijack_detection(dll_paths):
    """Run all hijacking detectors and return a de-duplicated list of findings."""
    print("\n🎯 Checking for DLL hijacking conditions...")
    system_index = get_system_dll_index()
    known_dlls = get_known_dlls()
    if not system_index:
        print("  (System32 not readable here - shadow/phantom checks need Windows.)")
    findings = detect_shadow_and_writable(dll_paths, system_index, known_dlls)
    findings += detect_phantom_opportunities(system_index, known_dlls)
    # De-duplicate on (type, dll).
    seen = set()
    unique = []
    for f in findings:
        key = (f["type"], f["dll"].lower())
        if key not in seen:
            seen.add(key)
            unique.append(f)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    unique.sort(key=lambda f: order.get(f["severity"], 3))
    return unique

def get_application_for_dll(dll_path):
    """Identify which application a DLL belongs to based on its path."""
    for app_name, (path_pattern, _) in EXPECTED_SIGNERS.items():
        if re.match(path_pattern, dll_path, re.IGNORECASE):
            return app_name
    return "Unknown"

def get_expected_signer(dll_path):
    """Get the expected signer for a DLL based on its path."""
    for _, (path_pattern, expected_signer) in EXPECTED_SIGNERS.items():
        if re.match(path_pattern, dll_path, re.IGNORECASE):
            return expected_signer
    return None

def get_loaded_dlls():
    """Return the set of unique DLL paths currently loaded by running processes.

    Order of preference:
      1. psutil  - pure Python, no external binaries, no admin needed for your
         own processes. This is the default so a fresh clone just works.
      2. Sysinternals ListDLLs - only if LISTDLLS_PATH is set/found (enhanced).
      3. PowerShell Get-Process - last-resort fallback, always present on Windows.
    """
    # 1. Preferred: psutil
    if psutil is not None:
        print("Enumerating loaded DLLs via psutil...")
        dlls = set()
        accessible = 0
        for proc in psutil.process_iter():
            try:
                for m in proc.memory_maps():
                    path = getattr(m, "path", "")
                    if path and path.lower().endswith(".dll"):
                        dlls.add(path)
                accessible += 1
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        if dlls:
            print(f"  Collected {len(dlls)} unique DLLs from {accessible} accessible processes.")
            print("  Tip: run as Administrator to see DLLs in system/other-user processes.")
            return sorted(dlls)
        print("  psutil returned no DLLs; trying fallbacks...")

    # 2. Optional: Sysinternals ListDLLs
    if LISTDLLS_PATH:
        try:
            print("Running ListDLLs (this may take a few moments)...")
            output = subprocess.check_output(f'"{LISTDLLS_PATH}" -accepteula', shell=True, text=True)
            return _extract_dll_paths(output)
        except Exception as e:
            print(f"Error running ListDLLs: {e}")

    # 3. Fallback: PowerShell
    print("Falling back to PowerShell (Get-Process modules)...")
    ps_command = ('powershell -NoProfile -Command "Get-Process | ForEach-Object {$_.Modules} | '
                  "Where-Object {$_.FileName -like '*.dll'} | Select-Object -ExpandProperty FileName -Unique\"")
    try:
        output = subprocess.check_output(ps_command, shell=True, text=True)
        if output.strip():
            return _extract_dll_paths(output)
    except Exception as e:
        print(f"Error with PowerShell fallback: {e}")

    return None

def _extract_dll_paths(text):
    """Pull unique DLL file paths out of a text blob (ListDLLs / PowerShell output)."""
    paths = set()
    for line in text.split("\n"):
        match = re.search(r'([A-Za-z]:\\[^\r\n]+?\.dll)', line, re.IGNORECASE)
        if match:
            paths.add(match.group(1).strip())
    return sorted(paths)

def get_file_hash(file_path):
    """Calculate SHA256 hash of a file (faster than multiple hashes)."""
    try:
        # Check file size first
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE_FOR_ANALYSIS:
            return {"SHA256": f"Skipped (file too large: {file_size/1048576:.2f} MB)"}
            
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
                
        return {"SHA256": sha256_hash.hexdigest()}
    except Exception as e:
        return {"SHA256": f"Error: {str(e)}"}

def get_virustotal_analysis(file_hash):
    """Query the VirusTotal API for file analysis based on hash."""
    if not VIRUSTOTAL_API_KEY:
        return {"Status": "No API key provided"}
    if requests is None:
        return {"Status": "requests not installed"}

    try:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        print(f"    Querying VirusTotal API for hash: {file_hash[:8]}...")
        
        try:
            response = requests.get(f"{VIRUSTOTAL_API_URL}{file_hash}", headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            return {"Status": f"Request error: {str(e)}"}
        
        if response.status_code == 200:
            try:
                result = response.json()
                
                # Extract key information
                data = result.get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                # Get detection stats
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + undetected
                
                # Get community score
                community_score = 0
                community_votes = attributes.get('total_votes', {})
                harmless_votes = community_votes.get('harmless', 0)
                malicious_votes = community_votes.get('malicious', 0)
                total_votes = harmless_votes + malicious_votes
                
                if total_votes > 0:
                    community_score = (malicious_votes / total_votes) * 100
                    
                # Get tags
                tags = attributes.get('tags', [])
                
                return {
                    "Status": "Found",
                    "CommunityScore": f"{community_score:.1f}% malicious ({malicious_votes}/{total_votes} votes)" if total_votes > 0 else "No votes",
                    "DetectionRate": f"{malicious + suspicious}/{total} ({((malicious + suspicious)/total*100) if total > 0 else 0:.1f}%)",
                    "FirstSubmission": attributes.get('first_submission_date', 'Unknown'),
                    "Tags": ", ".join(tags) if tags else "None", 
                    "Link": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
                }
            except json.JSONDecodeError:
                return {"Status": "Invalid JSON response from VirusTotal"}
            except Exception as e:
                return {"Status": f"Error parsing response: {str(e)}"}
            
        elif response.status_code == 404:
            return {"Status": "Not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"Status": "API rate limit exceeded"}
        elif response.status_code == 403:
            return {"Status": "API key invalid or unauthorized"}
        else:
            return {"Status": f"API Error: HTTP {response.status_code}"}
            
    except Exception as e:
        return {"Status": f"Error: {str(e)}"}

def get_file_origin(file_path):
    """Get basic file information."""
    try:
        file_info = os.stat(file_path)
        modified = datetime.datetime.fromtimestamp(file_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        size = file_info.st_size
        
        if size > MAX_FILE_SIZE_FOR_ANALYSIS:
            return {
                "Modified": modified,
                "Size": f"{size/1048576:.2f} MB (too large for detailed analysis)"
            }
            
        # Get basic company info
        try:
            ps_cmd = f'powershell -Command "(Get-Item \'{file_path}\').VersionInfo.CompanyName"'
            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            company = result.stdout.strip() or "Unknown"
            return {
                "Modified": modified,
                "Size": f"{size/1048576:.2f} MB",
                "Company": company
            }
        except:
            return {
                "Modified": modified,
                "Size": f"{size/1048576:.2f} MB"
            }
    except Exception as e:
        return {"Error": f"Unable to get file info: {str(e)}"}

def analyze_imports(file_path):
    """Analyze DLL imports for suspicious API calls with timeout."""
    start_time = time.time()
    if pefile is None:
        return {"ImportAnalysis": "Skipped (pefile not installed)", "TotalSuspiciousAPIs": 0}
    try:
        # Check file size first
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE_FOR_ANALYSIS:
            return {
                "ImportAnalysis": f"Skipped (file too large: {file_size/1048576:.2f} MB)",
                "TotalSuspiciousAPIs": 0
            }
            
        pe = pefile.PE(file_path, fast_load=True)
        suspicious_apis = []
        
        # Only parse the import directory
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        
        # Check for imported functions
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8')
                    for imp in entry.imports:
                        # Check timeout
                        if time.time() - start_time > 10:  # 10 seconds timeout for import analysis
                            return {
                                "SuspiciousAPIs": suspicious_apis,
                                "TotalSuspiciousAPIs": len(suspicious_apis),
                                "Note": "Analysis timed out (partial results)"
                            }
                            
                        if imp.name:
                            func_name = imp.name.decode('utf-8')
                            for suspicious in SUSPICIOUS_IMPORTS:
                                if suspicious.lower() in func_name.lower():
                                    suspicious_apis.append(f"{dll_name}:{func_name}")
                except:
                    continue
                    
        return {
            "SuspiciousAPIs": suspicious_apis,
            "TotalSuspiciousAPIs": len(suspicious_apis)
        }
    except Exception as e:
        return {
            "ImportAnalysis": f"Error: {str(e)}",
            "TotalSuspiciousAPIs": 0
        }

def render_table(rows, headers):
    """Render a table with tabulate if available, else a plain fallback."""
    if tabulate is not None:
        return tabulate(rows, headers=headers, tablefmt="grid")
    lines = ["  |  ".join(str(h) for h in headers)]
    lines.append("-" * len(lines[0]))
    for row in rows:
        lines.append("  |  ".join(str(c) for c in row))
    return "\n".join(lines)

def _extract_cn(subject):
    """Pull the CN (common name) out of an X.500 certificate subject string."""
    if not subject:
        return ""
    m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject)
    if m:
        return (m.group(1) or m.group(2)).strip()
    return subject.strip()

def _signature_via_powershell(dll_path):
    """Return (is_signed, publisher) using built-in PowerShell Get-AuthenticodeSignature.

    Status 'Valid' counts as signed; this also covers catalog-signed OS DLLs, which
    avoids flagging legitimate unsigned-on-disk Windows components as suspicious.
    """
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s = Get-AuthenticodeSignature -LiteralPath '{dll_path}';"
        "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' };"
        "Write-Output ($s.Status.ToString() + '||' + $subj)"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=20
    )
    out = (result.stdout or "").strip()
    status, _, subject = out.partition("||")
    is_signed = status.strip().lower() == "valid"
    return is_signed, _extract_cn(subject)

def _signature_via_sigcheck(dll_path):
    """Return (is_signed, publisher) using Sysinternals sigcheck (enhanced mode)."""
    cmd = f'"{SIGCHECK_PATH}" -nobanner -a "{dll_path}"'
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout or ""
    signed_match = re.search(r"Verified:\s*(\w+)", output, re.IGNORECASE) or re.search(r"Signed:\s*(\w+)", output, re.IGNORECASE)
    is_signed = bool(signed_match and signed_match.group(1).lower() in ("signed", "true"))
    publisher = ""
    pub_match = re.search(r"Publisher:\s*(.*?)$", output, re.MULTILINE)
    if pub_match:
        publisher = pub_match.group(1).strip()
    return is_signed, publisher

def check_digital_signature(dll_path):
    """Enhanced check for digital signature with verification against expected signer."""
    signature_info = {}
    
    # Identify application and expected signer
    app_name = get_application_for_dll(dll_path)
    expected_signer = get_expected_signer(dll_path)
    
    # Add application and expected signer to signature info
    signature_info["Application"] = app_name
    if expected_signer:
        signature_info["ExpectedSigner"] = expected_signer
    
    # Get basic file info
    origin = get_file_origin(dll_path)
    signature_info.update(origin)
    
    # Skip large files
    if origin.get("Size", "").endswith("too large for detailed analysis)"):
        signature_info["SignatureStatus"] = "Not checked (file too large)"
        signature_info["SignatureVerification"] = "Skipped - file too large"
        return signature_info
    
    # Check digital signature. Default: built-in PowerShell Get-AuthenticodeSignature
    # (present on every Windows box, understands catalog-signed system DLLs).
    # If SIGCHECK_PATH is set, use Sysinternals sigcheck instead (enhanced mode).
    try:
        if SIGCHECK_PATH:
            is_signed, publisher = _signature_via_sigcheck(dll_path)
        else:
            is_signed, publisher = _signature_via_powershell(dll_path)

        signature_info["SignatureStatus"] = "Signed" if is_signed else "Unsigned"
        signature_info["Publisher"] = publisher or "None"

        if expected_signer:
            if is_signed and publisher and expected_signer.lower() in publisher.lower():
                signature_info["SignatureVerification"] = f"✓ Verified (matches {app_name})"
            elif is_signed:
                signature_info["SignatureVerification"] = f"❌ Invalid (expected {expected_signer}, got {publisher})"
            else:
                signature_info["SignatureVerification"] = f"❌ Invalid (expected {expected_signer}, no valid signature found)"
        elif is_signed:
            signature_info["SignatureVerification"] = f"Signed by {publisher}" if publisher else "Signed"
        else:
            signature_info["SignatureVerification"] = "Unsigned"
    except Exception as e:
        signature_info["SignatureStatus"] = "Check Failed"
        signature_info["SignatureVerification"] = f"Error: {str(e)}"
    
    # Only get hash for files without proper verification
    if signature_info.get("SignatureVerification", "").startswith("❌") or signature_info.get("SignatureStatus") in ["Unsigned", "Check Failed"]:
        hashes = get_file_hash(dll_path)
        signature_info.update(hashes)
    
    return signature_info

def format_signature_info(signature_info, virustotal_data=None):
    """Format the signature info for display."""
    if isinstance(signature_info, str):
        return signature_info
        
    # Format based on signature status
    if signature_info.get("SignatureVerification", "").startswith("✓"):
        return f"Signature: Verified, Publisher: {signature_info.get('Publisher', 'Unknown')}, Verification: {signature_info.get('SignatureVerification')}"
    
    # For failed/invalid signatures, create a more structured report
    result = {
        "Signature": signature_info.get("SignatureStatus", "Unknown"),
        "Verification": signature_info.get("SignatureVerification", "Unknown"),
        "Application": signature_info.get("Application", "Unknown"),
        "Size": signature_info.get("Size", "Unknown"),
        "Company": signature_info.get("Company", "Unknown") if "Company" in signature_info else "Unknown",
    }
    
    # Add VirusTotal info if available
    if virustotal_data and virustotal_data.get("Status") == "Found":
        result["VT Community"] = virustotal_data.get("CommunityScore", "Unknown")
        result["VT Detection"] = virustotal_data.get("DetectionRate", "Unknown")
        if virustotal_data.get('Tags') and virustotal_data.get('Tags') != "None":
            result["VT Tags"] = virustotal_data.get("Tags", "None")
    elif "SHA256" in signature_info and not signature_info["SHA256"].startswith("Error") and not signature_info["SHA256"].startswith("Skipped"):
        result["VT Link"] = f"https://www.virustotal.com/gui/file/{signature_info['SHA256']}"
        
    # Format as a string for display in simple table
    return ", ".join(f"{k}: {v}" for k, v in result.items())

def rank_suspicious_dlls(dll_info_list):
    """Rank suspicious DLLs by risk level."""
    # Get unique application paths first to ensure diversity in sampling
    app_dll_groups = {}
    
    for dll_path, dll_info in dll_info_list:
        app_name = get_application_for_dll(dll_path)
        if app_name not in app_dll_groups:
            app_dll_groups[app_name] = []
        app_dll_groups[app_name].append((dll_path, dll_info))
    
    # Extract DLLs from each application group, prioritizing diversity
    result = []
    
    # First, ensure we get at least one DLL from each known application
    known_apps = [app for app in EXPECTED_SIGNERS.keys() if app in app_dll_groups]
    for app in known_apps:
        if app_dll_groups[app]:
            result.append(app_dll_groups[app][0])
            app_dll_groups[app] = app_dll_groups[app][1:]  # Remove the first item
    
    # Then, add remaining DLLs from each application group until we hit our limit
    all_remaining = []
    for app, dlls in app_dll_groups.items():
        all_remaining.extend(dlls)
    
    # Add remaining DLLs up to the limit
    remaining_slots = MAX_SUSPICIOUS_TO_ANALYZE - len(result)
    if remaining_slots > 0 and all_remaining:
        result.extend(all_remaining[:remaining_slots])
    
    return result

def analyze_dlls():
    """Analyzes DLLs for hijacking risks with performance optimizations."""
    start_time = time.time()
    print("\n🔍 Scanning for Suspicious DLLs...\n")
    
    dll_paths = get_loaded_dlls()
    if not dll_paths:
        print("❌ Unable to fetch DLL list!")
        return

    all_dlls = []
    suspicious_dlls = []

    # First pass: identify all DLLs and mark suspicious ones
    print("Identifying suspicious DLLs...")
    dll_count = 0
    for dll_path in dll_paths:
        dll_count += 1
        is_suspicious = is_suspicious_dll(dll_path)
        dll_info = {
            "Path": dll_path,
            "Suspicious": "Yes" if is_suspicious else "No",
            "Signature": "Not checked",
            "Verification": "",
            "Application": get_application_for_dll(dll_path),
            "VTCommunity": "",
            "VTDetection": "",
            "VTTags": ""
        }
        all_dlls.append(dll_info)

        # Only add to suspicious list, don't analyze yet
        if is_suspicious:
            suspicious_dlls.append((dll_path, dll_info))

    # Rank suspicious DLLs to prioritize diverse applications
    ranked_suspicious_dlls = rank_suspicious_dlls(suspicious_dlls)
    
    # Remove duplicates - keep only one DLL per unique path
    unique_suspicious_dlls = []
    seen_paths = set()
    for dll_path, dll_info in ranked_suspicious_dlls:
        if dll_path not in seen_paths:
            seen_paths.add(dll_path)
            unique_suspicious_dlls.append((dll_path, dll_info))
    
    print(f"Found {len(suspicious_dlls)} suspicious DLLs, prioritizing {len(unique_suspicious_dlls)} for detailed analysis")

    # Dedicated DLL-hijacking detection (shadowing / writable dirs / phantom imports).
    hijack_findings = run_hijack_detection(dll_paths)
    if hijack_findings:
        highs = sum(1 for f in hijack_findings if f["severity"] == "HIGH")
        print(f"\n⚠️  {len(hijack_findings)} potential hijacking condition(s) found ({highs} HIGH):")
        for f in hijack_findings[:15]:
            print(f"  [{f['severity']}] {f['type']}: {os.path.basename(f['dll'])} - {f['detail']}")
        if len(hijack_findings) > 15:
            print(f"  ... and {len(hijack_findings) - 15} more (see report).")
    else:
        print("  No hijacking conditions detected.")

    # Limit analysis to the specified maximum from unique DLLs
    suspicious_to_analyze = unique_suspicious_dlls[:MAX_SUSPICIOUS_TO_ANALYZE]
    
    # Second pass: analyze only the limited set of suspicious DLLs
    if suspicious_to_analyze:
        print(f"Analyzing {len(suspicious_to_analyze)} unique suspicious DLLs...")
        analyzed_dlls = []
        analyzed_data = []  # For detailed formatted table
        vt_hashes = []  # Store hashes for VirusTotal API lookup
        vt_dll_indices = []  # Store indices of DLLs for VirusTotal lookup
        
        for i, (dll_path, dll_info) in enumerate(suspicious_to_analyze):
            app_name = get_application_for_dll(dll_path)
            print(f"  Analyzing {i+1}/{len(suspicious_to_analyze)}: {os.path.basename(dll_path)} ({app_name})")
            
            try:
                signature_info = check_digital_signature(dll_path)
                
                # Store hash for VirusTotal if we have a good SHA256 and API key
                if (VIRUSTOTAL_API_KEY and "SHA256" in signature_info and 
                    not signature_info["SHA256"].startswith("Error") and 
                    not signature_info["SHA256"].startswith("Skipped") and
                    len(vt_hashes) < VIRUSTOTAL_ANALYSIS_LIMIT):
                    vt_hashes.append(signature_info["SHA256"])
                    vt_dll_indices.append(i)
                
                # Perform deep analysis only on unsigned DLLs
                if signature_info.get("SignatureStatus") not in ["Verified", "Signed"] and "SignatureVerification" in signature_info and signature_info["SignatureVerification"].startswith("❌"):
                    try:
                        # Check if file is not too large
                        if os.path.getsize(dll_path) <= MAX_FILE_SIZE_FOR_ANALYSIS:
                            imports = analyze_imports(dll_path)
                            signature_info.update(imports)
                    except:
                        pass
                        
                formatted_info = format_signature_info(signature_info)
                dll_info["Signature"] = formatted_info
                dll_info["RawInfo"] = signature_info  # Store raw info for later use with VirusTotal
                
                # Store data for detailed table
                analysis_data = {
                    "Path": dll_path,
                    "Application": signature_info.get("Application", "Unknown"),
                    "Signature": signature_info.get("SignatureStatus", "Unknown"),
                    "Verification": signature_info.get("SignatureVerification", "Unknown"),
                    "Publisher": signature_info.get("Publisher", "Unknown") if "Publisher" in signature_info else "Unknown",
                    "ExpectedSigner": signature_info.get("ExpectedSigner", "Unknown") if "ExpectedSigner" in signature_info else "Unknown",
                    "Company": signature_info.get("Company", "") if "Company" in signature_info else "",
                    "Size": signature_info.get("Size", "Unknown"),
                    "Modified": signature_info.get("Modified", ""),
                    "SHA256": signature_info.get("SHA256", "") if "SHA256" in signature_info else "",
                    "VTCommunity": "",
                    "VTDetection": "",
                    "VTTags": ""
                }
                analyzed_data.append(analysis_data)
                analyzed_dlls.append((dll_path, formatted_info, signature_info, analysis_data))
                
            except Exception as e:
                dll_info["Signature"] = f"Analysis error: {str(e)}"
                analysis_data = {
                    "Path": dll_path,
                    "Application": get_application_for_dll(dll_path),
                    "Signature": "Error",
                    "Verification": f"Error: {str(e)}",
                    "VTCommunity": "",
                    "VTDetection": "",
                    "VTTags": ""
                }
                analyzed_data.append(analysis_data)
                analyzed_dlls.append((dll_path, f"Analysis error: {str(e)}", {}, analysis_data))
        
        # Third pass: Check VirusTotal for selected files
        if VIRUSTOTAL_API_KEY and vt_hashes:
            print(f"\nChecking VirusTotal community scores for {len(vt_hashes)} files...")
            vt_results = {}
            
            for i, file_hash in enumerate(vt_hashes):
                dll_index = vt_dll_indices[i]
                dll_path, _, raw_info, analysis_data = analyzed_dlls[dll_index]
                
                print(f"  Checking VirusTotal for {os.path.basename(dll_path)}...")
                vt_data = get_virustotal_analysis(file_hash)
                vt_results[file_hash] = vt_data
                
                # Update the formatted info with VirusTotal data
                if vt_data.get("Status") == "Found":
                    # Update analysis data with VirusTotal information
                    analysis_data["VTCommunity"] = vt_data.get("CommunityScore", "No votes")
                    analysis_data["VTDetection"] = vt_data.get("DetectionRate", "Unknown")
                    analysis_data["VTTags"] = vt_data.get("Tags", "None")
                    
                    # Update the display info
                    new_formatted_info = format_signature_info(raw_info, vt_data)
                    analyzed_dlls[dll_index] = (dll_path, new_formatted_info, raw_info, analysis_data)
                    
                    # Update the dll_info in all_dlls
                    for dll in all_dlls:
                        if dll["Path"] == dll_path:
                            dll["Signature"] = new_formatted_info
                            dll["VTCommunity"] = vt_data.get("CommunityScore", "")
                            dll["VTDetection"] = vt_data.get("DetectionRate", "")
                            dll["VTTags"] = vt_data.get("Tags", "")
                            break
                
                # Respect rate limits
                if i < len(vt_hashes) - 1:
                    print("    Waiting to avoid API rate limits...")
                    time.sleep(2)  # Avoid hitting rate limits
        elif not VIRUSTOTAL_API_KEY and len(vt_hashes) > 0:
            print("\nSkipping VirusTotal analysis - no API key provided")
            print("To enable VirusTotal community score analysis:")
            print("1. Get a free API key from https://www.virustotal.com/")
            print("2. Pass it with --vt-key <KEY> or set the VT_API_KEY environment variable")
    
        # Output to console
        print(f"\nFound {len(suspicious_dlls)} suspicious DLLs out of {dll_count} total DLLs")
        
        if suspicious_to_analyze:
            # Create a detailed table for analyzed DLLs with VirusTotal data
            detailed_table = []
            headers = ["#", "Application", "DLL", "Signature", "Verification"]
            
            for i, (dll_path, _, _, data) in enumerate(analyzed_dlls, 1):
                # Create row with basic info
                row = [
                    i,
                    data.get("Application", "Unknown"),
                    os.path.basename(dll_path),
                    data.get("Signature", "Unknown"),
                    data.get("Verification", "Unknown")
                ]
                
                detailed_table.append(row)
                
            # Print the detailed table
            print("\n" + render_table(detailed_table, headers))
            
            if len(suspicious_dlls) > MAX_SUSPICIOUS_TO_ANALYZE:
                print(f"\nNote: Only {len(suspicious_to_analyze)} of {len(suspicious_dlls)} suspicious DLLs were analyzed.")
        else:
            print("No suspicious DLLs were analyzed.")
        
        print(f"\nFull report saved to: {OUTPUT_FILE}")
        print(f"CSV report saved to: {CSV_OUTPUT_FILE}")
        
        # Save to text file
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("DLL HIJACKING VULNERABILITY SCAN REPORT\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"System: {platform.system()} {platform.version()} ({platform.architecture()[0]})\n")
            f.write(f"Scan duration: {time.time() - start_time:.2f} seconds\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("SUMMARY:\n")
            f.write(f"Total DLLs scanned: {dll_count}\n")
            f.write(f"Suspicious DLLs found: {len(suspicious_dlls)}\n")
            f.write(f"DLLs analyzed in detail: {len(suspicious_to_analyze)}\n")
            f.write(f"Hijacking conditions found: {len(hijack_findings)} "
                    f"({sum(1 for x in hijack_findings if x['severity'] == 'HIGH')} HIGH)\n\n")

            f.write(format_hijack_findings(hijack_findings))

            # Write detailed table to file
            if suspicious_to_analyze:
                f.write("ANALYZED SUSPICIOUS DLLs:\n")
                f.write(render_table(detailed_table, headers))
                f.write("\n\n")
                
                # Write detailed signature verification information for each DLL
                f.write("DETAILED SIGNATURE VERIFICATION:\n")
                for i, (dll_path, _, _, data) in enumerate(analyzed_dlls, 1):
                    f.write(f"{i}. {os.path.basename(dll_path)} ({data.get('Application', 'Unknown')})\n")
                    f.write(f"   Path: {dll_path}\n")
                    f.write(f"   Signature Status: {data.get('Signature', 'Unknown')}\n")
                    f.write(f"   Publisher: {data.get('Publisher', 'Unknown')}\n")
                    f.write(f"   Expected Signer: {data.get('ExpectedSigner', 'Unknown')}\n")
                    f.write(f"   Verification: {data.get('Verification', 'Unknown')}\n")
                    f.write(f"   Company: {data.get('Company', 'Unknown')}\n")
                    f.write(f"   Size: {data.get('Size', 'Unknown')}\n")
                    f.write(f"   SHA256: {data.get('SHA256', '')}\n")
                    
                    # Add VirusTotal data if available
                    if data.get("VTCommunity"):
                        f.write(f"   VirusTotal Community Score: {data.get('VTCommunity', '')}\n")
                        f.write(f"   VirusTotal Detection Rate: {data.get('VTDetection', '')}\n")
                        f.write(f"   VirusTotal Tags: {data.get('VTTags', '')}\n")

                    f.write("\n")
            
            # Write all suspicious DLLs paths (without detailed analysis)
            f.write("ALL SUSPICIOUS DLLs:\n")
            grouped_by_app = {}
            for i, (dll_path, dll_info) in enumerate(suspicious_dlls, 1):
                app_name = get_application_for_dll(dll_path)
                if app_name not in grouped_by_app:
                    grouped_by_app[app_name] = []
                grouped_by_app[app_name].append(dll_path)
            
            # Write grouped by application
            for app_name, dll_paths in sorted(grouped_by_app.items()):
                f.write(f"\n{app_name} ({len(dll_paths)} DLLs):\n")
                for i, dll_path in enumerate(dll_paths, 1):
                    f.write(f"  {i}. {dll_path}\n")
            f.write("\n")
        
        # Save to CSV file with VirusTotal data
        with open(CSV_OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["Index", "Application", "DLL Path", "Signature Status", "Publisher", "Expected Signer", "Verification", "Company", "Size", "Modified", "SHA256"]
            
            # Add VirusTotal fields if we have data
            has_vt_data = any(data.get("VTCommunity") for _, _, _, data in analyzed_dlls)
            if has_vt_data:
                fieldnames.extend(["VT Community Score", "VT Detection Rate", "VT Tags"])
                
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Add analyzed suspicious DLLs
            for i, (dll_path, _, _, data) in enumerate(analyzed_dlls, 1):
                row = {
                    "Index": i,
                    "Application": data.get("Application", "Unknown"),
                    "DLL Path": dll_path,
                    "Signature Status": data.get("Signature", ""),
                    "Publisher": data.get("Publisher", ""),
                    "Expected Signer": data.get("ExpectedSigner", ""),
                    "Verification": data.get("Verification", ""),
                    "Company": data.get("Company", ""),
                    "Size": data.get("Size", ""),
                    "Modified": data.get("Modified", ""),
                    "SHA256": data.get("SHA256", "")
                }
                
                # Add VirusTotal data if available
                if has_vt_data:
                    row.update({
                        "VT Community Score": data.get("VTCommunity", ""),
                        "VT Detection Rate": data.get("VTDetection", ""),
                        "VT Tags": data.get("VTTags", "")
                    })
                    
                writer.writerow(row)
        
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
    else:
        # No suspicious DLLs, but still write a report so hijacking findings persist.
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("DLL HIJACKING VULNERABILITY SCAN REPORT\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"System: {platform.system()} {platform.version()} ({platform.architecture()[0]})\n")
            f.write("=" * 80 + "\n\n")
            f.write("SUMMARY:\n")
            f.write(f"Total DLLs scanned: {dll_count}\n")
            f.write("Suspicious DLLs found: 0\n")
            f.write(f"Hijacking conditions found: {len(hijack_findings)} "
                    f"({sum(1 for x in hijack_findings if x['severity'] == 'HIGH')} HIGH)\n\n")
            f.write(format_hijack_findings(hijack_findings))
        print(f"\nNo suspicious DLLs. Report saved to: {OUTPUT_FILE}")
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")

def _auto_find_sysinternals(name):
    """Return the path to a Sysinternals tool if it happens to be on PATH."""
    for candidate in (name, name.replace("64", ""), name + ".exe"):
        found = shutil.which(candidate)
        if found:
            return found
    return None

def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect suspicious DLLs loaded from non-standard locations (potential DLL hijacking).",
        epilog="Just run 'python find_suspicious_dlls.py' with no arguments for a default scan."
    )
    parser.add_argument("--vt-key", default=VIRUSTOTAL_API_KEY,
                        help="VirusTotal API key (or set the VT_API_KEY environment variable). Optional.")
    parser.add_argument("--max", type=int, default=MAX_SUSPICIOUS_TO_ANALYZE,
                        help=f"Max suspicious DLLs to deeply analyze (default {MAX_SUSPICIOUS_TO_ANALYZE}).")
    parser.add_argument("--listdlls", default=None,
                        help="Optional path to Sysinternals Listdlls.exe (enhanced enumeration).")
    parser.add_argument("--sigcheck", default=None,
                        help="Optional path to Sysinternals sigcheck.exe (enhanced signature checks).")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    VIRUSTOTAL_API_KEY = args.vt_key
    MAX_SUSPICIOUS_TO_ANALYZE = args.max
    LISTDLLS_PATH = args.listdlls or _auto_find_sysinternals("Listdlls64.exe")
    SIGCHECK_PATH = args.sigcheck or _auto_find_sysinternals("sigcheck64.exe")

    if platform.system() != "Windows":
        print("⚠️  This tool inspects Windows DLLs and is intended to run on Windows.")
        print("    It will still start, but DLL enumeration will likely return nothing here.\n")
    if psutil is None:
        print("⚠️  psutil is not installed. Install dependencies first:")
        print("       pip install -r requirements.txt\n")

    analyze_dlls()
