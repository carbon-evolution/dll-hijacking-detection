import os
import subprocess
import re
import datetime
import csv
import hashlib
import pefile
import platform
import time
import requests
import json
from tabulate import tabulate  # You may need to install this: pip install tabulate

# Define paths for Sysinternals tools (update if needed)
LISTDLLS_PATH = r"C:\Users\arthur\Downloads\SysinternalsSuite\Listdlls64.exe"
SIGCHECK_PATH = r"C:\Users\arthur\Downloads\SysinternalsSuite\sigcheck64.exe"

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

# VirusTotal API settings
# Replace with your API key - get one free at https://www.virustotal.com/
VIRUSTOTAL_API_KEY = ""  # Add your API key here if you want to use VirusTotal
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
    """Runs ListDLLs.exe to get all loaded DLLs."""
    cmd = f'"{LISTDLLS_PATH}" -accepteula'
    try:
        print("Running ListDLLs (this may take a few moments)...")
        output = subprocess.check_output(cmd, shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error running ListDLLs: {e}")
        # Fallback to PowerShell method if ListDLLs fails
        print("Falling back to PowerShell method...")
        ps_command = 'powershell -Command "Get-Process | ForEach-Object {$_.Modules} | Where-Object {$_.FileName -like \'*.dll\'} | Select-Object FileName -Unique | Format-Table -HideTableHeaders"'
        try:
            output = subprocess.check_output(ps_command, shell=True, text=True)
            if output.strip():
                return output
        except Exception as e:
            print(f"Error with PowerShell fallback: {e}")
        
        return None

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
    
    # Check digital signature using sigcheck
    try:
        cmd = f'"{SIGCHECK_PATH}" -nobanner -a "{dll_path}"'
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout
        
        # Extract signature status
        if "Signed" in output:
            signed_match = re.search(r"Signed:\s*(\w+)", output, re.IGNORECASE)
            is_signed = signed_match and signed_match.group(1).lower() == "true"
            signature_info["SignatureStatus"] = "Signed" if is_signed else "Unsigned"
        else:
            signature_info["SignatureStatus"] = "Unsigned"
            
        # Extract publisher if available
        if "Publisher:" in output:
            publisher_match = re.search(r"Publisher:\s*(.*?)$", output, re.MULTILINE)
            if publisher_match:
                publisher = publisher_match.group(1).strip()
                signature_info["Publisher"] = publisher
                
                # Verify if publisher matches expected signer
                if expected_signer:
                    if publisher and expected_signer.lower() in publisher.lower():
                        signature_info["SignatureVerification"] = f"✓ Verified (matches {app_name})"
                    else:
                        signature_info["SignatureVerification"] = f"❌ Invalid (expected {expected_signer}, got {publisher})"
                else:
                    signature_info["SignatureVerification"] = "Unknown (no expected signer)"
        else:
            signature_info["Publisher"] = "None"
            if expected_signer:
                signature_info["SignatureVerification"] = f"❌ Invalid (expected {expected_signer}, no signature found)"
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
    
    dll_data = get_loaded_dlls()
    if not dll_data:
        print("❌ Unable to fetch DLL list!")
        return

    all_dlls = []
    suspicious_dlls = []
    
    # First pass: identify all DLLs and mark suspicious ones
    print("Identifying suspicious DLLs...")
    dll_count = 0
    for line in dll_data.split("\n"):
        match = re.search(r'([A-Za-z]:\\[^\s]+\.dll)', line)
        if match:
            dll_count += 1
            dll_path = match.group(1)
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
            print("2. Add your API key to the script at line 45 (VIRUSTOTAL_API_KEY variable)")
    
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
            print("\n" + tabulate(detailed_table, headers=headers, tablefmt="grid"))
            
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
            f.write(f"DLLs analyzed in detail: {len(suspicious_to_analyze)}\n\n")
            
            # Write detailed table to file
            if suspicious_to_analyze:
                f.write("ANALYZED SUSPICIOUS DLLs:\n")
                f.write(tabulate(detailed_table, headers=headers, tablefmt="grid"))
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

if __name__ == "__main__":
    analyze_dlls()
