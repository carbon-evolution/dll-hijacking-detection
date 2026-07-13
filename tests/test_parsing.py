"""Cross-platform tests for the parsing / signature helpers.

These mock out subprocess so the Windows-only code paths (PowerShell signature
parsing, DLL-path extraction, cert-subject parsing) can be verified on any OS.
Run with:  python -m pytest -q
"""
import os
import importlib.util
from types import SimpleNamespace

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "find_suspicious_dlls", os.path.join(_ROOT, "find_suspicious_dlls.py"))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def test_extract_cn_plain():
    assert m._extract_cn("CN=Google LLC, O=Google, L=Mountain View") == "Google LLC"


def test_extract_cn_quoted_with_comma():
    assert m._extract_cn('CN="Foo, Bar Inc.", O=x') == "Foo, Bar Inc."


def test_extract_cn_empty():
    assert m._extract_cn("") == ""


def test_extract_dll_paths_dedupes_and_sorts():
    text = (
        r"C:\Windows\System32\kernel32.dll" "\n"
        r"some noise C:\Program Files\App\helper.dll more" "\n"
        r"C:\Windows\System32\kernel32.dll" "\n"   # duplicate
        "no dll here\n"
    )
    paths = m._extract_dll_paths(text)
    assert paths == [r"C:\Program Files\App\helper.dll", r"C:\Windows\System32\kernel32.dll"]


def test_signature_via_powershell_valid(monkeypatch):
    monkeypatch.setattr(m.subprocess, "run",
        lambda *a, **k: SimpleNamespace(stdout="Valid||CN=Google LLC, O=Google", stderr=""))
    is_signed, publisher = m._signature_via_powershell(r"C:\x\a.dll")
    assert is_signed is True
    assert publisher == "Google LLC"


def test_signature_via_powershell_unsigned(monkeypatch):
    monkeypatch.setattr(m.subprocess, "run",
        lambda *a, **k: SimpleNamespace(stdout="NotSigned||", stderr=""))
    is_signed, publisher = m._signature_via_powershell(r"C:\x\a.dll")
    assert is_signed is False
    assert publisher == ""


def test_is_suspicious_dll_paths():
    assert m.is_suspicious_dll(r"C:\Users\bob\AppData\Local\App\evil.dll") is True
    assert m.is_suspicious_dll(r"C:\Windows\System32\kernel32.dll") is False


def test_run_hijack_detection_dedup_and_sort(monkeypatch):
    # Two findings for the same dll+type should collapse; HIGH sorts before MEDIUM.
    monkeypatch.setattr(m, "get_system_dll_index", lambda: set())
    monkeypatch.setattr(m, "get_known_dlls", lambda: set())
    monkeypatch.setattr(m, "detect_phantom_opportunities", lambda *a, **k: [])
    monkeypatch.setattr(m, "detect_shadow_and_writable", lambda *a, **k: [
        {"type": "WRITABLE", "severity": "MEDIUM", "dll": r"C:\a\x.dll", "detail": "d", "technique": "t"},
        {"type": "SHADOW",   "severity": "HIGH",   "dll": r"C:\a\y.dll", "detail": "d", "technique": "t"},
        {"type": "SHADOW",   "severity": "HIGH",   "dll": r"C:\a\y.dll", "detail": "d", "technique": "t"},
    ])
    findings = m.run_hijack_detection([])
    assert len(findings) == 2
    assert findings[0]["severity"] == "HIGH"
