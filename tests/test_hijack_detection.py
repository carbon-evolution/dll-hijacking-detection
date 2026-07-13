"""Cross-platform tests for the DLL hijacking detectors.

These exercise the detection logic with synthetic paths, so they run on any OS
(no Windows or live processes required). Run with:  python -m pytest -q
"""
import os
import sys
import tempfile
import importlib.util

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "find_suspicious_dlls", os.path.join(_ROOT, "find_suspicious_dlls.py"))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def _setup(monkeypatch_system_dirs):
    sysdir = tempfile.mkdtemp()
    m._SYSTEM_DIRS = [sysdir]
    return sysdir


def test_shadow_from_writable_dir_is_high():
    app = tempfile.mkdtemp()
    sysdir = _setup(app)
    loaded = [os.path.join(app, "version.dll")]  # system name, non-system writable dir
    findings = m.detect_shadow_and_writable(loaded, {"version.dll"}, set())
    assert len(findings) == 1
    assert findings[0]["type"] == "SHADOW"
    assert findings[0]["severity"] == "HIGH"


def test_known_dll_is_never_flagged():
    app = tempfile.mkdtemp()
    _setup(app)
    loaded = [os.path.join(app, "kernel32.dll")]
    findings = m.detect_shadow_and_writable(loaded, {"kernel32.dll"}, {"kernel32.dll"})
    assert findings == []


def test_system_copy_is_ignored():
    app = tempfile.mkdtemp()
    sysdir = _setup(app)
    loaded = [os.path.join(sysdir, "version.dll")]  # legit copy in System32
    findings = m.detect_shadow_and_writable(loaded, {"version.dll"}, set())
    assert findings == []


def test_writable_nonsystem_dll_is_low():
    app = tempfile.mkdtemp()
    _setup(app)
    loaded = [os.path.join(app, "vendor_helper.dll")]  # not a system name
    findings = m.detect_shadow_and_writable(loaded, {"version.dll"}, set())
    assert len(findings) == 1
    assert findings[0]["type"] == "WRITABLE"
    assert findings[0]["severity"] == "LOW"


def test_redistributable_shadow_is_ignored():
    app = tempfile.mkdtemp()
    _setup(app)
    # vcruntime140 legitimately ships in app folders even though it exists in System32.
    loaded = [os.path.join(app, "vcruntime140.dll")]
    findings = m.detect_shadow_and_writable(loaded, {"vcruntime140.dll"}, set())
    assert findings == []


def test_apiset_helper():
    assert m._is_apiset("api-ms-win-core-file-l1-1-0.dll") is True
    assert m._is_apiset("ext-ms-win-foo.dll") is True
    assert m._is_apiset("kernel32.dll") is False


def test_format_findings_empty_and_nonempty():
    assert "None detected" in m.format_hijack_findings([])
    block = m.format_hijack_findings([
        {"type": "SHADOW", "severity": "HIGH", "dll": r"C:\a\version.dll",
         "detail": "x", "technique": "T1574.001"}])
    assert "HIGH" in block and "version.dll" in block


if __name__ == "__main__":
    # Allow running without pytest installed.
    import traceback
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); passed += 1; print(f"PASS {name}")
            except Exception:
                failed += 1; print(f"FAIL {name}"); traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
