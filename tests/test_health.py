#!/usr/bin/env python3
"""Health tests for SecretGlyph. Built by Mourad.Soltani"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CLI = ROOT / "secretglyph.py"

def run(*args):
    result = subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr

def test_health():
    code, out, err = run("health", "--json")
    assert code == 0, err
    data = json.loads(out)
    assert data["ok"] is True
    assert data["signature"] == "Mourad.Soltani"
    assert data["entropy_works"] is True
    assert data["generate_works"] is True

def test_analyze():
    code, out, err = run("analyze", "password123", "--json")
    assert code == 0
    data = json.loads(out)
    assert data["strength"] in ("weak", "fair")
    assert data["total_bits"] > 0

def test_generate():
    code, out, err = run("generate", "--length", "20", "--json")
    assert code == 0
    data = json.loads(out)
    assert len(data["password"]) == 20
    assert data["strength"] in ("good", "strong", "excellent")

def test_scan_empty(tmp_path=None):
    # Just ensure scan doesn't crash on current dir (may find nothing)
    code, out, err = run("scan", ".", "--json")
    assert code == 0
    data = json.loads(out)
    assert "findings" in data
    assert "count" in data

if __name__ == "__main__":
    test_health()
    test_analyze()
    test_generate()
    test_scan_empty()
    print("All health tests passed.")
