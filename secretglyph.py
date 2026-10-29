#!/usr/bin/env python3
"""
SecretGlyph - Offline secret entropy prober and generator.
Built by Mourad.Soltani

Probes directories and strings for weak secrets using Shannon entropy
and common patterns. Generates strong replacements. Fully offline.
"""

import argparse
import json
import math
import os
import re
import secrets
import string
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Signature: Mourad.Soltani

VERSION = "1.0.0"
SIGNATURE = "Mourad.Soltani"

# Common secret patterns (regex)
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key", "critical"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI / Anthropic style key", "critical"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", "critical"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token", "critical"),
    (r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})", "Generic secret assignment", "high"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", "critical"),
]

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def total_entropy_bits(s: str) -> float:
    """Approximate total entropy bits (length * shannon)."""
    return len(s) * shannon_entropy(s)

def strength_label(bits: float) -> str:
    if bits < 28:
        return "weak"
    if bits < 40:
        return "fair"
    if bits < 60:
        return "good"
    if bits < 80:
        return "strong"
    return "excellent"

def analyze_string(s: str) -> Dict:
    """Analyze a single string for entropy and strength."""
    ent = shannon_entropy(s)
    bits = total_entropy_bits(s)
    return {
        "value_length": len(s),
        "shannon_entropy": round(ent, 3),
        "total_bits": round(bits, 1),
        "strength": strength_label(bits),
        "charset_size": len(set(s)),
    }

def generate_password(length: int = 24, charset: str = "alnum+sym") -> str:
    """Generate cryptographically strong password using secrets."""
    if charset == "alnum":
        chars = string.ascii_letters + string.digits
    elif charset == "alnum+sym":
        chars = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    else:
        chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))

def scan_file(path: Path, min_entropy: float = 3.5, min_len: int = 16) -> List[Dict]:
    """Scan a single file for potential secrets."""
    findings = []
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return findings

    # Pattern matches
    for pattern, name, severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            if len(value) >= min_len:
                analysis = analyze_string(value)
                findings.append({
                    "file": str(path),
                    "line_approx": text[:match.start()].count("\n") + 1,
                    "type": name,
                    "severity": severity,
                    "matched": value[:40] + "..." if len(value) > 40 else value,
                    **analysis,
                })

    # High-entropy candidates (simple heuristic)
    # Look for long alnum strings
    for match in re.finditer(r"[A-Za-z0-9_\-]{20,}", text):
        cand = match.group(0)
        ent = shannon_entropy(cand)
        if ent >= min_entropy and len(cand) >= min_len:
            # Avoid duplicates from patterns
            if not any(f["matched"].startswith(cand[:20]) for f in findings):
                analysis = analyze_string(cand)
                findings.append({
                    "file": str(path),
                    "line_approx": text[:match.start()].count("\n") + 1,
                    "type": "high-entropy candidate",
                    "severity": "medium",
                    "matched": cand[:40] + "..." if len(cand) > 40 else cand,
                    **analysis,
                })
    return findings

def scan_directory(root: Path, extensions: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> List[Dict]:
    """Recursively scan directory."""
    if extensions is None:
        extensions = [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".toml", ".sh", ".md"]
    if exclude is None:
        exclude = ["node_modules", ".git", "__pycache__", "dist", "build", ".venv"]

    findings = []
    for path in root.rglob("*"):
        if any(ex in path.parts for ex in exclude):
            continue
        if path.is_file() and path.suffix.lower() in extensions:
            findings.extend(scan_file(path))
    return findings

def cmd_analyze(args):
    s = args.string
    if args.file:
        s = Path(args.file).read_text().strip()
    result = analyze_string(s)
    result["input"] = s[:60] + "..." if len(s) > 60 else s
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"SecretGlyph analyze | {SIGNATURE}")
        print(f"Length: {result['value_length']}")
        print(f"Shannon entropy: {result['shannon_entropy']} bits/char")
        print(f"Total bits: {result['total_bits']}")
        print(f"Strength: {result['strength']}")
        print(f"Unique chars: {result['charset_size']}")

def cmd_generate(args):
    pw = generate_password(args.length, args.charset)
    result = {
        "password": pw,
        **analyze_string(pw),
        "note": "Generated with secrets module (CSPRNG)",
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"SecretGlyph generate | {SIGNATURE}")
        print(pw)
        print(f"Strength: {result['strength']} ({result['total_bits']} bits)")

def cmd_scan(args):
    root = Path(args.path)
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        sys.exit(1)
    findings = scan_directory(root)
    if args.json:
        print(json.dumps({"findings": findings, "count": len(findings), "signature": SIGNATURE}, indent=2))
    else:
        print(f"SecretGlyph scan | {SIGNATURE} | {len(findings)} findings")
        for f in findings[:50]:  # limit display
            print(f"[{f['severity'].upper()}] {f['type']} in {f['file']}:{f['line_approx']} — {f['matched']} ({f['total_bits']} bits)")
        if len(findings) > 50:
            print(f"... and {len(findings)-50} more (use --json)")

def cmd_health(args):
    """Health check for tests and buyers."""
    checks = {
        "version": VERSION,
        "signature": SIGNATURE,
        "entropy_works": shannon_entropy("aaaa") < 0.1 and shannon_entropy("abc123XYZ!@#") > 2.5,
        "generate_works": len(generate_password(16)) == 16,
        "stdlib_only": True,
    }
    ok = all(checks.values()) if isinstance(list(checks.values())[2], bool) else True
    checks["ok"] = ok
    if args.json:
        print(json.dumps(checks, indent=2))
    else:
        print(f"SecretGlyph health | {SIGNATURE}")
        for k, v in checks.items():
            print(f"  {k}: {v}")
    sys.exit(0 if ok else 1)

def main():
    parser = argparse.ArgumentParser(
        description="SecretGlyph - Offline secret entropy prober. Built by Mourad.Soltani"
    )
    parser.add_argument("--version", action="version", version=f"SecretGlyph {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="Analyze entropy of a string or file")
    p_an.add_argument("string", nargs="?", help="String to analyze")
    p_an.add_argument("--file", help="File containing the string")
    p_an.add_argument("--json", action="store_true")
    p_an.set_defaults(func=cmd_analyze)

    p_gen = sub.add_parser("generate", help="Generate a strong password")
    p_gen.add_argument("--length", type=int, default=24)
    p_gen.add_argument("--charset", choices=["alnum", "alnum+sym"], default="alnum+sym")
    p_gen.add_argument("--json", action="store_true")
    p_gen.set_defaults(func=cmd_generate)

    p_scan = sub.add_parser("scan", help="Scan directory for potential secrets")
    p_scan.add_argument("path", help="Directory or file to scan")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_health = sub.add_parser("health", help="Health check")
    p_health.add_argument("--json", action="store_true")
    p_health.set_defaults(func=cmd_health)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
