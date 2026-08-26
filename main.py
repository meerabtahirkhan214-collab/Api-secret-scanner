#!/usr/bin/env python3
"""
 Source Code Editor
------------------------------------------
A lightweight static-analysis tool that scans text/code files for
patterns matching common API keys, tokens, and credentials.

Author: [Meerab khan]
Purpose: Portfolio project demonstrating regex-based secret scanning.
"""

import re
import os
import sys

# -------------------------------------------------------------------
# STEP 1: Define regex patterns for well-known API key formats.
# Each service has a somewhat predictable "shape" for its keys
# (prefix + fixed length + character set), which makes them
# detectable without needing the actual key value.
# -------------------------------------------------------------------
PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token":          r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "GitHub Token":         r"gh[pousr]_[0-9a-zA-Z]{36}",
    "Generic Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
    "Generic API Key":      r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]",
    "Generic Secret":       r"(?i)(secret|token|passwd|password)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
    "Private Key Block":    r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----",
}

# Pre-compile patterns once for performance (avoids recompiling
# the same regex on every line of every file).
COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}


def scan_file(filepath):
    """
    Scans a single file line-by-line for secret patterns.
    Returns a list of findings: (line_number, key_type, matched_text).
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for key_type, pattern in COMPILED_PATTERNS.items():
                    match = pattern.search(line)
                    if match:
                        findings.append((line_number, key_type, match.group().strip()))
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not read {filepath}: {e}")

    return findings


def mask_secret(secret, visible_chars=4):
    """
    Masks a detected secret so it's safe to print/log
    (e.g., 'AKIA123...XYZ9' instead of the full key).
    """
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]


def scan_directory(directory):
    """
    Walks through a directory recursively and scans every file.
    Skips common non-text/irrelevant folders like .git and node_modules.
    """
    skip_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv"}
    all_results = {}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]  # prune skip dirs in-place

        for filename in files:
            filepath = os.path.join(root, filename)
            results = scan_file(filepath)
            if results:
                all_results[filepath] = results

    return all_results


def print_report(all_results):
    """
    Prints a clean, readable summary report of all findings.
    """
    if not all_results:
        print("✅ No leaked credentials detected.")
        return

    print("🚨 POTENTIAL LEAKED CREDENTIALS FOUND 🚨\n")
    total = 0
    for filepath, findings in all_results.items():
        print(f"📄 File: {filepath}")
        for line_number, key_type, matched_text in findings:
            print(f"   Line {line_number}: [{key_type}] -> {mask_secret(matched_text)}")
            total += 1
        print()

    print(f"Total findings: {total}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]

    if os.path.isfile(target):
        results = {target: scan_file(target)}
        results = {k: v for k, v in results.items() if v}  # drop empty
    elif os.path.isdir(target):
        results = scan_directory(target)
    else:
        print(f"[ERROR] Path not found: {target}")
        sys.exit(1)

    print_report(results)