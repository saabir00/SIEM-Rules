#!/usr/bin/env python3
"""
validate_rules.py
-----------------
Lightweight pre-deploy linter. Runs in CI BEFORE deploy_rules.py so a malformed
rule never reaches Splunk. Checks each .spl file has the required header
(@name) and a non-empty SPL body, and that pipes/parentheses look balanced.
Exits non-zero on any problem.
"""
import os
import re
import sys
import glob

_here = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.environ.get("RULES_DIR", os.path.join(_here, "..", "rules"))


def check(path):
    errors = []
    name = None
    body = []
    in_body = False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not in_body and s.upper().startswith("# === SPL ==="):
                in_body = True
                continue
            if not in_body and s.startswith("#") and "@name" in s:
                name = s.split("=", 1)[1].strip() if "=" in s else None
            elif in_body and not s.startswith("#"):
                body.append(s)

    text = "\n".join([b for b in body if b])
    # Ignore parentheses inside quoted string / regex literals; only
    # SPL-syntax parens should be balance-checked.
    code = re.sub(r'"[^"]*"', '""', text)
    if not name:
        errors.append("missing '# @name =' header")
    if not text.strip():
        errors.append("empty SPL body (no content after '# === SPL ===')")
    if code.count("(") != code.count(")"):
        errors.append("unbalanced parentheses in SPL")
    if text and not text.lstrip().lower().startswith(("index", "|", "search", "tstats", "from")):
        errors.append("SPL should start with a base search (index=/search/|tstats)")
    return errors


def main():
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.spl")))
    if not files:
        print(f"::error::No .spl files in {RULES_DIR}")
        sys.exit(1)

    total_err = 0
    for path in files:
        errs = check(path)
        base = os.path.basename(path)
        if errs:
            total_err += len(errs)
            for e in errs:
                print(f"::error file={base}::{e}")
        else:
            print(f"  [OK] {base}")

    if total_err:
        print(f"\nValidation FAILED: {total_err} problem(s).")
        sys.exit(1)
    print(f"\nValidation passed: {len(files)} rule(s) OK.")


if __name__ == "__main__":
    main()
