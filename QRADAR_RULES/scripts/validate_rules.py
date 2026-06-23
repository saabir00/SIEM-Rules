#!/usr/bin/env python3
"""
validate_rules.py  (QRadar)
---------------------------
Offline pre-deploy linter for .aql rules. Runs in CI BEFORE deploy_rules.py so a
malformed rule never reaches QRadar. Checks each file has the required header
(@name), a non-empty AQL body starting with SELECT, balanced parentheses, and a
time window (LAST ... or START/STOP). Exits non-zero on any problem.
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
            if not in_body and s.upper().startswith("-- === AQL ==="):
                in_body = True
                continue
            if not in_body and s.startswith("--") and "@name" in s:
                name = s.split("=", 1)[1].strip() if "=" in s else None
            elif in_body and not s.startswith("--"):
                body.append(s)

    text = "\n".join([b for b in body if b])
    code = re.sub(r"'[^']*'", "''", text)   # ignore parens inside string literals

    if not name:
        errors.append("missing '-- @name =' header")
    if not text.strip():
        errors.append("empty AQL body (no content after '-- === AQL ===')")
    elif not text.lstrip().upper().startswith("SELECT"):
        errors.append("AQL should start with SELECT")
    if code.count("(") != code.count(")"):
        errors.append("unbalanced parentheses in AQL")
    if not re.search(r"\bLAST\b|\bSTART\b", text.upper()):
        errors.append("AQL missing time window (LAST ... or START/STOP)")
    return errors


def main():
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.aql")))
    if not files:
        print(f"::error::No .aql files in {RULES_DIR}")
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
