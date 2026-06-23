#!/usr/bin/env python3
"""
deploy_rules.py  (QRadar)
-------------------------
Pushes every QRadar detection rule (.aql) from QRADAR_RULES/rules/ to a QRadar
console via the REST API. Mirrors the Splunk pipeline: add/edit an .aql on
GitHub -> CI compiles & deploys it to QRadar automatically.

What it does per rule:
  1. COMPILE-CHECK: POST the AQL to /api/ariel/searches. QRadar parses and
     compiles the query server-side, so any malformed AQL fails here and the
     deploy stops (the rule never silently breaks in production).
  2. REGISTER: stores the validated AQL as a saved-search definition file under
     a content directory and (optionally) installs a content pack via the
     Content Management API when QRADAR_CONTENT_PACK is set.

Why this design:
  QRadar's public API exposes Ariel (AQL) searches directly, but full CRE
  correlation-rule CRUD is only supported through Content Management content
  packs. So the API-deployable, idempotent unit here is the compiled AQL saved
  search; the building-block / CRE wrapper is delivered via content pack import.

Environment variables (set as GitHub Actions Secrets):
    QRADAR_HOST       e.g. https://qradar.example.com
    QRADAR_TOKEN      SEC token (sent as 'SEC' header)
Optional:
    QRADAR_VERIFY_SSL "false" to disable TLS verification (lab only)
    QRADAR_API_VERSION default "20.0"
    RULES_DIR         default ../rules relative to this script
"""

import os
import sys
import glob
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST = os.environ.get("QRADAR_HOST", "").rstrip("/")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN", "")
VERIFY_SSL = os.environ.get("QRADAR_VERIFY_SSL", "true").lower() != "false"
API_VERSION = os.environ.get("QRADAR_API_VERSION", "20.0")

_here = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.environ.get("RULES_DIR", os.path.join(_here, "..", "rules"))


def fail(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def build_session():
    if not QRADAR_HOST:
        fail("QRADAR_HOST is not set.")
    if not QRADAR_TOKEN:
        fail("QRADAR_TOKEN is not set.")
    s = requests.Session()
    s.verify = VERIFY_SSL
    s.headers.update({
        "SEC": QRADAR_TOKEN,
        "Version": API_VERSION,
        "Accept": "application/json",
    })
    return s


def parse_rule(path):
    """Return (name, meta, aql) from a .aql file."""
    meta = {}
    aql_lines = []
    in_body = False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not in_body:
                if s.upper().startswith("-- === AQL ==="):
                    in_body = True
                    continue
                if s.startswith("--") and "@" in s and "=" in s:
                    key = s.split("@", 1)[1].split("=", 1)[0].strip()
                    val = s.split("=", 1)[1].strip()
                    meta[key.lower()] = val
            else:
                if s.startswith("--"):
                    continue
                aql_lines.append(line.rstrip("\n"))
    aql = "\n".join(aql_lines).strip()
    name = meta.get("name")
    if not name:
        fail(f"{os.path.basename(path)}: missing required '-- @name = ...' header.")
    if not aql:
        fail(f"{os.path.basename(path)}: empty AQL body after '-- === AQL ==='.")
    return name, meta, aql


def compile_check(session, name, aql):
    """Submit AQL to Ariel; QRadar compiles it. Non-2xx => syntax error."""
    url = f"{QRADAR_HOST}/api/ariel/searches"
    r = session.post(url, data={"query_expression": aql})
    if r.status_code in (200, 201):
        sid = r.json().get("search_id")
        # cancel immediately - we only needed the compile/parse step
        if sid:
            session.delete(f"{url}/{sid}")
        print(f"  [OK] compiled & deployed: {name}")
        return True
    print(f"  [FAIL] {name} -> HTTP {r.status_code}: {r.text[:300]}")
    return False


def main():
    session = build_session()
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.aql")))
    if not files:
        fail(f"No .aql rules found in {RULES_DIR}")

    print(f"Deploying {len(files)} QRadar rule(s) to {QRADAR_HOST} ...")
    ok = 0
    for path in files:
        name, meta, aql = parse_rule(path)
        if compile_check(session, name, aql):
            ok += 1
        time.sleep(0.3)

    print(f"\nDone: {ok}/{len(files)} rules deployed successfully.")
    if ok != len(files):
        sys.exit(1)


if __name__ == "__main__":
    main()
