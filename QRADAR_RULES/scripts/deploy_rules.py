#!/usr/bin/env python3
"""
deploy_rules.py  (QRadar) — JSON + AQL deploy (REST API)
--------------------------------------------------------
GitHub'dakı rules/*.json rule-larını QRadar-a "deploy" edir.

Hər rule üçün: metadata banner çıxarır, AQL-i QRadar Ariel API-sinə göndərir,
search-i icra edir (COMPLETED gözləyir), neçə event tapıldığını göstərir.

Environment variables (GitHub Secrets):
  QRADAR_HOST        məs: https://10.0.0.10
  QRADAR_SEC_TOKEN  (və ya QRADAR_TOKEN)   SEC token
Optional:
  QRADAR_VERIFY_SSL  default "false"
  QRADAR_API_VERSION default "20.0"
  RULES_DIR          default ../rules
  POLL_TIMEOUT       default 60
"""

import os
import sys
import glob
import time
import json
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.environ.get("QRADAR_HOST", "").rstrip("/")
TOKEN = os.environ.get("QRADAR_SEC_TOKEN") or os.environ.get("QRADAR_TOKEN", "")
VERIFY = os.environ.get("QRADAR_VERIFY_SSL", "false").lower() == "true"
API_VERSION = os.environ.get("QRADAR_API_VERSION", "20.0")
POLL_TIMEOUT = int(os.environ.get("POLL_TIMEOUT", "60"))

_here = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.environ.get("RULES_DIR", os.path.join(_here, "..", "rules"))

LINE = "=" * 55


def run_search(session, aql):
    r = session.post(f"{HOST}/api/ariel/searches", data={"query_expression": aql})
    if r.status_code not in (200, 201):
        return ("ERROR", 0, f"HTTP {r.status_code}: {r.text[:200]}")
    sid = r.json().get("search_id")
    deadline = time.time() + POLL_TIMEOUT
    status, count = "UNKNOWN", 0
    while time.time() < deadline:
        j = session.get(f"{HOST}/api/ariel/searches/{sid}").json()
        status = j.get("status", "UNKNOWN")
        count = j.get("record_count", 0)
        if status in ("COMPLETED", "ERROR", "CANCELED"):
            break
        time.sleep(1)
    try:
        session.delete(f"{HOST}/api/ariel/searches/{sid}")
    except Exception:
        pass
    return (status, count, sid)


def main():
    if not HOST or not TOKEN:
        print("::error::QRADAR_HOST ve ya QRADAR_SEC_TOKEN teyin edilmeyib.")
        sys.exit(1)

    session = requests.Session()
    session.verify = VERIFY
    session.headers.update({"SEC": TOKEN, "Version": API_VERSION, "Accept": "application/json"})

    print(LINE)
    print("  QRadar JSON+AQL Deploy — GitHub Actions")
    print(LINE)
    print(f"  Host: {HOST}")
    print(LINE)

    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.json")))
    print(f"{len(files)} JSON rule fayl tapildi.")

    ok, err = 0, 0
    for path in files:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        rid = data.get("id", "")
        title = data.get("title", "")
        full = f"{rid}: {title}" if rid else title
        tags = data.get("tags", [])
        tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags)

        print(f"Fayl: {os.path.relpath(path)}")
        print(LINE)
        print(f"Rule    : {full}")
        print(f"Severity: {data.get('severity', '-')}")
        print(f"Tactic  : {data.get('tactic', '-')}")
        print(f"MITRE   : {data.get('mitre', '-')}")
        print(f"Tags    : {tags_str}")
        print(LINE)
        print("   AQL gonderilir...")
        aql = data.get("aql", "")
        print("   " + aql[:90] + "...")

        status, count, info = run_search(session, aql)
        if status == "ERROR":
            print(f"   [XETA] {info}")
            err += 1
        else:
            print(f"   Search ID: {info}")
            print(f"   Status [1]: {status}")
            print(f"   {count} event tapildi")
            print("   Tehlikeli event tapildi" if count else "   Tehlikeli event tapilmadi")
            if status == "COMPLETED":
                ok += 1
            else:
                err += 1
        time.sleep(0.2)

    print(LINE)
    print(f"  Ugurlu : {ok}")
    print(f"  Xetali : {err}")
    print(LINE)
    if err:
        sys.exit(1)


if __name__ == "__main__":
    main()
