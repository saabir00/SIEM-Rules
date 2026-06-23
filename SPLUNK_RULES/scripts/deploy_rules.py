#!/usr/bin/env python3
"""
deploy_rules.py
---------------
Pushes every Splunk detection rule (.spl) from SPLUNK_RULES/rules/ to a Splunk
instance via the REST API as a Saved Search (scheduled alert).

It is IDEMPOTENT: if a saved search with the same name already exists it is
UPDATED (POST to the named endpoint); otherwise it is CREATED. This is what the
GitHub Actions workflow runs on every push, so "add a rule on GitHub -> it
appears/updates in Splunk automatically".

Rule file format (parsed from the header comments):
    # @name     = <saved search name>      (required)
    # @cron     = */5 * * * *               (cron_schedule)
    # @earliest = -10m@m                    (dispatch.earliest_time)
    # @latest   = now                       (dispatch.latest_time)
    # @severity = 4                         (alert.severity 1-6)
    # @app      = search                    (Splunk app context, default 'search')
    # === SPL ===
    <the SPL search body ...>

Required environment variables (set as GitHub Actions Secrets):
    SPLUNK_HOST       e.g. https://splunk.example.com:8089
    SPLUNK_TOKEN      Splunk authentication (Bearer) token
        -- OR --
    SPLUNK_USERNAME / SPLUNK_PASSWORD
Optional:
    SPLUNK_OWNER      owner namespace for the saved search (default: nobody)
    SPLUNK_VERIFY_SSL "false" to disable TLS verification (lab only)
    RULES_DIR         path to rules dir (default: ../rules relative to script)
"""

import os
import sys
import glob
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------------------------------------------------------
# Configuration from environment
# ----------------------------------------------------------------------------
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "").rstrip("/")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_USER = os.environ.get("SPLUNK_USERNAME", "")
SPLUNK_PASS = os.environ.get("SPLUNK_PASSWORD", "")
SPLUNK_OWNER = os.environ.get("SPLUNK_OWNER", "nobody")
VERIFY_SSL = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() != "false"

_here = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.environ.get("RULES_DIR", os.path.join(_here, "..", "rules"))


def fail(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def build_session():
    if not SPLUNK_HOST:
        fail("SPLUNK_HOST is not set.")
    s = requests.Session()
    s.verify = VERIFY_SSL
    if SPLUNK_TOKEN:
        s.headers.update({"Authorization": f"Bearer {SPLUNK_TOKEN}"})
    elif SPLUNK_USER and SPLUNK_PASS:
        s.auth = (SPLUNK_USER, SPLUNK_PASS)
    else:
        fail("Provide SPLUNK_TOKEN or SPLUNK_USERNAME + SPLUNK_PASSWORD.")
    return s


def parse_rule(path):
    """Return (name, params_dict, search_string) from a .spl rule file."""
    meta = {}
    search_lines = []
    in_body = False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not in_body:
                if stripped.upper().startswith("# === SPL ==="):
                    in_body = True
                    continue
                if stripped.startswith("#") and "@" in stripped and "=" in stripped:
                    key = stripped.split("@", 1)[1].split("=", 1)[0].strip()
                    val = stripped.split("=", 1)[1].strip()
                    meta[key.lower()] = val
            else:
                # strip trailing explanatory comments inside the body
                if stripped.startswith("# NOTE") or stripped.startswith("# ----"):
                    continue
                search_lines.append(line.rstrip("\n"))

    search = "\n".join(search_lines).strip()
    name = meta.get("name")
    if not name:
        fail(f"{os.path.basename(path)}: missing required '# @name = ...' header.")
    if not search:
        fail(f"{os.path.basename(path)}: empty search body after '# === SPL ==='.")

    params = {
        "search": search,
        "cron_schedule": meta.get("cron", "*/10 * * * *"),
        "dispatch.earliest_time": meta.get("earliest", "-15m@m"),
        "dispatch.latest_time": meta.get("latest", "now"),
        "is_scheduled": "1",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.severity": meta.get("severity", "3"),
        "alert.suppress": "1",
        "alert.suppress.period": "3600s",
        "alert.track": "1",
        "actions": meta.get("actions", ""),
        "disabled": "0",
    }
    app = meta.get("app", "search")
    return name, app, params


def deploy(session, name, app, params):
    base = f"{SPLUNK_HOST}/servicesNS/{SPLUNK_OWNER}/{app}/saved/searches"
    # Does it already exist?
    from urllib.parse import quote
    check = session.get(f"{base}/{quote(name, safe='')}",
                        params={"output_mode": "json"})
    if check.status_code == 200:
        # UPDATE: cannot send 'name' on update
        update_params = {k: v for k, v in params.items() if k != "name"}
        r = session.post(f"{base}/{quote(name, safe='')}",
                         data={**update_params, "output_mode": "json"})
        action = "UPDATED"
    else:
        # CREATE
        r = session.post(base, data={**params, "name": name,
                                     "output_mode": "json"})
        action = "CREATED"

    if r.status_code in (200, 201):
        print(f"  [OK] {action}: {name}")
        return True
    print(f"  [FAIL] {name} -> HTTP {r.status_code}: {r.text[:300]}")
    return False


def main():
    session = build_session()
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.spl")))
    if not files:
        fail(f"No .spl rules found in {RULES_DIR}")

    print(f"Deploying {len(files)} rule(s) to {SPLUNK_HOST} ...")
    ok = 0
    for path in files:
        name, app, params = parse_rule(path)
        if deploy(session, name, app, params):
            ok += 1

    print(f"\nDone: {ok}/{len(files)} rules deployed successfully.")
    if ok != len(files):
        sys.exit(1)


if __name__ == "__main__":
    main()
