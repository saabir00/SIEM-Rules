#!/usr/bin/env python3
"""
QRadar Rule Deploy Script — JSON to AQL
GitHub Actions CI/CD Pipeline

Hər rules/*.json üçün AQL-i QRadar Ariel API-sinə göndərir, search icra edir,
COMPLETED gözləyir və tapılan event-ləri göstərir. JSON sxemi:
  id, title, status, description, author, date, tags, mitre{}, logsource{},
  qradar{rule_name, severity, credibility, relevance, response_action},
  aql, falsepositives, level
"""

import os
import re
import json
import glob
import sys
import time
import urllib3
import requests
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST  = os.environ.get('QRADAR_HOST', '').rstrip('/')
QRADAR_TOKEN = os.environ.get('QRADAR_SEC_TOKEN') or os.environ.get('QRADAR_TOKEN', '')

if not QRADAR_HOST or not QRADAR_TOKEN:
    print("XETA: QRADAR_HOST ve ya QRADAR_SEC_TOKEN tapilmadi!")
    sys.exit(1)

HEADERS = {
    'SEC'     : QRADAR_TOKEN,
    'Accept'  : 'application/json',
    'Version' : '17.0',
}


# ── AQL-i hazirla ─────────────────────────────────────────────────
def build_aql(aql_template):
    """ORDER BY / LAST ... vaxt penceresini cixar, START/STOP elave et."""
    aql = aql_template.strip()

    # ORDER BY ... (bir sutun + yon) -> sil
    aql = re.sub(r'\bORDER\s+BY\s+[^()]+?\b(ASC|DESC)?\b(?=\s+LAST\b|\s*$)', ' ',
                 aql, flags=re.IGNORECASE)

    # LAST <n> SECONDS/MINUTES/HOURS/DAYS -> sil (START/STOP ile evez olunacaq)
    aql = re.sub(r'\bLAST\s+\d+\s+(SECONDS|MINUTES|HOURS|DAYS)\b', '',
                 aql, flags=re.IGNORECASE)

    aql = aql.strip().rstrip(';').strip()
    aql = re.sub(r'\s+', ' ', aql)  # bosluqlari sadelesdir

    # QEYD: bu rule-larin AQL-i artiq UTF8(payload) istifade edir,
    # ona gore elave 'payload' -> UTF8(payload) cevrilmesi ETMIRIK
    # (yoxsa UTF8(UTF8(payload)) yaranar).

    now   = datetime.utcnow()
    start = now - timedelta(hours=1)
    return (f"{aql} "
            f"START '{start.strftime('%Y-%m-%d %H:%M')}' "
            f"STOP '{now.strftime('%Y-%m-%d %H:%M')}'")


# ── AQL search icra et ────────────────────────────────────────────
def run_aql_search(aql_template):
    aql = build_aql(aql_template)
    print("   AQL gonderilir...")
    print(f"   {aql[:150]}...")

    post_headers = dict(HEADERS)
    post_headers['Content-Type'] = 'application/x-www-form-urlencoded'

    r = requests.post(
        f'{QRADAR_HOST}/api/ariel/searches',
        headers=post_headers,
        data=f'query_expression={requests.utils.quote(aql)}',
        verify=False,
    )
    if r.status_code not in (200, 201):
        print(f"   XETA: HTTP {r.status_code}")
        print(f"   {r.text[:300]}")
        return None

    search_id = r.json().get('search_id')
    print(f"   Search ID: {search_id}")

    status = None
    for i in range(20):
        time.sleep(3)
        sr = requests.get(f'{QRADAR_HOST}/api/ariel/searches/{search_id}',
                          headers=HEADERS, verify=False)
        status = sr.json().get('status')
        print(f"   Status [{i+1}]: {status}")
        if status == 'COMPLETED':
            break
        if status == 'ERROR':
            print("   XETA: AQL icra xetasi")
            return None

    rr = requests.get(f'{QRADAR_HOST}/api/ariel/searches/{search_id}/results',
                      headers=HEADERS, verify=False)
    if rr.status_code == 200:
        events = rr.json().get('events', [])
        print(f"   {len(events)} event tapildi")
        return events

    print(f"   XETA: Neticeler alinmadi HTTP {rr.status_code}")
    return None


# ── JSON rule-u islet ─────────────────────────────────────────────
def process_rule(rule_data):
    q        = rule_data.get('qradar', {})
    aql      = rule_data.get('aql', '')
    name     = q.get('rule_name', rule_data.get('title', 'Unnamed'))
    severity = q.get('severity', 'HIGH')
    mitre    = rule_data.get('mitre', {})
    tags     = rule_data.get('tags', [])

    print("\n" + "=" * 55)
    print(f"Rule    : {name}")
    print(f"Severity: {severity}")
    print(f"Tactic  : {mitre.get('tactic', 'N/A')}")
    print(f"MITRE   : {mitre.get('technique', 'N/A')}")
    print(f"Tags    : {', '.join(tags)}")
    print("=" * 55)

    if not aql:
        print("   XETA: AQL tapilmadi!")
        return False

    events = run_aql_search(aql.strip())
    if events is None:
        return False

    if len(events) > 0:
        print(f"\n   XEBERDARLIQ: {len(events)} subheli event!")
        for i, ev in enumerate(events[:3]):
            print(f"\n   [{i+1}]")
            print(f"     Event     : {ev.get('EventName', 'N/A')}")
            print(f"     SourceIP  : {ev.get('sourceip', ev.get('sourceIP', 'N/A'))}")
            print(f"     Username  : {ev.get('username', 'N/A')}")
            print(f"     LogSource : {ev.get('LogSource', 'N/A')}")
        if len(events) > 3:
            print(f"   ... ve {len(events)-3} event daha")
    else:
        print("   Tehlikeli event tapilmadi")

    return True


# ── Esas funksiya ─────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  QRadar JSON+AQL Deploy — GitHub Actions")
    print("=" * 55)
    print(f"  Host: {QRADAR_HOST}")
    print("=" * 55)

    rule_files = sorted(glob.glob('rules/*.json'))
    if not rule_files:
        print("XETA: rules/ qovlugunda JSON fayl tapilmadi!")
        sys.exit(1)

    print(f"\n{len(rule_files)} JSON rule fayl tapildi.\n")

    ok = fail = 0
    for f in rule_files:
        print(f"\nFayl: {f}")
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if data and process_rule(data):
                ok += 1
            else:
                fail += 1
        except json.JSONDecodeError as e:
            print(f"   XETA: JSON xetasi — {e}")
            fail += 1
        except Exception as e:
            print(f"   XETA: {e}")
            fail += 1

    print("\n" + "=" * 55)
    print(f"  Ugurlu : {ok}")
    print(f"  Xetali : {fail}")
    print("=" * 55)
    sys.exit(0)


if __name__ == '__main__':
    main()
