#!/usr/bin/env python3
"""
deploy_rules.py  (QRadar)
-------------------------
GitHub'dakı QRadar detection rule-larını QRadar Console'a deploy edir.

İKİ MƏRHƏLƏLİ axın (real deploy, sadəcə compile-check deyil):

  MƏRHƏLƏ 1 — COMPILE-CHECK (REST API):
    rules/*.aql fayllarının hər birini /api/ariel/searches-ə göndərir.
    QRadar AQL-i server tərəfdə kompilyasiya edir. Sintaksis xətası olan rule
    burada FAIL olur və deploy DAYANIR (xarab rule heç vaxt prod-a getmir).
    Search yoxlanışdan sonra dərhal silinir.

  MƏRHƏLƏ 2 — REAL DEPLOY (SSH + Content Management Tool):
    QRadar-da yeni CRE (offense) rule REST API ilə YARADILA bilmir.
    Dəstəklənən yeganə avtomatlaşma yolu — contentManagement.pl konsolda.
    Bu mərhələ content_packages/*.zip paketlərini SSH/SFTP ilə konsola atır və
    `contentManagement.pl --action update` ilə import edir.
      * update = eyni adlı rule ÜSTÜNDƏN yazılmır, YENİLƏNİR -> idempotent.
        GitHub-da dəyişib push edəndə SIEM-də avtomatik update olur.

Niyə belə dizayn:
    AQL = Ariel axtarış sorğusu (compile-check üçün əla). Offense yaradan CRE
    rule isə content-pack kimi import olunmalıdır. Beləliklə CI eyni anda həm
    AQL sintaksisini canlı QRadar-a qarşı yoxlayır, həm də rule-u real deploy edir.

Environment variables (GitHub Actions Secrets):
    QRADAR_HOST        məs: https://qradar.example.com   (REST API üçün)
    QRADAR_TOKEN       SEC token ('SEC' header)
    QRADAR_SSH_KEY     konsola root SSH private key faylının yolu
                       (default: ~/.ssh/id_ed25519)
Optional:
    QRADAR_SSH_HOST    SSH host (default: QRADAR_HOST-dan çıxarılır)
    QRADAR_SSH_USER    default "root"
    QRADAR_SSH_PORT    default "22"
    QRADAR_VERIFY_SSL  "false" -> TLS yoxlamasını söndür (yalnız lab)
    QRADAR_API_VERSION default "20.0"
    RULES_DIR          default ../rules
    PACKAGE_DIR        default ../QRADAR_RULES/content_packages
                       (yoxdursa Mərhələ 2 keçilir, yalnız compile-check işləyir)
    REMOTE_TMP         default /store/cmt_import
    SKIP_COMPILE       "true" -> Mərhələ 1-i keç
    SKIP_DEPLOY        "true" -> Mərhələ 2-i keç (yalnız compile-check)
"""

import os
import sys
import glob
import time
import urllib.parse
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST = os.environ.get("QRADAR_HOST", "").rstrip("/")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN", "")
VERIFY_SSL = os.environ.get("QRADAR_VERIFY_SSL", "true").lower() != "false"
API_VERSION = os.environ.get("QRADAR_API_VERSION", "20.0")

QRADAR_SSH_USER = os.environ.get("QRADAR_SSH_USER", "root")
QRADAR_SSH_PORT = int(os.environ.get("QRADAR_SSH_PORT", "22"))
QRADAR_SSH_KEY = os.environ.get(
    "QRADAR_SSH_KEY", os.path.expanduser("~/.ssh/id_ed25519")
)
REMOTE_TMP = os.environ.get("REMOTE_TMP", "/store/cmt_import")
CMT = "/opt/qradar/bin/contentManagement.pl"

SKIP_COMPILE = os.environ.get("SKIP_COMPILE", "false").lower() == "true"
SKIP_DEPLOY = os.environ.get("SKIP_DEPLOY", "false").lower() == "true"

_here = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.environ.get("RULES_DIR", os.path.join(_here, "..", "rules"))
PACKAGE_DIR = os.environ.get(
    "PACKAGE_DIR", os.path.join(_here, "..", "QRADAR_RULES", "content_packages")
)


def fail(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def ssh_host():
    explicit = os.environ.get("QRADAR_SSH_HOST")
    if explicit:
        return explicit
    netloc = urllib.parse.urlparse(QRADAR_HOST).netloc or QRADAR_HOST
    return netloc.split("@")[-1].split(":")[0]


# --------------------------------------------------------------------------- #
# MƏRHƏLƏ 1 — COMPILE-CHECK
# --------------------------------------------------------------------------- #
def build_session():
    if not QRADAR_HOST:
        fail("QRADAR_HOST təyin edilməyib.")
    if not QRADAR_TOKEN:
        fail("QRADAR_TOKEN təyin edilməyib.")
    s = requests.Session()
    s.verify = VERIFY_SSL
    s.headers.update(
        {"SEC": QRADAR_TOKEN, "Version": API_VERSION, "Accept": "application/json"}
    )
    return s


def parse_rule(path):
    """Return (name, meta, aql) from a .aql file."""
    meta, aql_lines, in_body = {}, [], False
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
        fail(f"{os.path.basename(path)}: '-- @name = ...' header yoxdur.")
    if not aql:
        fail(f"{os.path.basename(path)}: '-- === AQL ===' sonra AQL boşdur.")
    return name, meta, aql


def compile_check(session, name, aql):
    url = f"{QRADAR_HOST}/api/ariel/searches"
    r = session.post(url, data={"query_expression": aql})
    if r.status_code in (200, 201):
        sid = r.json().get("search_id")
        if sid:
            session.delete(f"{url}/{sid}")
        print(f"  [OK] compiled: {name}")
        return True
    print(f"  [FAIL] {name} -> HTTP {r.status_code}: {r.text[:300]}")
    return False


def run_compile_phase():
    session = build_session()
    files = sorted(glob.glob(os.path.join(RULES_DIR, "*.aql")))
    if not files:
        fail(f"{RULES_DIR} içində .aql rule tapılmadı")
    print(f"[Mərhələ 1] {len(files)} rule-un AQL sintaksisi yoxlanılır ...")
    ok = 0
    for path in files:
        name, _meta, aql = parse_rule(path)
        if compile_check(session, name, aql):
            ok += 1
        time.sleep(0.3)
    print(f"[Mərhələ 1] Nəticə: {ok}/{len(files)} rule compile oldu.")
    if ok != len(files):
        fail("Bəzi rule-lar compile olmadı — deploy dayandırıldı.")


# --------------------------------------------------------------------------- #
# MƏRHƏLƏ 2 — REAL DEPLOY (SSH + CMT)
# --------------------------------------------------------------------------- #
def run_deploy_phase():
    packages = sorted(glob.glob(os.path.join(PACKAGE_DIR, "*.zip")))
    if not packages:
        print(
            f"[Mərhələ 2] {PACKAGE_DIR} içində content paketi yoxdur -> "
            "deploy keçildi. (Əvvəlcə export_rules.py ilə rule-ları çıxarın.)"
        )
        return

    try:
        import paramiko
    except ImportError:
        fail("paramiko quraşdırılmayıb. `pip install -r requirements.txt` edin.")

    host = ssh_host()
    print(f"[Mərhələ 2] {len(packages)} paket {host} konsoluna deploy edilir ...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=QRADAR_SSH_PORT,
        username=QRADAR_SSH_USER,
        key_filename=QRADAR_SSH_KEY,
        timeout=20,
    )

    def run(cmd):
        _in, out, err = client.exec_command(cmd)
        rc = out.channel.recv_exit_status()
        return rc, out.read().decode(errors="replace"), err.read().decode(errors="replace")

    failed = 0
    try:
        run(f"mkdir -p '{REMOTE_TMP}'")
        sftp = client.open_sftp()
        for pkg in packages:
            base = os.path.basename(pkg)
            remote = f"{REMOTE_TMP}/{base}"
            print(f"  -> kopyalanır: {base}")
            sftp.put(pkg, remote)
            print(f"  -> import (update): {base}")
            rc, sout, serr = run(f"{CMT} --action update -f '{remote}'")
            if rc == 0:
                print(f"  [OK] {base}")
            else:
                failed += 1
                print(f"  [FAIL] {base} (rc={rc})\n{sout}\n{serr}")
        sftp.close()
        run(f"rm -f '{REMOTE_TMP}'/*.zip")
    finally:
        client.close()

    if failed:
        fail(f"{failed} paket deploy olmadı.")
    print("[Mərhələ 2] Deploy tamamlandı.")
    print("QEYD: Lazım olsa QRadar UI -> 'Admin > Deploy Changes' edin.")


def main():
    if not SKIP_COMPILE:
        run_compile_phase()
    else:
        print("[Mərhələ 1] keçildi (SKIP_COMPILE=true).")

    if not SKIP_DEPLOY:
        run_deploy_phase()
    else:
        print("[Mərhələ 2] keçildi (SKIP_DEPLOY=true).")

    print("\nHazırdır.")


if __name__ == "__main__":
    main()
