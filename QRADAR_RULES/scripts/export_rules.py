#!/usr/bin/env python3
"""
export_rules.py  (QRadar)
-------------------------
QRadar UI-də qurulmuş Custom/Offense rule-larını content paketi (.zip) kimi
konsoldan export edib repoya gətirir. "Source of truth GitHub-dadır" axınının
ilk halqası:

    UI-də rule qur  ->  export_rules.py  ->  commit & push
                    ->  GitHub Actions   ->  deploy_rules.py (real deploy)

İki rejim (MODE env):
    ALL  : bütün custom rule-ları bir paketdə export edir
    IDS  : yalnız RULE_IDS-də göstərilən rule ID-lərini export edir

Environment variables:
    QRADAR_SSH_HOST (və ya QRADAR_HOST), QRADAR_SSH_USER (def root),
    QRADAR_SSH_PORT (def 22), QRADAR_SSH_KEY (def ~/.ssh/id_ed25519)
    MODE (def ALL), RULE_IDS (MODE=IDS üçün, məs "100,101")
    PACKAGE_DIR (def ../QRADAR_RULES/content_packages)
    REMOTE_OUT (def /store/cmt_export)
"""

import os
import sys
import glob
import urllib.parse

CMT = "/opt/qradar/bin/contentManagement.pl"
_here = os.path.dirname(os.path.abspath(__file__))

MODE = os.environ.get("MODE", "ALL").upper()
RULE_IDS = os.environ.get("RULE_IDS", "")
PACKAGE_DIR = os.environ.get(
    "PACKAGE_DIR", os.path.join(_here, "..", "QRADAR_RULES", "content_packages")
)
REMOTE_OUT = os.environ.get("REMOTE_OUT", "/store/cmt_export")
SSH_USER = os.environ.get("QRADAR_SSH_USER", "root")
SSH_PORT = int(os.environ.get("QRADAR_SSH_PORT", "22"))
SSH_KEY = os.environ.get("QRADAR_SSH_KEY", os.path.expanduser("~/.ssh/id_ed25519"))


def ssh_host():
    h = os.environ.get("QRADAR_SSH_HOST") or os.environ.get("QRADAR_HOST", "")
    netloc = urllib.parse.urlparse(h).netloc or h
    return netloc.split("@")[-1].split(":")[0]


def main():
    host = ssh_host()
    if not host:
        sys.exit("::error::QRADAR_SSH_HOST (və ya QRADAR_HOST) təyin edilməyib.")

    if MODE == "ALL":
        export_cmd = f"{CMT} -a export -c customrule --id all -o '{REMOTE_OUT}'"
    elif MODE == "IDS":
        if not RULE_IDS:
            sys.exit("::error::MODE=IDS üçün RULE_IDS lazımdır (məs: 100,101).")
        export_cmd = f"{CMT} -a export -c 3 --id '{RULE_IDS}' -o '{REMOTE_OUT}'"
    else:
        sys.exit(f"::error::Tanımsız MODE: {MODE} (ALL və ya IDS).")

    try:
        import paramiko
    except ImportError:
        sys.exit("::error::paramiko yoxdur. `pip install -r requirements.txt`.")

    os.makedirs(PACKAGE_DIR, exist_ok=True)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=SSH_PORT, username=SSH_USER,
                   key_filename=SSH_KEY, timeout=20)
    try:
        for cmd in (f"mkdir -p '{REMOTE_OUT}'", export_cmd):
            _in, out, err = client.exec_command(cmd)
            rc = out.channel.recv_exit_status()
            so, se = out.read().decode(errors="replace"), err.read().decode(errors="replace")
            print(so or se)
            if rc != 0:
                sys.exit(f"::error::Komanda uğursuz (rc={rc}): {cmd}")

        sftp = client.open_sftp()
        remote_zips = [f for f in sftp.listdir(REMOTE_OUT) if f.endswith(".zip")]
        if not remote_zips:
            sys.exit("::error::Export paketi yaranmadı.")
        for z in remote_zips:
            local = os.path.join(PACKAGE_DIR, z)
            print(f"  <- gətirilir: {z}")
            sftp.get(f"{REMOTE_OUT}/{z}", local)
            sftp.remove(f"{REMOTE_OUT}/{z}")
        sftp.close()
    finally:
        client.close()

    print(f"\nHazırdır -> {PACKAGE_DIR}/")
    print("İndi: git add QRADAR_RULES/content_packages && git commit -m 'export rules' && git push")


if __name__ == "__main__":
    main()
