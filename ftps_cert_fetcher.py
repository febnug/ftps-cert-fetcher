#!/usr/bin/env python3
"""
ftps_cert_fetcher.py

Fetch FTPS certificates (STARTTLS on port 21 and implicit on 990) via openssl s_client,
save PEM chains, extract leaf cert, and produce a human-readable summary.

Requirements: 'openssl' command available on PATH.

Usage:
    python3 ftps_cert_fetcher.py <host> [--no-starttls] [--no-implicit] [--outdir ./ftps_certs] [--timeout 10]

Examples:
    python3 ftps_cert_fetcher.py ftp.mypantero.com
    python3 ftps_cert_fetcher.py ftp.mypantero.com --no-implicit
"""

import argparse
import os
import shlex
import subprocess
import sys
from datetime import datetime

def run_cmd(cmd, timeout=20):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"
    except Exception as e:
        return 1, "", str(e)

def save_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def extract_first_pem_block(pem_text):
    # returns first BEGIN..END block
    beg = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    a = pem_text.find(beg)
    if a == -1:
        return None
    b = pem_text.find(end, a)
    if b == -1:
        return None
    return pem_text[a:b+len(end)]

def parse_cert_text(pem_path):
    # Use openssl to print subject/issuer/dates/SAN
    cmd = f"openssl x509 -in {shlex.quote(pem_path)} -noout -subject -issuer -dates -ext subjectAltName"
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        return None, out, err
    # parse into dict-ish
    info = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            info["subject"] = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[len("issuer="):].strip()
        elif line.startswith("notBefore="):
            info["notBefore"] = line[len("notBefore="):].strip()
        elif line.startswith("notAfter="):
            info["notAfter"] = line[len("notAfter="):].strip()
        elif line.startswith("X509v3 Subject Alternative Name:"):
            # the next line(s) will contain SAN entries, but openssl prints them on same or next line
            pass
        elif "DNS:" in line or "IP Address:" in line:
            # append SANs raw
            info.setdefault("SAN_raw", "")
            if info["SAN_raw"]:
                info["SAN_raw"] += " ; " + line
            else:
                info["SAN_raw"] = line
    return info, out, err

def fetch_starttls(host, outdir, timeout):
    outpath = os.path.join(outdir, "starttls_21_raw.pem")
    print(f"[+] STARTTLS (port 21) - probing and saving to {outpath}")
    # openssl s_client -connect host:21 -starttls ftp -showcerts
    cmd = f"openssl s_client -connect {shlex.quote(host)}:21 -starttls ftp -showcerts -ign_eof -brief"
    rc, out, err = run_cmd(cmd, timeout=timeout)
    if rc != 0 and not out:
        print(f"  [!] openssl failed (rc={rc}): {err.strip()[:200]}")
        return None
    save_file(outpath, out + "\n" + err)
    leaf = extract_first_pem_block(out)
    if leaf:
        leaf_path = os.path.join(outdir, "starttls_leaf.pem")
        save_file(leaf_path, leaf)
        info, _, _ = parse_cert_text(leaf_path)
        return {"raw": outpath, "leaf": leaf_path, "info": info}
    else:
        print("  [!] No PEM certificate block found in STARTTLS output.")
        return {"raw": outpath, "leaf": None, "info": None}

def fetch_implicit(host, outdir, timeout):
    outpath = os.path.join(outdir, "implicit_990_raw.pem")
    print(f"[+] Implicit FTPS (port 990) - probing and saving to {outpath}")
    cmd = f"openssl s_client -connect {shlex.quote(host)}:990 -showcerts -ign_eof -brief"
    rc, out, err = run_cmd(cmd, timeout=timeout)
    if rc != 0 and not out:
        print(f"  [!] openssl failed (rc={rc}): {err.strip()[:200]}")
        return None
    save_file(outpath, out + "\n" + err)
    leaf = extract_first_pem_block(out)
    if leaf:
        leaf_path = os.path.join(outdir, "implicit_leaf.pem")
        save_file(leaf_path, leaf)
        info, _, _ = parse_cert_text(leaf_path)
        return {"raw": outpath, "leaf": leaf_path, "info": info}
    else:
        print("  [!] No PEM certificate block found in implicit FTPS output.")
        return {"raw": outpath, "leaf": None, "info": None}

def print_summary(host, starttls_res, implicit_res):
    print("\n" + "="*60)
    print(f"FTPS Certificate Summary for {host}")
    print("="*60)
    now = datetime.utcnow().isoformat() + "Z"
    print(f"Checked at: {now}")
    print("-"*60)
    if starttls_res:
        print("[STARTTLS (port 21)]")
        print(f"  Raw output: {starttls_res.get('raw')}")
        leaf = starttls_res.get("leaf")
        if leaf:
            print(f"  Leaf PEM : {leaf}")
            info = starttls_res.get("info") or {}
            print(f"    Subject : {info.get('subject','-')}")
            print(f"    Issuer  : {info.get('issuer','-')}")
            print(f"    Valid   : {info.get('notBefore','-')} -> {info.get('notAfter','-')}")
            print(f"    SANs    : {info.get('SAN_raw','-')}")
        else:
            print("  No leaf certificate extracted.")
    else:
        print("[STARTTLS (port 21)] - not available / failed")

    print("-"*60)
    if implicit_res:
        print("[Implicit FTPS (port 990)]")
        print(f"  Raw output: {implicit_res.get('raw')}")
        leaf = implicit_res.get("leaf")
        if leaf:
            print(f"  Leaf PEM : {leaf}")
            info = implicit_res.get("info") or {}
            print(f"    Subject : {info.get('subject','-')}")
            print(f"    Issuer  : {info.get('issuer','-')}")
            print(f"    Valid   : {info.get('notBefore','-')} -> {info.get('notAfter','-')}")
            print(f"    SANs    : {info.get('SAN_raw','-')}")
        else:
            print("  No leaf certificate extracted.")
    else:
        print("[Implicit FTPS (port 990)] - not available / failed")
    print("="*60 + "\n")

def main():
    p = argparse.ArgumentParser(description="Fetch FTPS certs (STARTTLS and implicit) and summarize")
    p.add_argument("host", help="target host (name or IP)")
    p.add_argument("--no-starttls", action="store_true", help="skip STARTTLS (port 21) probe")
    p.add_argument("--no-implicit", action="store_true", help="skip implicit FTPS (port 990) probe")
    p.add_argument("--outdir", default="./ftps_certs", help="base output directory")
    p.add_argument("--timeout", type=int, default=10, help="openssl command timeout (seconds)")
    args = p.parse_args()

    host = args.host
    base = os.path.abspath(args.outdir)
    target_dir = os.path.join(base, host)
    os.makedirs(target_dir, exist_ok=True)

    starttls_res = None
    implicit_res = None

    if not args.no_starttls:
        starttls_res = fetch_starttls(host, target_dir, timeout=args.timeout)
    else:
        print("[*] Skipped STARTTLS per flag")

    if not args.no_implicit:
        implicit_res = fetch_implicit(host, target_dir, timeout=args.timeout)
    else:
        print("[*] Skipped implicit FTPS per flag")

    print_summary(host, starttls_res, implicit_res)
    print(f"[+] All raw outputs and PEMs saved under: {target_dir}")

if __name__ == "__main__":
    main()
