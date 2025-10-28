#!/usr/bin/env python3
"""
Full Port & Banner Scanner (conservative)

Features:
- TCP connect scan for a given port range (default: common ports; option to scan all ports)
- Banner grabbing (simple probes) for services that respond
- HTTP Server header retrieval (uses requests if available)
- OS inference using TTL from ping (heuristic)
- Conservative "outdated" checks by matching banner substrings (non-exhaustive)
- CSV output and human-readable summary

USAGE examples:
    python full_port_scanner.py --targets 192.168.1.10 example.com --ports 1-1024 --output report.csv
    python full_port_scanner.py --targets-file hosts.txt --all-ports --output full_report.csv

LEGAL: Only scan systems you own or have permission to test.
"""

import socket
import argparse
import csv
import time
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional dependency
try:
    import requests
except Exception:
    requests = None

# ---------- Config ----------
DEFAULT_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3389,5432,8080]  # small default set
CONNECT_TIMEOUT = 1.5
THREADS = 200
BANNER_READ_BYTES = 2048
OUTPUT_CSV = "scan_report.csv"
# Conservative outdated patterns (expand as needed)
OUTDATED_PATTERNS = [
    ("apache/2.2", "Apache 2.2 (EOL) — consider upgrade"),
    ("apache/2.0", "Apache 2.0 (very old)"),
    ("nginx/1.4", "nginx 1.4 (old)"),
    ("openssh_5.", "OpenSSH 5.x (old)"),
    ("openssl/0.", "OpenSSL 0.x (very old)"),
]
# ----------------------------

def parse_ports(port_spec):
    """Parse port specification like '1-65535' or '22,80,443' or empty -> default"""
    if not port_spec:
        return DEFAULT_PORTS
    ports = set()
    parts = port_spec.split(",")
    for p in parts:
        p = p.strip()
        if "-" in p:
            lo, hi = p.split("-",1)
            try:
                lo = int(lo); hi = int(hi)
                if lo < 1: lo = 1
                if hi > 65535: hi = 65535
                ports.update(range(lo, hi+1))
            except Exception:
                continue
        else:
            try:
                ports.add(int(p))
            except Exception:
                continue
    return sorted([pt for pt in ports if 1 <= pt <= 65535])

def ping_ttl(host):
    """Ping once and try to extract TTL. Returns (ttl, guess) or (None, 'unknown')."""
    ttl = None
    out = ""
    try:
        # unix-like
        p = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=4)
        out = p.stdout + p.stderr
    except Exception:
        try:
            p = subprocess.run(["ping", "-n", "1", host], capture_output=True, text=True, timeout=4)
            out = p.stdout + p.stderr
        except Exception:
            return None, "unknown"
    m = re.search(r"ttl[=|:]\s*(\d+)", out, re.IGNORECASE)
    if not m:
        m = re.search(r"TTL=(\d+)", out)
    if m:
        try:
            ttl = int(m.group(1))
        except:
            ttl = None
    if ttl is None:
        return None, "unknown"
    if ttl >= 128:
        return ttl, f"Windows-like (TTL {ttl})"
    if ttl >= 64:
        return ttl, f"Unix/Linux-like (TTL {ttl})"
    return ttl, f"Network/embedded (TTL {ttl})"

def try_tcp_connect(host, port, timeout=CONNECT_TIMEOUT):
    """Attempts to connect and returns (True, banner_str) or (False, '')."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except Exception:
        try:
            s.close()
        except: pass
        return False, ""
    banner = ""
    try:
        # If HTTP-like, try to use requests (better for HTTPS). For plain sockets, send minimal probes.
        if port in (80, 8080, 8000):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            except Exception:
                pass
        elif port == 443 and requests:
            # close socket and fetch via requests for HTTPS
            try:
                s.close()
            except: pass
            try:
                r = requests.head(f"https://{host}", timeout=timeout, verify=False)
                return True, r.headers.get("Server", "") or ""
            except Exception:
                return True, ""
        else:
            # wait briefly then recv
            time.sleep(0.15)
            try:
                data = s.recv(BANNER_READ_BYTES)
                banner = data.decode(errors="ignore").strip()
            except Exception:
                # try to provoke banner
                try:
                    s.sendall(b"\r\n")
                    time.sleep(0.15)
                    data = s.recv(BANNER_READ_BYTES)
                    banner = data.decode(errors="ignore").strip()
                except Exception:
                    banner = ""
    finally:
        try:
            s.close()
        except: pass
    return True, banner

def http_server_header(host, port):
    """Try to get Server header via requests or socket fallback."""
    if requests:
        try:
            scheme = "https" if port == 443 else "http"
            r = requests.head(f"{scheme}://{host}", timeout=CONNECT_TIMEOUT, verify=False)
            return r.headers.get("Server", "") or ""
        except Exception:
            pass
    # fallback: raw socket HEAD
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        time.sleep(0.15)
        resp = s.recv(BANNER_READ_BYTES).decode(errors="ignore")
        s.close()
        for ln in resp.splitlines():
            if ln.lower().startswith("server:"):
                return ln.split(":",1)[1].strip()
    except Exception:
        pass
    return ""

def check_outdated(banner):
    """Return list of matched outdated hints."""
    if not banner:
        return []
    low = banner.lower()
    matches = [msg for pat, msg in OUTDATED_PATTERNS if pat in low]
    return matches

def scan_host_ports(host, ports):
    """Scan specified ports on host. Returns list of dict rows."""
    rows = []
    ttl, os_guess = ping_ttl(host)
    for port in ports:
        open_flag, banner = try_tcp_connect(host, port)
        server_header = ""
        outdated_notes = []
        if open_flag:
            # prefer explicit HTTP Server header for web ports
            if port in (80, 8080, 8000, 443) or (banner and banner.lower().startswith("http")):
                srv = http_server_header(host, port)
                server_header = srv or banner or ""
            else:
                server_header = banner or ""
            outdated_notes = check_outdated(server_header)
        rows.append({
            "target": host,
            "ttl": ttl,
            "os_guess": os_guess,
            "port": port,
            "open": open_flag,
            "banner": server_header.replace("\n"," ").strip(),
            "outdated_flags": "; ".join(outdated_notes)
        })
    return rows

def write_csv(rows, outfile):
    fieldnames = ["target","ttl","os_guess","port","open","banner","outdated_flags"]
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def main():
    parser = argparse.ArgumentParser(description="Full port + banner scanner (conservative).")
    parser.add_argument("--targets", nargs="*", help="Targets (IPs or hostnames).")
    parser.add_argument("--targets-file", help="File with targets (one per line).")
    parser.add_argument("--ports", help="Ports spec: '80,443,8080' or '1-65535' or '1-1024'.")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports 1-65535 (very slow).")
    parser.add_argument("--output", default=OUTPUT_CSV, help="CSV output file.")
    parser.add_argument("--threads", type=int, default=THREADS, help="Concurrency level.")
    args = parser.parse_args()

    targets = []
    if args.targets:
        targets.extend(args.targets)
    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                targets.extend([l.strip() for l in f if l.strip()])
        except Exception as e:
            print("Error reading targets file:", e); return
    targets = list(dict.fromkeys([t for t in targets if t]))  # dedupe
    if not targets:
        print("No targets provided. Use --targets or --targets-file"); return

    if args.all_ports:
        ports = list(range(1, 65536))
    else:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS

    print(f"[+] Targets: {targets}")
    print(f"[+] Ports count: {len(ports)} (first 20 if long): {ports[:20]}")
    print(f"[+] Output: {args.output}")
    all_rows = []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        future_map = {}
        for t in targets:
            future_map[ex.submit(scan_host_ports, t, ports)] = t
        for fut in as_completed(future_map):
            t = future_map[fut]
            try:
                res = fut.result()
                all_rows.extend(res)
                print(f"[+] Completed: {t}")
            except Exception as e:
                print(f"[!] Error scanning {t}: {e}")

    write_csv(all_rows, args.output)
    print(f"[+] Scan complete. Results written to {args.output}")

    # human summary
    for host in targets:
        host_rows = [r for r in all_rows if r["target"] == host and r["open"]]
        if not host_rows:
            print(f"[{host}] No open ports in scanned set.")
            continue
        print(f"[{host}] Open ports and banners:")
        seen_ports = set()
        for r in host_rows:
            if r["port"] in seen_ports: 
                continue
            seen_ports.add(r["port"])
            note = f" -> {r['outdated_flags']}" if r["outdated_flags"] else ""
            banner = r["banner"] or "(no banner)"
            print(f"  - {r['port']}: {banner}{note}")
        print(f"  OS guess: {host_rows[0]['os_guess']} (TTL {host_rows[0]['ttl']})")

if __name__ == "__main__":
    main()
