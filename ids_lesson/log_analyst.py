#!/usr/bin/env python3
import argparse, time, re, csv, os
from collections import defaultdict, deque

# Regex for Debian/Ubuntu auth.log (adjust as needed)
AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.*)$"
)

# Common/combined log format (Nginx/Apache)
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<m>\S+)\s+(?P<path>[^"]+)\s+(?P<pver>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Very naive tokens to flag
TOKENS = re.compile(r"(UNION\s+SELECT|<script|onerror\s*=|or\s+1=1|/etc/passwd|xp_cmdshell|sleep\(\d+\))", re.I)

def follow(path):
    # Tail-like follower; yields new lines as file grows
    with open(path, "r", errors="ignore") as f:
        # If file exists and has content, seek to end to simulate "now"
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")

def analyze_auth(path):
    print(f"[INFO] Following SSH log: {path}")
    fails = defaultdict(lambda: deque())  # ip -> deque[timestamps]
    SUS_THRESHOLD = 5
    WINDOW = 120  # seconds

    for line in follow(path):
        m = AUTH_RE.match(line)
        if not m:
            continue
        msg = m.group("msg")
        # Typical: "Failed password for root from 203.0.113.45 port 22 ssh2"
        if "Failed password for" in msg and "from " in msg:
            try:
                ip = msg.split("from ")[1].split()[0]
            except Exception:
                ip = "unknown"
            now = time.time()
            q = fails[ip]
            q.append(now)
            while q and now - q[0] > WINDOW:
                q.popleft()
            if len(q) >= SUS_THRESHOLD:
                print(f"[ALERT][SSH] Bruteforce? {ip} {len(q)} fails in {WINDOW}s")
        elif "Accepted password for" in msg and "from " in msg:
            ip = msg.split("from ")[1].split()[0]
            print(f"[NOTICE][SSH] Successful login from {ip} -> verify if expected")

def analyze_access(path, csv_out="web_summary.csv"):
    print(f"[INFO] Following access log: {path}")
    # Track per-IP stats and tokens
    stats = defaultdict(lambda: {"total":0, "4xx":0, "5xx":0, "tokens":0})
    last_emit = time.time()

    with open(csv_out, "w", newline="") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["ip","total","4xx","5xx","token_hits","4xx_ratio","5xx_ratio"])

        for line in follow(path):
            m = ACCESS_RE.match(line)
            if not m:
                continue
            ip = m.group("ip")
            pathq = m.group("path")
            status = int(m.group("status"))
            stats[ip]["total"] += 1
            if 400 <= status < 500: stats[ip]["4xx"] += 1
            if 500 <= status < 600: stats[ip]["5xx"] += 1
            if TOKENS.search(pathq):
                stats[ip]["tokens"] += 1
                print(f"[ALERT][WEB] {ip} suspicious path token: {pathq[:100]}")

            # Periodic CSV snapshot
            now = time.time()
            if now - last_emit > 15:
                last_emit = now
                for k,v in stats.items():
                    t = v["total"] or 1
                    w.writerow([k, v["total"], v["4xx"], v["5xx"], v["tokens"], f"{v['4xx']/t:.2f}", f"{v['5xx']/t:.2f}"])
                fcsv.flush()

def main():
    ap = argparse.ArgumentParser(description="Real-time Log Analyst (SSH + Web)")
    ap.add_argument("--auth", help="Path to auth.log (e.g., /var/log/auth.log or sample_auth.log)")
    ap.add_argument("--access", help="Path to access log (e.g., /var/log/nginx/access.log)")
    args = ap.parse_args()

    if not args.auth and not args.access:
        print("Provide --auth and/or --access")
        return

    # Run whichever is provided; simple & sequential for teaching
    try:
        if args.auth:
            analyze_auth(args.auth)
        if args.access:
            analyze_access(args.access)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped. CSV summaries saved where applicable.")

if __name__ == "__main__":
    main()
