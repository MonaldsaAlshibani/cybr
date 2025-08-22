# Mini-IDS & Log Analysis — Instructor Pack

**Duration:** ~5 hours (can compress to 3)  
**Prereqs:** Python 3.10+, Linux/macOS terminal. `sudo` for packet sniffing (or use a `.pcap` file).

## Learning Outcomes
1. Build a small **network IDS** in Python (live sniff or pcap) detecting:
   - **SYN port scans**
   - **Beaconing** (regular intervals)
   - **Suspicious DNS** (very long/high-entropy labels)
   - **HTTP payload patterns** (basic SQLi/XSS tokens)
2. Analyze **system & web logs** in real-time:
   - SSH brute-force from `/var/log/auth.log`
   - Nginx/Apache access logs for injection attempts
   - Rolling thresholds, CSV summaries, and live alerts

---

## Setup
```bash
python3 --version
# Optional: create venv
python3 -m venv .venv && source .venv/bin/activate

# Packages for IDS (scapy is optional if you use a pcap file)
pip install scapy rich
```
> If `scapy` install is blocked, skip live sniffing and use `--pcap` with any capture (e.g., `nmap -sS -p 1-100 localhost` captured by Wireshark/Tcpdump).

---

## Files
- `ids.py` — Mini-IDS (live sniff or pcap)
- `log_analyst.py` — Real-time log analysis (SSH & access logs)
- `generate_access_log.py` — Generates an `access.log` with mixed benign + attack-like requests
- `sample_auth.log` — Example SSH failures/successes
- `sample_access.log` — Example web requests (benign & attack-like)

---

## Quick Starts

### A) Network Mini‑IDS
**Live sniff (requires sudo & an interface like `eth0`, `wlan0`, or `en0`):**
```bash
sudo python3 ids.py --iface en0
```
**From a pcap file:**
```bash
python3 ids.py --pcap sample.pcap
```

**Trigger some signals (in another terminal):**
```bash
# Port scan (generates SYNs): requires nmap
sudo nmap -sS -p1-200 127.0.0.1

# DNS query with a long/entropy-heavy label (replace resolver IP if needed)
python3 - <<'PY'
import socket, random, string
host = ''.join(random.choices(string.ascii_lowercase+string.digits, k=60)) + ".example.com"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b'\x00'*20, ("8.8.8.8", 53))
print("Sent dummy UDP packet; real DNS crafting best via scapy/dig")
PY
```

### B) Log Analysis (no sudo needed)
**Tail SSH auth log sample:**
```bash
python3 log_analyst.py --auth sample_auth.log
```
**Tail access log sample (or your actual Nginx/Apache path):**
```bash
python3 generate_access_log.py --out sample_access.log --rate 5 &
python3 log_analyst.py --access sample_access.log
```

---

## Instructor Flow (suggested minute-by-minute)
1. **(10m)** Threat modeling: what a *minimal* IDS can & cannot do. Legality & ethics.
2. **(25m)** Code walkthrough: `ids.py` data structures (deques, rolling windows), rules.
3. **(30m)** Live demo: Port scan → alert; DNS long-label → alert; HTTP token → alert.
4. **(15m)** Q&A: false positives vs. false negatives; thresholds; tuning.
5. **(25m)** `log_analyst.py`: regex parsing, rolling thresholds, CSV outputs.
6. **(25m)** Live demo with `generate_access_log.py` and `sample_auth.log`.
7. **(20m)** Student lab: add one new rule each (e.g., RDP brute-force in Windows logs, 403 burst).
8. **(10m)** Wrap-up & rubric: correctness, explainability, and operational fit.

---

## Rubric (20 pts)
- (6) Correct detections (scan/DNS/HTTP/bruteforce) with low noise
- (6) Clear, justified thresholds and comments
- (4) CSV/console summaries that a Tier‑1 analyst can use
- (4) One original rule or improvement (e.g., entropy tweak, new log pattern)

---

## Notes
- This is **defensive** content. Use only on systems/networks where you have permission.
- Live sniffing requires privileges; pcap mode works anywhere.
- The patterns here are intentionally simple to make them teachable; in production, you’d pair with Suricata/Sigma/Zeek + SIEM.
