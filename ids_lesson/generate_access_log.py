#!/usr/bin/env python3
import argparse, time, random, string, sys

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def benign_path():
    products = ["laptop","phone","mouse","keyboard","monitor","router"]
    return f"/shop/{random.choice(products)}?page={random.randint(1,5)}"

def attack_path():
    samples = [
        "/search?q=' or 1=1 --",
        "/login?user=admin&pass=admin' OR '1'='1",
        "/items?id=1 UNION SELECT username,password FROM users",
        "/?q=<script>alert(1)</script>",
        "/download?path=../../../../etc/passwd",
        "/report?delay=sleep(5)",
    ]
    return random.choice(samples)

def gen_line(ip, path, status):
    ua = random.choice([
        "Mozilla/5.0",
        "curl/7.88.1",
        "python-requests/2.31",
        "Go-http-client/1.1",
    ])
    now = time.strftime("%d/%b/%Y:%H:%M:%S %z", time.localtime())
    return f'{ip} - - [{now}] "GET {path} HTTP/1.1" {status} {random.randint(50,5000)} "-" "{ua}"'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="access.log")
    ap.add_argument("--rate", type=float, default=5.0, help="lines per second")
    ap.add_argument("--attack-ratio", type=float, default=0.25, help="0..1 fraction of attacky requests")
    args = ap.parse_args()

    with open(args.out, "a") as f:
        try:
            while True:
                is_attack = random.random() < args.attack_ratio
                path = attack_path() if is_attack else benign_path()
                status = random.choice([200,200,200,404,500]) if is_attack else random.choice([200,200,200,304,404])
                line = gen_line(rand_ip(), path, status)
                f.write(line + "\n")
                f.flush()
                time.sleep(1.0/max(args.rate, 0.1))
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
