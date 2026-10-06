#!/usr/bin/env python3
"""
rinnegan.py - HTTP header fuzzer for authorized web security testing.

Sends requests with different HTTP headers against one or more targets, diffs the response
against a baseline, and flags anything that looks interesting: auth/403
bypasses, reflected header values, host-header injection via redirects,
and general response anomalies. Built for daily bug bounty / pentest use.

Zero required dependencies (pure stdlib). `colorama` is used for color if
installed, but the script works fine without it.

----------------------------------------------------------------------
QUICK START
----------------------------------------------------------------------
Single target, default header list, with baseline diffing:
  python3 rinnegan.py -u https://target.tld/ --default-list --baseline

Your own wordlist:
  python3 rinnegan.py -u https://target.tld/ -w headers.txt --baseline

403/401 bypass hunting (auto-enables baseline):
  python3 rinnegan.py -u https://target.tld/admin --bypass-403

Multiple targets from a file, piped from httpx etc:
  cat urls.txt | python3 rinnegan.py -i -w headers.txt --baseline
  python3 rinnegan.py -l targets.txt --bypass-403 --rps 5

Through Burp:
  python3 rinnegan.py -u https://target.tld/ -w headers.txt -x 127.0.0.1:8080

Save a report + raw evidence for flagged findings:
  python3 rinnegan.py -u https://target.tld/ --bypass-403 \
      --report findings.md --save-evidence ./evidence

----------------------------------------------------------------------
HEADERS FILE FORMAT
----------------------------------------------------------------------
One header per line. Blank-line-separated blocks let a single test case
carry multiple header lines together (sent as one request):
  X-Forwarded-For: 127.0.0.1
  X-Forwarded-Host: evil.com

  X-Original-URL: /admin
  # lines starting with # are comments
"""

import argparse
import concurrent.futures
import csv
import difflib
import json
import os
import random
import re
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    C_RED, C_GREEN, C_MAGENTA, C_YELLOW, C_CYAN, C_BLUE, C_BOLD, C_RESET = (
        Fore.RED, Fore.GREEN, Fore.MAGENTA, Fore.YELLOW, Fore.CYAN, Fore.BLUE,
        Style.BRIGHT, Style.RESET_ALL,
    )
except ImportError:
    C_RED = C_GREEN = C_MAGENTA = C_YELLOW = C_CYAN = C_BLUE = C_BOLD = C_RESET = ""

SEV_COLOR = {"CRITICAL": C_RED + C_BOLD, "HIGH": C_RED, "MEDIUM": C_YELLOW, "INFO": C_BLUE}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

# ----------------------------------------------------------------------
# Header wordlists
# ----------------------------------------------------------------------

DEFAULT_HEADERS = [
    "X-Forwarded-For: 127.0.0.1",
    "X-Forwarded-For: localhost",
    "X-Forwarded-Host: localhost",
    "X-Forwarded-Host: evil.com",
    "X-Forwarded-Proto: https",
    "X-Forwarded-Scheme: https",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /admin",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "X-Client-IP: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "X-Host: localhost",
    "X-HTTP-Method-Override: PUT",
    "X-HTTP-Method: PUT",
    "X-Method-Override: DELETE",
    "True-Client-IP: 127.0.0.1",
    "CF-Connecting-IP: 127.0.0.1",
    "Forwarded: for=127.0.0.1;proto=https",
    "Referer: https://127.0.0.1/",
    "Origin: null",
    "Proxy-Authenticate: foobar",
    "Proxy-Authorization: foobar",
    "Proxy-Connection: foobar",
    "Proxy-Host: foobar",
]

# Headers specifically known to trip up reverse proxies / WAFs / app-level
# access control into treating a request as internal, already-authenticated,
# or routed to a different path than the one being blocked.
BYPASS_403_HEADERS = [
    "X-Forwarded-For: 127.0.0.1",
    "X-Forwarded-For: 127.0.0.1:80",
    "X-Forwarded-For: 127.0.0.1, 127.0.0.1",
    "X-Forwarded-For: localhost",
    "X-Forwarded-For: 0.0.0.0",
    "X-Forwarded-For: ::1",
    "X-Forwarded-Host: 127.0.0.1",
    "X-Forwarded-Host: localhost",
    "X-Forwarded-Scheme: https",
    "X-Forwarded-Proto: internal",
    "X-Originating-IP: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1",
    "X-Remote-Addr: 127.0.0.1",
    "X-Client-IP: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "X-Original-URL: /",
    "X-Rewrite-URL: /",
    "X-Override-URL: /",
    "X-Original-Remote-Addr: 127.0.0.1",
    "X-Haproxy-Current-Date: 127.0.0.1",
    "X-ProxyUser-Ip: 127.0.0.1",
    "X-Forwarded: 127.0.0.1",
    "Forwarded-For: 127.0.0.1",
    "Forwarded: for=127.0.0.1",
    "Client-IP: 127.0.0.1",
    "True-Client-IP: 127.0.0.1",
    "CF-Connecting-IP: 127.0.0.1",
    "X-Host: 127.0.0.1",
    "X-Forwarded-Server: 127.0.0.1",
    "X-HTTP-Method-Override: GET",
    "X-Permitted-Cross-Domain-Policies: all",
]

REFLECTION_MIN_LEN = 4  # don't flag trivially short values like "1" or "on"


@dataclass
class Result:
    target: str
    header: str
    url: str
    status: int
    length: int
    elapsed_ms: int
    location: str = ""
    error: str = ""
    severity: str = ""          # highest severity flag, "" if none
    notes: str = field(default_factory=list)


# ----------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------

def cachebuster(n=10):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def add_query_param(url, key, value):
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    q.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def strip_query_param(url, key):
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def build_opener(proxy, insecure):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": f"http://{proxy}", "https": f"http://{proxy}"}))
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


class RateLimiter:
    """Shared across threads; caps aggregate requests/sec with light jitter."""
    def __init__(self, rps):
        self.interval = 1.0 / rps if rps and rps > 0 else 0
        self.lock = threading.Lock()
        self.next_time = time.time()

    def wait(self):
        if self.interval <= 0:
            return
        with self.lock:
            now = time.time()
            if self.next_time < now:
                self.next_time = now
            sleep_for = self.next_time - now
            self.next_time += self.interval + random.uniform(0, self.interval * 0.1)
        if sleep_for > 0:
            time.sleep(sleep_for)


def parse_header_block(block):
    pairs = []
    for line in (block or "").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, val = line.split(":", 1)
        pairs.append((name.strip(), val.strip()))
    return pairs


def send_raw(opener, base_url, method, header_block, timeout, base_headers, use_cachebuster, limiter):
    """Returns (headers_sent: dict, status, body: bytes, location, elapsed_ms, error, final_url)."""
    url = add_query_param(base_url, "cachebuster", cachebuster()) if use_cachebuster else base_url
    headers = dict(base_headers)
    for name, val in parse_header_block(header_block):
        headers[name] = val

    if limiter:
        limiter.wait()

    req = urllib.request.Request(url, method=method, headers=headers)
    start = time.time()
    display_url = strip_query_param(url, "cachebuster") if use_cachebuster else url
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
            elapsed = int((time.time() - start) * 1000)
            return headers, resp.status, body, resp.headers.get("Location", ""), elapsed, "", display_url
    except urllib.error.HTTPError as e:
        body = e.read()
        elapsed = int((time.time() - start) * 1000)
        loc = e.headers.get("Location", "") if e.headers else ""
        return headers, e.code, body, loc, elapsed, "", display_url
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        return headers, 0, b"", "", elapsed, str(e), display_url


def similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    sa = a[:4000].decode("utf-8", "ignore")
    sb = b[:4000].decode("utf-8", "ignore")
    return difflib.SequenceMatcher(None, sa, sb).quick_ratio()


# ----------------------------------------------------------------------
# Analysis / flagging
# ----------------------------------------------------------------------

def analyze(header_block, headers_sent, status, body, location, baseline_status, baseline_body):
    """Returns (severity_or_None, list_of_note_strings)."""
    notes = []
    severities = []

    if baseline_status is not None:
        bypass = baseline_status in (401, 403, 404, 405) and status in (200, 201, 202, 204, 206)
        if bypass:
            severities.append("CRITICAL")
            notes.append(f"Possible access-control bypass: baseline {baseline_status} -> {status}")
        elif status != baseline_status:
            severities.append("MEDIUM")
            notes.append(f"Status changed: {baseline_status} -> {status}")

        sim = similarity(baseline_body, body)
        if sim < 0.5:
            severities.append("HIGH")
            notes.append(f"Response body very different from baseline (similarity {sim:.0%})")
        elif sim < 0.92:
            severities.append("MEDIUM")
            notes.append(f"Response body differs from baseline (similarity {sim:.0%})")

    # Reflection: does any injected header VALUE show up verbatim in the body?
    for name, val in parse_header_block(header_block):
        if len(val) >= REFLECTION_MIN_LEN and val.encode() in body:
            severities.append("HIGH")
            notes.append(f"Injected value of '{name}' is reflected in the response body")

        # Host-header-style injection surfacing in a redirect Location
        if name.lower() in ("host", "x-forwarded-host", "x-forwarded-server", "x-host", "x-original-url",
                             "x-rewrite-url", "x-override-url") and val and val in location:
            severities.append("HIGH")
            notes.append(f"Injected '{name}' value appears in redirect Location header ({location})")

    if not severities:
        return None, notes

    best = min(severities, key=lambda s: SEV_ORDER[s])
    return best, notes


# ----------------------------------------------------------------------
# I/O: targets & headers
# ----------------------------------------------------------------------

def load_lines(path):
    out = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


def load_header_blocks(path):
    blocks, current = [], []
    with open(path) as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.strip().startswith("#"):
                continue
            if line.strip() == "":
                if current:
                    blocks.append("\n".join(current))
                    current = []
                continue
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------

def print_row(r: Result, show_all):
    if not r.severity and not show_all:
        return

    status_color = C_GREEN if 200 <= r.status < 300 else (C_YELLOW if r.status else C_RED)
    tag = ""
    if r.severity:
        tag = f" {SEV_COLOR[r.severity]}[{r.severity}]{C_RESET}"
    elif r.error:
        tag = f" {C_RED}[ERROR]{C_RESET}"

    header_label = r.header.replace("\n", " | ")[:45] or "(baseline)"
    line = (
        f"{status_color}[{r.status or 'ERR'}]{C_RESET} "
        f"{C_MAGENTA}[CL:{r.length}]{C_RESET} "
        f"{C_CYAN}[{header_label}]{C_RESET} "
        f"{C_YELLOW}{r.target}{C_RESET}"
        f"{tag}"
    )
    print(line)
    for n in r.notes:
        print(f"      -> {n}")
    if r.error:
        print(f"      -> ERROR: {r.error}")


def print_summary(results):
    flagged = [r for r in results if r.severity]
    if not flagged:
        print(f"\n{C_GREEN}[*] No anomalies flagged.{C_RESET}")
        return
    flagged.sort(key=lambda r: SEV_ORDER[r.severity])
    print(f"\n{C_BOLD}{'=' * 70}{C_RESET}")
    print(f"{C_BOLD}FINDINGS SUMMARY ({len(flagged)}){C_RESET}")
    print(f"{C_BOLD}{'=' * 70}{C_RESET}")
    for r in flagged:
        col = SEV_COLOR[r.severity]
        print(f"{col}[{r.severity:<8}]{C_RESET} {r.target}  header: {r.header.replace(chr(10), ' | ')}")
        for n in r.notes:
            print(f"             {n}")
    counts = {}
    for r in flagged:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    print(f"\n{C_BOLD}Totals:{C_RESET} " + "  ".join(f"{SEV_COLOR[s]}{s}: {counts.get(s,0)}{C_RESET}"
                                                       for s in ("CRITICAL", "HIGH", "MEDIUM", "INFO") if counts.get(s)))


def write_out(path, results):
    rows = [asdict(r) for r in results]
    for row in rows:
        row["notes"] = "; ".join(row["notes"])
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump(rows, f, indent=2)
    else:
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else
                                ["target", "header", "url", "status", "length", "elapsed_ms",
                                 "location", "error", "severity", "notes"])
            w.writeheader()
            for row in rows:
                w.writerow(row)


def write_report(path, results):
    flagged = sorted([r for r in results if r.severity], key=lambda r: SEV_ORDER[r.severity])
    is_html = path.endswith(".html") or path.endswith(".htm")

    if is_html:
        rows_html = "".join(
            f"<tr><td>{r.severity}</td><td>{r.target}</td><td><code>{r.header}</code></td>"
            f"<td>{r.status}</td><td>{r.length}</td>"
            f"<td>{'<br>'.join(r.notes)}</td></tr>"
            for r in flagged
        )
        html = f"""<html><head><meta charset="utf-8"><title>rinnegan report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }}
th {{ background: #222; color: #fff; }}
tr:nth-child(even) {{ background: #f6f6f6; }}
code {{ font-size: 0.85em; }}
</style></head><body>
<h1>rinnegan report</h1>
<p>{len(flagged)} flagged result(s) out of {len(results)} requests.</p>
<table><tr><th>Severity</th><th>Target</th><th>Header</th><th>Status</th><th>Length</th><th>Notes</th></tr>
{rows_html}
</table>
</body></html>"""
        with open(path, "w") as f:
            f.write(html)
    else:
        lines = ["# rinnegan report", "",
                  f"{len(flagged)} flagged result(s) out of {len(results)} requests.", ""]
        for r in flagged:
            lines.append(f"## [{r.severity}] {r.target}")
            lines.append(f"- Header: `{r.header}`")
            lines.append(f"- Status: {r.status}  Length: {r.length}")
            for n in r.notes:
                lines.append(f"- {n}")
            lines.append("")
        with open(path, "w") as f:
            f.write("\n".join(lines))


def save_evidence(evdir, headers_sent, r: Result, body: bytes):
    os.makedirs(evdir, exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9]+", "_", r.target)[:50]
    safe_header = re.sub(r"[^a-zA-Z0-9]+", "_", r.header.split(":")[0])[:30]
    fname = f"{safe_target}__{safe_header}__{int(time.time()*1000)}.txt"
    path = os.path.join(evdir, fname)
    with open(path, "w", errors="ignore") as f:
        f.write(f"TARGET: {r.target}\nURL: {r.url}\nSEVERITY: {r.severity}\n\n")
        f.write("--- Request headers sent ---\n")
        for k, v in headers_sent.items():
            f.write(f"{k}: {v}\n")
        f.write(f"\n--- Response: {r.status} ---\nLocation: {r.location}\n\n")
        for n in r.notes:
            f.write(f"NOTE: {n}\n")
        f.write("\n--- Body (first 2000 bytes) ---\n")
        f.write(body[:2000].decode("utf-8", "ignore"))


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="HTTP header fuzzer for authorized security testing.")
    ap.add_argument("-u", "--url", action="append", default=[], help="Target URL (repeatable)")
    ap.add_argument("-l", "--list", help="File of target URLs, one per line")
    ap.add_argument("-i", "--stdin", action="store_true", help="Read target URLs from stdin")
    ap.add_argument("-w", "--wordlist", help="Path to headers file")
    ap.add_argument("--default-list", action="store_true", help="Include built-in general header list")
    ap.add_argument("--bypass-403", action="store_true",
                     help="Include 403/401-bypass header preset and auto-enable baseline diffing")
    ap.add_argument("-X", "--method", default="GET", help="HTTP method (default GET)")
    ap.add_argument("-H", "--base-header", action="append", default=[],
                     help="Static header sent on every request, e.g. -H 'Authorization: Bearer xxx'. Repeatable.")
    ap.add_argument("-x", "--proxy", help="Proxy IP:PORT, e.g. 127.0.0.1:8080 (Burp Suite)")
    ap.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent requests (default 10)")
    ap.add_argument("--rps", type=float, default=0, help="Max aggregate requests/sec (0 = unlimited)")
    ap.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    ap.add_argument("--no-cachebuster", action="store_true", help="Don't append a random cachebuster query param")
    ap.add_argument("--baseline", action="store_true", help="Send a baseline request per target and diff against it")
    ap.add_argument("--show-all", action="store_true", help="Print every request, not just flagged ones")
    ap.add_argument("--out", help="Write raw results to CSV or JSON (by extension)")
    ap.add_argument("--report", help="Write a findings report to .md or .html")
    ap.add_argument("--save-evidence", help="Directory to save raw request/response for flagged findings")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    args = ap.parse_args()

    if not args.quiet:
        print(f"""{C_MAGENTA}
                    .::::::::::.
                .::::::::::::::::.
             .::::::'       '::::::.
           .::::'   .:::::::.  '::::.
          ::::'   .::::::::::::.  '::::
         ::::   .::::::'   '::::::.  ::::
         ::::  ::::::         ::::::  ::::
         ::::  ::::::    .     ::::::  ::::
         ::::  ::::::   '|'    ::::::  ::::
         ::::   '::::::.___.::::::'   ::::
          ::::'   '::::::::::::'   '::::
           '::::.   '::::::::'   .::::'
             '::::::.       .::::::'
                '::::::::::::::::'
                    '::::::::'
{C_RESET}{C_BOLD}{C_RED}  R I N N E G A N{C_RESET}{C_CYAN}  —  HTTP header fuzzer{C_RESET}
{C_MAGENTA}  "Through every header, see the truth of the response."{C_RESET}
""")

    targets = list(args.url)
    if args.list:
        targets.extend(load_lines(args.list))
    if args.stdin:
        targets.extend(line.strip() for line in sys.stdin if line.strip())
    targets = list(dict.fromkeys(targets))  # dedupe, preserve order
    if not targets:
        print("No targets given. Use -u, -l, or -i.", file=sys.stderr)
        sys.exit(1)

    header_blocks = []
    if args.wordlist:
        header_blocks.extend(load_header_blocks(args.wordlist))
    if args.default_list:
        header_blocks.extend(DEFAULT_HEADERS)
    if args.bypass_403:
        header_blocks.extend(BYPASS_403_HEADERS)
        args.baseline = True
    header_blocks = list(dict.fromkeys(header_blocks))
    if not header_blocks:
        print("No headers to test. Use -w, --default-list, and/or --bypass-403.", file=sys.stderr)
        sys.exit(1)

    base_headers = {}
    for h in args.base_header:
        if ":" not in h:
            print(f"Malformed -H value: {h}", file=sys.stderr)
            sys.exit(1)
        k, v = h.split(":", 1)
        base_headers[k.strip()] = v.strip()

    opener = build_opener(args.proxy, args.insecure)
    use_cb = not args.no_cachebuster
    limiter = RateLimiter(args.rps) if args.rps else None

    print(f"[*] Targets: {len(targets)}  Headers/target: {len(header_blocks)}  "
          f"Total requests: {len(targets) * (len(header_blocks) + (1 if args.baseline else 0))}  "
          f"Concurrency: {args.concurrency}{'  Proxy: ' + args.proxy if args.proxy else ''}\n")

    baselines = {}  # target -> (status, body)
    if args.baseline:
        for t in targets:
            _, status, body, _, elapsed, err, _ = send_raw(opener, t, args.method, None, args.timeout,
                                                             base_headers, use_cb, limiter)
            baselines[t] = (status, body)
            tag = f"{C_RED}ERROR: {err}{C_RESET}" if err else ""
            print(f"[*] Baseline {t} -> status={status} length={len(body)} time={elapsed}ms {tag}")
        print()

    results = []
    lock = threading.Lock()

    def worker(target, block):
        headers_sent, status, body, location, elapsed, err, display_url = send_raw(
            opener, target, args.method, block, args.timeout, base_headers, use_cb, limiter)
        bstatus, bbody = baselines.get(target, (None, b""))
        sev, notes = analyze(block, headers_sent, status, body, location, bstatus, bbody)
        if err:
            notes = notes or []
        r = Result(target, block or "(baseline)", display_url, status, len(body), elapsed,
                   location, err, sev or "", notes)
        with lock:
            print_row(r, args.show_all)
            results.append(r)
            if args.save_evidence and sev:
                save_evidence(args.save_evidence, headers_sent, r, body)

    tasks = [(t, b) for t in targets for b in header_blocks]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = [pool.submit(worker, t, b) for t, b in tasks]
        for f in concurrent.futures.as_completed(futs):
            f.result()  # surface exceptions, if any

    print_summary(results)

    if args.out:
        write_out(args.out, results)
        print(f"\n[*] Raw results written to {args.out}")
    if args.report:
        write_report(args.report, results)
        print(f"[*] Report written to {args.report}")
    if args.save_evidence:
        print(f"[*] Evidence for flagged findings saved to {args.save_evidence}/")


if __name__ == "__main__":
    main()
