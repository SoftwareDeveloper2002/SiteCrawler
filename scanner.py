import requests
import threading
import re
import json
import sys
import time
import socket
import ssl
import argparse
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN  = "\033[92m"
ORANGE = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
PURPLE = "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

found_lock   = threading.Lock()
printed_lock = threading.Lock()

fingerprints   = {}
server_profile = {}

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
def banner():
    print(GREEN + r"""
  ██████ ██▄▄▄█████▓█████ ▄████▄  ██▀███  ▄▄▄      █     █░██▓   ▓█████ ██▀███
▒██    ▒▓██▓  ██▒ ▓▓█   ▀▒██▀ ▀█ ▓██ ▒ ██▒████▄   ▓█░ █ ░█▓██▒   ▓█   ▀▓██ ▒ ██▒
░ ▓██▄  ▒██▒ ▓██░ ▒▒███  ▒▓█    ▄▓██ ░▄█ ▒██  ▀█▄ ▒█░ █ ░█▒██░   ▒███  ▓██ ░▄█ ▒
  ▒   ██░██░ ▓██▓ ░▒▓█  ▄▒▓▓▄ ▄██▒██▀▀█▄ ░██▄▄▄▄██░█░ █ ░█▒██░   ▒▓█  ▄▒██▀▀█▄
▒██████▒░██░ ▒██▒ ░░▒████▒ ▓███▀ ░██▓ ▒██▒▓█   ▓██░░██▒██▓░██████░▒████░██▓ ▒██▒
▒ ▒▓▒ ▒ ░▓   ▒ ░░  ░░ ▒░ ░ ░▒ ▒  ░ ▒▓ ░▒▓░▒▒   ▓▒█░ ▓░▒ ▒ ░ ▒░▓  ░░ ▒░ ░ ▒▓ ░▒▓░
░ ░▒  ░ ░▒ ░   ░    ░ ░  ░ ░  ▒    ░▒ ░ ▒░ ▒   ▒▒ ░ ▒ ░ ░ ░ ░ ▒  ░░ ░  ░ ░▒ ░ ▒░
░  ░  ░  ▒ ░ ░        ░  ░         ░░   ░  ░   ▒    ░   ░   ░ ░     ░    ░░   ░
      ░  ░            ░  ░ ░        ░          ░  ░   ░       ░  ░  ░  ░  ░
                              SiteCrawler v2.0  (analyst-grade fingerprint)
                                        -CoderSigma
    """ + RESET)

# ─────────────────────────────────────────────
#  RISK CLASSIFICATION
# ─────────────────────────────────────────────
RISK_CRITICAL = [
    ".env",".env.local",".env.production",".env.development",".env.staging",
    ".git/config",".git/HEAD",".git/index",".git/packed-refs",
    ".htpasswd","actuator/heapdump","actuator/threaddump","actuator/shutdown",
    "actuator/env","actuator/beans","phpinfo.php","info.php",
    "backup.sql","dump.sql","database.sql","db.sqlite","db.sqlite3",
    "config.json","config.yaml","config.yml","docker-compose.yml",
    "Dockerfile","composer.json","WEB-INF/web.xml","web.config","package.json",".git",
]
RISK_HIGH = [
    "admin","admin/login","admin/dashboard","admin/panel","admin/users",
    "administrator","superadmin","graphiql","graphql-playground",
    "graphql/console","swagger-ui","swagger-ui.html","openapi.json",
    "openapi.yaml","api-docs","debug","debug/vars","debug/pprof",
    "actuator","actuator/health","actuator/info","actuator/metrics",
    "metrics","prometheus",".htaccess",".gitignore","wp-login.php",
    "wp-admin","xmlrpc.php","telescope","horizon","nova",
    "api/debug","api/internal","api/private","api/admin","api/dev","api/test",
    "api/v1/users","api/v2/users","users/list","users/search",
]
RISK_MEDIUM = [
    "graphql","swagger","redoc","apidocs","auth/oauth","auth/oauth2",
    "oauth/token","session","sessions","health","healthcheck",
    "logs","audit","reports","export","upload","uploads",
    ".DS_Store","users","accounts","api/v1/accounts",
]

def get_risk(path):
    p = path.lower().lstrip("/")
    if any(p == r or p.startswith(r + "/") for r in RISK_CRITICAL):
        return "CRITICAL", RED
    if any(p == r or p.startswith(r + "/") for r in RISK_HIGH):
        return "HIGH",     ORANGE
    if any(p == r or p.startswith(r + "/") for r in RISK_MEDIUM):
        return "MEDIUM",   YELLOW
    return "LOW", DIM

# ─────────────────────────────────────────────
#  WAF DETECTION
# ─────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":            ["cf-ray","cf-cache-status","__cfduid","cf-request-id"],
    "AWS WAF / CloudFront":  ["x-amz-cf-id","x-amzn-requestid","x-amz-request-id"],
    "Akamai":                ["x-akamai-transformed","akamai-origin-hop","x-check-cacheable"],
    "Imperva/Incapsula":     ["x-iinfo","x-cdn","incap_ses","visid_incap"],
    "Sucuri":                ["x-sucuri-id","x-sucuri-cache"],
    "F5 BIG-IP":             ["bigipserver","x-cnection","f5-"],
    "Barracuda":             ["barra_counter_session"],
    "Fastly":                ["x-fastly-request-id","fastly-restarts","x-served-by"],
    "ModSecurity":           ["mod_security","modsec"],
}

def detect_waf(headers, body=""):
    detected = []
    h_lower  = {k.lower(): v.lower() for k, v in headers.items()}
    body_l   = body.lower()
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in h_lower or sig in body_l:
                detected.append(waf)
                break
    server = h_lower.get("server","")
    if "cloudflare" in server: detected.append("Cloudflare (server header)")
    if "awselb" in server or "amazonaws" in server: detected.append("AWS ELB/CloudFront")
    if "sucuri"  in server: detected.append("Sucuri Firewall")
    return list(dict.fromkeys(detected))

# ─────────────────────────────────────────────
#  TECH DETECTION
# ─────────────────────────────────────────────
TECH_SIGNATURES = {
    "server": {
        "nginx":         "Nginx",
        "apache":        "Apache",
        "microsoft-iis": "IIS",
        "cloudflare":    "Cloudflare",
        "openresty":     "OpenResty/Nginx",
        "caddy":         "Caddy",
        "gunicorn":      "Gunicorn (Python)",
        "uvicorn":       "Uvicorn (Python)",
        "jetty":         "Jetty (Java)",
        "tomcat":        "Tomcat (Java)",
        "lighttpd":      "Lighttpd",
        "litespeed":     "LiteSpeed",
    },
    "x-powered-by": {
        "php":      "PHP",
        "express":  "Express (Node.js)",
        "next.js":  "Next.js",
        "asp.net":  "ASP.NET",
        "laravel":  "Laravel",
        "django":   "Django",
        "rails":    "Ruby on Rails",
        "fastapi":  "FastAPI",
        "flask":    "Flask (Python)",
        "spring":   "Spring (Java)",
    },
    "x-generator": {
        "drupal":    "Drupal",
        "wordpress": "WordPress",
        "joomla":    "Joomla",
    },
    "via": {
        "varnish": "Varnish Cache",
        "squid":   "Squid Proxy",
    },
}

def detect_tech(headers):
    tech = []
    for header, sigs in TECH_SIGNATURES.items():
        val = headers.get(header, "").lower()
        if val:
            for key, label in sigs.items():
                if key in val:
                    tech.append(label)
                    break
    cookies = headers.get("set-cookie", "").lower()
    if "laravel_session"   in cookies: tech.append("Laravel (session)")
    if "phpsessid"         in cookies: tech.append("PHP session")
    if "asp.net_sessionid" in cookies: tech.append("ASP.NET session")
    if "csrftoken"         in cookies: tech.append("Django (CSRF)")
    if "rack.session"      in cookies: tech.append("Rack/Rails")
    if "connect.sid"       in cookies: tech.append("Express/Node.js (session)")
    if "wordpress_"        in cookies: tech.append("WordPress (cookie)")
    ct = headers.get("content-type", "").lower()
    if "application/json"    in ct: tech.append("JSON API")
    if "application/xml"     in ct: tech.append("XML API")
    if "text/xml"            in ct: tech.append("XML API")
    if "application/graphql" in ct: tech.append("GraphQL")
    return list(dict.fromkeys(tech))

# ─────────────────────────────────────────────
#  VERSION EXTRACTION
# ─────────────────────────────────────────────
def extract_versions(headers, body=""):
    versions = {}
    server = headers.get("server","")
    xpb    = headers.get("x-powered-by","")
    m = re.search(r'(nginx|apache)[/\s]([\d.]+)', server, re.IGNORECASE)
    if m: versions[m.group(1).capitalize()] = m.group(2)
    m = re.search(r'PHP/([\d.]+)', xpb, re.IGNORECASE)
    if m: versions["PHP"] = m.group(1)
    m = re.search(r'ASP\.NET[/\s]?([\d.]+)', xpb, re.IGNORECASE)
    if m and m.group(1): versions["ASP.NET"] = m.group(1)
    m = re.search(r'WordPress[/\s]([\d.]+)', body, re.IGNORECASE)
    if m: versions["WordPress"] = m.group(1)
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if m: versions["Generator"] = m.group(1)[:80]
    return versions

# ─────────────────────────────────────────────
#  CVE HINTS
# ─────────────────────────────────────────────
CVE_HINTS = [
    ("PHP",       lambda v: _ver_lt(v,"8.0"),    "CVE-2021-21703 / CVE-2019-11043", "PHP < 8.0 — multiple RCE/path traversal vulns"),
    ("PHP",       lambda v: _ver_lt(v,"7.4"),    "CVE-2019-11043",                  "PHP-FPM < 7.4 — Remote Code Execution via path info"),
    ("Nginx",     lambda v: _ver_lt(v,"1.24"),   "CVE-2023-44487",                  "Nginx < 1.24 — HTTP/2 Rapid Reset DoS"),
    ("Apache",    lambda v: _ver_lt(v,"2.4.55"), "CVE-2023-25690",                  "Apache < 2.4.55 — mod_proxy HTTP request splitting"),
    ("Apache",    lambda v: _ver_lt(v,"2.4.50"), "CVE-2021-41773",                  "Apache 2.4.49-50 — Path traversal & RCE (CRITICAL)"),
    ("WordPress", lambda v: _ver_lt(v,"6.4"),    "CVE-2023-5561",                   "WordPress < 6.4 — username enumeration / XSS"),
]

def _ver_lt(v, threshold):
    try:
        vt = tuple(int(x) for x in v.split(".")[:3])
        tt = tuple(int(x) for x in threshold.split(".")[:3])
        return vt < tt
    except Exception:
        return False

def check_cves(versions):
    hits = []
    for tech, check_fn, cve, desc in CVE_HINTS:
        v = versions.get(tech)
        if v and check_fn(v):
            hits.append((cve, desc, v))
    return hits

# ─────────────────────────────────────────────
#  AUTH + SECURITY HEADERS
# ─────────────────────────────────────────────
def detect_auth(headers, status_code):
    hints = []
    www_auth = headers.get("www-authenticate","")
    if www_auth:
        wl = www_auth.lower()
        if   "bearer" in wl: hints.append("Bearer token required")
        elif "basic"  in wl: hints.append("HTTP Basic auth")
        elif "digest" in wl: hints.append("HTTP Digest auth")
        elif "oauth"  in wl: hints.append("OAuth required")
        else:                hints.append(f"Auth: {www_auth[:60]}")
    if status_code == 401 and not www_auth:
        hints.append("401 Unauthorized — custom auth scheme (no WWW-Authenticate header)")
    if status_code == 403:
        hints.append("403 Forbidden — endpoint exists but access denied")
    sec_ok, sec_miss = [], []
    checks = [
        ("strict-transport-security", "HSTS"),
        ("content-security-policy",   "CSP"),
        ("x-frame-options",           "X-Frame-Options"),
        ("x-content-type-options",    "X-Content-Type-Options"),
        ("referrer-policy",           "Referrer-Policy"),
        ("permissions-policy",        "Permissions-Policy"),
    ]
    for hdr, label in checks:
        if headers.get(hdr): sec_ok.append(label)
        else:                sec_miss.append(label)
    return hints, sec_ok, sec_miss

# ─────────────────────────────────────────────
#  COOKIE SECURITY
# ─────────────────────────────────────────────
def analyze_cookies(headers):
    issues, info = [], []
    raw = headers.get("set-cookie","")
    if not raw:
        return info, issues
    for ck in raw.split(","):
        ck_l = ck.lower()
        name = ck.split("=")[0].strip()
        flags = []
        if "httponly" in ck_l: flags.append("HttpOnly")
        else: issues.append(f"Cookie '{name}' missing HttpOnly — XSS risk")
        if "secure" in ck_l: flags.append("Secure")
        else: issues.append(f"Cookie '{name}' missing Secure flag — cleartext exposure")
        if "samesite" in ck_l: flags.append("SameSite")
        else: issues.append(f"Cookie '{name}' missing SameSite — CSRF risk")
        info.append(f"{name}: {', '.join(flags) if flags else 'no security flags'}")
    return info, issues

# ─────────────────────────────────────────────
#  CORS ANALYSIS
# ─────────────────────────────────────────────
def detect_cors(headers):
    origin  = headers.get("access-control-allow-origin","")
    methods = headers.get("access-control-allow-methods","")
    hdrs    = headers.get("access-control-allow-headers","")
    creds   = headers.get("access-control-allow-credentials","")
    info, issues = [], []
    if origin:
        info.append(f"Allow-Origin: {origin}")
        if origin == "*":
            issues.append("CORS wildcard (*) — any origin can read responses")
        if origin == "*" and creds.lower() == "true":
            issues.append("CRITICAL: CORS wildcard + credentials=true — authentication bypass possible")
        if origin not in ("*","null") and creds.lower() == "true":
            info.append("Credentialed CORS (origin-specific) — verify origin reflection")
    if methods:
        info.append(f"Allow-Methods: {methods}")
        if "DELETE" in methods.upper() or "PUT" in methods.upper():
            issues.append(f"Dangerous methods allowed via CORS: {methods}")
    if hdrs:
        info.append(f"Allow-Headers: {hdrs}")
        if "authorization" in hdrs.lower():
            issues.append("Authorization header exposed via CORS — token theft risk")
    return info, issues

# ─────────────────────────────────────────────
#  RATE LIMIT DETECTION
# ─────────────────────────────────────────────
def detect_rate_limit(headers, status_code):
    info = []
    rl_hdrs = ["x-ratelimit-limit","x-ratelimit-remaining","x-ratelimit-reset",
               "x-rate-limit-limit","x-rate-limit-remaining","retry-after",
               "ratelimit-limit","ratelimit-remaining","ratelimit-reset"]
    found = {k:v for k,v in headers.items() if k.lower() in rl_hdrs}
    if found:
        for k,v in found.items():
            info.append(f"{k}: {v}")
    elif status_code == 429:
        info.append("HTTP 429 Too Many Requests — rate limiting active")
    else:
        info.append("No rate-limit headers detected — brute-force / enumeration risk")
    return info

# ─────────────────────────────────────────────
#  BODY ANALYSIS
# ─────────────────────────────────────────────
def analyze_body(body_text, content_type):
    hints = []
    body  = body_text[:4000]
    if "application/json" in content_type or body.lstrip().startswith(("{","[")):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                keys = list(parsed.keys())
                hints.append(f"JSON keys: {keys[:12]}")
                flat = json.dumps(parsed).lower()
                for word in ["token","password","secret","key","api_key","auth","email",
                             "user","role","admin","error","message","version","debug",
                             "stack","jwt","bearer","hash","salt","private","internal"]:
                    if word in flat:
                        hints.append(f"Sensitive field hint: '{word}' found in response")
            elif isinstance(parsed, list):
                hints.append(f"JSON array ({len(parsed)} items)")
                if parsed and isinstance(parsed[0], dict):
                    hints.append(f"Item keys: {list(parsed[0].keys())[:10]}")
        except Exception:
            hints.append("JSON-like body (parse failed)")

    for pattern, label in [
        (r"(traceback|stack.?trace|exception in|at \w+\.java)",    "Stack trace / exception leaked"),
        (r"(syntax error|mysql error|ora-\d{5}|pg::\w+Error|sqlite3)", "Database error in response"),
        (r"(laravel|symfony|django|rails|spring|express).*error",  "Framework error message leaked"),
        (r"(password|passwd|pwd)\s*[:=]\s*\S+",                    "Password-like value in body"),
        (r"(api.?key|apikey|secret)\s*[:=]\s*\S+",                 "API key or secret in body"),
        (r"(internal server error)",                                "Internal server error message"),
        (r"(debug|dev mode|development mode)",                      "Debug / dev mode active"),
        (r"(swagger|openapi)",                                      "API documentation reference"),
        (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",            "JWT token in response body"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY",                      "Private key exposed in response"),
        (r"(AKIA|ASIA)[A-Z0-9]{16}",                                "AWS Access Key ID pattern"),
        (r"ghp_[a-zA-Z0-9]{36}",                                    "GitHub Personal Access Token"),
        (r"(root|admin):\$",                                        "Password hash pattern (passwd-like)"),
        (r"<\?php",                                                  "PHP source code in response"),
        (r"(xmlns|soap:|xsi:schemaLocation)",                        "SOAP/XML service endpoint"),
    ]:
        if re.search(pattern, body, re.IGNORECASE):
            hints.append(f"[!] {label}")
    return hints

# ─────────────────────────────────────────────
#  INJECTION PROBING (passive)
# ─────────────────────────────────────────────
INJECTION_PROBES = [
    ("SQLi (error-based)",  "?id=1'",               r"(sql|syntax|mysql|pg::|ora-\d|sqlite|unterminated)"),
    ("XSS reflection",      "?q=<script>xss</script>", r"<script>xss</script>"),
    ("Path traversal",      "/../../../etc/passwd",  r"(root:|nobody:|daemon:)"),
    ("SSTI",                "?name={{7*7}}",          r"\b49\b"),
    ("Open redirect",       "?next=//evil.com",      r"(Location:\s*//evil\.com|Location:\s*https?://evil)"),
]

def probe_injections(session, base_url, path, headers):
    url  = base_url.rstrip("/") + "/" + path.lstrip("/")
    hits = []
    for label, suffix, pattern in INJECTION_PROBES:
        try:
            r = session.get(url + suffix, headers=headers, timeout=5, allow_redirects=False)
            target = r.text[:2000] + " " + str(dict(r.headers))
            if re.search(pattern, target, re.IGNORECASE):
                hits.append(f"Possible {label} — pattern matched")
        except Exception:
            pass
    return hits

# ─────────────────────────────────────────────
#  TLS INSPECTION
# ─────────────────────────────────────────────
def inspect_tls(hostname, port=443):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls_version"]     = ssock.version()
                info["cipher"]          = ssock.cipher()
                info["subject"]         = dict(x[0] for x in cert.get("subject",[]))
                info["issuer"]          = dict(x[0] for x in cert.get("issuer",[]))
                info["not_before"]      = cert.get("notBefore","")
                info["not_after"]       = cert.get("notAfter","")
                info["san"]             = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
                try:
                    exp   = datetime.datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
                    delta = exp - datetime.datetime.utcnow()
                    info["expires_in_days"] = delta.days
                except Exception:
                    info["expires_in_days"] = None
    except Exception as e:
        info["tls_error"] = str(e)
    return info

# ─────────────────────────────────────────────
#  DNS / IP RECON
# ─────────────────────────────────────────────
def recon_dns(hostname):
    info = {}
    try:
        ip = socket.gethostbyname(hostname)
        info["ip"] = ip
        try:    info["rdns"] = socket.gethostbyaddr(ip)[0]
        except: info["rdns"] = "N/A"
    except Exception as e:
        info["ip_error"] = str(e)
    return info

# ─────────────────────────────────────────────
#  SERVER RECON  (runs once at startup)
# ─────────────────────────────────────────────
def recon_server(base_url, session, headers):
    global server_profile
    parsed = urlparse(base_url)
    host   = parsed.hostname
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_tls = parsed.scheme == "https"

    print(BLUE + "\n[*] Running server reconnaissance..." + RESET)

    profile = {
        "host": host, "port": port, "scheme": parsed.scheme,
        "dns":{}, "tls":{}, "headers":{}, "tech":[], "waf":[],
        "versions":{}, "cves":[], "cookies":{"info":[],"issues":[]}, "timing":{},
    }

    profile["dns"] = recon_dns(host)
    if is_tls:
        profile["tls"] = inspect_tls(host, port)

    try:
        t0   = time.time()
        resp = session.get(base_url, headers=headers, timeout=10, allow_redirects=True)
        profile["timing"]   = {
            "base_ms":   round((time.time()-t0)*1000),
            "redirects": len(resp.history),
            "final_url": resp.url,
        }
        profile["status"]   = resp.status_code
        profile["headers"]  = dict(resp.headers)
        profile["tech"]     = detect_tech(dict(resp.headers))
        profile["waf"]      = detect_waf(dict(resp.headers), resp.text[:2000])
        profile["versions"] = extract_versions(dict(resp.headers), resp.text[:5000])
        profile["cves"]     = check_cves(profile["versions"])
        ci, cx              = analyze_cookies(dict(resp.headers))
        profile["cookies"]  = {"info":ci, "issues":cx}
        try:
            opt = session.options(base_url, headers=headers, timeout=6, allow_redirects=False)
            profile["allow_methods"] = (opt.headers.get("allow","") or
                                        opt.headers.get("access-control-allow-methods",""))
        except Exception:
            profile["allow_methods"] = ""
    except Exception as e:
        profile["error"] = str(e)

    server_profile.update(profile)
    _print_server_profile(profile)


def _print_server_profile(p):
    print(f"\n{BOLD}{'═'*72}{RESET}")
    print(f"{BOLD}{CYAN}  SERVER RECONNAISSANCE REPORT{RESET}")
    print(f"{BOLD}{'═'*72}{RESET}")

    # Network
    print(f"\n  {BOLD}[NETWORK & DNS]{RESET}")
    dns = p.get("dns",{})
    print(f"    Host          : {p['host']}:{p['port']}")
    if "ip" in dns:   print(f"    IP Address    : {GREEN}{dns['ip']}{RESET}")
    if "rdns" in dns: print(f"    Reverse DNS   : {dns['rdns']}")
    print(f"    Scheme        : {p['scheme'].upper()}")
    timing = p.get("timing",{})
    if timing:
        print(f"    Base RTT      : {timing.get('base_ms','?')} ms")
        if timing.get("redirects",0):
            print(f"    Redirects     : {timing['redirects']}  →  {timing.get('final_url','')}")

    # TLS
    tls = p.get("tls",{})
    if tls and "tls_error" not in tls:
        print(f"\n  {BOLD}[TLS / SSL CERTIFICATE]{RESET}")
        print(f"    Protocol      : {tls.get('tls_version','?')}")
        cipher = tls.get("cipher",())
        if cipher:
            print(f"    Cipher Suite  : {cipher[0]}  ({cipher[2]} bits)")
        subj   = tls.get("subject",{})
        issuer = tls.get("issuer",{})
        print(f"    Cert Subject  : {subj.get('commonName','?')}")
        print(f"    Issuer        : {issuer.get('organizationName','?')}")
        print(f"    Valid From    : {tls.get('not_before','?')}")
        exp_str = tls.get("not_after","?")
        exp_days = tls.get("expires_in_days")
        if exp_days is not None:
            col = RED if exp_days < 14 else (ORANGE if exp_days < 30 else GREEN)
            print(f"    Valid Until   : {exp_str}  {col}({exp_days} days remaining){RESET}")
        else:
            print(f"    Valid Until   : {exp_str}")
        san = tls.get("san",[])
        if san:
            print(f"    SANs          : {', '.join(san[:6])}" + (" ..." if len(san)>6 else ""))
        proto = tls.get("tls_version","")
        if proto in ("TLSv1","TLSv1.1","SSLv3"):
            print(f"    {RED}[!] Weak TLS version detected — upgrade to TLS 1.2/1.3{RESET}")
        else:
            print(f"    {GREEN}TLS version is acceptable ({proto}){RESET}")
    elif tls.get("tls_error"):
        print(f"\n  {BOLD}[TLS]{RESET}  {RED}Error: {tls['tls_error']}{RESET}")

    # Server identity
    print(f"\n  {BOLD}[SERVER IDENTITY & TECH STACK]{RESET}")
    hdrs   = p.get("headers",{})
    server = hdrs.get("server","") or hdrs.get("Server","")
    xpb    = hdrs.get("x-powered-by","") or hdrs.get("X-Powered-By","")
    xgen   = hdrs.get("x-generator","") or hdrs.get("X-Generator","")
    xaspv  = hdrs.get("x-aspnet-version","")
    via    = hdrs.get("via","")
    if server: print(f"    Server        : {CYAN}{server}{RESET}")
    if xpb:    print(f"    X-Powered-By  : {CYAN}{xpb}{RESET}")
    if xgen:   print(f"    X-Generator   : {CYAN}{xgen}{RESET}")
    if xaspv:  print(f"    ASP.NET Ver.  : {CYAN}{xaspv}{RESET}")
    if via:    print(f"    Via (proxy)   : {CYAN}{via}{RESET}")
    if p.get("allow_methods"):
        print(f"    Allow Methods : {p['allow_methods']}")
    tech = p.get("tech",[])
    if tech:
        print(f"    Detected Tech : {', '.join(tech)}")

    versions = p.get("versions",{})
    if versions:
        print(f"\n  {BOLD}[SOFTWARE VERSIONS]{RESET}")
        for t, v in versions.items():
            print(f"    {t:<18}: {v}")

    # WAF
    waf = p.get("waf",[])
    print(f"\n  {BOLD}[WAF / CDN DETECTION]{RESET}")
    if waf:
        for w in waf:
            print(f"    {GREEN}[+] Detected  : {w}{RESET}")
    else:
        print(f"    {ORANGE}[!] No WAF/CDN signatures detected — target may be unprotected{RESET}")

    # CVE hints
    cves = p.get("cves",[])
    if cves:
        print(f"\n  {BOLD}[CVE / KNOWN VULNERABILITY HINTS]{RESET}")
        for cve, desc, ver in cves:
            print(f"    {RED}[!] {cve}{RESET}")
            print(f"        Description : {desc}")
            print(f"        Detected ver: {ver}")

    # Cookie security
    ck_issues = p.get("cookies",{}).get("issues",[])
    ck_info   = p.get("cookies",{}).get("info",[])
    if ck_issues or ck_info:
        print(f"\n  {BOLD}[COOKIE SECURITY]{RESET}")
        for ci in ck_info[:4]:
            print(f"    {DIM}{ci}{RESET}")
        for cx in ck_issues:
            print(f"    {ORANGE}[!] {cx}{RESET}")

    # Key security response headers
    print(f"\n  {BOLD}[SECURITY RESPONSE HEADERS]{RESET}")
    sec_checks = [
        ("strict-transport-security", "HSTS"),
        ("content-security-policy",   "CSP"),
        ("x-frame-options",           "X-Frame-Options"),
        ("x-content-type-options",    "X-Content-Type-Options"),
        ("referrer-policy",           "Referrer-Policy"),
        ("permissions-policy",        "Permissions-Policy"),
    ]
    for hdr, label in sec_checks:
        val = hdrs.get(hdr,"")
        if val:
            print(f"    {GREEN}[OK]{RESET}  {label:<28}: {val[:60]}")
        else:
            print(f"    {ORANGE}[!!]{RESET}  {label:<28}: MISSING")

    # All response headers
    print(f"\n  {BOLD}[ALL RESPONSE HEADERS]{RESET}")
    for k, v in hdrs.items():
        print(f"    {DIM}{k:<36}{RESET} {v}")

    print(f"\n{BOLD}{'═'*72}{RESET}\n")

# ─────────────────────────────────────────────
#  SINGLE REQUEST
# ─────────────────────────────────────────────
def probe_method(session, url, method, headers, timeout=7):
    try:
        body, req_hdrs = None, dict(headers)
        if method in ("POST","PUT","PATCH"):
            body = json.dumps({})
            req_hdrs.setdefault("Content-Type","application/json")
        t0   = time.time()
        resp = session.request(method, url, data=body, headers=req_hdrs,
                               timeout=timeout, allow_redirects=False)
        return {
            "method":       method,
            "status":       resp.status_code,
            "elapsed_ms":   round((time.time()-t0)*1000),
            "headers":      dict(resp.headers),
            "body":         resp.text,
            "content_type": resp.headers.get("content-type",""),
            "content_len":  resp.headers.get("content-length", len(resp.content)),
            "location":     resp.headers.get("location",""),
            "error":        None,
        }
    except requests.exceptions.Timeout:
        return {"method":method,"status":None,"error":"TIMEOUT","headers":{},"body":"","content_type":"","location":"","elapsed_ms":0,"content_len":0}
    except requests.exceptions.ConnectionError:
        return {"method":method,"status":None,"error":"CONNECTION_FAILED","headers":{},"body":"","content_type":"","location":"","elapsed_ms":0,"content_len":0}
    except requests.exceptions.RequestException as e:
        return {"method":method,"status":None,"error":str(e)[:80],"headers":{},"body":"","content_type":"","location":"","elapsed_ms":0,"content_len":0}

# ─────────────────────────────────────────────
#  FINGERPRINT ONE ENDPOINT
# ─────────────────────────────────────────────
def fingerprint_endpoint(base_url, path, session, extra_headers, methods, verbose=False, run_inject=False):
    url  = base_url.rstrip("/") + "/" + path.lstrip("/")
    risk, risk_color = get_risk(path)
    results     = {m: probe_method(session, url, m, extra_headers) for m in methods}
    interesting = {m: r for m,r in results.items() if r["status"] is not None and r["status"] != 404}

    if not interesting and not verbose:
        return None

    sample = (next((r for r in interesting.values() if r["status"]), None)
              or next(iter(results.values())))

    tech            = detect_tech(sample["headers"])
    auth_hints, sec_ok, sec_miss = detect_auth(sample["headers"], sample.get("status",0))
    cors_info, cors_issues = detect_cors(sample["headers"])
    body_hints      = analyze_body(sample["body"], sample["content_type"])
    rl_info         = detect_rate_limit(sample["headers"], sample.get("status",0)) if interesting else []
    waf             = detect_waf(sample["headers"], sample.get("body","")[:1000])
    ck_info, ck_issues = analyze_cookies(sample["headers"])
    inject_hits     = probe_injections(session, base_url, path, extra_headers) if run_inject and interesting else []
    working         = [m for m,r in interesting.items() if r["status"] not in (405,501)]
    no_method       = [m for m,r in interesting.items() if r["status"] in (405,501)]

    fp = {
        "url":url,"path":path,"risk":risk,"risk_color":risk_color,
        "methods":results,"working":working,"no_method":no_method,
        "tech":tech,"auth_hints":auth_hints,"sec_ok":sec_ok,"sec_miss":sec_miss,
        "cors_info":cors_info,"cors_issues":cors_issues,"body_hints":body_hints,
        "rl_info":rl_info,"waf":waf,"ck_info":ck_info,"ck_issues":ck_issues,
        "inject_hits":inject_hits,
        "server":sample["headers"].get("server",""),
        "x_powered_by":sample["headers"].get("x-powered-by",""),
    }

    with printed_lock:
        _print_fp(fp, interesting, verbose)
    with found_lock:
        fingerprints[path] = fp
    return fp


def _print_fp(fp, interesting, verbose):
    if not interesting:
        if verbose:
            print(DIM + f"[404] {fp['url']}" + RESET)
        return
    rc = fp["risk_color"]
    print(f"\n{BOLD}{'─'*72}{RESET}")
    print(f"{BOLD}{rc}[{fp['risk']}]{RESET} {BOLD}{fp['url']}{RESET}")
    for method, r in interesting.items():
        code = r["status"]
        ms   = r.get("elapsed_ms","?")
        clen = r.get("content_len","?")
        loc  = f"  →  {r['location']}" if r.get("location") else ""
        ct   = r.get("content_type","").split(";")[0].strip()
        if   code in (200,201,202,204):   col = GREEN
        elif code in (301,302,307,308):   col = CYAN
        elif code in (401,403):           col = ORANGE
        elif code == 405:                 col = PURPLE
        elif code and code >= 500:        col = RED
        else:                             col = DIM
        print(f"  {col}[{code}]{RESET} {BOLD}{method:<8}{RESET} {ms}ms  len={clen}  {ct}{loc}")
    if fp["working"]:    print(f"  {GREEN}Working    :{RESET} {', '.join(fp['working'])}")
    if fp["no_method"]:  print(f"  {PURPLE}405 methods:{RESET} {', '.join(fp['no_method'])}")
    if fp["tech"]:       print(f"  {CYAN}Tech       :{RESET} {', '.join(fp['tech'])}")
    if fp["server"]:     print(f"  {CYAN}Server     :{RESET} {fp['server']}")
    if fp["x_powered_by"]: print(f"  {CYAN}X-Powered  :{RESET} {fp['x_powered_by']}")
    if fp["waf"]:        print(f"  {CYAN}WAF/CDN    :{RESET} {', '.join(fp['waf'])}")
    for h in fp["auth_hints"]:
        print(f"  {ORANGE}Auth       :{RESET} {h}")
    for c in fp["cors_issues"]:
        print(f"  {RED}CORS !     :{RESET} {c}")
    for c in fp["cors_info"]:
        print(f"  {CYAN}CORS       :{RESET} {c}")
    for b in fp["body_hints"]:
        col = RED if "[!]" in b else CYAN
        print(f"  {col}Body       :{RESET} {b}")
    for cx in fp["ck_issues"]:
        print(f"  {ORANGE}Cookie !   :{RESET} {cx}")
    for inj in fp["inject_hits"]:
        print(f"  {RED}[!] Inject :{RESET} {inj}")
    rl = fp.get("rl_info",[])
    if rl and "No rate-limit" in rl[0]:
        print(f"  {ORANGE}RateLimit  :{RESET} {rl[0]}")
    elif rl:
        print(f"  {GREEN}RateLimit  :{RESET} {rl[0]}")
    if fp["sec_ok"]:     print(f"  {GREEN}Sec OK     :{RESET} {', '.join(fp['sec_ok'])}")
    if fp["sec_miss"]:   print(f"  {ORANGE}Sec miss   :{RESET} {', '.join(fp['sec_miss'])}")

# ─────────────────────────────────────────────
#  MODE 6 — DEEP PROBE (single endpoint)
# ─────────────────────────────────────────────
def probe_single(base_url, path, session, headers):
    all_methods = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    print(BLUE + f"\n[*] Deep probe -> {url}" + RESET)
    print(BLUE +  "    Testing all HTTP methods + full analyst dump\n" + RESET)

    results     = {m: probe_method(session, url, m, headers) for m in all_methods}
    interesting = {m: r for m,r in results.items() if r["status"] is not None and r["status"] != 404}

    if not interesting:
        print(RED + "    All methods returned 404 — endpoint likely does not exist." + RESET)
        return

    risk, risk_color = get_risk(path)
    sample = results.get("GET") or results.get("POST") or next(iter(results.values()))

    # Method table
    print(f"{BOLD}{'─'*72}{RESET}")
    print(f"{BOLD}{risk_color}[{risk}]{RESET}  {BOLD}{url}{RESET}")
    print(f"{BOLD}{'─'*72}{RESET}")
    print(f"  {'METHOD':<8}  {'STATUS':<6}  {'TIME':>6}  {'SIZE':>8}  CONTENT-TYPE")
    print(f"  {'─'*8}  {'─'*6}  {'─'*6}  {'─'*8}  {'─'*30}")
    for method in all_methods:
        r    = results[method]
        code = r["status"]
        if code is None:
            print(f"  {DIM}{method:<8}  {r['error']}{RESET}")
            continue
        ms   = r.get("elapsed_ms","?")
        clen = str(r.get("content_len","?"))
        ct   = r.get("content_type","").split(";")[0].strip()
        loc  = f"  →  {r['location']}" if r.get("location") else ""
        if   code in (200,201,202,204):   col = GREEN
        elif code in (301,302,307,308):   col = CYAN
        elif code in (401,403):           col = ORANGE
        elif code == 405:                 col = PURPLE
        elif code and code >= 500:        col = RED
        else:                             col = DIM
        print(f"  {col}{method:<8}  {code:<6}{RESET}  {ms:>5}ms  {clen:>8}  {ct}{loc}")

    opt_allow = (results.get("OPTIONS",{}).get("headers",{}) or {})
    allow_hdr = opt_allow.get("allow","") or opt_allow.get("access-control-allow-methods","")
    if allow_hdr:
        print(f"\n  {GREEN}Server Allow header:{RESET} {allow_hdr}")

    tech            = detect_tech(sample["headers"])
    auth_hints, sec_ok, sec_miss = detect_auth(sample["headers"], sample.get("status",0))
    cors_info, cors_issues = detect_cors(sample["headers"])
    body_hints      = analyze_body(sample["body"], sample["content_type"])
    rl_info         = detect_rate_limit(sample["headers"], sample.get("status",0))
    waf             = detect_waf(sample["headers"], sample.get("body","")[:1000])
    ck_info, ck_issues = analyze_cookies(sample["headers"])
    inject_hits     = probe_injections(session, base_url, path, headers)
    versions        = extract_versions(sample["headers"], sample.get("body",""))
    cves            = check_cves(versions)

    print(f"\n{BOLD}  ANALYST REPORT{RESET}")
    print(f"  {'─'*68}")

    print(f"\n  {BOLD}[TECH STACK]{RESET}")
    if tech:   print(f"    Stack         : {', '.join(tech)}")
    server = sample["headers"].get("server","")
    xpb    = sample["headers"].get("x-powered-by","")
    if server:    print(f"    Server        : {server}")
    if xpb:       print(f"    X-Powered-By  : {xpb}")
    for t, v in versions.items():
        print(f"    Version       : {t} {v}")
    if waf:       print(f"    WAF/CDN       : {', '.join(waf)}")
    else:         print(f"    {ORANGE}WAF/CDN       : None detected{RESET}")

    print(f"\n  {BOLD}[AUTHENTICATION]{RESET}")
    if auth_hints:
        for h in auth_hints: print(f"    {ORANGE}{h}{RESET}")
    else:
        print(f"    No auth enforcement detected on this endpoint")

    print(f"\n  {BOLD}[CORS POLICY]{RESET}")
    for c in cors_issues: print(f"    {RED}[!] {c}{RESET}")
    for c in cors_info:   print(f"    {CYAN}{c}{RESET}")
    if not cors_info:     print(f"    No CORS headers present")

    print(f"\n  {BOLD}[RATE LIMITING]{RESET}")
    for r in rl_info:
        col = ORANGE if "No rate-limit" in r else GREEN
        print(f"    {col}{r}{RESET}")

    print(f"\n  {BOLD}[SECURITY HEADERS]{RESET}")
    sec_checks = [
        ("strict-transport-security","HSTS"),
        ("content-security-policy","CSP"),
        ("x-frame-options","X-Frame-Options"),
        ("x-content-type-options","X-Content-Type-Options"),
        ("referrer-policy","Referrer-Policy"),
        ("permissions-policy","Permissions-Policy"),
    ]
    for hdr, label in sec_checks:
        val = sample["headers"].get(hdr,"")
        if val: print(f"    {GREEN}[OK]{RESET}  {label:<28}: {val[:60]}")
        else:   print(f"    {ORANGE}[!!]{RESET}  {label:<28}: MISSING")

    print(f"\n  {BOLD}[COOKIE SECURITY]{RESET}")
    if ck_issues:
        for cx in ck_issues: print(f"    {ORANGE}[!] {cx}{RESET}")
    elif ck_info:
        for ci in ck_info[:3]: print(f"    {DIM}{ci}{RESET}")
    else:
        print(f"    No Set-Cookie headers on this endpoint")

    print(f"\n  {BOLD}[BODY ANALYSIS]{RESET}")
    if body_hints:
        for b in body_hints:
            col = RED if "[!]" in b else CYAN
            print(f"    {col}{b}{RESET}")
    else:
        print(f"    No sensitive patterns detected in response body")

    print(f"\n  {BOLD}[INJECTION PROBING (passive)]{RESET}")
    if inject_hits:
        for inj in inject_hits: print(f"    {RED}[!] {inj}{RESET}")
    else:
        print(f"    {GREEN}No injection patterns triggered{RESET}")

    if cves:
        print(f"\n  {BOLD}[CVE / KNOWN VULNS]{RESET}")
        for cve, desc, ver in cves:
            print(f"    {RED}[!] {cve}{RESET}")
            print(f"        {desc}")
            print(f"        Detected version: {ver}")

    print(f"\n  {BOLD}[RAW RESPONSE HEADERS]{RESET}")
    print(f"  {'─'*68}")
    for k, v in sample["headers"].items():
        print(f"    {DIM}{k:<36}{RESET} {v}")

    body = sample.get("body","").strip()
    if body:
        preview = body[:1000]
        print(f"\n  {BOLD}[BODY PREVIEW — first 1000 chars]{RESET}")
        print(f"  {'─'*68}")
        for line in preview.splitlines()[:35]:
            print(f"    {line}")
        if len(body) > 1000:
            print(f"    {DIM}... ({len(body)} total chars){RESET}")

    print(f"\n{BOLD}{'─'*72}{RESET}")

# ─────────────────────────────────────────────
#  BULK SCAN
# ─────────────────────────────────────────────
def load_wordlist(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(RED + f"[ERROR] Wordlist '{path}' not found." + RESET)
        sys.exit(1)

def bulk_scan(base_url, paths, session, headers, methods, threads, verbose, label, inject=False):
    print(BLUE + f"\n[*] {label} — {len(paths)} paths × {len(methods)} methods" + RESET)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(fingerprint_endpoint, base_url, p, session, headers, methods, verbose, inject): p
                   for p in paths}
        for _ in as_completed(futures):
            pass

def deep_crawl(base_url, session, headers, methods, verbose):
    print(BLUE + "\n[*] Deep crawl — extracting links & API refs from page" + RESET)
    try:
        resp     = session.get(base_url, timeout=8, headers=headers)
        links    = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
        assets   = re.findall(r'src=["\']([^"\']+)["\']', resp.text)
        api_refs = re.findall(r'["\'`](/(?:api|v\d|rest|graphql)[^"\'`\s]{1,80})', resp.text)
        all_paths = set()
        base_netloc = urlparse(base_url).netloc
        for link in links + assets + api_refs:
            if link.startswith("http"):
                p = urlparse(link)
                if p.netloc != base_netloc: continue
                all_paths.add(p.path.lstrip("/"))
            elif link.startswith("/"):
                all_paths.add(link.lstrip("/"))
        print(BLUE + f"    {len(all_paths)} references found" + RESET)
        bulk_scan(base_url, list(all_paths), session, headers, methods, 20, verbose, "Crawl scan")
    except requests.exceptions.RequestException as e:
        print(RED + f"[ERROR] Crawl failed: {e}" + RESET)

# ─────────────────────────────────────────────
#  RISK REPORT
# ─────────────────────────────────────────────
def print_risk_report():
    crit = [(p,f) for p,f in fingerprints.items() if f["risk"]=="CRITICAL"]
    high = [(p,f) for p,f in fingerprints.items() if f["risk"]=="HIGH"]
    med  = [(p,f) for p,f in fingerprints.items() if f["risk"]=="MEDIUM"]

    print(f"\n{BOLD}{'═'*72}{RESET}")
    print(f"{BOLD}  CYBERSECURITY ANALYST RISK REPORT{RESET}")
    print(f"{BOLD}{'═'*72}{RESET}")

    sp = server_profile
    if sp:
        print(f"\n  {BOLD}TARGET SUMMARY{RESET}")
        print(f"    Host       : {sp.get('host','?')}  [{sp.get('dns',{}).get('ip','?')}]")
        print(f"    Tech Stack : {', '.join(sp.get('tech',[])) or 'Unknown'}")
        tls_ver  = sp.get('tls',{}).get('tls_version','N/A')
        tls_days = sp.get('tls',{}).get('expires_in_days','?')
        print(f"    TLS        : {tls_ver}  (cert expires in {tls_days} days)")
        print(f"    WAF/CDN    : {', '.join(sp.get('waf',[])) or 'None detected'}")
        cves = sp.get("cves",[])
        if cves:
            print(f"    {RED}CVEs       : {len(cves)} known vuln hint(s) detected{RESET}")
        ck_issues = sp.get("cookies",{}).get("issues",[])
        if ck_issues:
            print(f"    {ORANGE}Cookies    : {len(ck_issues)} cookie security issue(s){RESET}")

    for label, color, group in [("CRITICAL",RED,crit),("HIGH",ORANGE,high),("MEDIUM",YELLOW,med)]:
        if not group: continue
        print(f"\n  {color}{BOLD}━━ [{label}] — {len(group)} finding(s){RESET}")
        for path, fp in group:
            statuses = {m:r["status"] for m,r in fp["methods"].items() if r.get("status")}
            working  = [m for m,s in statuses.items() if s not in (404,405,None)]
            s_str    = "  ".join(f"{m}={s}" for m,s in statuses.items() if s)
            print(f"\n    {BOLD}{fp['url']}{RESET}")
            print(f"      HTTP Status : {s_str}")
            if working:
                print(f"      Methods OK  : {', '.join(working)}")
            if fp.get("tech"):
                print(f"      Tech        : {', '.join(fp['tech'])}")
            if fp.get("waf"):
                print(f"      WAF/CDN     : {', '.join(fp['waf'])}")
            if fp.get("auth_hints"):
                print(f"      Auth        : {'; '.join(fp['auth_hints'])}")
            for c in fp.get("cors_issues",[]):
                print(f"      {RED}CORS Issue  : {c}{RESET}")
            for cx in fp.get("ck_issues",[]):
                print(f"      {ORANGE}Cookie Issue: {cx}{RESET}")
            for b in fp.get("body_hints",[]):
                if "[!]" in b:
                    print(f"      {RED}Body Alert  : {b}{RESET}")
            for inj in fp.get("inject_hits",[]):
                print(f"      {RED}Injection   : {inj}{RESET}")
            rl = fp.get("rl_info",[])
            if rl and "No rate-limit" in rl[0]:
                print(f"      {ORANGE}Rate Limit  : No rate-limiting detected{RESET}")
            if fp.get("sec_miss"):
                print(f"      Sec Missing : {', '.join(fp['sec_miss'])}")

    total     = len(fingerprints)
    found     = sum(1 for f in fingerprints.values()
                    if any(r.get("status") not in (404,None) for r in f["methods"].values()))
    inj_total  = sum(len(f.get("inject_hits",[])) for f in fingerprints.values())
    cors_total = sum(1 for f in fingerprints.values() if f.get("cors_issues"))
    ck_total   = sum(1 for f in fingerprints.values() if f.get("ck_issues"))
    no_rl      = sum(1 for f in fingerprints.values()
                     if f.get("rl_info") and "No rate-limit" in f["rl_info"][0])

    print(f"\n  {BOLD}SCAN STATISTICS{RESET}")
    print(f"    Paths probed       : {total}")
    print(f"    Active endpoints   : {found}")
    print(f"    Critical           : {len(crit)}")
    print(f"    High               : {len(high)}")
    print(f"    Medium             : {len(med)}")
    if inj_total:   print(f"    {RED}Injection hits     : {inj_total}{RESET}")
    if cors_total:  print(f"    {ORANGE}CORS issues        : {cors_total}{RESET}")
    if ck_total:    print(f"    {ORANGE}Cookie issues      : {ck_total}{RESET}")
    if no_rl:       print(f"    {ORANGE}No rate-limit on   : {no_rl} endpoint(s){RESET}")
    print(f"{BOLD}{'═'*72}{RESET}\n")

# ─────────────────────────────────────────────
#  SAVE
# ─────────────────────────────────────────────
def save_results(output_file):
    lines = []
    for path, fp in fingerprints.items():
        for method, r in fp["methods"].items():
            if r.get("status") and r["status"] != 404:
                line = (f"[{fp['risk']}] [{r['status']}] [{method}] {fp['url']}"
                        + (f" | tech:{','.join(fp['tech'])}"            if fp.get("tech")         else "")
                        + (f" | waf:{','.join(fp['waf'])}"              if fp.get("waf")          else "")
                        + (f" | auth:{';'.join(fp['auth_hints'])}"      if fp.get("auth_hints")   else "")
                        + (f" | cors:{';'.join(fp['cors_issues'])}"     if fp.get("cors_issues")  else "")
                        + (f" | cookie:{';'.join(fp['ck_issues'])}"     if fp.get("ck_issues")    else "")
                        + (f" | inject:{';'.join(fp['inject_hits'])}"   if fp.get("inject_hits")  else ""))
                lines.append(line)
    if lines:
        with open(output_file,"w",encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(GREEN + f"[*] Saved -> {output_file} ({len(lines)} entries)" + RESET)
    else:
        print(RED + "[*] No findings to save." + RESET)

# ─────────────────────────────────────────────
#  BUILT-IN API PATHS
# ─────────────────────────────────────────────
API_PATHS = [
    "api","api/v1","api/v2","api/v3","api/v4","api/v1.0","api/v2.0","api/v3.0",
    "api/internal","api/public","api/private","api/beta","api/alpha",
    "api/admin","api/dev","api/debug","api/test","apis","api-docs","api-gateway",
    "rest","rest/v1","rest/v2","restapi","rpc","jsonrpc","xmlrpc",
    "auth","auth/login","auth/logout","auth/register","auth/signup",
    "auth/token","auth/refresh","auth/verify","auth/reset",
    "auth/oauth","auth/oauth2","auth/callback",
    "oauth","oauth2","oauth/token","oauth/authorize","oauth/callback",
    "login","logout","register","signup","signin","signout",
    "sso","saml","saml/acs","saml/metadata",
    "token","tokens","refresh-token","session","sessions","session/new",
    "password","password/reset","password/change","password/forgot",
    "forgot-password","reset-password","2fa","mfa","otp",
    "verify","verify/email","confirm","confirmation",
    ".well-known/openid-configuration",".well-known/jwks.json",
    "users","user","user/me","users/me","users/profile","users/list","users/search",
    "account","accounts","account/settings","account/profile","profile","profiles","me",
    "members","member","admin/users","api/v1/users","api/v2/users",
    "api/v1/accounts","api/v2/accounts",
    "admin","admin/login","admin/dashboard","admin/panel","admin/api",
    "administrator","administrator/login","manager","management",
    "dashboard","control-panel","controlpanel","panel",
    "backend","back-end","backoffice","back-office",
    "cms","cms/admin","cms/api","console","console/login","superadmin","super-admin","root",
    "graphql","graphiql","graphql/console","playground","graphql-playground",
    "api/graphql","v1/graphql","query",
    "swagger","swagger-ui","swagger-ui.html","swagger/index.html","swagger/ui",
    "swagger/v1","swagger/v2","api-docs","api-docs/v1","api-docs/v2",
    "openapi","openapi.json","openapi.yaml","openapi.yml",
    "api/swagger","docs/api","redoc","api/redoc","apidocs",
    "health","healthcheck","health-check","health/ready","health/live",
    "status","ping","pong","alive","ready","readiness","liveness",
    "metrics","prometheus","actuator","actuator/health","actuator/info",
    "actuator/metrics","actuator/env","actuator/beans","actuator/mappings",
    "actuator/shutdown","actuator/heapdump","actuator/threaddump",
    "monitor","monitoring","api/health","api/status","api/ping",
    "version","info","about","build","build-info","api/version","api/info",
    "env","environment","config",
    "upload","uploads","upload/file","upload/image","media","media/upload",
    "files","file","static","assets","resources","cdn","images","img","docs","documents",
    "search","find","lookup","notifications","notification","messages","message",
    "inbox","outbox","chat","ws","websocket","events","webhooks","webhook",
    "products","product","catalog","catalogue","categories","category",
    "items","item","inventory","stock","orders","order","cart","checkout",
    "payments","payment","billing","invoice","invoices",
    "subscriptions","subscription","plans","plan",
    "posts","post","articles","article","blog","blogs","news","announcements",
    "pages","page","content","contents","comments","comment","reviews","review",
    "settings","setting","preferences","configuration","options","flags","feature-flags",
    "logs","log","audit","audit-log","audit-logs","activity","activities","history",
    "integrations","integration","connect","callbacks","callback",
    "debug","debug/info","debug/vars","debug/pprof","trace","profiler",
    "phpinfo.php","test.php","info.php",
    ".env",".env.local",".env.production",".env.development",".env.staging",
    "config.json","config.yaml","config.yml","app.json","manifest.json",
    "robots.txt","sitemap.xml","crossdomain.xml","browserconfig.xml",
    "server-status","server-info",
    ".git",".git/config",".git/HEAD",".gitignore",".htaccess",".htpasswd",
    "web.config","WEB-INF/web.xml","WEB-INF/classes",
    "composer.json","package.json","yarn.lock","package-lock.json",
    "requirements.txt","Gemfile","Gemfile.lock",
    "Dockerfile","docker-compose.yml","docker-compose.yaml",".dockerignore",
    "README.md","CHANGELOG.md","backup.zip","backup.tar.gz",
    "backup.sql","dump.sql","database.sql","db.sql","db.sqlite","db.sqlite3",
    "telescope","horizon","nova","api/user","sanctum/csrf-cookie","storage","storage/logs",
    "django-admin","admin/doc","admin/jsi18n","api/schema","api/schema.json",
    "api/healthz","api/readyz","api/livez","_api","_internal","_debug",
    "rails/info","rails/info/properties","rails/mailers","letter_opener",
    "wp-json","wp-json/wp/v2","wp-json/wp/v2/users",
    "wp-login.php","wp-admin","wp-admin/admin-ajax.php","xmlrpc.php","wp-cron.php",
    "internal","internal/api","private","private/api","service","services",
    "gateway","proxy","cron","jobs","job","tasks","task","queue","worker",
    "reports","report","analytics","statistics","stats",
    "export","import","sync","migrate","cache","flush","clear",
    "error","errors","exception","exceptions",
]

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(description="SiteCrawler v4.0 — analyst-grade endpoint fingerprinting")
    parser.add_argument("-u","--url",       help="Target base URL")
    parser.add_argument("-p","--path",      help="Single path for mode 6 probe (omit to auto-probe all API paths)")
    parser.add_argument("-w","--wordlist",  default="wordlist.txt")
    parser.add_argument("-t","--threads",   type=int, default=40)
    parser.add_argument("-m","--methods",   default="GET,POST,PUT,DELETE")
    parser.add_argument("-H","--header",    action="append", default=[])
    parser.add_argument("--token",          help="Bearer token (sets Authorization header)")
    parser.add_argument("--inject",         action="store_true", help="Enable passive injection probing per endpoint")
    parser.add_argument("-v","--verbose",   action="store_true")
    parser.add_argument("-o","--output",    default="result.txt")
    parser.add_argument("--mode",           help="1=normal 2=crawl 3=api 4=hybrid 5=full 6=probe")
    parser.add_argument("--no-recon",       action="store_true", help="Skip initial server recon")
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; SiteCrawler/4.0)",
        "Accept":     "application/json, text/html, */*",
    })
    custom_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()
    if args.token:
        custom_headers["Authorization"] = f"Bearer {args.token}"

    base_url = args.url or input(CYAN + "Target URL: " + RESET).strip()
    methods  = [m.strip().upper() for m in args.methods.split(",") if m.strip()]

    if not args.no_recon:
        recon_server(base_url, session, custom_headers)

    if not args.mode:
        print(f"""
  {BOLD}Scan modes:{RESET}
  1  Normal       — wordlist paths
  2  Crawl        — extract links & assets from page
  3  API          — built-in API/backend route list
  4  Hybrid       — Normal + Crawl + API
  5  Full         — everything combined
  6  Probe        — deep fingerprint all API paths (all 7 methods + analyst report)
               tip: add -p <path> to probe one specific endpoint
               tip: add --inject  to enable passive injection probing
               tip: add --no-recon to skip the initial server recon
""")
        choice = input(CYAN + "Choice [1-6]: " + RESET).strip()
    else:
        choice = args.mode

    t     = args.threads
    v     = args.verbose
    inj   = args.inject
    start = time.time()

    if choice == "6":
        all_methods = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]
        if args.path:
            probe_single(base_url, args.path, session, custom_headers)
        else:
            print(BLUE + f"\n[*] Probe mode — auto-scanning all {len(API_PATHS)} built-in API paths" + RESET)
            print(BLUE +  "    All 7 HTTP methods per path\n" + RESET)
            bulk_scan(base_url, API_PATHS, session, custom_headers, all_methods, t, v, "Probe scan", inj)
            print_risk_report()
    elif choice == "1":
        words = load_wordlist(args.wordlist)
        bulk_scan(base_url, words, session, custom_headers, methods, t, v, "Normal scan", inj)
    elif choice == "2":
        deep_crawl(base_url, session, custom_headers, methods, v)
    elif choice == "3":
        bulk_scan(base_url, API_PATHS, session, custom_headers, methods, t, v, "API scan", inj)
    elif choice == "4":
        words = load_wordlist(args.wordlist)
        bulk_scan(base_url, words,     session, custom_headers, methods, t, v, "Normal scan", inj)
        deep_crawl(base_url, session, custom_headers, methods, v)
        bulk_scan(base_url, API_PATHS, session, custom_headers, methods, t, v, "API scan",    inj)
    elif choice == "5":
        words = load_wordlist(args.wordlist)
        bulk_scan(base_url, list(dict.fromkeys(words + API_PATHS)),
                  session, custom_headers, methods, t, v, "Full scan", inj)
        deep_crawl(base_url, session, custom_headers, methods, v)
    else:
        print(RED + "[ERROR] Invalid choice." + RESET)
        sys.exit(1)

    if choice != "6":
        print_risk_report()

    save_results(args.output)
    print(GREEN + f"\n[DONE] {time.time()-start:.1f}s" + RESET)

if __name__ == "__main__":
    main()