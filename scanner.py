#!/usr/bin/env python3
"""
SiteCrawler v4.0 — Analyst-grade endpoint fingerprinting
Premium PyQt5 GUI — CoderSigma
"""

import sys, re, json, time, socket, ssl, datetime, threading, os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

found_lock  = threading.Lock()
fingerprints  = {}
server_profile = {}

# ═══════════════════════════════════════════════════════════
#  BACKEND ENGINE
# ═══════════════════════════════════════════════════════════
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
    if any(p == r or p.startswith(r + "/") for r in RISK_CRITICAL): return "CRITICAL","#ff3355"
    if any(p == r or p.startswith(r + "/") for r in RISK_HIGH):     return "HIGH","#ff8800"
    if any(p == r or p.startswith(r + "/") for r in RISK_MEDIUM):   return "MEDIUM","#f0c040"
    return "LOW","#4a9"

WAF_SIGNATURES = {
    "Cloudflare":         ["cf-ray","cf-cache-status","__cfduid","cf-request-id"],
    "AWS WAF/CloudFront": ["x-amz-cf-id","x-amzn-requestid","x-amz-request-id"],
    "Akamai":             ["x-akamai-transformed","akamai-origin-hop","x-check-cacheable"],
    "Imperva/Incapsula":  ["x-iinfo","x-cdn","incap_ses","visid_incap"],
    "Sucuri":             ["x-sucuri-id","x-sucuri-cache"],
    "F5 BIG-IP":          ["bigipserver","x-cnection","f5-"],
    "Barracuda":          ["barra_counter_session"],
    "Fastly":             ["x-fastly-request-id","fastly-restarts","x-served-by"],
    "ModSecurity":        ["mod_security","modsec"],
}

def detect_waf(headers, body=""):
    detected,h_lower,body_l = [],[],body.lower()
    h_lower = {k.lower(): v.lower() for k,v in headers.items()}
    for waf,sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in h_lower or sig in body_l:
                detected.append(waf); break
    server = h_lower.get("server","")
    if "cloudflare" in server: detected.append("Cloudflare (server)")
    if "awselb" in server or "amazonaws" in server: detected.append("AWS ELB/CloudFront")
    if "sucuri" in server: detected.append("Sucuri Firewall")
    return list(dict.fromkeys(detected))

TECH_SIGNATURES = {
    "server":       {"nginx":"Nginx","apache":"Apache","microsoft-iis":"IIS","cloudflare":"Cloudflare",
                     "openresty":"OpenResty/Nginx","caddy":"Caddy","gunicorn":"Gunicorn (Python)",
                     "uvicorn":"Uvicorn (Python)","jetty":"Jetty (Java)","tomcat":"Tomcat (Java)",
                     "lighttpd":"Lighttpd","litespeed":"LiteSpeed"},
    "x-powered-by": {"php":"PHP","express":"Express (Node.js)","next.js":"Next.js",
                     "asp.net":"ASP.NET","laravel":"Laravel","django":"Django",
                     "rails":"Ruby on Rails","fastapi":"FastAPI","flask":"Flask","spring":"Spring (Java)"},
    "x-generator":  {"drupal":"Drupal","wordpress":"WordPress","joomla":"Joomla"},
    "via":          {"varnish":"Varnish Cache","squid":"Squid Proxy"},
}

def detect_tech(headers):
    tech = []
    for header,sigs in TECH_SIGNATURES.items():
        val = headers.get(header,"").lower()
        if val:
            for key,label in sigs.items():
                if key in val: tech.append(label); break
    ck = headers.get("set-cookie","").lower()
    if "laravel_session" in ck:   tech.append("Laravel (session)")
    if "phpsessid"       in ck:   tech.append("PHP session")
    if "asp.net_session" in ck:   tech.append("ASP.NET session")
    if "csrftoken"       in ck:   tech.append("Django (CSRF)")
    if "rack.session"    in ck:   tech.append("Rack/Rails")
    if "connect.sid"     in ck:   tech.append("Express/Node.js")
    if "wordpress_"      in ck:   tech.append("WordPress (cookie)")
    ct = headers.get("content-type","").lower()
    if "application/json"    in ct: tech.append("JSON API")
    if "application/xml"     in ct: tech.append("XML API")
    if "application/graphql" in ct: tech.append("GraphQL")
    return list(dict.fromkeys(tech))

def extract_versions(headers, body=""):
    versions = {}
    server = headers.get("server",""); xpb = headers.get("x-powered-by","")
    m = re.search(r'(nginx|apache)[/\s]([\d.]+)', server, re.I)
    if m: versions[m.group(1).capitalize()] = m.group(2)
    m = re.search(r'PHP/([\d.]+)', xpb, re.I)
    if m: versions["PHP"] = m.group(1)
    m = re.search(r'ASP\.NET[/\s]?([\d.]+)', xpb, re.I)
    if m and m.group(1): versions["ASP.NET"] = m.group(1)
    m = re.search(r'WordPress[/\s]([\d.]+)', body, re.I)
    if m: versions["WordPress"] = m.group(1)
    return versions

CVE_HINTS = [
    ("PHP","8.0","CVE-2021-21703/CVE-2019-11043","PHP < 8.0 — multiple RCE/path traversal vulnerabilities"),
    ("PHP","7.4","CVE-2019-11043","PHP-FPM < 7.4 — Remote Code Execution via path info"),
    ("Nginx","1.24","CVE-2023-44487","Nginx < 1.24 — HTTP/2 Rapid Reset DoS"),
    ("Apache","2.4.55","CVE-2023-25690","Apache < 2.4.55 — mod_proxy HTTP request splitting"),
    ("Apache","2.4.50","CVE-2021-41773","Apache 2.4.49/50 — Path traversal & Remote Code Execution"),
    ("WordPress","6.4","CVE-2023-5561","WordPress < 6.4 — username enumeration / stored XSS"),
]

def _ver_lt(v, threshold):
    try:
        return tuple(int(x) for x in v.split(".")[:3]) < tuple(int(x) for x in threshold.split(".")[:3])
    except: return False

def check_cves(versions):
    hits = []
    for tech,thr,cve,desc in CVE_HINTS:
        v = versions.get(tech)
        if v and _ver_lt(v,thr): hits.append((cve,desc,v))
    return hits

def detect_auth(headers, status_code):
    hints,sec_ok,sec_miss = [],[],[]
    www_auth = headers.get("www-authenticate","")
    if www_auth:
        wl = www_auth.lower()
        if "bearer" in wl: hints.append("Bearer token required")
        elif "basic" in wl: hints.append("HTTP Basic Auth")
        elif "digest" in wl: hints.append("HTTP Digest Auth")
        elif "oauth" in wl: hints.append("OAuth required")
        else: hints.append(f"Auth: {www_auth[:60]}")
    if status_code == 401 and not www_auth: hints.append("401 Unauthorized — custom auth scheme")
    if status_code == 403: hints.append("403 Forbidden — endpoint exists, access denied")
    for hdr,label in [("strict-transport-security","HSTS"),("content-security-policy","CSP"),
                      ("x-frame-options","X-Frame-Options"),("x-content-type-options","X-Content-Type-Options"),
                      ("referrer-policy","Referrer-Policy"),("permissions-policy","Permissions-Policy")]:
        (sec_ok if headers.get(hdr) else sec_miss).append(label)
    return hints, sec_ok, sec_miss

def analyze_cookies(headers):
    issues,info = [],[]
    raw = headers.get("set-cookie","")
    if not raw: return info,issues
    for ck in raw.split(","):
        ck_l = ck.lower(); name = ck.split("=")[0].strip(); flags = []
        if "httponly" in ck_l: flags.append("HttpOnly")
        else: issues.append(f"'{name}' missing HttpOnly — XSS risk")
        if "secure" in ck_l: flags.append("Secure")
        else: issues.append(f"'{name}' missing Secure — cleartext exposure")
        if "samesite" in ck_l: flags.append("SameSite")
        else: issues.append(f"'{name}' missing SameSite — CSRF risk")
        info.append(f"{name}: {', '.join(flags) if flags else 'NO security flags'}")
    return info,issues

def detect_cors(headers):
    origin  = headers.get("access-control-allow-origin","")
    methods = headers.get("access-control-allow-methods","")
    hdrs    = headers.get("access-control-allow-headers","")
    creds   = headers.get("access-control-allow-credentials","")
    info,issues = [],[]
    if origin:
        info.append(f"Allow-Origin: {origin}")
        if origin == "*": issues.append("CORS wildcard (*) — any origin can read responses")
        if origin == "*" and creds.lower() == "true":
            issues.append("CRITICAL: Wildcard + credentials=true — auth bypass possible")
        if origin not in ("*","null") and creds.lower() == "true":
            info.append("Credentialed CORS (origin-specific) — verify reflection")
    if methods:
        info.append(f"Allow-Methods: {methods}")
        if "DELETE" in methods.upper() or "PUT" in methods.upper():
            issues.append(f"Dangerous methods via CORS: {methods}")
    if hdrs:
        info.append(f"Allow-Headers: {hdrs}")
        if "authorization" in hdrs.lower(): issues.append("Authorization header exposed via CORS")
    return info,issues

def detect_rate_limit(headers, status_code):
    info = []
    rl_hdrs = ["x-ratelimit-limit","x-ratelimit-remaining","x-ratelimit-reset",
               "x-rate-limit-limit","x-rate-limit-remaining","retry-after",
               "ratelimit-limit","ratelimit-remaining","ratelimit-reset"]
    found = {k:v for k,v in headers.items() if k.lower() in rl_hdrs}
    if found:
        for k,v in found.items(): info.append(f"{k}: {v}")
    elif status_code == 429: info.append("HTTP 429 Too Many Requests — rate limiting active")
    else: info.append("No rate-limit headers detected — brute-force / enumeration risk")
    return info

def analyze_body(body_text, content_type):
    hints = []; body = body_text[:4000]
    if "application/json" in content_type or body.lstrip().startswith(("{","[")):
        try:
            parsed = json.loads(body)
            if isinstance(parsed,dict):
                hints.append(f"JSON keys: {list(parsed.keys())[:12]}")
                flat = json.dumps(parsed).lower()
                for w in ["token","password","secret","api_key","auth","jwt","bearer","hash","salt","private"]:
                    if w in flat: hints.append(f"Sensitive field: '{w}' found in response")
            elif isinstance(parsed,list):
                hints.append(f"JSON array — {len(parsed)} items")
                if parsed and isinstance(parsed[0],dict):
                    hints.append(f"Item keys: {list(parsed[0].keys())[:10]}")
        except: hints.append("JSON-like body (parse failed)")
    for pattern,label in [
        (r"(traceback|stack.?trace|exception in|at \w+\.java)","Stack trace / exception leaked"),
        (r"(syntax error|mysql error|ora-\d{5}|pg::\w+Error|sqlite3)","Database error in response"),
        (r"(password|passwd|pwd)\s*[:=]\s*\S+","Password-like value in body"),
        (r"(api.?key|apikey|secret)\s*[:=]\s*\S+","API key or secret in body"),
        (r"(internal server error)","Internal server error message"),
        (r"(debug|dev mode|development mode)","Debug / dev mode active"),
        (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}","JWT token in response body"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY","Private key exposed in response"),
        (r"(AKIA|ASIA)[A-Z0-9]{16}","AWS Access Key ID pattern"),
        (r"ghp_[a-zA-Z0-9]{36}","GitHub Personal Access Token"),
        (r"<\?php","PHP source code in response"),
    ]:
        if re.search(pattern, body, re.I): hints.append(f"[!] {label}")
    return hints

INJECTION_PROBES = [
    ("SQLi (error-based)",  "?id=1'",                  r"(sql|syntax|mysql|pg::|ora-\d|sqlite|unterminated)"),
    ("XSS reflection",      "?q=<script>xss</script>",  r"<script>xss</script>"),
    ("Path traversal",      "/../../../etc/passwd",      r"(root:|nobody:|daemon:)"),
    ("SSTI",                "?name={{7*7}}",              r"\b49\b"),
    ("Open redirect",       "?next=//evil.com",          r"(Location:\s*//evil\.com)"),
]

def probe_injections(session, base_url, path, headers):
    url  = base_url.rstrip("/") + "/" + path.lstrip("/"); hits = []
    for label,suffix,pattern in INJECTION_PROBES:
        try:
            r = session.get(url+suffix, headers=headers, timeout=5, allow_redirects=False)
            target = r.text[:2000] + " " + str(dict(r.headers))
            if re.search(pattern, target, re.I): hits.append(f"Possible {label} — pattern matched")
        except: pass
    return hits

def inspect_tls(hostname, port=443):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls_version"] = ssock.version()
                info["cipher"]      = ssock.cipher()
                info["subject"]     = dict(x[0] for x in cert.get("subject",[]))
                info["issuer"]      = dict(x[0] for x in cert.get("issuer",[]))
                info["not_before"]  = cert.get("notBefore","")
                info["not_after"]   = cert.get("notAfter","")
                info["san"]         = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
                try:
                    exp = datetime.datetime.strptime(info["not_after"],"%b %d %H:%M:%S %Y %Z")
                    info["expires_in_days"] = (exp - datetime.datetime.utcnow()).days
                except: info["expires_in_days"] = None
    except Exception as e: info["tls_error"] = str(e)
    return info

def recon_dns(hostname):
    info = {}
    try:
        ip = socket.gethostbyname(hostname); info["ip"] = ip
        try:    info["rdns"] = socket.gethostbyaddr(ip)[0]
        except: info["rdns"] = "N/A"
    except Exception as e: info["ip_error"] = str(e)
    return info

def probe_method(session, url, method, headers, timeout=7):
    try:
        body,req_hdrs = None,dict(headers)
        if method in ("POST","PUT","PATCH"):
            body = json.dumps({}); req_hdrs.setdefault("Content-Type","application/json")
        t0   = time.time()
        resp = session.request(method, url, data=body, headers=req_hdrs, timeout=timeout, allow_redirects=False)
        return {"method":method,"status":resp.status_code,"elapsed_ms":round((time.time()-t0)*1000),
                "headers":dict(resp.headers),"body":resp.text,
                "content_type":resp.headers.get("content-type",""),
                "content_len":resp.headers.get("content-length",len(resp.content)),
                "location":resp.headers.get("location",""),"error":None}
    except requests.exceptions.Timeout:
        return {"method":method,"status":None,"error":"TIMEOUT","headers":{},"body":"","content_type":"","location":"","elapsed_ms":0,"content_len":0}
    except requests.exceptions.ConnectionError:
        return {"method":method,"status":None,"error":"CONNECTION_FAILED","headers":{},"body":"","content_type":"","location":"","elapsed_ms":0,"content_len":0}
    except requests.exceptions.RequestException as e:
        return {"method":method,"status":None,"error":str(e)[:80],"headers":{},"body":"","content_type":"","location":"","elapsed_ms":0,"content_len":0}

def fingerprint_endpoint(base_url, path, session, extra_headers, methods, run_inject=False):
    url  = base_url.rstrip("/") + "/" + path.lstrip("/")
    risk,risk_color = get_risk(path)
    results     = {m: probe_method(session, url, m, extra_headers) for m in methods}
    interesting = {m: r for m,r in results.items() if r["status"] is not None and r["status"] != 404}
    if not interesting: return None
    sample = next((r for r in interesting.values() if r["status"]), None) or next(iter(results.values()))
    tech                     = detect_tech(sample["headers"])
    auth_hints,sec_ok,sec_miss = detect_auth(sample["headers"], sample.get("status",0))
    cors_info,cors_issues    = detect_cors(sample["headers"])
    body_hints               = analyze_body(sample["body"], sample["content_type"])
    rl_info                  = detect_rate_limit(sample["headers"], sample.get("status",0))
    waf                      = detect_waf(sample["headers"], sample.get("body","")[:1000])
    ck_info,ck_issues        = analyze_cookies(sample["headers"])
    inject_hits              = probe_injections(session, base_url, path, extra_headers) if run_inject else []
    working                  = [m for m,r in interesting.items() if r["status"] not in (405,501)]
    no_method                = [m for m,r in interesting.items() if r["status"] in (405,501)]
    versions                 = extract_versions(sample["headers"], sample.get("body",""))
    cves                     = check_cves(versions)
    fp = {"url":url,"path":path,"risk":risk,"risk_color":risk_color,
          "methods":results,"working":working,"no_method":no_method,
          "tech":tech,"auth_hints":auth_hints,"sec_ok":sec_ok,"sec_miss":sec_miss,
          "cors_info":cors_info,"cors_issues":cors_issues,"body_hints":body_hints,
          "rl_info":rl_info,"waf":waf,"ck_info":ck_info,"ck_issues":ck_issues,
          "inject_hits":inject_hits,"versions":versions,"cves":cves,
          "server":sample["headers"].get("server",""),
          "x_powered_by":sample["headers"].get("x-powered-by",""),
          "interesting":interesting,"sample_headers":sample["headers"],"sample_body":sample.get("body","")}
    with found_lock:
        fingerprints[path] = fp
    return fp

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
    "members","member","admin/users","api/v1/users","api/v2/users","api/v1/accounts","api/v2/accounts",
    "admin","admin/login","admin/dashboard","admin/panel","admin/api",
    "administrator","administrator/login","manager","management",
    "dashboard","control-panel","controlpanel","panel",
    "backend","back-end","backoffice","back-office",
    "cms","cms/admin","cms/api","console","console/login","superadmin","super-admin","root",
    "graphql","graphiql","graphql/console","playground","graphql-playground",
    "api/graphql","v1/graphql","query",
    "swagger","swagger-ui","swagger-ui.html","swagger/index.html","swagger/ui",
    "swagger/v1","swagger/v2","api-docs","api-docs/v1","api-docs/v2",
    "openapi","openapi.json","openapi.yaml","openapi.yml","api/swagger","docs/api","redoc","api/redoc","apidocs",
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
    "posts","post","articles","article","blog","news","settings","setting",
    "logs","log","audit","audit-log","activity","history",
    "debug","debug/info","debug/vars","trace",
    "phpinfo.php","test.php","info.php",
    ".env",".env.local",".env.production",".env.development",".env.staging",
    "config.json","config.yaml","config.yml","app.json","manifest.json",
    "robots.txt","sitemap.xml","crossdomain.xml",
    ".git",".git/config",".git/HEAD",".gitignore",".htaccess",".htpasswd",
    "web.config","WEB-INF/web.xml","composer.json","package.json","Dockerfile",
    "backup.sql","dump.sql","database.sql","db.sqlite","db.sqlite3",
    "telescope","horizon","nova","wp-login.php","wp-admin","xmlrpc.php",
    "wp-json","wp-json/wp/v2","wp-json/wp/v2/users",
    "internal","internal/api","private","private/api",
    "reports","report","analytics","statistics","stats",
    "export","import","sync","cache","flush",
]

# ═══════════════════════════════════════════════════════════
#  PyQt5 GUI
# ═══════════════════════════════════════════════════════════
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QCheckBox,
    QComboBox, QSpinBox, QProgressBar, QFrame, QScrollArea,
    QFileDialog, QMessageBox, QToolBar, QSizePolicy, QAbstractItemView,
    QDialog, QDialogButtonBox, QTextBrowser, QAction, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, pyqtSlot, QPoint
from PyQt5.QtGui import (
    QColor, QFont, QTextCursor, QPalette, QPainter,
    QLinearGradient, QBrush, QPen, QPixmap, QIcon
)

# ── Colour palette ──────────────────────────────────────────
C = {
    "bg0":      "#07090d",   # deepest background
    "bg1":      "#0b0f15",   # panel background
    "bg2":      "#10161f",   # card / row
    "bg3":      "#151d28",   # input / slightly lighter
    "line":     "#1a2d42",   # borders
    "line2":    "#0d1e2d",   # subtle separators
    "cyan":     "#00d4ff",   # primary accent
    "green":    "#00e87a",   # success / ok
    "red":      "#ff2d55",   # critical
    "orange":   "#ff8c00",   # high / warning
    "yellow":   "#f0c040",   # medium
    "purple":   "#b06aff",   # special
    "blue":     "#2d8cff",   # info
    "t0":       "#ddeeff",   # text primary
    "t1":       "#7a9bbf",   # text secondary
    "t2":       "#3a5a78",   # text muted
    "t3":       "#1e3348",   # very muted
}

# status code colours
def status_color(code):
    if code is None:          return C["t2"]
    if code in (200,201,204): return C["green"]
    if code in (301,302,307,308): return C["cyan"]
    if code in (401,403):     return C["orange"]
    if code == 405:           return C["purple"]
    if code == 429:           return C["yellow"]
    if code >= 500:           return C["red"]
    return C["t1"]

def risk_color(risk):
    return {"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],"LOW":C["green"]}.get(risk,C["t1"])

def risk_bg(risk):
    return {"CRITICAL":"#1a0008","HIGH":"#160800","MEDIUM":"#14100000","LOW":"#001a08"}.get(risk,"transparent")

# ── Global stylesheet ───────────────────────────────────────
QSS = f"""
* {{
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: {C['t0']};
    background: transparent;
}}
QMainWindow, QDialog {{
    background-color: {C['bg0']};
}}
QWidget#root_widget {{
    background-color: {C['bg0']};
}}

/* ── Scrollbars ── */
QScrollBar:vertical {{
    background: {C['bg0']};
    width: 7px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {C['line']};
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {C['cyan']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C['bg0']};
    height: 7px;
}}
QScrollBar::handle:horizontal {{
    background: {C['line']};
    border-radius: 3px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {C['cyan']};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Menu ── */
QMenuBar {{
    background-color: {C['bg1']};
    border-bottom: 1px solid {C['line']};
    padding: 2px 4px;
}}
QMenuBar::item {{ padding: 4px 10px; border-radius: 3px; }}
QMenuBar::item:selected {{ background: {C['bg2']}; color: {C['cyan']}; }}
QMenu {{
    background: {C['bg1']};
    border: 1px solid {C['line']};
    padding: 4px;
}}
QMenu::item {{ padding: 5px 24px 5px 12px; border-radius: 3px; }}
QMenu::item:selected {{ background: {C['bg2']}; color: {C['cyan']}; }}
QMenu::separator {{ height: 1px; background: {C['line']}; margin: 4px 8px; }}

/* ── Status bar ── */
QStatusBar {{
    background: {C['bg1']};
    border-top: 1px solid {C['line']};
    color: {C['t1']};
    font-size: 11px;
}}
QStatusBar::item {{ border: none; }}

/* ── Tabs ── */
QTabWidget::pane {{
    border: 1px solid {C['line']};
    background: {C['bg1']};
    border-radius: 0 4px 4px 4px;
}}
QTabBar {{
    background: transparent;
}}
QTabBar::tab {{
    background: {C['bg0']};
    color: {C['t2']};
    padding: 8px 22px;
    border: 1px solid {C['line']};
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    margin-right: 2px;
    font-size: 11px;
    letter-spacing: 1px;
}}
QTabBar::tab:selected {{
    background: {C['bg1']};
    color: {C['cyan']};
    border-color: {C['cyan']};
    border-bottom: 1px solid {C['bg1']};
}}
QTabBar::tab:hover:!selected {{
    color: {C['t0']};
    background: {C['bg2']};
}}

/* ── Group box ── */
QGroupBox {{
    background: {C['bg2']};
    border: 1px solid {C['line']};
    border-radius: 6px;
    margin-top: 18px;
    padding: 10px 10px 10px 10px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    top: -1px;
    padding: 2px 8px;
    background: {C['bg2']};
    color: {C['cyan']};
    font-size: 10px;
    letter-spacing: 2px;
    border-radius: 3px;
    border: 1px solid {C['line']};
}}

/* ── Line edit ── */
QLineEdit {{
    background: {C['bg3']};
    border: 1px solid {C['line']};
    border-radius: 5px;
    padding: 7px 10px;
    color: {C['t0']};
    font-size: 12px;
    selection-background-color: {C['cyan']};
    selection-color: {C['bg0']};
}}
QLineEdit:focus {{
    border-color: {C['cyan']};
    background: #0e1e2f;
}}
QLineEdit:disabled {{
    color: {C['t2']};
    background: {C['bg1']};
}}
QLineEdit::placeholder {{
    color: {C['t2']};
}}

/* ── Text areas ── */
QTextEdit, QTextBrowser {{
    background: {C['bg0']};
    border: 1px solid {C['line']};
    border-radius: 5px;
    color: {C['green']};
    font-size: 12px;
    padding: 6px;
    selection-background-color: #0e2d40;
}}

/* ── Buttons ── */
QPushButton {{
    background: {C['bg2']};
    border: 1px solid {C['line']};
    border-radius: 5px;
    color: {C['t0']};
    padding: 7px 16px;
    font-size: 11px;
    letter-spacing: 1px;
}}
QPushButton:hover {{
    background: #1a2d42;
    border-color: {C['cyan']};
    color: {C['cyan']};
}}
QPushButton:pressed {{
    background: #0a1e30;
}}
QPushButton:disabled {{
    color: {C['t2']};
    border-color: {C['t3']};
    background: {C['bg1']};
}}
QPushButton#btn_start {{
    background: #003d22;
    border: 1px solid {C['green']};
    color: {C['green']};
    font-size: 13px;
    font-weight: bold;
    padding: 11px 0;
    border-radius: 6px;
    letter-spacing: 2px;
}}
QPushButton#btn_start:hover {{ background: #005530; }}
QPushButton#btn_start:pressed {{ background: #002516; }}
QPushButton#btn_stop {{
    background: #3a000e;
    border: 1px solid {C['red']};
    color: {C['red']};
    font-size: 12px;
    font-weight: bold;
    padding: 9px 0;
    border-radius: 6px;
    letter-spacing: 2px;
}}
QPushButton#btn_stop:hover {{ background: #520010; }}
QPushButton#btn_action {{
    background: #001c2e;
    border: 1px solid {C['cyan']};
    color: {C['cyan']};
    padding: 6px 14px;
    font-size: 11px;
    border-radius: 5px;
}}
QPushButton#btn_action:hover {{ background: #002a45; }}

/* ── Combo box ── */
QComboBox {{
    background: {C['bg3']};
    border: 1px solid {C['line']};
    border-radius: 5px;
    padding: 6px 10px;
    color: {C['t0']};
    font-size: 12px;
}}
QComboBox:focus {{ border-color: {C['cyan']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 7px solid {C['t1']};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background: {C['bg1']};
    border: 1px solid {C['line']};
    selection-background-color: {C['bg2']};
    selection-color: {C['cyan']};
    outline: none;
}}

/* ── Spin box ── */
QSpinBox {{
    background: {C['bg3']};
    border: 1px solid {C['line']};
    border-radius: 5px;
    padding: 6px 8px;
    color: {C['t0']};
}}
QSpinBox:focus {{ border-color: {C['cyan']}; }}
QSpinBox::up-button, QSpinBox::down-button {{
    background: {C['bg2']};
    border: none;
    width: 18px;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background: {C['line']};
}}

/* ── Checkbox ── */
QCheckBox {{
    color: {C['t0']};
    spacing: 8px;
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {C['line']};
    border-radius: 3px;
    background: {C['bg3']};
}}
QCheckBox::indicator:checked {{
    background: {C['cyan']};
    border-color: {C['cyan']};
}}
QCheckBox::indicator:indeterminate {{
    background: {C['t2']};
}}

/* ── Progress bar ── */
QProgressBar {{
    background: {C['bg0']};
    border: 1px solid {C['line']};
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C['cyan']}, stop:1 {C['green']});
    border-radius: 4px;
}}

/* ── Table ── */
QTableWidget {{
    background: {C['bg0']};
    border: 1px solid {C['line']};
    border-radius: 5px;
    gridline-color: {C['line2']};
    selection-background-color: #0d2236;
    selection-color: {C['cyan']};
    alternate-background-color: {C['bg2']};
    font-size: 12px;
    outline: none;
}}
QTableWidget::item {{
    padding: 7px 10px;
    border-bottom: 1px solid {C['line2']};
}}
QTableWidget::item:selected {{
    background: #0d2236;
    color: {C['t0']};
}}
QHeaderView::section {{
    background: {C['bg1']};
    color: {C['cyan']};
    border: none;
    border-right: 1px solid {C['line2']};
    border-bottom: 2px solid {C['line']};
    padding: 8px 10px;
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: bold;
}}
QHeaderView::section:last {{ border-right: none; }}
QHeaderView::section:checked {{ background: {C['bg2']}; }}

/* ── Splitter ── */
QSplitter::handle {{
    background: {C['line']};
}}
QSplitter::handle:hover {{
    background: {C['cyan']};
}}

/* ── Frame ── */
QFrame[frameShape="4"] {{ color: {C['line']}; }}
QFrame[frameShape="5"] {{ color: {C['line']}; }}

/* ── Label ── */
QLabel {{ background: transparent; }}
"""


# ═══════════════════════════════════════════════════════════
#  WORKER THREAD
# ═══════════════════════════════════════════════════════════
class ScanWorker(QThread):
    log_signal      = pyqtSignal(str, str)
    result_signal   = pyqtSignal(dict)
    recon_signal    = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int)
    done_signal     = pyqtSignal(float)

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
        fingerprints = {}; server_profile = {}
        cfg   = self.config; start = time.time()
        if not REQUESTS_OK:
            self.emit_log("ERROR: 'requests' library not installed  →  pip install requests", "error")
            self.done_signal.emit(0); return
        session = requests.Session()
        session.headers.update({"User-Agent":"Mozilla/5.0 (compatible; SiteCrawler/4.0)",
                                 "Accept":"application/json, text/html, */*"})
        custom_headers = {}
        for h in cfg.get("headers",[]):
            if ":" in h:
                k,v = h.split(":",1); custom_headers[k.strip()] = v.strip()
        if cfg.get("token"):
            custom_headers["Authorization"] = f"Bearer {cfg['token']}"
        base_url = cfg["url"]; methods = cfg["methods"]
        threads  = cfg["threads"]; inject  = cfg["inject"]
        mode     = cfg["mode"]

        if cfg.get("recon", True):
            self.emit_log("Starting server reconnaissance…", "info")
            profile = self._do_recon(base_url, session, custom_headers)
            server_profile.update(profile)
            self.recon_signal.emit(profile)

        if not self._running:
            self.done_signal.emit(time.time()-start); return

        paths = []
        if mode in ("1","4","5"):
            wl = cfg.get("wordlist","")
            if wl:
                try:
                    with open(wl, encoding="utf-8") as f:
                        paths += [l.strip() for l in f if l.strip() and not l.startswith("#")]
                except Exception as e:
                    self.emit_log(f"Wordlist error: {e}", "warn")
        if mode in ("3","4","5","6"):
            paths += API_PATHS
        if mode in ("2","4","5"):
            paths += self._crawl_paths(base_url, session, custom_headers)
        paths = list(dict.fromkeys(paths))
        if mode == "6" and cfg.get("probe_path"):
            paths = [cfg["probe_path"]]
        total = len(paths)
        self.emit_log(f"Scanning {total} paths × {len(methods)} methods  [{threads} threads]", "info")
        done  = 0
        all_m = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"] if mode == "6" else methods
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(fingerprint_endpoint, base_url, p, session,
                                 custom_headers, all_m, inject): p for p in paths}
            for future in as_completed(futures):
                if not self._running: break
                done += 1; self.progress_signal.emit(done, total)
                fp = future.result()
                if fp:
                    self.result_signal.emit(fp)
                    level = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium"}.get(fp["risk"],"ok")
                    codes = {m:r["status"] for m,r in fp["interesting"].items()}
                    code_str = "  ".join(f"{m}={s}" for m,s in codes.items())
                    self.emit_log(f"[{fp['risk']:<8}]  {fp['path']:<45}  {code_str}", level)
        self.done_signal.emit(time.time()-start)

    def _do_recon(self, base_url, session, headers):
        parsed = urlparse(base_url)
        host = parsed.hostname; port = parsed.port or (443 if parsed.scheme=="https" else 80)
        profile = {"host":host,"port":port,"scheme":parsed.scheme,
                   "dns":{},"tls":{},"headers":{},"tech":[],"waf":[],
                   "versions":{},"cves":[],"cookies":{"info":[],"issues":[]},"timing":{}}
        profile["dns"] = recon_dns(host)
        if parsed.scheme == "https":
            profile["tls"] = inspect_tls(host, port)
        try:
            t0   = time.time()
            resp = session.get(base_url, headers=headers, timeout=10, allow_redirects=True)
            profile["timing"]   = {"base_ms":round((time.time()-t0)*1000),
                                   "redirects":len(resp.history),"final_url":resp.url}
            profile["status"]   = resp.status_code
            profile["headers"]  = dict(resp.headers)
            profile["tech"]     = detect_tech(dict(resp.headers))
            profile["waf"]      = detect_waf(dict(resp.headers), resp.text[:2000])
            profile["versions"] = extract_versions(dict(resp.headers), resp.text[:5000])
            profile["cves"]     = check_cves(profile["versions"])
            ci,cx               = analyze_cookies(dict(resp.headers))
            profile["cookies"]  = {"info":ci,"issues":cx}
        except Exception as e:
            profile["error"] = str(e)
        return profile

    def _crawl_paths(self, base_url, session, headers):
        paths = []
        try:
            resp     = session.get(base_url, timeout=8, headers=headers)
            links    = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
            assets   = re.findall(r'src=["\']([^"\']+)["\']', resp.text)
            api_refs = re.findall(r'["\'`](/(?:api|v\d|rest|graphql)[^"\'`\s]{1,80})', resp.text)
            base_netloc = urlparse(base_url).netloc
            for link in links+assets+api_refs:
                if link.startswith("http"):
                    p = urlparse(link)
                    if p.netloc != base_netloc: continue
                    paths.append(p.path.lstrip("/"))
                elif link.startswith("/"):
                    paths.append(link.lstrip("/"))
            self.emit_log(f"Crawl extracted {len(paths)} paths from page", "info")
        except Exception as e:
            self.emit_log(f"Crawl error: {e}", "warn")
        return paths


# ═══════════════════════════════════════════════════════════
#  CUSTOM WIDGETS
# ═══════════════════════════════════════════════════════════

class TopBar(QWidget):
    """Animated top banner with scanner name and live clock"""
    def __init__(self):
        super().__init__()
        self.setFixedHeight(72)
        self._tick = 0
        t = QTimer(self); t.timeout.connect(self._animate); t.start(50)

    def _animate(self):
        self._tick += 1; self.update()

    def paintEvent(self, ev):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        # Background gradient
        grad = QLinearGradient(0, 0, self.width(), 0)
        grad.setColorAt(0,   QColor("#050810"))
        grad.setColorAt(0.4, QColor("#071525"))
        grad.setColorAt(1,   QColor("#050810"))
        p.fillRect(self.rect(), QBrush(grad))
        # Subtle grid
        p.setPen(QPen(QColor("#0a1e30"), 1))
        for x in range(0, self.width(), 48):
            p.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 24):
            p.drawLine(0, y, self.width(), y)
        # Bottom border glow
        pen = QPen(QColor(C["cyan"])); pen.setWidth(1)
        p.setPen(pen); p.drawLine(0, self.height()-1, self.width(), self.height()-1)
        # Left accent bar
        p.fillRect(0, 0, 3, self.height(), QColor(C["cyan"]))
        # Title "SITE"
        f1 = QFont("Consolas", 22, QFont.Bold); p.setFont(f1)
        p.setPen(QColor(C["cyan"])); p.drawText(16, 48, "SITE")
        # "CRAWLER"
        p.setPen(QColor(C["green"])); p.drawText(88, 48, "CRAWLER")
        # Separator
        p.setPen(QPen(QColor(C["line"]), 1))
        p.drawLine(235, 20, 235, 52)
        # Subtitle
        f2 = QFont("Consolas", 9); p.setFont(f2)
        p.setPen(QColor(C["t2"]))
        p.drawText(244, 34, "v4.0 — Analyst-Grade Endpoint Fingerprinting")
        p.drawText(244, 50, "CoderSigma")
        # Right clock
        now = datetime.datetime.now()
        f3  = QFont("Consolas", 11, QFont.Bold); p.setFont(f3)
        p.setPen(QColor(C["t1"]))
        ts  = now.strftime("%H:%M:%S")
        p.drawText(self.width()-130, 38, ts)
        f4  = QFont("Consolas", 9); p.setFont(f4)
        p.setPen(QColor(C["t2"]))
        p.drawText(self.width()-130, 54, now.strftime("%Y-%m-%d"))
        # Pulse dot
        import math
        alpha = int(120 + 100*abs(math.sin(self._tick*0.08)))
        p.setBrush(QBrush(QColor(0, 232, 122, alpha)))
        p.setPen(Qt.NoPen)
        p.drawEllipse(self.width()-154, 27, 8, 8)


class SectionLabel(QLabel):
    """Styled section header with left bar accent"""
    def __init__(self, text):
        super().__init__(text.upper())
        self.setFixedHeight(28)
        self.setStyleSheet(f"""
            QLabel {{
                color: {C['cyan']};
                font-size: 10px;
                letter-spacing: 3px;
                font-weight: bold;
                padding-left: 10px;
                border-left: 3px solid {C['cyan']};
                background: {C['bg1']};
            }}
        """)


class StatCard(QFrame):
    """Metric display card"""
    def __init__(self, title, value="0", accent=None, icon=""):
        super().__init__()
        self.accent = accent or C["cyan"]
        self.setStyleSheet(f"""
            QFrame {{
                background: {C['bg2']};
                border: 1px solid {C['line']};
                border-top: 2px solid {self.accent};
                border-radius: 6px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        top = QHBoxLayout()
        lbl_icon = QLabel(icon)
        lbl_icon.setStyleSheet(f"font-size: 16px; color: {self.accent}; border: none; background: transparent;")
        top.addWidget(lbl_icon)
        top.addStretch()
        self.val = QLabel(value)
        self.val.setStyleSheet(f"""
            QLabel {{
                font-size: 26px;
                font-weight: bold;
                color: {self.accent};
                border: none;
                background: transparent;
            }}
        """)
        self.val.setAlignment(Qt.AlignCenter)
        lbl_title = QLabel(title.upper())
        lbl_title.setStyleSheet(f"font-size: 9px; color: {C['t2']}; letter-spacing: 2px; border: none; background: transparent;")
        lbl_title.setAlignment(Qt.AlignCenter)
        lay.addLayout(top)
        lay.addWidget(self.val)
        lay.addWidget(lbl_title)

    def set_value(self, v):
        self.val.setText(str(v))


class LogTerminal(QTextEdit):
    """Styled terminal output widget"""
    LEVEL_COLORS = {
        "info":     C["t0"],
        "ok":       C["green"],
        "warn":     C["orange"],
        "error":    C["red"],
        "critical": C["red"],
        "high":     C["orange"],
        "medium":   C["yellow"],
        "debug":    C["t2"],
    }

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 12))
        self.document().setMaximumBlockCount(5000)

    def log(self, msg, level="info"):
        color = self.LEVEL_COLORS.get(level, C["t0"])
        ts    = datetime.datetime.now().strftime("%H:%M:%S")
        # Level badge
        badge_map = {
            "info": f"<span style='color:{C['t2']}'>INFO </span>",
            "ok":   f"<span style='color:{C['green']}'>  OK  </span>",
            "warn": f"<span style='color:{C['orange']}'>WARN </span>",
            "error":f"<span style='color:{C['red']}'>ERR  </span>",
            "critical":f"<span style='color:{C['red']}'>CRIT </span>",
            "high": f"<span style='color:{C['orange']}'>HIGH </span>",
            "medium":f"<span style='color:{C['yellow']}'>MED  </span>",
            "debug":f"<span style='color:{C['t2']}'>DBG  </span>",
        }
        badge = badge_map.get(level, f"<span style='color:{C['t2']}'>.... </span>")
        # Escape HTML
        safe_msg = msg.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        html = (f'<span style="color:{C["t3"]}">[{ts}]</span> '
                f'{badge} '
                f'<span style="color:{color}">{safe_msg}</span><br>')
        cur = self.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertHtml(html)
        self.setTextCursor(cur)
        self.ensureCursorVisible()


class ResultsTable(QTableWidget):
    """Enhanced results table with colour-coded rows"""
    COLS = ["Risk","Status","Method","Path","Tech","WAF","Auth","CORS","Body Alert","Inject","Rate Limit"]

    def __init__(self):
        super().__init__(0, len(self.COLS))
        self.setHorizontalHeaderLabels(self.COLS)
        hh = self.horizontalHeader()
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        for i in [0,1,2,4,5,6,7,8,9,10]:
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
        row = self.rowCount(); self.insertRow(row)
        risk    = fp["risk"]
        rc      = risk_color(risk)
        rb      = risk_bg(risk)
        working = fp.get("working",[])
        interesting = fp.get("interesting",{})
        # Pick first interesting method/status
        first_m = next(iter(interesting), "")
        first_s = interesting[first_m]["status"] if first_m else None
        sc      = status_color(first_s)
        cors_n  = len(fp.get("cors_issues",[]))
        body_n  = sum(1 for b in fp.get("body_hints",[]) if "[!]" in b)
        inj_n   = len(fp.get("inject_hits",[]))
        rl      = fp.get("rl_info",[""])[0]
        rl_color = C["orange"] if "No rate-limit" in rl else C["green"]

        cells = [
            (risk,                                  rc,         rb),
            (str(first_s) if first_s else "-",      sc,         rb),
            (", ".join(working) or "-",             C["green"], rb),
            (fp["path"],                            C["t0"],    rb),
            (", ".join(fp.get("tech",[])) or "-",  C["cyan"],  rb),
            (", ".join(fp.get("waf",[])) or "-",   C["purple"],rb),
            ("; ".join(fp.get("auth_hints",[])) or "-", C["orange"], rb),
            (str(cors_n) if cors_n else "-",        C["red"] if cors_n else C["t2"], rb),
            (str(body_n) if body_n else "-",        C["red"] if body_n else C["t2"], rb),
            (str(inj_n)  if inj_n  else "-",        C["red"] if inj_n  else C["t2"], rb),
            (rl[:28] if rl else "-",                rl_color,   rb),
        ]
        for col,(text,fg,bg) in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(fg))
            if bg and bg != "transparent":
                item.setBackground(QColor(bg))
            if col == 0:
                f = QFont("Consolas", 11, QFont.Bold); item.setFont(f)
            self.setItem(row, col, item)
        self.setSortingEnabled(True)


# ─── HTML report helpers ─────────────────────────────────────
def _html_head(title=""):
    t1,t2,line,bg0,bg1,bg2 = C["t1"],C["t2"],C["line"],C["bg0"],C["bg1"],C["bg2"]
    cyan,green,red,orange,yellow = C["cyan"],C["green"],C["red"],C["orange"],C["yellow"]
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<style>
*    {{margin:0;padding:0;box-sizing:border-box;}}
body {{background:{bg0};color:{C['t0']};font-family:'Consolas','Courier New',monospace;
      font-size:12px;padding:20px;line-height:1.6;}}
h1   {{color:{cyan};font-size:16px;letter-spacing:3px;border-bottom:2px solid {line};
      padding-bottom:10px;margin-bottom:18px;}}
h2   {{color:{cyan};font-size:13px;letter-spacing:2px;margin:22px 0 10px;
      border-left:3px solid {cyan};padding-left:10px;}}
h3   {{color:{t1};font-size:11px;letter-spacing:2px;margin:14px 0 6px;text-transform:uppercase;}}
p    {{color:{C['t0']};margin:4px 0;}}
.kv  {{display:flex;margin:4px 0;align-items:baseline;}}
.key {{color:{t2};min-width:200px;font-size:11px;flex-shrink:0;}}
.val {{color:{C['t0']};word-break:break-all;}}
.ok  {{color:{green};}}  .warn{{color:{orange};}} .crit{{color:{red};font-weight:bold;}}
.med {{color:{yellow};}} .cyan{{color:{cyan};}}   .dim{{color:{t2};}}  .purple{{color:{C['purple']};}}
.badge {{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;
        font-weight:bold;letter-spacing:1px;margin:2px;}}
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
th    {{background:{bg1};color:{cyan};padding:8px 12px;text-align:left;
       font-size:10px;letter-spacing:2px;border-bottom:2px solid {line};}}
td    {{padding:7px 12px;border-bottom:1px solid {C['line2']};vertical-align:top;}}
tr:hover td {{background:{bg2};}}
pre   {{background:{bg1};border:1px solid {line};border-radius:4px;
       padding:12px;white-space:pre-wrap;word-wrap:break-word;
       color:{green};font-size:11px;margin:6px 0;max-height:300px;overflow-y:auto;}}
.sep  {{height:1px;background:{line};margin:16px 0;}}
.grid-2 {{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0;}}
.stat-block {{background:{bg2};border:1px solid {line};border-radius:6px;padding:14px;text-align:center;}}
.stat-num   {{font-size:28px;font-weight:bold;}}
.stat-lbl   {{font-size:9px;color:{t2};letter-spacing:2px;margin-top:2px;}}
</style></head><body>"""

def _html_close():
    return "</body></html>"


class ReconView(QTextBrowser):
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, p):
        if not p: return
        dns = p.get("dns",{}); tls = p.get("tls",{}); timing = p.get("timing",{})
        hdrs = p.get("headers",{}); tech = p.get("tech",[]); waf = p.get("waf",[])
        versions = p.get("versions",{}); cves = p.get("cves",[])
        ck_info = p.get("cookies",{}).get("info",[]); ck_issues = p.get("cookies",{}).get("issues",[])

        html = _html_head("Recon")
        html += "<h1>⚡ SERVER RECONNAISSANCE REPORT</h1>"

        # Network
        html += "<h2>Network &amp; DNS</h2><div class='card'>"
        html += f"<div class='kv'><span class='key'>Host</span><span class='val cyan'>{p.get('host','?')}:{p.get('port','?')}</span></div>"
        if "ip"       in dns: html += f"<div class='kv'><span class='key'>IP Address</span><span class='val ok'>{dns['ip']}</span></div>"
        if "rdns"     in dns: html += f"<div class='kv'><span class='key'>Reverse DNS</span><span class='val'>{dns['rdns']}</span></div>"
        if "ip_error" in dns: html += f"<div class='kv'><span class='key'>DNS Error</span><span class='val warn'>{dns['ip_error']}</span></div>"
        html += f"<div class='kv'><span class='key'>Scheme</span><span class='val'>{p.get('scheme','?').upper()}</span></div>"
        if timing:
            html += f"<div class='kv'><span class='key'>Base RTT</span><span class='val'>{timing.get('base_ms','?')} ms</span></div>"
            if timing.get("redirects"):
                html += f"<div class='kv'><span class='key'>Redirects</span><span class='val'>{timing['redirects']} &rarr; {timing.get('final_url','')}</span></div>"
        html += "</div>"

        # TLS
        if tls and "tls_error" not in tls:
            exp_days = tls.get("expires_in_days")
            exp_cls  = "crit" if exp_days and exp_days < 14 else ("warn" if exp_days and exp_days < 30 else "ok")
            cipher   = tls.get("cipher",())
            html += "<h2>TLS / SSL Certificate</h2><div class='card'>"
            html += f"<div class='kv'><span class='key'>Protocol</span><span class='val cyan'>{tls.get('tls_version','?')}</span></div>"
            if cipher:
                html += f"<div class='kv'><span class='key'>Cipher Suite</span><span class='val'>{cipher[0]} ({cipher[2]} bits)</span></div>"
            subj   = tls.get("subject",{}); issuer = tls.get("issuer",{})
            html += f"<div class='kv'><span class='key'>Subject (CN)</span><span class='val'>{subj.get('commonName','?')}</span></div>"
            html += f"<div class='kv'><span class='key'>Issuer (Org)</span><span class='val dim'>{issuer.get('organizationName','?')}</span></div>"
            html += f"<div class='kv'><span class='key'>Valid From</span><span class='val dim'>{tls.get('not_before','?')}</span></div>"
            if exp_days is not None:
                html += f"<div class='kv'><span class='key'>Valid Until</span><span class='val {exp_cls}'>{tls.get('not_after','?')}  ({exp_days} days remaining)</span></div>"
            san = tls.get("san",[])
            if san:
                html += f"<div class='kv'><span class='key'>SANs ({len(san)})</span><span class='val dim'>{', '.join(san[:8])}{'…' if len(san)>8 else ''}</span></div>"
            proto = tls.get("tls_version","")
            if proto in ("TLSv1","TLSv1.1","SSLv3"):
                html += f"<p class='crit'>⚠ Weak TLS version {proto} — upgrade to TLS 1.2 / 1.3</p>"
            else:
                html += f"<p class='ok'>✔ TLS version acceptable ({proto})</p>"
            html += "</div>"
        elif tls.get("tls_error"):
            html += f"<h2>TLS</h2><div class='card'><p class='warn'>Error: {tls['tls_error']}</p></div>"

        # Server Identity
        server = hdrs.get("server","") or hdrs.get("Server","")
        xpb    = hdrs.get("x-powered-by","") or hdrs.get("X-Powered-By","")
        xgen   = hdrs.get("x-generator","") or hdrs.get("X-Generator","")
        via    = hdrs.get("via","")
        html += "<h2>Server Identity &amp; Tech Stack</h2><div class='card'>"
        if server: html += f"<div class='kv'><span class='key'>Server</span><span class='val cyan'>{server}</span></div>"
        if xpb:    html += f"<div class='kv'><span class='key'>X-Powered-By</span><span class='val cyan'>{xpb}</span></div>"
        if xgen:   html += f"<div class='kv'><span class='key'>X-Generator</span><span class='val cyan'>{xgen}</span></div>"
        if via:    html += f"<div class='kv'><span class='key'>Via</span><span class='val dim'>{via}</span></div>"
        if tech:
            tags = "".join(f"<span class='badge badge-cyan'>{t}</span>" for t in tech)
            html += f"<div class='kv'><span class='key'>Detected Tech</span><span class='val'>{tags}</span></div>"
        html += "</div>"

        # Versions
        if versions:
            html += "<h2>Software Versions</h2><div class='card'>"
            for t,v in versions.items():
                html += f"<div class='kv'><span class='key'>{t}</span><span class='val warn'>{v}</span></div>"
            html += "</div>"

        # WAF
        html += "<h2>WAF / CDN Detection</h2><div class='card'>"
        if waf:
            for w in waf: html += f"<p class='ok'>✔ {w}</p>"
        else:
            html += f"<p class='warn'>⚠ No WAF/CDN signatures detected — target may be unprotected</p>"
        html += "</div>"

        # CVEs
        if cves:
            html += "<h2>CVE / Known Vulnerability Hints</h2>"
            for cve,desc,ver in cves:
                html += f"<div class='card card-crit'>"
                html += f"<p class='crit'>⚡ {cve}</p>"
                html += f"<p class='dim' style='margin-top:4px'>{desc}</p>"
                html += f"<p class='dim'>Detected version: <span class='warn'>{ver}</span></p>"
                html += "</div>"

        # Cookie security
        if ck_info or ck_issues:
            html += "<h2>Cookie Security</h2><div class='card'>"
            for ci in ck_info[:6]: html += f"<p class='dim'>{ci}</p>"
            for cx in ck_issues:   html += f"<p class='warn'>⚠ {cx}</p>"
            html += "</div>"

        # Security headers
        html += "<h2>Security Response Headers</h2><div class='card'>"
        for hdr,label in [("strict-transport-security","HSTS"),("content-security-policy","CSP"),
                          ("x-frame-options","X-Frame-Options"),("x-content-type-options","X-Content-Type-Options"),
                          ("referrer-policy","Referrer-Policy"),("permissions-policy","Permissions-Policy")]:
            val = hdrs.get(hdr,"") or hdrs.get(hdr.title(),"")
            if val:
                html += f"<div class='kv'><span class='key ok'>✔ {label}</span><span class='val dim'>{val[:100]}</span></div>"
            else:
                html += f"<div class='kv'><span class='key warn'>✖ {label}</span><span class='val warn'>MISSING</span></div>"
        html += "</div>"

        # All headers table
        html += "<h2>All Response Headers</h2>"
        html += "<table><tr><th>Header</th><th>Value</th></tr>"
        for k,v in hdrs.items():
            html += f"<tr><td class='dim'>{k}</td><td>{v}</td></tr>"
        html += "</table>"

        html += _html_close()
        self.setHtml(html)


class DetailView(QTextBrowser):
    """Full endpoint detail panel"""
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, fp):
        if not fp: return
        risk = fp["risk"]; rc = risk_color(risk)
        html = _html_head("Detail")
        # Header
        badge_cls = {"CRITICAL":"badge-crit","HIGH":"badge-high","MEDIUM":"badge-med","LOW":"badge-low"}.get(risk,"badge-ok")
        html += f"<h1><span class='badge {badge_cls}'>{risk}</span>  {fp['url']}</h1>"

        # Method table
        html += "<h2>HTTP Method Results</h2>"
        html += "<table><tr><th>Method</th><th>Status</th><th>Time (ms)</th><th>Size</th><th>Content-Type</th><th>Location</th></tr>"
        for method in ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]:
            r = fp["methods"].get(method)
            if not r: continue
            code = r.get("status"); ms = r.get("elapsed_ms","?")
            clen = r.get("content_len","?"); ct = r.get("content_type","").split(";")[0].strip()
            loc  = r.get("location",""); err = r.get("error","")
            sc   = status_color(code)
            if code is None:
                html += f"<tr><td class='cyan'>{method}</td><td class='dim' colspan='5'>{err}</td></tr>"
            else:
                html += f"<tr><td class='cyan' style='font-weight:bold'>{method}</td>"
                html += f"<td style='color:{sc};font-weight:bold'>{code}</td>"
                html += f"<td class='dim'>{ms}</td><td class='dim'>{clen}</td>"
                html += f"<td class='dim'>{ct}</td><td class='dim'>{loc}</td></tr>"
        html += "</table>"

        # Two-column grid of info sections
        html += "<div class='grid-2'>"

        # Tech stack card
        html += "<div class='card'><h3>Tech Stack</h3>"
        if fp.get("tech"):
            html += "".join(f"<span class='badge badge-cyan'>{t}</span>" for t in fp["tech"])
        else:
            html += "<p class='dim'>None detected</p>"
        if fp.get("server"):    html += f"<p class='dim' style='margin-top:8px'>Server: <span class='cyan'>{fp['server']}</span></p>"
        if fp.get("x_powered_by"): html += f"<p class='dim'>X-Powered: <span class='cyan'>{fp['x_powered_by']}</span></p>"
        if fp.get("versions"):
            for t,v in fp["versions"].items(): html += f"<p class='dim'>{t}: <span class='warn'>{v}</span></p>"
        html += "</div>"

        # WAF card
        html += "<div class='card'><h3>WAF / CDN</h3>"
        if fp.get("waf"):
            for w in fp["waf"]: html += f"<p class='ok'>✔ {w}</p>"
        else:
            html += "<p class='warn'>⚠ No WAF detected</p>"
        html += "</div>"

        html += "</div>"  # end grid

        # Auth
        html += "<h2>Authentication &amp; Access Control</h2><div class='card'>"
        if fp.get("auth_hints"):
            for a in fp["auth_hints"]: html += f"<p class='warn'>⚠ {a}</p>"
        else:
            html += "<p class='dim'>No authentication enforcement detected on this endpoint</p>"
        html += "</div>"

        # CORS
        if fp.get("cors_issues") or fp.get("cors_info"):
            html += "<h2>CORS Policy</h2><div class='card'>"
            for c in fp.get("cors_issues",[]): html += f"<p class='crit'>⚡ {c}</p>"
            for c in fp.get("cors_info",[]):   html += f"<p class='cyan'>{c}</p>"
            html += "</div>"

        # Security headers
        html += "<h2>Security Headers</h2><div class='card'>"
        for s in fp.get("sec_ok",[]): html += f"<p class='ok'>✔ {s}</p>"
        for s in fp.get("sec_miss",[]): html += f"<p class='warn'>✖ {s} — MISSING</p>"
        html += "</div>"

        # Cookie issues
        if fp.get("ck_issues") or fp.get("ck_info"):
            html += "<h2>Cookie Security</h2><div class='card'>"
            for ci in fp.get("ck_info",[])[:4]:  html += f"<p class='dim'>{ci}</p>"
            for cx in fp.get("ck_issues",[]):     html += f"<p class='warn'>⚠ {cx}</p>"
            html += "</div>"

        # Rate limiting
        html += "<h2>Rate Limiting</h2><div class='card'>"
        rl = fp.get("rl_info",[])
        if rl:
            cl = "warn" if "No rate-limit" in rl[0] else "ok"
            for r in rl: html += f"<p class='{cl}'>{r}</p>"
        html += "</div>"

        # Body analysis
        html += "<h2>Body Analysis</h2><div class='card'>"
        if fp.get("body_hints"):
            for b in fp["body_hints"]:
                cls = "crit" if "[!]" in b else "cyan"
                html += f"<p class='{cls}'>{b}</p>"
        else:
            html += "<p class='dim'>No sensitive patterns detected in response body</p>"
        html += "</div>"

        # Injection probes
        html += "<h2>Injection Probing</h2><div class='card'>"
        if fp.get("inject_hits"):
            for inj in fp["inject_hits"]: html += f"<p class='crit'>⚡ {inj}</p>"
        else:
            html += "<p class='ok'>✔ No injection patterns triggered</p>"
        html += "</div>"

        # CVEs
        if fp.get("cves"):
            html += "<h2>CVE Hints</h2>"
            for cve,desc,ver in fp["cves"]:
                html += f"<div class='card card-crit'><p class='crit'>⚡ {cve}</p>"
                html += f"<p class='dim'>{desc}</p><p class='dim'>Detected: <span class='warn'>{ver}</span></p></div>"

        # Response headers
        if fp.get("sample_headers"):
            html += "<h2>Response Headers</h2>"
            html += "<table><tr><th>Header</th><th>Value</th></tr>"
            for k,v in fp["sample_headers"].items():
                html += f"<tr><td class='dim'>{k}</td><td>{v}</td></tr>"
            html += "</table>"

        # Body preview
        body = fp.get("sample_body","").strip()
        if body:
            html += "<h2>Response Body Preview</h2>"
            safe = body[:1500].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            html += f"<pre>{safe}{'…' if len(body)>1500 else ''}</pre>"

        html += _html_close()
        self.setHtml(html)


class RiskReportView(QTextBrowser):
    """Post-scan risk summary"""
    def __init__(self):
        super().__init__()
        self.setOpenLinks(False)

    def render(self, fps, sp=None):
        crit = [(p,f) for p,f in fps.items() if f["risk"]=="CRITICAL"]
        high = [(p,f) for p,f in fps.items() if f["risk"]=="HIGH"]
        med  = [(p,f) for p,f in fps.items() if f["risk"]=="MEDIUM"]
        total  = len(fps)
        active = sum(1 for f in fps.values()
                     if any(r.get("status") not in (404,None) for r in f["methods"].values()))
        inj_t  = sum(len(f.get("inject_hits",[])) for f in fps.values())
        cors_t = sum(1 for f in fps.values() if f.get("cors_issues"))
        ck_t   = sum(1 for f in fps.values() if f.get("ck_issues"))
        no_rl  = sum(1 for f in fps.values() if f.get("rl_info") and "No rate-limit" in f["rl_info"][0])

        html = _html_head("Risk Report")
        html += "<h1>⚡ CYBERSECURITY ANALYST RISK REPORT</h1>"

        # Summary cards
        html += "<div style='display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin:16px 0'>"
        stats = [
            ("SCANNED",  total,    C["cyan"]),
            ("ACTIVE",   active,   C["green"]),
            ("CRITICAL", len(crit),C["red"]),
            ("HIGH",     len(high),C["orange"]),
            ("MEDIUM",   len(med), C["yellow"]),
            ("INJECTIONS",inj_t,  C["red"]),
            ("CORS ISSUES",cors_t,C["orange"]),
            ("COOKIE",   ck_t,    C["orange"]),
        ]
        for lbl,val,col in stats:
            html += f"""<div class='stat-block'>
                <div class='stat-num' style='color:{col}'>{val}</div>
                <div class='stat-lbl'>{lbl}</div>
            </div>"""
        html += "</div>"

        # Target summary
        if sp:
            html += "<h2>Target Summary</h2><div class='card'>"
            dns = sp.get("dns",{}); tls = sp.get("tls",{})
            html += f"<div class='kv'><span class='key'>Host</span><span class='val cyan'>{sp.get('host','?')}</span></div>"
            if "ip" in dns:
                html += f"<div class='kv'><span class='key'>IP</span><span class='val'>{dns['ip']}</span></div>"
            html += f"<div class='kv'><span class='key'>Tech Stack</span><span class='val'>{', '.join(sp.get('tech',[])) or 'Unknown'}</span></div>"
            tver = tls.get("tls_version","N/A"); tdays = tls.get("expires_in_days","?")
            html += f"<div class='kv'><span class='key'>TLS</span><span class='val'>{tver}  (expires in {tdays} days)</span></div>"
            html += f"<div class='kv'><span class='key'>WAF/CDN</span><span class='val'>{', '.join(sp.get('waf',[])) or 'None detected'}</span></div>"
            if sp.get("cves"):
                html += f"<div class='kv'><span class='key'>CVE Hints</span><span class='val crit'>{len(sp['cves'])} vulnerability hint(s)</span></div>"
            html += "</div>"

        # Findings by severity
        for label,badge_cls,group in [
            ("CRITICAL","badge-crit",crit),
            ("HIGH","badge-high",high),
            ("MEDIUM","badge-med",med),
        ]:
            if not group: continue
            card_cls = {"CRITICAL":"card-crit","HIGH":"card-high","MEDIUM":"card-med"}[label]
            html += f"<h2><span class='badge {badge_cls}'>{label}</span>  {len(group)} finding(s)</h2>"
            for path,fp in group:
                statuses = {m:r["status"] for m,r in fp["methods"].items() if r.get("status")}
                working  = fp.get("working",[])
                s_str    = "  ".join(f"{m}={s}" for m,s in statuses.items() if s)
                html += f"<div class='card {card_cls}'>"
                html += f"<p style='font-size:13px;font-weight:bold;margin-bottom:6px'>{fp['url']}</p>"
                html += f"<div class='kv'><span class='key'>HTTP Statuses</span><span class='val dim'>{s_str}</span></div>"
                if working:
                    html += f"<div class='kv'><span class='key'>Working Methods</span><span class='val ok'>{', '.join(working)}</span></div>"
                if fp.get("tech"):
                    html += f"<div class='kv'><span class='key'>Tech Stack</span><span class='val cyan'>{', '.join(fp['tech'])}</span></div>"
                if fp.get("waf"):
                    html += f"<div class='kv'><span class='key'>WAF/CDN</span><span class='val ok'>{', '.join(fp['waf'])}</span></div>"
                if fp.get("auth_hints"):
                    html += f"<div class='kv'><span class='key'>Auth</span><span class='val warn'>{'; '.join(fp['auth_hints'])}</span></div>"
                for c in fp.get("cors_issues",[]): html += f"<p class='crit'>⚡ CORS: {c}</p>"
                for b in fp.get("body_hints",[]):
                    if "[!]" in b: html += f"<p class='crit'>⚡ Body: {b}</p>"
                for inj in fp.get("inject_hits",[]): html += f"<p class='crit'>⚡ Injection: {inj}</p>"
                if fp.get("rl_info") and "No rate-limit" in fp["rl_info"][0]:
                    html += f"<p class='warn'>⚠ No rate-limiting detected on this endpoint</p>"
                if fp.get("sec_miss"):
                    html += f"<div class='kv'><span class='key'>Missing Sec Headers</span><span class='val warn'>{', '.join(fp['sec_miss'])}</span></div>"
                if fp.get("cves"):
                    for cve,desc,ver in fp["cves"]:
                        html += f"<p class='crit'>⚡ {cve} — {desc} (v{ver})</p>"
                html += "</div>"

        # Stats footer
        html += "<h2>Scan Statistics</h2><div class='card'>"
        html += f"<div class='kv'><span class='key'>Paths probed</span><span class='val'>{total}</span></div>"
        html += f"<div class='kv'><span class='key'>Active endpoints</span><span class='val ok'>{active}</span></div>"
        html += f"<div class='kv'><span class='key'>Critical findings</span><span class='val crit'>{len(crit)}</span></div>"
        html += f"<div class='kv'><span class='key'>High findings</span><span class='val warn'>{len(high)}</span></div>"
        html += f"<div class='kv'><span class='key'>Medium findings</span><span class='val med'>{len(med)}</span></div>"
        if inj_t: html += f"<div class='kv'><span class='key'>Injection hits</span><span class='val crit'>{inj_t}</span></div>"
        if cors_t: html += f"<div class='kv'><span class='key'>CORS issues</span><span class='val warn'>{cors_t} endpoint(s)</span></div>"
        if ck_t:   html += f"<div class='kv'><span class='key'>Cookie issues</span><span class='val warn'>{ck_t} endpoint(s)</span></div>"
        if no_rl:  html += f"<div class='kv'><span class='key'>No rate-limit</span><span class='val warn'>{no_rl} endpoint(s)</span></div>"
        html += "</div>"

        html += _html_close()
        self.setHtml(html)


# ═══════════════════════════════════════════════════════════
#  HEADERS DIALOG
# ═══════════════════════════════════════════════════════════
class HeadersDialog(QDialog):
    def __init__(self, parent, current):
        super().__init__(parent)
        self.setWindowTitle("Custom HTTP Headers")
        self.setMinimumSize(540, 400)
        self.setStyleSheet(QSS + f"QDialog{{background:{C['bg1']};}}")
        lay = QVBoxLayout(self); lay.setSpacing(12); lay.setContentsMargins(16,16,16,16)
        hdr = QLabel("Custom HTTP Headers")
        hdr.setStyleSheet(f"font-size:14px;font-weight:bold;color:{C['cyan']};background:transparent;")
        sub = QLabel("One header per line in  Key: Value  format")
        sub.setStyleSheet(f"color:{C['t1']};font-size:11px;background:transparent;")
        lay.addWidget(hdr); lay.addWidget(sub)
        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{C['line']};"); lay.addWidget(sep)
        self.editor = QTextEdit()
        self.editor.setPlainText("\n".join(current))
        self.editor.setFont(QFont("Consolas", 12))
        self.editor.setStyleSheet(f"""
            QTextEdit {{background:{C['bg0']};border:1px solid {C['line']};
                       border-radius:5px;color:{C['t0']};font-size:12px;padding:8px;}}
        """)
        lay.addWidget(self.editor)
        # Preset buttons
        prow = QHBoxLayout()
        prow.addWidget(QLabel("Quick add:"))
        for label,value in [("JSON Content-Type","Content-Type: application/json"),
                             ("Accept JSON","Accept: application/json"),
                             ("No Cache","Cache-Control: no-cache")]:
            b = QPushButton(label)
            b.setFixedHeight(26)
            b.setStyleSheet(f"font-size:10px;padding:2px 10px;background:{C['bg2']};border:1px solid {C['line']};border-radius:3px;")
            b.clicked.connect(lambda _, v=value: self.editor.append(v))
            prow.addWidget(b)
        prow.addStretch()
        lay.addLayout(prow)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.setStyleSheet(f"""
            QPushButton {{background:{C['bg2']};border:1px solid {C['line']};
                         border-radius:4px;padding:6px 20px;color:{C['t0']};}}
            QPushButton:hover {{border-color:{C['cyan']};color:{C['cyan']};}}
        """)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def get_headers(self):
        return [l.strip() for l in self.editor.toPlainText().splitlines()
                if l.strip() and ":" in l]


# ═══════════════════════════════════════════════════════════
#  SIDEBAR (config panel)
# ═══════════════════════════════════════════════════════════
class Sidebar(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setMinimumWidth(550)
        self.setMaximumWidth(550)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet(f"""
            QScrollArea {{
                background: {C['bg1']};
                border: none;
                border-right: 1px solid {C['line']};
            }}
            QScrollArea > QWidget > QWidget {{ background: {C['bg1']}; }}
        """)
        inner = QWidget()
        inner.setStyleSheet(f"background: {C['bg1']};")
        self.setWidget(inner)
        self.lay = QVBoxLayout(inner)
        self.lay.setContentsMargins(14, 14, 14, 14)
        self.lay.setSpacing(14)
        self._build()

    def _build(self):
        L = self.lay

        # ── Target ──────────────────────────────
        tg = QGroupBox("Target")
        tl = QVBoxLayout(tg); tl.setSpacing(8)

        url_lbl = QLabel("URL"); url_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example.com")
        self.url_input.setClearButtonEnabled(True)

        tok_lbl = QLabel("Auth Token (Bearer)"); tok_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("eyJ… or leave blank")
        self.token_input.setEchoMode(QLineEdit.Password)

        wl_lbl = QLabel("Wordlist  (modes 1/4/5)"); wl_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        wl_row = QHBoxLayout(); wl_row.setSpacing(6)
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("wordlist.txt")
        btn_browse = QPushButton("…"); btn_browse.setFixedWidth(34); btn_browse.setFixedHeight(34)
        btn_browse.setObjectName("btn_action")
        wl_row.addWidget(self.wordlist_input); wl_row.addWidget(btn_browse)
        btn_browse.clicked.connect(self._browse_wl)

        tl.addWidget(url_lbl); tl.addWidget(self.url_input)
        tl.addWidget(tok_lbl); tl.addWidget(self.token_input)
        tl.addWidget(wl_lbl); tl.addLayout(wl_row)
        L.addWidget(tg)

        # ── Scan Mode ───────────────────────────
        mg = QGroupBox("Scan Mode")
        ml = QVBoxLayout(mg); ml.setSpacing(8)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "1  —  Normal      (wordlist paths)",
            "2  —  Crawl       (extract links from page)",
            "3  —  API         (built-in API route list)",
            "4  —  Hybrid      (Normal + Crawl + API)",
            "5  —  Full        (everything combined)",
            "6  —  Probe       (all 7 methods, deep report)",
        ])
        self.mode_combo.setCurrentIndex(2)
        probe_lbl = QLabel("Probe path  (mode 6 only, blank = all)"); probe_lbl.setStyleSheet(f"color:{C['t1']};font-size:10px;letter-spacing:1px;background:transparent;")
        self.probe_path = QLineEdit()
        self.probe_path.setPlaceholderText("api/v1/users")
        ml.addWidget(self.mode_combo); ml.addWidget(probe_lbl); ml.addWidget(self.probe_path)
        L.addWidget(mg)

        # ── HTTP Methods ────────────────────────
        me_g = QGroupBox("HTTP Methods")
        me_l = QVBoxLayout(me_g); me_l.setSpacing(6)
        self.method_cbs = {}
        row1 = QHBoxLayout(); row2 = QHBoxLayout()
        for i,m in enumerate(["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]):
            cb = QCheckBox(m); cb.setChecked(m in ("GET","POST","PUT","DELETE"))
            self.method_cbs[m] = cb
            (row1 if i < 4 else row2).addWidget(cb)
        # Select all / none buttons
        btn_row = QHBoxLayout()
        for label,checked in [("All",True),("None",False),("Common",None)]:
            b = QPushButton(label); b.setFixedHeight(24)
            b.setStyleSheet(f"font-size:10px;padding:2px 8px;background:{C['bg3']};border:1px solid {C['line']};border-radius:3px;")
            if checked is True:  b.clicked.connect(lambda: [cb.setChecked(True)  for cb in self.method_cbs.values()])
            elif checked is False: b.clicked.connect(lambda: [cb.setChecked(False) for cb in self.method_cbs.values()])
            else:
                b.clicked.connect(lambda: [cb.setChecked(cb.text() in ("GET","POST","PUT","DELETE"))
                                           for cb in self.method_cbs.values()])
            btn_row.addWidget(b)
        btn_row.addStretch()
        me_l.addLayout(row1); me_l.addLayout(row2); me_l.addLayout(btn_row)
        L.addWidget(me_g)

        # ── Options ─────────────────────────────
        og = QGroupBox("Scan Options")
        ol = QVBoxLayout(og); ol.setSpacing(10)
        # Threads
        th_row = QHBoxLayout()
        th_lbl = QLabel("Threads"); th_lbl.setStyleSheet(f"color:{C['t1']};font-size:11px;background:transparent;")
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1,200); self.threads_spin.setValue(40)
        th_row.addWidget(th_lbl); th_row.addWidget(self.threads_spin)
        # Timeout
        to_row = QHBoxLayout()
        to_lbl = QLabel("Timeout (s)"); to_lbl.setStyleSheet(f"color:{C['t1']};font-size:11px;background:transparent;")
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(1,60); self.timeout_spin.setValue(7)
        to_row.addWidget(to_lbl); to_row.addWidget(self.timeout_spin)
        ol.addLayout(th_row); ol.addLayout(to_row)
        # Checkboxes
        self.inject_cb = QCheckBox("Enable passive injection probing")
        self.recon_cb  = QCheckBox("Run server recon first")
        self.recon_cb.setChecked(True)
        ol.addWidget(self.inject_cb); ol.addWidget(self.recon_cb)
        L.addWidget(og)

        # ── Custom Headers ──────────────────────
        hdr_g = QGroupBox("Custom Headers")
        hdr_l = QVBoxLayout(hdr_g); hdr_l.setSpacing(6)
        self.headers_preview = QLabel("0 custom headers set")
        self.headers_preview.setStyleSheet(f"color:{C['t2']};font-size:11px;background:transparent;")
        self.headers_preview.setWordWrap(True)
        btn_hdrs = QPushButton("Edit Custom Headers…"); btn_hdrs.setObjectName("btn_action")
        btn_hdrs.clicked.connect(self._open_hdrs)
        hdr_l.addWidget(self.headers_preview); hdr_l.addWidget(btn_hdrs)
        L.addWidget(hdr_g)

        L.addStretch()

        # ── Start / Stop ────────────────────────
        self.btn_start = QPushButton("▶   START SCAN")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.setFixedHeight(46)
        self.btn_stop  = QPushButton("■   STOP")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setFixedHeight(38)
        L.addWidget(self.btn_start)
        L.addWidget(self.btn_stop)

        # internal header storage
        self._custom_headers = []

    def _browse_wl(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text (*.txt);;All (*)")
        if path: self.wordlist_input.setText(path)

    def _open_hdrs(self):
        dlg = HeadersDialog(self, self._custom_headers)
        if dlg.exec_():
            self._custom_headers = dlg.get_headers()
            n = len(self._custom_headers)
            preview = "; ".join(self._custom_headers[:3])
            if n > 3: preview += f" +{n-3} more"
            self.headers_preview.setText(f"{n} header(s): {preview}" if n else "0 custom headers set")

    def get_config(self):
        methods = [m for m,cb in self.method_cbs.items() if cb.isChecked()]
        return {
            "url":        self.url_input.text().strip(),
            "token":      self.token_input.text().strip(),
            "wordlist":   self.wordlist_input.text().strip(),
            "mode":       str(self.mode_combo.currentIndex() + 1),
            "probe_path": self.probe_path.text().strip(),
            "methods":    methods,
            "threads":    self.threads_spin.value(),
            "timeout":    self.timeout_spin.value(),
            "inject":     self.inject_cb.isChecked(),
            "recon":      self.recon_cb.isChecked(),
            "headers":    self._custom_headers,
        }


# ═══════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SiteCrawler v4.0")
        self.setMinimumSize(1400, 860)
        self.resize(1600, 960)
        self.worker = None
        self._fps   = {}
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
        self._log("SiteCrawler v4.0 ready.  Configure target on the left and click  ▶ START SCAN", "ok")
        self._log("Tip: Mode 3 (API) scans all built-in API/backend routes with zero config needed.", "info")
        self._log("Tip: Enable injection probing for passive vulnerability detection.", "info")

    def _build_menu(self):
        mb = self.menuBar()
        # File
        fm = mb.addMenu("&File")
        for label,slot,key in [("New Scan",self._reset,"Ctrl+N"),
                                ("Save Results…",self._save,"Ctrl+S"),
                                ("Export JSON…",self._export_json,"Ctrl+E"),
                                ("Export HTML Report…",self._export_html,"Ctrl+R")]:
            a = QAction(label, self); a.setShortcut(key); a.triggered.connect(slot); fm.addAction(a)
        fm.addSeparator()
        a = QAction("Exit", self); a.setShortcut("Ctrl+Q"); a.triggered.connect(self.close); fm.addAction(a)
        # Scan
        sm = mb.addMenu("&Scan")
        for label,slot,key in [("Start Scan",self._start,"F5"),("Stop Scan",self._stop,"F6")]:
            a = QAction(label,self); a.setShortcut(key); a.triggered.connect(slot); sm.addAction(a)
        sm.addSeparator()
        a = QAction("Clear Terminal",self); a.triggered.connect(lambda: self.log_terminal.clear()); sm.addAction(a)
        a = QAction("Clear Results", self); a.triggered.connect(self._clear_results); sm.addAction(a)
        # View
        vm = mb.addMenu("&View")
        for i,label in enumerate(["Terminal","Results","Recon","Risk Report","Headers"]):
            a = QAction(label,self); a.setShortcut(f"Ctrl+{i+1}")
            a.triggered.connect(lambda _,idx=i: self.tabs.setCurrentIndex(idx)); vm.addAction(a)
        # Help
        hm = mb.addMenu("&Help")
        a = QAction("About", self); a.triggered.connect(self._about); hm.addAction(a)

    def _build_ui(self):
        root = QWidget(); root.setObjectName("root_widget")
        root.setStyleSheet(f"QWidget#root_widget{{background:{C['bg0']};}}")
        self.setCentralWidget(root)
        root_lay = QVBoxLayout(root)
        root_lay.setContentsMargins(0,0,0,0); root_lay.setSpacing(0)

        # Top bar
        self.topbar = TopBar()
        root_lay.addWidget(self.topbar)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal); splitter.setHandleWidth(1)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{C['line']};}}")
        root_lay.addWidget(splitter, 1)

        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.btn_start.clicked.connect(self._start)
        self.sidebar.btn_stop.clicked.connect(self._stop)
        splitter.addWidget(self.sidebar)

        # Right area
        right = QWidget()
        right.setStyleSheet(f"background:{C['bg0']};")
        rv = QVBoxLayout(right); rv.setContentsMargins(10,10,10,10); rv.setSpacing(10)

        # Stat cards
        stat_row = QHBoxLayout(); stat_row.setSpacing(8)
        self.sc_total    = StatCard("Scanned",  "0",  C["cyan"],    "⬡")
        self.sc_active   = StatCard("Active",   "0",  C["green"],   "✦")
        self.sc_critical = StatCard("Critical", "0",  C["red"],     "⚡")
        self.sc_high     = StatCard("High",     "0",  C["orange"],  "▲")
        self.sc_medium   = StatCard("Medium",   "0",  C["yellow"],  "◆")
        self.sc_inject   = StatCard("Injections","0", C["purple"],  "⚔")
        self.sc_elapsed  = StatCard("Elapsed",  "—",  C["t1"],      "⏱")
        for sc in [self.sc_total, self.sc_active, self.sc_critical, self.sc_high,
                   self.sc_medium, self.sc_inject, self.sc_elapsed]:
            stat_row.addWidget(sc)
        rv.addLayout(stat_row)

        # Progress bar
        prog_row = QHBoxLayout(); prog_row.setSpacing(8)
        self.progress     = QProgressBar()
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress_lbl = QLabel("Ready")
        self.progress_lbl.setStyleSheet(f"color:{C['t2']};font-size:11px;background:transparent;min-width:180px;")
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.progress_lbl)
        rv.addLayout(prog_row)

        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        rv.addWidget(self.tabs, 1)

        # ── Tab 0: Terminal ──────────────────────
        t0_w = QWidget(); t0_w.setStyleSheet(f"background:{C['bg1']};")
        t0_l = QVBoxLayout(t0_w); t0_l.setContentsMargins(0,6,0,0); t0_l.setSpacing(4)
        ctrl_bar = QHBoxLayout(); ctrl_bar.setContentsMargins(8,0,8,0)
        lbl_term = SectionLabel("Live Terminal Output")
        btn_clr  = QPushButton("Clear Terminal"); btn_clr.setObjectName("btn_action")
        btn_clr.setFixedHeight(28); btn_clr.setFixedWidth(140)
        btn_clr.clicked.connect(lambda: self.log_terminal.clear())
        ctrl_bar.addWidget(lbl_term); ctrl_bar.addStretch(); ctrl_bar.addWidget(btn_clr)
        self.log_terminal = LogTerminal()
        t0_l.addLayout(ctrl_bar); t0_l.addWidget(self.log_terminal)
        self.tabs.addTab(t0_w, "  Terminal  ")

        # ── Tab 1: Results ───────────────────────
        t1_w  = QWidget(); t1_w.setStyleSheet(f"background:{C['bg1']};")
        t1_l  = QVBoxLayout(t1_w); t1_l.setContentsMargins(0,6,0,0); t1_l.setSpacing(6)
        # Filter bar
        fbar = QHBoxLayout(); fbar.setContentsMargins(8,0,8,0); fbar.setSpacing(8)
        fbar.addWidget(SectionLabel("Endpoint Results"))
        fbar.addSpacing(16)
        fbar.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by URL, method, tech, WAF…")
        self.filter_input.setFixedHeight(30); self.filter_input.textChanged.connect(self._filter)
        self.risk_filter = QComboBox(); self.risk_filter.setFixedWidth(140); self.risk_filter.setFixedHeight(30)
        self.risk_filter.addItems(["All Risks","CRITICAL","HIGH","MEDIUM","LOW"])
        self.risk_filter.currentIndexChanged.connect(self._filter)
        btn_clr2 = QPushButton("Clear"); btn_clr2.setObjectName("btn_action")
        btn_clr2.setFixedHeight(30); btn_clr2.setFixedWidth(80)
        btn_clr2.clicked.connect(self._clear_results)
        fbar.addWidget(self.filter_input, 1); fbar.addWidget(self.risk_filter); fbar.addWidget(btn_clr2)
        t1_l.addLayout(fbar)
        # Vertical split: table + detail
        vsplit = QSplitter(Qt.Vertical); vsplit.setHandleWidth(4)
        self.results_table = ResultsTable()
        self.results_table.cellClicked.connect(self._on_row_click)
        vsplit.addWidget(self.results_table)
        # Detail panel with its own section header
        detail_wrap = QWidget(); detail_wrap.setStyleSheet(f"background:{C['bg1']};")
        dw_l = QVBoxLayout(detail_wrap); dw_l.setContentsMargins(0,0,0,0); dw_l.setSpacing(0)
        dw_l.addWidget(SectionLabel("Endpoint Detail"))
        self.detail_view = DetailView()
        dw_l.addWidget(self.detail_view, 1)
        vsplit.addWidget(detail_wrap)
        vsplit.setSizes([440, 320])
        t1_l.addWidget(vsplit, 1)
        self.tabs.addTab(t1_w, "  Results  ")

        # ── Tab 2: Recon ─────────────────────────
        t2_w = QWidget(); t2_w.setStyleSheet(f"background:{C['bg1']};")
        t2_l = QVBoxLayout(t2_w); t2_l.setContentsMargins(0,6,0,0); t2_l.setSpacing(0)
        t2_l.addWidget(SectionLabel("Server Reconnaissance"))
        self.recon_view = ReconView()
        t2_l.addWidget(self.recon_view, 1)
        self.tabs.addTab(t2_w, "  Recon  ")

        # ── Tab 3: Risk Report ───────────────────
        t3_w = QWidget(); t3_w.setStyleSheet(f"background:{C['bg1']};")
        t3_l = QVBoxLayout(t3_w); t3_l.setContentsMargins(0,6,0,0); t3_l.setSpacing(0)
        t3_l.addWidget(SectionLabel("Analyst Risk Report"))
        self.risk_report = RiskReportView()
        t3_l.addWidget(self.risk_report, 1)
        self.tabs.addTab(t3_w, "  Risk Report  ")

        # ── Tab 4: Headers ───────────────────────
        t4_w = QWidget(); t4_w.setStyleSheet(f"background:{C['bg1']};")
        t4_l = QVBoxLayout(t4_w); t4_l.setContentsMargins(0,6,0,0); t4_l.setSpacing(0)
        t4_l.addWidget(SectionLabel("All Response Headers"))
        self.headers_view = QTextBrowser()
        self.headers_view.setOpenLinks(False)
        t4_l.addWidget(self.headers_view, 1)
        self.tabs.addTab(t4_w, "  Headers  ")

        splitter.addWidget(right)
        splitter.setSizes([330, 1270])

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

    # ── helpers ──────────────────────────────────
    def _log(self, msg, level="info"):
        self.log_terminal.log(msg, level)

    def _update_stats(self):
        total    = len(self._fps)
        active   = sum(1 for f in self._fps.values()
                       if any(r.get("status") not in (404,None) for r in f["methods"].values()))
        critical = sum(1 for f in self._fps.values() if f["risk"]=="CRITICAL")
        high     = sum(1 for f in self._fps.values() if f["risk"]=="HIGH")
        medium   = sum(1 for f in self._fps.values() if f["risk"]=="MEDIUM")
        inj      = sum(len(f.get("inject_hits",[])) for f in self._fps.values())
        self.sc_total.set_value(total)
        self.sc_active.set_value(active)
        self.sc_critical.set_value(critical)
        self.sc_high.set_value(high)
        self.sc_medium.set_value(medium)
        self.sc_inject.set_value(inj)
        self._status_count.setText(f"  {active} active  |  {critical} crit  {high} high  {medium} med  ")

    def _tick_elapsed(self):
        if self._scan_start and self.worker and self.worker.isRunning():
            e = int(time.time() - self._scan_start)
            m,s = divmod(e,60)
            self.sc_elapsed.set_value(f"{m:02d}:{s:02d}")

    # ── scan control ─────────────────────────────
    def _start(self):
        cfg = self.sidebar.get_config()
        url = cfg["url"]
        if not url:
            QMessageBox.warning(self,"No URL","Please enter a target URL."); return
        if not url.startswith(("http://","https://")):
            url = "https://" + url
            self.sidebar.url_input.setText(url)
            cfg["url"] = url
        if not cfg["methods"]:
            QMessageBox.warning(self,"No Methods","Select at least one HTTP method."); return
        self._fps = {}; self._scan_start = time.time()
        self.sc_elapsed.set_value("00:00")
        self._reset_counts()
        self.results_table.setRowCount(0)
        self.log_terminal.clear()
        self.detail_view.clear()
        self.progress.setMaximum(0); self.progress.setValue(0)
        self.sidebar.btn_start.setEnabled(False)
        self.sidebar.btn_stop.setEnabled(True)
        mode_names = ["Normal","Crawl","API","Hybrid","Full","Probe"]
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
        self.worker.start()

    def _stop(self):
        if self.worker:
            self.worker.stop()
            self._log("Stop requested — waiting for in-flight requests to finish…", "warn")

    def _reset(self):
        self._stop()
        self._fps = {}; self._reset_counts()
        self.results_table.setRowCount(0)
        self.log_terminal.clear()
        self.detail_view.clear()
        self.recon_view.clear()
        self.risk_report.clear()
        self.headers_view.clear()
        self.progress.setValue(0); self.progress.setMaximum(100)
        self._status_main.setText("Ready — Configure target and press  ▶ START SCAN  (F5)")
        self._status_count.setText(""); self._status_mode.setText("")
        self.sc_elapsed.set_value("—")

    def _reset_counts(self):
        for sc in [self.sc_total,self.sc_active,self.sc_critical,
                   self.sc_high,self.sc_medium,self.sc_inject]:
            sc.set_value("0")

    def _clear_results(self):
        self._fps = {}; self._reset_counts()
        self.results_table.setRowCount(0)
        self.detail_view.clear()

    # ── worker slots ─────────────────────────────
    @pyqtSlot(str, str)
    def _on_log(self, msg, level):
        self.log_terminal.log(msg, level)

    @pyqtSlot(dict)
    def _on_result(self, fp):
        self._fps[fp["path"]] = fp
        self.results_table.add_fp(fp)
        self._update_stats()

    @pyqtSlot(dict)
    def _on_recon(self, profile):
        self.recon_view.render(profile)
        # Populate headers tab
        hdrs = profile.get("headers",{})
        t1,line,bg0,bg1,bg2,cyan = C["t1"],C["line"],C["bg0"],C["bg1"],C["bg2"],C["cyan"]
        html = _html_head("Headers")
        html += "<h1>All Response Headers</h1>"
        html += "<table><tr><th>Header</th><th>Value</th></tr>"
        for k,v in hdrs.items():
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
        m,s = divmod(int(elapsed), 60)
        self.sc_elapsed.set_value(f"{m:02d}:{s:02d}")
        if self.progress.maximum() == 0:
            self.progress.setMaximum(1); self.progress.setValue(1)
        self.risk_report.render(self._fps, server_profile)
        self._log(f"Scan complete in {elapsed:.1f}s — {len(self._fps)} findings, {sum(1 for f in self._fps.values() if f['risk']=='CRITICAL')} critical", "ok")
        self._status_main.setText(f"Scan complete — {elapsed:.1f}s  |  {len(self._fps)} findings")
        self.tabs.setCurrentIndex(1)

    # ── table interaction ─────────────────────────
    def _on_row_click(self, row, col):
        path_item = self.results_table.item(row, 3)  # Path column
        if not path_item: return
        path = path_item.text()
        fp   = self._fps.get(path)
        if fp:
            self.detail_view.render(fp)

    def _filter(self):
        text     = self.filter_input.text().lower()
        risk_flt = self.risk_filter.currentText()
        for row in range(self.results_table.rowCount()):
            risk_item = self.results_table.item(row, 0)
            if not risk_item: continue
            risk = risk_item.text()
            row_text = " ".join(
                self.results_table.item(row, c).text().lower()
                for c in range(self.results_table.columnCount())
                if self.results_table.item(row, c)
            )
            risk_ok = (risk_flt == "All Risks" or risk == risk_flt)
            text_ok = (not text or text in row_text)
            self.results_table.setRowHidden(row, not (risk_ok and text_ok))

    # ── save/export ───────────────────────────────
    def _save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Results", "sitecrawler_results.txt", "Text (*.txt);;All (*)")
        if not path: return
        lines = []
        for fp in self._fps.values():
            for method, r in fp["methods"].items():
                if r.get("status") and r["status"] != 404:
                    line = (f"[{fp['risk']:<8}] [{r['status']}] [{method}] {fp['url']}"
                            + (f" | tech:{','.join(fp.get('tech',[]))}"           if fp.get("tech")        else "")
                            + (f" | waf:{','.join(fp.get('waf',[]))}"             if fp.get("waf")         else "")
                            + (f" | auth:{';'.join(fp.get('auth_hints',[]))}"     if fp.get("auth_hints")  else "")
                            + (f" | cors:{';'.join(fp.get('cors_issues',[]))}"    if fp.get("cors_issues") else "")
                            + (f" | inject:{';'.join(fp.get('inject_hits',[]))}"  if fp.get("inject_hits") else ""))
                    lines.append(line)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._log(f"Results saved  →  {path}  ({len(lines)} entries)", "ok")
        QMessageBox.information(self, "Saved", f"Saved {len(lines)} findings to:\n{path}")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "sitecrawler.json", "JSON (*.json)")
        if not path: return
        out = {}
        for p, fp in self._fps.items():
            entry = {k: v for k, v in fp.items() if k not in ("methods","sample_headers","sample_body")}
            entry["methods"] = {
                m: {"status": r.get("status"), "elapsed_ms": r.get("elapsed_ms"),
                    "content_type": r.get("content_type",""), "location": r.get("location","")}
                for m, r in fp["methods"].items()
            }
            out[p] = entry
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
        self._log(f"JSON exported  →  {path}", "ok")
        QMessageBox.information(self, "Exported", f"Exported {len(out)} entries to:\n{path}")

    def _export_html(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML Report", "sitecrawler_report.html", "HTML (*.html)")
        if not path: return
        html = _html_head("SiteCrawler Report")
        html += "<h1>⚡ SiteCrawler v4.0 — Full Scan Report</h1>"
        html += f"<p class='dim'>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        # Embed risk report content
        self.risk_report.render(self._fps, server_profile)
        for fp in sorted(self._fps.values(), key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW"].index(f["risk"])):
            rc = risk_color(fp["risk"])
            html += f"<hr style='border-color:{C['line']};margin:20px 0'>"
            html += f"<h2 style='color:{rc}'>[{fp['risk']}] {fp['url']}</h2>"
            html += "<table><tr><th>Method</th><th>Status</th><th>Time</th><th>Content-Type</th></tr>"
            for m,r in fp["methods"].items():
                if r.get("status"):
                    sc2 = status_color(r["status"])
                    st2 = r["status"]
                    html += f"<tr><td>{m}</td><td style='color:{sc2}'>{st2}</td>"
                    html += f"<td>{r.get('elapsed_ms','?')}ms</td><td class='dim'>{r.get('content_type','')[:60]}</td></tr>"
            html += "</table>"
            if fp.get("tech"):
                tags2 = "  ".join(f'<span class="badge badge-cyan">{t}</span>' for t in fp["tech"])
                html += f"<p>Tech: {tags2}</p>"
            if fp.get("waf"):  html += f"<p>WAF: <span class='ok'>{', '.join(fp['waf'])}</span></p>"
            for c in fp.get("cors_issues",[]): html += f"<p class='crit'>⚡ CORS: {c}</p>"
            for b in fp.get("body_hints",[]):
                if "[!]" in b: html += f"<p class='crit'>⚡ {b}</p>"
            for inj in fp.get("inject_hits",[]): html += f"<p class='crit'>⚡ Injection: {inj}</p>"
        html += _html_close()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        self._log(f"HTML report exported  →  {path}", "ok")
        QMessageBox.information(self, "Exported", f"HTML report saved to:\n{path}")

    def _about(self):
        QMessageBox.about(self, "About SiteCrawler",
            f"<b style='font-size:14px'>SiteCrawler v4.0</b><br><br>"
            "Analyst-grade endpoint fingerprinting &amp; security assessment.<br><br>"
            "<b>Author:</b> CoderSigma<br>"
            "<b>GUI Framework:</b> PyQt5<br><br>"
            "<b>Features</b><br>"
            "• WAF / CDN detection<br>"
            "• TLS / SSL certificate inspection<br>"
            "• CVE version hints<br>"
            "• CORS policy analysis<br>"
            "• Cookie security flags<br>"
            "• Response body analysis (secrets, JWTs, keys)<br>"
            "• Passive injection probing (SQLi, XSS, SSTI, traversal)<br>"
            "• Risk-classified report (Critical / High / Medium / Low)<br>"
            "• Export: TXT, JSON, HTML")


# ═══════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════
def main():
    if not REQUESTS_OK:
        print("[ERROR] Missing: pip install requests PyQt5")
        sys.exit(1)
    app = QApplication(sys.argv)
    app.setApplicationName("SiteCrawler")
    app.setApplicationVersion("4.0")
    for fn in ["Consolas","Courier New","DejaVu Sans Mono","Liberation Mono","Monospace"]:
        f = QFont(fn, 12)
        if f.exactMatch(): app.setFont(f); break
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()