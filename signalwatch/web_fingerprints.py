"""Bounded HTTP fingerprints with explicit deployment and inference provenance.

These are response signatures, not proof that a product is vulnerable. SaaS
allowlists and dependency hints deliberately do not produce deployment CPEs.
"""

import re
from collections import deque
from html.parser import HTMLParser
from itertools import islice
from urllib.parse import urljoin, urlsplit

METHOD = "http_fingerprint_v1"
HTML_LIMIT = 250_000
FINDING_LIMIT = 100
VERSION = r"[0-9]+(?:\.[0-9]+){0,4}(?:[-+~][0-9A-Za-z_.-]+)?"

# key: canonical vendor/product, display names, category, CPE part, known CPE identity.
_TECH = {
    "nginx": ("f5", "nginx", "F5 / Nginx", "Nginx", "Web Server", "a", True),
    "apache": ("apache", "http_server", "Apache", "Apache HTTP Server", "Web Server", "a", True),
    "iis": ("microsoft", "internet_information_services", "Microsoft", "Microsoft IIS", "Web Server", "a", True),
    "php": ("php", "php", "PHP", "PHP", "Runtime", "a", True),
    "aspnet": ("microsoft", "asp.net", "Microsoft", "ASP.NET", "Web Framework", "a", True),
    "express": ("expressjs", "express", "Express", "Express", "Web Framework", "a", True),
    "cloudflare": ("cloudflare", "cloudflare", "Cloudflare", "Cloudflare", "CDN / WAF", "a", False),
    "cloudfront": ("amazon", "cloudfront", "Amazon", "Amazon CloudFront", "CDN", "a", False),
    "incapsula": ("imperva", "incapsula", "Imperva", "Imperva Incapsula", "WAF", "a", False),
    "varnish": ("varnish-software", "varnish_cache", "Varnish Software", "Varnish Cache", "Web Cache", "a", True),
    "nextjs": ("vercel", "next.js", "Vercel", "Next.js", "Web Framework", "a", True),
    "angular": ("angular", "angular", "Google", "Angular", "Web Framework", "a", True),
    "wordpress": ("wordpress", "wordpress", "WordPress", "WordPress", "CMS", "a", True),
    "drupal": ("drupal", "drupal", "Drupal", "Drupal", "CMS", "a", True),
    "joomla": ("joomla", "joomla!", "Joomla", "Joomla!", "CMS", "a", True),
    "jquery": ("jquery", "jquery", "jQuery", "jQuery", "JavaScript Library", "a", True),
    "laravel": ("laravel", "framework", "Laravel", "Laravel", "Web Framework", "a", True),
    "tomcat": ("apache", "tomcat", "Apache", "Apache Tomcat", "Application Server", "a", True),
    "servlet": ("java", "servlet", "Java", "Java Servlet", "Web Framework", "a", False),
    "java": ("java", "java", "Java", "Java Runtime", "Runtime", "a", False),
    "react": ("facebook", "react", "Meta", "React", "Web Framework", "a", True),
    "aws": ("amazon", "aws", "Amazon", "AWS", "Cloud", "a", False),
    # Portal branding does not identify the installed GlobalProtect endpoint client.
    "globalprotect": ("paloaltonetworks", "globalprotect", "Palo Alto Networks", "GlobalProtect Gateway", "VPN", "a", False),
    "fortios": ("fortinet", "fortios", "Fortinet", "FortiOS SSL VPN", "Firewall", "o", True),
    "citrix": ("citrix", "netscaler_gateway", "Citrix", "Citrix NetScaler Gateway", "VPN", "a", True),
    "routeros": ("mikrotik", "routeros", "MikroTik", "RouterOS", "Operating System", "o", True),
    "datadog_rum": ("datadog", "rum", "Datadog", "Datadog RUM", "Observability", "a", False),
    "sentry_sdk": ("sentry", "javascript_sdk", "Sentry", "Sentry JavaScript SDK", "Observability", "a", False),
    "stripe": ("stripe", "stripe", "Stripe", "Stripe", "Payments", "a", False),
    "okta": ("okta", "okta", "Okta", "Okta", "Identity", "a", False),
    "auth0": ("auth0", "auth0", "Okta", "Auth0", "Identity", "a", False),
    "datadog": ("datadog", "datadog", "Datadog", "Datadog", "Observability", "a", False),
    "sentry": ("sentry", "sentry", "Sentry", "Sentry", "Observability", "a", False),
    "segment": ("twilio", "segment", "Twilio", "Twilio Segment", "Customer Data Platform", "a", False),
    "launchdarkly": ("launchdarkly", "launchdarkly", "LaunchDarkly", "LaunchDarkly", "Feature Management", "a", False),
    "intercom": ("intercom", "intercom", "Intercom", "Intercom", "Customer Support", "a", False),
    "zendesk": ("zendesk", "zendesk", "Zendesk", "Zendesk", "Customer Support", "a", False),
    "marketo": ("adobe", "marketo", "Adobe", "Adobe Marketo", "Marketing Automation", "a", False),
    "hubspot": ("hubspot", "hubspot", "HubSpot", "HubSpot", "CRM / Marketing", "a", False),
    "fullstory": ("fullstory", "fullstory", "FullStory", "FullStory", "Digital Experience", "a", False),
    "amplitude": ("amplitude", "amplitude", "Amplitude", "Amplitude", "Product Analytics", "a", False),
}

# A static Next.js export does not establish a deployed Node.js runtime. WordPress
# does not establish MySQL (MariaDB and other database arrangements exist).
IMPLIES = {"nextjs": ("react",), "wordpress": ("php",), "laravel": ("php",),
           "tomcat": ("java",), "servlet": ("java",), "cloudfront": ("aws",)}
CSP_DOMAINS = {
    "okta.com": "okta", "auth0.com": "auth0", "datadoghq.com": "datadog", "sentry.io": "sentry",
    "stripe.com": "stripe", "segment.io": "segment", "segment.com": "segment",
    "launchdarkly.com": "launchdarkly", "intercom.io": "intercom", "zdassets.com": "zendesk",
    "mktoresp.com": "marketo", "hs-scripts.com": "hubspot", "fullstory.com": "fullstory", "amplitude.com": "amplitude",
}
_CSP_DIRECTIVES = {"default-src", "script-src", "script-src-elem", "script-src-attr", "connect-src",
                   "frame-src", "child-src", "img-src", "style-src", "style-src-elem", "font-src",
                   "media-src", "worker-src", "object-src", "form-action"}
# Set-Cookie is not a comma-separated header. Commas may occur in values and
# Expires attributes; scanning past the first name would let values spoof names.
_COOKIE = re.compile(r"^\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=")


def _version(value):
    value = str(value or "")[:64]
    return value if re.fullmatch(VERSION, value) else ""


def _cpe_token(value):
    return re.sub(r"([^A-Za-z0-9_.-])", r"\\\1", value)


def _finding(key, evidence_type, evidence, version="", confidence=0.9, status="http_detected", **extra):
    vendor, product, vendor_name, product_name, category, part, known_cpe = _TECH[key]
    version = _version(version) if status == "http_detected" else ""
    row = {"vendor": vendor, "product": product, "vendor_name": vendor_name, "product_name": product_name,
           "category": category, "part": part, "version": version, "status": status,
           "confidence": confidence, "evidence_snippet": evidence[:300], "method": METHOD,
           "evidence_type": evidence_type, **extra}
    if known_cpe and status == "http_detected":
        row["cpe"] = ":".join(["cpe", "2.3", part, _cpe_token(vendor), _cpe_token(product),
                                _cpe_token(version) if version else "*", *(["*"] * 7)])
    return row


def _headers(headers):
    result, remaining = {}, 65_536
    items = headers.multi_items() if hasattr(headers, "multi_items") else headers.items() if hasattr(headers, "items") else headers or ()
    for index, (name, values) in enumerate(items):
        if index >= 128 or remaining <= 0:
            break
        name = str(name).lower()
        for value in values if isinstance(values, (list, tuple)) else (values,):
            text = str(value)[:min(4096, remaining)]
            remaining -= len(text)
            result.setdefault(name, []).append(text)
            if remaining <= 0:
                break
    return result


class _Page(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags, self.inline, self.title = [], [], []
        self._script = self._title = False
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        self._script = self._script or tag == "script"
        self._title = self._title or tag == "title"
        if len(self.tags) < 3000:
            self.tags.append((tag, dict(attrs)))

    def handle_endtag(self, tag):
        if tag == "script":
            self._script = False
        elif tag == "title":
            self._title = False

    def handle_data(self, data):
        if self._script:
            self.inline.append(data)
        if self._title:
            self.title.append(data)


def _host_source(token):
    """Parse a CSP host-source, never a keyword, nonce, hash, or URL path."""
    if not token or token[0] in "'\"" or token in {"*", "data:", "blob:"}:
        return ""
    try:
        parsed = urlsplit(token if "://" in token else "https://" + token)
        if parsed.scheme not in {"http", "https", "ws", "wss"} or parsed.username or parsed.password:
            return ""
        # CSP permits wildcard ports; urlsplit.port intentionally cannot parse it.
        authority = parsed.netloc
        if ":" in authority and not authority.startswith("["):
            port = authority.rsplit(":", 1)[1]
            if port != "*" and (not port.isdigit() or not 0 < int(port) <= 65535):
                return ""
        host = (parsed.hostname or "").removeprefix("*.").rstrip(".").lower()
        host = host.encode("idna").decode("ascii")
        return host if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) else ""
    except (ValueError, UnicodeError):
        return ""


def _subdomain(host, domain):
    return host == domain or host.endswith("." + domain)


def _implied(direct):
    """Breadth-first closure with visited keys makes cycles and diamonds finite."""
    seen = set(direct)
    pending = deque(direct)
    result = []
    while pending and len(result) < FINDING_LIMIT:
        parent = pending.popleft()
        for key in IMPLIES.get(parent, ()):
            if key in seen or key not in _TECH:
                continue
            seen.add(key)
            pending.append(key)
            parent_name = _TECH[parent][3]
            result.append(_finding(key, "implied", "Dependency implied by " + parent_name,
                                   confidence=0.65, status="implied_dependency", implied_by=[parent_name]))
    return result


def analyze_http_response(url, headers, html, *, cookie_names=()):
    """Return at most 100 conservative findings from one already-fetched page."""
    lower = _headers(headers)
    if isinstance(html, bytes):
        sample = html[:HTML_LIMIT].decode("utf-8", errors="replace")
    else:
        sample = str(html or "")[:HTML_LIMIT].encode("utf-8")[:HTML_LIMIT].decode("utf-8", errors="ignore")
    page = _Page(sample)
    direct = {}

    def add(key, kind, evidence, version="", confidence=0.9):
        row = _finding(key, kind, evidence, version, confidence)
        old = direct.get(key)
        if old is None or (bool(row["version"]), row["confidence"]) > (bool(old["version"]), old["confidence"]):
            direct[key] = row

    header_rules = (
        ("server", rf"\bnginx(?:/({VERSION}))?(?=[\s;()]|$)", "nginx"),
        ("server", rf"\bApache(?:/({VERSION}))?(?=[\s;()]|$)(?!\s+Tomcat\b)", "apache"),
        ("server", rf"\bMicrosoft-IIS(?:/({VERSION}))?(?=[\s;()]|$)", "iis"),
        ("server", rf"\bApache Tomcat(?:/({VERSION}))?(?=[\s;()]|$)", "tomcat"),
        ("server", rf"\bVarnish(?:/({VERSION}))?(?=[\s;()]|$)", "varnish"),
        ("x-powered-by", rf"\bPHP(?:/({VERSION}))?(?=[\s;,()]|$)", "php"),
        ("x-powered-by", rf"\bASP\.NET(?:/({VERSION}))?(?=[\s;,()]|$)", "aspnet"),
        ("x-powered-by", rf"\bExpress(?:/({VERSION}))?(?=[\s;,()]|$)", "express"),
        ("x-powered-by", rf"\bNext\.js(?:[ /]+v?({VERSION}))?(?=[\s;,()]|$)", "nextjs"),
        ("server", r"^\s*cloudflare\s*$", "cloudflare"),
        ("via", r"\bCloudFront\b", "cloudfront"),
        ("x-cdn", r"\bIncapsula\b", "incapsula"),
    )
    for name, pattern, key in header_rules:
        for value in lower.get(name, ()):
            match = re.search(pattern, value, re.I)
            if match:
                version = match.group(1) if match.lastindex else ""
                add(key, "header", "HTTP " + name + ": " + _TECH[key][3] + (" " + version if version else ""), version, 0.96)
    for name, key in (("cf-ray", "cloudflare"), ("x-amz-cf-id", "cloudfront"), ("x-amz-cf-pop", "cloudfront"),
                      ("x-iinfo", "incapsula"), ("x-varnish", "varnish")):
        if any(value.strip() for value in lower.get(name, ())):
            add(key, "header", "HTTP " + name + " header present", confidence=0.9)
    for value in lower.get("x-aspnet-version", ()):
        if _version(value.strip()):
            add("aspnet", "header", "HTTP x-aspnet-version: " + value.strip(), value.strip(), 0.96)

    cookie_rules = ((r"__cf_bm|cf_clearance", "cloudflare"), (r"incap_ses_[\w-]+|visid_incap_[\w-]+", "incapsula"),
                    (r"laravel_session", "laravel"), (r"JSESSIONID", "servlet"), (r"ASP\.NET_SessionId", "aspnet"),
                    (r"SVPNCOOKIE", "fortios"), (r"NSC_AAAC|NSC_TMAA", "citrix"), (r"_dd_s", "datadog_rum"))
    names = {str(name)[:200] for name in islice(cookie_names, 500)}
    names.update(match.group(1) for value in lower.get("set-cookie", ()) for match in _COOKIE.finditer(value))
    for name in sorted(names):
        for pattern, key in cookie_rules:
            if re.fullmatch(pattern, name, re.I):
                add(key, "cookie", "Set-Cookie name: " + name[:100], confidence=0.8)

    for tag, attrs in page.tags:
        if tag == "meta" and str(attrs.get("name") or "").lower() in {"generator", "application-name"}:
            content = attrs.get("content") or ""
            for name, key in (("WordPress", "wordpress"), ("Drupal", "drupal"), ("Joomla!?", "joomla")):
                match = re.fullmatch(rf"\s*{name}(?:\s+({VERSION}))?(?:\s*[-;].*)?\s*", content, re.I)
                if match:
                    version = match.group(1) or ""
                    add(key, "meta", "meta " + attrs["name"].lower() + ": " + _TECH[key][3] + (" " + version if version else ""), version, 0.95)
        if "ng-version" in attrs and _version(attrs["ng-version"]):
            version = attrs["ng-version"]
            add("angular", "dom", "DOM ng-version=" + version, version, 0.94)
        if tag == "script" and attrs.get("id") == "__NEXT_DATA__":
            add("nextjs", "dom", "script id=__NEXT_DATA__", confidence=0.92)
        if attrs.get("id") == "PanGlobalProtect":
            add("globalprotect", "dom", "DOM id=PanGlobalProtect", confidence=0.9)
        resource = attrs.get("src") if tag in {"script", "img"} else attrs.get("href") if tag == "link" else attrs.get("action") if tag == "form" else None
        if not resource:
            continue
        try:
            parsed = urlsplit(urljoin(url, resource))
            host, path = (parsed.hostname or "").lower().rstrip("."), parsed.path
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
                continue
        except ValueError:
            continue
        if tag in {"script", "link"}:
            if path.startswith("/_next/static/"):
                add("nextjs", "script", "resource path /_next/static/")
            if "/wp-content/" in path or "/wp-includes/" in path:
                add("wordpress", "script", "resource path /wp-content/ or /wp-includes/")
            if "/sites/default/" in path and "drupal" in path.lower():
                add("drupal", "script", "Drupal resource under /sites/default/")
        if tag == "script":
            jquery = re.search(rf"(?:^|[/@-])jquery(?:[/-]v?({VERSION}))?(?:\.min)?\.js$", path, re.I)
            packaged = re.search(rf"/(?:jquery@|jquery/)({VERSION})/", path, re.I)
            if jquery or packaged:
                version = (jquery.group(1) if jquery else "") or (packaged.group(1) if packaged else "") or ""
                add("jquery", "script", "jQuery script" + (" " + version if version else ""), version)
            if host == "js.stripe.com" and path.startswith("/v3/"):
                add("stripe", "script", "script host js.stripe.com path /v3/")
            if host == "browser.sentry-cdn.com":
                match = re.match(rf"/({VERSION})/", path)
                version = match.group(1) if match else ""
                add("sentry_sdk", "script", "Sentry browser SDK from browser.sentry-cdn.com" + (" " + version if version else ""), version)
            if (host in {"www.datadoghq-browser-agent.com", "www.datadog-browser-agent.com"} and "datadog-rum" in path
                    or re.search(r"(?:^|/)datadog-rum(?:[-./]|$)", path)):
                add("datadog_rum", "script", "Datadog RUM script signature")
        if tag == "form" and path == "/global-protect/login.esp":
            add("globalprotect", "dom", "form action path /global-protect/login.esp")

    inline = "\n".join(page.inline)
    for pattern, key, evidence in ((r"\bwindow\.__NEXT_DATA__\s*=", "nextjs", "window.__NEXT_DATA__ assignment"),
                                   (r"\bSentry\.init\s*\(", "sentry_sdk", "Sentry.init browser SDK call"),
                                   (r"\bDD_RUM\.init\s*\(", "datadog_rum", "DD_RUM.init call"),
                                   (r"\bPanGlobalProtect\b", "globalprotect", "PanGlobalProtect script signature")):
        if re.search(pattern, inline):
            add(key, "script", evidence, confidence=0.85)
    title = " ".join(page.title).strip()
    for pattern, key in ((rf"(?:MikroTik\s+)?RouterOS(?:\s+v?({VERSION}))?(?:\s+-\s+.*)?", "routeros"),
                         (rf"Apache Tomcat(?:/({VERSION}))?", "tomcat")):
        match = re.fullmatch(pattern, title, re.I)
        if match:
            version = match.group(1) or ""
            add(key, "html", "page title: " + _TECH[key][3] + (" " + version if version else ""), version)
    if re.fullmatch(r"(?:Citrix|NetScaler) Gateway", title, re.I):
        add("citrix", "html", "page title: Citrix / NetScaler Gateway")
    if (re.search(r"\bForti(?:Gate|net)\b", title, re.I)
            and any(tag == "form" and str(attrs.get("action") or "").split("?")[0] == "/remote/login" for tag, attrs in page.tags)):
        add("fortios", "dom", "Fortinet page title and /remote/login form")

    result = list(direct.values()) + _implied(direct)
    csp_seen = set()
    for policy in lower.get("content-security-policy", ()):
        # Comma-separated policies are independently enforced; a repeated
        # directive within one policy uses its first occurrence.
        for policy_part in policy.split(","):
            directives_seen = set()
            for directive in policy_part.split(";"):
                words = directive.split()
                if not words:
                    continue
                name = words[0].lower()
                if name not in _CSP_DIRECTIVES or name in directives_seen:
                    continue
                directives_seen.add(name)
                if "'none'" in words[1:] and len(words) == 2:
                    continue
                for token in words[1:]:
                    host = _host_source(token)
                    for domain, key in CSP_DOMAINS.items():
                        if key not in csp_seen and _subdomain(host, domain):
                            csp_seen.add(key)
                            result.append(_finding(key, "csp", "CSP " + name + " allows host " + host,
                                                   confidence=0.6, status="csp_integration",
                                                   csp_directive=name, matched_host=host))
    return result[:FINDING_LIMIT]
