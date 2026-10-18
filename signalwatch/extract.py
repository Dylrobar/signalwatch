import calendar
import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
from bs4 import BeautifulSoup

from .matching import normalize


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
VERSION = r"[0-9]+(?:\.[0-9]+){0,4}(?:[-+][0-9A-Za-z_.-]+)?"


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")



def canonical_url(value):
    try:
        parts = urlsplit(value.strip())
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return ""
        host = parts.hostname.encode("idna").decode().lower().rstrip(".")
        netloc = f"[{host}]" if ":" in host else host
        port = parts.port
        if port and not (parts.scheme.lower() == "http" and port == 80 or parts.scheme.lower() == "https" and port == 443):
            netloc += f":{port}"
        query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not k.lower().startswith("utm_") and k.lower() not in {"fbclid", "gclid", "mc_cid", "mc_eid"}]
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", urlencode(query), ""))
    except (ValueError, UnicodeError):
        return ""


def open_payload(path):
    path = Path(path)
    with path.open("rb") as handle:
        compressed = handle.read(2) == b"\x1f\x8b"
    return gzip.open(path, "rb") if compressed else path.open("rb")


def read_json(path):
    with open_payload(path) as stream:
        return json.load(stream)


def cpe_parts(criteria):
    fields = []
    field = []
    escaped = False
    for character in criteria:
        if character == ":" and not escaped:
            fields.append("".join(field))
            field = []
        else:
            field.append(character)
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    fields.append("".join(field))
    if len(fields) < 6 or fields[:2] != ["cpe", "2.3"]:
        return None
    unescape = lambda value: re.sub(r"\\(.)", r"\1", value)
    return {"part": fields[2], "vendor": unescape(fields[3]), "product": unescape(fields[4]), "version": unescape(fields[5])}


def parse_nvd(cve):
    affected = []
    def visit(value):
        if isinstance(value, dict):
            for match in value.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                parts = cpe_parts(criteria)
                if parts:
                    record = {**parts, "criteria": criteria}
                    for field in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                        if match.get(field):
                            record[field] = match[field]
                    affected.append(record)
            for key, child in value.items():
                if key != "cpeMatch" and isinstance(child, (list, dict)):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    configurations = cve.get("configurations", [])
    visit(configurations)
    summary = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    severity = None
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = sorted(metrics.get(name, []), key=lambda row: row.get("type") != "Primary")
        if candidates:
            severity = candidates[0].get("cvssData", {}).get("baseScore")
            if severity is not None:
                severity = float(severity)
                break
    identifier = cve["id"].upper()
    return {
        "id": identifier, "aliases": [identifier], "title": identifier,
        "summary": summary, "published": cve.get("published"), "modified": cve.get("lastModified"),
        "severity": severity, "source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{identifier}",
        "affected": affected, "configurations": configurations,
        "references": [r["url"] for r in cve.get("references", []) if r.get("url")],
        "rejected": cve.get("vulnStatus", "").lower() == "rejected",
    }


def product_entities(affected, source_url, observed_at=None):
    observed_at = observed_at or utcnow()
    products = {}
    for item in affected:
        vendor, product, part = item.get("vendor", ""), item.get("product", ""), item.get("part", "a")
        if not vendor or not product or vendor in ("*", "-") or product in ("*", "-"):
            continue
        identifier = f"cpe:{part}:{normalize(vendor)}:{normalize(product)}"
        products[identifier] = {
            "id": identifier, "kind": {"o": "os", "h": "device"}.get(part, "technology"),
            "name": product.replace("_", " "), "value": f"{vendor}:{product}",
            "metadata": {"vendor": vendor, "product": product, "part": part, "catalog": True},
            "source_url": source_url, "observed_at": observed_at, "confidence": 1.0,
        }
    return list(products.values())


def parse_feed(path, source, feed_url):
    with open_payload(path) as handle:
        parsed = feedparser.parse(handle.read())
    if not str(parsed.get("version", "")).startswith(("rss", "atom")):
        raise ValueError(f"Expected RSS or Atom feed: {feed_url}")
    articles = {}
    for entry in parsed.entries:
        url = canonical_url(entry.get("link") or entry.get("id", ""))
        if not url:
            continue
        title = BeautifulSoup(entry.get("title", ""), "html.parser").get_text(" ", strip=True)
        summary = BeautifulSoup(entry.get("summary", ""), "html.parser").get_text(" ", strip=True)[:12000]
        date = entry.get("published_parsed") or entry.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(date), timezone.utc).isoformat() if date else None
        articles[url] = {
            "url": url, "title": title, "summary": summary, "published": published,
            "source": source, "cves": sorted(set(c.upper() for c in CVE_RE.findall(title + " " + summary))),
            "guid": entry.get("id", url), "feed_url": feed_url,
        }
    if not parsed.entries and parsed.get("bozo"):
        raise ValueError(f"Invalid feed {feed_url}: {parsed.get('bozo_exception')}")
    return list(articles.values())


def fingerprint_page(url, html, headers):
    soup = BeautifulSoup(html, "html.parser")
    lower_headers = {key.lower(): value for key, value in headers.items()}
    host = urlsplit(url).hostname
    observed = utcnow()
    found = {}
    def add(vendor, product, version, evidence, confidence=0.9, part="a"):
        key = (vendor, product)
        if key in found and (found[key].get("version") or not version):
            return
        version = version.strip().rstrip(".;,") if version else None
        cpe_product = product.replace("!", "\\!").replace(":", "\\:")
        criteria = f"cpe:2.3:{part}:{vendor}:{cpe_product}:{version or '*'}:*:*:*:*:*:*:*"
        found[key] = {
            "asset_id": f"domain:{host}", "vendor": vendor, "product": product,
            "version": version, "cpe": criteria, "source_url": url,
            "evidence": evidence[:500], "observed_at": observed, "confidence": confidence,
        }
    server = lower_headers.get("server", "")
    powered = lower_headers.get("x-powered-by", "")
    for text, pattern, vendor, product in (
        (server, r"\bnginx(?:/([\w.~-]+))?", "f5", "nginx"),
        (server, r"\bApache(?:/([\w.~-]+))?", "apache", "http_server"),
        (server, r"\bMicrosoft-IIS(?:/([\w.~-]+))?", "microsoft", "internet_information_services"),
        (powered, r"\bPHP(?:/([\w.~-]+))?", "php", "php"),
        (powered, r"\bASP\.NET(?:/([\w.~-]+))?", "microsoft", "asp.net"),
        (powered, r"\bExpress\b(?:/([\w.~-]+))?", "expressjs", "express"),
    ):
        match = re.search(pattern, text, re.I)
        if match:
            add(vendor, product, match.group(1), f"HTTP header: {text}", 0.95)
    generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if generator:
        content = str(generator.get("content", ""))
        for pattern, vendor, product in (
            (rf"\bWordPress(?:\s+({VERSION}))?", "wordpress", "wordpress"),
            (rf"\bDrupal(?:\s+({VERSION}))?", "drupal", "drupal"),
            (rf"\bJoomla!?(?:\s+({VERSION}))?", "joomla", "joomla!"),
        ):
            match = re.search(pattern, content, re.I)
            if match:
                add(vendor, product, match.group(1), f"meta generator: {content}", 0.95)
    for tag in soup.find_all(["script", "link"], limit=500):
        resource = str(tag.get("src") or tag.get("href") or "")
        if not resource:
            continue
        if "/wp-content/" in resource or "/wp-includes/" in resource:
            add("wordpress", "wordpress", None, f"resource: {resource}")
        jquery = re.search(rf"(?:^|[/@-])jquery(?:[/-](?:v)?({VERSION}))?(?:\.min)?\.js(?:[?#]|$)", resource, re.I)
        if jquery:
            add("jquery", "jquery", jquery.group(1), f"resource: {resource}")
        elif re.search(r"/(?:jquery@|jquery/)(\d[^/]+)/", resource, re.I):
            version = re.search(r"/(?:jquery@|jquery/)(\d[^/]+)/", resource, re.I).group(1)
            add("jquery", "jquery", version, f"resource: {resource}")
        if "/_next/static/" in resource:
            add("vercel", "next.js", None, f"resource: {resource}")
        if "/sites/default/" in resource and "drupal" in resource.lower():
            add("drupal", "drupal", None, f"resource: {resource}")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    router = re.fullmatch(rf"(?:MikroTik\s+)?RouterOS(?:\s+v?({VERSION}))?(?:\s+-\s+.*)?", title, re.I)
    if router:
        add("mikrotik", "routeros", router.group(1), f"page title: {title}", 0.9, "o")
    if ("f5", "nginx") in found:
        legacy = dict(found[("f5", "nginx")])
        legacy["vendor"] = "nginx"
        legacy["cpe"] = legacy["cpe"].replace(":f5:nginx:", ":nginx:nginx:", 1)
        found[("nginx", "nginx")] = legacy
    return list(found.values())
