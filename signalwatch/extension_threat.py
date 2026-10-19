import asyncio
import calendar
import csv
import hashlib
import heapq
import io
import ipaddress
import json
import os
import re
from email.parser import Parser
from email.utils import parsedate_to_datetime
from urllib.robotparser import RobotFileParser
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlsplit

import feedparser
from bs4 import BeautifulSoup

from .extract import CVE_RE, canonical_url, utcnow
from .signal_filter import qualify_signal


SOURCE_DEFINITIONS = [
    {"id": "fulldisclosure", "name": "Full Disclosure", "category": "threat", "family": "threat", "access": "public", "description": "Public disclosure mailing-list RSS; claims remain attributed news evidence.", "homepage": "https://seclists.org/fulldisclosure/", "required": []},
    {"id": "oss_security", "name": "OSS-Security", "category": "threat", "family": "threat", "access": "public", "description": "Public open-source security mailing-list RSS.", "homepage": "https://seclists.org/oss-sec/", "required": []},
    {"id": "zdi_upcoming", "name": "ZDI Upcoming Advisories", "category": "threat", "family": "threat", "access": "public", "description": "Upcoming vendor-notified disclosures; no CVE or exploitability is invented.", "homepage": "https://www.zerodayinitiative.com/rss/", "required": []},
    {"id": "zdi_published", "name": "ZDI Published Advisories", "category": "threat", "family": "threat", "access": "public", "description": "Published ZDI advisory RSS, retained as source-attributed articles.", "homepage": "https://www.zerodayinitiative.com/rss/", "required": []},
    {"id": "zdi_blog", "name": "ZDI Research Blog", "category": "threat", "family": "threat", "access": "public", "description": "Public ZDI research blog RSS.", "homepage": "https://www.zerodayinitiative.com/rss/", "required": []},
    {"id": "dark_reading", "name": "Dark Reading", "category": "threat", "family": "threat", "access": "public", "description": "Public cybersecurity news RSS with product and exploit keyword qualification.", "homepage": "https://www.darkreading.com/", "required": []},
    {"id": "apple_security", "name": "Apple Security Releases", "category": "threat", "family": "threat", "access": "public", "description": "Bounded parsing of Apple's official security-release index; not a pre-release feed.", "homepage": "https://support.apple.com/en-us/100100", "required": []},
    {"id": "cisco_psirt", "name": "Cisco PSIRT", "category": "threat", "family": "threat", "access": "public", "description": "Official Cisco advisory RSS; unavailable/challenge HTML is a collection error.", "homepage": "https://sec.cloudapps.cisco.com/security/center/rss.x", "required": []},
    {"id": "oss_fuzz", "name": "OSS-Fuzz Public Disclosures", "category": "threat", "family": "threat", "access": "configured_url", "description": "Public issue RSS/JSON export or imported disclosure records; private bugs are not collected.", "homepage": "https://google.github.io/oss-fuzz/getting-started/bug-disclosure-guidelines/", "required": ["url"]},
    {"id": "exploit_db", "name": "Exploit-DB", "category": "threat", "family": "threat", "access": "configured_url", "description": "CSV reference-index or RSS import; no exploit programs are downloaded or executed.", "homepage": "https://gitlab.com/exploit-database/exploitdb", "required": ["url"]},
    {"id": "greynoise", "name": "GreyNoise Community IP Lookup", "category": "threat", "family": "threat", "access": "api_key", "description": "Bounded configured public IPv4 lookups; Community API is not a global threat feed.", "homepage": "https://docs.greynoise.io/reference/getcommunityip", "required": ["api_key", "ips"]},
    {"id": "urlhaus", "name": "URLhaus", "category": "threat", "family": "threat", "access": "api_key", "description": "Authenticated recent CSV export; malware URLs remain indicators and are never visited.", "homepage": "https://urlhaus.abuse.ch/api/", "required": ["api_key"]},
    {"id": "vulncheck", "name": "VulnCheck KEV", "category": "threat", "family": "threat", "access": "api_key", "description": "Credentialed KEV API/export records retain VulnCheck attribution, independently of CISA KEV state.", "homepage": "https://docs.vulncheck.com/community/vulncheck-kev/schema", "required": ["api_key"]},
    {"id": "attackerkb", "name": "AttackerKB", "category": "threat", "family": "threat", "access": "api_key", "description": "Credentialed public topic records and assessments; community claims are evidence.", "homepage": "https://api.attackerkb.com/v1/api-docs/docs", "required": ["api_key"]},
    {"id": "packet_storm", "name": "Packet Storm", "category": "threat", "family": "threat", "access": "configured_url", "description": "Configure a working public RSS/export URL or import records; no obsolete feed is assumed live.", "homepage": "https://packetstorm.news/", "required": ["url"]},
    {"id": "hackerone_hacktivity", "name": "HackerOne Hacktivity", "category": "threat", "family": "threat", "access": "import", "description": "Import publicly disclosed report exports; no unrestricted global Hacktivity API is assumed.", "homepage": "https://hackerone.com/hacktivity", "required": ["import"]},
    {"id": "redhat_security", "name": "Red Hat Security Data", "category": "threat", "family": "threat", "access": "configured_url", "description": "Bounded JSON/RSS security data URL or import; existing CSAF collectors remain independent.", "homepage": "https://access.redhat.com/security/data", "required": ["url"]},
    {"id": "ubuntu_launchpad", "name": "Ubuntu Launchpad Security Bugs", "category": "threat", "family": "threat", "access": "configured_url", "description": "Configured public bug-query RSS/JSON export; Ubuntu Security Notices already have native RSS coverage.", "homepage": "https://bugs.launchpad.net/ubuntu", "required": ["url"]},
    {"id": "debian_tracker", "name": "Debian Security Tracker", "category": "threat", "family": "threat", "access": "configured_url", "description": "Bounded tracker JSON export or import preserves distribution release/fix context; native DSA RSS is separate.", "homepage": "https://security-tracker.debian.org/tracker/", "required": ["url"]},
    {"id": "shadowserver", "name": "Shadowserver", "category": "threat", "family": "threat", "access": "import", "description": "Import public aggregate telemetry or reports supplied to the operator; no unrestricted global device feed is assumed.", "homepage": "https://www.shadowserver.org/what-we-do/network-reporting/", "required": ["import"]},
    {"id": "anyrun", "name": "ANY.RUN", "category": "threat", "family": "threat", "access": "import", "description": "Public analysis/report export import; service-specific API subscriptions are not treated as free feeds.", "homepage": "https://any.run/cybersecurity-blog/api-documentation/", "required": ["import"]},
    {"id": "hybrid_analysis", "name": "Hybrid Analysis", "category": "threat", "family": "threat", "access": "import", "description": "Public report export import; deprecated feed/latest endpoint is not assumed operational.", "homepage": "https://www.hybrid-analysis.com/docs/api/v2-changelog", "required": ["import"]},
    {"id": "reddit_netsec", "name": "Reddit r/netsec", "category": "threat", "family": "threat", "access": "api_key", "description": "OAuth-authorized public listing; watched product AND exploit/patch indicator required for article qualification.", "homepage": "https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki", "required": ["api_key", "watch_products"]},
    {"id": "reddit_sysadmin", "name": "Reddit r/sysadmin", "category": "threat", "family": "threat", "access": "api_key", "description": "OAuth-authorized public listing; unqualified posts remain source records rather than news articles.", "homepage": "https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki", "required": ["api_key", "watch_products"]},
    {"id": "mastodon", "name": "Mastodon Public Hashtag", "category": "threat", "family": "threat", "access": "configured_url", "description": "Configure an instance's public hashtag/timeline JSON URL; instance policies may require credentials.", "homepage": "https://docs.joinmastodon.org/client/public/", "required": ["url", "watch_products"]},
    {"id": "bluesky", "name": "Bluesky Public Search", "category": "threat", "family": "threat", "access": "public", "description": "Configured public search query; service may require authentication or deny search access.", "homepage": "https://docs.bsky.app/docs/api/app-bsky-feed-search-posts", "required": ["query", "watch_products"]},
]

FEEDS = {
    "fulldisclosure": "https://seclists.org/rss/fulldisclosure.rss",
    "oss_security": "https://seclists.org/rss/oss-sec.rss",
    "zdi_upcoming": "https://www.zerodayinitiative.com/rss/upcoming/",
    "zdi_published": "https://www.zerodayinitiative.com/rss/published/",
    "zdi_blog": "https://www.zerodayinitiative.com/blog/?format=rss",
    "dark_reading": "https://www.darkreading.com/rss.xml",
    "cisco_psirt": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
}
SOCIAL = frozenset({"reddit_netsec", "reddit_sysadmin", "mastodon", "bluesky"})
DEFINITIONS = {value["id"]: value for value in SOURCE_DEFINITIONS}


ARCHIVES = {
    "oss_security": ("https://www.openwall.com/lists/oss-security/", "oss-security"),
    "fulldisclosure": ("https://lists.openwall.net/full-disclosure/", "full-disclosure"),
}


def _archive_url(provider, url, *, message=False):
    from .normalization import NormalizationError
    root, _ = ARCHIVES[provider]
    parsed, expected = urlsplit(url), urlsplit(root)
    suffix = parsed.path.removeprefix(expected.path)
    if (parsed.scheme != "https" or parsed.netloc != expected.netloc or parsed.query or parsed.fragment
            or not parsed.path.startswith(expected.path) or (message and not re.fullmatch(r"\d{4}/\d{2}/\d{2}/[1-9]\d*", suffix))
            or (not message and parsed.path != expected.path)):
        raise NormalizationError("Unexpected mailing-list archive location")
    return url


def _archive_links(payload, provider, source_url, limit):
    from .normalization import NormalizationError
    _archive_url(provider, source_url)
    page = BeautifulSoup(payload, "html.parser")
    _, name = ARCHIVES[provider]
    heading = page.find("h2")
    if not heading or heading.get_text(" ", strip=True) != name + " mailing list":
        raise NormalizationError("Unexpected mailing-list archive index")
    links = set()
    for anchor in page.select("li a[href]"):
        url = urljoin(source_url, anchor["href"])
        try:
            _archive_url(provider, url, message=True)
            parts = urlsplit(url).path.split("/")[-4:]
            datetime.strptime("/".join(parts[:3]), "%Y/%m/%d")
        except (NormalizationError, ValueError):
            continue
        if anchor.get_text(" ", strip=True):
            links.add(url)
    if not links:
        raise NormalizationError("Mailing-list archive index has no allowed message links")
    return sorted(links, key=lambda url: tuple(int(part) for part in urlsplit(url).path.split("/")[-4:]), reverse=True)[:limit]


def _archive_record(payload, provider, source_url):
    from .normalization import NormalizationError
    _archive_url(provider, source_url, message=True)
    page = BeautifulSoup(payload, "html.parser")
    _, name = ARCHIVES[provider]
    blocks = page.find_all("pre")
    if not page.title or not page.title.get_text().startswith(name + " - ") or len(blocks) != 1:
        raise NormalizationError("Unexpected mailing-list archive message")
    message = Parser().parsestr(blocks[0].get_text().lstrip())
    subject, date = message.get("Subject"), message.get("Date")
    if not subject or not date or not message.get("From") or not message.get("Message-ID"):
        raise NormalizationError("Mailing-list archive message lacks mail headers")
    try:
        published = parsedate_to_datetime(date)
        if published.tzinfo is None:
            raise ValueError("Missing date timezone")
        published = published.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError) as error:
        raise NormalizationError("Mailing-list archive message has invalid published date") from error
    return {"id": source_url, "url": source_url, "title": " ".join(subject.split())[:1000],
            "summary": str(message.get_payload())[:12000], "published": published,
            "record_type": "news", "claim_type": "attributed_mailing_list_claim",
            "message_id": message.get("Message-ID")}


async def _archive_fallback(config, store, http, provider, limit, max_bytes, metadata):
    from .http import HTTPError, public_error
    from .sourcehub import stage_payload
    root, _ = ARCHIVES[provider]
    robots_url = urljoin(root, "/robots.txt")
    parser = RobotFileParser(robots_url)
    try:
        response = await http.get(robots_url, max_bytes=min(max_bytes, 128 * 1024), max_attempts=2, allow_redirects=False)
        if response.status not in (200, 304):
            raise ValueError("Unexpected mailing-list archive robots response")
        robots = await asyncio.to_thread(response.path.read_bytes)
        parser.parse(robots.decode("utf-8").splitlines())
    except HTTPError as error:
        if error.status != 404:
            raise
        parser.parse([])
    agent = config.get("user_agent") or "SignalWatch"
    if not parser.can_fetch(agent, root):
        raise ValueError("Mailing-list archive robots.txt disallows automated access")
    # One recent index and at most eight messages; no calendar/history traversal,
    # off-origin redirects, attachments or links found inside message bodies.
    response = await http.get(root, max_bytes=min(max_bytes, 1024 * 1024), max_attempts=2, allow_redirects=False)
    if response.status not in (200, 304):
        raise ValueError("Unexpected mailing-list archive index response")
    _archive_url(provider, response.url)
    payload = await asyncio.to_thread(response.path.read_bytes)
    urls = _archive_links(payload, provider, root, min(limit, 8))
    index_metadata = {**metadata, "format": "mail_archive_index"}
    queued = await stage_payload(config, store, payload, provider=provider, source_url=root, content_type="text/html",
                                 stream_key=provider + ":archive:index", metadata=index_metadata)
    staged, duplicates = int(not queued.get("duplicate")), int(bool(queued.get("duplicate")))
    records, errors = [], []
    for url in urls:
        try:
            if not parser.can_fetch(agent, url):
                raise ValueError("Mailing-list archive robots.txt disallows automated access")
            response = await http.get(url, max_bytes=min(max_bytes, 512 * 1024), max_attempts=2, allow_redirects=False)
            if response.status not in (200, 304):
                raise ValueError("Unexpected mailing-list archive message response")
            _archive_url(provider, response.url, message=True)
            if response.url != url:
                raise ValueError("Unexpected mailing-list archive message location")
            payload = await asyncio.to_thread(response.path.read_bytes)
            record = _archive_record(payload, provider, url)
            queued = await stage_payload(config, store, payload, provider=provider, source_url=url, content_type="text/html",
                                         stream_key=provider + ":archive:" + url, metadata={**metadata, "format": "mail_archive_message"})
            staged += int(not queued.get("duplicate"))
            duplicates += int(bool(queued.get("duplicate")))
            records.append(record)
        except Exception as error:
            errors.append(public_error(error))
    return records, staged, duplicates, errors


def _clean(value, maximum=12000):
    return BeautifulSoup(str(value or ""), "html.parser").get_text(" ", strip=True)[:maximum]


def _json(payload):
    from .normalization import NormalizationError
    try:
        return json.loads(payload.decode("utf-8-sig"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise NormalizationError("Public source did not return valid UTF-8 JSON") from error


def _published(value):
    if not value:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            return None
    return str(value)[:100]


def _feed_records(payload, limit):
    from .normalization import NormalizationError
    parsed = feedparser.parse(payload)
    if not str(parsed.get("version", "")).startswith(("rss", "atom")) or parsed.get("bozo"):
        raise NormalizationError("Public source returned invalid RSS/Atom or an HTML error page")
    records = []
    for entry in parsed.entries[:limit]:
        date = entry.get("published_parsed") or entry.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(date), timezone.utc).isoformat() if date else None
        records.append({"id": entry.get("id") or entry.get("link"), "url": canonical_url(entry.get("link") or entry.get("id") or ""),
                        "title": _clean(entry.get("title"), 1000), "summary": _clean(entry.get("summary")), "published": published, "record_type": "news"})
    return records


def _apple_records(payload, source_url, limit):
    from .normalization import NormalizationError
    page = BeautifulSoup(payload, "html.parser")
    heading = page.find("h1")
    if not heading or "apple security releases" not in heading.get_text(" ", strip=True).lower():
        raise NormalizationError("Apple source returned an unexpected index or error page")
    records = []
    for table in page.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) < 3:
                continue
            link = cells[0].find("a", href=True)
            if not link:
                continue
            url = canonical_url(urljoin(source_url, link["href"]))
            if urlsplit(url).hostname != "support.apple.com":
                continue
            released = cells[-1].get_text(" ", strip=True)
            try:
                released = datetime.strptime(released, "%d %b %Y").replace(tzinfo=timezone.utc).date().isoformat()
            except ValueError:
                released = None
            records.append({"id": url, "url": url, "title": cells[0].get_text(" ", strip=True)[:1000],
                            "summary": " ".join(cell.get_text(" ", strip=True) for cell in cells)[:12000], "published": released})
            if len(records) >= limit:
                return records
    if not page.find("table"):
        raise NormalizationError("Apple security-release index has no release table")
    return records


def _csv_records(payload, provider, limit):
    from .normalization import NormalizationError
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError as error:
        raise NormalizationError("CSV source requires UTF-8 text") from error
    if provider == "urlhaus":
        lines = text.splitlines()
        header = next((line.lstrip("# ") for line in lines if line.lstrip("# ").lower().startswith(("id,", '"id",'))), None)
        body = "\n".join(line for line in lines if line.strip() and not line.startswith("#"))
        if header and not body.lower().startswith(("id,", '"id",')):
            body = header + "\n" + body
        reader = csv.DictReader(io.StringIO(body))
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise NormalizationError("URLhaus CSV lacks a URL header")
        return [{**row, "title": row.get("threat") or "URLhaus malware URL", "summary": row.get("tags") or "", "record_type": "malware_url"}
                for _, row in zip(range(limit), reader)]
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"id", "description", "file"}.issubset(reader.fieldnames):
        raise NormalizationError("Exploit-DB CSV lacks its reference-index headers")
    rows = heapq.nlargest(limit, reader, key=lambda row: (row.get("date_added") or row.get("date_published") or "", int(row["id"]) if str(row.get("id")).isdigit() else 0))
    return [{**row, "url": "https://www.exploit-db.com/exploits/" + row["id"], "title": row.get("description") or row["id"],
             "summary": " ".join(str(row.get(key) or "") for key in ("description", "codes", "tags", "aliases")),
             "published": row.get("date_published"), "record_type": "exploit_reference"} for row in rows]


def _records(item, limit):
    from .normalization import NormalizationError
    metadata = item.get("metadata") or {}
    provider = metadata.get("provider")
    payload = item["payload"]
    if provider not in DEFINITIONS:
        raise NormalizationError("Unknown public threat-source provider")
    format_name = metadata.get("format", "")
    if format_name == "mail_archive_index":
        _archive_links(payload, provider, item["source_url"], min(limit, 8))
        return []
    if format_name == "mail_archive_message":
        return [_archive_record(payload, provider, item["source_url"])]
    if format_name == "apple_index" or provider == "apple_security":
        return _apple_records(payload, item.get("source_url") or DEFINITIONS[provider]["homepage"], limit)
    if format_name == "csv" or provider in {"urlhaus", "exploit_db"} and not payload.lstrip().startswith((b"{", b"[", b"<")):
        return _csv_records(payload, provider, limit)
    if format_name == "rss" or payload.lstrip().startswith(b"<"):
        return _feed_records(payload, limit)
    value = _json(payload)
    if isinstance(value, dict) and (value.get("error") or value.get("errors") or value.get("success") is False or isinstance(value.get("status"), str) and value["status"] in {"error", "failed"}):
        raise NormalizationError("Public source returned an API error object")
    if provider in {"vulncheck", "attackerkb"} and isinstance(value, dict) and not isinstance(value.get("data"), list):
        raise NormalizationError("Credentialed threat API response lacks its data array")
    if provider == "mastodon" and not isinstance(value, list):
        raise NormalizationError("Mastodon response lacks a public status array")
    if provider == "greynoise":
        if not isinstance(value, dict) or not isinstance(value.get("ip"), str) or not isinstance(value.get("noise"), bool):
            raise NormalizationError("GreyNoise response lacks IP context")
        try:
            address = ipaddress.ip_address(value["ip"])
        except ValueError as error:
            raise NormalizationError("GreyNoise response has an invalid IP") from error
        expected = metadata.get("ip")
        if expected and str(address) != expected:
            raise NormalizationError("GreyNoise response does not match the requested IP")
        return [{**value, "id": str(address), "title": "GreyNoise IP context: " + str(address), "record_type": "ip_context"}]
    if provider in {"reddit_netsec", "reddit_sysadmin"}:
        children = value.get("data", {}).get("children") if isinstance(value, dict) else None
        if not isinstance(children, list):
            raise NormalizationError("Reddit response lacks a public listing")
        return [{**child["data"], "url": canonical_url("https://www.reddit.com" + child["data"].get("permalink", "")),
                 "summary": _clean(child["data"].get("selftext")), "published": _published(child["data"].get("created_utc"))}
                for child in children[:limit] if isinstance(child, dict) and isinstance(child.get("data"), dict)]
    if provider == "bluesky":
        posts = value.get("posts") if isinstance(value, dict) else None
        if not isinstance(posts, list):
            raise NormalizationError("Bluesky response lacks public posts")
        records = []
        for post in posts[:limit]:
            if not isinstance(post, dict) or not isinstance(post.get("record"), dict):
                continue
            uri = str(post.get("uri") or "")
            did, _, key = uri.removeprefix("at://").partition("/app.bsky.feed.post/")
            url = "https://bsky.app/profile/" + quote(did, safe=":") + "/post/" + quote(key, safe="") if did and key else ""
            text = _clean(post["record"].get("text"))
            records.append({"id": uri, "url": url, "title": text[:300], "summary": text, "published": _published(post["record"].get("createdAt"))})
        return records
    if provider == "debian_tracker" and isinstance(value, dict) and not any(key in value for key in ("data", "items", "records")):
        result = []
        for package, issues in value.items():
            if not isinstance(issues, dict):
                continue
            for cve, issue in issues.items():
                if not isinstance(issue, dict):
                    continue
                result.append({**issue, "id": package + ":" + cve, "title": package + ": " + cve, "package": package, "cve": cve,
                               "url": "https://security-tracker.debian.org/tracker/" + quote(cve, safe=""),
                               "summary": issue.get("description") or "", "record_type": "distribution_tracker"})
                if len(result) >= limit:
                    return result
        return result
    if isinstance(value, dict):
        container = next((value[key] for key in ("records", "data", "results", "reports", "issues", "bugs", "entries", "items", "objects") if isinstance(value.get(key), list)), None)
        value = container if container is not None else [value]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise NormalizationError("Threat-source JSON requires an object or an array of objects")
    records = []
    for row in value[:limit]:
        if provider == "oss_fuzz" and (row.get("visibility") in {"private", "restricted"} or row.get("public") is False):
            raise NormalizationError("OSS-Fuzz adapter accepts only public disclosure records")
        row = dict(row)
        if provider == "mastodon":
            row.update(title=_clean(row.get("content"), 300), summary=_clean(row.get("content")), published=_published(row.get("created_at")))
        else:
            row.setdefault("title", row.get("name") or row.get("summary") or row.get("short_desc") or row.get("vulnerabilityName") or row.get("CVE") or row.get("id") or provider)
            row.setdefault("summary", row.get("description") or row.get("shortDescription") or row.get("text") or "")
            row.setdefault("published", row.get("created") or row.get("date_added") or row.get("public_date"))
        if provider == "urlhaus":
            row["record_type"] = "malware_url"
        records.append(row)
    return records


def _context(item, record, signal):
    provider = item["metadata"]["provider"]
    encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    identifier = str(record.get("id") or record.get("url") or hashlib.sha256(encoded.encode()).hexdigest())
    kind = "threat_indicator" if record.get("record_type") in {"malware_url", "ip_context"} else "source_record"
    return {"id": kind + ":" + hashlib.sha256((provider + "\0" + identifier).encode()).hexdigest(), "kind": kind,
            "name": _clean(record.get("title") or identifier, 1000), "value": str(record.get("url") or record.get("ip") or identifier)[:4096],
            "source_url": canonical_url(record.get("url") or record.get("link") or "") or item.get("source_url") or "",
            "observed_at": item.get("observed_at") or item.get("received_at"), "confidence": 1.0,
            "metadata": {"provider": provider, "record_type": record.get("record_type") or "public_threat_record", "qualification": signal,
                         "record": record if len(encoded.encode()) <= 8192 else {"truncated": True, "preview": encoded[:4096]}}}


def normalize_threat(item, max_records=5000):
    from .normalization import _annotate
    metadata = item.get("metadata") or {}
    provider = metadata.get("provider")
    limit = min(max_records, int(metadata.get("record_limit") or 100))
    if limit < 1:
        raise ValueError("Threat normalization record limit must be positive")
    records = _records(item, limit)
    articles, entities, edges = [], [], []
    for record in records:
        if len(articles) + len(entities) + len(edges) >= max_records:
            break
        title = _clean(record.get("title"), 1000)
        summary = _clean(record.get("summary"))
        signal = qualify_signal(title + " " + summary, metadata.get("watch_products") or [], metadata.get("exploit_keywords") or [])
        url = canonical_url(record.get("url") or record.get("link") or "")
        if url and (provider in FEEDS or provider == "apple_security" or provider in SOCIAL and signal["qualified"] or record.get("record_type") in {"exploit_reference", "news"} and provider not in SOCIAL):
            articles.append({"url": url, "title": title, "summary": summary, "published": _published(record.get("published")),
                             "source": DEFINITIONS[provider]["name"], "feed_url": item.get("source_url") or "", "guid": record.get("id") or url,
                             "cves": sorted(set(value.upper() for value in CVE_RE.findall(title + " " + summary))), "_signal": signal})
        else:
            entity = _context(item, record, signal)
            entities.append(entity)
            cves = sorted(set(value.upper() for value in CVE_RE.findall(json.dumps(record, ensure_ascii=False))))
            remaining = max_records - len(articles) - len(entities) - len(edges)
            edges.extend({"from_id": entity["id"], "to_id": cve, "relation": "mentions", "source_url": entity["source_url"],
                          "observed_at": entity["observed_at"], "confidence": 1.0} for cve in cves[:min(20, remaining)])
    batch = _annotate({"articles": articles, "entities": entities, "edges": edges}, item)
    if metadata.get("fallback_used"):
        for article in batch["articles"]:
            # Keep the feed/provider identity; provenance points to the actual archive.
            article["feed_url"] = metadata["primary_source_url"]
            article["_staging"].update({key: metadata[key] for key in
                                      ("fallback_used", "primary_source_url", "primary_error", "claim_type")})
    return batch


def _credential(config, provider):
    value = config.get("provider_credentials", {}).get(provider) or ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("env"), str):
            return os.environ.get(value["env"], "")
        return next((value[key] for key in ("api_key", "token", "key", "auth_key") if isinstance(value.get(key), str) and value[key]), "")
    return ""


def _request(provider, settings, credential, limit):
    headers, params = {"Accept": "application/json"}, {}
    source_url = settings.get("url") or FEEDS.get(provider) or ""
    format_name = "rss" if provider in FEEDS else "json"
    if provider == "apple_security":
        source_url, format_name = settings.get("url") or "https://support.apple.com/en-us/100100", "apple_index"
    elif provider == "greynoise":
        ips = settings.get("ips") or []
        address = ipaddress.ip_address(ips[0])
        if address.version != 4 or not address.is_global:
            raise ValueError("GreyNoise requires routable public IPv4 targets")
        source_url = "https://api.greynoise.io/v3/community/" + str(address)
        headers["key"] = credential
    elif provider == "urlhaus":
        source_url, format_name = "https://urlhaus-api.abuse.ch/v2/files/exports/[redacted]/recent.csv", "csv"
    elif provider == "vulncheck":
        source_url = "https://api.vulncheck.com/v3/index/vulncheck-kev"
        headers["Authorization"] = "Bearer " + credential
        params = {}
    elif provider == "attackerkb":
        source_url = "https://api.attackerkb.com/v1/topics"
        headers["Authorization"] = "Token " + credential
        params = {"size": limit, "sort": "created", "order": "desc"}
    elif provider in {"reddit_netsec", "reddit_sysadmin"}:
        subreddit = provider.removeprefix("reddit_")
        source_url = "https://oauth.reddit.com/r/" + subreddit + "/new"
        headers["Authorization"] = "Bearer " + credential
        params = {"limit": min(limit, 100), "raw_json": 1}
    elif provider == "bluesky":
        source_url = settings.get("url") or "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"
        params = {"q": settings["query"], "limit": min(limit, 100), "sort": "latest"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
    elif provider == "mastodon" and credential:
        headers["Authorization"] = "Bearer " + credential
    if settings.get("format"):
        format_name = settings["format"]
    elif provider not in FEEDS and provider not in {"apple_security", "urlhaus"} and source_url.lower().split("?")[0].endswith((".xml", ".rss", ".atom")):
        format_name = "rss"
    elif provider == "exploit_db":
        format_name = "csv"
    parsed = urlsplit(source_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Provider requires an absolute HTTP(S) source URL")
    request_url = source_url.replace("[redacted]", quote(credential, safe="")) if provider == "urlhaus" else source_url
    return request_url, source_url, headers, params, format_name


async def collect_threat_sources(config, store, http):
    from .sourcehub import stage_payload
    from .http import HTTPError, PublicRequestError, display_url, public_error
    settings_map = config.get("provider_settings") or {}
    products = config.get("watch_products") or []
    indicators = config.get("exploit_keywords") or []
    limit = min(1000, max(1, int(config.get("public_source_records", 100))))
    budget = max(1, int(config.get("threat_source_batch", config.get("public_source_batch", 3))))
    health, ready = {}, []
    for definition in SOURCE_DEFINITIONS:
        provider = definition["id"]
        settings = settings_map.get(provider) or {}
        credential = _credential(config, provider)
        missing = []
        for required in definition["required"]:
            if required == "api_key" and not credential or required == "watch_products" and not products or required not in {"api_key", "watch_products"} and not settings.get(required):
                missing.append(required)
        previous = await asyncio.to_thread(store.source_state, "provider:" + provider)
        if settings.get("enabled") is False:
            health[provider] = {"status": "disabled", "requirements": []}
        elif not settings.get("enabled") or missing:
            health[provider] = {"status": "unconfigured", "requirements": missing or ["enabled"]}
        elif definition["access"] == "import":
            health[provider] = {"status": "unconfigured", "requirements": ["import"]}
        else:
            health[provider] = {**previous, "status": previous.get("status") or "ready", "requirements": []}
            ready.append((provider, settings, credential))
    state = await asyncio.to_thread(store.source_state, "threat_provider_cursor")
    offset = int(state.get("offset") or 0) % max(len(ready), 1)
    selected = (ready[offset:] + ready[:offset])[:budget]
    selected_ids = {provider for provider, _, _ in selected}
    for provider, _, _ in ready:
        if provider not in selected_ids:
            health[provider] = {**health[provider], "status": "partial", "deferred": True, "reason": "Collection deferred by per-cycle request budget"}
    semaphore = asyncio.Semaphore(max(1, min(16, int(config.get("public_source_concurrency", 4)))))
    max_bytes = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)

    async def collect(provider, settings, credential):
        async with semaphore:
            stamp = utcnow()
            staged = None
            try:
                local = dict(settings)
                if provider == "greynoise":
                    old = await asyncio.to_thread(store.source_state, "provider:" + provider)
                    ips = list(settings.get("ips") or [])
                    index = int(old.get("ip_offset") or 0) % len(ips)
                    local["ips"] = [ips[index]]
                request_url, source_url, headers, params, format_name = _request(provider, local, credential, limit)
                metadata = {"provider": provider, "format": format_name, "record_limit": limit, "watch_products": products, "exploit_keywords": indicators}
                try:
                    response = await http.get(request_url, headers=headers, params=params or None, max_bytes=max_bytes,
                                              cache=not bool(credential), allow_redirects=not bool(credential), max_attempts=2)
                except (HTTPError, PublicRequestError) as primary:
                    if provider not in ARCHIVES or local.get("url") or credential:
                        raise
                    # Stable sanitized envelope metadata keeps retries deduplicated.
                    primary_error = (f"HTTP {primary.status}" if isinstance(primary, HTTPError) else primary.reason) + ": " + display_url(request_url)
                    metadata.update(fallback_used=True, primary_source_url=source_url, primary_error=primary_error,
                                    claim_type="attributed_mailing_list_claim")
                    try:
                        records, archive_staged, duplicates, archive_errors = await _archive_fallback(
                            config, store, http, provider, limit, max_bytes, metadata)
                        qualified = sum(qualify_signal(_clean(row["title"]) + " " + _clean(row["summary"]), products, indicators)["qualified"] for row in records)
                        outcome = {"status": "partial" if records else "error", "checked_at": stamp, "deferred": False,
                                   "requirements": [], "staged": archive_staged, "duplicates": duplicates,
                                   "records": len(records), "qualified": qualified, "filtered": len(records) - qualified,
                                   "qualification_only": True, "fallback_used": True, "primary_error": primary_error,
                                   "fallback_source_url": ARCHIVES[provider][0], "errors": archive_errors,
                                   "error": primary_error + ("; " + "; ".join(archive_errors) if archive_errors else "")}
                        if records:
                            outcome["last_success"] = stamp
                    except Exception as fallback:
                        reason = str(fallback) if isinstance(fallback, ValueError) and str(fallback) == "Mailing-list archive robots.txt disallows automated access" else public_error(fallback)
                        outcome = {"status": "error", "checked_at": stamp, "deferred": False, "requirements": [],
                                   "staged": 0, "records": 0, "qualified": 0, "filtered": 0,
                                   "fallback_used": False, "primary_error": primary_error,
                                   "fallback_source_url": ARCHIVES[provider][0], "error": primary_error + "; " + reason}
                    await asyncio.to_thread(store.update_source, "provider:" + provider, **outcome)
                    return provider, outcome
                payload = await asyncio.to_thread(response.path.read_bytes)
                if provider == "greynoise":
                    metadata["ip"] = str(ipaddress.ip_address(local["ips"][0]))
                mime = "application/rss+xml" if format_name == "rss" else "text/html" if format_name == "apple_index" else "text/csv" if format_name == "csv" else "application/json"
                staged = await stage_payload(config, store, payload, provider=provider, source_url=source_url, content_type=mime,
                                             stream_key=provider + (":" + metadata["ip"] if provider == "greynoise" else ""), metadata=metadata)
                item = {"payload": payload, "source_url": source_url, "metadata": metadata}
                records = _records(item, limit)
                reasons = Counter()
                qualified = 0
                for record in records:
                    signal = qualify_signal(_clean(record.get("title")) + " " + _clean(record.get("summary")), products, indicators)
                    qualified += signal["qualified"]
                    reasons.update(signal["reasons"])
                outcome = {"status": "unchanged" if staged.get("duplicate") else "ok", "checked_at": stamp, "last_success": stamp, "deferred": False,
                           "requirements": [], "staged": int(not staged.get("duplicate")), "records": len(records), "qualified": qualified,
                           "filtered": len(records) - qualified, "reason_counts": dict(reasons), "qualification_only": True, "error": ""}
                if provider in ARCHIVES:
                    outcome.update(fallback_used=False, primary_error="", fallback_source_url="", errors=[])
                if provider == "greynoise":
                    outcome["ip_offset"] = index + 1
                await asyncio.to_thread(store.update_source, "provider:" + provider, **outcome)
                return provider, outcome
            except Exception as error:
                detail = f"HTTP {error.status}" if hasattr(error, "status") else str(error)
                if credential:
                    detail = detail.replace(credential, "[redacted]").replace(quote(credential, safe=""), "[redacted]")
                outcome = {"status": "error", "checked_at": stamp, "deferred": False, "requirements": [],
                           "staged": int(staged is not None and not staged.get("duplicate")), "records": 0,
                           "qualified": 0, "filtered": 0, "error": " ".join(detail.split())[:300]}
                await asyncio.to_thread(store.update_source, "provider:" + provider, **outcome)
                return provider, outcome

    results = await asyncio.gather(*(collect(*value) for value in selected))
    health.update(results)
    await asyncio.to_thread(store.update_source, "threat_provider_cursor", offset=offset + len(selected))
    errors = [provider + ": " + result["error"] for provider, result in results if result.get("error")]
    return {"targets": len(selected), "staged": sum(result.get("staged", 0) for _, result in results),
            "records": sum(result.get("records", 0) for _, result in results), "qualified": sum(result.get("qualified", 0) for _, result in results),
            "filtered": sum(result.get("filtered", 0) for _, result in results), "errors": errors, "provider_health": health}
