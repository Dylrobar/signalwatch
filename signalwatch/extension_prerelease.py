import asyncio
import calendar
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import feedparser
from bs4 import BeautifulSoup
from fastapi import Query

from .async_utils import gather, to_thread
from .extract import CVE_RE, canonical_url, utcnow
from .normalization import NormalizationError, _annotate


SOURCE_DEFINITIONS = [
    {"id": "windows_insider", "name": "Microsoft Windows Insider", "category": "prerelease", "family": "prerelease", "access": "public", "description": "Official Windows Insider preview release notes and component changes; unverified early signals.", "homepage": "https://blogs.windows.com/windows-insider/", "required": []},
    {"id": "apple_developer", "name": "Apple Developer Beta Releases", "category": "prerelease", "family": "prerelease", "access": "public", "description": "Public Apple beta/RC announcements and public DocC release notes; known issues remain distinct from fixes.", "homepage": "https://developer.apple.com/news/releases/", "required": []},
    {"id": "mikrotik_testing", "name": "MikroTik RouterOS Testing", "category": "prerelease", "family": "prerelease", "access": "public", "description": "Official RouterOS testing and development RSS changelogs; no firmware binaries are fetched.", "homepage": "https://mikrotik.com/download/rss", "required": []},
]
DEFINITIONS = {row["id"]: row for row in SOURCE_DEFINITIONS}
FEEDS = {
    "windows_insider": ["https://blogs.windows.com/windows-insider/feed/"],
    "apple_developer": ["https://developer.apple.com/news/releases/rss/releases.rss"],
    "mikrotik_testing": ["https://cdn.mikrotik.com/routeros/latest-testing.rss", "https://cdn.mikrotik.com/routeros/latest-development.rss"],
}
STAGES = frozenset({"beta", "rc", "dev", "canary", "release_preview", "preview"})
STATUS = "unverified_prerelease_signal"
SECURITY = re.compile(r"\b(?:security|vulnerabilit\w*|CVE-\d{4}-\d+|remote code execution|authentication bypass|privilege escalation|memory corruption|buffer overflow|use.after.free|certificate validation|sandbox escape)\b", re.I)
CHANGE = re.compile(r"\b(?:fix(?:ed|es)?|resolv\w*|chang\w*|updat\w*|improv\w*|add(?:ed|s)?|remov\w*|support\w*|address\w*)\b", re.I)
FILE = re.compile(r"(?<![\w.])(?:[\w.-]+[/\\])*[\w.-]+\.(?:dll|sys|exe|kext|dylib|so(?:\.\d+)*|c|cpp|h|rs|js|ts|py|ko|conf|framework)\b", re.I)


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _stage(text):
    for expression, stage in ((r"release[ -]candidate|\brc\s*\d*\b|\drc\d", "rc"),
                              (r"\bbeta\s*\d*\b|\dbeta\d", "beta"),
                              (r"release[ -]preview", "release_preview"), (r"\bcanary\b", "canary"),
                              (r"\bdev(?:elopment)?(?: channel)?\b|\bexperimental\b", "dev"), (r"\bpreview\b|\btesting\b", "preview")):
        if re.search(expression, text, re.I):
            return stage
    return None


def _date(entry):
    value = entry.get("published_parsed") or entry.get("updated_parsed")
    return datetime.fromtimestamp(calendar.timegm(value), timezone.utc).isoformat() if value else None


def _inline(value):
    if isinstance(value, list):
        return "".join(_inline(child) for child in value)
    if not isinstance(value, dict):
        return ""
    return str(value.get("text") or value.get("code") or "") + _inline(value.get("inlineContent", []))


def _docc(payload):
    try:
        doc = json.loads(payload)
    except (ValueError, UnicodeError) as error:
        raise NormalizationError("Apple release note is not valid JSON") from error
    if not isinstance(doc, dict) or not isinstance(doc.get("primaryContentSections"), list):
        raise NormalizationError("Apple release note lacks public documentation content")
    lines, component, section = [], "", ""

    def walk(nodes):
        nonlocal component, section
        for node in nodes:
            if not isinstance(node, dict):
                continue
            kind = node.get("type")
            if kind == "heading":
                text = str(node.get("text") or "")
                level = node.get("level", 4)
                if level <= 3:
                    component, section = text, ""
                else:
                    section = text
            elif kind == "paragraph":
                text = _inline(node.get("inlineContent", []))
                if text.strip():
                    lines.append((component, section, text.strip()))
            for key in ("content", "items"):
                if isinstance(node.get(key), list):
                    walk(node[key])
    for section_node in doc["primaryContentSections"]:
        walk(section_node.get("content", []))
    if not lines:
        raise NormalizationError("Apple release note contains no public note text")
    return lines


def _html(payload):
    page = BeautifulSoup(payload, "html.parser")
    root = page.select_one("article .entry-content,article .c-post-content,main article,main") or page
    for tag in root.select("script,style,nav,header,footer"):
        tag.decompose()
    lines, component, section = [], "", ""
    for node in root.find_all(["h2", "h3", "h4", "p", "li"]):
        if node.name in {"p", "li"} and node.find_parent(["li"]) is not None:
            continue
        text = node.get_text(" ", strip=True)
        if node.name.startswith("h"):
            if re.search(r"known issues|resolved issues|fixes|changes|improvements", text, re.I):
                section = text
            else:
                component, section = text.strip("[]"), ""
        elif re.fullmatch(r"\[[^\]]{1,100}\]", text):
            component, section = text[1:-1], ""
        elif text:
            lines.append((component, section, text))
    if not lines:
        lines = [("", "", line.strip()) for line in root.get_text("\n", strip=True).splitlines() if line.strip()]
    return lines


def _components(lines):
    result, seen = [], set()
    for component, section, text in lines:
        text = " ".join(text.split())[:2000]
        if not text:
            continue
        known = bool(re.search(r"known issues|workaround", section, re.I))
        changed = bool(CHANGE.search(text))
        if not known and not changed:
            continue
        negated = bool(re.search(r"\b(?:no|not|never|will|may|might|plan to)\s+(?:\w+\s+){0,2}(?:fix(?:ed|es)?|resolv\w*)\b", text, re.I))
        fixed = bool(re.search(r"\bfix(?:ed|es)?\b", text, re.I) or re.match(r"(?:Resolved|Addressed):?\s", text, re.I) or re.search(r"resolved|fixes", section, re.I))
        kind = "known_issue" if known else "mentioned" if negated else "resolved" if fixed else "changed"
        router = re.match(r"\*\)\s*([^;\n]{1,100}?)\s+-\s+", text)
        bracket = re.match(r"\[([^\]]{1,100})\]", text)
        context_heading = component.lower().startswith(("reminders for", "about the beta", "important links", "learn more"))
        names = FILE.findall(text)[:4] or ([router.group(1)] if router else [bracket.group(1)] if bracket else [component] if component and not context_heading and component.lower() not in {"overview", "general", "changes and improvements", "fixes", "gradual rollout", "normal rollout", "additional resources", "feedback"} else [])
        for name in names:
            key = (name, kind, text)
            if key not in seen:
                seen.add(key)
                result.append({"name": name[:200], "kind": kind, "quote": text[:1200]})
        if len(result) >= 512:
            break
    return sorted(result, key=lambda value: not bool(SECURITY.search(value["quote"])))[:48]


def _identity(provider, title, text):
    stage = _stage(title) or (_stage(text) if provider == "windows_insider" else None)
    if not stage:
        return None
    if provider == "windows_insider":
        builds = list(dict.fromkeys(re.findall(r"\b\d{5}\.\d{2,6}\b", title + " " + text)))[:8]
        version = ", ".join(builds)
        if not version:
            return None
        return "Microsoft", "Windows", version, stage
    if provider == "mikrotik_testing":
        match = re.search(r"\b\d+\.\d+(?:\.\d+)?(?:rc|beta)\d+\b", title, re.I)
        if not match:
            return None
        return "MikroTik", "RouterOS", match.group(0), stage
    match = re.match(r"(.+?)\s+(\d+(?:\.\d+){0,3}(?:\s+(?:beta|RC|release candidate)\s*\d*)?)", title, re.I)
    if not match:
        return None
    return "Apple", match.group(1).strip(), match.group(2).strip(), stage


def _apple_note_url(body):
    for anchor in BeautifulSoup(body, "html.parser").select("a[href]"):
        parsed = urlsplit(canonical_url(urljoin("https://developer.apple.com", anchor["href"])))
        identifiers = parse_qs(parsed.query).get("id", [])
        if parsed.scheme == "https" and parsed.hostname == "developer.apple.com" and parsed.port in {None, 443} and parsed.path == "/go/" and len(identifiers) == 1 and identifiers[0]:
            return "https://developer.apple.com/go/?" + urlencode({"id": identifiers[0]})
    return ""


def feed_notes(payload, provider):
    parsed = feedparser.parse(payload)
    if parsed.get("bozo") or not str(parsed.get("version", "")).startswith(("rss", "atom")):
        raise NormalizationError("Pre-release source returned invalid RSS/Atom or an error page")
    entries = parsed.entries[:30]
    if provider == "apple_developer":
        entries = sorted(entries, key=lambda entry: _date(entry) or "", reverse=True)
    rows, apple_notes = [], set()
    for entry in entries:
        title = BeautifulSoup(entry.get("title", ""), "html.parser").get_text(" ", strip=True)
        body = next((value.get("value", "") for value in entry.get("content", []) if value.get("value")), entry.get("summary", ""))
        text = BeautifulSoup(body, "html.parser").get_text(" ", strip=True)
        if provider == "apple_developer":
            note_url = _apple_note_url(body)
            if note_url:
                if note_url in apple_notes:
                    continue
                apple_notes.add(note_url)
        if provider == "windows_insider":
            links = []
            for anchor in BeautifulSoup(body, "html.parser").select("a[href]"):
                location = canonical_url(anchor["href"])
                parsed_url = urlsplit(location)
                if parsed_url.hostname != "learn.microsoft.com" or not re.fullmatch(r"/en-us/windows-insider/release-notes/[a-z0-9-]+/(?:preview-)?build-[0-9-]+", parsed_url.path):
                    continue
                if location in links:
                    continue
                links.append(location)
                channel = parsed_url.path.split("/")[-2]
                builds = re.findall(r"(\d{5})-(\d{2,6})", parsed_url.path.split("/")[-1])
                version = ", ".join(a + "." + b for a, b in builds)
                if not version:
                    continue
                rows.append({"title": "Windows " + anchor.get_text(" ", strip=True) + " · " + channel,
                             "body": "", "source_url": location, "published": _date(entry), "vendor": "Microsoft", "product": "Windows",
                             "version": version, "build": version, "stage": _stage(channel) or "preview", "fetch_note": True,
                             "announcement_url": canonical_url(entry.get("link") or "")})
            if links:
                if len(rows) >= 10:
                    break
                continue
        identity = _identity(provider, title, text)
        if not identity:
            continue
        url = canonical_url(entry.get("link") or entry.get("id") or "")
        if provider == "windows_insider" and urlsplit(url).hostname != "blogs.windows.com":
            continue
        if provider == "apple_developer" and urlsplit(url).hostname != "developer.apple.com":
            continue
        if provider == "mikrotik_testing":
            url = "https://download.mikrotik.com/routeros/" + identity[2] + "/CHANGELOG"
        if not url:
            continue
        rows.append({"title": title, "body": body, "source_url": url, "published": _date(entry),
                     "vendor": identity[0], "product": identity[1], "version": identity[2], "stage": identity[3],
                     "build": next(iter(re.findall(r"\(([A-Za-z0-9]+)\)", title)), ""), "announcement_url": url})
    return rows


def normalize_prerelease(item, max_records=5000):
    meta = item.get("metadata") or {}
    provider = meta.get("provider")
    if provider not in DEFINITIONS:
        raise NormalizationError("Unknown pre-release provider")
    if meta.get("format") in {"discovery", "redirect"}:
        return {"entities": [], "edges": [], "articles": []}
    if meta.get("stage") not in STAGES or not all(isinstance(meta.get(key), str) and meta[key] for key in ("vendor", "product", "version", "title")):
        raise NormalizationError("Pre-release note lacks release identity or stage")
    url = canonical_url(item.get("source_url") or "")
    if not url or urlsplit(url).hostname not in {"blogs.windows.com", "learn.microsoft.com", "developer.apple.com", "download.mikrotik.com"}:
        raise NormalizationError("Pre-release note requires an official vendor source URL")
    payload = item["payload"]
    if meta.get("format") == "docc":
        lines = _docc(payload)
        overview = " ".join(text for component, _, text in lines if component.lower() == "overview")
        base, _, suffix = meta["version"].partition(" ")
        expected = re.escape(base) + (r"(?:\s+[A-Za-z][A-Za-z-]*){0,3}\s+" + re.escape(suffix).replace(r"\ ", r"\s*") if suffix else "")
        if not re.search(r"(?<![\d.])" + expected + r"(?!\d)", overview, re.I):
            raise NormalizationError("Apple shared release note does not identify the announcement's current beta/RC version")
    elif meta.get("format") == "text":
        lines = [("", "", line) for line in payload.decode("utf-8").splitlines()]
    else:
        lines = _html(payload)
    text = "\n".join((component + " — " if component else "") + (section + ": " if section else "") + value for component, section, value in lines)
    if not text.strip():
        raise NormalizationError("Pre-release note contains no public release text")
    content_hash = _hash(text)
    release_id = "prerelease:" + _hash("\0".join((provider, url, meta["product"], meta["version"], meta["stage"], str(meta.get("build") or ""))))
    revision_id = "prerelease_revision:" + _hash(release_id + "\0" + content_hash)
    observed = item.get("observed_at") or item.get("received_at")
    components = _components(lines)
    if not components and not any(version.casefold() in text.casefold() for version in meta["version"].split(", ")):
        raise NormalizationError("Vendor response lacks release identity and component-change content")
    cves = sorted(set(value.upper() for value in CVE_RE.findall(text)))[:32]
    metadata = {key: meta.get(key) for key in ("vendor", "product", "version", "stage", "published", "announcement_url", "build", "feed_url", "payload_source_url")}
    metadata.update(provider=provider, status=STATUS, security_relevant=bool(SECURITY.search(text)), components=components,
                    cves=cves, content_hash=content_hash, first_seen=observed, current_revision_id=revision_id,
                    evidence_role="prerelease_note", inventory_observation=False,
                    coverage={"component_limit": 48, "components_truncated": len(components) >= 48, "article_text_limit": 12000,
                              "article_text_truncated": len(text) > 12000, "stage_basis": "official_release_announcement", "note_snapshot": "Public documentation observed at collection time"})
    entity = {"id": release_id, "kind": "prerelease", "name": meta["title"], "value": meta["version"],
              "metadata": metadata, "source_url": url, "observed_at": observed, "confidence": 1.0}
    revision = {**entity, "id": revision_id, "kind": "prerelease_revision", "name": meta["title"] + " · " + content_hash[:10],
                "metadata": {**metadata, "release_id": release_id, "text_preview": text[:16000]}}
    entities = [entity, revision]
    edges = [{"from_id": release_id, "to_id": revision_id, "relation": "has_revision", "source_url": url, "observed_at": observed}]
    for index, component in enumerate(components):
        key = "prerelease_component:" + _hash(revision_id + "\0" + str(index) + "\0" + component["name"])
        entities.append({"id": key, "kind": "component_change", "name": component["name"], "metadata": {**component, "status": STATUS, "release_id": release_id}, "source_url": url, "observed_at": observed})
        edges.append({"from_id": revision_id, "to_id": key, "relation": "documents_" + component["kind"], "source_url": url, "observed_at": observed})
    for cve in cves:
        entities.append({"id": cve, "kind": "vulnerability", "name": cve, "metadata": {"evidence_role": "prerelease_identifier_only"},
                         "source_url": "", "observed_at": observed, "_reference_only": True})
        edges.append({"from_id": revision_id, "to_id": cve, "relation": "mentions", "source_url": url, "observed_at": observed})
    article_id = "article:" + _hash(url)[:32]
    edges.append({"from_id": article_id, "to_id": release_id, "relation": "documents_prerelease", "source_url": url, "observed_at": observed})
    articles = [{"id": article_id, "url": url, "title": meta["title"], "summary": text[:12000], "source": DEFINITIONS[provider]["name"],
                 "feed_url": meta.get("feed_url") or url, "published": meta.get("published"), "cves": cves, "status": STATUS}]
    batch = {"entities": entities, "edges": edges, "articles": articles}
    if sum(map(len, batch.values())) > max_records:
        raise NormalizationError("Pre-release note exceeds normalization record budget")
    return _annotate(batch, item)


def prereleases(store, q="", vendor="", stage="", security_only=False, limit=25, offset=0):
    where, values = ["kind='prerelease'"], []
    if q:
        where.append("(name LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\' OR metadata LIKE ? ESCAPE '\\')")
        term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        values.extend([term] * 3)
    if vendor:
        where.append("json_extract(metadata,'$.vendor')=? COLLATE NOCASE")
        values.append(vendor)
    if stage:
        where.append("json_extract(metadata,'$.stage')=?")
        values.append(stage)
    if security_only:
        where.append("json_extract(metadata,'$.security_relevant')=1")
    clause = " AND ".join(where)
    with store.connection() as conn:
        total = conn.execute("SELECT count(*) FROM entities WHERE " + clause, values).fetchone()[0]
        rows = conn.execute("SELECT * FROM entities WHERE " + clause + " ORDER BY coalesce(json_extract(metadata,'$.published'),observed_at) DESC,id LIMIT ? OFFSET ?", [*values, limit, offset]).fetchall()
    items = []
    for row in rows:
        metadata = json.loads(row["metadata"])
        items.append({"id": row["id"], "name": row["name"], "source_url": row["source_url"], "observed_at": row["observed_at"],
                      **{key: metadata.get(key) for key in ("vendor", "product", "version", "stage", "published", "security_relevant", "components", "cves", "content_hash", "status", "coverage", "build", "announcement_url", "current_revision_id", "first_seen")}})
    return {"items": items, "total": total, "coverage": {"providers": list(DEFINITIONS), "signal_status": STATUS, "installed_inventory": False}}


def register_prerelease_routes(app, store):
    @app.get("/api/prereleases")
    def list_prereleases(q: str = Query(default="", max_length=300), vendor: str = Query(default="", max_length=100),
                         stage: str = Query(default="", pattern=r"^(|beta|rc|dev|canary|release_preview|preview)$"),
                         security_only: bool = False, limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0, le=10000)):
        return prereleases(store, q, vendor, stage, security_only, limit, offset)


async def collect_prerelease_sources(config, store, http):
    from .http import HTTPError, public_error
    from .sourcehub import stage_payload
    settings = config.get("provider_settings", {})
    health, results = {}, []
    semaphore = asyncio.Semaphore(3)

    async def collect(provider):
        async with semaphore:
            stamp = utcnow()
            previous = await to_thread(store.source_state, "provider:" + provider)
            if settings.get(provider, {}).get("enabled") is False:
                return provider, {"status": "disabled", "requirements": []}
            retry_at = previous.get("retry_at")
            if retry_at:
                try:
                    if datetime.fromisoformat(retry_at) > datetime.now(timezone.utc):
                        return provider, {**previous, "status": "deferred", "deferred": True}
                except ValueError:
                    pass
            staged, duplicates, count, failures = 0, 0, 0, []
            note_limit, robots = 4, {}

            async def get(url, *, html=False, maximum=2 * 1024 * 1024):
                origin = urlsplit(url)
                if html:
                    root = origin.scheme + "://" + origin.netloc
                    if root not in robots:
                        parser = RobotFileParser(root + "/robots.txt")
                        try:
                            response = await http.get(root + "/robots.txt", max_bytes=128 * 1024, max_attempts=2, allow_redirects=False)
                            parser.parse((await asyncio.to_thread(response.path.read_bytes)).decode("utf-8").splitlines())
                        except HTTPError as error:
                            if error.status != 404:
                                raise
                            parser.parse([])
                        robots[root] = parser
                    if not robots[root].can_fetch(config.get("user_agent", "SignalWatch"), url):
                        raise NormalizationError("Vendor robots.txt disallows release-note access")
                response = await http.get(url, max_bytes=maximum, max_attempts=2, allow_redirects=False)
                if response.status not in {200, 304} or response.url != url:
                    raise NormalizationError("Unexpected vendor release-note response or redirect")
                return await asyncio.to_thread(response.path.read_bytes)

            async def stage(payload, url, metadata, mime):
                nonlocal staged, duplicates
                queued = await stage_payload(config, store, payload, provider=provider, source_url=url, content_type=mime,
                                             stream_key=provider + ":" + _hash(url), metadata=metadata)
                staged += int(not queued.get("duplicate"))
                duplicates += int(bool(queued.get("duplicate")))
                if queued.get("status") == "dead":
                    raise NormalizationError("Pre-release raw record is in the dead-letter queue; retry ingestion")

            try:
                notes = []
                for feed_url in FEEDS[provider]:
                    try:
                        raw = await get(feed_url, maximum=4 * 1024 * 1024 if provider == "windows_insider" else 2 * 1024 * 1024)
                        discovered = feed_notes(raw, provider)
                        await stage(raw, feed_url, {"format": "discovery"}, "application/rss+xml")
                        notes.extend({**note, "feed_url": feed_url} for note in discovered)
                    except Exception as error:
                        reason = str(error) if isinstance(error, NormalizationError) else public_error(error)
                        failures.append(feed_url + ": " + reason)
                unique = {note["source_url"] + "\0" + note["version"]: note for note in reversed(notes)}
                notes = list(reversed(list(unique.values())))
                offset = int(previous.get("note_offset") or 0) % max(1, len(notes))
                selected = (notes[offset:] + notes[:offset])[:note_limit]
                documents = {}
                for note in selected:
                    try:
                        body = note.pop("body")
                        url = note.pop("source_url")
                        payload, format_name, mime = body.encode("utf-8"), "html", "text/html"
                        if provider == "windows_insider" and note.pop("fetch_note", False):
                            payload = await get(url, html=True)
                            if not any(version in BeautifulSoup(payload, "html.parser").get_text(" ", strip=True) for version in note["version"].split(", ")):
                                raise NormalizationError("Windows public release note does not identify the announced build")
                        if provider == "apple_developer":
                            go = _apple_note_url(body)
                            if not go:
                                raise NormalizationError("Apple beta announcement lacks public release notes")
                            redirect = await get(go, html=True)
                            target = re.search(rb"window\.location\.replace\(['\"](/documentation/[a-zA-Z0-9_/-]+)['\"]\)", redirect)
                            if not target:
                                raise NormalizationError("Apple public release-note redirect is unrecognized")
                            await stage(redirect, go, {"format": "redirect"}, "text/html")
                            path = target.group(1).decode()
                            url = "https://developer.apple.com/tutorials/data" + path + ".json"
                            if url not in documents:
                                documents[url] = await get(url)
                            payload, format_name, mime = documents[url], "docc", "application/json"
                        metadata = {**note, "format": format_name,
                                    "payload_source_url": note["feed_url"] if provider == "mikrotik_testing" else url}
                        normalize_prerelease({"id": 0, "source": "public:" + provider, "payload_hash": hashlib.sha256(payload).hexdigest(),
                                              "payload": payload, "source_url": url, "metadata": {**metadata, "provider": provider}})
                        await stage(payload, url, metadata, mime)
                        count += 1
                    except Exception as error:
                        reason = str(error) if isinstance(error, NormalizationError) else public_error(error)
                        failures.append(str(note.get("title") or "Release note") + ": " + reason)
                outcome = {"status": "partial" if failures and count else "error" if failures else "unchanged" if not staged else "ok",
                           "checked_at": stamp, "requirements": [], "deferred": False, "staged": staged, "duplicates": duplicates,
                           "records": count, "error": "; ".join(failures)[:1000], "retry_at": "", "coverage": "Up to four recent public pre-release notes; official RSS/DocC metadata only"}
                outcome["note_offset"] = offset + len(selected)
                outcome["available_notes"] = len(notes)
                outcome["deferred_notes"] = max(0, len(notes) - len(selected))
                if not failures or count:
                    outcome["last_success"] = stamp
                if failures:
                    outcome["retry_at"] = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
            except Exception as error:
                outcome = {"status": "error", "checked_at": stamp, "staged": staged, "records": count, "error": public_error(error),
                           "retry_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}
            await to_thread(store.update_source, "provider:" + provider, **outcome)
            return provider, outcome

    results = await gather(*(collect(provider) for provider in DEFINITIONS))
    health.update(results)
    return {"targets": len(results), "staged": sum(row.get("staged", 0) for _, row in results),
            "records": sum(row.get("records", 0) for _, row in results), "errors": [key + ": " + row["error"] for key, row in results if row.get("error")], "provider_health": health}
