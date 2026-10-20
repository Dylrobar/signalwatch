"""Bounded passive matches from ProjectDiscovery's MIT-licensed catalog.

Catalog findings are technology hints, never trusted CPE identities. Browser
execution, DOM/CSS selectors and cookie values are deliberately not evaluated;
coverage limitations are returned as diagnostics rather than hidden.
"""

import hashlib
import json
import math
import os
import re
import tempfile
import time
from collections import Counter, deque
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

import regex

from .async_utils import to_thread
from .http import public_error


CATALOG_URL = "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json"
CATALOG_BYTES = 8 * 1024 * 1024
CACHE_TTL = 24 * 60 * 60
CACHE_NAME = "web-fingerprint-catalog-last-good.json"
MATCH_SECONDS = 0.25
PATTERN_SECONDS = 0.005
COMPILE_SECONDS = 10
FINDING_LIMIT = 100
HTML_LIMIT = 250_000
METHOD = "projectdiscovery_wappalyzer"
LICENSE = """MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,4}(?:[-+~][0-9A-Za-z_.-]+)?\Z")
_COOKIE_NAME = re.compile(r"^\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=")
_VERSION_TEMPLATE = re.compile(r"(?:\\[1-9][0-9]?|[.\-+~])+\Z")
_VECTORS = {"headers": "header", "cookies": "cookie", "meta": "meta", "scriptSrc": "script", "html": "html"}
_METADATA = {"cats", "website", "icon", "description", "cpe", "implies"}


class CatalogError(ValueError):
    """A bounded, non-sensitive explanation of an unusable catalog."""


@dataclass(frozen=True)
class _Rule:
    name: str
    vector: str
    key: str
    pattern: object
    version: str
    confidence: float


def _label(value, limit=200):
    return isinstance(value, str) and 0 < len(value) <= limit and not any(ord(char) < 32 for char in value)


def _patterns(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and len(value) <= 100 and all(isinstance(item, str) for item in value):
        return value
    raise CatalogError("Catalog has an invalid pattern collection")


class _Signals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.meta = {}
        self.remaining = 32_768

    def handle_starttag(self, tag, attrs):
        if self.remaining <= 0:
            return
        values = dict(attrs)
        if tag == "script" and values.get("src") and len(self.scripts) < 128:
            text = values["src"][:min(2048, self.remaining)]
            self.scripts.append(text)
            self.remaining -= len(text)
        if tag == "meta" and (values.get("name") or values.get("property")) and "content" in values and len(self.meta) < 128:
            key = (values.get("name") or values["property"]).casefold()[:200]
            text = (values["content"] or "")[:min(2048, self.remaining)]
            self.meta.setdefault(key, []).append(text)
            self.remaining -= len(text)


def _signals(headers, html, cookie_names):
    values, names, remaining = {}, set(), 65_536
    items = headers.multi_items() if hasattr(headers, "multi_items") else headers.items() if hasattr(headers, "items") else headers or ()
    for index, (name, content) in enumerate(items):
        if index >= 128 or remaining <= 0:
            break
        name = str(name).casefold()[:200]
        for value in content if isinstance(content, (list, tuple)) else (content,):
            if remaining <= 0:
                break
            text = str(value)[:min(4096, remaining)]
            remaining -= len(text)
            if name == "set-cookie":
                names.update(match.group(1).casefold() for match in _COOKIE_NAME.finditer(text))
            elif name not in {"cookie", "authorization", "proxy-authorization"}:
                values.setdefault(name, []).append(text)
    for index, name in enumerate(cookie_names):
        if index >= 128:
            break
        if isinstance(name, str) and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,200}", name):
            names.add(name.casefold())
    # Bound the encoded HTML sample before parsing or evaluating any expression.
    sample = html[:HTML_LIMIT].decode("utf-8", "replace") if isinstance(html, bytes) else str(html or "")[:HTML_LIMIT]
    sample = sample.encode("utf-8", "replace")[:HTML_LIMIT].decode("utf-8", "ignore")
    parser = _Signals()
    parser.feed(sample)
    return {"headers": values, "cookies": {name: [""] for name in names}, "meta": parser.meta,
            "scriptSrc": {"": parser.scripts}, "html": {"": [sample] if sample else []}}


class Catalog:
    def __init__(self, payload, *, fetched_at=None):
        if not isinstance(payload, bytes) or len(payload) > CATALOG_BYTES:
            raise CatalogError("Catalog exceeds the 8 MiB limit")
        try:
            document = json.loads(payload.decode("utf-8-sig"))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise CatalogError("Catalog is not valid JSON") from error
        apps = document.get("apps") if isinstance(document, dict) else None
        if not isinstance(apps, dict) or not 1 <= len(apps) <= 15_000:
            raise CatalogError("Catalog must contain between 1 and 15000 apps")
        self.rules = []
        self.implies = {}
        counts = Counter()
        supported = set()
        deadline = time.monotonic() + COMPILE_SECONDS
        constrained = {name for name, app in apps.items() if isinstance(app, dict)
                       and any(app.get(field) for field in ("requires", "requiresCategory", "excludes"))}
        for name, app in apps.items():
            if not _label(name) or not isinstance(app, dict):
                raise CatalogError("Catalog has an invalid app")
            if name in constrained:
                counts["apps with unsupported dependency constraints"] += 1
                continue
            for vector in app.keys() - _VECTORS.keys() - _METADATA:
                if app[vector]:
                    kind = f"unsupported {vector} rules" if vector in {"js", "dom", "css", "scripts"} else "unsupported catalog fields"
                    counts[kind] += 1
            implications = app.get("implies", [])
            if isinstance(implications, str):
                implications = [implications]
            if not isinstance(implications, list) or len(implications) > 100 or any(not _label(item) for item in implications):
                raise CatalogError("Catalog has invalid dependency hints")
            self.implies[name] = []
            for item in implications:
                parts = item.split(r"\;")
                target, confidence, valid = parts[0], 0.5, True
                for modifier in parts[1:]:
                    field, separator, value = modifier.partition(":")
                    if field == "confidence" and separator and value.isdigit() and 0 <= int(value) <= 100:
                        confidence = min(confidence, int(value) / 100)
                    else:
                        valid = False
                if not valid:
                    counts["unsupported dependency modifiers"] += 1
                elif confidence == 0:
                    counts["zero-confidence dependency hints ignored"] += 1
                elif target in constrained:
                    counts["dependency hints with unsupported constraints"] += 1
                elif target in apps:
                    self.implies[name].append((target, confidence))
                else:
                    counts["unknown dependency hints"] += 1
            for vector in _VECTORS:
                if vector not in app:
                    continue
                values = app[vector] if vector in {"headers", "cookies", "meta"} else {"": app[vector]}
                if not isinstance(values, dict) or len(values) > 100:
                    raise CatalogError("Catalog has an invalid signal map")
                for key, patterns in values.items():
                    if key and not _label(key):
                        raise CatalogError("Catalog has an invalid signal name")
                    for expression in _patterns(patterns):
                        if len(self.rules) >= 30_000 or time.monotonic() >= deadline:
                            raise CatalogError("Catalog exceeds the pattern compilation budget")
                        if len(expression) > 2048:
                            counts["oversized patterns"] += 1
                            continue
                        parts = expression.split(r"\;")
                        pattern, version, confidence = parts[0], "", 0.9
                        # These generic names establish less than the catalog's
                        # product labels. Curated rules retain their safer scope.
                        # Sentry's catalog also mistakes app release values for
                        # server versions; the curated SDK signature handles it.
                        if name.casefold() == "sentry" or vector == "cookies" and key.casefold() in {"jsessionid", "xsrf-token", "asp.net_sessionid"}:
                            counts["ambiguous signatures left to curated rules"] += 1
                            continue
                        unknown = False
                        for modifier in parts[1:]:
                            field, separator, value = modifier.partition(":")
                            if field == "version" and separator:
                                if _VERSION_TEMPLATE.fullmatch(value):
                                    version = value
                                else:
                                    counts["unsupported version expressions"] += 1
                            elif field == "confidence" and separator and value.isdigit() and 0 <= int(value) <= 100:
                                confidence = min(0.9, int(value) / 100)
                            else:
                                unknown = True
                        if unknown:
                            counts["unsupported pattern modifiers"] += 1
                            continue
                        if confidence == 0:
                            counts["zero-confidence patterns ignored"] += 1
                            continue
                        if vector == "cookies" and pattern:
                            counts["cookie-value patterns not evaluated"] += 1
                            continue
                        # Huge counted repetitions can consume excessive memory
                        # during compile, before search's timeout can intervene.
                        repetitions = re.findall(r"\{(\d+)(?:,(\d*))?\}", pattern)
                        if any(int(value) > 10_000 for pair in repetitions for value in pair if value):
                            counts["oversized repetitions"] += 1
                            continue
                        try:
                            compiled = regex.compile(pattern, regex.IGNORECASE) if pattern else None
                        except (regex.error, RecursionError, OverflowError):
                            counts["invalid regular expressions"] += 1
                            continue
                        self.rules.append(_Rule(name, vector, key.casefold(), compiled, version, confidence))
                        supported.add(name)
        if not self.rules:
            raise CatalogError("Catalog has no supported passive patterns")
        order = {name: index for index, name in enumerate(_VECTORS)}
        self.rules.sort(key=lambda rule: order[rule.vector])
        self.diagnostics = [f"ProjectDiscovery catalog: {count} {kind}" for kind, count in sorted(counts.items())]
        self.metadata = {"apps": len(apps), "supported_apps": len(supported), "patterns": len(self.rules),
                         "digest": hashlib.sha256(payload).hexdigest(), "source_url": CATALOG_URL,
                         "fetched_at": time.time() if fetched_at is None else fetched_at}

    def _finding(self, name, vector, key="", version="", confidence=0.9, *, implied_by=""):
        status = "implied_dependency" if implied_by else "http_detected"
        snippet = f"ProjectDiscovery catalog signature: {name}; {_VECTORS.get(vector, vector)}"
        if key:
            snippet += f" ({key})"
        if implied_by:
            snippet = f"ProjectDiscovery catalog dependency hint: {name}; implied by {implied_by}"
        return {"vendor": "unknown", "vendor_name": "Unknown", "product": name.casefold(), "product_name": name,
                "category": "Web technology", "part": "a", "version": "" if implied_by else version,
                "cpe": None, "status": status, "confidence": confidence,
                "evidence_snippet": snippet[:300], "method": METHOD,
                "evidence_type": "implied" if implied_by else _VECTORS[vector],
                **({"implied_by": [implied_by]} if implied_by else {})}

    def match(self, url, headers, html, cookie_names=()):
        """Return passive findings and visible limits; never execute page code."""
        deadline = time.monotonic() + MATCH_SECONDS
        signals = _signals(headers, html, cookie_names)
        found, diagnostics = {}, []
        timed_out = 0
        for rule in self.rules:
            if time.monotonic() >= deadline:
                diagnostics.append("ProjectDiscovery matching reached its response time budget; findings are partial")
                break
            for target in signals[rule.vector].get(rule.key, ()):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    match = rule.pattern.search(target, timeout=min(PATTERN_SECONDS, remaining)) if rule.pattern is not None else True
                except TimeoutError:
                    timed_out += 1
                    continue
                if not match:
                    continue
                version = ""
                if rule.version and match is not True:
                    try:
                        value = re.sub(r"\\([1-9][0-9]?)", lambda item: match.group(int(item.group(1))) or "", rule.version)
                        if len(value) <= 64 and _VERSION.fullmatch(value):
                            version = value
                    except (IndexError, TypeError):
                        pass
                previous = found.get(rule.name)
                if previous is None or version and not previous["version"]:
                    found[rule.name] = self._finding(rule.name, rule.vector, rule.key, version, rule.confidence)
                break
            if len(found) >= FINDING_LIMIT:
                diagnostics.append("ProjectDiscovery matching reached the 100 finding limit; findings are partial")
                break
        if timed_out:
            diagnostics.append(f"ProjectDiscovery matching skipped {timed_out} regex evaluations that exceeded their time budget")
        pending = deque(found)
        while pending and len(found) < FINDING_LIMIT:
            source = pending.popleft()
            for name, confidence in self.implies.get(source, ()):
                if name not in found:
                    found[name] = self._finding(name, "implied", confidence=min(confidence, found[source]["confidence"]), implied_by=source)
                    pending.append(name)
                    if len(found) >= FINDING_LIMIT:
                        diagnostics.append("ProjectDiscovery dependency hints reached the 100 finding limit")
                        break
        return list(found.values()), diagnostics


def _read_bytes(path, maximum=CATALOG_BYTES):
    with Path(path).open("rb") as stream:
        payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise CatalogError("Catalog exceeds its size limit")
    return payload


def _cached(path):
    value = json.loads(_read_bytes(path, 2 * CATALOG_BYTES + 4096))
    if value.get("source_url") != CATALOG_URL or value.get("schema") != 1:
        raise CatalogError("Cached catalog metadata is invalid")
    timestamp = float(value["fetched_at"])
    if not math.isfinite(timestamp) or timestamp > time.time() + 300 or timestamp < 0:
        raise CatalogError("Cached catalog timestamp is invalid")
    payload = value["data"].encode("utf-8")
    if hashlib.sha256(payload).hexdigest() != value["digest"]:
        raise CatalogError("Cached catalog digest does not match")
    return Catalog(payload, fetched_at=timestamp)


def _save(path, payload, catalog):
    value = {"schema": 1, **catalog.metadata, "data": payload.decode("utf-8"), "license": LICENSE}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, ensure_ascii=False)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


async def load_catalog(http, cache_dir):
    """Use a daily cache; refresh failure preserves and uses validated last-good data."""
    path = Path(cache_dir) / CACHE_NAME
    cached, diagnostics = None, []
    if path.exists():
        try:
            cached = await to_thread(_cached, path)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
            diagnostics.append("ProjectDiscovery last-good catalog cache is invalid; refreshing")
    if cached is not None and time.time() - cached.metadata["fetched_at"] < CACHE_TTL:
        return cached, diagnostics + cached.diagnostics
    try:
        response = await http.get(CATALOG_URL, max_bytes=CATALOG_BYTES, cache=True)
        payload = await to_thread(_read_bytes, response.path)
        catalog = await to_thread(Catalog, payload)
    except Exception as error:
        reason = str(error) if isinstance(error, CatalogError) else public_error(error)
        fallback = "using the last-good catalog" if cached is not None else "using built-in fingerprints only"
        diagnostics.append(f"ProjectDiscovery catalog refresh failed; {fallback}: {reason}")
        return cached, diagnostics + (cached.diagnostics if cached is not None else [])
    try:
        await to_thread(_save, path, payload, catalog)
    except OSError:
        diagnostics.append("ProjectDiscovery catalog loaded, but its last-good cache could not be saved")
    return catalog, diagnostics + catalog.diagnostics
