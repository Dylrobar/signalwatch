import asyncio
import base64
import hashlib
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, quote, urlsplit

from bs4 import BeautifulSoup

from .http import display_url, public_error

SOURCE_DEFINITIONS = [
    {"id": "github_public", "name": "GitHub public repositories", "category": "developer", "family": "developer", "access": "public", "description": "Explicit organization repositories and bounded dependency manifests; declared dependencies are evidence, not deployed inventory.", "homepage": "https://docs.github.com/en/rest/repos", "required": ["github_org or configured public URL"]},
    {"id": "gitlab_public", "name": "GitLab public projects", "category": "developer", "family": "developer", "access": "public", "description": "Explicit GitLab.com group public project metadata or configured public exports.", "homepage": "https://docs.gitlab.com/api/groups/", "required": ["gitlab_group or configured public URL"]},
    {"id": "bitbucket_public", "name": "Bitbucket public repositories", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public repository metadata exports; authenticated API discovery is not assumed.", "homepage": "https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/", "required": ["url or urls"]},
    {"id": "wayback_cdx", "name": "Internet Archive CDX", "category": "developer", "family": "developer", "access": "public", "description": "Bounded historical URL index discovery; archive records do not establish current exposure.", "homepage": "https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server", "required": ["target domain"]},
    {"id": "commoncrawl", "name": "Common Crawl URL index", "category": "developer", "family": "developer", "access": "public", "description": "Latest available crawl index URL discovery without downloading WARC contents.", "homepage": "https://index.commoncrawl.org/", "required": ["target domain"]},
    {"id": "javascript_artifacts", "name": "Public JavaScript and sourcemaps", "category": "developer", "family": "developer", "access": "configured_url", "description": "Explicit public script and sourcemap URLs; source package identities and URLs remain candidate evidence.", "homepage": "https://tc39.es/ecma426/", "required": ["javascript_urls or url or urls"]},
    {"id": "dockerhub", "name": "Docker Hub tag metadata", "category": "developer", "family": "developer", "access": "api_key", "description": "Configured repository tag and image architecture metadata through the current Hub API; no layers downloaded.", "homepage": "https://docs.docker.com/reference/api/hub/latest/operations/ListRepositoryTags/", "required": ["repositories", "credential or public export URL"]},
    {"id": "quay", "name": "Quay public tag metadata", "category": "developer", "family": "developer", "access": "public", "description": "Explicit public repository tag metadata; no container layers or filesystems downloaded.", "homepage": "https://docs.quay.io/api/", "required": ["repositories or configured public URL"]},
    {"id": "postman_public", "name": "Postman public collections", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public collection exports or public workspace pages; no undocumented discovery API.", "homepage": "https://learning.postman.com/docs/collaborating-in-postman/using-workspaces/public-workspaces/", "required": ["url or urls"]},
    {"id": "swaggerhub_public", "name": "SwaggerHub public specifications", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public OpenAPI JSON specifications and pages; endpoint declarations are not verified exposure.", "homepage": "https://support.smartbear.com/swaggerhub/docs/en/explore-and-manage-apis/export-an-api-definition.html", "required": ["url or urls"]},
    {"id": "appstore_public", "name": "Apple App Store public metadata", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public listing or metadata export; app binaries are not downloaded.", "homepage": "https://apps.apple.com/", "required": ["url or urls"]},
    {"id": "googleplay_public", "name": "Google Play public metadata", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public listing or metadata export; no APK download or private store API.", "homepage": "https://play.google.com/store/apps", "required": ["url or urls"]},
    {"id": "chrome_webstore_public", "name": "Chrome Web Store public metadata", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public extension listings or metadata exports; no extension package download.", "homepage": "https://chromewebstore.google.com/", "required": ["url or urls"]},
    {"id": "slack_apps_public", "name": "Slack Marketplace public metadata", "category": "developer", "family": "developer", "access": "configured_url", "description": "Configured public app listing metadata; a listing does not establish a company's use of the app.", "homepage": "https://slack.com/marketplace", "required": ["url or urls"]},
]

PROVIDERS = {value["id"] for value in SOURCE_DEFINITIONS}
MANIFESTS = frozenset({"package.json", "requirements.txt", "pom.xml", "go.mod", "Cargo.toml", "composer.json", "Dockerfile"})
def _url(value):
    if not isinstance(value, str):
        raise ValueError("Public source URL must be text")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Public source requires an HTTP URL without embedded credentials")
    if any(re.search(r"(?:token|secret|password|api[_-]?key|authorization)", key, re.I) for key, _ in parse_qsl(parsed.query)):
        raise ValueError("Public source URL must not contain credential parameters")
    return value


def _strings(value):
    if isinstance(value, str):
        return [value] if value else []
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _context(target):
    return {key: str(target[key])[:500] for key in ("domain", "name", "company_id") if target.get(key)}


async def collect_developer_sources(config, store, http):
    from .sourcehub import stage_payload

    batch = min(20, max(1, int(config.get("public_source_batch", 3))))
    maximum = min(1000, max(1, int(config.get("public_source_records", 100))))
    targets = [target for target in config.get("source_targets", []) if isinstance(target, dict)]
    state = await asyncio.to_thread(store.source_state, "developer_sources") if store is not None else {}
    cursors = dict(state.get("cursors") or {})

    def rotate(values, key):
        if not values:
            return []
        cursor = int(cursors.get(key, 0)) % len(values)
        selected = (values[cursor:] + values[:cursor])[:batch]
        cursors[key] = (cursor + len(selected)) % len(values)
        return selected
    settings = config.get("provider_settings", {})
    credentials = config.get("provider_credentials", {})
    semaphore = asyncio.Semaphore(min(32, max(1, int(config.get("public_source_concurrency", 4)))))
    max_bytes = min(int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024), 2 * 1024 * 1024)
    result = {"staged": 0, "duplicates": 0, "fetched": 0, "errors": [], "provider_health": {}}

    async def provider_run(provider):
        options = settings.get(provider, {})
        if not isinstance(options, dict):
            options = {}
        health = {"status": "unconfigured", "staged": 0, "duplicates": 0, "fetched": 0, "errors": []}
        result["provider_health"][provider] = health
        if options.get("enabled") is False:
            health["status"] = "disabled"
            return
        credential = credentials.get(provider)
        if isinstance(credential, dict):
            credential = credential.get("token") or credential.get("access_token") or credential.get("api_key") or credential.get("key")
        if provider == "github_public":
            credential = credential or config.get("github_token")
        github_headers = {"Accept": "application/vnd.github+json"}
        if provider == "github_public" and credential:
            github_headers["Authorization"] = "Bearer " + str(credential)

        async def fetch(url, context, *, params=None, kind="generic", headers=None):
            url = _url(url)
            async with semaphore:
                response = await http.get(url, params=params, headers=headers or {}, max_bytes=max_bytes, max_attempts=2, allow_redirects=not bool(headers and headers.get("Authorization")))
                payload = await asyncio.to_thread(response.path.read_bytes)
                health["fetched"] += 1
                result["fetched"] += 1
                source_url = _url(response.url)
                content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "application/octet-stream")
                stream_key = hashlib.sha256(json.dumps([source_url, context], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                staged = await stage_payload(config, store, payload, provider=provider, source_url=source_url, content_type=content_type, stream_key=stream_key, metadata={**context, "artifact_kind": kind, "record_limit": maximum})
                key = "duplicates" if isinstance(staged, dict) and staged.get("duplicate") else "staged"
                health[key] += 1
                result[key] += 1
                return payload

        async def attempt(url, context, **kwargs):
            try:
                return await fetch(url, context, **kwargs)
            except Exception as error:
                message = f"{provider}: {public_error(error)} at {display_url(url)}"
                health["errors"].append(message)
                result["errors"].append(message)
                return None

        configured = []
        for url in _strings(options.get("url")) + _strings(options.get("urls")):
            configured.append((url, {}))
        for target in targets:
            mapping = target.get("provider_urls", {})
            urls = mapping.get(provider, []) if isinstance(mapping, dict) else []
            if provider == "javascript_artifacts":
                urls = _strings(urls) + _strings(target.get("javascript_urls")) + _strings(target.get("sourcemap_urls"))
            for url in _strings(urls):
                configured.append((url, _context(target)))
        if configured:
            await asyncio.gather(*(attempt(url, context, kind="javascript" if provider == "javascript_artifacts" else "generic") for url, context in rotate(configured, "urls:" + provider)))

        if provider == "github_public":
            eligible = [target for target in targets if target.get("github_org")]
            for target in rotate(eligible, "targets:" + provider):
                org = str(target.get("github_org") or "")
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", org):
                    continue
                context = {**_context(target), "github_org": org}
                page_key = "github_page:" + org.lower()
                page = max(1, int(cursors.get(page_key, 1)))
                raw = await attempt(f"https://api.github.com/orgs/{quote(org, safe='')}/repos", context, params={"type": "public", "sort": "pushed", "per_page": min(batch, 100), "page": page}, kind="repositories", headers=github_headers)
                if raw is None:
                    continue
                try:
                    repositories = json.loads(raw)
                    if not isinstance(repositories, list):
                        raise ValueError("Expected repository array")
                except (ValueError, UnicodeDecodeError):
                    health["errors"].append("github_public: invalid repository JSON")
                    result["errors"].append(health["errors"][-1])
                    continue
                cursors[page_key] = page + 1 if len(repositories) >= batch else 1
                for repository in repositories[:batch]:
                    if not isinstance(repository, dict) or repository.get("private") or repository.get("visibility", "public") != "public":
                        continue
                    full_name = repository.get("full_name", "")
                    if not isinstance(full_name, str) or not re.fullmatch(re.escape(org) + r"/[A-Za-z0-9_.-]+", full_name, re.I):
                        continue
                    repo_context = {**context, "repository": full_name, "repository_url": "https://github.com/" + full_name}
                    raw_listing = await attempt(f"https://api.github.com/repos/{full_name}/contents/", repo_context, kind="repository_files", headers=github_headers)
                    if raw_listing is None:
                        continue
                    try:
                        listing = json.loads(raw_listing)
                        if not isinstance(listing, list):
                            raise ValueError("Expected directory array")
                        files = [entry for entry in listing if isinstance(entry, dict) and entry.get("type") == "file" and entry.get("name") in MANIFESTS and entry.get("path") == entry.get("name") and isinstance(entry.get("size"), int) and 0 <= entry["size"] <= max_bytes]
                    except (ValueError, UnicodeDecodeError):
                        health["errors"].append("github_public: invalid directory JSON")
                        result["errors"].append(health["errors"][-1])
                        continue
                    for entry in rotate(files, "files:" + full_name.lower()):
                        await attempt(f"https://api.github.com/repos/{full_name}/contents/{quote(entry['path'], safe='')}", {**repo_context, "manifest_path": entry["path"]}, kind="manifest", headers={**github_headers, "Accept": "application/vnd.github.raw+json"})
        elif provider == "gitlab_public":
            for target in rotate([target for target in targets if target.get("gitlab_group")], "targets:" + provider):
                group = str(target.get("gitlab_group") or "")
                if group and len(group) <= 200:
                    await attempt(f"https://gitlab.com/api/v4/groups/{quote(group, safe='')}/projects", _context(target), params={"visibility": "public", "per_page": min(maximum, 100), "include_subgroups": "true", "with_shared": "false"}, kind="repositories")
        elif provider == "wayback_cdx":
            for target in rotate([target for target in targets if target.get("domain")], "targets:" + provider):
                domain = str(target.get("domain") or "").strip().lower().rstrip(".")
                if domain:
                    await attempt("https://web.archive.org/cdx/search/cdx", _context(target), params={"url": domain + "/*", "matchType": "domain", "output": "json", "fl": "timestamp,original,statuscode,mimetype,digest", "collapse": "urlkey", "filter": "statuscode:200", "limit": maximum}, kind="archive_index")
        elif provider == "commoncrawl":
            domains = rotate([target for target in targets if target.get("domain")], "targets:" + provider)
            if domains:
                index_url = options.get("index_url")
                if not index_url:
                    raw = await attempt("https://index.commoncrawl.org/collinfo.json", {}, kind="archive_catalog")
                    if raw is not None:
                        try:
                            catalogs = json.loads(raw)
                            index_url = catalogs[0].get("cdx-api") if isinstance(catalogs, list) and catalogs and isinstance(catalogs[0], dict) else None
                            if not isinstance(index_url, str) or not re.fullmatch(r"https://index\.commoncrawl\.org/CC-MAIN-\d{4}-\d{2}-index", index_url):
                                raise ValueError("Unrecognized public crawl index")
                        except (ValueError, UnicodeDecodeError):
                            health["errors"].append("commoncrawl: invalid index catalog")
                            result["errors"].append(health["errors"][-1])
                            index_url = None
                if index_url:
                    for target in domains:
                        await attempt(index_url, _context(target), params={"url": str(target["domain"]).strip().lower().rstrip(".") + "/*", "matchType": "domain", "output": "json", "filter": "status:200", "collapse": "urlkey", "limit": maximum}, kind="archive_index")
        elif provider in {"dockerhub", "quay"}:
            repositories = [(repository, {}) for repository in _strings(options.get("repositories"))]
            for target in targets:
                repositories.extend((repository, _context(target)) for repository in _strings(target.get(provider + "_repositories")))
            token = credential
            if provider == "dockerhub" and repositories and not token:
                health["reason"] = "Current Docker Hub API requires a configured bearer credential; public export URLs remain supported"
            else:
                for repository, context in rotate(repositories, "repositories:" + provider):
                    if not re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", repository):
                        continue
                    namespace, name = repository.split("/")
                    if provider == "dockerhub":
                        url = f"https://hub.docker.com/v2/namespaces/{quote(namespace, safe='')}/repositories/{quote(name, safe='')}/tags"
                        headers = {"Authorization": "Bearer " + str(token)}
                        params = {"page_size": min(maximum, 100), "page": 1}
                    else:
                        url = f"https://quay.io/api/v1/repository/{repository}/tag/"
                        headers = {}
                        params = {"limit": min(maximum, 100), "onlyActiveTags": "true", "page": 1}
                    await attempt(url, {**context, "repository": repository}, params=params, kind="container_tags", headers=headers)

        health["status"] = ("partial" if health["fetched"] else "error") if health["errors"] else "healthy" if health["fetched"] else "unconfigured"
        if health["status"] == "unconfigured":
            health["requirements"] = next(definition["required"] for definition in SOURCE_DEFINITIONS if definition["id"] == provider)

    await asyncio.gather(*(provider_run(definition["id"]) for definition in SOURCE_DEFINITIONS))
    if store is not None:
        await asyncio.to_thread(store.update_source, "developer_sources", cursors=cursors)
    return result


def _object(item):
    try:
        return json.loads(item["payload"].decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None


def _short(value):
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return value if len(encoded.encode()) <= 12000 else {"truncated": True, "preview": encoded[:6000]}


def _record(item, kind, identity, name, fields):
    metadata = item.get("metadata") or {}
    context = {key: metadata[key] for key in ("domain", "name", "company_id", "repository") if metadata.get(key)}
    origin = [metadata.get("provider"), item.get("source_url"), context, kind, identity]
    digest = hashlib.sha256(json.dumps(origin, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return {"id": kind + ":" + digest, "kind": kind, "name": str(name)[:1000], "value": str(identity)[:4096], "source_url": item.get("source_url") or "", "observed_at": item.get("observed_at") or item.get("received_at"), "confidence": 0.6, "metadata": {"provider": metadata.get("provider"), "evidence_role": "public_artifact", "deployment_confirmed": False, "deployment_verified": False, "ownership_verified": False, "company_context": context, "fields": _short(fields), "staging": {"id": item.get("id"), "raw_reference": "staging:" + str(item.get("id")), "payload_hash": item.get("payload_hash"), "source": item.get("source"), "source_url": item.get("source_url"), "observed_at": item.get("observed_at") or item.get("received_at")}}}


def _dependency_records(payload, path, maximum):
    text = payload.decode("utf-8-sig")
    values = []
    if path == "package.json":
        data = json.loads(text)
        for scope in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, version in (data.get(scope) or {}).items():
                if isinstance(version, str):
                    values.append({"ecosystem": "npm", "name": name, "constraint": version, "scope": scope})
    elif path == "requirements.txt":
        for line in text.splitlines():
            line = line.split(" #", 1)[0].strip()
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*((?:===|==|~=|!=|<=|>=|<|>).+)?$", line.split(";", 1)[0].strip())
            if match:
                values.append({"ecosystem": "PyPI", "name": match[1], "constraint": match[2] or "", "scope": "requirements"})
    elif path == "pom.xml":
        root = ET.fromstring(text)
        for dependency in root.findall(".//{*}dependencies/{*}dependency"):
            group = dependency.findtext("{*}groupId")
            artifact = dependency.findtext("{*}artifactId")
            if group and artifact:
                values.append({"ecosystem": "Maven", "name": group + ":" + artifact, "constraint": dependency.findtext("{*}version") or "", "scope": dependency.findtext("{*}scope") or "compile"})
    elif path == "Cargo.toml":
        data = tomllib.loads(text)
        for scope in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, value in (data.get(scope) or {}).items():
                values.append({"ecosystem": "crates.io", "name": name, "constraint": value if isinstance(value, str) else str(value.get("version") or "") if isinstance(value, dict) else "", "scope": scope})
    elif path == "composer.json":
        data = json.loads(text)
        for scope in ("require", "require-dev"):
            for name, version in (data.get(scope) or {}).items():
                if isinstance(version, str):
                    values.append({"ecosystem": "Packagist", "name": name, "constraint": version, "scope": scope})
    elif path == "go.mod":
        block = False
        for line in text.splitlines():
            line = line.split("//", 1)[0].strip()
            if line == "require (":
                block = True
                continue
            if line == ")":
                block = False
            match = re.fullmatch(r"(?:require\s+)?([\w.~-]+(?:/[\w.~-]+)+)\s+(v[^\s]+)", line) if block or line.startswith("require ") else None
            if match:
                values.append({"ecosystem": "Go", "name": match[1], "constraint": match[2], "scope": "require"})
    elif path == "Dockerfile":
        for image in re.findall(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.I | re.M):
            values.append({"ecosystem": "container", "name": image, "constraint": "", "scope": "build_base_image"})
    return values[:maximum]


def normalize_developer(item, max_records=5000):
    from .normalization import NormalizationError

    metadata = item.get("metadata") or {}
    provider = metadata.get("provider")
    if provider not in PROVIDERS:
        raise NormalizationError("Unknown developer source provider")
    maximum = min(max_records, max(1, int(metadata.get("record_limit", max_records))))
    data = _object(item)
    kind = metadata.get("artifact_kind", "generic")
    entities = []
    edges = []

    def add(record):
        if len(entities) + len(edges) < maximum:
            entities.append(record)
            return True
        return False

    if kind == "manifest" or metadata.get("manifest_path"):
        path = str(metadata.get("manifest_path") or "").rsplit("/", 1)[-1]
        if path not in MANIFESTS:
            raise NormalizationError("Unsupported dependency manifest")
        payload = item["payload"]
        if isinstance(data, dict) and data.get("encoding") == "base64" and isinstance(data.get("content"), str):
            try:
                payload = base64.b64decode("".join(data["content"].split()), validate=True)
            except ValueError as error:
                raise NormalizationError("Invalid GitHub manifest encoding") from error
        artifact = _record(item, "developer_artifact", item.get("source_url") or path, path, {"manifest_path": path, "repository": metadata.get("repository"), "evidence_role": "declared_dependencies"})
        add(artifact)
        try:
            dependencies = _dependency_records(payload, path, maximum)
        except (ValueError, TypeError, AttributeError, UnicodeDecodeError, ET.ParseError) as error:
            raise NormalizationError("Invalid dependency manifest") from error
        for dependency in dependencies:
            record = _record(item, "software_evidence", dependency["ecosystem"] + ":" + dependency["name"] + ":" + dependency["scope"], dependency["name"], dependency)
            record["metadata"]["evidence_role"] = "declared_dependency"
            if add(record) and len(entities) + len(edges) < maximum:
                edges.append({"from_id": artifact["id"], "to_id": record["id"], "relation": "declares_dependency", "source_url": item.get("source_url") or "", "observed_at": item.get("observed_at") or item.get("received_at"), "confidence": 0.6})
    elif kind == "repositories":
        records = data.get("values", []) if isinstance(data, dict) else data
        if not isinstance(records, list):
            raise NormalizationError("Public repository response must contain an array")
        for record in records[:maximum]:
            if not isinstance(record, dict) or record.get("private") or record.get("is_private") or record.get("visibility", "public") != "public":
                continue
            links = record.get("links") if isinstance(record.get("links"), dict) else {}
            html_link = links.get("html") if isinstance(links.get("html"), dict) else {}
            url = record.get("html_url") or record.get("web_url") or html_link.get("href")
            name = record.get("full_name") or record.get("path_with_namespace") or record.get("name")
            if name:
                add(_record(item, "public_repository", url or name, name, {key: record.get(key) for key in ("description", "language", "default_branch", "updated_at", "pushed_at", "archived", "fork", "visibility")}))
    elif kind == "archive_index":
        if provider == "wayback_cdx":
            if not isinstance(data, list):
                raise NormalizationError("CDX index must be a JSON array")
            fields = data[0] if data and isinstance(data[0], list) else []
            if data and "original" not in fields:
                raise NormalizationError("CDX index header lacks original URL")
            records = [dict(zip(fields, row)) for row in data[1:maximum + 1] if isinstance(row, list)]
        else:
            try:
                records = [json.loads(line) for line in item["payload"].decode("utf-8-sig").splitlines()[:maximum] if line.strip()]
            except (ValueError, UnicodeDecodeError) as error:
                raise NormalizationError("Common Crawl index requires JSON lines") from error
        for record in records:
            if isinstance(record, dict):
                url = record.get("original") or record.get("url")
                if isinstance(url, str) and urlsplit(url).scheme in {"http", "https"}:
                    add(_record(item, "archived_url", url, url, {**record, "historical": True, "currently_reachable": None}))
    elif kind == "container_tags":
        records = data.get("results", data.get("tags", [])) if isinstance(data, dict) else None
        if not isinstance(records, list):
            raise NormalizationError("Container tag response must contain an array")
        for record in records[:maximum]:
            if isinstance(record, dict) and record.get("name"):
                repository = metadata.get("repository", "")
                fields = {key: record.get(key) for key in ("name", "digest", "manifest_digest", "last_modified", "last_updated", "size", "full_size")}
                images = record.get("images") or []
                fields["images"] = [{key: image.get(key) for key in ("architecture", "os", "os_version", "digest", "size")} for image in images[:20] if isinstance(image, dict)] if isinstance(images, list) else []
                fields["repository"] = repository
                add(_record(item, "container_tag", str(repository) + ":" + str(record["name"]), record["name"], fields))
    elif provider == "javascript_artifacts" and isinstance(data, dict) and data.get("version") == 3 and isinstance(data.get("sources"), list):
        artifact = _record(item, "developer_artifact", item.get("source_url"), data.get("file") or "Source map", {"file": data.get("file"), "sourceRoot": data.get("sourceRoot"), "source_count": len(data["sources"])})
        add(artifact)
        for source in data["sources"][:maximum]:
            if isinstance(source, str):
                add(_record(item, "source_reference", source, source, {"source_map": item.get("source_url"), "path": source}))
                package = re.search(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)", source)
                if package:
                    add(_record(item, "software_evidence", "npm:" + package[1], package[1], {"ecosystem": "npm", "name": package[1], "constraint": "", "scope": "source_map_reference"}))
    elif provider in {"postman_public", "swaggerhub_public"} and isinstance(data, dict) and ("openapi" in data or "swagger" in data or "item" in data):
        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        artifact = _record(item, "api_specification", item.get("source_url"), info.get("title") or info.get("name") or "Public API specification", {"format": "openapi" if "paths" in data else "postman", "info": info, "servers": data.get("servers"), "host": data.get("host"), "basePath": data.get("basePath")})
        add(artifact)
        if isinstance(data.get("paths"), dict):
            for path, methods in list(data["paths"].items())[:maximum]:
                if isinstance(methods, dict):
                    for method in methods:
                        if method.lower() in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
                            add(_record(item, "api_route", method.upper() + " " + str(path), method.upper() + " " + str(path), {"method": method.upper(), "path": path, "specification": item.get("source_url"), "exposure_verified": False}))
        else:
            if not isinstance(data.get("item"), list):
                raise NormalizationError("Postman collection item must be an array")
            pending = list(data.get("item") or [])[:maximum]
            inspected = 0
            while pending and inspected < maximum:
                record = pending.pop(0)
                inspected += 1
                if not isinstance(record, dict):
                    continue
                if isinstance(record.get("item"), list):
                    pending.extend(record["item"][:maximum - inspected])
                request = record.get("request")
                if isinstance(request, dict):
                    url = request.get("url")
                    url = url.get("raw") if isinstance(url, dict) else url
                    if isinstance(url, str):
                        method = str(request.get("method") or "GET").upper()
                        add(_record(item, "api_route", method + " " + url, record.get("name") or method + " " + url, {"method": method, "declared_url": url, "specification": item.get("source_url"), "exposure_verified": False}))
    else:
        if data is not None:
            fields = {"data": _short(data)}
            name = provider + " public metadata"
        else:
            text = item["payload"].decode("utf-8", errors="replace")
            soup = BeautifulSoup(text, "html.parser") if "<" in text[:1000] else None
            name = soup.title.get_text(" ", strip=True) if soup is not None and soup.title else provider + " public artifact"
            fields = {"text": soup.get_text(" ", strip=True)[:10000] if soup is not None else text[:10000]}
        add(_record(item, "developer_artifact", item.get("source_url") or item.get("payload_hash"), name, fields))
        if provider == "javascript_artifacts":
            text = item["payload"].decode("utf-8", errors="replace")
            for url in dict.fromkeys(re.findall(r"https?://[^\s\"'<>`\\]+", text)):
                if len(entities) + len(edges) >= maximum:
                    break
                try:
                    _url(url)
                except ValueError:
                    continue
                add(_record(item, "source_reference", url, url, {"declared_url": url, "exposure_verified": False}))
    return {"entities": entities, "edges": edges}
