import asyncio
import email.utils
import hashlib
import json
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path

import aiohttp


class HTTPError(RuntimeError):
    def __init__(self, status, url, detail=""):
        self.status = status
        self.url = url
        super().__init__(f"HTTP {status}: {url} {detail}".strip())


@dataclass(frozen=True)
class FetchResult:
    path: Path
    status: int
    headers: dict
    url: str
    changed: bool
    digest: str


def retry_delay(value, attempt):
    try:
        return min(60.0, max(0.0, float(value)))
    except (ValueError, TypeError):
        try:
            return min(60.0, max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time()))
        except (ValueError, TypeError, AttributeError):
            return min(30.0, 2 ** attempt + random.random())


class PublicHTTP:
    def __init__(self, config):
        self.config = config
        self.cache = Path(config["cache_dir"])
        self.cache.mkdir(parents=True, exist_ok=True)
        self.session = None
        self.locks = {}
        self.host_wait = {}

    async def __aenter__(self):
        headers = {"User-Agent": self.config["user_agent"], **self.config.get("headers", {})}
        connector = aiohttp.TCPConnector(
            limit=int(self.config["concurrency"]),
            limit_per_host=int(self.config["per_host"]),
            ttl_dns_cache=600,
        )
        timeout = aiohttp.ClientTimeout(total=float(self.config["timeout"]), connect=10)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers, trust_env=True)
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def get(self, url, *, params=None, headers=None, max_bytes=None, cache=True, force=False, allow_redirects=True):
        request_url = str(aiohttp.client_reqrep.URL(url).with_query(params)) if params else url
        representation = "\n".join(f"{key.lower()}:{value}" for key, value in sorted((headers or {}).items()) if key.lower() in {"range", "accept", "accept-language"})
        key = hashlib.sha256(f"{request_url}\n{representation}".encode()).hexdigest()
        lock = self.locks.setdefault(key, asyncio.Lock())
        async with lock:
            return await self._get(request_url, key, headers or {}, max_bytes, cache, force, allow_redirects)

    async def _get(self, url, key, headers, max_bytes, cache, force, allow_redirects):
        body = self.cache / f"{key}.body"
        meta_path = self.cache / f"{key}.json"
        meta = {}
        if cache and meta_path.exists() and body.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except (OSError, ValueError):
                meta = {}
        request_headers = dict(headers)
        if not force and meta:
            if meta.get("etag"):
                request_headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                request_headers["If-Modified-Since"] = meta["last_modified"]
        limit = max_bytes if max_bytes is not None else int(self.config["max_response_mb"]) * 1024 * 1024
        host = aiohttp.client_reqrep.URL(url).host
        for attempt in range(4):
            delay = self.host_wait.get(host, 0) - time.monotonic()
            if delay > 0:
                await asyncio.sleep(min(delay, 60))
            temp = self.cache / f"{key}.{os.getpid()}.{random.getrandbits(64):016x}.part"
            try:
                async with self.session.get(url, headers=request_headers, allow_redirects=allow_redirects) as response:
                    response_headers = dict(response.headers)
                    if response.status == 304 and body.exists():
                        return FetchResult(body, 304, {**meta.get("headers", {}), **response_headers}, str(response.url), False, meta.get("digest", ""))
                    if response.status in (429, 503) and attempt < 3:
                        wait = retry_delay(response.headers.get("Retry-After"), attempt)
                        self.host_wait[host] = time.monotonic() + wait
                        await response.read()
                        await asyncio.sleep(wait)
                        continue
                    if response.status >= 400:
                        detail = (await response.content.read(256)).decode(errors="replace")
                        raise HTTPError(response.status, str(response.url), detail)
                    size = 0
                    digest = hashlib.sha256()
                    with temp.open("wb") as stream:
                        async for chunk in response.content.iter_chunked(256 * 1024):
                            size += len(chunk)
                            if size > limit:
                                raise ValueError(f"Response exceeds {limit} bytes: {url}")
                            stream.write(chunk)
                            digest.update(chunk)
                    value = digest.hexdigest()
                    changed = value != meta.get("digest")
                    temp.replace(body)
                    metadata = {
                        "url": str(response.url), "etag": response.headers.get("ETag"),
                        "last_modified": response.headers.get("Last-Modified"),
                        "digest": value, "size": size, "fetched_at": time.time(),
                        "headers": {key: value for key, value in response_headers.items() if key.lower() != "set-cookie"},
                    }
                    if cache:
                        meta_temp = meta_path.with_suffix(".json.tmp")
                        meta_temp.write_text(json.dumps(metadata, separators=(",", ":")))
                        meta_temp.replace(meta_path)
                    return FetchResult(body, response.status, response_headers, str(response.url), changed, value)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == 3:
                    raise
                await asyncio.sleep(retry_delay(None, attempt))
            finally:
                temp.unlink(missing_ok=True)
        raise RuntimeError(f"Request failed: {url}")
