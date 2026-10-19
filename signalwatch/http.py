import asyncio
import email.utils
import hashlib
import json
import math
import os
import random
import socket
import time
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import aiohttp


def display_url(url):
    """Keep the useful request location without query strings or credentials."""
    try:
        parsed = urlsplit(str(url))
        host = parsed.hostname or "unknown host"
        if ":" in host:
            host = f"[{host}]"
        if parsed.port:
            host += f":{parsed.port}"
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme, host, path[:180], "", ""))
    except ValueError:
        return "invalid request URL"


class PublicRequestError(RuntimeError):
    def __init__(self, reason, url):
        self.reason = reason
        super().__init__(f"{reason}: {display_url(url)}")


def public_error(error):
    if isinstance(error, (HTTPError, PublicRequestError)):
        return str(error)
    return f"{type(error).__name__} while collecting public metadata"


class HTTPError(RuntimeError):
    def __init__(self, status, url, detail="", *, retry_after=None):
        self.status = status
        self.url = display_url(url)
        self.retry_after = retry_after
        try:
            reason = HTTPStatus(status).phrase
        except ValueError:
            reason = "Request failed"
        message = f"HTTP {status} {reason}: {self.url}"
        # Response bodies frequently contain entire error pages; they are not useful
        # collector diagnostics and may echo query parameters or other request data.
        if detail and "<" not in detail:
            message += ". " + " ".join(str(detail).split())[:180]
        if retry_after is not None:
            message += f". Retry after {math.ceil(retry_after)} seconds"
        super().__init__(message)


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
        delay = float(value)
        if math.isfinite(delay):
            return max(0.0, delay)
    except (ValueError, TypeError):
        try:
            return max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())
        except (ValueError, TypeError, AttributeError, OverflowError):
            pass
    return min(30.0, 2 ** attempt + random.random())


class PublicHTTP:
    def __init__(self, config):
        self.config = config
        self.cache = Path(config["cache_dir"])
        self.cache.mkdir(parents=True, exist_ok=True)
        self.session = None
        self.locks = {}
        self.host_wait = {}
        self.host_status = {}

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

    async def get(self, url, *, params=None, headers=None, max_bytes=None, cache=True, force=False, allow_redirects=True, max_attempts=4):
        if not 1 <= max_attempts <= 4:
            raise ValueError("max_attempts must be between 1 and 4")
        request_url = str(aiohttp.client_reqrep.URL(url).with_query(params)) if params else url
        representation = "\n".join(f"{key.lower()}:{value}" for key, value in sorted((headers or {}).items()) if key.lower() in {"range", "accept", "accept-language"})
        key = hashlib.sha256(f"{request_url}\n{representation}".encode()).hexdigest()
        return await self._get(request_url, key, headers or {}, max_bytes, cache, force, allow_redirects, max_attempts)

    async def post(self, url, *, json=None, data=None, headers=None, max_bytes=None, allow_redirects=False, max_attempts=1):
        from json import dumps
        if not 1 <= max_attempts <= 4:
            raise ValueError("max_attempts must be between 1 and 4")
        if json is not None and data is not None:
            raise ValueError("Supply JSON or form data, not both")
        representation = dumps([json, data, headers or {}], sort_keys=True, default=str, separators=(",", ":"))
        key = hashlib.sha256((url + "\nPOST\n" + representation).encode()).hexdigest()
        return await self._get(url, key, headers or {}, max_bytes, False, True, allow_redirects,
                               max_attempts, method="POST", request_body={"json": json, "data": data})

    async def _get(self, url, key, headers, max_bytes, cache, force, allow_redirects, max_attempts,
                   method="GET", request_body=None):
        body = self.cache / f"{key}.body"
        meta_path = self.cache / f"{key}.json"
        limit = max_bytes if max_bytes is not None else int(self.config["max_response_mb"]) * 1024 * 1024
        host = aiohttp.client_reqrep.URL(url).host
        attempt = 0
        while attempt < max_attempts:
            delay = self.host_wait.get(host, 0) - time.monotonic()
            while delay > 0:
                if delay > 60:
                    # Leave long cooldowns to the scheduler rather than tying up a
                    # collection cycle or silently shortening Retry-After.
                    raise HTTPError(self.host_status.get(host, 429), url, retry_after=delay)
                await asyncio.sleep(delay)
                delay = self.host_wait.get(host, 0) - time.monotonic()
            temp = self.cache / f"{key}.{os.getpid()}.{random.getrandbits(64):016x}.part"
            try:
                lock = self.locks.setdefault(key, asyncio.Lock())
                async with lock:
                    # A request ahead of us may have established a cooldown while
                    # we awaited this cache lock. Release it and wait outside;
                    # cooldown checks never consume a network attempt.
                    remaining = self.host_wait.get(host, 0) - time.monotonic()
                    if remaining > 0:
                        continue
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
                    request = self.session.get if method == "GET" else self.session.post
                    attempt += 1
                    async with request(url, headers=request_headers, allow_redirects=allow_redirects, **(request_body or {})) as response:
                        response_headers = dict(response.headers)
                        if response.status == 304 and body.exists():
                            return FetchResult(body, 304, {**meta.get("headers", {}), **response_headers}, str(response.url), False, meta.get("digest", ""))
                        if response.status in (429, 502, 503, 504):
                            wait = max(1.0, retry_delay(response.headers.get("Retry-After"), attempt - 1))
                            self.host_wait[host] = max(self.host_wait.get(host, 0), time.monotonic() + wait)
                            self.host_status[host] = response.status
                            if attempt < max_attempts and wait <= 60:
                                continue
                            raise HTTPError(response.status, str(response.url), retry_after=wait)
                        if response.status >= 400:
                            raise HTTPError(response.status, str(response.url))
                        size = 0
                        digest = hashlib.sha256()
                        with temp.open("wb") as stream:
                            async for chunk in response.content.iter_chunked(256 * 1024):
                                size += len(chunk)
                                if size > limit:
                                    raise ValueError(f"Response exceeds {limit} bytes: {display_url(url)}")
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
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                permanent = isinstance(error, (aiohttp.ClientSSLError, aiohttp.TooManyRedirects)) or (
                    isinstance(error, aiohttp.ClientConnectorError) and isinstance(error.os_error, socket.gaierror)
                    and error.os_error.errno in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}
                )
                if attempt == max_attempts or permanent:
                    if isinstance(error, asyncio.TimeoutError):
                        reason = "Connection timed out"
                    elif isinstance(error, aiohttp.ClientConnectorCertificateError):
                        reason = "TLS certificate verification failed"
                    elif isinstance(error, aiohttp.ClientSSLError):
                        reason = "TLS connection failed"
                    elif isinstance(error, aiohttp.TooManyRedirects):
                        reason = "Too many HTTP redirects"
                    elif isinstance(error, aiohttp.ClientConnectorError) and isinstance(error.os_error, socket.gaierror):
                        reason = "DNS lookup failed"
                    else:
                        reason = "Connection failed"
                    raise PublicRequestError(reason, url) from error
                await asyncio.sleep(retry_delay(None, attempt - 1))
            finally:
                temp.unlink(missing_ok=True)
        raise RuntimeError(f"Request failed: {display_url(url)}")
