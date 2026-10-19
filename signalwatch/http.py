import asyncio
import email.utils
import hashlib
import json
import math
import os
import random
import socket
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from multidict import CIMultiDict

from .proxies import ProxyPool, ProxyUnavailableError, direct_hosts_from_env


_REDIRECT_CREDENTIAL_HEADERS = frozenset({
    "authorization", "proxyauthorization", "cookie", "apikey", "xapikey", "key",
    "authkey", "xauthkey", "authtoken", "xauthtoken", "apitoken", "xapitoken",
    "accesstoken", "xaccesstoken", "xgoogapikey",
})


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
    def __init__(self, reason, url, *, retry_after=None):
        self.reason = reason
        self.retry_after = retry_after
        message = f"{reason}: {display_url(url)}"
        if retry_after is not None:
            message += f". Retry after {math.ceil(retry_after)} seconds"
        super().__init__(message)


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
        self.host_slots = {}
        self.restored_hosts = set()
        self.proxy_pool = ProxyPool.from_env()
        self.proxy_direct_hosts = direct_hosts_from_env()

    def _cooldown_path(self, host):
        return self.cache / ("cooldown-" + hashlib.sha256(str(host).encode()).hexdigest() + ".json")

    def _restore_cooldown(self, host):
        if host in self.restored_hosts:
            return
        self.restored_hosts.add(host)
        path = self._cooldown_path(host)
        try:
            value = json.loads(path.read_text())
            remaining = float(value["until"]) - time.time()
            status = int(value["status"])
            if math.isfinite(remaining) and remaining > 0 and status in {403, 429, 502, 503, 504}:
                self.host_wait[host] = max(self.host_wait.get(host, 0), time.monotonic() + remaining)
                self.host_status[host] = status
            else:
                path.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            pass

    def _cooldown(self, host, status, delay):
        self._restore_cooldown(host)
        self.host_wait[host] = max(self.host_wait.get(host, 0), time.monotonic() + delay)
        self.host_status[host] = status
        # Persist only the origin's deadline/status, never proxy or request secrets.
        path = self._cooldown_path(host)
        remaining = max(0, self.host_wait[host] - time.monotonic())
        self._persist_cooldown(path, time.time() + remaining, status)

    def _persist_cooldown(self, path, until, status):
        temporary = path.with_suffix(f".{os.getpid()}.{random.getrandbits(64):016x}.tmp")
        try:
            temporary.write_text(json.dumps({"until": until, "status": status}))
            temporary.replace(path)
        except OSError:
            # A cache write failure must not replace the server's HTTP diagnosis
            # or drop the in-memory backoff.
            pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _proxy_cooldown(self):
        if self.proxy_pool is None:
            return None, 0
        path = self.cache / f"proxy-cooldown-{self.proxy_pool.cache_key}.json"
        try:
            value = json.loads(path.read_text())
            until = float(value["until"])
            if math.isfinite(until) and int(value["status"]) in {403, 429, 502, 503, 504}:
                return path, until
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            pass
        return path, 0

    def _restore_proxy_cooldown(self):
        # Other PublicHTTP instances can share this configured gateway. Re-read
        # before every hop so a fresh client cannot skip its Retry-After period.
        path, until = self._proxy_cooldown()
        remaining = until - time.time()
        if path is not None and remaining > 0:
            self.proxy_pool.defer(remaining)

    def _defer_proxy(self, status, delay):
        path, previous = self._proxy_cooldown()
        if path is not None:
            until = max(previous, time.time() + delay)
            self.proxy_pool.defer(max(0, until - time.time()))
            self._persist_cooldown(path, until, status)

    async def __aenter__(self):
        # Apply configured headers per logical request so a cross-origin redirect
        # can remove credentials without ClientSession restoring its defaults.
        headers = {"User-Agent": self.config["user_agent"]}
        connector = aiohttp.TCPConnector(
            limit=int(self.config["concurrency"]),
            limit_per_host=int(self.config["per_host"]),
            ttl_dns_cache=600,
        )
        timeout = aiohttp.ClientTimeout(total=float(self.config["timeout"]), connect=10)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers,
                                             trust_env=self.proxy_pool is None)
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    @asynccontextmanager
    async def _request(self, url, *, method, headers, request_body, allow_redirects, proxy, state):
        """Follow bounded redirects while checking each actual destination."""
        current = aiohttp.client_reqrep.URL(url)
        request_headers = CIMultiDict(headers)
        request_body = dict(request_body or {})
        redirects = 0
        auth = None
        remaining_timeout = float(self.config["timeout"])
        while True:
            if current.user is not None:
                auth = aiohttp.BasicAuth.from_url(current)
                current = current.with_user(None)
            host = current.host
            self._restore_cooldown(host)
            delay = self.host_wait.get(host, 0) - time.monotonic()
            if delay > 0:
                if delay > 60:
                    raise HTTPError(self.host_status.get(host, 429), str(current), retry_after=delay)
                await asyncio.sleep(delay)
                continue
            # Release the previous host's slot before waiting for the next host.
            slot = self.host_slots.setdefault(host, asyncio.Semaphore(int(self.config["per_host"])))
            async with slot:
                if self.host_wait.get(host, 0) > time.monotonic():
                    continue
                hop_proxy = None
                route_host = (current.raw_host or host).lower().removesuffix(".")
                if self.proxy_pool and route_host not in self.proxy_direct_hosts:
                    self._restore_proxy_cooldown()
                    try:
                        if proxy is None:
                            proxy = self.proxy_pool.choose()
                        self.proxy_pool.ensure_available(proxy)
                        hop_proxy = proxy
                    except ProxyUnavailableError as exc:
                        raise PublicRequestError(str(exc), str(current), retry_after=exc.retry_after) from None
                state["proxy"] = hop_proxy
                state["retained_proxy"] = proxy
                options = dict(request_body)
                if hop_proxy is not None:
                    options.update(proxy=hop_proxy.url, proxy_auth=hop_proxy.auth)
                if auth is not None:
                    options["auth"] = auth
                if remaining_timeout <= 0:
                    raise asyncio.TimeoutError
                options["timeout"] = aiohttp.ClientTimeout(total=remaining_timeout, connect=min(10, remaining_timeout))
                request = self.session.get if method == "GET" else self.session.post
                state["url"] = str(current)
                started = time.monotonic()
                async with request(str(current), headers=CIMultiDict(request_headers), allow_redirects=False, **options) as response:
                    if allow_redirects and response.status in {301, 302, 303, 307, 308}:
                        redirects += 1
                        if redirects >= 10:
                            raise PublicRequestError("Too many HTTP redirects", str(current))
                        response_headers = CIMultiDict(response.headers)
                        location = response_headers.get("Location") or response_headers.get("URI")
                        if location is not None:
                            try:
                                target = aiohttp.client_reqrep.URL(location)
                                if target.scheme not in {"", "http", "https"}:
                                    raise ValueError
                                if not target.scheme or (target.scheme == current.scheme and not target.raw_authority):
                                    target = current.join(target)
                                cross_origin = current.origin() != target.origin()
                            except (ValueError, TypeError):
                                raise PublicRequestError("Invalid HTTP redirect", str(current)) from None
                            if cross_origin:
                                auth = None
                                # Provider keys (including NVD's apiKey) are
                                # credentials too, even without Authorization.
                                for name in tuple(request_headers):
                                    normalized = name.lower().replace("-", "").replace("_", "")
                                    if normalized in _REDIRECT_CREDENTIAL_HEADERS:
                                        request_headers.popall(name, None)
                            if response.status == 303 or (response.status in {301, 302} and method == "POST"):
                                method = "GET"
                                request_body = {}
                                request_headers.popall("Content-Length", None)
                            else:
                                data = request_body.get("data")
                                if hasattr(data, "read") or hasattr(data, "__aiter__"):
                                    # A separate aiohttp request may already have consumed
                                    # or closed a streaming body. Never replay it as empty.
                                    raise PublicRequestError("Cannot replay a streaming request body after redirect", str(current))
                            current = target
                            remaining_timeout -= time.monotonic() - started
                            continue
                    yield response
                    return

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
        proxy = None
        self._restore_cooldown(host)
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
            request_state = {"url": url, "proxy": None}
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
                    request_headers = CIMultiDict(self.config.get("headers", {}))
                    request_headers.update(headers)
                    if not force and meta:
                        if meta.get("etag"):
                            request_headers["If-None-Match"] = meta["etag"]
                        if meta.get("last_modified"):
                            request_headers["If-Modified-Since"] = meta["last_modified"]
                    attempt += 1
                    async with self._request(url, method=method, headers=request_headers,
                                             request_body=request_body, allow_redirects=allow_redirects,
                                             proxy=proxy, state=request_state) as response:
                        proxy = request_state.get("retained_proxy", proxy)
                        response_headers = CIMultiDict(response.headers)
                        if response.status == 304:
                            if (not cache or force or not meta or not body.exists()
                                    or not (meta.get("etag") or meta.get("last_modified"))):
                                raise PublicRequestError("HTTP 304 without a usable cached response", str(response.url))
                            if body.stat().st_size > limit:
                                raise ValueError(f"Response exceeds {limit} bytes: {display_url(url)}")
                            cached_headers = CIMultiDict(meta.get("headers", {}))
                            cached_headers.update(response_headers)
                            return FetchResult(body, 304, cached_headers, str(response.url), False, meta.get("digest", ""))
                        limited_403 = response.status == 403 and (
                            response_headers.get("Retry-After") is not None
                            or response_headers.get("X-RateLimit-Remaining") == "0")
                        if response.status in (429, 502, 503, 504) or limited_403:
                            wait = max(1.0, retry_delay(response_headers.get("Retry-After"), attempt - 1))
                            if limited_403:
                                wait = max(wait, 60.0)
                                try:
                                    reset = float(response_headers.get("X-RateLimit-Reset", "")) - time.time()
                                    if math.isfinite(reset):
                                        wait = max(wait, reset)
                                except ValueError:
                                    pass
                            for cooldown_host in {host, aiohttp.client_reqrep.URL(str(response.url)).host}:
                                self._cooldown(cooldown_host, response.status, wait)
                            # Retain the same proxy on origin HTTP responses. A different
                            # address must not skip an authentication/access/rate limit.
                            if not limited_403 and attempt < max_attempts and wait <= 60:
                                continue
                            raise HTTPError(response.status, str(response.url), retry_after=wait)
                        if response.status == 407 and request_state["proxy"] is not None:
                            self.proxy_pool.reject_auth()
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
                        # A successful uncached fetch still replaces this body.
                        # Remove its old validators first so later revalidation
                        # cannot pair the new bytes with the previous digest.
                        if not cache:
                            meta_path.unlink(missing_ok=True)
                        temp.replace(body)
                        metadata = {
                            "url": str(response.url), "etag": response_headers.get("ETag"),
                            "last_modified": response_headers.get("Last-Modified"),
                            "digest": value, "size": size, "fetched_at": time.time(),
                            "headers": {key: value for key, value in response_headers.items() if key.lower() != "set-cookie"},
                        }
                        if cache:
                            meta_temp = meta_path.with_suffix(".json.tmp")
                            meta_temp.write_text(json.dumps(metadata, separators=(",", ":")))
                            meta_temp.replace(meta_path)
                        return FetchResult(body, response.status, response_headers, str(response.url), changed, value)
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                failed_url = request_state["url"]
                failed_host = aiohttp.client_reqrep.URL(failed_url).host
                active_proxy = request_state["proxy"]
                proxy = request_state.get("retained_proxy", proxy)
                proxy_error = isinstance(error, aiohttp.ClientHttpProxyError)
                proxy_denied = proxy_error and 400 <= error.status < 500
                if proxy_error and error.status == 407 and active_proxy is not None:
                    self.proxy_pool.reject_auth()
                proxy_retry_after = CIMultiDict(error.headers or {}).get("Retry-After") if proxy_error else None
                if proxy_error and (error.status == 429 or (error.status in {403, 502, 503, 504} and proxy_retry_after is not None)):
                    wait = max(1.0, retry_delay(proxy_retry_after, attempt - 1))
                    self._cooldown(failed_host, error.status, wait)
                    if active_proxy is not None:
                        self._defer_proxy(error.status, wait)
                    raise PublicRequestError(f"Proxy HTTP {error.status}", failed_url, retry_after=wait) from None
                permanent = proxy_denied or isinstance(error, (aiohttp.ClientSSLError, aiohttp.TooManyRedirects)) or (
                    active_proxy is None and isinstance(error, aiohttp.ClientConnectorError)
                    and isinstance(error.os_error, socket.gaierror)
                    and error.os_error.errno in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}
                )
                if active_proxy is not None and not permanent:
                    self.proxy_pool.fail(active_proxy)
                    proxy = None
                if attempt == max_attempts or permanent:
                    if isinstance(error, asyncio.TimeoutError):
                        reason = "Connection timed out"
                    elif proxy_error:
                        reason = f"Proxy HTTP {error.status}"
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
                    # aiohttp exception chains can contain proxy authentication,
                    # headers and query strings. Keep only the typed diagnosis.
                    raise PublicRequestError(reason, failed_url) from None
                await asyncio.sleep(retry_delay(None, attempt - 1))
            finally:
                temp.unlink(missing_ok=True)
        raise RuntimeError(f"Request failed: {display_url(url)}")
