"""Environment-only proxy configuration for the public HTTP collector client."""

import hashlib
import ipaddress
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp


MAX_PROXY_BYTES = 256 * 1024
MAX_PROXIES = 256
DEFAULT_DIRECT_HOSTS = "www.cisa.gov,nvd.nist.gov,services.nvd.nist.gov"


class ProxyConfigurationError(ValueError):
    """A sanitized configuration error safe to show in collector diagnostics."""


class ProxyUnavailableError(RuntimeError):
    def __init__(self, message="No proxy is currently available", *, retry_after=None):
        self.retry_after = retry_after
        super().__init__(message)


@dataclass(frozen=True)
class ProxyEndpoint:
    url: str
    auth: aiohttp.BasicAuth | None = field(default=None, repr=False)


def _host(value):
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ProxyConfigurationError("Invalid proxy hostname")
    bracketed = value.startswith("[") and value.endswith("]")
    if bracketed:
        value = value[1:-1]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if bracketed:
            raise ProxyConfigurationError("Invalid proxy hostname") from None
        # Keep proxy authorities unambiguous: no URL escapes, credentials, paths,
        # IPv6 scope identifiers, or malformed numeric IP literals.
        try:
            hostname = value.encode("idna").decode("ascii").lower().removesuffix(".")
        except UnicodeError:
            raise ProxyConfigurationError("Invalid proxy hostname") from None
        if (not hostname or len(hostname) > 253 or re.fullmatch(r"[0-9.]+", hostname)
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                       for label in hostname.split("."))):
            raise ProxyConfigurationError("Invalid proxy hostname") from None
        return hostname
    if "%" in value or (bracketed and address.version != 6):
        raise ProxyConfigurationError("Invalid proxy hostname")
    return f"[{address.compressed}]" if address.version == 6 else str(address)


def _port(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ProxyConfigurationError("Invalid proxy port")
    return value


def direct_hosts_from_env(environ=None):
    """Exact public destinations intentionally collected without a proxy.

    Government feeds are unavailable through providers that restrict government
    targets. This is a routing policy, never a fallback after a proxy denial.
    An explicitly empty value sends every destination through the configured pool.
    """
    env = os.environ if environ is None else environ
    value = env.get("SIGNALWATCH_PROXY_DIRECT_HOSTS", DEFAULT_DIRECT_HOSTS)
    if not isinstance(value, str) or len(value) > 16384:
        raise ProxyConfigurationError("Invalid direct proxy host list")
    try:
        return frozenset(_host(host.strip()).strip("[]") for host in value.split(",") if host.strip())
    except ProxyConfigurationError:
        raise ProxyConfigurationError("Direct proxy hosts must be exact hostnames without URLs, ports or wildcards") from None


def _endpoint_url(entry):
    if isinstance(entry, dict):
        return f"http://{_host(entry.get('entryPoint'))}:{_port(entry.get('port'))}"
    if not isinstance(entry, str) or not entry or any(ord(char) <= 32 or ord(char) == 127 for char in entry):
        raise ProxyConfigurationError("Invalid proxy entry")
    explicit_scheme = "://" in entry
    candidate = entry if explicit_scheme else "http://" + entry
    try:
        parsed = urlsplit(candidate)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc
                or parsed.path or "?" in candidate or "#" in candidate or "@" in parsed.netloc):
            raise ValueError
        authority = parsed.netloc
        if authority.startswith("["):
            if not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", authority):
                raise ValueError
        elif authority.count(":") > 1:
            raise ValueError
        # A trailing colon is not an omitted port.
        if authority.endswith(":"):
            raise ValueError
        port = parsed.port
        if port is None:
            if not explicit_scheme:
                raise ValueError
            port = 443 if parsed.scheme == "https" else 80
        return f"{parsed.scheme}://{_host(parsed.hostname)}:{_port(port)}"
    except (ValueError, UnicodeError):
        raise ProxyConfigurationError("Invalid proxy URL; use an HTTP(S) authority without credentials or a path") from None


def _load_entries(inline, filename):
    try:
        if filename:
            source = Path(filename)
            if not source.is_file():
                raise OSError
            with source.open("rb") as stream:
                raw = stream.read(MAX_PROXY_BYTES + 1)
        else:
            raw = inline.encode("utf-8")
        if len(raw) > MAX_PROXY_BYTES:
            raise ProxyConfigurationError("Proxy list exceeds the 256 KiB size limit")
        entries = json.loads(raw.decode("utf-8"))
    except ProxyConfigurationError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ProxyConfigurationError("Proxy list must be a readable UTF-8 JSON file or JSON value") from None
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_PROXIES:
        raise ProxyConfigurationError("Proxy list must contain between 1 and 256 entries")
    return entries


class ProxyPool:
    """Round-robin selection with local transport-failure cooldowns.

    A configured pool never falls back to a direct connection. Origin HTTP
    errors and Retry-After policies are handled by PublicHTTP, not by this pool.
    """

    def __init__(self, endpoints, *, clock=None):
        self._endpoints = tuple(endpoints)
        if not self._endpoints:
            raise ProxyConfigurationError("Proxy list must contain at least one endpoint")
        self._cache_key = hashlib.sha256("\n".join(sorted({endpoint.url for endpoint in self._endpoints})).encode()).hexdigest()
        self._clock = clock if clock is not None else time.monotonic
        self._next = 0
        self._cooldowns = {}
        self._deferred_until = 0
        self._auth_rejected = False

    @property
    def cache_key(self):
        """Stable cache identity for the endpoint set, independent of credentials."""
        return self._cache_key

    @classmethod
    def from_env(cls, environ=None, *, clock=None):
        env = os.environ if environ is None else environ
        inline = env.get("SIGNALWATCH_PROXY_LIST_JSON", "")
        filename = env.get("SIGNALWATCH_PROXY_LIST_FILE", "")
        username = env.get("SIGNALWATCH_PROXY_USERNAME", "")
        password = env.get("SIGNALWATCH_PROXY_PASSWORD", "")
        if inline and filename:
            raise ProxyConfigurationError("Set only one proxy list environment variable")
        if bool(username) != bool(password):
            raise ProxyConfigurationError("Proxy username and password must both be configured")
        if not inline and not filename:
            if username or password:
                raise ProxyConfigurationError("Proxy credentials require a proxy list")
            return None
        auth = None
        if username:
            try:
                if any(ord(char) < 32 or ord(char) == 127 for char in username + password):
                    raise ValueError
                auth = aiohttp.BasicAuth(username, password)
                auth.encode()  # Validate encoding before any network request.
            except (ValueError, UnicodeError):
                raise ProxyConfigurationError("Invalid proxy credentials") from None
        urls = dict.fromkeys(_endpoint_url(entry) for entry in _load_entries(inline, filename))
        return cls((ProxyEndpoint(url, auth) for url in urls), clock=clock)

    def choose(self, exclude=()):
        if self._auth_rejected:
            raise ProxyUnavailableError("Proxy authentication was rejected; check server-side credentials")
        excluded = {endpoint.url if isinstance(endpoint, ProxyEndpoint) else endpoint for endpoint in exclude}
        now = self._clock()
        if self._deferred_until > now:
            raise ProxyUnavailableError(retry_after=self._deferred_until - now)
        waits = []
        for offset in range(len(self._endpoints)):
            index = (self._next + offset) % len(self._endpoints)
            endpoint = self._endpoints[index]
            if endpoint.url in excluded:
                continue
            remaining = self._cooldowns.get(endpoint.url, 0) - now
            if remaining > 0:
                waits.append(remaining)
                continue
            self._next = (index + 1) % len(self._endpoints)
            return endpoint
        raise ProxyUnavailableError(retry_after=min(waits) if waits else None)

    def ensure_available(self, endpoint):
        """Recheck a retained endpoint before an HTTP retry without rotating."""
        if self._auth_rejected:
            raise ProxyUnavailableError("Proxy authentication was rejected; check server-side credentials")
        if endpoint not in self._endpoints:
            raise ProxyUnavailableError("Unknown proxy endpoint")
        remaining = max(self._deferred_until, self._cooldowns.get(endpoint.url, 0)) - self._clock()
        if remaining > 0:
            raise ProxyUnavailableError(retry_after=remaining)

    def fail(self, endpoint, cooldown=60):
        if not math.isfinite(cooldown) or cooldown < 0:
            raise ValueError("Proxy cooldown must be finite and nonnegative")
        if endpoint not in self._endpoints:
            raise ValueError("Unknown proxy endpoint")
        self._cooldowns[endpoint.url] = max(self._cooldowns.get(endpoint.url, 0), self._clock() + cooldown)

    def reject_auth(self):
        self._auth_rejected = True

    def defer(self, delay):
        """Honor a provider-wide cooldown without rotating around its limit."""
        if not math.isfinite(delay) or delay < 0:
            raise ValueError("Proxy cooldown must be finite and nonnegative")
        self._deferred_until = max(self._deferred_until, self._clock() + delay)
