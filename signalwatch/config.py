import json
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


VERSION = "0.5.0"


DEFAULTS = {
    "db": "data/signalwatch.db",
    "cache_dir": "data/cache",
    "host": "127.0.0.1",
    "port": 8765,
    "cors_origins": [],
    "api_token": "",
    "concurrency": 32,
    "per_host": 4,
    "timeout": 30,
    "max_response_mb": 32,
    "crawl_pages": 8,
    "crawl_depth": 1,
    "crawl_batch": 50,
    "crawl_interval_hours": 24,
    "max_discovered_domains": 10000,
    "user_agent": f"SignalWatch/{VERSION} (+public-source intelligence collector)",
    "headers": {},
    "interval_minutes": 30,
    "bootstrap_days": 30,
    "nvd_api_key": "",
    "github_token": "",
    "osv_max_records": 500,
    "osv_index_chunk_mb": 1,
    "osv_index_chunks": 8,
    "osv_index_max_chunks": 32,
    "cve_max_records": 250,
    "cve_max_zip_mb": 16,
    "csaf_max_records": 100,
    "network_batch": 20,
    "network_interval_hours": 24,
    "news_concurrency": 8,
    "dns_mode": "fallback",
    "dns_doh_url": "https://dns.google/resolve",
    "dns_timeout": 5,
    "dns_concurrency": 4,
    "sbom_max_mb": 20,
    "events_max_rows": 50000,
    "events_retention_days": 90,
    "sources": {
        "nvd": True,
        "kev": True,
        "epss": True,
        "github": True,
        "osv": True,
        "cve_program": True,
        "csaf": True,
        "network": True,
        "wikidata": True,
        "news": True,
        "web": True
    },
    "feeds": [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
        {"name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed_full.xml"},
        {"name": "CERT-EU", "url": "https://cert.europa.eu/publications/security-advisories-rss"},
        {"name": "Microsoft Security Response Center", "url": "https://api.msrc.microsoft.com/update-guide/rss"},
        {"name": "Fortinet PSIRT", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml"},
        {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek"},
        {"name": "Debian Security Advisories", "url": "https://www.debian.org/security/dsa"},
        {"name": "Ubuntu Security Notices", "url": "https://ubuntu.com/security/notices/rss.xml"},
        {"name": "CERT/CC Vulnerability Notes", "url": "https://www.kb.cert.org/vuls/atomfeed/"},
        {"name": "Palo Alto Networks PSIRT", "url": "https://security.paloaltonetworks.com/rss.xml"}
    ],
    "csaf_feeds": [
        {"name": "CISA Operational Technology", "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"},
        {"name": "CISA Information Technology", "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json"},
        {"name": "CISA Vulnerability Advisories", "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/VA/white/cisa-csaf-va-feed-tlp-white.json"},
        {"name": "Siemens ProductCERT", "url": "https://productcert.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"}
    ],
    "seed_urls": [
        "https://www.apache.org/", "https://nginx.org/", "https://www.openssl.org/",
        "https://www.cisco.com/", "https://www.fortinet.com/", "https://www.tp-link.com/",
        "https://www.synology.com/", "https://www.qnap.com/", "https://www.microsoft.com/",
        "https://www.ubuntu.com/", "https://www.redhat.com/", "https://www.siemens.com/"
    ]
}


def load_config(path="config.json"):
    path = Path(path).expanduser().resolve()
    config = json.loads(json.dumps(DEFAULTS))
    if path.exists():
        supplied = json.loads(path.read_text())
        for key, value in supplied.items():
            if key == "sources":
                config[key].update(value)
            else:
                config[key] = value
    config["nvd_api_key"] = os.environ.get("NVD_API_KEY", config["nvd_api_key"])
    config["github_token"] = os.environ.get("GITHUB_TOKEN", config["github_token"])
    config["api_token"] = os.environ.get("SIGNALWATCH_API_TOKEN", config["api_token"])
    if "SIGNALWATCH_CORS_ORIGINS" in os.environ:
        config["cors_origins"] = [origin.strip() for origin in os.environ["SIGNALWATCH_CORS_ORIGINS"].split(",") if origin.strip()]
    if not isinstance(config["api_token"], str):
        raise ValueError("api_token must be a string")
    if not isinstance(config["cors_origins"], list):
        raise ValueError("cors_origins must be an array of exact HTTP(S) origins")
    origins = []
    for origin in config["cors_origins"]:
        if not isinstance(origin, str) or "*" in origin:
            raise ValueError("cors_origins must contain exact HTTP(S) origins without wildcards")
        parsed = urlsplit(origin.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("cors_origins must contain exact HTTP(S) origins without paths or credentials")
        parsed.port
        origins.append(urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", "")))
    config["cors_origins"] = list(dict.fromkeys(origins))
    for name in ("db", "cache_dir"):
        target = Path(config[name]).expanduser()
        config[name] = str(target if target.is_absolute() else path.parent / target)
    for name in ("concurrency", "per_host", "timeout", "crawl_pages", "crawl_batch", "interval_minutes",
                 "osv_max_records", "osv_index_chunk_mb", "osv_index_chunks", "osv_index_max_chunks", "cve_max_records",
                 "cve_max_zip_mb", "csaf_max_records", "network_batch", "network_interval_hours", "news_concurrency"):
        if int(config[name]) < 1:
            raise ValueError(f"{name} must be positive")
    for name in ("dns_timeout", "dns_concurrency", "sbom_max_mb", "events_max_rows", "events_retention_days"):
        if float(config[name]) <= 0:
            raise ValueError(f"{name} must be positive")
    if config["dns_mode"] not in {"system", "fallback", "doh"}:
        raise ValueError("dns_mode must be system, fallback, or doh")
    config["config_path"] = str(path)
    return config
