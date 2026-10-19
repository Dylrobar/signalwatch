import json
import math
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


VERSION = "0.16.0"


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
    "user_agent": f"SignalWatch/{VERSION} (https://github.com/Dylrobar/signalwatch)",
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
    "staging_max_payload_mb": 8,
    "staging_max_mb": 512,
    "staging_max_records": 10000,
    "staging_batch": 25,
    "staging_poll_seconds": 2,
    "staging_retention_days": 7,
    "staging_max_completed": 10000,
    "wireless_import_max_mb": 32,
    "wireless_chunk_rows": 5000,
    "source_intervals": {"news": 15, "threat": 15, "prerelease": 60, "nvd": 360, "kev": 360, "epss": 360,
                         "github": 360, "osv": 360, "cve_program": 360, "csaf": 360,
                         "web": 5, "wikidata": 15, "network": 15,
                         "exposure": 30, "corporate": 15, "developer": 360, "hardware": 43200, "nmap": 1440},
    "public_source_batch": 3,
    "public_source_records": 100,
    "public_source_concurrency": 4,
    "threat_source_batch": 8,
    "source_targets": [{"name": "Apache Software Foundation", "domain": "apache.org", "github_org": "apache"},
                       {"name": "Cisco", "domain": "cisco.com", "github_org": "cisco"},
                       {"name": "Microsoft", "domain": "microsoft.com", "github_org": "microsoft", "cik": "0000789019"}],
    "watch_products": [],
    "exploit_keywords": ["exploit", "zero-day", "zero day", "rce", "remote code execution", "security fix", "security patch", "actively exploited", "authentication bypass", "memory corruption"],
    "provider_settings": {"nmap": {"enabled": True, "profile": "quick", "targets": [], "timeout": 900},
                          "ctlogs": {"enabled": True}, "certspotter": {"enabled": False},
                          "crtsh": {"enabled": True}, "dns_txt": {"enabled": True},
                          "gleif": {"enabled": True}, "corporate_discovery": {"enabled": True, "batch": 12},
                          "greenhouse": {"enabled": True}, "lever": {"enabled": True},
                          "ashby": {"enabled": True}, "company_feeds": {"enabled": True},
                          "technographics": {"enabled": True},
                          "importyeti_public": {"enabled": True},
                          "circl_misp": {"enabled": True}, "greynoise_public": {"enabled": True},
                          "fulldisclosure": {"enabled": True}, "oss_security": {"enabled": True},
                          "zdi_published": {"enabled": True}, "zdi_upcoming": {"enabled": True},
                          "dark_reading": {"enabled": True}, "apple_security": {"enabled": True},
                          "windows_insider": {"enabled": True}, "apple_developer": {"enabled": True}, "mikrotik_testing": {"enabled": True}},
    "provider_credentials": {},
    "sources": {
        "nvd": True,
        "kev": True,
        "epss": True,
        "github": True,
        "osv": True,
        "cve_program": True,
        "csaf": True,
        "network": True,
        "nmap": True,
        "wikidata": True,
        "news": True,
        "web": True,
        "exposure": True,
        "corporate": True,
        "developer": True,
        "threat": True,
        "hardware": True,
        "prerelease": True
    },
    "feeds": [
        {"name": "BBC News - Technology", "url": "https://feeds.bbci.co.uk/news/technology/rss.xml"},
        {"name": "The Guardian - Technology", "url": "https://www.theguardian.com/uk/technology/rss"},
        {"name": "NPR - Technology", "url": "https://feeds.npr.org/1019/rss.xml"},
        {"name": "MIT Technology Review", "url": "https://www.technologyreview.com/feed/"},
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
            if key in {"sources", "source_intervals", "provider_settings", "provider_credentials"}:
                config[key].update(value)
            else:
                config[key] = value
    config["nvd_api_key"] = os.environ.get("NVD_API_KEY", config["nvd_api_key"])
    config["github_token"] = os.environ.get("GITHUB_TOKEN", config["github_token"])
    config["api_token"] = os.environ.get("SIGNALWATCH_API_TOKEN", config["api_token"])
    for key, value in os.environ.items():
        if key.startswith("SIGNALWATCH_") and key.endswith("_CREDENTIALS"):
            provider = key[len("SIGNALWATCH_"):-len("_CREDENTIALS")].lower()
            try:
                config["provider_credentials"][provider] = json.loads(value)
            except ValueError:
                config["provider_credentials"][provider] = value
    for provider, name in {"shodan": "SHODAN_API_KEY", "fofa": "FOFA_API_KEY", "netlas": "NETLAS_API_KEY",
                           "zoomeye": "ZOOMEYE_API_KEY", "greynoise": "GREYNOISE_API_KEY", "urlhaus": "URLHAUS_AUTH_KEY",
                           "vulncheck": "VULNCHECK_API_KEY", "attackerkb": "ATTACKERKB_API_KEY", "sam_gov": "SAM_GOV_API_KEY",
                           "opencorporates": "OPENCORPORATES_API_KEY", "censys": "CENSYS_API_KEY"}.items():
        if name in os.environ:
            config["provider_credentials"][provider] = os.environ[name]
    if "SIGNALWATCH_SEC_USER_AGENT" in os.environ:
        config["provider_settings"].setdefault("sec_edgar", {})["user_agent"] = os.environ["SIGNALWATCH_SEC_USER_AGENT"]
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
                 "staging_max_records", "staging_batch", "staging_max_completed",
                 "public_source_batch", "public_source_records", "public_source_concurrency", "threat_source_batch",
                 "cve_max_zip_mb", "csaf_max_records", "network_batch", "network_interval_hours", "news_concurrency"):
        if int(config[name]) < 1:
            raise ValueError(f"{name} must be positive")
    for name in ("dns_timeout", "dns_concurrency", "sbom_max_mb", "events_max_rows", "events_retention_days",
                 "staging_max_payload_mb", "staging_max_mb", "staging_poll_seconds", "staging_retention_days", "wireless_import_max_mb"):
        if not math.isfinite(float(config[name])) or float(config[name]) <= 0:
            raise ValueError(f"{name} must be positive")
    chunk_rows = float(config["wireless_chunk_rows"])
    if isinstance(config["wireless_chunk_rows"], bool) or not math.isfinite(chunk_rows) or not chunk_rows.is_integer() or not 1 <= chunk_rows <= 5000:
        raise ValueError("wireless_chunk_rows must be an integer between 1 and 5000")
    config["wireless_chunk_rows"] = int(chunk_rows)
    if config["dns_mode"] not in {"system", "fallback", "doh"}:
        raise ValueError("dns_mode must be system, fallback, or doh")
    if int(config["staging_batch"]) > 500:
        raise ValueError("staging_batch must be at most 500")
    if int(config["public_source_records"]) > 5000:
        raise ValueError("public_source_records must be at most 5000")
    if not isinstance(config["source_intervals"], dict) or any(not math.isfinite(float(value)) or float(value) <= 0 for value in config["source_intervals"].values()):
        raise ValueError("source_intervals must map source families to positive minutes")
    if not isinstance(config["source_targets"], list) or any(not isinstance(target, dict) for target in config["source_targets"]):
        raise ValueError("source_targets must be an array of target objects")
    for name in ("provider_settings", "provider_credentials"):
        if not isinstance(config[name], dict):
            raise ValueError(f"{name} must be an object")
    if any(not isinstance(value, dict) for value in config["provider_settings"].values()):
        raise ValueError("Provider settings must be objects")
    if any(not isinstance(value, (str, dict)) for value in config["provider_credentials"].values()):
        raise ValueError("Provider credentials must be strings or objects")
    for name in ("watch_products", "exploit_keywords"):
        if not isinstance(config[name], list) or any(not isinstance(value, str) for value in config[name]):
            raise ValueError(f"{name} must be an array of strings")
    config["config_path"] = str(path)
    return config
