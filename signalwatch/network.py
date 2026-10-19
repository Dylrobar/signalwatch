import asyncio
import ipaddress
from urllib.parse import urlencode

from .async_utils import gather, to_thread
from .extract import read_json, utcnow


NETWORK_URL = "https://stat.ripe.net/data/network-info/data.json"


def parse_network(payload, target, source_url, stamp):
    if payload.get("status") != "ok" or not isinstance(payload.get("data"), dict):
        raise ValueError("RIPEstat response is not a successful network result")
    data = payload["data"]
    address = ipaddress.ip_address(target["value"])
    prefix = data.get("prefix")
    raw_asns = data.get("asns", [])
    if not isinstance(raw_asns, list):
        raise ValueError("RIPEstat announcing ASNs must be a list")
    asns = []
    for value in raw_asns:
        if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= 4294967295:
            raise ValueError("RIPEstat returned an invalid ASN")
        asns.append(int(value))
    asns = sorted(set(asns))
    if not prefix and asns:
        raise ValueError("RIPEstat returned announcing ASNs without a prefix")
    network = ipaddress.ip_network(prefix) if prefix else None
    if network and (address.version != network.version or address not in network):
        raise ValueError("RIPEstat prefix does not contain the requested IP")
    metadata = {**target.get("metadata", {}), "network_enriched_at": stamp,
                "network_prefix": str(network) if network else None, "announcing_asns": asns,
                "network_source": "RIPE RIS", "network_data_time": payload.get("data_call_time")}
    entities = [{**target, "metadata": metadata}]
    edges = []
    if network:
        prefix_id = "prefix:" + str(network)
        entities.append({"id": prefix_id, "kind": "prefix", "name": str(network), "value": str(network),
                         "metadata": {"context": "BGP routing", "provider": "RIPE RIS"},
                         "source_url": source_url, "observed_at": stamp, "confidence": 1.0})
        edges.append({"from_id": target["id"], "to_id": prefix_id, "relation": "routed_in",
                      "source_url": source_url, "observed_at": stamp, "confidence": 1.0})
        for asn in asns:
            asn_id = f"asn:AS{asn}"
            entities.append({"id": asn_id, "kind": "asn", "name": f"AS{asn}", "value": str(asn),
                             "metadata": {"context": "BGP announcing network", "provider": "RIPE RIS"},
                             "source_url": source_url, "observed_at": stamp, "confidence": 1.0})
            edges.append({"from_id": prefix_id, "to_id": asn_id, "relation": "announced_by",
                          "source_url": source_url, "observed_at": stamp, "confidence": 1.0})
    return {"entities": entities, "edges": edges}


async def collect_network(config, store, http):
    limit = int(config.get("network_batch", 20))
    refresh = float(config.get("network_interval_hours", 24))
    if limit < 1 or refresh <= 0:
        raise ValueError("Network collection limits must be positive")
    targets = await to_thread(store.network_targets, limit, refresh)
    semaphore = asyncio.Semaphore(min(8, int(config.get("concurrency", 32))))

    async def fetch(target):
        async with semaphore:
            source_url = NETWORK_URL + "?" + urlencode({"resource": target["value"]})
            try:
                result = await http.get(source_url)
                payload = await asyncio.to_thread(read_json, result.path)
                batch = parse_network(payload, target, source_url, utcnow())
                await to_thread(store.ingest, batch)
                return {"routed": bool(payload["data"].get("prefix")), "error": None}
            except Exception as exc:
                return {"routed": False, "error": f"{target['value']}: {exc}"}

    results = await gather(*(fetch(target) for target in targets))
    errors = [row["error"] for row in results if row["error"]]
    pending = await to_thread(store.network_pending_count, refresh)
    counts = {"targets": len(targets), "enriched": len(results) - len(errors),
              "routed": sum(row["routed"] for row in results), "pending": pending,
              "errors": errors, "coverage": "observed_public_ips"}
    await to_thread(store.update_source, "network", coverage_scope="observed_public_ips",
                            checked_at=utcnow(), pending=counts["pending"])
    if results and len(errors) == len(results):
        raise RuntimeError("All RIPEstat targets failed: " + "; ".join(errors)[:2000])
    return counts
