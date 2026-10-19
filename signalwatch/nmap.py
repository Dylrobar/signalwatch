import asyncio
import copy
import hashlib
import ipaddress
import json
import math
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .csaf import cpe_identity
from .extract import utcnow


PROFILES = {
    "quick": ("--top-ports", "1000"),
    "full": ("-p-",),
    "service_version": ("--top-ports", "1000", "-sV", "--version-light"),
}


def scan_options(options):
    profile = options.get("profile", "quick")
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError("Nmap profile must be quick, full, or service_version")
    try:
        timeout = float(options.get("timeout", 900))
    except (TypeError, ValueError):
        raise ValueError("Nmap timeout must be positive seconds") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Nmap timeout must be positive seconds")
    values = options.get("targets", [])
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError("Nmap targets must be an array of IPs, CIDRs, or hostnames")
    targets, seen = [], set()
    for value in values:
        value = value.strip()
        try:
            target = str(ipaddress.ip_network(value, strict=False)) if "/" in value else str(ipaddress.ip_address(value))
        except ValueError:
            target = value.rstrip(".").encode("idna").decode("ascii").lower()
            if len(target) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in target.split(".")):
                raise ValueError("Invalid Nmap target: " + value[:200]) from None
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return profile, timeout, targets


def _root(value):
    try:
        root = ET.fromstring(value) if isinstance(value, bytes) else ET.parse(value).getroot()
    except ET.ParseError as error:
        raise ValueError("Invalid Nmap XML") from error
    if root.tag != "nmaprun":
        raise ValueError("Nmap XML requires an nmaprun root")
    finished = root.find("runstats/finished")
    if finished is not None and finished.get("exit", "success") != "success":
        raise ValueError("Nmap XML reports an unsuccessful scan")
    return root


def parse_nmap_xml(payload, observed_at):
    root = _root(payload)
    entities, edges = {}, {}

    def entity(key, kind, value, metadata, stamp, confidence=1.0):
        entities[key] = {"id": key, "kind": kind, "name": value, "value": value,
                         "metadata": {"provider": "nmap", **metadata}, "observed_at": stamp, "confidence": confidence}

    def edge(left, right, relation, stamp, confidence=1.0):
        edges[left, right, relation] = {"from_id": left, "to_id": right, "relation": relation,
                                       "observed_at": stamp, "confidence": confidence}

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ports = [port for port in host.findall("ports/port") if port.find("state") is not None and port.find("state").get("state") == "open"]
        if not ports:
            continue
        addresses = [str(ipaddress.ip_address(node.get("addr", ""))) for node in host.findall("address") if node.get("addrtype") in {"ipv4", "ipv6"}]
        if not addresses:
            raise ValueError("Nmap open ports require an IP address")
        address = addresses[0]
        stamp = datetime.fromtimestamp(int(host.get("endtime")), timezone.utc).isoformat() if host.get("endtime") else observed_at
        ip_id = "ip:" + address
        entity(ip_id, "ip", address, {"nmap_addresses": addresses, "nmap_hostnames": [node.get("name") for node in host.findall("hostnames/hostname") if node.get("name")]}, stamp)
        for port in ports:
            number = int(port.get("portid", "0"))
            protocol = port.get("protocol")
            if not 1 <= number <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                raise ValueError("Invalid Nmap port or protocol")
            endpoint = f"{protocol}://{'[' + address + ']' if ':' in address else address}:{number}"
            port_id = "open_port:" + endpoint
            service = port.find("service")
            details = dict(service.attrib) if service is not None else {}
            entity(port_id, "open_port", endpoint, {"address": address, "port": number, "protocol": protocol, "state": "open", "reason": port.find("state").get("reason", ""), "service": details}, stamp)
            edge(ip_id, port_id, "has_open_port", stamp)
            if service is None or not (details.get("method") == "probed" or any(details.get(key) for key in ("product", "version", "extrainfo", "servicefp"))):
                continue
            confidence = max(0, min(10, int(details.get("conf", "10")))) / 10
            banner_id = "service_banner:" + hashlib.sha256(json.dumps([endpoint, details], sort_keys=True).encode()).hexdigest()
            banner = " ".join(details[key] for key in ("name", "product", "version", "extrainfo") if details.get(key)) or endpoint
            entity(banner_id, "service_banner", banner, {"endpoint": endpoint, **details}, stamp, confidence)
            edge(port_id, banner_id, "has_service_banner", stamp, confidence)
            for node in service.findall("cpe"):
                cpe = (node.text or "").strip()
                identity = cpe_identity(cpe)
                if not identity:
                    continue
                product_id = "cpe_product:" + hashlib.sha256(cpe.encode()).hexdigest()
                entity(product_id, "cpe_product", cpe, {"cpe": cpe, **identity}, stamp, confidence)
                edge(banner_id, product_id, "identifies_product", stamp, confidence)
    return {"entities": list(entities.values()), "edges": list(edges.values())}


def scan_documents(root, max_records=5000):
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        header = ET.Element("host", host.attrib)
        for node in host:
            if node.tag != "ports":
                header.append(copy.deepcopy(node))
        fragment = ET.Element("nmaprun", root.attrib)
        fragment.append(header)
        ports = ET.SubElement(header, "ports")
        cost = 1
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            size = 2 + (2 + 2 * len(service.findall("cpe")) if service is not None else 0)
            if size + 1 > max_records:
                raise ValueError("One Nmap port exceeds the staging record limit")
            if cost + size > max_records:
                yield ET.tostring(fragment, encoding="utf-8")
                ports.clear()
                cost = 1
            ports.append(port)
            cost += size
        if len(ports):
            yield ET.tostring(fragment, encoding="utf-8")


async def collect_nmap(config, store, http):
    from .ingestion import staging_queue

    options = config.get("provider_settings", {}).get("nmap", {})
    profile, timeout, targets = scan_options(options)
    counts = {"profile": profile, "targets": len(targets), "scans": 0, "staged": 0, "errors": [], "provider_health": {"nmap": {"status": "unconfigured", "requirements": ["Scan targets"], "records": 0}}}
    health = counts["provider_health"]["nmap"]
    if options.get("enabled", True) is False:
        health.update(status="disabled", requirements=[])
        return counts
    if not targets:
        return counts
    executable = shutil.which("nmap")
    if not executable:
        raise RuntimeError("Nmap executable is unavailable")
    queue = staging_queue(store, config)
    groups = {4: [], 6: []}
    for target in targets:
        groups[6 if ":" in target else 4].append(target)
    for version, group in groups.items():
        if not group:
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="signalwatch-nmap-") as folder:
                target_file, output_file = Path(folder) / "targets", Path(folder) / "scan.xml"
                target_file.write_text("\n".join(group) + "\n")
                command = [executable, "-sT", "-n", "--unprivileged", "-T4", "--open", "--max-retries", "1", *PROFILES[profile], *(["-6"] if version == 6 else []), "-oX", str(output_file), "-iL", str(target_file)]
                process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
                try:
                    _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    if process.returncode is None:
                        process.kill()
                    await process.communicate()
                    raise
                if process.returncode:
                    raise RuntimeError("Nmap exited with code " + str(process.returncode) + ": " + stderr.decode(errors="replace")[:500])
                root = await asyncio.to_thread(_root, output_file)
                hosts = root.find("runstats/hosts")
                if hosts is not None and int(hosts.get("total", "0")) == 0:
                    raise RuntimeError("Nmap resolved no targets: " + stderr.decode(errors="replace")[:500])
                for index, payload in enumerate(scan_documents(root)):
                    await asyncio.to_thread(queue.enqueue, payload, source="nmap", adapter="nmap_xml", content_type="application/xml", stream_key=f"{profile}:ipv{version}:{index}", metadata={"profile": profile, "address_family": version}, observed_at=utcnow())
                    counts["staged"] += 1
                counts["scans"] += 1
        except Exception as error:
            counts["errors"].append(f"IPv{version}: {str(error) or type(error).__name__}")
    health.update(status="partial" if counts["scans"] and counts["errors"] else "error" if counts["errors"] else "healthy", requirements=[], records=counts["staged"])
    return counts
