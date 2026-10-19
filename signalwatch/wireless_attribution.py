import asyncio
import csv
import hashlib
import io
import json
import math
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit


ATTRIBUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS wireless_manufacturer_prefixes (
 registry TEXT NOT NULL,prefix TEXT NOT NULL,bits INTEGER NOT NULL,company_id TEXT NOT NULL,
 name TEXT NOT NULL,source_url TEXT NOT NULL,version TEXT NOT NULL DEFAULT '',imported_at TEXT NOT NULL,
 PRIMARY KEY(registry,prefix,company_id)
);
CREATE INDEX IF NOT EXISTS wireless_manufacturer_assignment ON wireless_manufacturer_prefixes(bits,prefix);
CREATE TABLE IF NOT EXISTS wireless_facilities (
 id TEXT PRIMARY KEY,name TEXT NOT NULL,latitude REAL NOT NULL,longitude REAL NOT NULL,
 company_id TEXT NOT NULL DEFAULT '',website TEXT NOT NULL DEFAULT '',evidence TEXT NOT NULL DEFAULT '{}',
 source_url TEXT NOT NULL,location_basis TEXT NOT NULL DEFAULT 'public_business_point',
 observed_at TEXT NOT NULL,updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS wireless_facility_company ON wireless_facilities(company_id,id);
CREATE VIRTUAL TABLE IF NOT EXISTS wireless_facility_geo USING rtree(facility_rowid,min_lat,max_lat,min_lon,max_lon);
CREATE TRIGGER IF NOT EXISTS wireless_facility_ai AFTER INSERT ON wireless_facilities BEGIN
 INSERT INTO wireless_facility_geo VALUES(new.rowid,new.latitude,new.latitude,new.longitude,new.longitude);
END;
CREATE TRIGGER IF NOT EXISTS wireless_facility_ad AFTER DELETE ON wireless_facilities BEGIN
 DELETE FROM wireless_facility_geo WHERE facility_rowid=old.rowid;
END;
CREATE TRIGGER IF NOT EXISTS wireless_facility_au AFTER UPDATE OF latitude,longitude ON wireless_facilities BEGIN
 UPDATE wireless_facility_geo SET min_lat=new.latitude,max_lat=new.latitude,min_lon=new.longitude,max_lon=new.longitude
 WHERE facility_rowid=new.rowid;
END;
CREATE TABLE IF NOT EXISTS wireless_company_links (
 device_id TEXT NOT NULL,company_id TEXT NOT NULL,role TEXT NOT NULL,status TEXT NOT NULL,
 facility_id TEXT NOT NULL DEFAULT '',origin TEXT NOT NULL,evidence TEXT NOT NULL DEFAULT '{}',
 source_url TEXT NOT NULL,observed_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(device_id,company_id,role,facility_id,origin)
);
CREATE INDEX IF NOT EXISTS wireless_link_company ON wireless_company_links(company_id,role,status,device_id);
CREATE INDEX IF NOT EXISTS wireless_link_device ON wireless_company_links(device_id,role,status);
CREATE INDEX IF NOT EXISTS wireless_facility_proximity ON wireless_company_links(facility_id) WHERE origin='facility_proximity';
CREATE INDEX IF NOT EXISTS wireless_manual_rejection ON wireless_company_links(device_id,company_id)
 WHERE origin='manual' AND status='rejected';
"""

REGISTRY_URLS = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.csv",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "MA-S": "https://standards-oui.ieee.org/oui36/oui36.csv",
    "IAB": "https://standards-oui.ieee.org/iab/iab.csv",
    "Bluetooth SIG": "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml",
}
EARTH_RADIUS = 6371008.8


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _coordinates(latitude, longitude):
    latitude, longitude = float(latitude), float(longitude)
    if not math.isfinite(latitude) or not math.isfinite(longitude) or not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError("Coordinates must be finite WGS84 latitude and longitude")
    return latitude, longitude


def _company_id(name):
    return "company:wireless:" + hashlib.sha256(name.strip().casefold().encode()).hexdigest()[:24]


def _ensure_company(store, conn, name, source_url, metadata, company_id=""):
    company_id = company_id or _company_id(name)
    existing = conn.execute("SELECT kind FROM entities WHERE id=?", (company_id,)).fetchone()
    if existing and existing["kind"] != "company":
        raise ValueError("Company ID refers to another entity kind")
    if not existing:
        store._entity(conn, {"id": company_id, "kind": "company", "name": name, "value": name,
                             "source_url": source_url, "metadata": metadata}, _now())
    return company_id


def _bluetooth_rows(text):
    try:
        data = json.loads(text)
    except ValueError:
        pending = None
        for line in text.splitlines():
            value = re.match(r"\s*-\s*value:\s*(0x[0-9a-fA-F]+|[0-9]+)\s*$", line)
            if value:
                pending = int(value.group(1), 0) if value.group(1).startswith("0x") else int(value.group(1))
            name = re.match(r"\s*name:\s*(.*?)\s*$", line)
            if name and pending is not None:
                label = name.group(1)
                if label.startswith('"'):
                    label = json.loads(label)
                elif label.startswith("'") and label.endswith("'"):
                    label = label[1:-1].replace("''", "'")
                yield pending, label
                pending = None
        return
    if isinstance(data, dict) and "company_identifiers" in data:
        data = data["company_identifiers"]
    if isinstance(data, dict):
        for value, name in data.items():
            yield int(value, 16) if str(value).lower().startswith("0x") else int(value), name
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict) or "value" not in item or "name" not in item:
                raise ValueError("Bluetooth assignment requires value and name")
            value = item["value"]
            if not isinstance(value, (str, int)) or isinstance(value, bool):
                raise ValueError("Invalid Bluetooth company identifier")
            yield int(value, 16) if isinstance(value, str) and value.lower().startswith("0x") else int(value), item["name"]


def import_manufacturer_registry(store, payload, registry, source_url, version=""):
    if registry not in REGISTRY_URLS:
        raise ValueError("Registry must be MA-L, MA-M, MA-S, IAB, or Bluetooth SIG")
    if not source_url:
        raise ValueError("Registry source URL is required")
    text = payload.decode("utf-8-sig") if isinstance(payload, bytes) else str(payload)
    bits = {"MA-L": 24, "MA-M": 28, "MA-S": 36, "IAB": 36, "Bluetooth SIG": 16}[registry]
    assignments = {}
    if registry == "Bluetooth SIG":
        for value, name in _bluetooth_rows(text):
            if not 0 <= value <= 65535 or not isinstance(name, str) or not name.strip():
                raise ValueError("Invalid Bluetooth company assignment")
            if value == 65535:
                continue
            assignments[(f"{value:04X}", name.strip())] = name.strip()
    else:
        reader = csv.DictReader(io.StringIO(text))
        if not {"Assignment", "Organization Name"}.issubset(reader.fieldnames or []):
            raise ValueError("IEEE registry requires Assignment and Organization Name columns")
        for row in reader:
            if not isinstance(row.get("Assignment"), str) or not isinstance(row.get("Organization Name"), str):
                raise ValueError("IEEE assignment requires prefix and organization name")
            prefix = row["Assignment"].strip().upper().replace("-", "").replace(":", "")
            name = row["Organization Name"].strip()
            if not re.fullmatch(r"[0-9A-F]{" + str(bits // 4) + "}", prefix) or not name:
                raise ValueError("Invalid IEEE assignment")
            assignments[(prefix, name)] = name
    if not assignments:
        raise ValueError("Registry contains no assignments")
    timestamp = _now()
    version = str(version) or "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    with store.connection(write=True) as conn:
        records = []
        company_ids = {}
        for (prefix, name) in assignments:
            company_id = company_ids.get(name)
            if company_id is None:
                company_id = _ensure_company(store, conn, name, source_url,
                                             {"origin": "wireless_assignment_registry", "registry": registry})
                company_ids[name] = company_id
            records.append((registry, prefix, bits, company_id, name, source_url, version, timestamp))
        conn.execute("DELETE FROM wireless_manufacturer_prefixes WHERE registry=?", (registry,))
        conn.executemany("INSERT OR IGNORE INTO wireless_manufacturer_prefixes VALUES(?,?,?,?,?,?,?,?)", records)
    return {"registry": registry, "assignments": len(assignments), "companies": len(company_ids),
            "source_url": source_url, "version": version}


async def refresh_manufacturer_registries(http, store, registries=None):
    results = []
    for registry in registries or REGISTRY_URLS:
        if registry not in REGISTRY_URLS:
            raise ValueError("Unknown manufacturer registry")
        response = await http.get(REGISTRY_URLS[registry], max_bytes=16 * 1024 * 1024)
        results.append(await asyncio.to_thread(import_manufacturer_registry, store, response.path.read_bytes(), registry,
                                               REGISTRY_URLS[registry], response.digest))
    return {"registries": results, "enrichment": await asyncio.to_thread(enrich_manufacturers, store)}


def enrich_manufacturers(store):
    timestamp = _now()
    with store.connection(write=True) as conn:
        conn.execute("DELETE FROM wireless_company_links WHERE origin IN ('ieee_registry','bluetooth_registry')")
        for bits in (36, 28, 24):
            more_specific = "".join(" AND NOT EXISTS (SELECT 1 FROM wireless_manufacturer_prefixes longer INDEXED BY wireless_manufacturer_assignment WHERE longer.bits="
                                    +str(width)+" AND longer.prefix=substr(upper(replace(replace(d.identifier,':',''),'-','')),1,"
                                    +str(width//4)+"))" for width in (28, 36) if width > bits)
            conn.execute("""INSERT OR IGNORE INTO wireless_company_links
             SELECT d.id,r.company_id,'manufacturer','assigned','','ieee_registry',
              json_object('registry',r.registry,'prefix',r.prefix,'prefix_bits',r.bits,'registry_version',r.version,
               'basis','IEEE address block assignee; model and operator unknown'),r.source_url,?,?
             FROM wireless_devices d NOT INDEXED CROSS JOIN wireless_manufacturer_prefixes r INDEXED BY wireless_manufacturer_assignment
             WHERE r.bits=? AND r.prefix=substr(upper(replace(replace(d.identifier,':',''),'-','')),1,?)
              AND length(replace(replace(d.identifier,':',''),'-',''))=12
              AND upper(replace(replace(d.identifier,':',''),'-','')) NOT GLOB '*[^0-9A-F]*'
              AND d.radio_type='WIFI'
              AND substr(upper(replace(replace(d.identifier,':',''),'-','')),2,1) IN ('0','4','8','C')"""
                         + more_specific, (timestamp, timestamp, bits, bits//4))
        conn.execute("""INSERT OR IGNORE INTO wireless_company_links
         SELECT o.device_id,r.company_id,'advertised_provider','claimed','','bluetooth_registry',
          json_object('registry',r.registry,'company_identifier',r.prefix,'registry_version',r.version,
           'basis','Observed Bluetooth manufacturer-specific data company ID; hardware and operator unverified'),
          r.source_url,max(coalesce(o.observed_at,'')),?
         FROM wireless_observations o NOT INDEXED CROSS JOIN wireless_manufacturer_prefixes r INDEXED BY wireless_manufacturer_assignment
         WHERE r.bits=16 AND r.registry='Bluetooth SIG' AND r.prefix=printf('%04X',CAST(o.manufacturer_id AS INTEGER))
          AND o.manufacturer_id!='' AND lower(substr(trim(o.manufacturer_id),1,2))!='0x'
          AND o.radio_type IN ('BLE','BT')
          AND trim(o.manufacturer_id) NOT GLOB '*[^0-9]*'
         GROUP BY o.device_id,r.company_id""", (timestamp,))
        conn.execute("""INSERT OR IGNORE INTO wireless_company_links
         SELECT o.device_id,r.company_id,'advertised_provider','claimed','','bluetooth_registry',
          json_object('registry',r.registry,'company_identifier',r.prefix,'registry_version',r.version,
           'basis','Observed Bluetooth manufacturer-specific data company ID; hardware and operator unverified'),
          r.source_url,max(coalesce(o.observed_at,'')),?
         FROM wireless_observations o NOT INDEXED CROSS JOIN wireless_manufacturer_prefixes r INDEXED BY wireless_manufacturer_assignment
         WHERE r.bits=16 AND r.registry='Bluetooth SIG' AND r.prefix=substr('0000'||upper(substr(trim(o.manufacturer_id),3)),-4)
          AND lower(substr(trim(o.manufacturer_id),1,2))='0x'
          AND o.radio_type IN ('BLE','BT')
          AND length(trim(o.manufacturer_id)) BETWEEN 3 AND 6
          AND upper(substr(trim(o.manufacturer_id),3)) NOT GLOB '*[^0-9A-F]*'
         GROUP BY o.device_id,r.company_id""", (timestamp,))
        counts = {row["role"]: row["count"] for row in conn.execute("""SELECT role,count(*) AS count FROM wireless_company_links
         WHERE origin IN ('ieee_registry','bluetooth_registry') GROUP BY role""")}
    return {"manufacturer_links": counts.get("manufacturer", 0), "advertised_provider_links": counts.get("advertised_provider", 0)}


def upsert_facility(store, name, latitude, longitude, company_id="", website="", evidence=None,
                    source_url="", facility_id="", location_basis="public_business_point", observed_at=None):
    latitude, longitude = _coordinates(latitude, longitude)
    name, source_url = str(name).strip(), str(source_url).strip()
    if not name or not source_url:
        raise ValueError("Facility name and source URL are required")
    if not isinstance(evidence if evidence is not None else {}, dict):
        raise ValueError("Facility evidence must be a JSON object")
    encoded = _json(evidence or {})
    if len(encoded.encode()) > 32768:
        raise ValueError("Facility evidence exceeds 32 KiB")
    timestamp = _now()
    facility_id = facility_id or "facility:manual:" + uuid.uuid4().hex
    with store.connection(write=True) as conn:
        if company_id and conn.execute("SELECT id FROM entities WHERE id=? AND kind='company'", (company_id,)).fetchone() is None:
            raise LookupError("Company does not exist")
        conn.execute("""INSERT INTO wireless_facilities
         (id,name,latitude,longitude,company_id,website,evidence,source_url,location_basis,observed_at,updated_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,latitude=excluded.latitude,
          longitude=excluded.longitude,company_id=excluded.company_id,website=excluded.website,evidence=excluded.evidence,
          source_url=excluded.source_url,location_basis=excluded.location_basis,observed_at=excluded.observed_at,updated_at=excluded.updated_at""",
                     (facility_id, name, latitude, longitude, company_id, website, encoded, source_url,
                      location_basis, str(observed_at or timestamp), timestamp))
        conn.execute("DELETE FROM wireless_company_links WHERE facility_id=? AND origin='facility_proximity'", (facility_id,))
    return {"id": facility_id, "name": name, "latitude": latitude, "longitude": longitude,
            "company_id": company_id, "source_url": source_url, "location_basis": location_basis}


def delete_facility(store, facility_id):
    with store.connection(write=True) as conn:
        result = conn.execute("DELETE FROM wireless_facilities WHERE id=?", (facility_id,))
        conn.execute("DELETE FROM wireless_company_links WHERE facility_id=? AND origin='facility_proximity'", (facility_id,))
        return {"removed": result.rowcount}


def list_facilities(store, company_id="", limit=100, offset=0):
    if not 1 <= int(limit) <= 1000 or int(offset) < 0:
        raise ValueError("Invalid facility pagination")
    with store.connection() as conn:
        where, params = (" WHERE f.company_id=?", [company_id]) if company_id else ("", [])
        total = conn.execute("SELECT count(*) FROM wireless_facilities f" + where, params).fetchone()[0]
        rows = conn.execute("""SELECT f.*,coalesce(p.name,e.name) AS company_name FROM wireless_facilities f
         LEFT JOIN entities e ON e.id=f.company_id LEFT JOIN company_profiles p ON p.company_id=f.company_id"""
                            + where + " ORDER BY f.name,f.id LIMIT ? OFFSET ?", (*params, int(limit), int(offset)))
        items = [{**dict(row), "evidence": json.loads(row["evidence"])} for row in rows]
    return {"items": items, "total": total, "limit": int(limit), "offset": int(offset)}


def _distance(lat1, lon1, lat2, lon2):
    lat1, lat2 = math.radians(lat1), math.radians(lat2)
    delta_lat, delta_lon = lat2 - lat1, math.radians(lon2 - lon1)
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    return 2 * EARTH_RADIUS * math.asin(min(1, math.sqrt(a)))


def match_facilities(store, radius_meters=100, max_accuracy_meters=250, facility_limit=5, after_facility_id=""):
    radius_meters, max_accuracy_meters = float(radius_meters), float(max_accuracy_meters)
    if not math.isfinite(radius_meters) or not 1 <= radius_meters <= 1000:
        raise ValueError("Radius must be between 1 and 1000 meters")
    if not math.isfinite(max_accuracy_meters) or not 0 <= max_accuracy_meters <= 1000:
        raise ValueError("Maximum accuracy must be between 0 and 1000 meters")
    if not 1 <= int(facility_limit) <= 10000:
        raise ValueError("Facility batch must be between 1 and 10000")
    timestamp, matched, processed = _now(), 0, 0
    with store.connection(write=True) as conn:
        try:
            conn.execute("SELECT radians(1),sin(1),cos(1),asin(1),sqrt(1)")
            distance_expression = """12742017.6*asin(min(1.0,sqrt(
             sin(radians(o.latitude-?)/2)*sin(radians(o.latitude-?)/2)
             +cos(radians(?))*cos(radians(o.latitude))
             *sin(radians(o.longitude-?)/2)*sin(radians(o.longitude-?)/2))))"""
            native_math = True
        except sqlite3.OperationalError:
            conn.create_function("wireless_distance", 4, _distance, deterministic=True)
            distance_expression, native_math = "wireless_distance(?,?,o.latitude,o.longitude)", False
        facilities = conn.execute("""SELECT * FROM wireless_facilities WHERE id>? AND company_id!=''
         ORDER BY id LIMIT ?""", (after_facility_id, int(facility_limit) + 1)).fetchall()
        more = len(facilities) > int(facility_limit)
        for facility in facilities[:int(facility_limit)]:
            processed += 1
            lat, lon = facility["latitude"], facility["longitude"]
            margin = radius_meters + max_accuracy_meters
            dy = math.degrees(margin / EARTH_RADIUS)
            dx = min(180, dy / max(0.000001, abs(math.cos(math.radians(lat)))))
            conn.execute("DELETE FROM wireless_company_links WHERE facility_id=? AND origin='facility_proximity'", (facility["id"],))
            intervals = [(max(-180, lon-dx), min(180, lon+dx))]
            if lon - dx < -180:
                intervals.append((lon-dx+360, 180))
            if lon + dx > 180:
                intervals.append((-180, lon+dx-360))
            candidates = {}
            for west, east in intervals:
                distance_params = (lat, lat, lat, lon, lon) if native_math else (lat, lon)
                rows = conn.execute("""WITH located AS (
                 SELECT o.id,o.device_id,o.latitude,o.longitude,o.accuracy_meters,o.observed_at,o.dataset_id,"""
                                    + distance_expression + """ AS exact_distance
                 FROM wireless_observation_geo g JOIN wireless_observations o ON o.id=g.observation_id
                 WHERE g.min_lat<=? AND g.max_lat>=? AND g.min_lon<=? AND g.max_lon>=?
                  AND (o.accuracy_meters IS NULL OR o.accuracy_meters>=0 AND o.accuracy_meters<=?)),
                 nearest AS (SELECT *,row_number() OVER(PARTITION BY device_id ORDER BY exact_distance,id DESC) AS proximity_rank
                  FROM located WHERE exact_distance<=?+coalesce(accuracy_meters,0))
                 SELECT nearest.*,s.source_url FROM nearest JOIN wireless_datasets s ON s.id=nearest.dataset_id
                 WHERE proximity_rank=1""", (*distance_params, min(90, lat+dy), max(-90, lat-dy), east, west,
                                             max_accuracy_meters, radius_meters))
                for row in rows:
                    distance = row["exact_distance"]
                    accuracy = row["accuracy_meters"]
                    effective_radius = radius_meters + (accuracy or 0)
                    if distance > effective_radius:
                        continue
                    prior = candidates.get(row["device_id"])
                    candidate = {"observation_id": row["id"], "dataset_id": row["dataset_id"],
                                 "distance_meters": round(distance, 2), "scan_accuracy_meters": accuracy,
                                 "scan_latitude": row["latitude"], "scan_longitude": row["longitude"],
                                 "observed_at": row["observed_at"], "observation_source_url": row["source_url"],
                                 "radius_meters": radius_meters, "effective_radius_meters": effective_radius,
                                 "facility_location_basis": facility["location_basis"],
                                 "facility_observed_at": facility["observed_at"],
                                 "basis": "Scan location near public business position; device location and operator unverified"}
                    if prior is None or distance < prior["distance_meters"]:
                        candidates[row["device_id"]] = candidate
            conn.executemany("INSERT INTO wireless_company_links VALUES(?,?,?,?,?,?,?,?,?,?)",
                             ((device_id, facility["company_id"], "candidate_business", "candidate", facility["id"],
                               "facility_proximity", _json(evidence), facility["source_url"],
                               evidence["observed_at"] or timestamp, timestamp) for device_id, evidence in candidates.items()))
            matched += len(candidates)
        cursor = facilities[min(int(facility_limit), len(facilities))-1]["id"] if facilities else after_facility_id
    return {"facilities_processed": processed, "candidate_links": matched, "next_cursor": cursor if more else "", "has_more": more}


def import_device_enrichment(store, records, source_url, version=""):
    if not isinstance(records, list) or len(records) > 10000 or not source_url:
        raise ValueError("Enrichment requires up to 10000 records and a source URL")
    timestamp, prepared = _now(), []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("labels"), dict) or not isinstance(record.get("evidence", {}), dict):
            raise ValueError("Enrichment records require labels and optional evidence objects")
        identifier = str(record.get("identifier", "")).strip().upper()
        radio_type = str(record.get("radio_type", "")).strip().upper()
        if not identifier or not radio_type:
            raise ValueError("Enrichment records require radio_type and identifier")
        if radio_type in {"WIFI", "BT", "BLE"}:
            compact = identifier.replace(":", "").replace("-", "")
            if not re.fullmatch(r"[0-9A-F]{12}", compact):
                raise ValueError("Invalid enrichment MAC address")
            identifier = ":".join(compact[i:i+2] for i in range(0, 12, 2))
        provider = record.get("provider") or record["labels"].get("provider") or ""
        if not isinstance(provider, str):
            raise ValueError("Advertised provider must be text")
        metadata = {"labels": record["labels"], "evidence": record.get("evidence", {}),
                    "source_url": source_url, "version": version, "imported_at": timestamp,
                    "status": "imported_claims", "basis": "Prior SignalAtlas labels; device model and operator unverified"}
        encoded = _json(metadata)
        if len(encoded.encode()) > 32768:
            raise ValueError("Enrichment record exceeds 32 KiB")
        prepared.append((radio_type, identifier, encoded, provider.strip()))
    with store.connection(write=True) as conn:
        conn.execute("CREATE TEMP TABLE imported_wireless_labels(radio_type TEXT,identifier TEXT,metadata TEXT,provider TEXT,PRIMARY KEY(radio_type,identifier))")
        conn.executemany("INSERT INTO imported_wireless_labels VALUES(?,?,?,?) ON CONFLICT(radio_type,identifier) DO UPDATE SET metadata=excluded.metadata,provider=excluded.provider", prepared)
        conn.execute("CREATE TEMP TABLE matched_wireless_labels(device_id TEXT PRIMARY KEY,metadata TEXT,provider TEXT)")
        conn.execute("""INSERT INTO matched_wireless_labels SELECT d.id,l.metadata,l.provider
         FROM imported_wireless_labels l CROSS JOIN wireless_devices d INDEXED BY wireless_identifier
         WHERE d.identifier!='' AND d.radio_type=l.radio_type AND d.identifier=l.identifier""")
        count = conn.execute("SELECT count(*) FROM matched_wireless_labels").fetchone()[0]
        conn.execute("""UPDATE wireless_devices AS d SET metadata=json_set(d.metadata,'$.imported_enrichment',json(l.metadata)),updated_at=?
         FROM matched_wireless_labels l WHERE d.id=l.device_id""", (timestamp,))
        conn.execute("""DELETE FROM wireless_company_links WHERE origin='imported_label' AND device_id IN (
         SELECT device_id FROM matched_wireless_labels)""")
        for row in conn.execute("SELECT DISTINCT provider FROM matched_wireless_labels WHERE provider!=''").fetchall():
            provider = row[0]
            company_id = _ensure_company(store, conn, provider, source_url,
                                         {"origin": "wireless_advertised_provider", "identity_basis": "Advertised name; corporate identity unverified"})
            conn.execute("""INSERT INTO wireless_company_links
             SELECT l.device_id,?,'advertised_provider','claimed','','imported_label',
              json_object('basis','Prior advertised provider label; operator unverified','imported_evidence',json(l.metadata)),?,?,?
             FROM matched_wireless_labels l
             WHERE l.provider=? ON CONFLICT(device_id,company_id,role,facility_id,origin) DO UPDATE SET
              evidence=excluded.evidence,source_url=excluded.source_url,observed_at=excluded.observed_at,updated_at=excluded.updated_at""",
                         (company_id, source_url, timestamp, timestamp, provider))
    return {"submitted": len(records), "matched_devices": count, "unmatched_devices": len({(r[0], r[1]) for r in prepared})-count}


def set_device_company(store, device_id, company_id, status, evidence, source_url):
    if status not in {"confirmed", "rejected"}:
        raise ValueError("Device operator decision must be confirmed or rejected")
    if not str(evidence).strip() or not str(source_url).strip():
        raise ValueError("Operator decisions require evidence and a source URL")
    timestamp = _now()
    with store.connection(write=True) as conn:
        if conn.execute("SELECT id FROM wireless_devices WHERE id=?", (device_id,)).fetchone() is None:
            raise LookupError("Wireless device does not exist")
        if conn.execute("SELECT id FROM entities WHERE id=? AND kind='company'", (company_id,)).fetchone() is None:
            raise LookupError("Company does not exist")
        conn.execute("""INSERT INTO wireless_company_links VALUES(?,?,'confirmed_operator',?,'','manual',?,?,?,?)
         ON CONFLICT(device_id,company_id,role,facility_id,origin) DO UPDATE SET status=excluded.status,
          evidence=excluded.evidence,source_url=excluded.source_url,observed_at=excluded.observed_at,updated_at=excluded.updated_at""",
                     (device_id, company_id, status, _json({"basis": str(evidence)}), source_url, timestamp, timestamp))
    return {"device_id": device_id, "company_id": company_id, "role": "confirmed_operator", "status": status}


def device_company_links(conn, device_id, limit=100):
    if not 1 <= int(limit) <= 1000:
        raise ValueError("Invalid attribution limit")
    rows = conn.execute("""SELECT l.*,coalesce(p.name,e.name) AS company_name,f.name AS facility_name,
     json_extract(l.evidence,'$.distance_meters') AS distance_m,
     EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=l.device_id AND deny.company_id=l.company_id
      AND deny.origin='manual' AND deny.status='rejected') AS rejected_by_user
     FROM wireless_company_links l JOIN entities e ON e.id=l.company_id
     LEFT JOIN company_profiles p ON p.company_id=l.company_id
     LEFT JOIN wireless_facilities f ON f.id=l.facility_id WHERE l.device_id=?
     ORDER BY CASE l.role WHEN 'confirmed_operator' THEN 0 WHEN 'manufacturer' THEN 1 WHEN 'advertised_provider' THEN 2 ELSE 3 END,
      CASE WHEN l.role='candidate_business' THEN json_extract(l.evidence,'$.distance_meters') END,
      l.company_id,l.facility_id LIMIT ?""", (device_id, int(limit)))
    items = [{**dict(row), "evidence": json.loads(row["evidence"]), "rejected_by_user": bool(row["rejected_by_user"])} for row in rows]
    providers = {row[0] for row in conn.execute("SELECT company_id FROM wireless_company_links WHERE device_id=? AND origin='bluetooth_registry'", (device_id,))}
    manufacturers = {row[0] for row in conn.execute("SELECT company_id FROM wireless_company_links WHERE device_id=? AND origin='ieee_registry'", (device_id,))}
    total = conn.execute("SELECT count(*) FROM wireless_company_links WHERE device_id=?", (device_id,)).fetchone()[0]
    operator_confirmed = conn.execute("""SELECT EXISTS(SELECT 1 FROM wireless_company_links
     WHERE device_id=? AND role='confirmed_operator' AND status='confirmed')""", (device_id,)).fetchone()[0]
    return {"items": items, "advertised_provider_conflict": len(providers) > 1,
            "manufacturer_assignment_conflict": len(manufacturers) > 1,
            "operator_confirmed": bool(operator_confirmed), "total": total, "truncated": total > len(items)}


def company_wireless_summary(conn, company_id, limit=100):
    if not 1 <= int(limit) <= 1000:
        raise ValueError("Invalid wireless summary limit")
    counts = {row["role"]: row["count"] for row in conn.execute("""SELECT role,count(DISTINCT device_id) AS count
     FROM wireless_company_links l WHERE company_id=? AND status!='rejected'
      AND NOT EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=l.device_id AND deny.company_id=l.company_id
       AND deny.origin='manual' AND deny.status='rejected') GROUP BY role""", (company_id,))}
    rows = conn.execute("""SELECT d.*,l.role,l.status,l.facility_id,l.source_url AS attribution_source_url,l.evidence AS attribution_evidence
     FROM wireless_company_links l JOIN wireless_devices d ON d.id=l.device_id
     WHERE l.company_id=? AND l.status!='rejected'
      AND NOT EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=l.device_id AND deny.company_id=l.company_id
       AND deny.origin='manual' AND deny.status='rejected')
     ORDER BY CASE l.role WHEN 'confirmed_operator' THEN 0 WHEN 'candidate_business' THEN 1 ELSE 2 END,d.id,l.facility_id LIMIT ?""",
                        (company_id, int(limit)))
    items = [{**dict(row), "metadata": json.loads(row["metadata"]), "attribution_evidence": json.loads(row["attribution_evidence"])} for row in rows]
    distinct_device_count = conn.execute("""SELECT count(DISTINCT l.device_id) FROM wireless_company_links l
     WHERE l.company_id=? AND l.status!='rejected'
      AND NOT EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=l.device_id AND deny.company_id=l.company_id
       AND deny.origin='manual' AND deny.status='rejected')""", (company_id,)).fetchone()[0]
    return {"counts_by_role": counts, "distinct_device_count": distinct_device_count, "devices": items, "limit": int(limit),
            "facility_count": conn.execute("SELECT count(*) FROM wireless_facilities WHERE company_id=?", (company_id,)).fetchone()[0]}


def dense_scan_cells(store, limit=12, cell_degrees=0.02, min_devices=10):
    cell_degrees = float(cell_degrees)
    if not math.isfinite(cell_degrees) or not 0.005 <= cell_degrees <= 0.1 or not 1 <= int(limit) <= 100 or int(min_devices) < 1:
        raise ValueError("Invalid dense-cell bounds")
    with store.connection() as conn:
        rows = conn.execute("""SELECT CAST((latitude+90)/? AS INTEGER) AS y,CAST((longitude+180)/? AS INTEGER) AS x,
         count(DISTINCT device_id) AS devices,count(*) AS observations FROM wireless_observations
         WHERE latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180
         GROUP BY y,x HAVING count(DISTINCT device_id)>=? ORDER BY devices DESC,y,x LIMIT ?""",
                            (cell_degrees, cell_degrees, int(min_devices), int(limit)))
        return [{"bbox": [round(row["y"]*cell_degrees-90, 8), round(row["x"]*cell_degrees-180, 8),
                          round(min(90, (row["y"]+1)*cell_degrees-90), 8), round(min(180, (row["x"]+1)*cell_degrees-180), 8)],
                 "devices": row["devices"], "observations": row["observations"]} for row in rows]


def _website_host(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
            return ""
        return parsed.hostname.encode("idna").decode("ascii").lower().removeprefix("www.")
    except (ValueError, UnicodeError):
        return ""


def import_osm_facilities(store, payload, limit=5000):
    data = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
    if not isinstance(data, dict) or not isinstance(data.get("elements"), list):
        raise ValueError("Expected Overpass JSON elements")
    if not 1 <= int(limit) <= 10000 or len(data["elements"]) > int(limit):
        raise ValueError("Business feature response exceeds limit")
    imported, skipped = 0, 0
    timestamp = data.get("osm3s", {}).get("timestamp_osm_base") or _now()
    for item in data["elements"]:
        if not isinstance(item, dict) or not isinstance(item.get("tags") or {}, dict):
            skipped += 1
            continue
        tags = item.get("tags") or {}
        name = tags.get("name") or tags.get("brand") or tags.get("operator")
        point = item if "lat" in item else item.get("center") or {}
        if not isinstance(name, str) or not name.strip() or not isinstance(point, dict) or not any(tags.get(key) for key in ("shop", "office", "craft", "industrial", "amenity")):
            skipped += 1
            continue
        try:
            latitude, longitude = _coordinates(point.get("lat"), point.get("lon"))
        except (TypeError, ValueError):
            skipped += 1
            continue
        if item.get("type") not in {"node", "way", "relation"} or not isinstance(item.get("id"), int):
            skipped += 1
            continue
        source_url = "https://www.openstreetmap.org/" + item["type"] + "/" + str(item["id"])
        company_name = tags.get("operator") or tags.get("brand") or name
        wikidata = tags.get("operator:wikidata") or tags.get("brand:wikidata") or ""
        if not isinstance(company_name, str) or not isinstance(wikidata, str):
            skipped += 1
            continue
        company_id = "company:wikidata:" + wikidata if re.fullmatch(r"Q[1-9][0-9]*", wikidata) else ""
        website = tags.get("website") or tags.get("contact:website") or ""
        if not isinstance(website, str):
            website = ""
        with store.connection(write=True) as conn:
            if not company_id and _website_host(website):
                host = _website_host(website)
                companies = conn.execute("""SELECT DISTINCT e.id FROM edges x JOIN entities e ON e.id=x.from_id
                 WHERE x.relation='official_website' AND x.to_id IN (?,?) AND e.kind='company' LIMIT 2""",
                                         ("domain:"+host, "domain:www."+host)).fetchall()
                if len(companies) == 1:
                    company_id = companies[0][0]
            if not company_id and website and _website_host(website):
                company_id = "company:business:" + hashlib.sha256((company_name.casefold()+"|"+_website_host(website)).encode()).hexdigest()[:24]
            if not company_id:
                company_id = "company:osm:" + item["type"] + ":" + str(item["id"])
            company_id = _ensure_company(store, conn, company_name, source_url,
                                         {"origin": "openstreetmap_business", "identity_basis": "public business label; legal entity unverified",
                                          "osm_feature": item["type"]+"/"+str(item["id"])}, company_id)
        upsert_facility(store, name, latitude, longitude, company_id, website,
                        {"osm_tags": tags, "license": "ODbL 1.0", "attribution": "OpenStreetMap contributors",
                         "business_identity_basis": "Public map operator/brand/name claim; corporate ownership unverified"},
                        source_url, "facility:osm:"+item["type"]+":"+str(item["id"]),
                        "osm_node" if item["type"] == "node" else "osm_feature_bbox_center", timestamp)
        imported += 1
    return {"imported": imported, "skipped": skipped, "source": "OpenStreetMap contributors", "source_timestamp": timestamp}


async def fetch_business_facilities(http, store, bbox, endpoint="https://overpass-api.de/api/interpreter", limit=5000):
    if not isinstance(bbox, (list, tuple)) or len(bbox) != 4:
        raise ValueError("Business query requires [south,west,north,east]")
    south, west = _coordinates(bbox[0], bbox[1])
    north, east = _coordinates(bbox[2], bbox[3])
    if south >= north or west >= east or north-south > 1 or east-west > 1:
        raise ValueError("Business query requires a positive bounding box no wider than one degree")
    if not 1 <= int(limit) <= 10000:
        raise ValueError("Business feature limit must be between 1 and 10000")
    bounds = ",".join(str(value) for value in (south, west, north, east))
    query = '[out:json][timeout:30];(' + "".join('nwr["'+key+'"][~"^(name|brand|operator)$"~"."]('+bounds+');'
                                                                    for key in ("shop", "office", "craft", "industrial", "amenity")) + ');out body center '+str(int(limit))+';'
    response = await http.post(endpoint, data={"data": query}, max_bytes=16*1024*1024, max_attempts=1)
    data = json.loads(response.path.read_bytes())
    if data.get("remark"):
        raise ValueError("Overpass returned an incomplete result: " + str(data["remark"])[:160])
    result = await asyncio.to_thread(import_osm_facilities, store, data, limit)
    return {**result, "bbox": [south, west, north, east], "possibly_truncated": len(data["elements"]) >= int(limit)}
