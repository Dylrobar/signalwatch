"""Analyst decisions are separate from replaceable collection projections."""
import json
from datetime import datetime, timezone, timedelta
from typing import Literal

from fastapi import HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator, HttpUrl

from .access import audit, timestamp


def ensure_schema(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS exposure_verifications (
      subject_id TEXT NOT NULL, company_id TEXT NOT NULL,
      version TEXT NOT NULL, source_url TEXT NOT NULL, evidence_url TEXT NOT NULL,
      expires_at TEXT NOT NULL, verified_at TEXT NOT NULL, actor_id TEXT NOT NULL,
      remediation TEXT NOT NULL, alert_first_seen TEXT NOT NULL, PRIMARY KEY(subject_id,company_id));
    CREATE TABLE IF NOT EXISTS analyst_reviews (
      subject_id TEXT NOT NULL, company_id TEXT NOT NULL DEFAULT '',
      state TEXT NOT NULL, reason TEXT NOT NULL, review_due_at TEXT,
      revision INTEGER NOT NULL, updated_at TEXT NOT NULL, actor_id TEXT NOT NULL,
      actor_name TEXT NOT NULL, PRIMARY KEY(subject_id,company_id));
    CREATE TABLE IF NOT EXISTS analyst_review_history (
      subject_id TEXT NOT NULL, company_id TEXT NOT NULL DEFAULT '',
      state TEXT NOT NULL, reason TEXT NOT NULL, review_due_at TEXT,
      revision INTEGER NOT NULL, updated_at TEXT NOT NULL, actor_id TEXT NOT NULL,
      actor_name TEXT NOT NULL, PRIMARY KEY(subject_id,company_id,revision));
    """)


class ExposureVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    observed_version: str = Field(min_length=1, max_length=256)
    evidence_url: HttpUrl
    runtime_verified: Literal[True]
    package_affected: Literal[True]
    expires_at: datetime
    remediation: str = Field(min_length=10, max_length=4000)

    @field_validator("expires_at")
    @classmethod
    def expiry(cls, value):
        now = datetime.now(timezone.utc)
        if value.tzinfo is None or not now < value <= now + timedelta(days=30):
            raise ValueError("Verification expiry must be timezone-aware, in the future, and within 30 days")
        return value.astimezone(timezone.utc)


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    subject_id: str = Field(min_length=1, max_length=500)
    company_id: str = Field(default="", max_length=300)
    state: Literal["open", "investigating", "not_applicable", "accepted_risk", "remediated", "confirmed_exposure"]
    reason: str = Field(min_length=1, max_length=10000)
    review_due_at: str | None = None
    verification: ExposureVerification | None = None
    expected_revision: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def confirmation(self):
        if self.state == "confirmed_exposure" and (not self.company_id or self.verification is None):
            raise ValueError("Confirmed exposure requires company scope and verification evidence")
        if self.state != "confirmed_exposure" and self.verification is not None:
            raise ValueError("Verification is only valid for a confirmed exposure")
        return self

    @field_validator("review_due_at")
    @classmethod
    def due_timestamp(cls, value):
        if not value:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("review_due_at must include a timezone")
        return parsed.astimezone(timezone.utc).isoformat()


def public_review(row):
    result = dict(row)
    result["actor"] = {"id": result.pop("actor_id"), "name": result.pop("actor_name")}
    return result


def validate_scope(conn, subject_id, company_id):
    alert = conn.execute("SELECT asset_id FROM alerts WHERE id=?", (subject_id,)).fetchone()
    if alert is None:
        raise HTTPException(404, "Active warning not found; historical decisions remain available in review history")
    if company_id:
        from .companies import company, company_assets
        try:
            company(conn, company_id)
        except (ValueError, LookupError) as exc:
            raise HTTPException(404, "Company not found") from exc
        assets, _ = company_assets(conn, company_id)
        included = {item["id"] for item in assets if item["included"]} | {company_id}
        if alert["asset_id"] not in included:
            raise HTTPException(409, "Warning is not currently attributed to this company")


def register_review_routes(app, store, config):
    @app.get("/api/reviews")
    def reviews(subject_id: str = "", company_id: str | None = None, limit: int = Query(100, ge=1, le=500)):
        where, params = [], []
        for key, value in (("subject_id", subject_id), ("company_id", company_id)):
            if value or (key == "company_id" and value is not None):
                where.append(key + "=?")
                params.append(value)
        with store.connection() as conn:
            rows = conn.execute("SELECT * FROM analyst_reviews" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY updated_at DESC,subject_id,company_id LIMIT ?", (*params, limit))
            return {"items": [public_review(row) for row in rows]}

    @app.get("/api/reviews/history")
    def history(subject_id: str = Query(..., min_length=1), company_id: str | None = None, limit: int = Query(100, ge=1, le=500)):
        where, params = "subject_id=?", [subject_id]
        if company_id is not None:
            where += " AND company_id=?"
            params.append(company_id)
        with store.connection() as conn:
            return {"items": [public_review(row) for row in conn.execute("SELECT * FROM analyst_review_history WHERE " + where + " ORDER BY updated_at DESC,revision DESC LIMIT ?", (*params, limit))]}

    @app.post("/api/reviews")
    def save_review(body: ReviewRequest, request: Request):
        with store.connection(write=True) as conn:
            validate_scope(conn, body.subject_id, body.company_id)
            if body.verification is not None:
                from .companies import company_assets
                alert = conn.execute("SELECT * FROM alerts WHERE id=?", (body.subject_id,)).fetchone()
                assets, _ = company_assets(conn, body.company_id)
                owned = any(a["id"] == alert["asset_id"] and a["included"] and a["status"] == "confirmed" and a["role"] == "owned" for a in assets)
                assessment = json.loads(alert['assessment'] or '{}')
                if assessment.get('evidence', {}).get('contradicting') or assessment.get('applicability', {}).get('state') == 'false':
                    raise HTTPException(409, "Resolve contradictory observations or incompatible configuration before confirming exposure")
                if not owned or alert["version_state"] not in ("exact", "affected_range") or alert["version"] != body.verification.observed_version:
                    raise HTTPException(409, "Confirm asset ownership and reload the exact affected version before verifying exposure")
            previous = conn.execute("SELECT * FROM analyst_reviews WHERE subject_id=? AND company_id=?", (body.subject_id, body.company_id)).fetchone()
            revision = previous["revision"] if previous else 0
            # Existing decisions require a revision to prevent silent lost updates.
            if (previous and body.expected_revision is None) or (body.expected_revision is not None and body.expected_revision != revision):
                raise HTTPException(409, "Review changed; reload the latest decision before saving")
            values = (body.subject_id, body.company_id, body.state, body.reason, body.review_due_at,
                      revision + 1, timestamp(), request.state.actor["id"], request.state.actor["name"])
            conn.execute("""INSERT INTO analyst_reviews VALUES(?,?,?,?,?,?,?,?,?)
              ON CONFLICT(subject_id,company_id) DO UPDATE SET state=excluded.state,reason=excluded.reason,
              review_due_at=excluded.review_due_at,revision=excluded.revision,updated_at=excluded.updated_at,
              actor_id=excluded.actor_id,actor_name=excluded.actor_name""", values)
            conn.execute("INSERT INTO analyst_review_history VALUES(?,?,?,?,?,?,?,?,?)", values)
            conn.execute("DELETE FROM exposure_verifications WHERE subject_id=? AND company_id=?", (body.subject_id, body.company_id))
            if body.verification is not None:
                v = body.verification
                conn.execute("INSERT INTO exposure_verifications VALUES(?,?,?,?,?,?,?,?,?,?)", (
                    body.subject_id, body.company_id, alert["version"], alert["source_url"], str(v.evidence_url),
                    v.expires_at.isoformat(), timestamp(), request.state.actor["id"], v.remediation, alert["first_seen"]))
                audit(conn, request.state.actor, "exposure.verified", body.subject_id,
                      after=v.model_dump(mode="json"), reason=body.reason)
            result = public_review(conn.execute("SELECT * FROM analyst_reviews WHERE subject_id=? AND company_id=?", (body.subject_id, body.company_id)).fetchone())
            audit(conn, request.state.actor, "warning.reviewed", body.subject_id, before=public_review(previous) if previous else None, after=result, reason=body.reason)
            return result
