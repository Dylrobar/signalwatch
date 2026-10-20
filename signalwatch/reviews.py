"""Analyst decisions are separate from replaceable collection projections."""
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .access import audit, timestamp


def ensure_schema(conn):
    conn.executescript("""
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


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    subject_id: str = Field(min_length=1, max_length=500)
    company_id: str = Field(default="", max_length=300)
    state: Literal["open", "investigating", "not_applicable", "accepted_risk", "remediated"]
    reason: str = Field(min_length=1, max_length=10000)
    review_due_at: str | None = None
    expected_revision: int | None = Field(default=None, ge=0)

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
            result = public_review(conn.execute("SELECT * FROM analyst_reviews WHERE subject_id=? AND company_id=?", (body.subject_id, body.company_id)).fetchone())
            audit(conn, request.state.actor, "warning.reviewed", body.subject_id, before=public_review(previous) if previous else None, after=result, reason=body.reason)
            return result
