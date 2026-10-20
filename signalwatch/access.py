"""Named workspace credentials and durable, secret-free mutation attribution."""
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


def ensure_schema(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS workspace_credentials (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT);
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, actor_name TEXT NOT NULL,
      action TEXT NOT NULL, subject_id TEXT NOT NULL, reason TEXT NOT NULL,
      before_json TEXT NOT NULL, after_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS audit_log_subject ON audit_log(subject_id,created_at);
    """)


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def audit(conn, actor, action, subject_id="", *, before=None, after=None, reason=""):
    conn.execute("INSERT INTO audit_log VALUES(?,?,?,?,?,?,?,?,?)", (
        uuid.uuid4().hex, actor["id"], actor["name"], action, subject_id, reason,
        json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True), timestamp()))


def public_credential(row):
    return {key: row[key] for key in ("id", "name", "role", "created_at", "revoked_at")}


class Access:
    def __init__(self, store, master_token=""):
        self.store, self.master_token = store, master_token

    def required(self):
        if self.master_token:
            return True
        with self.store.connection() as conn:
            # Revoking a credential must never re-enable anonymous access.
            return conn.execute("SELECT 1 FROM workspace_credentials LIMIT 1").fetchone() is not None

    def authenticate(self, header):
        scheme, _, token = header.partition(" ")
        if scheme.lower() == "bearer" and token:
            if self.master_token and secrets.compare_digest(token.encode(), self.master_token.encode()):
                return {"id": "master", "name": "Workspace administrator", "role": "admin"}
            digest = hashlib.sha256(token.encode()).hexdigest()
            with self.store.connection() as conn:
                row = conn.execute("SELECT * FROM workspace_credentials WHERE token_hash=? AND revoked_at IS NULL", (digest,)).fetchone()
                if row and secrets.compare_digest(digest, row["token_hash"]):
                    return {key: row[key] for key in ("id", "name", "role")}
            return None
        if not self.required():
            return {"id": "local", "name": "Local administrator", "role": "admin"}
        return None

    @staticmethod
    def allowed(actor, method, path):
        if path.startswith("/api/auth/credentials") or path == "/api/audit":
            return actor["role"] == "admin"
        if method in {"GET", "HEAD", "OPTIONS"}:
            return True
        if path in {"/api/companies/resolve", "/api/companies/preview"}:
            return True
        if path in {"/api/sources/settings", "/api/sources/feed"}:
            return actor["role"] == "admin"
        return actor["role"] in {"admin", "editor"}


class CredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    role: Literal["viewer", "editor", "admin"]


def register_access_routes(app, store, config, access):
    @app.get("/api/auth/me")
    def me(request: Request):
        return request.state.actor

    @app.get("/api/capabilities")
    def capabilities(request: Request):
        from .config import VERSION
        role = request.state.actor["role"]
        return {"version": VERSION, "database": "postgresql" if str(config["db"]).startswith(("postgres://", "postgresql://")) else "sqlite",
                "features": {key: True for key in ("data_quality", "evidence_history", "evidence_pagination", "analyst_review", "job_progress", "credential_roles", "graph_focus")},
                "user": request.state.actor, "permissions": {"read": True, "write": role != "viewer", "admin": role == "admin"}}

    @app.get("/api/auth/credentials")
    def credentials():
        with store.connection() as conn:
            return {"items": [public_credential(row) for row in conn.execute("SELECT * FROM workspace_credentials ORDER BY created_at,id")]}

    @app.post("/api/auth/credentials")
    def create_credential(body: CredentialRequest, request: Request):
        credential_id = uuid.uuid4().hex
        token = "sw_" + credential_id + "." + secrets.token_urlsafe(32)
        with store.connection(write=True) as conn:
            if not access.master_token and not conn.execute("SELECT 1 FROM workspace_credentials WHERE revoked_at IS NULL AND role='admin' LIMIT 1").fetchone() and body.role != "admin":
                raise HTTPException(409, "Create an administrator credential first to preserve workspace access")
            conn.execute("INSERT INTO workspace_credentials VALUES(?,?,?,?,?,NULL)",
                         (credential_id, body.name, body.role, hashlib.sha256(token.encode()).hexdigest(), timestamp()))
            record = public_credential(conn.execute("SELECT * FROM workspace_credentials WHERE id=?", (credential_id,)).fetchone())
            audit(conn, request.state.actor, "credential.created", credential_id, after=record)
        return {"credential": record, "token": token}

    @app.post("/api/auth/credentials/{credential_id}/revoke")
    def revoke_credential(credential_id: str, request: Request):
        with store.connection(write=True) as conn:
            row = conn.execute("SELECT * FROM workspace_credentials WHERE id=?", (credential_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Credential not found")
            before = public_credential(row)
            if not row["revoked_at"]:
                if row["role"] == "admin" and not access.master_token and not conn.execute("SELECT 1 FROM workspace_credentials WHERE role='admin' AND revoked_at IS NULL AND id!=? LIMIT 1", (credential_id,)).fetchone():
                    raise HTTPException(409, "Cannot revoke the last administrator credential")
                conn.execute("UPDATE workspace_credentials SET revoked_at=? WHERE id=?", (timestamp(), credential_id))
                after = public_credential(conn.execute("SELECT * FROM workspace_credentials WHERE id=?", (credential_id,)).fetchone())
                audit(conn, request.state.actor, "credential.revoked", credential_id, before=before, after=after)
            else:
                after = before
        return after

    @app.get("/api/audit")
    def audit_history(subject_id: str = "", limit: int = 100):
        if not 1 <= limit <= 500:
            raise HTTPException(422, "limit must be between 1 and 500")
        with store.connection() as conn:
            where, params = ("WHERE subject_id=?", [subject_id]) if subject_id else ("", [])
            rows = conn.execute("SELECT * FROM audit_log " + where + " ORDER BY created_at DESC,id DESC LIMIT ?", (*params, limit))
            items = []
            for row in rows:
                item = dict(row)
                for field in ("before", "after"):
                    item[field] = json.loads(item.pop(field + "_json"))
                items.append(item)
            return {"items": items}
