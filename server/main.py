"""SentinelX self-hosted central API with local administrator and agent credentials."""
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, Integer, JSON, String, UniqueConstraint, create_engine, desc, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from server.security import generate_secret, hash_password, hash_secret, verify_password

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
ADMIN_USERNAME = os.getenv("SENTINELX_ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.getenv("SENTINELX_ADMIN_PASSWORD", "")
SESSION_HOURS = max(1, min(int(os.getenv("SENTINELX_SESSION_HOURS", "12")), 168))
COOKIE_SECURE = os.getenv("SENTINELX_COOKIE_SECURE", "true").lower() == "true"
ALLOW_LEGACY_TOKEN = os.getenv("SENTINELX_ALLOW_LEGACY_AGENT_TOKEN", "false").lower() == "true"
LEGACY_TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
SESSION_COOKIE = "sentinelx_session"
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Admin(Base):
    __tablename__ = "local_admin"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Telemetry(Base):
    __tablename__ = "telemetry"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)


class IngestedBatch(Base):
    __tablename__ = "ingested_batches"
    __table_args__ = (UniqueConstraint("host_id", "batch_id", name="uq_ingested_batch_host_batch"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    batch_id: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class Host(Base):
    __tablename__ = "hosts"
    host_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    platform: Mapped[str] = mapped_column(String(100), default="")
    os_release: Mapped[str] = mapped_column(String(255), default="")
    architecture: Mapped[str] = mapped_column(String(100), default="")
    agent_version: Mapped[str] = mapped_column(String(50), default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    last_sequence: Mapped[int] = mapped_column(Integer, default=0)


class LatestMetrics(Base):
    __tablename__ = "latest_metrics"
    host_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    message: Mapped[str] = mapped_column(String(1000))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


Base.metadata.create_all(bind=engine)
if not ADMIN_PASSWORD:
    raise RuntimeError("SENTINELX_ADMIN_PASSWORD must be configured before starting SentinelX")
if len(ADMIN_PASSWORD) < 12:
    raise RuntimeError("SENTINELX_ADMIN_PASSWORD must contain at least 12 characters")
with SessionLocal() as _db:
    _admin = _db.scalar(select(Admin).where(Admin.username == ADMIN_USERNAME))
    if _admin is None:
        _db.add(Admin(username=ADMIN_USERNAME, password_hash=hash_password(ADMIN_PASSWORD)))
        _db.commit()
    elif os.getenv("SENTINELX_RESET_ADMIN_PASSWORD", "false").lower() == "true":
        _admin.password_hash = hash_password(ADMIN_PASSWORD)
        _db.commit()

app = FastAPI(title="SentinelX Central API", version="0.3.0",
              description="Self-hosted cross-platform infrastructure monitoring and security telemetry.")
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_admin(request: Request, db: Session):
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(status_code=401, detail="Administrator authentication required")
    row = db.scalar(select(AdminSession).where(
        AdminSession.token_hash == hash_secret(raw),
        AdminSession.revoked_at.is_(None),
        AdminSession.expires_at > datetime.now(timezone.utc)))
    if row is None:
        raise HTTPException(status_code=401, detail="Administrator session expired")
    return True


@app.middleware("http")
async def protect_dashboard_and_api(request: Request, call_next):
    path = request.url.path
    public = (path in {"/health", "/login", "/api/v1/auth/login", "/api/v1/agents/enroll"}
              or path.startswith("/docs") or path.startswith("/openapi.json")
              or path.startswith("/redoc"))
    protected = path.startswith("/dashboard") or (path.startswith("/api/v1/") and path != "/api/v1/telemetry")
    if protected and not public:
        raw = request.cookies.get(SESSION_COOKIE)
        valid = False
        if raw:
            with SessionLocal() as db:
                row = db.scalar(select(AdminSession).where(
                    AdminSession.token_hash == hash_secret(raw),
                    AdminSession.revoked_at.is_(None),
                    AdminSession.expires_at > datetime.now(timezone.utc)))
                valid = row is not None
        if not valid:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Administrator authentication required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
    return await call_next(request)


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/dashboard/")


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(DASHBOARD_DIR / "login.html")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


@app.post("/api/v1/auth/login")
def admin_login(payload: LoginIn, response: Response, db: Session = Depends(db_session)):
    admin = db.scalar(select(Admin).where(Admin.username == payload.username.strip()))
    if admin is None or not verify_password(payload.password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid administrator credentials")
    raw = generate_secret()
    db.add(AdminSession(id=secrets.token_hex(16), token_hash=hash_secret(raw),
                        expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)))
    db.commit()
    response.set_cookie(SESSION_COOKIE, raw, httponly=True, secure=COOKIE_SECURE,
                        samesite="strict", max_age=SESSION_HOURS * 3600, path="/")
    return {"authenticated": True, "username": admin.username}


@app.post("/api/v1/auth/logout")
def admin_logout(request: Request, response: Response, db: Session = Depends(db_session)):
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        row = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_secret(raw)))
        if row and row.revoked_at is None:
            row.revoked_at = datetime.now(timezone.utc)
            db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True,
                           secure=COOKIE_SECURE, samesite="strict")
    return {"authenticated": False}


class EnrollmentIn(BaseModel):
    enrollment_token: str = Field(min_length=20, max_length=256)
    host_id: str = Field(min_length=1, max_length=255)


@app.post("/api/v1/agents/enroll")
def enroll_agent(payload: EnrollmentIn, db: Session = Depends(db_session)):
    now = datetime.now(timezone.utc)
    claimed = db.execute(update(EnrollmentToken).where(
        EnrollmentToken.token_hash == hash_secret(payload.enrollment_token),
        EnrollmentToken.used_at.is_(None), EnrollmentToken.revoked_at.is_(None),
        EnrollmentToken.expires_at > now).values(used_at=now))
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=401, detail="Enrollment token is invalid, expired, or already used")
    credential = generate_secret()
    db.add(AgentCredential(id=secrets.token_hex(16), host_id=payload.host_id,
                           token_hash=hash_secret(credential)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Enrollment could not be completed")
    return {"host_id": payload.host_id, "agent_token": credential}


def verify_agent(token: str | None, host_id: str, db: Session):
    if token and ALLOW_LEGACY_TOKEN and LEGACY_TOKEN and hmac.compare_digest(token, LEGACY_TOKEN):
        return
    if not token:
        raise HTTPException(status_code=401, detail="Agent credential required")
    credential = db.scalar(select(AgentCredential).where(
        AgentCredential.token_hash == hash_secret(token),
        AgentCredential.revoked_at.is_(None)))
    if credential is None or not hmac.compare_digest(credential.host_id, host_id):
        raise HTTPException(status_code=401, detail="Invalid or revoked agent credential")
    credential.last_used_at = datetime.now(timezone.utc)
    db.commit()


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinelx-central", "version": "0.3.0"}


class EventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="info", pattern="^(info|low|medium|high|critical)$")
    message: str = Field(min_length=1, max_length=1000)
    details: dict[str, Any] = Field(default_factory=dict)


class AgentInfo(BaseModel):
    version: str = Field(default="", max_length=50)
    platform: str = Field(default="", max_length=100)
    architecture: str = Field(default="", max_length=100)


class TelemetryIn(BaseModel):
    host_id: str = Field(min_length=1, max_length=255)
    batch_id: str | None = Field(default=None, min_length=1, max_length=64)
    metrics: dict[str, Any]
    events: list[EventIn] = Field(default_factory=list, max_length=500)
    schema_version: int = Field(default=1, ge=1, le=100)
    agent: AgentInfo = Field(default_factory=AgentInfo)
    collected_at: datetime | None = None
    sequence: int = Field(default=0, ge=0)


@app.post("/api/v1/admin/agents/enrollment-tokens")
def create_enrollment_token(request: Request, payload: dict | None = None,
                            db: Session = Depends(db_session)):
    current_admin(request, db)
    minutes = int((payload or {}).get("expires_minutes", 30))
    if minutes < 5 or minutes > 1440:
        raise HTTPException(status_code=422, detail="expires_minutes must be between 5 and 1440")
    raw = generate_secret()
    db.add(EnrollmentToken(id=secrets.token_hex(16), token_hash=hash_secret(raw),
                           expires_at=datetime.now(timezone.utc) + timedelta(minutes=minutes)))
    db.commit()
    return {"enrollment_token": raw, "expires_in_minutes": minutes}


@app.get("/api/v1/admin/agents")
def list_agents(request: Request, db: Session = Depends(db_session)):
    current_admin(request, db)
    rows = db.scalars(select(AgentCredential).order_by(AgentCredential.issued_at.desc())).all()
    return [{"id": row.id, "host_id": row.host_id, "issued_at": row.issued_at,
             "last_used_at": row.last_used_at, "revoked": row.revoked_at is not None}
            for row in rows]


@app.post("/api/v1/admin/agents/{credential_id}/revoke")
def revoke_agent(credential_id: str, request: Request, db: Session = Depends(db_session)):
    current_admin(request, db)
    row = db.get(AgentCredential, credential_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Agent credential not found")
    row.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return {"revoked": True, "host_id": row.host_id}


@app.post("/api/v1/telemetry", status_code=202)
def ingest(payload: TelemetryIn, x_agent_token: str | None = Header(default=None),
           db: Session = Depends(db_session)):
    verify_agent(x_agent_token, payload.host_id, db)
    now = datetime.now(timezone.utc)
    if payload.batch_id:
        # Flush the unique idempotency record before writing any telemetry.
        # A retry after a lost HTTP response is acknowledged without duplicating
        # metric samples, host updates, or security events.
        db.add(IngestedBatch(host_id=payload.host_id, batch_id=payload.batch_id))
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return {
                "accepted": True,
                "duplicate": True,
                "host_id": payload.host_id,
                "events_received": 0,
            }
    db.add(Telemetry(host_id=payload.host_id, metrics=payload.metrics))
    snapshot = db.get(LatestMetrics, payload.host_id)
    if snapshot is None:
        snapshot = LatestMetrics(host_id=payload.host_id, received_at=now, metrics=payload.metrics)
        db.add(snapshot)
    else:
        snapshot.received_at = now
        snapshot.metrics = payload.metrics
    host = db.get(Host, payload.host_id)
    os_info = payload.metrics.get("os", {}) if isinstance(payload.metrics, dict) else {}
    os_info = os_info if isinstance(os_info, dict) else {}
    if host is None:
        host = Host(host_id=payload.host_id)
        db.add(host)
    host.hostname = str(payload.metrics.get("hostname") or payload.host_id)[:255]
    host.platform = str(payload.agent.platform or os_info.get("system") or payload.metrics.get("platform") or "")[:100]
    host.os_release = str(os_info.get("release") or os_info.get("version") or "")[:255]
    host.architecture = str(payload.agent.architecture or os_info.get("machine") or "")[:100]
    host.agent_version = payload.agent.version[:50]
    host.last_seen = now
    host.last_sequence = max(host.last_sequence or 0, payload.sequence)
    for event in payload.events:
        db.add(SecurityEvent(
            host_id=payload.host_id,
            event_type=event.event_type,
            severity=event.severity,
            message=event.message,
            details=event.details,
        ))
    db.commit()
    return {"accepted": True, "host_id": payload.host_id,
            "events_received": len(payload.events)}


@app.get("/api/v1/hosts")
def hosts(db: Session = Depends(db_session)):
    snapshots = db.scalars(select(LatestMetrics).order_by(LatestMetrics.host_id)).all()
    registry = {row.host_id: row for row in db.scalars(select(Host)).all()}
    result = []
    for row in snapshots:
        registered = registry.get(row.host_id)
        result.append({
            "host_id": row.host_id,
            "last_seen": row.received_at,
            "metrics": row.metrics,
            "hostname": registered.hostname if registered else row.host_id,
            "platform": registered.platform if registered else row.metrics.get("platform", ""),
            "os_release": registered.os_release if registered else "",
            "architecture": registered.architecture if registered else "",
            "agent_version": registered.agent_version if registered else "",
            "last_sequence": registered.last_sequence if registered else 0,
        })
    return result


@app.get("/api/v1/events")
def events(limit: int = 100, db: Session = Depends(db_session)):
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
    ).all()
    return [{
        "id": row.id,
        "host_id": row.host_id,
        "event_type": row.event_type,
        "severity": row.severity,
        "message": row.message,
        "details": row.details,
        "created_at": row.created_at,
    } for row in rows]



@app.get("/api/v1/disk-history")
def disk_history(host_id: str, mountpoint: str, limit: int = 60,
                 db: Session = Depends(db_session)):
    """Return recent stored disk-usage samples for one host and mount point."""
    limit = max(2, min(limit, 500))
    rows = db.scalars(
        select(Telemetry)
        .where(Telemetry.host_id == host_id)
        .order_by(desc(Telemetry.received_at))
        .limit(limit)
    ).all()
    samples = []
    for row in reversed(rows):
        disk_data = (row.metrics or {}).get("disk", {})
        volume = disk_data.get(mountpoint) if isinstance(disk_data, dict) else None
        if not isinstance(volume, dict) or volume.get("percent") is None:
            continue
        samples.append({
            "recorded_at": row.received_at,
            "percent": volume.get("percent"),
            "total_bytes": volume.get("total_bytes"),
            "used_bytes": volume.get("used_bytes"),
            "free_bytes": volume.get("free_bytes"),
        })
    return {"host_id": host_id, "mountpoint": mountpoint, "samples": samples}


@app.get("/api/v1/summary")
# Fail closed: these legacy queries are not yet tenant-scoped.
# The dependency intentionally blocks access until migration and isolation tests are complete.
def summary(db: Session = Depends(db_session)):
    latest_hosts = [{
        "host_id": row.host_id,
        "metrics": row.metrics,
        "last_seen": row.received_at,
    } for row in db.scalars(select(LatestMetrics).order_by(LatestMetrics.host_id)).all()]
    recent = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(10)
    ).all()
    return {
        "monitored_hosts": len(latest_hosts),
        "latest_hosts": latest_hosts,
        "recent_events": [{
            "host_id": event.host_id,
            "severity": event.severity,
            "event_type": event.event_type,
            "message": event.message,
            "created_at": event.created_at,
        } for event in recent],
    }



@app.get("/api/v1/metrics/history")
# Fail closed: these legacy queries are not yet tenant-scoped.
# The dependency intentionally blocks access until migration and isolation tests are complete.
def metrics_history(host_id: str, metric: str = "cpu", limit: int = 120,
                    db: Session = Depends(db_session)):
    """Return bounded historical CPU, memory or network samples for one host."""
    if metric not in {"cpu", "memory", "network"}:
        raise HTTPException(status_code=400, detail="metric must be cpu, memory, or network")
    limit = max(2, min(limit, 500))
    rows = db.scalars(select(Telemetry).where(Telemetry.host_id == host_id)
                      .order_by(desc(Telemetry.received_at)).limit(limit)).all()
    samples = []
    for row in reversed(rows):
        data = row.metrics or {}
        if metric == "cpu":
            value = data.get("cpu_percent")
            sample = {"recorded_at": row.received_at, "value": value}
        elif metric == "memory":
            memory = data.get("memory") or {}
            sample = {"recorded_at": row.received_at, "value": memory.get("percent")}
        else:
            interfaces = data.get("network_interfaces") or {}
            sample = {"recorded_at": row.received_at, "interfaces": interfaces}
        if metric == "network" or sample.get("value") is not None:
            samples.append(sample)
    return {"host_id": host_id, "metric": metric, "samples": samples}
