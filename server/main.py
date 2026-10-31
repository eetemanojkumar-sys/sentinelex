"""SentinelX central telemetry API (rule-based; no AI/ML)."""
import os
from datetime import datetime, timezone
from typing import Any
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, Integer, JSON, String, UniqueConstraint, create_engine, desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
if not TOKEN:
    raise RuntimeError("SENTINELX_AGENT_TOKEN must be configured")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """Customer organization. Tenant-owned records must be scoped to this ID."""
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class User(Base):
    """Platform identity. Passwords are stored only as salted password hashes."""
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class TenantMembership(Base):
    """A user's role inside one organization; users may belong to multiple tenants."""
    __tablename__ = "tenant_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_membership_user"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="viewer", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class UserSession(Base):
    """Opaque browser session; only a SHA-256 token digest is persisted."""
    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class EnrollmentToken(Base):
    """Single-use, expiring organization enrollment token; persist only its hash."""
    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class AgentCredential(Base):
    """Per-host agent credential metadata; never store the plaintext credential."""
    __tablename__ = "agent_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    host_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    """Tenant-scoped audit trail for security-sensitive actions."""
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class Telemetry(Base):
    __tablename__ = "telemetry"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)


class IngestedBatch(Base):
    """Idempotency ledger: one accepted batch per host and batch identifier."""
    __tablename__ = "ingested_batches"
    __table_args__ = (
        UniqueConstraint("host_id", "batch_id", name="uq_ingested_batch_host_batch"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    batch_id: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class Host(Base):
    """Latest identity and lifecycle metadata for each endpoint."""
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
    """One bounded latest snapshot per host for fast fleet queries."""
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


Base.metadata.create_all(bind=engine)
app = FastAPI(
    title="SentinelX Central API",
    version="0.2.0",
    description="Independent cross-platform infrastructure health and security telemetry platform",
)

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def dashboard_home():
    return RedirectResponse(url="/dashboard/")


class EventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="info",
                           pattern="^(info|low|medium|high|critical)$")
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


def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def verify_agent(token: str | None):
    if not token or token != TOKEN:
        raise HTTPException(status_code=401, detail="Invalid agent token")


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinelx-central", "version": "0.2.0"}


@app.post("/api/v1/telemetry", status_code=202)
def ingest(payload: TelemetryIn, x_agent_token: str | None = Header(default=None),
           db: Session = Depends(db_session)):
    verify_agent(x_agent_token)
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
