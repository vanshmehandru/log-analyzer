from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

try:
    from backend.database import get_db
    from backend.models.uploads import Upload
    from backend.models.raw_logs import RawLog
    from backend.models.normalized_logs import NormalizedLog
except ModuleNotFoundError:
    from database import get_db
    from models.uploads import Upload
    from models.raw_logs import RawLog
    from models.normalized_logs import NormalizedLog

router = APIRouter(tags=["Logs"])

@router.get("/uploads")
async def list_uploads(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Lists all file upload records."""
    uploads = db.query(Upload).order_by(Upload.upload_time.desc()).offset(skip).limit(limit).all()
    return uploads

@router.get("/uploads/{upload_id}")
async def get_upload(upload_id: int, db: Session = Depends(get_db)):
    """Gets details for a specific upload."""
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    return upload

@router.get("/logs/raw")
async def get_raw_logs(upload_id: int = None, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Retrieves raw logs, optionally filtered by upload_id."""
    query = db.query(RawLog)
    if upload_id:
        query = query.filter(RawLog.upload_id == upload_id)
    return query.order_by(RawLog.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/logs/normalized")
async def get_normalized_logs(upload_id: int = None, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Retrieves normalized logs, optionally filtered by upload_id."""
    query = db.query(NormalizedLog)
    if upload_id:
        query = query.filter(NormalizedLog.upload_id == upload_id)
    return query.order_by(NormalizedLog.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/logs/flow")
async def get_flow_logs(
    event_category: Optional[str] = Query(None, description="Filter by event category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    source_log: Optional[str] = Query(None, description="Filter by log filename"),
    time_range: Optional[str] = Query(None, description="Filter by relative time range"),
    db: Session = Depends(get_db)
):
    """Retrieves chronologically sorted logs with correlation context for Wireshark Flow Graph."""
    try:
        from backend.models.incidents import Incident
        from backend.models.incident_evidence import IncidentEvidence
    except ModuleNotFoundError:
        from models.incidents import Incident
        from models.incident_evidence import IncidentEvidence

    query = db.query(
        NormalizedLog,
        Upload.file_name.label("source_log"),
        Incident.incident_name.label("incident_name"),
        Incident.severity.label("incident_severity"),
        Incident.id.label("incident_id")
    ).join(
        Upload, Upload.id == NormalizedLog.upload_id
    ).outerjoin(
        IncidentEvidence, IncidentEvidence.normalized_log_id == NormalizedLog.id
    ).outerjoin(
        Incident, Incident.id == IncidentEvidence.incident_id
    )

    # Apply filters
    if event_category:
        query = query.filter(NormalizedLog.event_category == event_category)
    if severity:
        query = query.filter(NormalizedLog.severity == severity)
    if source_log:
        query = query.filter(Upload.file_name == source_log)

    # Time Range filter relative to ingestion time (created_at)
    if time_range:
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        if time_range == "last_5_minutes":
            query = query.filter(NormalizedLog.created_at >= now - timedelta(minutes=5))
        elif time_range == "last_hour":
            query = query.filter(NormalizedLog.created_at >= now - timedelta(hours=1))
        elif time_range == "last_24_hours":
            query = query.filter(NormalizedLog.created_at >= now - timedelta(hours=24))

    # Sort ascending for time-series flow
    results = query.order_by(NormalizedLog.id.asc()).all()

    logs = []
    for row in results:
        log_obj, file_name, incident_name, incident_sev, incident_id = row
        log_dict = {
            "id": log_obj.id,
            "upload_id": log_obj.upload_id,
            "timestamp": log_obj.timestamp,
            "event_name": log_obj.event_name,
            "event_category": log_obj.event_category,
            "username": log_obj.username,
            "hostname": log_obj.hostname,
            "src_ip": log_obj.src_ip,
            "dst_ip": log_obj.dst_ip,
            "src_port": log_obj.src_port,
            "dst_port": log_obj.dst_port,
            "protocol": log_obj.protocol,
            "application": log_obj.application,
            "process_name": log_obj.process_name,
            "domain": log_obj.domain,
            "dns_query": log_obj.dns_query,
            "severity": log_obj.severity,
            "risk_score": log_obj.risk_score,
            "outcome": log_obj.outcome,
            "bytes": log_obj.bytes,
            "packet_count": log_obj.packet_count,
            "duration": log_obj.duration,
            "extra_attributes": log_obj.extra_attributes,
            "source_log": file_name,
            "incident_name": incident_name,
            "incident_severity": incident_sev,
            "incident_id": incident_id,
            "correlated": incident_name is not None
        }
        logs.append(log_dict)

    return logs
