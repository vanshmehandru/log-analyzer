from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import func

try:
    from database import get_db
    from models.incidents import Incident
    from models.normalized_logs import NormalizedLog
    from analytics.timeline import get_log_timeline
    from analytics.top_sources import get_top_sources, get_top_source_users
    from analytics.top_destinations import get_top_destinations
    from analytics.top_ports import get_top_ports
    from analytics.category_distribution import get_category_distribution
    from analytics.risk_trends import get_risk_trends
except ModuleNotFoundError:
    from backend.database import get_db
    from backend.models.incidents import Incident
    from backend.models.normalized_logs import NormalizedLog
    from backend.analytics.timeline import get_log_timeline
    from backend.analytics.top_sources import get_top_sources, get_top_source_users
    from backend.analytics.top_destinations import get_top_destinations
    from backend.analytics.top_ports import get_top_ports
    from backend.analytics.category_distribution import get_category_distribution
    from backend.analytics.risk_trends import get_risk_trends

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
async def get_stats(upload_id: Optional[int] = Query(None, description="Filter by upload ID"), db: Session = Depends(get_db)):
    """Retrieves aggregated analytics for the main dashboard."""
    # Count total logs
    log_query = db.query(func.count(NormalizedLog.id))
    if upload_id is not None:
        log_query = log_query.filter(NormalizedLog.upload_id == upload_id)
    total_logs = log_query.scalar() or 0
    
    # Count total incidents
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    
    # Average risk score
    risk_query = db.query(func.avg(NormalizedLog.risk_score))
    if upload_id is not None:
        risk_query = risk_query.filter(NormalizedLog.upload_id == upload_id)
    avg_risk = risk_query.scalar() or 0.0
    
    return {
        "total_logs": total_logs,
        "total_incidents": total_incidents,
        "average_risk_score": round(float(avg_risk), 2),
        "top_sources": get_top_sources(db, limit=5, upload_id=upload_id),
        "top_destinations": get_top_destinations(db, limit=5, upload_id=upload_id),
        "category_distribution": get_category_distribution(db, upload_id=upload_id),
        "risk_trends": get_risk_trends(db, upload_id=upload_id)
    }

@router.get("/timeline")
async def get_timeline(upload_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves timeline series for event count & risk scores."""
    return get_log_timeline(db, upload_id=upload_id)

@router.get("/top-sources")
async def get_sources(limit: int = 5, upload_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves top source IPs and top source user accounts."""
    return {
        "ips": get_top_sources(db, limit=limit, upload_id=upload_id),
        "users": get_top_source_users(db, limit=limit, upload_id=upload_id)
    }

@router.get("/top-destinations")
async def get_destinations(limit: int = 5, upload_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves top destination IPs."""
    return get_top_destinations(db, limit=limit, upload_id=upload_id)

@router.get("/top-ports")
async def get_ports(limit: int = 5, upload_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves top destination ports."""
    return get_top_ports(db, limit=limit, upload_id=upload_id)

@router.get("/incidents")
async def list_incidents(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Lists all generated security incidents."""
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    return incidents
