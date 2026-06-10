from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

try:
    from backend.database import get_db
    from backend.models.incidents import Incident
    from backend.correlation.engine import run_correlation, load_rules_config
except ModuleNotFoundError:
    from database import get_db
    from models.incidents import Incident
    from correlation.engine import run_correlation, load_rules_config

router = APIRouter(tags=["Correlation"])

@router.get("/incidents")
async def list_incidents(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Lists all security correlation incidents."""
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    return incidents

@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Gets details for a specific incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/correlation/run")
async def trigger_correlation(upload_id: Optional[int] = Query(None, description="Trigger only for a specific upload"), db: Session = Depends(get_db)):
    """Manually runs the correlation engine."""
    try:
        new_incidents = run_correlation(db, upload_id=upload_id)
        return {
            "status": "success",
            "message": f"Correlation engine finished. Generated {len(new_incidents)} new incidents.",
            "new_incidents": [
                {
                    "id": inc.id,
                    "name": inc.incident_name,
                    "severity": inc.severity,
                    "description": inc.description
                }
                for inc in new_incidents
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Correlation run failed: {str(e)}")

@router.get("/correlation/rules")
async def get_rules():
    """Gets the active correlation rules configuration."""
    return load_rules_config()
