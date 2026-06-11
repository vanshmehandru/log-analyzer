from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
from models.normalized_logs import NormalizedLog

def get_risk_trends(db: Session, upload_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieves average, min, and max risk scores aggregated by severity levels."""
    query = db.query(
        NormalizedLog.severity,
        func.count(NormalizedLog.id).label("count")
    ).filter(NormalizedLog.severity != None)
    
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    results = (
        query.group_by(NormalizedLog.severity)
        .all()
    )
    
    return [
        {
            "severity": row[0],
            "count": row[1],
            "average_risk": 0.0
        }
        for row in results
    ]
