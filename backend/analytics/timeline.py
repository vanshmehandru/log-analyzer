from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
from models.normalized_logs import NormalizedLog

def get_log_timeline(db: Session, upload_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieves log count and average risk score aggregated by timestamp/time bucket."""
    query = db.query(
        NormalizedLog.timestamp,
        func.count(NormalizedLog.id).label("count"),
        func.avg(NormalizedLog.risk_score).label("avg_risk")
    )
    
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    results = (
        query.group_by(NormalizedLog.timestamp)
        .order_by(NormalizedLog.timestamp)
        .all()
    )
    
    timeline = []
    for row in results:
        # Avoid displaying None timestamps
        if not row[0]:
            continue
        timeline.append({
            "time": row[0],
            "count": row[1],
            "average_risk": round(float(row[2] or 0.0), 2)
        })
        
    return timeline
