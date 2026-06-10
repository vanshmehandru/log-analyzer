from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
from models.normalized_logs import NormalizedLog

def get_category_distribution(db: Session, upload_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Aggregates log count grouped by event category."""
    query = db.query(
        NormalizedLog.event_category,
        func.count(NormalizedLog.id).label("count")
    ).filter(NormalizedLog.event_category != None)
    
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    results = (
        query.group_by(NormalizedLog.event_category)
        .all()
    )
    
    return [{"category": row[0], "count": row[1]} for row in results]
