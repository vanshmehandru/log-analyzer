from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from models.normalized_logs import NormalizedLog

def get_top_ports(db: Session, limit: int = 5, upload_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Aggregates the most targeted destination ports and counts."""
    query = db.query(
        NormalizedLog.dst_port,
        func.count(NormalizedLog.id).label("count")
    ).filter(NormalizedLog.dst_port != None)
    
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    results = (
        query.group_by(NormalizedLog.dst_port)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    
    return [{"port": row[0], "count": row[1]} for row in results]
