from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from models.normalized_logs import NormalizedLog

def get_top_sources(db: Session, limit: int = 5, upload_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Aggregates the top source IP addresses and counts."""
    query = db.query(
        NormalizedLog.src_ip,
        func.count(NormalizedLog.id).label("count")
    ).filter(NormalizedLog.src_ip != None)
    
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    results = (
        query.group_by(NormalizedLog.src_ip)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    
    return [{"ip": row[0], "count": row[1]} for row in results]

def get_top_source_users(db: Session, limit: int = 5, upload_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Aggregates the top usernames and counts."""
    query = db.query(
        NormalizedLog.username,
        func.count(NormalizedLog.id).label("count")
    ).filter(NormalizedLog.username != None)
    
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    results = (
        query.group_by(NormalizedLog.username)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    
    return [{"user": row[0], "count": row[1]} for row in results]
