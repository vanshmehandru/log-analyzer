import json
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any

from models.uploads import Upload
from models.header_mappings import HeaderMapping
from models.raw_logs import RawLog
from models.normalized_logs import NormalizedLog
from models.incidents import Incident

def create_upload(db: Session, file_name: str, log_source: str = None) -> Upload:
    """Creates a new upload tracking record."""
    upload = Upload(file_name=file_name, log_source=log_source, status="processing")
    db.add(upload)
    db.commit()
    db.refresh(upload)
    return upload

def store_raw_logs(db: Session, upload_id: int, records: List[Dict[str, Any]]):
    """Stores the original raw CSV rows as JSONB."""
    raw_logs = [
        RawLog(upload_id=upload_id, raw_data=record)
        for record in records
    ]
    db.add_all(raw_logs)
    db.commit()

def store_header_mappings(db: Session, upload_id: int, translation_dict: Dict[str, str]):
    """Stores how original headers mapped to normalized headers."""
    mappings = [
        HeaderMapping(
            upload_id=upload_id, 
            original_header=orig, 
            normalized_header=norm
        )
        for orig, norm in translation_dict.items()
    ]
    db.add_all(mappings)
    db.commit()

def store_normalized_logs(db: Session, upload_id: int, records: List[Dict[str, Any]]):
    """Stores the fully parsed and categorized normalized records."""
    normalized_logs = []
    for record in records:
        log = NormalizedLog(
            upload_id=upload_id,
            timestamp=record.get("timestamp"),
            event_id=record.get("event_id"),
            event_name=record.get("event_name"),
            event_category=record.get("event_category"),
            src_user=record.get("src_user"),
            dst_user=record.get("dst_user"),
            src_hostname=record.get("src_hostname"),
            dst_hostname=record.get("dst_hostname"),
            src_ip=record.get("src_ip"),
            dst_ip=record.get("dst_ip"),
            src_port=record.get("src_port"),
            dst_port=record.get("dst_port"),
            protocol=record.get("protocol"),
            application=record.get("application"),
            flow_direction=record.get("flow_direction"),
            threat_category=record.get("threat_category"),
            severity=record.get("severity"),
            bytes_sent=record.get("bytes_sent"),
            bytes_received=record.get("bytes_received"),
            extra_attributes=record.get("extra_attributes", {})
        )
        normalized_logs.append(log)
    
    db.add_all(normalized_logs)
    db.commit()

def store_incident(db: Session, incident_name: str, severity: str, description: str, related_log_ids: List[int]) -> Incident:
    """Stores an incident representing a correlation outcome."""
    incident = Incident(
        incident_name=incident_name,
        severity=severity,
        description=description,
        related_log_ids=related_log_ids,
        status="open"
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident

def get_dashboard_stats(db: Session) -> Dict[str, Any]:
    """Generates analytical queries for the dashboard."""
    total_logs = db.query(func.count(NormalizedLog.id)).scalar()
    total_incidents = db.query(func.count(Incident.id)).scalar()
    
    # Top Source IPs
    top_src_ips = (
        db.query(NormalizedLog.src_ip, func.count(NormalizedLog.id).label("count"))
        .filter(NormalizedLog.src_ip != None)
        .group_by(NormalizedLog.src_ip)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    
    # Top Destination IPs
    top_dst_ips = (
        db.query(NormalizedLog.dst_ip, func.count(NormalizedLog.id).label("count"))
        .filter(NormalizedLog.dst_ip != None)
        .group_by(NormalizedLog.dst_ip)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    
    # Category Distribution
    category_dist = (
        db.query(NormalizedLog.event_category, func.count(NormalizedLog.id).label("count"))
        .filter(NormalizedLog.event_category != None)
        .group_by(NormalizedLog.event_category)
        .all()
    )
    
    # Severity Distribution
    severity_dist = (
        db.query(NormalizedLog.severity, func.count(NormalizedLog.id).label("count"))
        .filter(NormalizedLog.severity != None)
        .group_by(NormalizedLog.severity)
        .all()
    )
    
    return {
        "total_logs": total_logs,
        "total_incidents": total_incidents,
        "average_risk_score": 0.0,
        "top_source_ips": [{"ip": row[0], "count": row[1]} for row in top_src_ips],
        "top_destination_ips": [{"ip": row[0], "count": row[1]} for row in top_dst_ips],
        "category_distribution": [{"category": row[0], "count": row[1]} for row in category_dist],
        "severity_distribution": [{"severity": row[0], "count": row[1]} for row in severity_dist],
    }
