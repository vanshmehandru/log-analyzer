from sqlalchemy.orm import Session
from typing import List, Dict, Any
from models.incident_evidence import IncidentEvidence
from models.normalized_logs import NormalizedLog
from correlation.brute_force import parse_log_timestamp

def build_incident_timeline(db: Session, incident_id: int) -> List[Dict[str, Any]]:
    """Gathers all logs related to an incident and orders them chronologically to build a sequence of events."""
    # 1. Fetch normalized log IDs linked as evidence
    evidence_ids = (
        db.query(IncidentEvidence.normalized_log_id)
        .filter(IncidentEvidence.incident_id == incident_id)
        .all()
    )
    log_ids = [row[0] for row in evidence_ids]
    
    if not log_ids:
        return []
        
    # 2. Fetch the actual logs
    logs = (
        db.query(NormalizedLog)
        .filter(NormalizedLog.id.in_(log_ids))
        .all()
    )
    
    # 3. Sort chronologically
    sorted_logs = sorted(logs, key=lambda l: parse_log_timestamp(l.timestamp))
    
    # 4. Format the timeline
    timeline = []
    for idx, log in enumerate(sorted_logs, 1):
        timeline.append({
            "step": idx,
            "log_id": log.id,
            "timestamp": log.timestamp,
            "event_name": log.event_name,
            "event_category": log.event_category,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "username": log.username,
            "hostname": log.hostname,
            "outcome": log.outcome,
            "process_name": log.process_name,
            "domain": log.domain,
            "dns_query": log.dns_query,
            "severity": log.severity,
            "risk_score": log.risk_score
        })
        
    return timeline
