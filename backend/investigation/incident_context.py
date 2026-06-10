from sqlalchemy.orm import Session
from typing import Dict, Any, List
from models.incidents import Incident
from models.incident_evidence import IncidentEvidence
from models.normalized_logs import NormalizedLog

def get_incident_context(db: Session, incident_id: int) -> Dict[str, Any]:
    """Assembles all investigation context for an incident.
    
    Includes severity, statistics, affected user list, targeted devices, and standard mitigation recommendations.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return {"error": "Incident not found"}
        
    evidence_ids = (
        db.query(IncidentEvidence.normalized_log_id)
        .filter(IncidentEvidence.incident_id == incident_id)
        .all()
    )
    log_ids = [row[0] for row in evidence_ids]
    
    if not log_ids:
        logs = []
    else:
        logs = db.query(NormalizedLog).filter(NormalizedLog.id.in_(log_ids)).all()
        
    # Aggregate context metrics
    users = list({log.username for log in logs if log.username})
    hosts = list({log.hostname for log in logs if log.hostname})
    src_ips = list({log.src_ip for log in logs if log.src_ip})
    dst_ips = list({log.dst_ip for log in logs if log.dst_ip})
    domains = list({log.domain for log in logs if log.domain} | {log.dns_query for log in logs if log.dns_query})
    domains = [d for d in domains if d]
    
    # Simple recommendation engine based on severity/incident name
    recommendations = []
    if "Brute Force" in incident.incident_name:
        recommendations = [
            "Temporary block the offending source IP address at the firewall/gateway.",
            "Enforce MFA or trigger a password reset for affected user accounts.",
            "Verify if any login attempts within the timeframe were successful."
        ]
    elif "Port Scan" in incident.incident_name:
        recommendations = [
            "Monitor destination hosts for subsequent exploit attempts or connection drops.",
            "Verify firewall ACL configurations to ensure unnecessary ports are fully blocked.",
            "Ensure IDS/IPS policies are actively dropping scan traffic from the source IP."
        ]
    elif "Lateral Movement" in incident.incident_name:
        recommendations = [
            "Isolate the originating system/host immediately from the internal network.",
            "Audit all credentials logged in on the source host and revoke sessions.",
            "Analyze system logs (event logs/bash history) on affected targets for process executions."
        ]
    else:
        recommendations = [
            "Review associated normalized events to evaluate true positive status.",
            "Trace network connection origins and cross-reference with known assets."
        ]
        
    return {
        "incident_id": incident.id,
        "incident_name": incident.incident_name,
        "severity": incident.severity,
        "description": incident.description,
        "status": incident.status,
        "created_at": incident.created_at,
        "metrics": {
            "evidence_count": len(logs),
            "unique_users_count": len(users),
            "unique_hosts_count": len(hosts),
            "unique_source_ips_count": len(src_ips),
            "unique_destination_ips_count": len(dst_ips)
        },
        "affected_entities": {
            "users": users,
            "hosts": hosts,
            "source_ips": src_ips,
            "destination_ips": dst_ips,
            "domains": domains
        },
        "recommendations": recommendations
    }
