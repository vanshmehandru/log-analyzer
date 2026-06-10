import os
import json
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from database import SessionLocal
from models.normalized_logs import NormalizedLog
from models.incidents import Incident
from models.incident_evidence import IncidentEvidence

# Import rule detectors
from correlation.brute_force import detect_brute_force
from correlation.port_scan import detect_port_scan
from correlation.lateral_movement import detect_lateral_movement

RULES_FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "config",
    "correlation_rules.json"
)

def load_rules_config() -> Dict[str, Any]:
    """Loads correlation rules from correlation_rules.json."""
    if os.path.exists(RULES_FILE_PATH):
        try:
            with open(RULES_FILE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading correlation rules: {e}")
    # Return default config if file is missing or corrupt
    return {
        "brute_force": {"enabled": True, "threshold": 5, "window_minutes": 5},
        "port_scan": {"enabled": True, "threshold": 10, "window_seconds": 30},
        "lateral_movement": {"enabled": True, "threshold": 3, "window_minutes": 10}
    }

def run_correlation(db: Session, upload_id: Optional[int] = None) -> List[Incident]:
    """Runs all enabled correlation rules against normalized logs.
    
    If upload_id is provided, correlation targets logs from that upload.
    Otherwise, it runs against all normalized logs in the database.
    """
    rules_config = load_rules_config()
    
    # 1. Fetch normalized logs from database
    query = db.query(NormalizedLog)
    if upload_id is not None:
        query = query.filter(NormalizedLog.upload_id == upload_id)
        
    logs = query.all()
    if not logs:
        return []
        
    # 2. Run detectors
    potential_incidents = []
    
    potential_incidents.extend(detect_brute_force(logs, rules_config))
    potential_incidents.extend(detect_port_scan(logs, rules_config))
    potential_incidents.extend(detect_lateral_movement(logs, rules_config))
    
    created_incidents = []
    
    # 3. Store new incidents and create evidence links
    for item in potential_incidents:
        # Check if an identical incident already exists (based on description)
        existing = db.query(Incident).filter(Incident.description == item["description"]).first()
        if existing:
            continue
            
        # Create Incident record
        incident = Incident(
            incident_name=item["incident_name"],
            severity=item["severity"],
            description=item["description"],
            related_log_ids=item["related_log_ids"],
            status="open"
        )
        db.add(incident)
        db.flush()  # Populates incident.id
        
        # Create IncidentEvidence links
        for log_id in item["related_log_ids"]:
            evidence = IncidentEvidence(
                incident_id=incident.id,
                normalized_log_id=log_id
            )
            db.add(evidence)
            
        db.commit()
        db.refresh(incident)
        created_incidents.append(incident)
        
    return created_incidents
