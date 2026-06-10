import os
import sys
import pandas as pd
from datetime import datetime, timedelta

# Adjust path to import backend modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import engine, SessionLocal, initialize_database
from models import Base
from models.uploads import Upload
from models.raw_logs import RawLog
from models.normalized_logs import NormalizedLog
from models.incidents import Incident
from models.incident_evidence import IncidentEvidence

# Import services & engines
from services.categorizer import categorize_event, categorize_dataframe
from correlation.engine import run_correlation
from analytics.timeline import get_log_timeline
from analytics.top_sources import get_top_sources
from investigation.timeline_builder import build_incident_timeline
from investigation.relationship_builder import build_incident_graph
from investigation.incident_context import get_incident_context

def run_verification():
    print("==================================================")
    print("RUNNING NORMALIZATION & CORRELATION INTEGRATION TESTS")
    print("==================================================")
    
    # 1. Initialize DB and recreate schema for test cleanliness
    print("\n[+] Initializing database tables...")
    initialize_database()
    
    db = SessionLocal()
    try:
        # Clear existing logs for a clean test run
        db.query(IncidentEvidence).delete()
        db.query(Incident).delete()
        db.query(NormalizedLog).delete()
        db.query(RawLog).delete()
        db.query(Upload).delete()
        db.commit()
        print("    Database cleared for testing.")

        # 2. Test Categorizer
        print("\n[+] Testing Categorizer service...")
        test_cases = [
            ("login failed", "Authentication"),
            ("login success", "Authentication"),
            ("dns query", "DNS"),
            ("port scan", "Reconnaissance"),
            ("connection established", "Network"),
            ("malware detected", "Malware"),
            ("random event name", "Other")
        ]
        for name, expected in test_cases:
            cat = categorize_event(name)
            print(f"    '{name}' -> '{cat}' (expected: '{expected}')")
            assert cat == expected, f"Failed categorization for '{name}': got '{cat}'"
        print("    Categorizer passed!")

        # 3. Create simulated file upload record
        print("\n[+] Creating mock upload and normalized logs...")
        upload = Upload(file_name="simulated_threats.csv", status="processing")
        db.add(upload)
        db.commit()
        db.refresh(upload)
        
        base_time = datetime.utcnow()
        logs_to_insert = []
        
        # Scenario A: Brute Force from IP 192.168.10.10 (5 failed login events)
        for i in range(6):
            ts = (base_time + timedelta(minutes=i)).isoformat()
            log = NormalizedLog(
                upload_id=upload.id,
                timestamp=ts,
                event_name="Login Failed",
                event_category="Authentication",
                username="admin",
                src_ip="192.168.10.10",
                dst_ip="10.0.0.5",
                outcome="Failure",
                risk_score=7.0 + i
            )
            logs_to_insert.append(log)
            
        # Scenario B: Port Scan from IP 192.168.10.11 (12 connection attempts within 20 seconds)
        for i in range(12):
            ts = (base_time + timedelta(seconds=i)).isoformat()
            log = NormalizedLog(
                upload_id=upload.id,
                timestamp=ts,
                event_name="Connection Terminated",
                event_category="Network",
                src_ip="192.168.10.11",
                dst_ip="10.0.0.1",
                dst_port=80 + i,
                outcome="Failure",
                risk_score=4.0
            )
            logs_to_insert.append(log)

        # Scenario C: Lateral Movement by user 'attacker_user'
        # Log 1: Success login to system-1
        # Log 2: Success login to system-2
        # Log 3: Success login to system-3
        # Log 4: Success login to system-4
        target_systems = ["system-1", "system-2", "system-3", "system-4"]
        for idx, target in enumerate(target_systems):
            ts = (base_time + timedelta(minutes=idx)).isoformat()
            log = NormalizedLog(
                upload_id=upload.id,
                timestamp=ts,
                event_name="login success",
                event_category="Authentication",
                username="attacker_user",
                src_ip="192.168.10.12",
                dst_ip=f"10.0.0.1{idx}",
                hostname=target,
                outcome="Success",
                risk_score=8.0
            )
            logs_to_insert.append(log)
            
        db.add_all(logs_to_insert)
        db.commit()
        
        # Update upload count
        upload.total_records = len(logs_to_insert)
        upload.status = "completed"
        db.commit()
        print(f"    Inserted {len(logs_to_insert)} mock logs.")

        # 4. Run Correlation Engine
        print("\n[+] Triggering Correlation Engine...")
        new_incidents = run_correlation(db, upload_id=upload.id)
        print(f"    Correlation engine finished. Generated {len(new_incidents)} incidents.")
        
        # We expect 3 incidents (Brute Force, Port Scan, Lateral Movement)
        assert len(new_incidents) == 3, f"Expected 3 incidents, but got {len(new_incidents)}"
        
        names = [inc.incident_name for inc in new_incidents]
        print(f"    Generated Incidents: {names}")
        assert "Brute Force Attack" in names
        assert "Port Scan / Reconnaissance" in names
        assert "Lateral Movement Detected" in names
        
        # 5. Verify Incident Evidence Join Table
        print("\n[+] Verifying Incident Evidence linking...")
        for incident in new_incidents:
            evidence_count = db.query(IncidentEvidence).filter(IncidentEvidence.incident_id == incident.id).count()
            print(f"    Incident '{incident.incident_name}' linked to {evidence_count} evidence logs.")
            assert evidence_count > 0, f"No evidence linked for incident {incident.incident_name}"
            
        # 6. Test Analytics Module queries
        print("\n[+] Verifying separated analytics query outputs...")
        timeline = get_log_timeline(db, upload_id=upload.id)
        print(f"    Timeline buckets count: {len(timeline)}")
        assert len(timeline) > 0
        
        top_src = get_top_sources(db, limit=5, upload_id=upload.id)
        print(f"    Top Sources aggregated: {top_src}")
        assert len(top_src) > 0
        
        # 7. Test Investigation Module builders
        print("\n[+] Testing Investigation builders (context, timeline, graph)...")
        test_incident = new_incidents[0]
        
        # Timeline builder
        incident_timeline = build_incident_timeline(db, incident_id=test_incident.id)
        print(f"    Timeline builder step count: {len(incident_timeline)}")
        assert len(incident_timeline) > 0
        
        # Graph builder
        incident_graph = build_incident_graph(db, incident_id=test_incident.id)
        print(f"    Graph nodes: {[n['id'] for n in incident_graph['nodes']]}")
        print(f"    Graph edges count: {len(incident_graph['edges'])}")
        assert len(incident_graph["nodes"]) > 0
        
        # Context builder
        incident_context = get_incident_context(db, incident_id=test_incident.id)
        print(f"    Context recommendation count: {len(incident_context['recommendations'])}")
        assert len(incident_context["recommendations"]) > 0
        
        print("\n==================================================")
        print("SUCCESS: ALL CORRELATION AND INTEGRATION TESTS PASSED!")
        print("==================================================")
        
    finally:
        db.close()

if __name__ == "__main__":
    run_verification()
