from datetime import datetime, timedelta
from typing import List, Dict, Any
from models.normalized_logs import NormalizedLog

def parse_log_timestamp(ts_str: str) -> datetime:
    """Helper to parse raw log timestamp strings into datetime objects."""
    if not ts_str:
        return datetime.utcnow()
    
    # Try common formats
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%H:%M:%S", "%H:%M"):
        try:
            parsed = datetime.strptime(ts_str.strip(), fmt)
            if fmt in ("%H:%M:%S", "%H:%M"):
                # Use today's date for relative time strings
                today = datetime.utcnow().date()
                parsed = datetime.combine(today, parsed.time())
            return parsed
        except ValueError:
            continue
            
    # Try ISO-8601 fallback
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        pass
        
    return datetime.utcnow()

def detect_brute_force(logs: List[NormalizedLog], rules_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detects brute force login attempts from normalized logs.
    
    Rule Criteria:
    - Event category: 'Authentication'
    - Outcome: 'Failure' or event name contains keywords like 'fail', 'denied', 'failure'
    - Threshold: 5+ failed logins for the same username within 5 minutes.
    """
    config = rules_config.get("brute_force", {})
    if not config.get("enabled", True):
        return []
        
    threshold = config.get("threshold", 5)
    window_minutes = config.get("window_minutes", 5)
    
    # 1. Filter failed authentication logs with username
    failed_auth_logs = []
    for log in logs:
        # Check event category
        is_auth = log.event_category == "Authentication"
        
        # Check outcome or name
        is_failure = False
        if log.outcome:
            is_failure = log.outcome.strip().lower() == "failure"
        elif log.event_name:
            name_lower = log.event_name.lower()
            is_failure = any(kw in name_lower for kw in ["fail", "denied", "failure"])
            
        if is_auth and is_failure and log.username:
            failed_auth_logs.append(log)
            
    if not failed_auth_logs:
        return []
        
    # 2. Group by username
    grouped_logs: Dict[str, List[NormalizedLog]] = {}
    for log in failed_auth_logs:
        grouped_logs.setdefault(log.username, []).append(log)
        
    incidents = []
    
    # 3. Apply sliding window detection per username
    for username, user_logs in grouped_logs.items():
        # Sort logs chronologically
        sorted_logs = sorted(user_logs, key=lambda l: parse_log_timestamp(l.timestamp))
        
        n_logs = len(sorted_logs)
        i = 0
        while i < n_logs:
            start_log = sorted_logs[i]
            start_time = parse_log_timestamp(start_log.timestamp)
            end_time = start_time + timedelta(minutes=window_minutes)
            
            # Find all logs within the window starting from index i
            window_logs = []
            j = i
            while j < n_logs and parse_log_timestamp(sorted_logs[j].timestamp) <= end_time:
                window_logs.append(sorted_logs[j])
                j += 1
                
            if len(window_logs) >= threshold:
                log_ids = [l.id for l in window_logs if l.id is not None]
                src_ips = list({l.src_ip for l in window_logs if l.src_ip})
                ip_str = f" from source IPs: {', '.join(src_ips)}" if src_ips else ""
                
                incidents.append({
                    "incident_name": "Brute Force Attack",
                    "severity": "High",
                    "description": f"Detected {len(window_logs)} failed login attempts for user '{username}'{ip_str} within {window_minutes} minutes.",
                    "related_log_ids": log_ids
                })
                
                # Advance index past this window
                i = j
            else:
                i += 1
                
    return incidents
