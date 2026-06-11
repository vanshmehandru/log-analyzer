from datetime import datetime, timedelta
from typing import List, Dict, Any
from models.normalized_logs import NormalizedLog
from correlation.brute_force import parse_log_timestamp

def detect_lateral_movement(logs: List[NormalizedLog], rules_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detects lateral movement patterns.
    
    Rule Criteria:
    - Event category: 'Authentication' (or network logs with successful outcome)
    - Outcome: 'Success' or event name contains 'success', 'accepted'
    - Threshold: Successfully accessing N unique destination IPs/hostnames 
      from the same username (or src_ip) within W minutes.
    """
    config = rules_config.get("lateral_movement", {})
    if not config.get("enabled", True):
        return []
        
    threshold = config.get("threshold", 3)
    window_minutes = config.get("window_minutes", 10)
    
    # 1. Filter successful authentications or connections
    success_logs = []
    for log in logs:
        is_auth = log.event_category == "Authentication"
        
        is_success = False
        if log.extra_attributes and log.extra_attributes.get("outcome"):
            is_success = str(log.extra_attributes.get("outcome")).strip().lower() == "success"
        elif log.event_name:
            name_lower = log.event_name.lower()
            is_success = any(kw in name_lower for kw in ["success", "accepted", "allowed"])
            
        if (is_auth or log.event_category == "Network") and is_success:
            # Must have src_user or src_ip as actor, and dst_ip or dst_hostname as target
            actor = log.src_user or log.src_ip
            target = log.dst_ip or log.dst_hostname
            if actor and target:
                log._actor = actor
                success_logs.append(log)
                
    if not success_logs:
        return []
        
    # 2. Group by actor
    grouped_logs: Dict[str, List[NormalizedLog]] = {}
    for log in success_logs:
        actor = log._actor
        if actor == log.src_ip and not log.src_user:
            actor = f"IP:{actor}"
        grouped_logs.setdefault(actor, []).append(log)
        
    incidents = []
    
    # 3. Apply sliding window detection per actor
    for actor, actor_logs in grouped_logs.items():
        sorted_logs = sorted(actor_logs, key=lambda l: parse_log_timestamp(l.timestamp))
        
        n_logs = len(sorted_logs)
        i = 0
        while i < n_logs:
            start_log = sorted_logs[i]
            start_time = parse_log_timestamp(start_log.timestamp)
            end_time = start_time + timedelta(minutes=window_minutes)
            
            # Find all logs within the window
            window_logs = []
            j = i
            while j < n_logs and parse_log_timestamp(sorted_logs[j].timestamp) <= end_time:
                window_logs.append(sorted_logs[j])
                j += 1
                
            # Count unique destinations
            unique_dsts = set()
            for l in window_logs:
                if l.dst_ip:
                    unique_dsts.add(l.dst_ip)
                if l.dst_hostname:
                    unique_dsts.add(l.dst_hostname)
                    
            if len(unique_dsts) >= threshold:
                log_ids = [l.id for l in window_logs if l.id is not None]
                desc = (
                    f"Actor '{actor}' demonstrated potential lateral movement by successfully authenticating "
                    f"or connecting to {len(unique_dsts)} unique destination hosts ({', '.join(unique_dsts)}) "
                    f"within {window_minutes} minutes."
                )
                
                incidents.append({
                    "incident_name": "Lateral Movement Detected",
                    "severity": "Critical",
                    "description": desc,
                    "related_log_ids": log_ids
                })
                
                i = j
            else:
                i += 1
                
    return incidents
