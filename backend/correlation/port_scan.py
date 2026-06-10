from datetime import datetime, timedelta
from typing import List, Dict, Any
from models.normalized_logs import NormalizedLog
from correlation.brute_force import parse_log_timestamp

def detect_port_scan(logs: List[NormalizedLog], rules_config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detects port scanning or network scanning behavior.
    
    Rule Criteria:
    - Event category: 'Reconnaissance' or 'Network' (or has a dst_port)
    - Threshold: N connections or unique ports from the same src_ip within W seconds.
    """
    config = rules_config.get("port_scan", {})
    if not config.get("enabled", True):
        return []
        
    threshold = config.get("threshold", 10)
    window_seconds = config.get("window_seconds", 30)
    
    # 1. Filter networking/recon logs
    network_logs = []
    for log in logs:
        is_net = log.event_category in ("Reconnaissance", "Network")
        has_port = log.dst_port is not None
        is_scan = log.event_name and any(kw in log.event_name.lower() for kw in ["scan", "ping"])
        
        if (is_net or has_port or is_scan) and log.src_ip:
            network_logs.append(log)
            
    if not network_logs:
        return []
        
    # 2. Group by src_ip
    grouped_logs: Dict[str, List[NormalizedLog]] = {}
    for log in network_logs:
        grouped_logs.setdefault(log.src_ip, []).append(log)
        
    incidents = []
    
    # 3. Apply sliding window detection per src_ip
    for src_ip, ip_logs in grouped_logs.items():
        sorted_logs = sorted(ip_logs, key=lambda l: parse_log_timestamp(l.timestamp))
        
        n_logs = len(sorted_logs)
        i = 0
        while i < n_logs:
            start_log = sorted_logs[i]
            start_time = parse_log_timestamp(start_log.timestamp)
            end_time = start_time + timedelta(seconds=window_seconds)
            
            # Find all logs within the window
            window_logs = []
            j = i
            while j < n_logs and parse_log_timestamp(sorted_logs[j].timestamp) <= end_time:
                window_logs.append(sorted_logs[j])
                j += 1
                
            # Collect unique ports and destination IPs targeted
            unique_ports = {l.dst_port for l in window_logs if l.dst_port is not None}
            unique_dsts = {l.dst_ip for l in window_logs if l.dst_ip}
            
            # Trigger alert if total connections OR unique ports/IPs exceed threshold
            # Usually, unique ports is the best indicator of a port scan
            target_metric = max(len(window_logs), len(unique_ports), len(unique_dsts))
            
            if target_metric >= threshold:
                log_ids = [l.id for l in window_logs if l.id is not None]
                desc = (
                    f"Detected network scan from source IP {src_ip} targeting {len(unique_dsts)} IPs "
                    f"and {len(unique_ports)} unique ports with {len(window_logs)} connection attempts "
                    f"within {window_seconds} seconds."
                )
                
                incidents.append({
                    "incident_name": "Port Scan / Reconnaissance",
                    "severity": "Medium",
                    "description": desc,
                    "related_log_ids": log_ids
                })
                
                # Move window forward
                i = j
            else:
                i += 1
                
    return incidents
