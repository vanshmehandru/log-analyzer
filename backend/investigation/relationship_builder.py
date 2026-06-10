from sqlalchemy.orm import Session
from typing import Dict, List, Set, Any
from models.incident_evidence import IncidentEvidence
from models.normalized_logs import NormalizedLog

def build_incident_graph(db: Session, incident_id: int) -> Dict[str, Any]:
    """Generates a graph of nodes and edges mapping entity relationships from incident evidence.
    
    Entities: User, Host, Source IP, Destination IP, Domain.
    Relations: auth_from, accessed, connected_to, queried_dns.
    """
    evidence_ids = (
        db.query(IncidentEvidence.normalized_log_id)
        .filter(IncidentEvidence.incident_id == incident_id)
        .all()
    )
    log_ids = [row[0] for row in evidence_ids]
    
    if not log_ids:
        return {"nodes": [], "edges": []}
        
    logs = (
        db.query(NormalizedLog)
        .filter(NormalizedLog.id.in_(log_ids))
        .all()
    )
    
    nodes: Dict[str, Dict[str, str]] = {}
    edges: Set[tuple] = set()
    
    def add_node(node_id: str, label: str, node_type: str):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type
            }
            
    for log in logs:
        # 1. Extracted Entities
        user_node = f"user:{log.username}" if log.username else None
        host_node = f"host:{log.hostname}" if log.hostname else None
        src_ip_node = f"ip:{log.src_ip}" if log.src_ip else None
        dst_ip_node = f"ip:{log.dst_ip}" if log.dst_ip else None
        domain_node = f"domain:{log.domain or log.dns_query}" if (log.domain or log.dns_query) else None
        
        # 2. Add Nodes
        if user_node:
            add_node(user_node, log.username, "user")
        if host_node:
            add_node(host_node, log.hostname, "host")
        if src_ip_node:
            add_node(src_ip_node, log.src_ip, "ip")
        if dst_ip_node:
            add_node(dst_ip_node, log.dst_ip, "ip")
        if domain_node:
            label = log.domain if log.domain else log.dns_query
            add_node(domain_node, label, "domain")
            
        # 3. Add Edges/Relations
        if user_node and src_ip_node:
            edges.add((user_node, src_ip_node, "logged_in_from"))
            
        if user_node and host_node:
            edges.add((user_node, host_node, "accessed"))
            
        if src_ip_node and host_node:
            edges.add((src_ip_node, host_node, "associated_with"))
            
        if src_ip_node and dst_ip_node:
            relation = "connected_to"
            if log.event_category == "Reconnaissance":
                relation = "scanned"
            edges.add((src_ip_node, dst_ip_node, relation))
            
        if src_ip_node and domain_node:
            edges.add((src_ip_node, domain_node, "queried_dns"))
            
        if dst_ip_node and domain_node:
            edges.add((dst_ip_node, domain_node, "resolves_to"))
            
    formatted_edges = [
        {"source": edge[0], "target": edge[1], "relation": edge[2]}
        for edge in edges
    ]
    
    return {
        "nodes": list(nodes.values()),
        "edges": formatted_edges
    }
