from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from database import Base

class NormalizedLog(Base):
    __tablename__ = "normalized_logs"

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    
    timestamp = Column(String, index=True, nullable=True)
    event_name = Column(String, index=True, nullable=True)
    event_category = Column(String, index=True, nullable=True)
    event_id = Column(String, index=True, nullable=True)
    action = Column(String, index=True, nullable=True)
    
    username = Column(String, index=True, nullable=True)
    hostname = Column(String, index=True, nullable=True)
    
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    src_port = Column(Integer, index=True, nullable=True)
    dst_port = Column(Integer, index=True, nullable=True)
    
    protocol = Column(String, index=True, nullable=True)
    application = Column(String, index=True, nullable=True)
    process_name = Column(String, index=True, nullable=True)
    
    domain = Column(String, index=True, nullable=True)
    dns_query = Column(String, index=True, nullable=True)
    
    severity = Column(String, index=True, nullable=True)
    risk_score = Column(Float, index=True, nullable=True)
    outcome = Column(String, index=True, nullable=True)
    
    bytes = Column(Integer, nullable=True)
    packet_count = Column(Integer, nullable=True)
    duration = Column(Float, nullable=True)
    
    extra_attributes = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
