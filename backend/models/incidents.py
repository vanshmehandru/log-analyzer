from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
from database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    incident_name = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    description = Column(String, nullable=True)
    
    # Store related NormalizedLog IDs that triggered this incident
    related_log_ids = Column(ARRAY(Integer), default=list)
    
    status = Column(String, default="open", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
