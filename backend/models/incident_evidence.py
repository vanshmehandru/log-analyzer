from sqlalchemy import Column, Integer, ForeignKey
from database import Base

class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    normalized_log_id = Column(Integer, ForeignKey("normalized_logs.id", ondelete="CASCADE"), nullable=False, index=True)
