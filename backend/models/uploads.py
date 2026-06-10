from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from database import Base

class Upload(Base):
    __tablename__ = "uploads"

    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, nullable=False)
    upload_time = Column(DateTime, default=datetime.utcnow)
    total_records = Column(Integer, default=0)
    log_source = Column(String, nullable=True)
    status = Column(String, default="pending")
