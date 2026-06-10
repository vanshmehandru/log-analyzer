from sqlalchemy import Column, Integer, String, ForeignKey
from database import Base

class HeaderMapping(Base):
    __tablename__ = "header_mappings"

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    original_header = Column(String, nullable=False)
    normalized_header = Column(String, nullable=False)
