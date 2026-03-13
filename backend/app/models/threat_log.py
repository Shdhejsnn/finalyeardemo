from sqlalchemy import Boolean, Column, Integer, String, Float, DateTime, Text
from datetime import datetime

from app.core.database import Base


class ThreatLog(Base):
    """
    Stores threat detection events.
    """

    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)

    url = Column(String, nullable=False)

    decision = Column(String)

    risk_score = Column(Float)

    severity = Column(Integer)

    summary = Column(String, nullable=True)

    reasons_json = Column(Text, nullable=True)

    source = Column(String, nullable=True)

    form_detected = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
