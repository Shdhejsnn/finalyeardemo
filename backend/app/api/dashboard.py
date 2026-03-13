import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.dependencies import get_db
from app.models.threat_log import ThreatLog

router = APIRouter()


def _serialize_threat(threat: ThreatLog) -> dict:
    reasons = []
    if threat.reasons_json:
        try:
            reasons = json.loads(threat.reasons_json)
        except json.JSONDecodeError:
            reasons = []

    return {
        "id": threat.id,
        "url": threat.url,
        "decision": threat.decision,
        "risk_score": threat.risk_score,
        "severity": threat.severity,
        "summary": threat.summary,
        "reasons": reasons,
        "source": threat.source,
        "form_detected": threat.form_detected,
        "created_at": threat.created_at,
    }


@router.get("/threats")
def get_threats(db: Session = Depends(get_db)):
    """
    Return recent threat events
    """

    threats = db.query(ThreatLog).order_by(
        ThreatLog.created_at.desc()
    ).limit(50).all()

    return [_serialize_threat(threat) for threat in threats]


@router.get("/threat-stats")
def get_threat_stats(db: Session = Depends(get_db)):
    """
    Return threat statistics
    """

    total = db.query(func.count(ThreatLog.id)).scalar()

    blocked = db.query(func.count(ThreatLog.id)).filter(
        ThreatLog.decision == "BLOCK"
    ).scalar()

    challenged = db.query(func.count(ThreatLog.id)).filter(
        ThreatLog.decision == "CHALLENGE"
    ).scalar()

    allowed = db.query(func.count(ThreatLog.id)).filter(
        ThreatLog.decision == "ALLOW"
    ).scalar()

    return {
        "total_events": total,
        "blocked": blocked,
        "challenged": challenged,
        "allowed": allowed,
        "average_risk": db.query(func.avg(ThreatLog.risk_score)).scalar() or 0,
    }


@router.get("/blocked-sites")
def get_blocked_sites(db: Session = Depends(get_db)):
    """
    Return list of blocked phishing domains
    """

    blocked = db.query(ThreatLog).filter(
        ThreatLog.decision == "BLOCK"
    ).order_by(
        ThreatLog.created_at.desc()
    ).limit(50).all()

    return [_serialize_threat(threat) for threat in blocked]


@router.get("/dashboard/overview")
def get_dashboard_overview(db: Session = Depends(get_db)):
    recent_events = db.query(ThreatLog).order_by(
        ThreatLog.created_at.desc()
    ).limit(12).all()

    decision_breakdown = db.query(
        ThreatLog.decision,
        func.count(ThreatLog.id)
    ).group_by(ThreatLog.decision).all()

    return {
        "stats": get_threat_stats(db),
        "recent_events": [_serialize_threat(threat) for threat in recent_events],
        "decision_breakdown": [
            {"decision": decision, "count": count}
            for decision, count in decision_breakdown
        ],
    }
