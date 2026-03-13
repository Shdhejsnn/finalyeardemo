import json

from sqlalchemy.orm import Session

from app.models.threat_log import ThreatLog


class LogService:

    def log_event(
        self,
        db: Session,
        url: str,
        decision: dict,
        source: str = "extension",
        form_detected: bool = False,
    ):

        threat = ThreatLog(
            url=url,
            decision=decision["decision"],
            risk_score=decision["risk_score"],
            severity=decision["severity"],
            summary=decision.get("summary"),
            reasons_json=json.dumps(decision.get("reasons", [])),
            source=source,
            form_detected=form_detected,
        )

        db.add(threat)
        db.commit()
        db.refresh(threat)

        return threat
