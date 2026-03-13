from typing import Dict


class DecisionEngine:
    """
    Combines agent outputs and determines final action.
    """

    def make_decision(self, risk_score: float, intel: Dict) -> Dict:
        """
        Determine final security decision.

        Returns:
            dict containing decision and severity
        """

        severity = self._calculate_severity(intel)

        if severity >= 4 or risk_score >= 0.75:
            decision = "BLOCK"

        elif severity >= 2 or risk_score >= 0.45:
            decision = "CHALLENGE"

        else:
            decision = "ALLOW"

        return {
            "decision": decision,
            "risk_score": risk_score,
            "severity": severity
        }

    def _calculate_severity(self, intel: Dict) -> int:
        """
        Calculate severity score from threat indicators.
        """

        severity = 0

        if intel["brand_impersonation"]:
            severity += 2

        if intel["typosquatting"]:
            severity += 2

        severity += intel["suspicious_domain_words"]

        if intel["domain_similarity"]["possible_typosquat"]:
            severity += 2

        return severity
