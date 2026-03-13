import logging
from urllib.parse import urlparse

from app.agents.monitoring_agent import MonitoringAgent
from app.agents.behavior_agent import BehaviorAgent
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.core.decision_engine import DecisionEngine
from app.ml.model_loader import get_model
from app.utils.anomaly_detector import AnomalyDetector
from app.utils.domain_age_detector import DomainAgeDetector
from app.utils.geoip_detector import GeoIPDetector


LOGGER = logging.getLogger(__name__)


class AnalysisService:
    """
    Coordinates all agents to analyze a URL.
    """

    def __init__(self):

        # Initialize detection agents
        self.monitor = MonitoringAgent()
        self.behavior = BehaviorAgent()
        self.threat = ThreatIntelAgent()
        self.decision_engine = DecisionEngine()

        # ML anomaly detector
        self.anomaly_detector = AnomalyDetector()
        self.geoip_detector = GeoIPDetector()
        self.domain_age_detector = DomainAgeDetector()
        self.ml_model = None

    def analyze_url(
        self,
        url: str,
        form_detected: bool = False,
        page_flags: list[str] | None = None,
    ):
        """
        Full URL analysis pipeline.
        """
        page_flags = page_flags or []

        if self._is_local_development_url(url):
            return {
                "decision": "ALLOW",
                "risk_score": 0.0,
                "severity": 0,
                "summary": "Local development traffic was allowed automatically.",
                "reasons": [
                    "The URL targets localhost or a private development address on a currently used local port."
                ],
                "captcha_required": False,
            }

        # Step 1: Extract features
        features = self.monitor.extract_features(url)
        # Step 2: Behavioral risk score
        risk_score = self.behavior.calculate_risk_score(features)

        # Step 3: Threat intelligence analysis
        intel = self.threat.analyze_domain(features["domain"])

        # Step 4: ML anomaly detection
        anomaly_detected = self.anomaly_detector.predict(features)

        if anomaly_detected:
            # Increase risk if anomaly detected
            risk_score += 0.2

        # Step 5: Supervised phishing model contribution
        ml_score = self._predict_ml_score(url)
        ml_score = self._calibrate_ml_score(ml_score, features, intel)
        risk_score += ml_score * 0.25

        # Step 6: GeoIP risk for direct-IP URLs
        geoip_result = self.geoip_detector.analyze_url(url)
        risk_score += float(geoip_result["risk"])

        # Step 7: Domain age signal
        domain_age = self.domain_age_detector.analyze_domain(features["registered_domain"])
        risk_score += float(domain_age["risk"])

        # Step 8: Page-level suspicious content signals from the extension
        risk_score += self._score_page_flags(page_flags, form_detected)
        risk_score += self._score_suspicious_subdomain(features)

        risk_score = self._apply_benign_structure_discount(
            risk_score, features, intel, ml_score, page_flags
        )

        risk_score = min(round(risk_score, 3), 1.0)

        # Step 9: Final decision
        decision = self.decision_engine.make_decision(risk_score, intel)

        if domain_age.get("age_days") is not None and domain_age["age_days"] <= 15:
            decision["decision"] = "BLOCK"
            decision["severity"] = max(decision["severity"], 4)

        if self._should_force_block_hosted_phishing(features, ml_score, form_detected, page_flags):
            decision["decision"] = "BLOCK"
            decision["severity"] = max(decision["severity"], 4)

        if form_detected and risk_score > 0.3:
            decision["severity"] += 1
            if decision["severity"] >= 3:
                decision["decision"] = "BLOCK"

        decision["summary"] = self._build_summary(decision["decision"], form_detected)
        decision["reasons"] = self._build_reasons(
            features=features,
            intel=intel,
            anomaly_detected=anomaly_detected,
            ml_score=ml_score,
            geoip_result=geoip_result,
            domain_age=domain_age,
            form_detected=form_detected,
            page_flags=page_flags,
        )
        decision["captcha_required"] = decision["decision"] == "CHALLENGE"
        decision["risk_score"] = min(round(decision["risk_score"], 3), 1.0)

        return decision

    def _predict_ml_score(self, url: str) -> float:
        if self.ml_model is None:
            self.ml_model = get_model()

        if self.ml_model is None:
            return 0.0

        try:
            if hasattr(self.ml_model, "predict_proba"):
                probabilities = self.ml_model.predict_proba([url])
                return float(probabilities[0][1])

            prediction = self.ml_model.predict([url])
            return 1.0 if int(prediction[0]) == 1 else 0.0
        except Exception:
            LOGGER.exception("Failed to score URL with phishing model")
            return 0.0

    def _calibrate_ml_score(self, ml_score: float, features: dict, intel: dict) -> float:
        if (
            features["uses_https"]
            and not features["has_ip"]
            and not features["has_port"]
            and features["num_subdomains"] <= 2
            and features["domain_hyphen_count"] <= 1
            and features["domain_digit_count"] <= 2
            and not intel["brand_impersonation"]
            and not intel["typosquatting"]
            and not intel["domain_similarity"]["possible_typosquat"]
            and intel["suspicious_domain_words"] == 0
        ):
            return min(ml_score, 0.25)

        return ml_score

    def _apply_benign_structure_discount(
        self,
        risk_score: float,
        features: dict,
        intel: dict,
        ml_score: float,
        page_flags: list[str],
    ) -> float:
        if (
            features["uses_https"]
            and not features["has_ip"]
            and not features["has_port"]
            and features["num_subdomains"] <= 2
            and features["domain_hyphen_count"] <= 1
            and features["domain_digit_count"] <= 2
            and not intel["brand_impersonation"]
            and not intel["typosquatting"]
            and not intel["domain_similarity"]["possible_typosquat"]
            and intel["suspicious_domain_words"] == 0
            and ml_score < 0.4
            and not page_flags
        ):
            return min(risk_score, 0.28)

        return risk_score

    def _build_summary(self, decision: str, form_detected: bool) -> str:
        if decision == "BLOCK":
            return "Blocked because the site shows multiple phishing or impersonation indicators."
        if decision == "CHALLENGE":
            if form_detected:
                return "Suspicious form behavior detected. Complete captcha verification to continue."
            return "The site looks suspicious. Complete captcha verification before continuing."
        return "No strong phishing indicators were detected for this site."

    def _build_reasons(
        self,
        *,
        features: dict,
        intel: dict,
        anomaly_detected: bool,
        ml_score: float,
        geoip_result: dict,
        domain_age: dict,
        form_detected: bool,
        page_flags: list[str],
    ) -> list[str]:
        reasons: list[str] = []

        if features["has_ip"]:
            reasons.append("The URL uses a direct IP address instead of a normal domain.")
        if features["has_port"]:
            reasons.append("The URL uses a custom port, which is uncommon for normal websites.")
        if intel["brand_impersonation"]:
            reasons.append("The domain appears to imitate a known brand.")
        if intel["typosquatting"] or intel["domain_similarity"]["possible_typosquat"]:
            reasons.append("The domain structure resembles a possible typosquatting pattern.")
        if intel["suspicious_domain_words"] > 0:
            reasons.append("The domain name contains security-themed words often abused in phishing.")
        if features.get("suspicious_subdomain_keywords", 0) >= 2:
            reasons.append("The subdomain naming pattern looks disposable or intentionally deceptive.")
        if anomaly_detected:
            reasons.append("The URL structure looks anomalous compared with normal browsing patterns.")
        if ml_score >= 0.75:
            reasons.append("The phishing classifier assigned a very high malicious probability.")
        elif ml_score >= 0.45:
            reasons.append("The phishing classifier assigned an elevated malicious probability.")
        if geoip_result.get("country"):
            reasons.append(f"Traffic resolved to {geoip_result['country']} with added GeoIP risk.")
        if domain_age.get("age_days") is not None and domain_age["age_days"] < 180:
            reasons.append("The domain appears recently registered, which increases phishing risk.")
        if domain_age.get("age_days") is not None and domain_age["age_days"] <= 15:
            reasons.append("The domain is 15 days old or newer, so ShieldX blocked it automatically.")
        if form_detected:
            reasons.append("A credential or payment form was detected on the page.")
        if "demo_keywords" in page_flags:
            reasons.append("The page content includes demo or test-environment wording.")
        if "test_card_language" in page_flags:
            reasons.append("The page references test-card or dummy payment instructions.")
        if "admin_surface" in page_flags:
            reasons.append("The page exposes admin-style wording on a public-facing domain.")

        if not reasons:
            reasons.append("The site has a benign structure and no strong phishing signals were found.")

        return reasons

    def _score_page_flags(self, page_flags: list[str], form_detected: bool) -> float:
        score = 0.0

        if "demo_keywords" in page_flags:
            score += 0.18
        if "test_card_language" in page_flags:
            score += 0.25
        if "admin_surface" in page_flags:
            score += 0.08
        if form_detected and page_flags:
            score += 0.12

        return score

    def _score_suspicious_subdomain(self, features: dict) -> float:
        suspicious_subdomain_keywords = int(features.get("suspicious_subdomain_keywords", 0))
        if suspicious_subdomain_keywords >= 3:
            return 0.24
        if suspicious_subdomain_keywords == 2:
            return 0.16
        if suspicious_subdomain_keywords == 1:
            return 0.08
        return 0.0

    def _should_force_block_hosted_phishing(
        self,
        features: dict,
        ml_score: float,
        form_detected: bool,
        page_flags: list[str],
    ) -> bool:
        suspicious_subdomain_keywords = int(features.get("suspicious_subdomain_keywords", 0))
        has_demo_payment_signals = (
            "demo_keywords" in page_flags and "test_card_language" in page_flags
        )

        if suspicious_subdomain_keywords >= 2 and ml_score >= 0.75:
            return True

        if suspicious_subdomain_keywords >= 1 and has_demo_payment_signals:
            return True

        if suspicious_subdomain_keywords >= 1 and form_detected and "test_card_language" in page_flags:
            return True

        return False

    def _is_local_development_url(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if hostname in {"localhost", "127.0.0.1", "::1"}:
            return True
        if hostname.endswith(".local"):
            return True
        if hostname.startswith("192.168.") or hostname.startswith("10."):
            return True
        if hostname.startswith("172."):
            try:
                second_octet = int(hostname.split(".")[1])
                return 16 <= second_octet <= 31
            except (IndexError, ValueError):
                return False

        return False
