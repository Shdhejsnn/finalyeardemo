from typing import Dict


class BehaviorAgent:
    """
    Behavior Agent responsible for calculating
    behavioral risk score based on URL features.
    """

    def calculate_risk_score(self, features: Dict) -> float:
        """
        Calculate risk score using weighted behavioral features.
        """

        domain_trust = self._domain_trust(features)
        url_structure = self._url_structure_score(features)
        port_analysis = self._port_analysis(features)
        path_analysis = self._path_analysis(features)
        suspicious_patterns = self._suspicious_pattern_score(features)

        score = (
            0.35 * domain_trust +
            0.15 * url_structure +
            0.20 * port_analysis +
            0.10 * path_analysis +
            0.20 * suspicious_patterns
        )

        return round(score, 3)

    def _domain_trust(self, features: Dict) -> float:
        """
        Lower trust if domain has suspicious characteristics.
        """

        if features["has_ip"]:
            return 1.0

        if features.get("suspicious_subdomain_keywords", 0) >= 2:
            return 1.0

        if features["num_subdomains"] > 2:
            return 0.7

        if features["domain_hyphen_count"] >= 2 or features["domain_digit_count"] >= 4:
            return 0.5

        return 0.05

    def _url_structure_score(self, features: Dict) -> float:
        """
        Detect suspicious URL structures.
        """

        if features["url_length"] > 120:
            return 1.0

        if features["url_length"] > 80:
            return 0.4

        return 0.05

    def _port_analysis(self, features: Dict) -> float:
        """
        Detect unusual port usage.
        """

        return 1.0 if features["has_port"] else 0.0

    def _path_analysis(self, features: Dict) -> float:
        """
        Analyze suspicious path length.
        """

        if features["path_length"] > 50:
            return 0.8

        if features["path_length"] > 25:
            return 0.25

        return 0.05

    def _suspicious_pattern_score(self, features: Dict) -> float:
        """
        Detect phishing keywords.
        """

        count = len(features["suspicious_keywords"])

        if count >= 3:
            return 1.0

        if count == 2:
            return 0.7

        if count == 1:
            return 0.4

        return 0.0
