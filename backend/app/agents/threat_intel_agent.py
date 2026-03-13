import re
from typing import Dict

from app.utils.domain_similarity import DomainSimilarityDetector
from app.utils.domain_utils import (
    extract_domain_label,
    extract_registered_domain,
    extract_subdomain_text,
    normalize_hostname,
)


class ThreatIntelAgent:
    """
    Detect phishing indicators using
    threat intelligence patterns.
    """

    def __init__(self):
        """
        Initialize similarity detector.
        """
        self.similarity_detector = DomainSimilarityDetector()

    KNOWN_BRANDS = [
        "amazon",
        "paypal",
        "google",
        "apple",
        "facebook",
        "microsoft",
        "netflix",
        "chase",
        "instagram"
    ]

    SUSPICIOUS_DOMAIN_WORDS = [
        "secure",
        "login",
        "verify",
        "account",
        "update",
        "payment",
        "confirm",
        "fake",
        "test",
        "demo",
        "sandbox",
        "admin",
    ]

    def analyze_domain(self, domain: str) -> Dict:
        """
        Analyze domain for phishing indicators.
        """
        normalized_domain = normalize_hostname(domain)
        registered_domain = extract_registered_domain(normalized_domain)
        domain_label = extract_domain_label(normalized_domain)
        subdomain_text = extract_subdomain_text(normalized_domain)
        similarity = self.similarity_detector.detect_similarity(registered_domain)

        return {
            "registered_domain": registered_domain,
            "trusted_brand_domain": False,
            "brand_impersonation": self._detect_brand_impersonation(normalized_domain, domain_label),
            "typosquatting": self._detect_typosquatting(domain_label),
            "suspicious_domain_words": self._detect_suspicious_words(
                f"{domain_label} {subdomain_text}"
            ),
            "domain_similarity": similarity,
        }

    def _detect_brand_impersonation(self, domain: str, domain_label: str) -> bool:
        """
        Detect if domain tries to impersonate a brand.
        """

        domain = domain.lower()
        separators = {"-", "_", "."}

        for brand in self.KNOWN_BRANDS:
            if brand in domain:
                if domain_label == brand:
                    continue

                remainder = domain_label.replace(brand, "")
                if any(separator in domain_label for separator in separators):
                    return True
                if any(character.isdigit() for character in remainder):
                    return True
                if self._detect_suspicious_words(remainder) > 0:
                    return True

        return False

    def _detect_typosquatting(self, domain_label: str) -> bool:
        """
        Detect simple typosquatting patterns.
        """

        patterns = [
            r"0",  # replacing 'o'
            r"1",  # replacing 'l'
            r"@",  # replacing 'a'
        ]

        for pattern in patterns:
            if re.search(pattern, domain_label):
                return True

        return False

    def _detect_suspicious_words(self, domain_label: str) -> int:
        """
        Count suspicious phishing-related words in domain.
        """

        count = 0

        for word in self.SUSPICIOUS_DOMAIN_WORDS:
            if word in domain_label:
                count += 1

        return count
