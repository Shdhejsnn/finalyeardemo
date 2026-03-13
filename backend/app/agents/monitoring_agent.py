import re
from urllib.parse import urlparse
from typing import Dict, List

from app.utils.domain_utils import (
    extract_domain_label,
    extract_registered_domain,
    extract_subdomain_text,
    normalize_hostname,
)


class MonitoringAgent:
    """
    Monitoring Agent responsible for extracting
    security-relevant features from URLs.
    """

    SUSPICIOUS_KEYWORDS = [
        "login",
        "secure",
        "account",
        "verify",
        "bank",
        "update",
        "payment",
        "signin"
    ]


    def extract_features(self, url: str) -> Dict:
        """
        Extract security features from a URL.

        Args:
            url (str): URL to analyze

        Returns:
            Dict: Extracted features
        """

        parsed = urlparse(url)

        domain = normalize_hostname(parsed.netloc)
        path = parsed.path

        return {
            "domain": domain,
            "registered_domain": extract_registered_domain(domain),
            "domain_label": extract_domain_label(domain),
            "subdomain_text": extract_subdomain_text(domain),
            "uses_https": parsed.scheme == "https",
            "url_length": len(url),
            "has_ip": self._has_ip(domain),
            "num_subdomains": self._count_subdomains(domain),
            "has_port": self._has_port(parsed),
            "path_length": len(path),
            "domain_hyphen_count": domain.count("-"),
            "domain_digit_count": sum(character.isdigit() for character in domain),
            "suspicious_keywords": self._detect_keywords(url),
            "suspicious_subdomain_keywords": self._count_suspicious_subdomain_keywords(domain),
        }


    def _has_ip(self, domain: str) -> bool:
        """
        Detect if domain is an IP address.
        """
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        return bool(re.search(ip_pattern, domain))


    def _count_subdomains(self, domain: str) -> int:
        """
        Count number of subdomains.
        """
        parts = domain.split(".")
        return max(len(parts) - 2, 0)


    def _has_port(self, parsed_url) -> bool:
        """
        Detect if URL contains custom port.
        """
        return parsed_url.port is not None


    def _detect_keywords(self, url: str) -> List[str]:
        """
        Detect suspicious phishing keywords in the hostname/query,
        avoiding normal login paths on genuine sites.
        """
        parsed = urlparse(url)
        inspected_text = " ".join(
            [
                normalize_hostname(parsed.netloc),
                parsed.query.lower(),
                parsed.fragment.lower(),
            ]
        )
        found = []

        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in inspected_text:
                found.append(keyword)

        return found

    def _count_suspicious_subdomain_keywords(self, domain: str) -> int:
        subdomain_text = extract_subdomain_text(domain)
        if not subdomain_text:
            return 0

        return sum(
            keyword in subdomain_text
            for keyword in ["fake", "test", "demo", "sandbox", "admin", "secure", "login", "verify"]
        )
