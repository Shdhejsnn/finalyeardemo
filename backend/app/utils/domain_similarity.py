import Levenshtein

from app.utils.domain_utils import extract_domain_label


class DomainSimilarityDetector:
    """
    Detects typosquatting attacks using
    Levenshtein distance.
    """

    KNOWN_BRANDS = [
        "amazon",
        "paypal",
        "google",
        "apple",
        "facebook",
        "microsoft",
        "netflix",
        "instagram",
        "chase"
    ]


    def detect_similarity(self, domain: str):
        domain = extract_domain_label(domain).lower()

        for brand in self.KNOWN_BRANDS:

            distance = Levenshtein.distance(domain, brand)

            if distance == 1:
                return {
                    "similar_to": brand,
                    "distance": distance,
                    "possible_typosquat": True
                }

        return {
            "similar_to": None,
            "distance": None,
            "possible_typosquat": False
        }
