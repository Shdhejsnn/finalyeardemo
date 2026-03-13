from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict

from app.utils.domain_utils import extract_registered_domain

try:
    import whois
except ImportError:  # pragma: no cover - optional dependency
    whois = None


LOGGER = logging.getLogger(__name__)


class DomainAgeDetector:
    """
    Lookup domain creation age and derive a bounded risk adjustment.
    """

    def __init__(self) -> None:
        self._cache: dict[str, Dict[str, float | int | None]] = {}
        self._missing_dependency_logged = False

    def analyze_domain(self, domain: str) -> Dict[str, float | int | None]:
        registered_domain = extract_registered_domain(domain)
        if not registered_domain:
            return {"age_days": None, "risk": 0.0}

        if registered_domain in self._cache:
            return self._cache[registered_domain]

        if whois is None:
            if not self._missing_dependency_logged:
                LOGGER.warning("python-whois is not installed; skipping domain age lookups")
                self._missing_dependency_logged = True
            result = {"age_days": None, "risk": 0.0}
            self._cache[registered_domain] = result
            return result

        try:
            record = whois.whois(registered_domain)
            creation_date = self._normalize_creation_date(record.creation_date)
            if creation_date is None:
                result = {"age_days": None, "risk": 0.0}
            else:
                age_days = max((datetime.now(timezone.utc) - creation_date).days, 0)
                result = {"age_days": age_days, "risk": self._risk_from_age(age_days)}
        except Exception:
            LOGGER.exception("Failed to resolve domain age for %s", registered_domain)
            result = {"age_days": None, "risk": 0.0}

        self._cache[registered_domain] = result
        return result

    def _normalize_creation_date(self, creation_date):
        if isinstance(creation_date, list):
            creation_date = min((value for value in creation_date if value is not None), default=None)

        if creation_date is None:
            return None

        if creation_date.tzinfo is None:
            return creation_date.replace(tzinfo=timezone.utc)

        return creation_date.astimezone(timezone.utc)

    def _risk_from_age(self, age_days: int) -> float:
        if age_days <= 15:
            return 1.0
        if age_days < 30:
            return 0.25
        if age_days < 180:
            return 0.12
        if age_days > 3650:
            return -0.18
        if age_days > 365:
            return -0.10
        return 0.0
