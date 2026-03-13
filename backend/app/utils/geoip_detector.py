from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # pragma: no cover - depends on deployment extras
    geoip2 = None
    AddressNotFoundError = Exception


LOGGER = logging.getLogger(__name__)
HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "CN"}
DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "GeoLite2-Country.mmdb"


class GeoIPDetector:
    """
    Perform country lookups for URLs that directly use IP-based hosts.
    """

    def __init__(self, database_path: str | Path | None = None):
        self.database_path = Path(database_path) if database_path else DEFAULT_DB_PATH
        self._reader = None

    def analyze_url(self, url: str) -> Dict[str, float | str | None]:
        host_ip = self.extract_ip_from_url(url)
        if not host_ip:
            return {"country": None, "risk": 0.0}

        reader = self._get_reader()
        if reader is None:
            return {"country": None, "risk": 0.0}

        try:
            response = reader.country(host_ip)
            country_code = response.country.iso_code
            return {
                "country": country_code,
                "risk": 0.3 if country_code in HIGH_RISK_COUNTRIES else 0.05,
            }
        except AddressNotFoundError:
            LOGGER.info("GeoIP lookup did not find %s", host_ip)
            return {"country": None, "risk": 0.0}
        except Exception:
            LOGGER.exception("GeoIP lookup failed for %s", host_ip)
            return {"country": None, "risk": 0.0}

    def extract_ip_from_url(self, url: str) -> str | None:
        hostname = urlparse(url).hostname
        if not hostname:
            return None

        try:
            return str(ipaddress.ip_address(hostname))
        except ValueError:
            return None

    def _get_reader(self) -> geoip2.database.Reader | None:
        if self._reader is not None:
            return self._reader

        try:
            if geoip2 is None:
                LOGGER.warning("geoip2 is not installed; skipping GeoIP lookups")
                return None

            if not self.database_path.exists():
                LOGGER.warning("GeoIP database not found at %s", self.database_path)
                return None

            self._reader = geoip2.database.Reader(str(self.database_path))
            return self._reader
        except Exception:
            LOGGER.exception("Failed to open GeoIP database at %s", self.database_path)
            return None
