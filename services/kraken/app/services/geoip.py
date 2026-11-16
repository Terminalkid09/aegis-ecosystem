import geoip2.database
import geoip2.errors
from typing import Dict, Optional
from loguru import logger
from app.core.config import settings
import ipaddress


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),
]


class GeoIPService:
    def __init__(self):
        self._reader: Optional[geoip2.database.Reader] = None
        self._asn_reader: Optional[geoip2.database.Reader] = None

    def _get_reader(self) -> Optional[geoip2.database.Reader]:
        if self._reader is None:
            try:
                self._reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
                logger.info(f"GeoIP database loaded from {settings.GEOIP_DB_PATH}")
            except FileNotFoundError:
                logger.warning(
                    f"GeoIP database not found at {settings.GEOIP_DB_PATH}. "
                    "Geolocation disabled. Download GeoLite2-City.mmdb from MaxMind."
                )
        return self._reader

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _PRIVATE_NETWORKS)
        except ValueError:
            return False

    def lookup(self, ip: str) -> Dict:
        result: Dict = {
            "country": None, "city": None,
            "latitude": None, "longitude": None,
            "asn": None, "isp": None,
        }

        if self._is_private(ip):
            result["country"] = "Private Network"
            return result

        reader = self._get_reader()
        if not reader:
            return result

        try:
            response = reader.city(ip)
            result["country"] = response.country.name
            result["city"] = response.city.name
            result["latitude"] = response.location.latitude
            result["longitude"] = response.location.longitude
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"GeoIP: no data for {ip}")
        except Exception as e:
            logger.error(f"GeoIP lookup error for {ip}: {e}")

        # Try ASN lookup
        try:
            asn_path = settings.GEOIP_DB_PATH.replace("City", "ASN")
            if asn_path != settings.GEOIP_DB_PATH:
                if self._asn_reader is None:
                    try:
                        self._asn_reader = geoip2.database.Reader(asn_path)
                    except FileNotFoundError:
                        pass
                if self._asn_reader:
                    asn_response = self._asn_reader.asn(ip)
                    result["asn"] = f"AS{asn_response.autonomous_system_number}"
                    result["isp"] = asn_response.autonomous_system_organization
        except Exception:
            pass

        return result

    def close(self):
        if self._reader:
            self._reader.close()
            self._reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None


geoip_service = GeoIPService()
