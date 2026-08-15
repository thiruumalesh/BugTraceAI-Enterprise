import os
import aiohttp
from typing import Any, Dict, Optional


class VirusTotalClient:
    """
    Lightweight VirusTotal API v3 client.

    Used for security-intelligence enrichment only.
    VirusTotal results must not independently confirm a vulnerability.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.enabled = (
            os.getenv("VT_ENABLED", "false").lower()
            in ("true", "1", "yes", "on")
        )

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not configured")

        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    async def _get(self, endpoint: str) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "enabled": False,
                "error": "VirusTotal integration is disabled",
            }

        if not self.api_key:
            return {
                "enabled": False,
                "error": "VIRUSTOTAL_API_KEY is not configured",
            }

        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"

        timeout = aiohttp.ClientTimeout(
            total=15,
            connect=5,
        )

        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=self._headers(),
            ) as session:

                async with session.get(url) as response:

                    if response.status == 200:
                        data = await response.json()

                        return {
                            "enabled": True,
                            "success": True,
                            "status": response.status,
                            "data": data,
                        }

                    body = await response.text()

                    return {
                        "enabled": True,
                        "success": False,
                        "status": response.status,
                        "error": body[:500],
                    }

        except Exception as exc:
            return {
                "enabled": True,
                "success": False,
                "error": str(exc),
            }

    async def get_domain(self, domain: str) -> Dict[str, Any]:
        """
        Retrieve VirusTotal domain intelligence.
        """
        domain = domain.strip().lower()

        result = await self._get(
            f"domains/{domain}"
        )

        if not result.get("success"):
            return result

        attributes = (
            result
            .get("data", {})
            .get("data", {})
            .get("attributes", {})
        )

        return {
            "enabled": True,
            "success": True,
            "domain": domain,
            "reputation": attributes.get("reputation"),
            "analysis_stats": attributes.get(
                "last_analysis_stats", {}
            ),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
            "categories": attributes.get(
                "categories", {}
            ),
            "registrar": attributes.get(
                "registrar"
            ),
        }

    async def get_ip(self, ip: str) -> Dict[str, Any]:
        """
        Retrieve VirusTotal IP intelligence.
        """
        ip = ip.strip()

        result = await self._get(
            f"ip_addresses/{ip}"
        )

        if not result.get("success"):
            return result

        attributes = (
            result
            .get("data", {})
            .get("data", {})
            .get("attributes", {})
        )

        return {
            "enabled": True,
            "success": True,
            "ip": ip,
            "reputation": attributes.get("reputation"),
            "analysis_stats": attributes.get(
                "last_analysis_stats", {}
            ),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
        }
