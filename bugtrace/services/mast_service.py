from __future__ import annotations

from typing import Any, Dict, List, Optional

from bugtrace.integrations.mobsf.client import MobSFClient
from bugtrace.reporting.models import Finding


class MASTService:
    """
    CalixAI MAST service.

    Retrieves a MobSF JSON report and converts it into
    a UI/API-friendly mobile application security assessment.
    """

    def __init__(
        self,
        mobsf_client: MobSFClient,
    ) -> None:
        self.mobsf = mobsf_client

    def get_report(self, scan_hash: str) -> Dict[str, Any]:
        return self.mobsf.json_report(scan_hash)

    def health(self) -> dict:
        """
        Check MobSF availability for the MAST integration.

        Returns a simple service-health structure without exposing
        the MobSF API key.
        """
        try:
            self.mobsf.recent_scans()

            return {
                "service": "mast",
                "status": "healthy",
                "mobsf_available": True,
            }

        except Exception as exc:
            return {
                "service": "mast",
                "status": "unhealthy",
                "mobsf_available": False,
                "error": str(exc),
            }

    def recent_scans(self) -> Dict[str, Any]:
        """
        Return recent MobSF scans.
        """
        return self.mobsf.recent_scans()

    def build_assessment(
        self,
        scan_hash: str,
    ) -> Dict[str, Any]:

        report = self.get_report(scan_hash)

        appsec = report.get("appsec") or {}
        permissions = report.get("permissions") or {}
        trackers = report.get("trackers") or {}
        domains = report.get("domains") or {}
        secrets = report.get("secrets") or []
        urls = report.get("urls") or []

        findings = self._build_findings(appsec)

        dangerous_permissions = [
            {
                "name": name,
                "status": details.get("status"),
                "info": details.get("info"),
                "description": details.get("description"),
            }
            for name, details in permissions.items()
            if isinstance(details, dict)
            and details.get("status") in {
                "dangerous",
                "unknown",
            }
        ]

        domain_items = []

        for domain, details in domains.items():
            if not isinstance(details, dict):
                details = {}

            geolocation = details.get("geolocation")

            domain_items.append(
                {
                    "domain": domain,
                    "bad": details.get("bad"),
                    "ofac": details.get("ofac"),
                    "geolocation": geolocation,
                }
            )

        tracker_items = trackers.get("trackers", [])

        return {
            "scan_hash": scan_hash,

            "application": {
                "app_name": report.get("app_name"),
                "file_name": report.get("file_name"),
                "app_type": report.get("app_type"),
                "package_name": report.get("package_name"),
                "version_name": report.get("version_name"),
                "version_code": report.get("version_code"),
                "min_sdk": report.get("min_sdk"),
                "target_sdk": report.get("target_sdk"),
                "max_sdk": report.get("max_sdk"),
                "sha256": report.get("sha256"),
                "size": report.get("size"),
                "main_activity": report.get("main_activity"),
            },

            "security": {
                "security_score": appsec.get("security_score"),
                "average_cvss": report.get("average_cvss"),
                "high": len(appsec.get("high") or []),
                "warning": len(appsec.get("warning") or []),
                "info": len(appsec.get("info") or []),
                "secure": len(appsec.get("secure") or []),
                "hotspot": len(appsec.get("hotspot") or []),
            },

            "findings": findings,

            "permissions": {
                "total": len(permissions),
                "dangerous": len(dangerous_permissions),
                "items": dangerous_permissions,
            },

            "trackers": {
                "detected": trackers.get("detected_trackers", 0),
                "total_known": trackers.get("total_trackers", 0),
                "items": tracker_items,
            },

            "domains": {
                "total": len(domains),
                "items": domain_items,
            },

            "secrets": {
                "count": len(secrets),
                "items": secrets[:100],
            },

            "urls": {
                "count": len(urls),
                "items": urls[:100],
            },

            "statistics": {
                "finding_count": len(findings),
                "dangerous_permission_count": len(
                    dangerous_permissions
                ),
                "tracker_count": trackers.get(
                    "detected_trackers",
                    0,
                ),
                "domain_count": len(domains),
                "secret_count": len(secrets),
                "url_count": len(urls),
            },
        }

    def _build_findings(
        self,
        appsec: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        findings: List[Dict[str, Any]] = []

        severity_sections = {
            "high": "HIGH",
            "warning": "MEDIUM",
            "info": "INFO",
            "hotspot": "MEDIUM",
        }

        for section, severity in severity_sections.items():

            items = appsec.get(section) or []

            if not isinstance(items, list):
                continue

            for item in items:

                if not isinstance(item, dict):
                    continue

                title = item.get(
                    "title",
                    "MobSF finding",
                )

                description = item.get(
                    "description",
                    "",
                )

                remediation = self._extract_remediation(
                    description
                )

                findings.append(
                    {
                        "title": title,
                        "severity": severity,
                        "description": description,
                        "remediation": remediation,
                        "section": item.get(
                            "section",
                            section,
                        ),
                    }
                )

        return findings

    @staticmethod
    def _extract_remediation(
        description: str,
    ) -> Optional[str]:

        if not description:
            return None

        markers = [
            "The vulnerability can be remediated",
            "can be remediated",
            "To fix",
            "Fix:",
        ]

        description_lower = description.lower()

        for marker in markers:

            position = description_lower.find(
                marker.lower()
            )

            if position >= 0:
                return description[position:].strip()

        return None
