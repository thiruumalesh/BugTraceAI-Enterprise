from typing import Any, Dict, List

from bugtrace.reporting.models import (
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from bugtrace.reporting.standards import normalize_severity


class MASTNormalizer:
    """
    Convert MobSF JSON findings into the existing BugTraceAI Finding model.

    MobSF remains the source of truth for detection.
    This class normalizes and preserves MobSF evidence and metadata.
    """

    def normalize(self, report: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        # Detailed MobSF sections are authoritative.
        findings.extend(self._manifest_findings(report))
        findings.extend(self._code_findings(report))
        findings.extend(self._certificate_findings(report))

        # Do NOT import appsec summary findings here.
        # MobSF appsec is an aggregate and can duplicate detailed findings.

        return self._deduplicate(findings)

    # =========================================================
    # Manifest Analysis
    # =========================================================

    def _manifest_findings(
        self,
        report: Dict[str, Any],
    ) -> List[Finding]:

        results: List[Finding] = []

        manifest = report.get("manifest_analysis", {})
        entries = manifest.get("manifest_findings", [])

        if not isinstance(entries, list):
            return results

        for item in entries:

            if not isinstance(item, dict):
                continue

            severity = self._severity(
                item.get("severity")
            )

            finding_type = self._finding_type(
                severity
            )

            confidence = self._confidence(
                severity
            )

            title = self._clean_html(
                item.get("title")
                or item.get("name")
                or "MobSF Manifest Finding"
            )

            description = self._clean_html(
                item.get("description")
                or "MobSF identified a manifest security finding."
            )

            finding = Finding(
                title=title,
                type=finding_type,
                severity=severity,
                confidence=confidence,
                description=description,
                remediation=self._extract_remediation(
                    item.get("description", "")
                ),
                references=[],
                evidence=[
                    Evidence(
                        description="MobSF manifest analysis",
                        content=self._build_manifest_evidence(
                            item
                        ),
                    )
                ],
                metadata={
                    "source": "MobSF",
                    "mast": True,
                    "mobsf_rule": item.get("rule"),
                    "mobsf_section": "manifest",
                    "component": item.get("component"),
                    "mobsf_name": item.get("name"),
                },
            )

            results.append(finding)

        return results

    # =========================================================
    # Code Analysis
    # =========================================================

    def _code_findings(
        self,
        report: Dict[str, Any],
    ) -> List[Finding]:

        results: List[Finding] = []

        code_analysis = report.get(
            "code_analysis",
            {}
        )

        findings = code_analysis.get(
            "findings",
            {}
        )

        if not isinstance(findings, dict):
            return results

        for rule, item in findings.items():

            if not isinstance(item, dict):
                continue

            metadata = item.get(
                "metadata",
                {}
            )

            if not isinstance(metadata, dict):
                metadata = {}

            files = item.get(
                "files",
                {}
            )

            severity = self._severity(
                metadata.get("severity")
            )

            finding_type = self._finding_type(
                severity
            )

            confidence = self._confidence(
                severity
            )

            cwe = metadata.get(
                "cwe"
            )

            cvss = metadata.get(
                "cvss"
            )

            masvs = metadata.get(
                "masvs"
            )

            owasp_mobile = metadata.get(
                "owasp-mobile"
            )

            reference = metadata.get(
                "ref"
            )

            references = []

            if reference:
                references.append(
                    str(reference)
                )

            finding = Finding(
                title=self._format_rule_title(
                    rule
                ),
                type=finding_type,
                severity=severity,
                confidence=confidence,
                description=metadata.get(
                    "description",
                    f"MobSF code analysis detected {rule}.",
                ),
                cwe_id=self._normalize_cwe(
                    cwe
                ),
                cvss_score=(
                    str(cvss)
                    if cvss is not None
                    else None
                ),
                references=references,
                evidence=[
                    Evidence(
                        description="MobSF code analysis evidence",
                        content=self._build_code_evidence(
                            files
                        ),
                    )
                ],
                metadata={
                    "source": "MobSF",
                    "mast": True,
                    "mobsf_rule": rule,
                    "mobsf_section": "code_analysis",
                    "masvs": masvs,
                    "owasp_mobile": owasp_mobile,
                    "files": files,
                    "mobsf_metadata": metadata,
                },
            )

            results.append(finding)

        return results

    # =========================================================
    # Certificate Analysis
    # =========================================================

    def _certificate_findings(
        self,
        report: Dict[str, Any],
    ) -> List[Finding]:

        results: List[Finding] = []

        certificate = report.get(
            "certificate_analysis",
            {}
        )

        if not isinstance(certificate, dict):
            return results

        entries = certificate.get(
            "certificate_findings",
            []
        )

        if not isinstance(entries, list):
            return results

        for entry in entries:

            if not isinstance(entry, list):
                continue

            if len(entry) < 2:
                continue

            severity_raw = entry[0]
            description = entry[1]

            title = (
                entry[2]
                if len(entry) > 2
                else "Certificate Finding"
            )

            severity = self._severity(
                severity_raw
            )

            finding_type = self._finding_type(
                severity
            )

            confidence = self._confidence(
                severity
            )

            certificate_info = certificate.get(
                "certificate_info",
                ""
            )

            finding = Finding(
                title=self._clean_html(
                    str(title)
                ),
                type=finding_type,
                severity=severity,
                confidence=confidence,
                description=self._clean_html(
                    str(description)
                ),
                evidence=[
                    Evidence(
                        description="MobSF certificate analysis",
                        content=str(
                            certificate_info
                        )[:10000],
                    )
                ],
                metadata={
                    "source": "MobSF",
                    "mast": True,
                    "mobsf_section": "certificate_analysis",
                },
            )

            results.append(finding)

        return results

    # =========================================================
    # Finding Classification
    # =========================================================

    @staticmethod
    def _finding_type(
        severity: Severity,
    ) -> FindingType:

        if severity == Severity.INFO:
            return FindingType.OBSERVATION

        return FindingType.VULNERABILITY

    @staticmethod
    def _confidence(
        severity: Severity,
    ) -> Confidence:

        if severity == Severity.INFO:
            return Confidence.CERTAIN

        # MobSF static analysis is strong evidence,
        # but it has not necessarily been manually validated.
        return Confidence.FIRM

    # =========================================================
    # Severity
    # =========================================================

    @staticmethod
    def _severity(
        value: Any,
    ) -> Severity:

        value = str(
            value or "INFO"
        ).lower().strip()

        mapping = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "warning": "MEDIUM",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "informational": "INFO",
            "good": "INFO",
            "secure": "INFO",
        }

        return normalize_severity(
            mapping.get(
                value,
                "INFO"
            )
        )

    # =========================================================
    # CWE / Rule Formatting
    # =========================================================

    @staticmethod
    def _normalize_cwe(
        value: Any,
    ) -> str | None:

        if not value:
            return None

        value = str(value)

        if value.startswith("CWE-"):
            return value

        return value

    @staticmethod
    def _format_rule_title(
        rule: str,
    ) -> str:

        if not rule:
            return "MobSF Code Analysis Finding"

        return (
            rule
            .replace("_", " ")
            .strip()
            .title()
        )

    # =========================================================
    # Evidence
    # =========================================================

    @staticmethod
    def _build_manifest_evidence(
        item: Dict[str, Any],
    ) -> str:

        component = item.get(
            "component"
        )

        lines = [
            f"Rule: {item.get('rule', '')}",
            f"Severity: {item.get('severity', '')}",
        ]

        if component:
            lines.append(
                f"Component: {component}"
            )

        name = item.get(
            "name"
        )

        if name:
            lines.append(
                f"Name: {name}"
            )

        return "\n".join(lines)

    @staticmethod
    def _build_code_evidence(
        files: Any,
    ) -> str:

        if not files:
            return (
                "No source file evidence "
                "supplied by MobSF."
            )

        if not isinstance(files, dict):
            return str(files)

        lines = []

        for filename, locations in files.items():
            lines.append(
                f"{filename}: {locations}"
            )

        return "\n".join(lines)

    # =========================================================
    # Remediation
    # =========================================================

    @staticmethod
    def _extract_remediation(
        description: str,
    ) -> str | None:

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
                return description[
                    position:
                ].strip()

        return None

    # =========================================================
    # Text Cleanup
    # =========================================================

    @staticmethod
    def _clean_html(
        value: str,
    ) -> str:

        if not value:
            return value

        replacements = {
            "<strong>": "",
            "</strong>": "",
            "<b>": "",
            "</b>": "",
        }

        for old, new in replacements.items():
            value = value.replace(
                old,
                new
            )

        return value.strip()

    # =========================================================
    # Deduplication
    # =========================================================

    @staticmethod
    def _deduplicate(
        findings: List[Finding],
    ) -> List[Finding]:

        unique = set()
        result = []

        for finding in findings:

            key = (
                finding.title.strip().lower(),
                finding.severity.value,
                finding.metadata.get(
                    "mobsf_rule",
                    "",
                ),
                finding.metadata.get(
                    "mobsf_section",
                    "",
                ),
            )

            if key in unique:
                continue

            unique.add(key)
            result.append(finding)

        return result
