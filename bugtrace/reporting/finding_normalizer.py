from typing import List, Dict
from bugtrace.core.scan_context import ScanContext
from bugtrace.core.event_bus import EventBus
from bugtrace.core.worker_pool import WorkerPool


class FindingNormalizer:
    def __init__(self, scan_context: ScanContext, event_bus: EventBus, worker_pool: WorkerPool):
        self.scan_context = scan_context
        self.event_bus = event_bus
        self.worker_pool = worker_pool
        self.findings = []

    def normalize_findings(self, findings: List[Dict[str, any]]) -> List[Dict[str, any]]:
        normalized_findings = []
        
        for finding in findings:
            normalized_finding = {
                "title": finding.get("title", "No title provided"),
                "severity": finding.get("severity", "unknown"),
                "description": finding.get("description", "No description provided"),
                "evidence": finding.get("evidence", "No evidence provided"),
                "endpoint": finding.get("endpoint", "No endpoint provided"),
                "parameter": finding.get("parameter", "No parameter provided"),
                "payload": finding.get("payload", "No payload provided"),
                "cwe": finding.get("cwe", "No CWE provided"),
                "owasp": finding.get("owasp", "No OWASP category provided"),
                "cvss": finding.get("cvss", "No CVSS score provided"),
                "agent": finding.get("agent", "No agent provided"),
                "confidence": finding.get("confidence", "No confidence provided")
            }
            normalized_findings.append(normalized_finding)
        
        return normalized_findings