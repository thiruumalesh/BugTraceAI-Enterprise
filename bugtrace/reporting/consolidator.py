from typing import List, Dict
from bugtrace.reporting.finding_normalizer import normalize_findings


class Consolidator:
    def __init__(self):
        self.normalized_findings = []

    def consolidate(self, findings: List[Dict[str, any]]) -> List[Dict[str, any]]:
        # Normalize findings first
        self.normalized_findings = normalize_findings(findings)
        
        # Consolidate findings
        consolidated = []
        
        for finding in self.normalized_findings:
            # Check if this finding is already consolidated
            duplicate = False
            for consolidated_finding in consolidated:
                if (findings.get("endpoint", "") == consolidated_finding.get("endpoint", "") and
                    findings.get("parameter", "") == consolidated_finding.get("parameter", "") and
                    findings.get("payload", "") == consolidated_finding.get("payload", "") and
                    findings.get("vulnerability", "") == consolidated_finding.get("vulnerability", "")):
                    
                    # Update severity if this finding has higher severity
                    if findings.get("severity", "unknown") > consolidated_finding.get("severity", "unknown"):
                        consolidated_finding["severity"] = findings.get("severity", "unknown")
                    
                    # Update description if this finding has more detailed description
                    if findings.get("description", "") != consolidated_finding.get("description", ""):
                        consolidated_finding["description"] = findings.get("description", "")
                    
                    duplicate = True
                    break
            
            if not duplicate:
                consolidated.append(finding)
        
        return consolidated