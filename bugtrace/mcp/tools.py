from typing import Optional, Dict, Any, List

from bugtrace.mcp.app import mcp_server
from bugtrace.services.scan_context import ScanOptions
from bugtrace.api.deps import get_scan_service

@mcp_server.tool()
async def get_bugtrace_scan_status(
    scan_id: int,
) -> Dict[str, Any]:
    """
    Get the live status and progress of an existing BugTraceAI scan.

    This exposes the existing ScanService.get_scan_status() method
    through MCP. It does not start, stop, modify, or otherwise affect
    the scan.

    Args:
        scan_id:
            Existing BugTraceAI scan ID.

    Returns:
        Current scan status, phase, progress, active agent,
        current URL, findings count, and scan metadata.
    """
    try:
        scan_service = get_scan_service()
        status = await scan_service.get_scan_status(scan_id)

        return {
            "success": True,
            **status,
        }

    except ValueError as e:
        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
        }

    except Exception as e:
        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
        }


@mcp_server.tool()
async def start_bugtrace_scan(
    target_url: str,
    scan_type: str = "full",
    max_depth: int = 2,
    max_urls: int = 20,
    safe_mode: Optional[bool] = None,
    use_vertical: bool = True,
    focused_agents: Optional[List[str]] = None,
    param: Optional[str] = None,
    scan_depth: str = "",
    auth_token: Optional[str] = None,
    auth: Optional[Dict[str, Any]] = None,
    url_list: Optional[List[str]] = None,
    scope_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Start a BugTraceAI security scan using the existing BugTraceAI
    ScanService and scanning pipeline.

    This MCP tool is only an adapter around the existing BugTraceAI
    scanning implementation. It does not implement a separate scanner.

    Use only against systems you are authorized to test.

    Args:
        target_url:
            Target website or API URL.

        scan_type:
            Scan mode. Examples:
            - full
            - hunter
            - manager
            - focused agent name

        max_depth:
            Maximum crawl depth.

        max_urls:
            Maximum number of URLs to process.

        safe_mode:
            Override the global safe-mode configuration.
            None means use the configured default.

        use_vertical:
            Enable vertical/advanced scanning.

        focused_agents:
            Optional list of specific agents, for example:
            ["xss"]
            ["sqli"]
            ["ssrf"]

        param:
            Optional parameter to target in focused scanning.

        scan_depth:
            Optional scan-depth override.

        auth_token:
            Optional pre-authenticated Bearer token.

        auth:
            Optional authentication configuration.

        url_list:
            Optional predefined URL list.

        scope_path:
            Optional path restriction, for example:
            "/WebPA/"

    Returns:
        Dictionary containing the scan ID and scan status.
    """

    if not target_url or not target_url.strip():
        return {
            "success": False,
            "error": "target_url is required"
        }

    try:
        # Build the same ScanOptions object used by the existing
        # BugTraceAI scanning workflow.
        options = ScanOptions(
            target_url=target_url.strip(),
            scan_type=scan_type,
            safe_mode=safe_mode,
            max_depth=max_depth,
            max_urls=max_urls,
            resume=False,
            use_vertical=use_vertical,
            focused_agents=focused_agents or [],
            param=param,
            scan_depth=scan_depth,
            auth_token=auth_token,
            auth=auth,
            url_list=url_list,
            scope_path=scope_path,
        )

        # Use the existing BugTraceAI ScanService.
        scan_service = get_scan_service()

        # Start the existing BugTraceAI scanning pipeline.
        scan_id = await scan_service.create_scan(
            options,
            origin="mcp",
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "target_url": target_url.strip(),
            "scan_type": scan_type,
            "status": "started",
            "message": (
                f"BugTraceAI scan started successfully. "
                f"Scan ID: {scan_id}"
            ),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "target_url": target_url.strip(),
        }


@mcp_server.tool()
async def query_findings(
    scan_id: int,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 20
) -> Dict[str, Any]:
    """
    Query vulnerability findings from a completed or running scan.

    Retrieves paginated list of security findings with optional filtering
    by severity level and vulnerability type.

    Args:
        scan_id:
            The ID of the scan to query.

        severity:
            Filter by severity:
            critical, high, medium, low, info.

        vuln_type:
            Filter by vulnerability type:
            xss, sqli, csrf, etc.

        page:
            Page number. Default: 1.

        per_page:
            Results per page. Default: 20.

    Returns:
        Dictionary containing findings data.
    """

    try:
        from bugtrace.core.database import get_db_manager
        from bugtrace.schemas.db_models import ScanTable

        db = get_db_manager()

        with db.get_session() as session:
            scan_service = get_scan_service()

            # Get the scan from the database.
            scan = session.get(ScanTable, scan_id)

            if not scan:
                return {
                    "error": f"Scan {scan_id} not found",
                    "scan_id": scan_id
                }

            # Group findings by severity.
            vulnerabilities = {
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
                "Informational": []
            }

            for finding in scan.findings or []:
                # FindingTable is a SQLModel object, not a dictionary.
                # Use its typed attributes instead of .get().
                finding_severity = getattr(finding, "severity", None) or "Informational"

                # Normalize severity names for the response grouping.
                severity_map = {
                    "CRITICAL": "Critical",
                    "HIGH": "High",
                    "MEDIUM": "Medium",
                    "LOW": "Low",
                    "INFO": "Informational",
                    "INFORMATIONAL": "Informational",
                }

                finding_severity = severity_map.get(
                    str(finding_severity).upper(),
                    "Informational"
                )

                # Convert the SQLModel object to a JSON-safe dictionary.
                finding_data = {
                    "id": finding.id,
                    "scan_id": finding.scan_id,
                    "type": (
                        finding.type.value
                        if hasattr(finding.type, "value")
                        else str(finding.type)
                    ),
                    "severity": finding_severity,
                    "details": finding.details,
                    "payload_used": finding.payload_used,
                    "reflection_context": (
                        finding.reflection_context.value
                        if hasattr(finding.reflection_context, "value")
                        else (
                            str(finding.reflection_context)
                            if finding.reflection_context is not None
                            else None
                        )
                    ),
                    "confidence_score": finding.confidence_score,
                    "visual_validated": finding.visual_validated,
                    "status": (
                        finding.status.value
                        if hasattr(finding.status, "value")
                        else str(finding.status)
                    ),
                    "validator_notes": finding.validator_notes,
                    "proof_screenshot_path": finding.proof_screenshot_path,
                    "attack_url": finding.attack_url,
                    "vuln_parameter": finding.vuln_parameter,
                    "reproduction_command": finding.reproduction_command,
                }

                vulnerabilities[finding_severity].append(finding_data)

            findings = await scan_service.get_findings(
                scan_id=scan_id,
                severity=severity,
                vuln_type=vuln_type,
                page=page,
                per_page=per_page
            )

            findings["vulnerabilities"] = vulnerabilities

            return findings

    except ValueError as e:
        return {
            "error": str(e),
            "scan_id": scan_id
        }

    except Exception as e:
        return {
            "error": str(e),
            "scan_id": scan_id
        }


@mcp_server.tool()
async def export_report(
    scan_id: int,
    section: str = "full"
) -> Dict[str, Any]:
    """
    Generate and export complete BugTraceAI reports from the
    authoritative database findings.

    Generates:
      - HTML report
      - JSON report
      - Markdown report

    The generated artifacts are verified before returning success.
    """

    try:
        from pathlib import Path
        import json

        from bugtrace.services.report_service import ReportService
        from bugtrace.core.database import get_db_manager
        from bugtrace.schemas.db_models import ScanTable, TargetTable

        db = get_db_manager()

        # ---------------------------------------------------------
        # 1. Verify scan exists and obtain scan information
        # ---------------------------------------------------------
        with db.get_session() as session:
            scan = session.get(ScanTable, scan_id)

            if not scan:
                return {
                    "success": False,
                    "error": f"Scan {scan_id} not found",
                    "scan_id": scan_id,
                }

            target = session.get(TargetTable, scan.target_id)

            target_url = target.url if target else "unknown"
            scan_status = (
                scan.status.value
                if hasattr(scan.status, "value")
                else str(scan.status)
            )

        # ---------------------------------------------------------
        # 2. Never generate a report for an incomplete scan
        # ---------------------------------------------------------
        if scan_status.upper() != "COMPLETED":
            return {
                "success": False,
                "error": (
                    f"Scan {scan_id} is not completed. "
                    f"Current status: {scan_status}"
                ),
                "scan_id": scan_id,
                "status": scan_status,
                "target": target_url,
            }

        # ---------------------------------------------------------
        # 3. Generate reports from the authoritative DB findings
        # ---------------------------------------------------------
        report_service = ReportService()

        html_path = report_service.generate_report(
            scan_id,
            "html"
        )

        json_path = report_service.generate_report(
            scan_id,
            "json"
        )

        markdown_path = report_service.generate_report(
            scan_id,
            "markdown"
        )

        # ---------------------------------------------------------
        # 4. Verify HTML artifact
        # ---------------------------------------------------------
        html_file = Path(html_path)

        if html_file.is_dir():
            html_file = html_file / "report.html"

        if not html_file.is_file():
            return {
                "success": False,
                "error": "HTML report generation failed: artifact missing",
                "scan_id": scan_id,
                "html_report": str(html_file),
            }

        # ---------------------------------------------------------
        # 5. Verify JSON artifact and count findings
        # ---------------------------------------------------------
        json_file = Path(json_path)

        if not json_file.is_file():
            return {
                "success": False,
                "error": "JSON report generation failed: artifact missing",
                "scan_id": scan_id,
                "json_report": str(json_file),
            }

        report_findings_count = None

        try:
            json_data = json.loads(
                json_file.read_text(encoding="utf-8")
            )

            report_findings_count = len(
                json_data.get("findings", [])
            )

        except Exception as e:
            return {
                "success": False,
                "error": f"JSON report validation failed: {e}",
                "scan_id": scan_id,
                "json_report": str(json_file),
            }

        # ---------------------------------------------------------
        # 6. Verify Markdown artifact
        # ---------------------------------------------------------
        markdown_dir = Path(markdown_path)

        markdown_exists = markdown_dir.exists()

        if not markdown_exists:
            return {
                "success": False,
                "error": "Markdown report generation failed: artifact missing",
                "scan_id": scan_id,
                "markdown_report": str(markdown_dir),
            }

        # ---------------------------------------------------------
        # 7. Compare generated report count with DB count
        # ---------------------------------------------------------
        db_findings = db.get_findings_for_scan(scan_id)
        db_findings_count = len(db_findings)

        if report_findings_count != db_findings_count:
            return {
                "success": False,
                "error": (
                    "Report finding count mismatch. "
                    f"Database={db_findings_count}, "
                    f"JSON report={report_findings_count}"
                ),
                "scan_id": scan_id,
                "database_findings": db_findings_count,
                "report_findings": report_findings_count,
                "html_report": str(html_file),
                "json_report": str(json_file),
                "markdown_report": str(markdown_dir),
            }

        # ---------------------------------------------------------
        # 8. Return verified report artifacts
        # ---------------------------------------------------------
        return {
            "success": True,
            "scan_id": scan_id,
            "target": target_url,
            "status": scan_status,
            "section": section,
            "findings_count": db_findings_count,
            "report_findings_count": report_findings_count,
            "report_location": str(markdown_dir),
            "html_report_location": str(html_file),
            "json_report_location": str(json_file),
            "markdown_report_location": str(markdown_dir),
            "artifacts_verified": True,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id,
        }
