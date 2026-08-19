"""
MAST API Routes

Mobile Application Security Testing integration with MobSF.

Flow:
    Upload APK/IPA
        ->
    MobSF upload
        ->
    Background static analysis
        ->
    Poll scan status
        ->
    Normalized MAST assessment
        ->
    PDF / JSON reports
"""

from __future__ import annotations

import re

import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, Response

from bugtrace.integrations.mobsf.client import MobSFClient
from bugtrace.services.mast_service import MASTService
from bugtrace.reporting.mast_pdf_report import generate_calix_mast_pdf


router = APIRouter()


# ============================================================
# IN-MEMORY JOB STATE
# ============================================================

_MAST_JOBS: dict[str, dict[str, Any]] = {}
_MAST_LOCK = threading.Lock()


# ============================================================
# CONFIGURATION
# ============================================================

def _load_mobsf_env_file() -> None:
    """
    Load .env.mobsf if the process environment does not already
    contain the MobSF configuration.

    The API key remains server-side and is never returned to
    the frontend.
    """

    if os.getenv("MOBSF_API_KEY"):
        return

    candidates = [
        Path(".env.mobsf"),
        Path.home() / "BugTraceCLI-Tool123" / ".env.mobsf",
    ]

    for env_path in candidates:
        if not env_path.exists():
            continue

        try:
            for raw_line in env_path.read_text().splitlines():
                line = raw_line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if key in {"MOBSF_URL", "MOBSF_API_KEY"}:
                    os.environ.setdefault(key, value)

            return

        except Exception:
            return


def _get_mast_service() -> MASTService:
    """
    Create a MAST service using environment configuration.
    """

    _load_mobsf_env_file()

    mobsf_url = os.getenv(
        "MOBSF_URL",
        "http://127.0.0.1:8000",
    )

    mobsf_api_key = os.getenv(
        "MOBSF_API_KEY",
        "",
    )

    if not mobsf_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MOBSF_API_KEY is not configured.",
        )

    client = MobSFClient(
        base_url=mobsf_url,
        api_key=mobsf_api_key,
    )

    return MASTService(client)


# ============================================================
# HELPERS
# ============================================================

_ALLOWED_EXTENSIONS = {
    ".apk": "APK",
    ".ipa": "IPA",
}


def _update_job(
    scan_hash: str,
    **values: Any,
) -> None:
    with _MAST_LOCK:
        job = _MAST_JOBS.setdefault(
            scan_hash,
            {},
        )
        job.update(values)


def _get_job(scan_hash: str) -> dict[str, Any]:
    with _MAST_LOCK:
        return dict(
            _MAST_JOBS.get(
                scan_hash,
                {},
            )
        )


def _flatten_text(value: Any) -> str:
    """
    Convert nested MobSF scan logs into searchable text.
    """
    if isinstance(value, dict):
        return " ".join(
            f"{key} {_flatten_text(item)}"
            for key, item in value.items()
        )

    if isinstance(value, list):
        return " ".join(
            _flatten_text(item)
            for item in value
        )

    return str(value)


def _scan_log_state(logs: Any) -> str | None:
    """
    Detect terminal state from MobSF scan logs.

    Returns:
        completed
        failed
        scanning
        None
    """

    text = _flatten_text(logs).lower()

    failed_markers = (
        "scan failed",
        "analysis failed",
        "task failed",
        "exception",
        "traceback",
    )

    completed_markers = (
        "scan completed",
        "analysis completed",
        "static analysis completed",
        "report generated",
        "scan finished",
        "analysis finished",
        "completed",
    )

    if any(marker in text for marker in failed_markers):
        return "failed"

    if any(marker in text for marker in completed_markers):
        return "completed"

    return "scanning"


def _background_scan(
    scan_hash: str,
    filename: str,
) -> None:
    """
    Execute MobSF scanning outside the HTTP request.

    This allows the frontend to display a real scanning state
    instead of waiting for the scan request to finish.
    """

    _update_job(
        scan_hash,
        status="scanning",
        progress=10,
        message="Starting MobSF static analysis...",
    )

    try:
        service = _get_mast_service()

        _update_job(
            scan_hash,
            progress=20,
            message="MobSF analysis started...",
        )

        # Start MobSF scan.
        scan_response = service.mobsf.scan(
            scan_hash
        )

        _update_job(
            scan_hash,
            progress=35,
            message="Analyzing mobile application...",
            scan_response=scan_response,
        )

        # Poll MobSF until logs/report indicate completion.
        max_wait_seconds = 60 * 60
        started = time.time()

        while time.time() - started < max_wait_seconds:

            try:
                logs = service.mobsf.scan_logs(
                    scan_hash
                )

                log_state = _scan_log_state(logs)

                _update_job(
                    scan_hash,
                    logs=logs,
                    message="MobSF static analysis in progress...",
                )

                if log_state == "failed":
                    _update_job(
                        scan_hash,
                        status="failed",
                        progress=100,
                        message="MobSF scan failed.",
                    )
                    return

                if log_state == "completed":
                    _update_job(
                        scan_hash,
                        status="completed",
                        progress=100,
                        message="Mobile security scan completed.",
                    )
                    return

            except Exception:
                pass

            # Some MobSF versions do not expose a terminal
            # completion message consistently. Try the report.
            try:
                report = service.mobsf.json_report(
                    scan_hash
                )

                if isinstance(report, dict) and report:
                    _update_job(
                        scan_hash,
                        status="completed",
                        progress=100,
                        message="Mobile security scan completed.",
                    )
                    return

            except Exception:
                pass

            # Slowly increase the visual progress indicator
            # while the backend is still working.
            job = _get_job(scan_hash)
            current_progress = int(
                job.get("progress", 35)
            )

            if current_progress < 90:
                current_progress += 5

            _update_job(
                scan_hash,
                progress=current_progress,
            )

            time.sleep(3)

        _update_job(
            scan_hash,
            status="failed",
            progress=100,
            message="MobSF scan timed out.",
        )

    except Exception as exc:
        _update_job(
            scan_hash,
            status="failed",
            progress=100,
            message=f"MobSF scan failed: {exc}",
            error=str(exc),
        )


# ============================================================
# HEALTH
# ============================================================

@router.get(
    "/mast/health",
    tags=["mast"],
)
def mast_health() -> dict[str, Any]:
    """
    Check MAST and MobSF availability.
    """

    try:
        service = _get_mast_service()
        return service.health()

    except HTTPException:
        raise

    except Exception as exc:
        return {
            "service": "mast",
            "status": "unhealthy",
            "mobsf_available": False,
            "error": str(exc),
        }


# ============================================================
# RECENT SCANS
# ============================================================

@router.get(
    "/mast/scans",
    tags=["mast"],
)
def mast_recent_scans() -> dict[str, Any]:
    """
    Return recent MobSF scans.
    """

    try:
        service = _get_mast_service()
        return service.recent_scans()

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to retrieve MobSF scans: {exc}",
        ) from exc


# ============================================================
# UPLOAD APK / IPA
# ============================================================

@router.post(
    "/mast/upload",
    tags=["mast"],
    status_code=status.HTTP_202_ACCEPTED,
)
async def mast_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """
    Upload APK/IPA to MobSF and start a background MAST scan.
    """

    filename = file.filename or "mobile-app"

    extension = Path(filename).suffix.lower()

    if extension not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only APK and IPA files are supported.",
        )

    service = _get_mast_service()

    temp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=extension,
            delete=False,
        ) as temp_file:

            temp_path = Path(
                temp_file.name
            )

            while True:
                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                temp_file.write(chunk)

        upload_result = service.mobsf.upload(
            temp_path
        )

        scan_hash = (
            upload_result.get("hash")
            or upload_result.get("md5")
            or upload_result.get("sha256")
        )

        if not scan_hash:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    "MobSF upload succeeded but "
                    "did not return a scan hash."
                ),
            )

        _update_job(
            scan_hash,
            status="queued",
            progress=5,
            message="File uploaded. Waiting for MobSF scan...",
            filename=filename,
            app_type=_ALLOWED_EXTENSIONS[extension],
        )

        background_tasks.add_task(
            _background_scan,
            scan_hash,
            filename,
        )

        return {
            "status": "queued",
            "scan_hash": scan_hash,
            "filename": filename,
            "app_type": _ALLOWED_EXTENSIONS[extension],
            "message": (
                "File uploaded successfully. "
                "MAST scan started."
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to upload mobile application: {exc}",
        ) from exc

    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(
                    missing_ok=True
                )
            except Exception:
                pass

        try:
            await file.close()
        except Exception:
            pass


# ============================================================
# SCAN STATUS
# ============================================================

@router.get(
    "/mast/scans/{scan_hash}/status",
    tags=["mast"],
)
def mast_scan_status(
    scan_hash: str,
) -> dict[str, Any]:
    """
    Return live status for an uploaded MAST scan.
    """

    if not scan_hash.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_hash is required.",
        )

    job = _get_job(
        scan_hash.strip()
    )

    # If the process has restarted, reconstruct basic status
    # from MobSF.
    if not job:
        job = {
            "scan_hash": scan_hash,
            "status": "scanning",
            "progress": 25,
            "message": "Checking MobSF scan status...",
        }

    try:
        service = _get_mast_service()

        try:
            logs = service.mobsf.scan_logs(
                scan_hash.strip()
            )

            state = _scan_log_state(logs)

            if state == "failed":
                _update_job(
                    scan_hash,
                    status="failed",
                    progress=100,
                    message="MobSF scan failed.",
                    logs=logs,
                )

            elif state == "completed":
                _update_job(
                    scan_hash,
                    status="completed",
                    progress=100,
                    message="Mobile security scan completed.",
                    logs=logs,
                )

        except Exception:
            pass

        job = _get_job(scan_hash)

        # Final verification for completed reports.
        if job.get("status") != "completed":
            try:
                report = service.mobsf.json_report(
                    scan_hash.strip()
                )

                if isinstance(report, dict) and report:
                    _update_job(
                        scan_hash,
                        status="completed",
                        progress=100,
                        message="Mobile security scan completed.",
                    )

            except Exception:
                pass

        job = _get_job(scan_hash)

        return {
            "scan_hash": scan_hash,
            "status": job.get(
                "status",
                "scanning",
            ),
            "progress": job.get(
                "progress",
                25,
            ),
            "message": job.get(
                "message",
                "Scanning mobile application...",
            ),
            "filename": job.get(
                "filename"
            ),
            "app_type": job.get(
                "app_type"
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to retrieve MAST scan status: {exc}",
        ) from exc


# ============================================================
# ASSESSMENT
# ============================================================

@router.get(
    "/mast/scans/{scan_hash}",
    tags=["mast"],
)
def mast_scan(
    scan_hash: str,
) -> dict[str, Any]:
    """
    Return a complete normalized MAST assessment.
    """

    if not scan_hash.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_hash is required.",
        )

    try:
        service = _get_mast_service()

        return service.build_assessment(
            scan_hash.strip()
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to analyze MobSF scan: {exc}",
        ) from exc


# ============================================================
# PDF
# ============================================================

@router.get(
    "/mast/scans/{scan_hash}/report/pdf",
    tags=["mast"],
)
def mast_pdf_report(
    scan_hash: str,
) -> Response:
    """
    Download the CALIX-branded MAST Security Assessment Report.

    The report is generated from the normalized MAST assessment
    rather than returning the original MobSF PDF.
    """

    if not scan_hash.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_hash is required.",
        )

    temp_path: Path | None = None

    try:
        service = _get_mast_service()

        assessment = service.build_assessment(
            scan_hash.strip()
        )

        application = (
            assessment.get("application")
            or {}
        )

        app_name = (
            application.get("app_name")
            or application.get("file_name")
            or "Mobile_Application"
        )

        # Keep generated reports outside the source tree.
        report_dir = Path("/tmp/calix-mast-reports")
        report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        safe_name = re.sub(
            r"[^A-Za-z0-9._-]+",
            "_",
            str(app_name),
        ).strip("_")

        if not safe_name:
            safe_name = "Mobile_Application"

        temp_path = (
            report_dir
            / f"CALIX_MAST_{safe_name}_{scan_hash.strip()}.pdf"
        )

        generate_calix_mast_pdf(
            assessment,
            temp_path,
        )

        pdf_data = temp_path.read_bytes()

        return Response(
            content=pdf_data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    'attachment; filename="'
                    f"CALIX_MAST_{safe_name}_Security_Assessment.pdf"
                ),
                "Cache-Control": "no-store",
            },
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Unable to generate CALIX MAST PDF report: "
                f"{exc}"
            ),
        ) from exc

    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(
                    missing_ok=True
                )
            except Exception:
                pass


# ============================================================
# JSON
# ============================================================

@router.get(
    "/mast/scans/{scan_hash}/report/json",
    tags=["mast"],
)
def mast_json_report(
    scan_hash: str,
) -> JSONResponse:
    """
    Download the original MobSF JSON report.
    """

    if not scan_hash.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_hash is required.",
        )

    try:
        service = _get_mast_service()

        report = service.mobsf.json_report(
            scan_hash.strip()
        )

        return JSONResponse(
            content=report,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="'
                    f'MAST_Report_{scan_hash}.json"'
                )
            },
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Unable to download MobSF JSON report: "
                f"{exc}"
            ),
        ) from exc


# ============================================================
# FINDINGS
# ============================================================

@router.get(
    "/mast/scans/{scan_hash}/findings",
    tags=["mast"],
)
def mast_findings(
    scan_hash: str,
) -> dict[str, Any]:
    """
    Return normalized MAST findings.
    """

    if not scan_hash.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_hash is required.",
        )

    try:
        service = _get_mast_service()

        assessment = service.build_assessment(
            scan_hash.strip()
        )

        return {
            "scan_hash": scan_hash,
            "count": len(
                assessment["findings"]
            ),
            "findings": assessment["findings"],
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Unable to retrieve MAST findings: {exc}"
            ),
        ) from exc


# ============================================================
# POSTURE
# ============================================================

@router.get(
    "/mast/scans/{scan_hash}/posture",
    tags=["mast"],
)
def mast_posture(
    scan_hash: str,
) -> dict[str, Any]:
    """
    Return application security posture and statistics.
    """

    if not scan_hash.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_hash is required.",
        )

    try:
        service = _get_mast_service()

        assessment = service.build_assessment(
            scan_hash.strip()
        )

        return {
            "scan_hash": scan_hash,
            "application": assessment["application"],
            "security": assessment["security"],
            "statistics": assessment["statistics"],
            "permissions": assessment["permissions"],
            "trackers": assessment["trackers"],
            "domains": assessment["domains"],
            "secrets": assessment["secrets"],
            "urls": assessment["urls"],
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Unable to retrieve MAST posture: {exc}"
            ),
        ) from exc
