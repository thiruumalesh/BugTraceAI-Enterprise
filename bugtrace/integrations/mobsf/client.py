"""
MobSF REST API client for CalixAI MAST.

Supports:
- APK / IPA upload
- Static analysis scan
- Scan logs
- JSON report
- PDF report
- Recent scans
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from bugtrace.integrations.mobsf.exceptions import (
    MobSFAPIError,
    MobSFConnectionError,
)


class MobSFClient:
    """Small, reusable MobSF REST API client."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_key: str = "",
        timeout: float = 1800.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    @property
    def headers(self) -> dict[str, str]:
        return {
            "X-MOBSF-API-KEY": self.api_key,
        }

    def _handle_error(self, response: httpx.Response) -> None:
        if response.is_success:
            return

        try:
            detail = response.json()
        except Exception:
            detail = response.text

        raise MobSFAPIError(
            f"MobSF API returned HTTP {response.status_code}: {detail}"
        )

    def health_check(self) -> bool:
        """Check whether MobSF is reachable."""

        try:
            response = httpx.get(
                f"{self.base_url}/",
                timeout=10.0,
                follow_redirects=False,
            )

            return response.status_code in {
                200,
                301,
                302,
                303,
                307,
                308,
            }

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"Unable to connect to MobSF at {self.base_url}: {exc}"
            ) from exc

    def upload(self, file_path: str | Path) -> dict[str, Any]:
        """Upload APK/IPA to MobSF."""

        path = Path(file_path)

        if not path.exists():
            raise MobSFAPIError(f"File does not exist: {path}")

        if not path.is_file():
            raise MobSFAPIError(f"Path is not a file: {path}")

        try:
            with path.open("rb") as file_handle:
                response = httpx.post(
                    f"{self.base_url}/api/v1/upload",
                    headers=self.headers,
                    files={
                        "file": (
                            path.name,
                            file_handle,
                            "application/octet-stream",
                        )
                    },
                    timeout=self.timeout,
                )

            self._handle_error(response)

            return response.json()

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"MobSF upload failed: {exc}"
            ) from exc

    def scan(self, file_hash: str) -> dict[str, Any]:
        """Start MobSF static analysis using the uploaded file hash."""

        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/scan",
                headers=self.headers,
                data={"hash": file_hash},
                timeout=self.timeout,
            )

            self._handle_error(response)
            return response.json()

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"MobSF scan request failed: {exc}"
            ) from exc

    def scan_logs(self, file_hash: str) -> dict[str, Any]:
        """Retrieve MobSF scan logs."""

        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/scan_logs",
                headers=self.headers,
                data={"hash": file_hash},
                timeout=30.0,
            )

            self._handle_error(response)
            return response.json()

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"MobSF scan log request failed: {exc}"
            ) from exc

    def json_report(self, file_hash: str) -> dict[str, Any]:
        """Retrieve the MobSF JSON report."""

        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/report_json",
                headers=self.headers,
                data={"hash": file_hash},
                timeout=self.timeout,
            )

            self._handle_error(response)
            return response.json()

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"MobSF JSON report request failed: {exc}"
            ) from exc

    def pdf_report(self, file_hash: str) -> bytes:
        """Retrieve the MobSF PDF report."""

        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/download_pdf",
                headers=self.headers,
                data={"hash": file_hash},
                timeout=self.timeout,
            )

            self._handle_error(response)
            return response.content

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"MobSF PDF report request failed: {exc}"
            ) from exc

    def recent_scans(self) -> dict[str, Any]:
        """Retrieve recent MobSF scans."""

        try:
            response = httpx.get(
                f"{self.base_url}/api/v1/scans",
                headers=self.headers,
                timeout=30.0,
            )

            self._handle_error(response)
            return response.json()

        except httpx.RequestError as exc:
            raise MobSFConnectionError(
                f"MobSF recent scans request failed: {exc}"
            ) from exc
