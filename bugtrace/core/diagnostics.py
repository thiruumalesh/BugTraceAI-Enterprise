import shutil
import asyncio
import os
import aiohttp
from bugtrace.core.config import settings


def _launch_chromium_with_fallback(playwright_obj, **kwargs):
    """Use the system Chromium if the Playwright browser bundle is not installed."""
    browser_executable = os.environ.get("BUGTRACE_CHROMIUM_PATH") or "/usr/bin/chromium"
    if os.path.exists(browser_executable):
        kwargs.setdefault("executable_path", browser_executable)
        kwargs.setdefault("args", ["--no-sandbox", "--disable-setuid-sandbox"])
        return playwright_obj.chromium.launch(**kwargs)
    return playwright_obj.chromium.launch(**kwargs)
from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("core.diagnostics")

class DiagnosticSystem:
    def __init__(self):
        self.results = {}  # {check_name: (success_bool, error_message)}

    async def run_all(self):
        """Runs a suite of health checks on the environment."""
        dashboard.set_phase("⚡ SYSTEMS CHECK")
        dashboard.log("Running system health check...", "INFO")

        self._log_debug_paths()
        
        # Critical checks (scan cannot run without these)
        await self._check_docker()
        await self._check_api_key()
        await self._check_connectivity()
        await self._check_credits()
        
        # Non-critical check (scan can run in headless/degraded mode)
        await self._check_browser()

        critical_checks = ["api_key", "connectivity"]
        all_passed = True
        
        for check in critical_checks:
            success, error = self.results.get(check, (False, "Check not run"))
            if not success:
                dashboard.log(f"❌ CRITICAL FAILURE: {check} - {error}", "CRITICAL")
                all_passed = False

        if all_passed:
            dashboard.log("Diagnostics complete. System ready.", "SUCCESS")
        else:
            dashboard.log("Diagnostics failed - critical components offline.", "ERROR")
            
        return all_passed

    def _log_debug_paths(self):
        """Log debug configuration paths."""
        logger.info(f"BASE_DIR: {settings.BASE_DIR}")
        logger.info(f"LOG_DIR: {settings.LOG_DIR}")
        dashboard.log(f"Config: {settings.LOG_DIR}", "DEBUG")

    async def _check_docker(self):
        """Check Docker availability."""
        docker_path = shutil.which("docker")
        success = docker_path is not None
        self.results["docker"] = (success, "" if success else "Docker binary not found in PATH")
        if success:
            dashboard.log("Docker detected (External tools enabled)", "SUCCESS")
        else:
            dashboard.log("Docker NOT found (Nuclei/SQLMap will be disabled)", "WARN")

    async def _check_browser(self):
        """Check whether Playwright browsers are installed and launchable."""
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await _launch_chromium_with_fallback(
                    p,
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox"],
                )
                await browser.close()

            self.results["browser"] = (True, "")
            dashboard.log("Browser Engine available", "SUCCESS")
            return
        except Exception as e:
            self.results["browser"] = (False, str(e))
            dashboard.log(
                "Browser Engine failed. Set BUGTRACE_CHROMIUM_PATH or install Chromium manually.", "CRITICAL"
            )
            return

    async def _check_api_key(self):
        """Check API-key requirement for the active AI provider."""
        provider = str(getattr(settings, "PROVIDER", "") or "").lower()

        # Ollama is local and does not require an API key.
        if provider == "ollama":
            self.results["api_key"] = (True, "")
            dashboard.log("Ollama selected - no API key required", "SUCCESS")
            return

        # OpenRouter and other remote providers may require an API key.
        provider_cfg = getattr(settings, "_provider_config", {}) or {}
        key_env = provider_cfg.get("api_key_env") or "OPENROUTER_API_KEY"
        key_value = getattr(settings, key_env, None) or os.environ.get(key_env)

        success = bool(key_value and len(key_value) > 10)
        self.results["api_key"] = (
            success,
            "" if success else f"{key_env} missing or too short"
        )

        if success:
            dashboard.log(f"{provider} API key detected", "SUCCESS")
        else:
            dashboard.log(f"No API key configured for {provider}", "WARN")


    async def _check_connectivity(self):
        """Check connectivity to the active AI provider."""
        provider = str(getattr(settings, "PROVIDER", "") or "").lower()

        if provider == "ollama":
            # Ollama is local; check its native health/model endpoint.
            url = "http://127.0.0.1:11434/api/tags"
            try:
                timeout = aiohttp.ClientTimeout(total=10, connect=5)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as resp:
                        success = resp.status == 200
                        self.results["connectivity"] = (
                            success,
                            "" if success else f"Ollama returned HTTP {resp.status}"
                        )

                        if success:
                            dashboard.log(
                                "Ollama Connectivity: OK",
                                "SUCCESS"
                            )
                        else:
                            dashboard.log(
                                f"Ollama Connectivity: FAILED (HTTP {resp.status})",
                                "ERROR"
                            )
            except Exception as e:
                self.results["connectivity"] = (False, str(e))
                logger.warning(f"Ollama connectivity check failed: {e}")
                dashboard.log(
                    f"Ollama Connectivity: FAILED ({type(e).__name__})",
                    "ERROR"
                )
            return

        # Remote-provider connectivity check.
        provider_cfg = getattr(settings, "_provider_config", {}) or {}
        base_url = provider_cfg.get("base_url")

        if not base_url:
            self.results["connectivity"] = (
                False,
                f"No base_url configured for provider {provider}"
            )
            dashboard.log(
                f"AI Connectivity: FAILED (no base_url for {provider})",
                "ERROR"
            )
            return

        try:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(base_url) as resp:
                    success = resp.status < 500
                    self.results["connectivity"] = (
                        success,
                        "" if success else f"{provider} returned HTTP {resp.status}"
                    )

                    if success:
                        dashboard.log(
                            f"{provider} Connectivity: OK",
                            "SUCCESS"
                        )
                    else:
                        dashboard.log(
                            f"{provider} Connectivity: FAILED (HTTP {resp.status})",
                            "ERROR"
                        )
        except Exception as e:
            self.results["connectivity"] = (False, str(e))
            logger.warning(f"{provider} connectivity check failed: {e}")
            dashboard.log(
                f"{provider} Connectivity: FAILED ({type(e).__name__})",
                "ERROR"
            )


    async def _check_credits(self):
        """Check credits only for OpenRouter."""
        provider = str(getattr(settings, "PROVIDER", "") or "").lower()

        # Local providers such as Ollama have no cloud credit requirement.
        if provider != "openrouter":
            self.results["credits"] = (True, "Not applicable for local provider")
            return

        success_key, _ = self.results.get("api_key", (False, ""))
        success_conn, _ = self.results.get("connectivity", (False, ""))

        if not (success_key and success_conn):
            return

        logger.info("Initiating OpenRouter credit check...")
        try:
            headers = {
                "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"
            }
            timeout = aiohttp.ClientTimeout(total=10, connect=5)

            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            ) as session:
                async with session.get(
                    "https://openrouter.ai/api/v1/auth/key"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        key_data = data.get("data", {})
                        limit = key_data.get("limit")
                        usage = key_data.get("usage", 0)

                        if limit is not None:
                            balance = limit - usage
                            dashboard.credits = balance

                            if balance < settings.MIN_CREDITS:
                                msg = (
                                    f"⛔ INSUFFICIENT FUNDS: "
                                    f"${balance:.2f} "
                                    f"(Required: ${settings.MIN_CREDITS:.2f})"
                                )
                                dashboard.log(msg, "CRITICAL")
                                self.results["credits"] = (
                                    False,
                                    "Insufficient balance"
                                )
                            else:
                                dashboard.log(
                                    f"OpenRouter Balance: ${balance:.2f}",
                                    "SUCCESS"
                                )
                                self.results["credits"] = (True, "")
                        else:
                            dashboard.credits = 999.00
                            dashboard.log(
                                "OpenRouter Key: Unlimited/Free Tier",
                                "SUCCESS"
                            )
                            self.results["credits"] = (True, "")
                    else:
                        dashboard.log(
                            f"Credit check failed (Status {resp.status})",
                            "WARN"
                        )
                        self.results["credits"] = (
                            False,
                            f"HTTP {resp.status}"
                        )

        except Exception as e:
            logger.error(
                f"Credit check failed: {e}",
                exc_info=True
            )
            dashboard.log(
                "Could not verify credits",
                "DEBUG"
            )
            self.results["credits"] = (
                True,
                "Verification error (ignored)"
            )


diagnostics = DiagnosticSystem()

diagnostics = DiagnosticSystem()
