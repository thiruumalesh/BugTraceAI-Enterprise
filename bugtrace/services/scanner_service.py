import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from bugtrace.tools.scanners.nuclei import scan as nuclei_scan
from bugtrace.tools.scanners.dalfox import scan as dalfox_scan
from bugtrace.tools.scanners.ffuf import scan as ffuf_scan
from bugtrace.tools.scanners.nikto import scan as nikto_scan
from bugtrace.tools.scanners.sqlmap import scan as sqlmap_scan

logger = logging.getLogger(__name__)


class ScannerService:

    def run(self, urls):
        findings = []

        with ThreadPoolExecutor(max_workers=5) as executor:

            future_map = {}

            for url in urls:
                future_map[executor.submit(nuclei_scan, url)] = "Nuclei"
                future_map[executor.submit(dalfox_scan, url)] = "Dalfox"
                future_map[executor.submit(ffuf_scan, url)] = "FFUF"
                future_map[executor.submit(nikto_scan, url)] = "Nikto"
                future_map[executor.submit(sqlmap_scan, url)] = "SQLMap"

            for future in as_completed(future_map):

                scanner = future_map[future]

                try:
                    result = future.result()

                    if result:
                        findings.extend(result)

                    logger.info("%s finished", scanner)

                except Exception:
                    logger.exception("%s failed", scanner)

        return findings
