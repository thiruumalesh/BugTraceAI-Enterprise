import re
import requests
import sys
from bugtrace.engine.scan_engine import ScanEngine


class ChatService:

    def __init__(self):
        self.scan_engine = ScanEngine()

    def ask(self, message: str):

        print("=" * 60, file=sys.stderr)
        print("ChatService started", file=sys.stderr)
       print("User:", message, file=sys.stderr)

        # Detect scan command
        if message.lower().startswith("scan "):

            target = message[5:].strip()

            print("[+] Scan requested:", target, file=sys.stderr)

            findings = self.scan_engine.run(target)

            if not findings:
                return f"""✅ Scan Completed

Target:
{target}

No findings were returned by the scanners.
Check terminal output for scanner logs.
"""

            output = []

            output.append("✅ Scan Completed\n")
            output.append(f"Target: {target}\n")
            output.append(f"Total Findings: {len(findings)}\n")

            for finding in findings:

                if isinstance(finding, dict):

                    output.append("--------------------------------")

                    output.append(
                        f"Scanner : {finding.get('scanner','Unknown')}"
                    )

                    output.append(
                        f"Severity: {finding.get('severity','Info')}"
                    )

                    output.append(
                        f"Title   : {finding.get('title','Finding')}"
                    )

                else:

                    output.append(str(finding))

            return "\n".join(output)

        # Normal AI chat
        try:

            response = requests.post(
                "http://127.0.0.1:11434/api/generate",
                json={
                    "model": "deepseek-r1:8b-0528-qwen3-q4_K_M",
                    "prompt": message,
                    "stream": False
                },
                timeout=120
            )

            response.raise_for_status()

            data = response.json()

            answer = data.get("response", "").strip()

           print("Assistant:", answer, file=sys.stderr)

           print("=" * 60, file=sys.stderr)

            return answer

        except Exception as e:

           print(e, file=sys.stderr)

            return f"AI Error: {e}"
