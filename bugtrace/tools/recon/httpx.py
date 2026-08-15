import subprocess
import re

ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def fingerprint(target):
    cmd = [
        "httpx",
        "-u", target,
        "-title",
        "-tech-detect",
        "-status-code",
        "-silent"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

        output = ANSI_ESCAPE.sub("", result.stdout).strip()
        return output

    except subprocess.TimeoutExpired:
        print("[!] HTTPX timeout")
        return ""

    except Exception as e:
        print(e)
        return ""
