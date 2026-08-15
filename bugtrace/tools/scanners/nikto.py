import json
import os
import subprocess
import tempfile


def scan(url):
    findings = []

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            outfile = f.name

        subprocess.run(
            [
                "nikto",
                "-h",
                url,
                "-Format",
                "json",
                "-output",
                outfile,
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        if os.path.exists(outfile):
            with open(outfile, "r", encoding="utf-8", errors="ignore") as fp:
                data = json.load(fp)

            if isinstance(data, dict):
                findings.append(data)

        os.remove(outfile)

    except Exception as e:
        print(f"Nikto error: {e}")

    return findings
