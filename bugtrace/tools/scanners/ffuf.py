import json
import os
import subprocess
import tempfile


def scan(url):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_file = tmp.name

        subprocess.run(
            [
                "ffuf",
                "-u",
                url.rstrip("/") + "/FUZZ",
                "-w",
                "/usr/share/wordlists/dirb/common.txt",
                "-of",
                "json",
                "-o",
                output_file,
                "-mc",
                "200,204,301,302,307,401,403",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
        )

        findings = []

        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                data = json.load(f)

            for item in data.get("results", []):
                findings.append(
                    {
                        "url": item.get("url"),
                        "status": item.get("status"),
                        "length": item.get("length"),
                        "words": item.get("words"),
                    }
                )

            os.remove(output_file)

        return findings

    except Exception as e:
        print(f"FFUF error: {e}")
        return []
