import subprocess


def scan(url):
    try:
        result = subprocess.run(
            [
                "dalfox",
                "url",
                url,
                "--silence",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        findings = []

        output = result.stdout + "\n" + result.stderr

        for line in output.splitlines():
            line = line.strip()

            if (
                "[POC]" in line
                or "[VULN]" in line
                or "[WEAK]" in line
                or "[GREP]" in line
            ):
                findings.append(line)

        return findings

    except Exception as e:
        print(f"Dalfox error: {e}")
        return []
