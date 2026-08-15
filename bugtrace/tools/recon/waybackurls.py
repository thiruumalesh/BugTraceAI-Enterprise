import subprocess


def scan(domain: str):
    """
    Fetch historical URLs from Wayback Machine.
    Returns a deduplicated list (maximum 200 URLs).
    """

    try:
        result = subprocess.run(
            ["waybackurls"],
            input=domain,
            capture_output=True,
            text=True,
            timeout=120
        )

        urls = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        # Remove duplicates
        urls = sorted(set(urls))

        # Limit to first 200 URLs
        return urls[:200]

    except subprocess.TimeoutExpired:
        print("[!] Waybackurls timed out")
        return []

    except Exception as e:
        print(f"[!] Waybackurls error: {e}")
        return []
