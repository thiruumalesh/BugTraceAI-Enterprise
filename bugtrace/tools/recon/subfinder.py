import subprocess


def scan(domain: str):
    cmd = [
        "subfinder",
        "-d",
        domain,
        "-silent"
    ]

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

        return [
            line.strip()
            for line in process.stdout.splitlines()
            if line.strip()
        ]

    except subprocess.TimeoutExpired:
        print("[!] Subfinder timeout")
        return []

    except Exception as e:
        print(f"[!] Subfinder error: {e}")
        return []
