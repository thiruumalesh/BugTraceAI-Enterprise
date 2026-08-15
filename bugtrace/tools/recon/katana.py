import subprocess
import json


def scan(target: str):
    cmd = [
        "katana",
        "-u",
        target,
        "-jc",
        "-silent",
    ]

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        urls = []

        for line in process.stdout.splitlines():
            try:
                item = json.loads(line)

                if "url" in item:
                    urls.append(item["url"])

            except Exception:
                pass

        return urls

    except subprocess.TimeoutExpired:
        print("[!] Katana timeout")
        return []

    except Exception as e:
        print(f"[!] Katana error: {e}")
        return []
