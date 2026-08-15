import json
import subprocess
import threading


def scan(url):
    findings = []

    print("[1] Starting Nuclei", flush=True)

    try:
        process = subprocess.Popen(
            [
                "nuclei",
                "-u",
                url,
                "-j",
                "-silent",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        print("[2] Process started", flush=True)

        def read_stdout():
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass

        def read_stderr():
            for _ in process.stderr:
                pass

        t1 = threading.Thread(target=read_stdout)
        t2 = threading.Thread(target=read_stderr)

        t1.start()
        t2.start()

        process.wait(timeout=60)

        t1.join()
        t2.join()

        print("[3] Process finished", flush=True)
        print(f"[4] Findings: {len(findings)}", flush=True)

        return findings

    except subprocess.TimeoutExpired:
        process.kill()
        print("[TIMEOUT]", flush=True)
        return findings

    except Exception as e:
        print(f"[ERROR] {e}", flush=True)
        return findings
