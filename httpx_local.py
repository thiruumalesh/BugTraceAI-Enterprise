import subprocess

def fingerprint(target):

    cmd = [
        "httpx",
        "-u",
        target,
        "-title",
        "-tech-detect",
        "-status-code"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    return result.stdout
