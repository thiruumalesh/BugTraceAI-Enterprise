import subprocess

def scan(domain: str):

    process = subprocess.run(
        ["waybackurls", domain],
        capture_output=True,
        text=True
    )

    return process.stdout.splitlines()

