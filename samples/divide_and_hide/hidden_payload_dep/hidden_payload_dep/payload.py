import base64


def decode_demo_payload() -> None:
    payload = base64.b64decode("cHJpbnQoJ2RlbW8gcGF5bG9hZCcp")
    exec(payload)
