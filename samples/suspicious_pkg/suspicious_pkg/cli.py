import os
import socket


def check_local_context() -> str:
    token_path = os.getenv("DEMO_TOKEN_PATH", ".env")
    socket_family = socket.AF_INET
    return f"checked {token_path} with socket family {socket_family}"
