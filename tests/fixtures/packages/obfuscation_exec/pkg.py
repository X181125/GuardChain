import base64


payload = base64.b64decode("cHJpbnQoJ3Rlc3QnKQ==")
exec(payload)
