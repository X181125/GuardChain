import httpx
import urllib.request


def send():
    httpx.post("https://example.invalid/collect", json={"demo": True})
    urllib.request.urlopen("https://example.invalid/")
