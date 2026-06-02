import requests


def fetch_status(url):
    response = requests.get(url, timeout=1)
    return response.status_code
