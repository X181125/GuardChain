# aet-test

Lightweight helpers for Azure environment validation and connectivity checks.

## Features

- Validate Azure endpoint reachability
- DNS resolution diagnostics
- Environment fingerprinting for CI/CD runners

## Installation

```bash
pip install aet-test
```

## Quick Start

```python
from aet_test import env_info

print(env_info())
```

## License

MIT
