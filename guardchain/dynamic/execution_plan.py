from __future__ import annotations


SUPPORTED_MODES = {"setup-py-metadata", "setup-py-install", "pip-install-no-deps"}


def build_execution_command(mode: str) -> str:
    if mode not in SUPPORTED_MODES:
        supported = ", ".join(sorted(SUPPORTED_MODES))
        raise ValueError(f"Unsupported sandbox mode '{mode}'. Expected one of: {supported}")
    trace = "strace -f -tt -o /guardchain-output/trace.log -e trace=file,process,network"
    prelude = "mkdir -p /tmp/home /tmp/install /guardchain-output"
    setup_guard = "test -f setup.py || { echo 'setup.py not found' >&2; exit 4; }"
    if mode == "setup-py-metadata":
        action = f"{setup_guard} && {trace} python setup.py --name"
    elif mode == "setup-py-install":
        action = f"{setup_guard} && {trace} python setup.py install --prefix /tmp/install"
    else:
        action = f"{trace} python -m pip install --no-deps --target /tmp/install /package"
    return f"{prelude} && {action}"
