"""Common validation helpers for Azure resource names and endpoints."""

import re

_STORAGE_ACCOUNT_RE = re.compile(r"^[a-z0-9]{3,24}$")
_RESOURCE_GROUP_RE = re.compile(r"^[-\w._()]{1,90}$")


def is_valid_storage_account(name):
    """Return True if *name* is a valid Azure storage account name."""
    return bool(_STORAGE_ACCOUNT_RE.match(name))


def is_valid_resource_group(name):
    """Return True if *name* is a valid Azure resource group name."""
    return bool(_RESOURCE_GROUP_RE.match(name)) and not name.endswith(".")


def is_valid_endpoint(url):
    """Basic check that *url* looks like an Azure service endpoint."""
    return url.startswith("https://") and ".azure." in url
