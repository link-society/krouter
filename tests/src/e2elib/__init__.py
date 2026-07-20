"""
Shared helpers for the krouter end-to-end, performance and benchmark suites.

Everything here is black-box: helpers only interact with the cluster through
kubectl and with the proxy through published NodePorts, exactly like a user
of the installation would (docs/SPECIFICATION.md §4, §7).
"""

import uuid


def unique_name(prefix: str) -> str:
    """
    Unique, DNS-safe object name for parallel-safe test resources.
    """

    return f"{prefix}-{uuid.uuid4().hex[:6]}"
