from __future__ import annotations

"""Lightweight metrics wrapper (Prometheus optional).

Exposes no-op functions if prometheus_client is not installed so imports never fail.
"""

try:
    from prometheus_client import Counter  # type: ignore

    presigns_total = Counter(
        "delivery_presigns_total",
        "Number of presigned URL generations",
        labelnames=("keyspace", "result"),
    )
    tokens_minted_total = Counter(
        "delivery_tokens_minted_total",
        "Number of one-time tokens minted",
    )

    def inc_presign(keyspace: str, result: str) -> None:
        presigns_total.labels(keyspace=keyspace, result=result).inc()

    def inc_token_minted() -> None:
        tokens_minted_total.inc()

except Exception:  # pragma: no cover
    def inc_presign(keyspace: str, result: str) -> None:  # type: ignore
        return None

    def inc_token_minted() -> None:  # type: ignore
        return None

__all__ = ["inc_presign", "inc_token_minted"]

