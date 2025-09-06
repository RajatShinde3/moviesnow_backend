from __future__ import annotations

"""Lightweight metrics wrapper (Prometheus optional).

Exposes no-op functions if prometheus_client is not installed so imports never fail.
"""

try:
    from prometheus_client import Counter, Histogram  # type: ignore

    presigns_total = Counter(
        "delivery_presigns_total",
        "Number of presigned URL generations",
        labelnames=("keyspace", "result"),
    )
    presign_latency = Histogram(
        "delivery_presign_seconds",
        "Latency for presigned URL generation",
        labelnames=("keyspace", "result"),
        buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
    tokens_minted_total = Counter(
        "delivery_tokens_minted_total",
        "Number of one-time tokens minted",
    )
    tokens_consumed_total = Counter(
        "delivery_tokens_consumed_total",
        "Number of one-time tokens consumed",
        labelnames=("result",),
    )
    limiter_blocks_total = Counter(
        "limiter_blocks_total",
        "Total number of application-level limiter blocks",
    )
    redis_errors_total = Counter(
        "redis_errors_total",
        "Redis errors encountered",
        labelnames=("component",),
    )
    db_errors_total = Counter(
        "db_errors_total",
        "Database errors encountered",
        labelnames=("component",),
    )

    def inc_presign(keyspace: str, result: str) -> None:
        presigns_total.labels(keyspace=keyspace, result=result).inc()

    def observe_presign_seconds(keyspace: str, result: str, seconds: float) -> None:
        presign_latency.labels(keyspace=keyspace, result=result).observe(seconds)

    def inc_token_minted() -> None:
        tokens_minted_total.inc()

    def inc_token_consumed(result: str) -> None:
        tokens_consumed_total.labels(result=result).inc()

    def inc_limiter_block() -> None:
        limiter_blocks_total.inc()

    def inc_redis_error(component: str) -> None:
        redis_errors_total.labels(component=component).inc()

    def inc_db_error(component: str) -> None:
        db_errors_total.labels(component=component).inc()

except Exception:  # pragma: no cover
    def inc_presign(keyspace: str, result: str) -> None:  # type: ignore
        return None

    def inc_token_minted() -> None:  # type: ignore
        return None

    def observe_presign_seconds(keyspace: str, result: str, seconds: float) -> None:  # type: ignore
        return None

    def inc_token_consumed(result: str) -> None:  # type: ignore
        return None

    def inc_limiter_block() -> None:  # type: ignore
        return None

    def inc_redis_error(component: str) -> None:  # type: ignore
        return None

    def inc_db_error(component: str) -> None:  # type: ignore
        return None

__all__ = [
    "inc_presign",
    "observe_presign_seconds",
    "inc_token_minted",
    "inc_token_consumed",
    "inc_limiter_block",
    "inc_redis_error",
    "inc_db_error",
]
