# app/core/observability.py
from __future__ import annotations

"""
MoviesNow — Observability (minimal, production-ready)
====================================================

What you get
------------
• Request/trace correlation IDs via `contextvars`
• JSON logging (falls back to plain text) with safe key injection
• Optional Prometheus metrics (/metrics) if `prometheus_client` is installed
• Optional OpenTelemetry tracing if OTel is installed
• Lightweight FastAPI middleware for request logs + metrics
• Tiny helpers (`observed`, `observe_block`) to instrument functions/blocks

No org/tenant code. Safe no-ops when optional deps are missing.
"""

import contextvars
import functools
import logging
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Tuple, TypeVar

# ───────────────────────────────────────────────────────────────
# 🎯 Correlation context (propagated via contextvars)
# ───────────────────────────────────────────────────────────────
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="-")
_span_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="-")

def bind_request_id(req_id: Optional[str]) -> None:
    _request_id_ctx.set((req_id or "-").strip() or "-")

def bind_trace_ids(trace_id: Optional[str], span_id: Optional[str]) -> None:
    _trace_id_ctx.set((trace_id or "-").strip() or "-")
    _span_id_ctx.set((span_id or "-").strip() or "-")

def current_observability_context() -> Dict[str, str]:
    return {
        "request_id": _request_id_ctx.get(),
        "trace_id": _trace_id_ctx.get(),
        "span_id": _span_id_ctx.get(),
    }

# ───────────────────────────────────────────────────────────────
# 🔎 OTel helpers (safe if OpenTelemetry is missing)
# ───────────────────────────────────────────────────────────────
def _get_current_otel_ids() -> Tuple[Optional[str], Optional[str]]:
    try:
        from opentelemetry import trace  # type: ignore
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx or not ctx.is_valid:
            return None, None
        return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
    except Exception:
        return None, None

# ───────────────────────────────────────────────────────────────
# 🪵 Logging (JSON if possible) with correlation fields
# ───────────────────────────────────────────────────────────────
class _CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # inject correlation ids if missing
        for k, v in current_observability_context().items():
            if not hasattr(record, k):
                setattr(record, k, v)
        # refresh from OTel if available
        if getattr(record, "trace_id", "-") in ("-", None) or getattr(record, "span_id", "-") in ("-", None):
            t_id, s_id = _get_current_otel_ids()
            if t_id:
                record.trace_id = t_id
            if s_id:
                record.span_id = s_id
        return True

def _make_handler() -> logging.Handler:
    handler = logging.StreamHandler()
    try:
        from pythonjsonlogger import jsonlogger  # type: ignore
        fmt = jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s "
            "%(request_id)s %(trace_id)s %(span_id)s"
        )
    except Exception:
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s | "
            "request_id=%(request_id)s trace_id=%(trace_id)s span_id=%(span_id)s"
        )
    handler.setFormatter(fmt)
    handler.addFilter(_CorrelationFilter())
    return handler

def _configure_root_logger() -> logging.Logger:
    logger = logging.getLogger("moviesnow")
    if logger.handlers:
        return logger  # idempotent

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = _make_handler()

    logger.setLevel(level)
    logger.addHandler(handler)
    logger.propagate = False

    # Align uvicorn loggers unless suppressed (use same handler/level)
    if os.getenv("OBS_SUPPRESS_UVICORN_INTEGRATION", "0") != "1":
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            uv = logging.getLogger(name)
            uv.handlers.clear()
            uv.addHandler(handler)
            uv.setLevel(level)
            uv.propagate = False

    return logger

logger = _configure_root_logger()

# ───────────────────────────────────────────────────────────────
# 📊 Metrics (Prometheus - optional)
# ───────────────────────────────────────────────────────────────
class _NoopMetric:
    def labels(self, **_): return self
    def inc(self, *_a, **_k): pass
    def observe(self, *_a, **_k): pass
    def set(self, *_a, **_k): pass

@dataclass
class _Metrics:
    enabled: bool
    Counter: Any
    Histogram: Any
    Gauge: Any
    registry: Any = None
    asgi_app_factory: Optional[Callable[[], Any]] = None

    def counter(self, name: str, documentation: str = "", labelnames: Iterable[str] = ()):
        try:
            return self.Counter(name, documentation or name, labelnames=tuple(labelnames), registry=self.registry)
        except Exception:
            return _NoopMetric()

    def histogram(self, name: str, documentation: str = "", labelnames: Iterable[str] = (), buckets: Optional[Iterable[float]] = None):
        try:
            return self.Histogram(
                name, documentation or name, labelnames=tuple(labelnames),
                buckets=list(buckets) if buckets else None, registry=self.registry
            )
        except Exception:
            return _NoopMetric()

    def gauge(self, name: str, documentation: str = "", labelnames: Iterable[str] = ()):
        try:
            return self.Gauge(name, documentation or name, labelnames=tuple(labelnames), registry=self.registry)
        except Exception:
            return _NoopMetric()

# caches avoid label-schema collisions
_COUNTER_CACHE: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
_HISTOGRAM_CACHE: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
_GAUGE_CACHE: Dict[Tuple[str, Tuple[str, ...]], Any] = {}

try:
    from prometheus_client import (
        Counter as _PCounter,
        Histogram as _PHistogram,
        Gauge as _PGauge,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
        make_asgi_app,
    )
    _registry = CollectorRegistry(auto_describe=True)
    metrics = _Metrics(True, _PCounter, _PHistogram, _PGauge, registry=_registry, asgi_app_factory=make_asgi_app)
except Exception:
    metrics = _Metrics(False, _NoopMetric, _NoopMetric, _NoopMetric)

# small convenience API that NEVER raises (even if labels change)
def metrics_increment(name: str, value: float = 1.0, **labels) -> None:
    try:
        key = (name, tuple(sorted(labels.keys())))
        c = _COUNTER_CACHE.get(key) or metrics.counter(name, f"counter:{name}", key[1]); _COUNTER_CACHE[key] = c
        c.labels(**labels).inc(value)
    except Exception:
        pass

def metrics_timing_seconds(name: str, seconds: float, **labels) -> None:
    try:
        key = (name, tuple(sorted(labels.keys())))
        h = _HISTOGRAM_CACHE.get(key) or metrics.histogram(
            name, f"latency:{name}", key[1],
            buckets=[0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10]
        ); _HISTOGRAM_CACHE[key] = h
        h.labels(**labels).observe(float(seconds))
    except Exception:
        pass

def metrics_set(name: str, value: float, **labels) -> None:
    try:
        key = (name, tuple(sorted(labels.keys())))
        g = _GAUGE_CACHE.get(key) or metrics.gauge(name, f"gauge:{name}", key[1]); _GAUGE_CACHE[key] = g
        g.labels(**labels).set(value)
    except Exception:
        pass

# ───────────────────────────────────────────────────────────────
# 🧵 Tracing (OTel - optional)
# ───────────────────────────────────────────────────────────────
class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def set_attribute(self, *_a, **_k): pass
    def record_exception(self, *_a, **_k): pass

class _Tracing:
    def __init__(self):
        self._enabled = False
        self._tracer = None
        try:
            from opentelemetry import trace  # type: ignore
            self._tracer = trace.get_tracer("moviesnow")
            self._enabled = True
        except Exception:
            self._enabled = False

    @contextmanager
    def start_span(self, name: str, **attributes):
        if self._enabled and self._tracer:
            from opentelemetry.trace import Status, StatusCode  # type: ignore
            cm = self._tracer.start_as_current_span(name, attributes=attributes or {})
            with cm as span:
                t_id, s_id = _get_current_otel_ids()
                bind_trace_ids(t_id, s_id)
                try:
                    yield span
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR))
                    raise
        else:
            bind_trace_ids(None, None)
            with _NoopSpan():
                yield _NoopSpan()

tracing = _Tracing()

# ───────────────────────────────────────────────────────────────
# ⏱️ Simple decorators to instrument functions/blocks
# ───────────────────────────────────────────────────────────────
F = TypeVar("F", bound=Callable[..., Any])

def _is_coro(fn: Callable[..., Any]) -> bool:
    try:
        import inspect
        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False

def observed(
    name: str,
    *,
    counter: str = "app_observed_total",
    histogram: str = "app_observed_duration_seconds",
    labels: Optional[Dict[str, str]] = None,
) -> Callable[[F], F]:
    lbls = labels or {}
    def wrap(func: F) -> F:
        is_coro = _is_coro(func)

        @functools.wraps(func)
        def _sync(*args, **kwargs):
            with tracing.start_span(name, **lbls):
                start = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    metrics_increment(counter, 1, **lbls)
                    metrics_timing_seconds(histogram, time.perf_counter() - start, **lbls)

        @functools.wraps(func)
        async def _async(*args, **kwargs):
            with tracing.start_span(name, **lbls):
                start = time.perf_counter()
                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    metrics_increment(counter, 1, **lbls)
                    metrics_timing_seconds(histogram, time.perf_counter() - start, **lbls)

        return (_async if is_coro else _sync)  # type: ignore
    return wrap  # type: ignore

@contextmanager
def observe_block(name: str, **labels: str):
    start = time.perf_counter()
    with tracing.start_span(name, **labels):
        try:
            yield
        finally:
            metrics_increment("app_observed_total", 1, **labels)
            metrics_timing_seconds("app_observed_duration_seconds", time.perf_counter() - start, **labels)

# ───────────────────────────────────────────────────────────────
# 🧩 FastAPI instrumentation (middleware + /metrics)
# ───────────────────────────────────────────────────────────────
def instrument_fastapi(app, *, expose_metrics: bool = True, ignore_paths: Optional[set[str]] = None) -> None:
    """
    Call once at startup:

        from app.observability import instrument_fastapi
        instrument_fastapi(app)

    Provides:
      • Request logs with request_id & trace ids
      • Prometheus metrics (/metrics) when available
      • Counter + latency histogram per (method, route, status)
      • OTel span per request (if OTel installed)
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import PlainTextResponse, Response

    ignored = ignore_paths or {"/metrics", "/health", "/livez", "/readyz", "/docs", "/openapi.json"}

    # pre-create metrics (safe even if disabled)
    req_counter = metrics.counter("http_requests_total", "HTTP requests", ("method", "route", "status"))
    latency_hist = metrics.histogram(
        "http_request_duration_seconds", "HTTP request latency (s)",
        ("method", "route", "status"),
        buckets=[0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10],
    )

    class _ObsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next: Callable[..., Awaitable[Response]]):
            # request id from header or generated
            request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
            bind_request_id(request_id)
            request.state.request_id = request_id  # make accessible downstream

            # best-effort route template
            try:
                route_tpl = (request.scope.get("route").path  # type: ignore[attr-defined]
                             if request.scope and request.scope.get("route")
                             else request.url.path)
            except Exception:
                route_tpl = request.url.path

            if route_tpl in ignored:
                resp = await call_next(request)
                resp.headers["x-request-id"] = request_id
                return resp

            with tracing.start_span("http.request", method=request.method, route=route_tpl):
                t_id, s_id = _get_current_otel_ids()
                bind_trace_ids(t_id, s_id)

                log = logger.getChild("http")
                start = time.perf_counter()
                try:
                    resp = await call_next(request)
                    status_code = getattr(resp, "status_code", 500)
                    elapsed = time.perf_counter() - start
                    # metrics
                    req_counter.labels(method=request.method, route=route_tpl, status=str(status_code)).inc()
                    latency_hist.labels(method=request.method, route=route_tpl, status=str(status_code)).observe(elapsed)
                    # structured log (include user_id if middleware set it earlier)
                    log.info(
                        "request_complete",
                        extra={
                            "request_id": request_id,
                            "trace_id": t_id or "-",
                            "span_id": s_id or "-",
                            "method": request.method,
                            "route": route_tpl,
                            "path": request.url.path,
                            "status": status_code,
                            "elapsed_ms": round(elapsed * 1000.0, 3),
                            "client_ip": request.client.host if request.client else None,
                            "user_agent": request.headers.get("user-agent"),
                            "user_id": getattr(request.state, "user_id", None),
                        },
                    )
                    resp.headers["x-request-id"] = request_id
                    return resp
                except Exception:
                    elapsed = time.perf_counter() - start
                    req_counter.labels(method=request.method, route=route_tpl, status="500").inc()
                    latency_hist.labels(method=request.method, route=route_tpl, status="500").observe(elapsed)
                    log.exception(
                        "request_error",
                        extra={
                            "request_id": request_id,
                            "trace_id": t_id or "-",
                            "span_id": s_id or "-",
                            "method": request.method,
                            "route": route_tpl,
                            "path": request.url.path,
                        },
                    )
                    raise

    app.add_middleware(_ObsMiddleware)

    # OTel FastAPI auto-instrumentation (best-effort)
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
        FastAPIInstrumentor.instrument_app(app)
        logger.info("OpenTelemetry FastAPI instrumentation enabled")
    except Exception:
        logger.info("OpenTelemetry FastAPI instrumentation not active")

    # /metrics exposure (only if prometheus_client is available)
    if expose_metrics and metrics.enabled:
        mounted = any(getattr(r, "path", None) == "/metrics" for r in getattr(app, "routes", []))
        if not mounted:
            try:
                if metrics.asgi_app_factory:
                    app.mount("/metrics", metrics.asgi_app_factory())
                else:
                    @app.get("/metrics")
                    def _metrics_endpoint():
                        # these names exist only if prometheus_client imported OK
                        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST  # type: ignore
                        return PlainTextResponse(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)
                logger.info("Prometheus /metrics endpoint ready")
            except Exception:
                logger.warning("Failed to expose /metrics endpoint")

# ───────────────────────────────────────────────────────────────
# 🔬 Optional boot log
# ───────────────────────────────────────────────────────────────
if os.getenv("OBS_DEBUG_BOOT_LOG", "0") == "1":
    logger.info("observability_module_loaded", extra=current_observability_context())
