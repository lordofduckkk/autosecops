"""Метрики Prometheus для AutoSecOps"""
import atexit
from prometheus_client import Counter, Histogram, Gauge, start_http_server


def setup_metrics(port: int = 8000, bind_addr: str = '127.0.0.1'):
    """Запускает HTTP server для scrape. Вызывать один раз при старте."""
    start_http_server(port, addr=bind_addr)


# === Метрики (глобальные, thread-safe) ===
INCIDENTS_TOTAL = Counter(
    'autosecops_incidents_total',
    'Total detected security incidents',
    ['attack_type']  # Кардинальность под контролем: brute_force, scan, etc.
)

MITIGATION_LATENCY = Histogram(
    'autosecops_mitigation_latency_seconds',
    'Time from detection to blocking',
    ['attack_type'],
    buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, float('inf')]
)

SERVICE_UP = Gauge(
    'autosecops_service_up',
    '1 if agent is running, 0 otherwise'
)

BLOCKED_IPS_CURRENT = Gauge(
    'autosecops_blocked_ips_current',
    'Current number of blocked IPs'
)


# === Хелперы==
def record_incident(attack_type: str = 'brute_force'):
    INCIDENTS_TOTAL.labels(attack_type=attack_type).inc()


def record_latency(attack_type: str, seconds: float):
    MITIGATION_LATENCY.labels(attack_type=attack_type).observe(seconds)


def set_blocked_count(count: int):
    BLOCKED_IPS_CURRENT.set(count)


# ===Graceful shutdown===
@atexit.register
def _on_exit():
    SERVICE_UP.set(0)
