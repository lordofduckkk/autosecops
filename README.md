# AutoSecOps

Система автоматического реагирования на инциденты информационной безопасности с мониторингом SLO.

## Описание

AutoSecOps автоматически обнаруживает и блокирует атаки методом brute-force на SSH, экспортирует метрики в Prometheus и предоставляет визуализации в Grafana

## Компоненты

- Parser - читает /var/log/auth.log в реальном времени, распознает атаки
- Blocker - блокирует IP атакующих через iptables
- Metrics - экспортирует 4 метрики Prometheus
- Prometheus - собирает метрики, оценивает alert rules
- Grafana - дашборд с визуализацией инцидентов и метрик

## Быстрый старт

```bash
# Запустить стек (Prometheus + Grafana)
cd ~/autosecops
docker-compose up -d

# Запустить агента
sudo /home/ubuntu/autosecops/venv/bin/python3 ~/autosecops/src/parser.py > /tmp/parser.log 2>&1 &

# доступ к етрикам
curl -s http://127.0.0.1:8000/metrics | grep autosecops
```

## Метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| autosecops_incidents_total  | Counter | Всего детектированных атак |
| autosecops_mitigation_latency_seconds | Histogram | Время от детекции до блокировки |
| autosecops_service_up | Gauge | 1 = агент работает, 0 = упал |
| autosecops_blocked_ips_current | Gauge | Текущее число заблокированных IP |

## SLO

Целевое значение: 95% блокировок выполняются быстрее 30 секунд.

## Alert Rules

| Алерт |   Условие | Severity |
|-------|---------|----------|
| HighMitigationLatency | P95 latency > 30с (5мин) | warning |
| SecurityAgentDown | agent не отвечает 1мин | critical |
| HighIncidentRate | > 6 атак/мин (10мин) | warning |




## Доступы

| Сервис | URL | Логин/Пароль |
|--------|-----|--------------|
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | admin / admin123 |
| Agent Metrics | http://127.0.0.1:8000/metrics | — |

## Структура проекта

```
/home/ubuntu/autosecops/
├── config/
│   └── whitelist.txt
├── docker/
│   └── Dockerfile
├── prometheus/
│   ├── prometheus.yml
│   └── alerts.yml
├── src/
│   ├── parser.py
│   ├── blocker.py
│   └── metrics.py
├── docker-compose.yml
└── requirements.txt
```

## CI/CD

GitHub Actions workflow находится в .github/workflows/ci.yml.

Пайплайн включает:
- lint  прооверка кода (flake8)
- test  проверка структуры проекта
- docker  сборка образа


## Трудности при разработке  
- Не заблокировать себя через  whitelist
- Правильно парсить два формата auth.log (классический и ISO)

## Что можно улучшить

- Добавить unit тесты
- Добавить экспорт дашборда Grafana в JSON

## Проект демонстрирует:
- Python, iptables, Prometheus,  Grafana, Docker
- Наблюдаемость: метрики, алерты, дашборды
- SRE-практики: SLO, graceful shutdown
- CI/CD:GitHub Actions workflow

## Требования

- Python 3.12
- Docker + Docker Compose
- Доступ к /var/log/auth.log
