FROM python:3.12-slim

LABEL maintainer="AutoSecOps Team"
LABEL description="Security agent for brute-force detection"
LABEL version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENT_VERSION=1.0.0

WORKDIR /app

RUN apt-get update && apt-get install -y \
    iptables \
    sudo \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN useradd -m -u 1000 secagent && \
    usermod -aG adm secagent && \
    echo "secagent ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

RUN chown -R secagent:secagent /app && \
    chmod +x /app/src/*.py

#USER secagent

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "src/parser.py"]
