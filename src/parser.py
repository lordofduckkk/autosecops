#!/usr/bin/env python3
"""
🔍 Log Parser для AutoSecOps
Читает auth.log в реальном времени и детектирует brute-force атаки
"""
import re
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
from metrics import setup_metrics, record_incident, record_latency, set_blocked_count, SERVICE_UP
import time
import tailer

# Добавляем src в path для импорта blocker
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blocker import IPBlocker

class AttackDetector:
    def __init__(self, config: dict):
        self.max_attempts = config.get('max_attempts', 5)
        self.time_window = config.get('time_window_sec', 60)
        self.whitelist = set(config.get('whitelist', []))
        self.failed_attempts = defaultdict(deque)
        
        # 🚫 Инициализируем блокировщик
        self.blocker = IPBlocker(self.whitelist)
        
        # Regex для Ubuntu 24.04 (ISO-формат) + классический syslog
        self.failed_pattern = re.compile(
            r'(?:\d{4}-\d{2}-\d{2}T[\d:.]+\+[\d:]+|\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
        )
    
    def is_whitelisted(self, ip: str) -> bool:
        if ip in self.whitelist:
            return True
        for entry in self.whitelist:
            if '/' in entry and ip.startswith(entry.split('/')[0].rsplit('.', 1)[0]):
                return True
        return False
    
    def parse_line(self, line: str) -> dict | None:
        match = self.failed_pattern.search(line)
        if match:
            return {'user': match.group(1), 'ip': match.group(2)}
        return None
    
    def record_attempt(self, ip: str) -> bool:
        now = datetime.now()
        window_start = now - timedelta(seconds=self.time_window)
        self.failed_attempts[ip].append(now)
        while self.failed_attempts[ip] and self.failed_attempts[ip][0] < window_start:
            self.failed_attempts[ip].popleft()
        if len(self.failed_attempts[ip]) >= self.max_attempts:
            return True
        return False
    
    def process_line(self, line: str) -> str | None:
        parsed = self.parse_line(line)
        if not parsed:
            return None
        
        ip = parsed['ip']
        
        if self.is_whitelisted(ip):
            print(f"⚪ WHITELIST: {ip} skipped", flush=True)
            return None
                    
            # 🚫 БЛОКИРУЕМ IP через iptables!
        if self.record_attempt(ip):
            start_time = time.time()  # ← Замер времени
            alert = f"🚨 ALERT: IP {ip} blocked ({parsed['user']}, {len(self.failed_attempts[ip])} attempts)"
            self.failed_attempts[ip].clear()

            if self.blocker.block_ip(ip):
                alert += " 🚫 FIREWALL"
                # === Запись метрик ===
                record_incident('brute_force')
                latency = time.time() - start_time
                record_latency('brute_force', latency)
                # Обновляем счётчик заблокированных IP
                set_blocked_count(len(self.blocker.list_blocked()))

            return alert
        return None

def load_whitelist(path: str) -> list[str]:
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

def main():
    config = {
        'log_path': '/var/log/auth.log',
        'max_attempts': 5,
        'time_window_sec': 60,
        'whitelist': load_whitelist('config/whitelist.txt')
    }
    # === Инициализация метрик ===
    setup_metrics(port=8000, bind_addr='0.0.0.0')  # WSL2: localhost доступен из Docker
    SERVICE_UP.set(1)
    print(f"📊 Metrics exposed on http://127.0.0.1:8000/metrics\n")
    print(f"🔍 AutoSecOps Parser started. Monitoring {config['log_path']}")
    print(f"📊 Threshold: {config['max_attempts']} attempts in {config['time_window_sec']}s")
    print(f"✅ Whitelisted IPs: {config['whitelist']}\n")
    
    detector = AttackDetector(config)
    
    try:
        for line in tailer.follow(open(config['log_path'], 'r')):
            alert = detector.process_line(line)
            if alert:
                print(alert, flush=True)
    except KeyboardInterrupt:
        print("\n👋 Parser stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    main()
