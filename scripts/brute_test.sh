#!/bin/bash
#Тестовая атака на SSH

TARGET="${1:-127.0.0.1}"
USER="${2:-$(whoami)}"
COUNT="${3:-5}"

echo "Атака: $USER@$TARGET ($COUNT попыток)"

for i in $(seq 1 $COUNT); do
    echo "[$i/$COUNT] Пробуем пароль wrong_$i..."
    sshpass -p "wrong_$i" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=2 -o PreferredAuthentications=password \
        "$USER@$TARGET" exit 2>/dev/null
    sleep 0.3
done
echo "Готово. Смотрите /var/log/auth.log"
