#!/bin/ash
set -e

# Установка значений по умолчанию, которые можно переопределить переменными окружения
DNS_HOST=${DNS_HOST:-0.0.0.0}
DNS_PORT=${DNS_PORT:-53}
UPSTREAM_DNS=${UPSTREAM_DNS:-8.8.8.8}
UPSTREAM_PORT=${UPSTREAM_PORT:-53}

echo "Запуск DNS прокси со следующими параметрами:"
echo "- Прослушивание: $DNS_HOST:$DNS_PORT"
echo "- Вышестоящий DNS: $UPSTREAM_DNS:$UPSTREAM_PORT"

# Запуск программы с параметрами из переменных окружения
exec uv run src/main.py \
    --host "$DNS_HOST" \
    --port "$DNS_PORT" \
    --upstream "$UPSTREAM_DNS" \
    --upstream-port "$UPSTREAM_PORT"