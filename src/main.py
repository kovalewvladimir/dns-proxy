import argparse
import asyncio
import logging
import os
from logging.handlers import TimedRotatingFileHandler

from dns import DNSProxyProtocol

# Путь для хранения логов
log_directory = "/var/log/dns-proxy"
log_file = os.path.join(log_directory, "dns_queries.log")

# Создаем директорию для логов, если она не существует
os.makedirs(log_directory, exist_ok=True)

# Настройка логирования с ротацией раз в неделю
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        TimedRotatingFileHandler(
            log_file,
            when="W0",  # W0 означает каждый понедельник
            interval=1,  # Интервал - 1 неделя
            backupCount=52,  # Хранить 52 предыдущих лога
        ),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger()


def handle_resolved_ips(query_name, ip_addresses):
    """
    Пример функции для обработки разрешенных IP-адресов.

    Args:
        query_name: Имя DNS-запроса
        ip_addresses: Список полученных IP-адресов
    """
    logger.info(f"Обработка IP-адресов для {query_name}: {ip_addresses}")
    # Здесь можно добавить дополнительную логику обработки IP-адресов
    # Например, сохранение в базу данных, анализ или фильтрацию


async def start_dns_proxy(host, port, upstream_server, upstream_port):
    """
    Запускает DNS прокси сервер.

    Args:
        host: Локальный IP для прослушивания
        port: Локальный порт для прослушивания
        upstream_server: IP вышестоящего DNS сервера
        upstream_port: Порт вышестоящего DNS сервера
    """
    # Создаем экземпляр протокола
    loop = asyncio.get_running_loop()

    # Создаем транспорт и связываем с протоколом
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSProxyProtocol(
            upstream_server,
            upstream_port,
            process_resolved_ips_callback=handle_resolved_ips,
        ),
        local_addr=(host, port),
    )

    logger.info(f"DNS прокси запущен на {host}:{port}")
    logger.info(f"Перенаправление запросов на {upstream_server}:{upstream_port}")

    try:
        # Бесконечный цикл для поддержания сервера активным
        while True:
            await asyncio.sleep(3600)  # Проверка каждый час
    except asyncio.CancelledError:
        pass
    finally:
        transport.close()
        logger.info("DNS прокси остановлен")


def parse_arguments():
    """Парсит аргументы командной строки"""
    parser = argparse.ArgumentParser(description="Асинхронный DNS прокси сервер")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="IP-адрес для прослушивания (по умолчанию: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", type=int, default=53, help="Порт для прослушивания (по умолчанию: 53)"
    )
    parser.add_argument(
        "--upstream",
        default="8.8.8.8",
        help="Вышестоящий DNS сервер (по умолчанию: 8.8.8.8)",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=53,
        help="Порт вышестоящего DNS сервера (по умолчанию: 53)",
    )
    return parser.parse_args()


def main():
    """Основная функция для запуска DNS прокси"""
    args = parse_arguments()

    try:
        asyncio.run(
            start_dns_proxy(args.host, args.port, args.upstream, args.upstream_port)
        )
    except KeyboardInterrupt:
        logger.info("Остановка DNS прокси...")


if __name__ == "__main__":
    main()
