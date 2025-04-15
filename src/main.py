import argparse
import asyncio
import logging
import os
import socket
import time
from logging.handlers import TimedRotatingFileHandler

from dnslib import DNSError, DNSRecord

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
logger = logging.getLogger("dns-proxy")


class DNSProxyProtocol:
    def __init__(self, upstream_server, upstream_port=53):
        """
        Инициализация DNS прокси.

        Args:
            upstream_server: IP-адрес вышестоящего DNS сервера
            upstream_port: Порт вышестоящего DNS сервера (по умолчанию 53)
        """
        self.upstream_server = upstream_server
        self.upstream_port = upstream_port
        self.transport = None

    def connection_made(self, transport):
        """Вызывается при установке соединения с клиентом"""
        self.transport = transport

    def connection_lost(self, exc):
        """Вызывается при закрытии соединения с клиентом

        Args:
            exc: Исключение, вызвавшее закрытие соединения, или None
        """
        if exc:
            logger.warning(f"Соединение закрыто с ошибкой: {exc}")
        self.transport = None

    def datagram_received(self, data, addr):
        """
        Вызывается при получении запроса от клиента.

        Args:
            data: Байты DNS запроса
            addr: Адрес клиента (IP, port)
        """
        # Создаем задачу для обработки DNS запроса
        asyncio.create_task(self._process_dns_query(data, addr))

    async def _process_dns_query(self, data, addr):
        """
        Обрабатывает DNS запрос асинхронно.

        Args:
            data: Байты DNS запроса
            addr: Адрес клиента (IP, port)
        """
        try:
            # Парсим DNS запрос
            request = DNSRecord.parse(data)

            # Логируем информацию о запросе
            query_name = request.q.qname
            query_type = request.q.qtype
            client_ip = addr[0]

            logger.info(f"{client_ip} - ЗАПРОС - {query_name} - (тип: {query_type})")

            # Пересылаем запрос вышестоящему DNS серверу
            start_time = time.time()
            response_data = await self._forward_request(data)
            elapsed_time = (time.time() - start_time) * 1000  # в миллисекундах

            if response_data:
                # Отправляем ответ обратно клиенту
                self.transport.sendto(response_data, addr)

                # Пытаемся распарсить ответ
                try:
                    response = DNSRecord.parse(response_data)
                    answer_count = len(response.rr)
                    logger.info(
                        f"{client_ip} - ОТВЕТ  - {query_name} - "
                        f"(ответов: {answer_count}, время: {elapsed_time:.2f} мс)"
                    )
                except DNSError:
                    logger.warning(f"Не удалось распарсить ответ для {query_name}")
            else:
                logger.error(
                    f"Не получен ответ от вышестоящего сервера для {query_name}"
                )

        except Exception as e:
            logger.error(f"Ошибка при обработке запроса: {e}")

    async def _forward_request(self, data):
        """
        Пересылает DNS запрос к вышестоящему серверу.

        Args:
            data: Байты DNS запроса

        Returns:
            bytes: Ответ от вышестоящего DNS сервера или None в случае ошибки
        """
        try:
            # Создаем UDP соединение с вышестоящим DNS сервером
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            # Устанавливаем таймаут в 5 секунд
            await loop.sock_connect(sock, (self.upstream_server, self.upstream_port))

            # Отправляем запрос
            await loop.sock_sendall(sock, data)

            # Получаем ответ (стандартный размер DNS ответа 512 байт)
            # Но для поддержки EDNS0 увеличим размер до 4096
            response = await loop.sock_recv(sock, 4096)

            sock.close()
            return response
        except TimeoutError:
            logger.error(
                f"Таймаут при ожидании ответа от {self.upstream_server}:{self.upstream_port}"
            )
            return None
        except Exception as e:
            logger.error(f"Ошибка при пересылке запроса: {e}")
            return None


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
        lambda: DNSProxyProtocol(upstream_server, upstream_port),
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
