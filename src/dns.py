import asyncio
import logging
import socket
import time

from dnslib import DNSError, DNSRecord

logger = logging.getLogger(__name__)


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
