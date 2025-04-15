FROM python:3.13.3-alpine3.21

# Timezone
ENV TZ=Europe/Moscow
RUN apk add --update --no-cache tzdata \
    && cp /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone

# install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock entrypoint.sh ./
COPY src/ ./src/

RUN uv sync \
    && chmod +x ./entrypoint.sh

EXPOSE 53/udp

ENTRYPOINT ["./entrypoint.sh"]