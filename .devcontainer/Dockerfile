FROM python:3.13.3-alpine3.21


# Timezone
ENV TZ=Europe/Moscow
RUN apk add --update --no-cache tzdata \
&& cp /usr/share/zoneinfo/$TZ /etc/localtime \
&& echo $TZ > /etc/timezone



# git
RUN apk add --update --no-cache git

# install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /uvx /bin/


# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true