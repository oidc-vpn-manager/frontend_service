ARG IMAGE_REPO=debian
ARG IMAGE_TAG=trixie-slim
FROM ${IMAGE_REPO}:${IMAGE_TAG} AS builder

RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /usr/src/app/wheels -r requirements.txt

# --- Final Image ---
FROM ${IMAGE_REPO}:${IMAGE_TAG}

RUN groupadd --system --gid 1001 appgroup && \
    useradd --system --uid 1001 --gid appgroup --no-create-home appuser

RUN apt-get update && \
    apt-get install -y python3 python3-pip libpq5 openvpn netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/wheels /wheels
RUN pip install --break-system-packages --no-cache --ignore-installed packaging /wheels/*

COPY migrations/ ./migrations/
COPY app/ ./app
COPY wsgi.py .
COPY --chmod=0755 run_migrate.sh .

RUN chown -R appuser:appgroup /usr/src/app

USER appuser

EXPOSE 8600

ENV GUNICORN_LOG_LEVEL="info"
ENV GUNICORN_CMD_ARGS="--bind=0.0.0.0:8600 --workers=3 --access-logfile - --error-logfile - --logger-class app.gunicorn_logging.CustomGunicornLogger"
ENV ENVIRONMENT="production"
ENV FLASK_APP="wsgi:application"

CMD [ "bash", "-c", "gunicorn --log-level $GUNICORN_LOG_LEVEL $FLASK_APP $GUNICORN_CMD_ARGS" ]