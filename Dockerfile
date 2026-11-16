# Data Sentinel discovery worker (V2) - to WORKER-STANDARD 2026-46-06
FROM python:3.13-slim-trixie

ARG DS_UID=10001
ARG DS_GID=10001

# Who it is, as the conductor's image sets its own three. 5600 until the workers' ports are assigned.
ENV DS_SERVICE=ds_discover \
    DS_SERVICE_EXTERNAL_HOST=ds_discover \
    DS_SERVICE_EXTERNAL_PORT=5600 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt

COPY main.py ds_discover.py ds_connect_lib.py walk_*.py ./

RUN groupadd --gid ${DS_GID} sentinel \
 && useradd --uid ${DS_UID} --gid ${DS_GID} --no-create-home --shell /usr/sbin/nologin sentinel \
 && mkdir -p /mnt/logs && chown ${DS_UID}:${DS_GID} /mnt/logs

USER ${DS_UID}:${DS_GID}

EXPOSE 5600
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('DS_SERVICE_EXTERNAL_PORT', '5600') + '/health', timeout=4)" || exit 1
STOPSIGNAL SIGTERM

CMD ["python", "main.py"]
