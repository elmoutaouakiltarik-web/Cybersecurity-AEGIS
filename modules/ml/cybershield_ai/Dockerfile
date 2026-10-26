FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8919

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8919/health', timeout=3).read()"

# Loopback by default: the port only needs to be reachable from the compose
# network, so containers set CYBERSHIELD_BIND=0.0.0.0 while a bare run stays local.
ENV CYBERSHIELD_BIND=127.0.0.1 \
    CYBERSHIELD_PORT=8919

CMD ["sh", "-c", "uvicorn api.app:app --host ${CYBERSHIELD_BIND} --port ${CYBERSHIELD_PORT}"]
