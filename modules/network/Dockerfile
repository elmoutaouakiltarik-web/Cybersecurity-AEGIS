FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py .
COPY lan_scanner.py .
COPY topology.py .
COPY tls_inspector.py .
COPY device_profiler.py .
COPY intelligence/ ./intelligence/
COPY app.py .
COPY wsgi.py .

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV NETWORK_API_PORT=8081
ENV AEGIS_LOG_LEVEL=INFO
ENV SCAN_MAX_HOSTS=256
ENV SCAN_MAX_CONCURRENT=3
EXPOSE 8081

CMD ["python", "app.py"]
