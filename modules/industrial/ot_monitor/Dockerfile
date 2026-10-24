FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY collector.py .
COPY app.py .
COPY wsgi.py .

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV OT_API_PORT=8087
ENV OT_MONITOR_SIMULATE=true
ENV AEGIS_LOG_LEVEL=INFO
EXPOSE 8087

CMD ["python", "app.py"]
