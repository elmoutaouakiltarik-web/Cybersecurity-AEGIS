FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY feeds.py .
COPY service.py .
COPY app.py .
COPY wsgi.py .
COPY feeds/ ./feeds/

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV THREAT_INTEL_API_PORT=8084
ENV THREAT_INTEL_FEEDS_DIR=/app/feeds
ENV AEGIS_LOG_LEVEL=INFO
EXPOSE 8084

CMD ["python", "app.py"]
