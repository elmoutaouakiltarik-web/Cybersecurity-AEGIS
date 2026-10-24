FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY executor.py .
COPY service.py .
COPY app.py .
COPY wsgi.py .

# Playbooks come in via bind-mount at /playbooks (docker-compose.full.yml).
RUN mkdir -p /playbooks

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV SOAR_API_PORT=8083
ENV SOAR_PLAYBOOKS_DIR=/playbooks
ENV SOAR_LIVE_MODE=false
ENV AEGIS_LOG_LEVEL=INFO
EXPOSE 8083

CMD ["python", "app.py"]
