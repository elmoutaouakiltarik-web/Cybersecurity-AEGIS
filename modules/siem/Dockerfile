FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY correlator.py .
COPY service.py .
COPY app.py .
COPY wsgi.py .
COPY siem_rules.yaml .

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV SIEM_API_PORT=8082
ENV SIEM_RULES_FILE=/app/siem_rules.yaml
ENV SIEM_DEDUP_COOLDOWN=300
ENV AEGIS_LOG_LEVEL=INFO
EXPOSE 8082

CMD ["python", "app.py"]
