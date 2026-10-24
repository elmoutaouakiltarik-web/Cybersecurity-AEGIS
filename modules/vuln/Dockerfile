FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .
COPY service.py .
COPY app.py .
COPY wsgi.py .

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV VULN_API_PORT=8085
ENV VULN_ACTIVE_SCAN=false
ENV AEGIS_LOG_LEVEL=INFO
EXPOSE 8085

CMD ["python", "app.py"]
