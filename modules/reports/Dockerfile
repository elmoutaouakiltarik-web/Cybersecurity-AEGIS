FROM python:3.12-slim
WORKDIR /app

RUN pip install --no-cache-dir flask>=2.3 requests>=2.32

COPY generator.py .
COPY app.py .

ENV ORCHESTRATOR_URL=http://orchestrator:8080
ENV REPORTS_API_PORT=8086
ENV REPORTS_DIR=/reports
ENV AEGIS_LOG_LEVEL=INFO
EXPOSE 8086

RUN mkdir -p /reports

CMD ["python", "app.py"]
