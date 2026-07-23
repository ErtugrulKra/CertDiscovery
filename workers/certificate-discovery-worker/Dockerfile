FROM python:3.12-slim
WORKDIR /app
COPY workers/certificate-discovery-worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY workers/certificate-discovery-worker/worker ./worker
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import socket; socket.gethostbyname('certificate-web')" || exit 1
CMD ["python", "-m", "worker.main"]
