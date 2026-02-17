FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir fastmcp httpx pyyaml

COPY server.py /app/server.py
COPY watchtower-api-openapi.yaml /app/watchtower-api-openapi.yaml

EXPOSE 8000

CMD ["python", "/app/server.py"]
