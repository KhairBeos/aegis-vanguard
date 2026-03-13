FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install runtime dependencies for Kafka producer-based streaming.
RUN pip install --no-cache-dir kafka-python pyyaml

COPY scripts /app/scripts
COPY rules /app/rules

CMD ["python", "/app/scripts/demo_stream.py", "--broker", "kafka:29092", "--topic", "siem.events", "--events-dir", "/app/runtime/mordor", "--campaign", "/app/scripts/demo_stream_campaign.json", "--rules-dir", "/app/rules/runtime", "--rate", "0.7", "--quiet"]