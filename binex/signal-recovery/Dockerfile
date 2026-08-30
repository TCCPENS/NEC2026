FROM python:3.12-slim

WORKDIR /app
COPY dist/signal_recovery /app/signal_recovery
COPY src/server.py /app/server.py
COPY src/flag.txt /app/flag
COPY src/entrypoint.sh /app/entrypoint.sh

RUN chmod 0555 /app/signal_recovery /app/server.py /app/entrypoint.sh && \
    chmod 0444 /app/flag

EXPOSE 31337
ENTRYPOINT ["/app/entrypoint.sh"]
