FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY dist/shelless /app/shelless
COPY dist/libc.so.6 /app/libc.so.6
COPY src/flag.txt /flag
COPY src/entrypoint.sh /entrypoint.sh
COPY src/run-shelless.sh /app/run-shelless

RUN chmod 0555 /app/shelless /app/libc.so.6 /app/run-shelless /entrypoint.sh /flag
EXPOSE 31337
ENTRYPOINT ["/entrypoint.sh"]
