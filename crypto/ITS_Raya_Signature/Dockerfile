FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pycryptodome

WORKDIR /app
COPY chall.py /app/chall.py
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 9999
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
