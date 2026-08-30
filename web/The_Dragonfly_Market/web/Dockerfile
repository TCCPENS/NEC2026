FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl wget iproute2 netcat-openbsd dnsutils && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/dragonfly
COPY requirements.txt /tmp/dragonfly-requirements.txt
RUN pip install --no-cache-dir -r /tmp/dragonfly-requirements.txt && rm -f /tmp/dragonfly-requirements.txt
COPY app ./.app
COPY templates ./.templates
COPY static ./.static
RUN addgroup --system --gid 10001 challenge && adduser --system --uid 10001 --ingroup challenge challenge && mkdir -p /data /var/lib/.field && chown -R 10001:10001 /opt/dragonfly /data /var/lib/.field
USER 10001:10001
EXPOSE 5000
CMD ["python", ".app/app.py"]
