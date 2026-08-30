FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/wp2shell
COPY requirements.txt /tmp/wp2shell-requirements.txt
RUN pip install --no-cache-dir -r /tmp/wp2shell-requirements.txt \
    && rm -f /tmp/wp2shell-requirements.txt
COPY app ./app
COPY templates ./templates

RUN addgroup --system --gid 10001 challenge \
    && adduser --system --uid 10001 --ingroup challenge challenge \
    && mkdir -p /data /opt/wp2shell/runtime/themes/twentytwentyfour \
    && chown -R 10001:10001 /opt/wp2shell /data

USER 10001:10001
EXPOSE 5000
CMD ["python", "app/app.py"]
