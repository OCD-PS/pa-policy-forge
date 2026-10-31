FROM python:3.15.0-slim@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --system --gid 10001 forge && useradd --system --uid 10001 --gid 10001 --create-home forge
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt && pip uninstall --yes setuptools msgpack
COPY app ./app
COPY vendor ./vendor
RUN mkdir -p /data /certs && chown -R forge:forge /data /app
USER forge
EXPOSE 8080/tcp 8443/tcp 5514/udp
CMD ["gunicorn","--workers","1","--threads","8","--timeout","1800","--keep-alive","5","--limit-request-fields","50","--limit-request-field_size","8190","--ciphers","ECDHE+AESGCM:ECDHE+CHACHA20","--no-control-socket","--bind","0.0.0.0:8443","--certfile","/certs/tls.crt","--keyfile","/certs/tls.key","app.main:app"]
