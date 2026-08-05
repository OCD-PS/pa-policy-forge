FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --system --gid 10001 forge && useradd --system --uid 10001 --gid 10001 --create-home forge
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY vendor ./vendor
RUN mkdir -p /data /certs && chown -R forge:forge /data /app
USER forge
EXPOSE 8443/tcp 5514/udp
CMD ["gunicorn","--workers","1","--threads","8","--timeout","1800","--bind","0.0.0.0:8443","--certfile","/certs/tls.crt","--keyfile","/certs/tls.key","app.main:app"]
