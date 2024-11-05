# scatterbox.dev/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn
RUN mkdir -p /var/Site-resources/logs/scatterbox.dev


COPY . .

CMD ["gunicorn", "--error-logfile", "/var/Site-resources/logs/scatterbox.dev/log.log", "--log-level", "info", "--capture-output", "--access-logfile", "/var/Site-resources/logs/scatterbox.dev/access.log", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", "--workers", "4", "-b", "0.0.0.0:3001", "--timeout", "60", "api:app"]