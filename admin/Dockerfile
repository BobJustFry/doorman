FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -r -u 10001 doorman && mkdir /data && chown doorman /data
USER doorman
CMD ["sh", "-c", "exec uvicorn app.main:app --host ${ADMIN_BIND:-127.0.0.1} --port ${ADMIN_PORT:-8080} --proxy-headers --forwarded-allow-ips 127.0.0.1"]
