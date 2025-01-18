FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt && pip install uwsgi

CMD ["sh", "-c", "mkdir -p /app/data && chown -R 33:33 /app/data && uwsgi --ini uwsgi.ini"]
