FROM python:3.10

WORKDIR /app

COPY . /app

USER root

RUN pip install --no-cache-dir -r requirements.txt && pip install uwsgi

RUN mkdir -p /app/data && chown -R 33:33 /app/data && chmod -R 755 /app/data

USER 33

CMD ["uwsgi", "--ini", "uwsgi.ini"]
