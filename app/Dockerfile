FROM python:3.10

WORKDIR /app

COPY . /app

USER root

RUN pip install --no-cache-dir -r requirements.txt && pip install uwsgi

RUN chown -R www-data:www-data /app/data

USER www-data

CMD ["uwsgi", "--ini", "uwsgi.ini"]
