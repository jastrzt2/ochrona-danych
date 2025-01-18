FROM python:3.10

WORKDIR /app

COPY . /app

RUN mkdir -p /app/data && \
    chown -R 33:33 /app/data && \
    chmod -R 755 /app/data

RUN pip install --no-cache-dir -r requirements.txt && pip install uwsgi 

CMD ["uwsgi", "--ini", "uwsgi.ini"]
