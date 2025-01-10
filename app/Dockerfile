FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install uwsgi 

EXPOSE 5000

CMD ["uwsgi", "--ini", "uwsgi.ini"]
