FROM python:3.7-alpine
WORKDIR /var/www
ENV FLASK_APP app/app.py
ENV FLASK_RUN_HOST 0.0.0.0
RUN apk add --no-cache gcc musl-dev linux-headers libffi-dev openssl-dev
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY app app
#CMD ["flask", "run"]

COPY uwsgi.ini uwsgi.ini
COPY wsgi.py wsgi.py
CMD ["uwsgi", "--ini", "uwsgi.ini"]
