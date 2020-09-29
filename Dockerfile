FROM python:3.8.0-slim-buster

# install requirements
RUN apt-get update -y && apt-get install gcc libpq-dev -y

# create working directory
RUN mkdir -p /usr/src/boa

# copy over source and switch to directory
COPY . /usr/src/boa
WORKDIR /usr/src/boa

# install requirements
RUN pip install --no-cache-dir -r requirements.txt

# set envvars for use
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_APP /usr/src/boa/boa/app.py

EXPOSE 8000
CMD ["gunicorn", "--worker-class", "eventlet", "--log-file=-", "boa.app:app"]
