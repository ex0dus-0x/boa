FROM python:3.8.0-slim-buster

# install requirements
RUN apt-get update -y && apt-get install gcc libpq-dev git -y

# create working directory
RUN mkdir -p /usr/src/boa

# copy over source and switch to directory
COPY . /usr/src/boa
WORKDIR /usr/src/boa

# install core and web requirements
RUN pip install .

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--worker-class", "eventlet", "--timeout", "120", "--threads", "3", "--log-level=debug", "--log-file=-", "uwsgi:app"]
