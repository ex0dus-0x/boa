FROM python:3.8.0-slim-buster

# create working directory
RUN mkdir -p /usr/src/boa
WORKDIR /usr/src/boa

# set envvars for use
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_APP /usr/src/boa/boa/app.py

# install requirements
RUN apt-get update -y && apt-get install gcc libpq-dev -y

# add and install requirements to directory
ADD ./requirements.txt /usr/src/boa/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# copy over rest of source
COPY . /usr/src/boa

EXPOSE 80
CMD ["flask", "run"]
