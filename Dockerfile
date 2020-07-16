FROM python:3.8.0-alpine

# create working directory
RUN mkdir -p /usr/src/boa
WORKDIR /usr/src/boa

# add and install requirements to directory
ADD ./requirements.txt /usr/src/boa/requirements.txt
RUN pip install -r requirements.txt

COPY . /usr/src/boa
