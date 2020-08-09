# boa

Black-Box Python Reverse Engineering Platform

## Introduction

__boa__ is a web-based reverse engineering platform dedicated to extrapolating source from Python-based executables and malware. It was built with the intent to simplify the analysis pipeline necessary in order to reverse engineer Python and replace it with a UI-friendly interface.

### Features

* Supports 2 installer unpackers
* Static analysis on decompiled source with `bandit`
* Report generation after analysis
* File object storage with AWS S3

## Usage

### Docker

WIP: Setting up `docker-compose`

```
$ docker build .
```

### Manual

To build and start a local development instance:

```
$ pip install -r requirements.txt

# set envvars for S3 integration
$ export AWS_S3_BUCKET=<BUCKET_NAME>
$ export AWS_S3_KEY=<KEY_HERE>
$ export AWS_S3_SECRET=<SECRET_FOR_KEY>

# set envvar to application entry point, or set `.env`
$ export FLASK_APP=boa/app.py

# now we can run!
$ flask run
```

## License

[MIT License](https://codemuch.tech/license.txt)
