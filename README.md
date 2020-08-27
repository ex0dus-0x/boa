# boa

Black-Box Python Reverse Engineering Platform

## Introduction

__boa__ is a web-based reverse engineering platform dedicated to extrapolating source from Python-based executables and malware. It was built with the intent to simplify the analysis pipeline necessary in order to reverse engineer Python and replace it with a UI-friendly interface.

### Features

* Simple & Intuitive User Interface
* Supports 2 installer unpackers
* Static analysis on decompiled source with `bandit`
* Report generation after analysis
* File object storage with AWS S3

## Usage

### Docker

Use `docker-compose up` to run a local development boa setup:

```
$ docker-compose up
```

### Manual

To build and start a local development instance:

```
$ pip install -r requirements.txt

# set envvars for S3 integration
$ export S3_BUCKET=<BUCKET_NAME>
$ export AWS_ACCESS_KEY_ID=<KEY_HERE>
$ export AWS_SECRET_ACCESS_KEY=<SECRET_FOR_KEY>

# set envvar to application entry point, or set `.env`
$ export FLASK_APP=boa/app.py

# now we can run!
$ flask run
```

## License

[MIT License](https://codemuch.tech/license.txt)
