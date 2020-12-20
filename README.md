# boa

Black-Box Python Reverse Engineering Platform

[Old Demo Version](http://boa.codemuch.tech)

## Introduction

__boa__ is a (first of its kind) web-based automated reverse engineering platform that helps extrapolate original and readable Python source from a compiled and packed executables. It is useful for hackers and reverse engineers attempt to better understand the functionality of Python-built apps and/or malware. It undergoes the following when an executable sample is processed through its pipeline:

* Executable Unpacking - parse out resources and code from binaries created with various packers.
* Bytecode Decompilation/Patching - decompile and patch (if necessary) Python source from unpacked bytecode.
* Deobfuscation - (TODO) attempt to recover readable source from bytecode and source-level obfuscation methods.
* Static Analysis - scan relevant source files for detrimental security issues.
* Report Generation - generate a user-friendly report on executable.

### Features

* Simple & intuitive web-based user interface to enhance workflow
* Supports unpacking multiple types of Python-based packers/installers
* Deep static analysis on decompiled source with `bandit` in order to discover low-hanging bugs and secrets
* Report generation in order to display analysis results for consumption
* File object storage with AWS S3 for successful samples

## Usage

__boa__ is designed to be either a self-hosted security tool, or hosted on the cloud. In either case, Docker is conveniently setup for fast and containerized deployment.

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

# now we can run!
$ python run.py
```

With a manually-built version of __boa__, artifacts during scanning are loaded into the `artifacts/` folder in the project workspace, with a local PostgreSQL database
instantiated at `db/boascans.db`.

## Contributions

Interested in helping out with __boa__? Check out the [issue tracker](https://github.com/ex0dus-0x/boa/issues)
to see what can be done to help improve the state of the project!

## License

[MIT License](https://codemuch.tech/license.txt)
