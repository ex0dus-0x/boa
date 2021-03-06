# boa

Black-Box Python Reverse Engineering Platform

> We are doing a full refactor to include both a CLI and better web version!

## Introduction

__boa__ is an all-in-one reverse engineering platform for aiding with the unpacking and extrapolation 
of source from Python-compiled malwares and executables.

### Features

* Standalone command-line and web applications

### Built With

* PyCQA's [Bandit](https://github.com/PyCQA/bandit) for static security analysis.

## Usage

### Docker _(recommended, installs full platform)_

Docker Compose is the recommended way to bootstrap the full platform, both the command line
and 

```
$ docker-compose up
```

The hacker can now visit [http://0.0.0.0:5000](http://0.0.0.0:5000) to use the web-based automated
solution, and invoke any tool component as so:

```
# start bash and operate in container ...
$ docker run -it boa bash


# ... or exec command directly in host
$ docker exec -t boa 
```


### Local _(CLI only)_

You are also welcome to install __boa__ locally without a container through `pip`.
If that's the case, only the CLI toolset is available, as the web application requires several
moving parts to operate fully. This is recommended if you choose to not utilize the full web
platform, only the command line tooling.

```
$ pip install boa
```

## Contributions

Interested in helping out with __boa__? Check out the [issue tracker](https://github.com/ex0dus-0x/boa/issues)
to see what can be done to help improve the state of the project!

## License

[MIT License](https://codemuch.tech/license.txt)
