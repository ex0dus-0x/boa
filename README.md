# boa

Reverse Engineering Framework for Python-compiled Malware/Apps

> We are doing a full refactor to include both a CLI and better web version!

## Introduction

__boa__ is an all-in-one reverse engineering platform for aiding with the unpacking and extrapolation 
of source from Python-compiled malwares and executables.

## Usage

### Command Line

For simple and one-off use cases, __boa__ supports a command line tool. Given a Python-compiled
sample, the follow will attempt to generate a full workspace with source:

```
$ boa reverse target.exe
```

However, if you only wish to conduct only specific operations, the following commands are also
supported:

__Detect__:

Determine metadata regarding a specific executable, if a user chooses only to fingerprint it
without doing any actual reversing:

```
$ boa detect target.exe
```

__Unpacking__:

Detects the type of installer that was used to create the executable, and attempts to unpack
bytecode from the given source:

```
$ boa unpack target.exe
```


### Web _(recommended, installs full platform)_

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

## Contributions

Interested in helping out with __boa__? Check out the [issue tracker](https://github.com/ex0dus-0x/boa/issues)
to see what can be done to help improve the state of the project!

## License

[MIT License](https://codemuch.tech/license.txt)
