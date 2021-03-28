<div align="center">
    <h1>boa</h1><br>
    <p>Reverse Engineering Framework for Python-Compiled Malware and Applications</p>
</div>

> We are doing a full refactor to include both a CLI and better web version!

## Features

* Implements rich and reliable reverse engineering functionality
  * Info-Gathering and Initial Threat Detection
  * Executable Unpacking
    * Supports traditional packers like UPX, ASProtect, etc.
    * Unfreezes code and resources from installer packers like PyInstaller, Py2exe, etc.
  * Bytecode Patching and Decompilation
  * Static Analysis
    * Find low-hanging vulnerabilities and leaked secrets and private keys
    * Detect malicious capabilities
  * Dynamic Analysis (WIP)
    * Automate bytecode/source recovery from advanced samples through binary emulation
* Convenient use through both command line and a [web platform](https://boa.codemuch.tech).

## Usage

```
$ pip install boa-re
```

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

## Depends on:

Here are some projects that __boa__ relies on that warrants some recognition:

* YARA - pattern matching for feature detection
* Qiling - dynamic binary emulation
* uncompyle6 / decompyle3 - bytecode decompilation
* Bandit - static analysis

## Contributions

Interested in helping out with __boa__? Check out the [issue tracker](https://github.com/ex0dus-0x/boa/issues)
to see what can be done to help improve the state of the project!

## License

[MIT License](https://codemuch.tech/license.txt)
