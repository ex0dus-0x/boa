#!/usr/bin/env python3
"""
setup.py

    Installs boa as both a client library and CLI application locally.

"""

import os
import setuptools

NAME = "boa"
VERSION = "2.0"

REPO = "https://github.com/ex0dus-0x/boa"
DESC = "Python Malware/App Reverse Engineering Framework"

# Main setup method
setuptools.setup(
    name = NAME,
    version = VERSION,
    author = "ex0dus",
    description = DESC,
    license = "MIT",
    url=REPO,
    download_url="{}/archive/v{}".format(REPO, VERSION),
    packages = setuptools.find_packages(exclude=["boa-web"]),
    entry_points = {
        "console_scripts": [
            "boa=boa.__main__:main"
        ],
    },
    install_requires=[
        "stdlib_list",
        "beautifultable",
        "lief",
        "yara-python",
        "uncompyle6",
        "bandit",
    ],
    extras_require={
        "dev": [
            "black",
            "pylint",
            "mypy"
        ],
        "web": [
            # flask-specific modules
            "flask",
            "flask_sse",
            "flask_login",
            "flask_sqlalchemy",
            "wtforms",
            "sqlalchemy == 1.3.23",
            "sqlalchemy_utils == 0.36.8",

            # backend utilities
            "rq",
            "redis",
            "boto3",
            "python-dotenv",
            "cryptography",
            "gunicorn",
            "eventlet",
        ]
    },
    dependency_links=[
        "https://github.com/rocky/python-decompile3/tarball/master#egg=package1.0"
    ],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: End Users/Desktop",
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ]
)
