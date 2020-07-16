"""
utils.py

    Helper routines for repeated operations used in the boa web service.
"""

import uuid

import boa.config as config


def allowed_file(filename: str) -> bool:
    """
    Helper to check if an input file is an allowed extension to use.
    TODO: security-conscious: ensure the file matches extension, and isnt hidden/polyglot
    """
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS


def endpoint(name: str) -> str:
    """
    Helper routine that constructs an appropriate API endpoint URL
    """
    return "/api/" + config.API_VERSION + "/" + name
