"""
utils.py

    Helper routines for repeated operations used in the boa web service.
"""

import os
import uuid

import boa.config as config


def allowed_file(filename: str) -> bool:
    """
    Helper to check if an input file is an allowed extension to use.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower()[1:] in config.ALLOWED_EXTENSIONS


def endpoint(name: str) -> str:
    """
    Helper routine that constructs an appropriate API endpoint URL
    """
    return "/api/" + config.API_VERSION + "/" + name
