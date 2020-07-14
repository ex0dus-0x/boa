"""
utils.py

    Helper routines for repeated operations used in the boa web service.
"""

import boa.config as config

def endpoint(name: str) -> str:
    """
    Helper routine that constructs an appropriate API endpoint URL
    """
    return "/api/" + config.API_VERSIOn + "/" + name
