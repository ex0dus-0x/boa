"""
py2exe.py

    Unpacker implementation for py2exe installers. Builds an abstraction around the unpy2exe
    module in order to be uniform with the API implementation.

    TODO
"""


class Py2Exe(object):
    def __init__(self, filepath):
        self.filepath = filepath

    def __str__(self):
        return "Py2exe"
