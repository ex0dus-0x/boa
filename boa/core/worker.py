"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    Consumes a target, reads it from a mounted storage system, and

"""

import boa.core.unpack

class WorkerException(Exception):
    pass


class BoaWorker(object):
    """
    Represents a worker that encapsulates the functionality of performing static analysis and
    reverse engineering on the given application.
    """

    def __init__(self, name: str):
        self.name = name
        self.checksum = ""


    def identify(self):
        pass


