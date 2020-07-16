"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    Consumes a target, reads it from a mounted storage system, and

"""
import uuid

import boa.core.unpack

class WorkerException(Exception):
    pass


class BoaWorker(object):
    """
    Represents a worker that encapsulates the functionality of performing static analysis and
    reverse engineering on the given application.
    """

    @staticmethod
    def init_workspace(root: str, filename: str) -> str:
        """
        Given an input sample to analyze, create a workspace surrounding it with the
        following structure:

        dir_name/
            - config.json
            - unpacked/
            - recovered/
        """

    def __init__(self, root: str, name: str):

        # simple metadata for identification
        self.name = name
        self.file_checksum = ""
        self.uuid = uuid.uuid1()

        # initialize the workspace
        self.ws_path = BoaWorker.init_workspace(root, self.name)


    @staticmethod
    def get_pyversion(filepath) -> str:
        pass

    @staticmethod
    def get_packer(filepath) -> str:
        pass

    def identify(self):
        pass


