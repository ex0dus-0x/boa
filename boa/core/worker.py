"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    Consumes a target, reads it from a mounted storage system, and

"""
import os
import uuid

import boa.core.unpack

class WorkerException(Exception):
    pass


class BoaWorker(object):
    """
    Represents a worker that encapsulates the functionality of performing static analysis and
    reverse engineering on the given application.
    """


    def __init__(self, filename: str):
        self.name = filename
        self.timestamp = ""
        self.file_checksum = ""
        self.uuid = uuid.uuid1()


    def init_workspace(self, root: str) -> str:
        """
        Given an input sample to analyze, create a workspace surrounding it with the
        following structure:

        dir_name/
            - config.json
            - unpacked/
            - recovered/
        """

        # construct the absolute path to store workspace
        self.workspace = os.path.join(root, self.name + "_analyzed")

        # if already analyzed before, return path without reinstantiating
        if os.path.exists(self.workspace):
            return os.path.join(self.workspace, self.name)

        # create the directory if it doesn't exist
        os.mkdir(self.workspace)

        # create its underlying components
        os.mkdir(os.path.join(self.workspace, "unpacked"))
        os.mkdir(os.path.join(self.workspace, "recovered"))

        # write empty configuration file with stats

        # return the name of the workspace plus binary for user to interact with
        return os.path.join(self.workspace, self.name)


    @staticmethod
    def get_pyversion(filepath) -> str:
        pass

    @staticmethod
    def get_packer(filepath) -> str:
        pass

    def identify(self):
        pass
