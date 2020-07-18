"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    Consumes a target, reads it from a mounted storage system, and

"""
import os
import uuid
import flask_socketio as sio

import boa.core.unpack


class BoaWorker(sio.Namespace):
    """
    Represents a stateful worker that consumes a checked Python-compiled executable path,
    instantiates a workspace, performs the necessary analysis workflow and implements handlers
    for WebSocket connections requesting functionality.
    """

    def __init__(self, root: str, filename: str) -> None:
        self.name = filename
        self.timestamp = ""
        self.file_checksum = ""
        self.uuid = uuid.uuid1()

        # initialize workspace and set path
        self.path = BoaWorker.init_workspace(root, filename)

        # initialize base object with no namespace identifier
        super().__init__()


    @staticmethod
    def init_workspace(root: str, filename: str) -> str:
        """
        Given an input sample to analyze, create a workspace with the following structure:

        dir_name/
            - config.json
            - unpacked/
            - recovered/
        """

        # construct the path to the workspace directory, ie `artifacts/File.exe_analyzed`
        workspace = os.path.join(root, filename + "_analyzed")

        # if already analyzed before, return path without recreating workspace
        # TODO: useful for testing, remove after
        if os.path.exists(workspace):
            return os.path.join(workspace, filename)

        # create the directory if it doesn't exist
        os.mkdir(workspace)

        # create its underlying components
        os.mkdir(os.path.join(workspace, "unpacked"))
        os.mkdir(os.path.join(workspace, "recovered"))

        # create a metadata.json file
        os.mknod(os.path.join(workspace, "metadata.json"))

        # return the name of the workspace plus binary for user to interact with
        return os.path.join(workspace, filename)


    #============================
    # Socket.io Channel Callbacks
    #============================

    def on_identify(self):
        """
        Server-side message handler when requested to parse out file information from the
        filename stored
        """
        self.emit("identify_reply", { "is_malware": False })


    def on_unpack(self):
        """
        Server-side message handler to call unpacker routine against the executable stored
        in the workspace.
        """
        self.emit("unpack_reply")


    def on_finalize(self):
        """
        Finalizes the analysis execution, write all results back into config.json
        """
        pass
