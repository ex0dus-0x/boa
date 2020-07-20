"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    Consumes a target, reads it from a mounted storage system, and

"""
import io
import os
import uuid
import flask_socketio as sio

import boa.core.unpack as unpack

class WorkerException(Exception):
    pass


class BoaWorker(sio.Namespace):
    """
    Represents a stateful worker that consumes a checked Python-compiled executable path,
    instantiates a workspace, performs the necessary analysis workflow and implements handlers
    for WebSocket connections requesting functionality.
    """


    def __init__(self, name, root, input_file) -> None:

        # first save the file to a temporary in-memory file object for sanity-checks
        # before even bothering storing to a workspace
        filecontent = io.BytesIO()
        input_file.save(filecontent)

        # sanity-check: get the original packer, or cleanup and throw exception
        if unpack.is_py2exe(filecontent.read()):
            self.packer = "py2exe"
        elif unpack.is_pyinstaller(filecontent.read()):
            self.packer = "pyinstaller"
        else:
            filecontent.close()
            raise WorkerException("Unable to determine the Python-based packer used!")

        # if a valid executable, create some valid metadata for it
        self.name = name
        self.timestamp = ""
        self.file_checksum = ""
        self.uuid = uuid.uuid1()

        # instantiate new workspace directory
        self.workspace = BoaWorker.init_workspace(root, self.name)

        # also include path to workspace and binary for convenience
        self.path = os.path.join(self.workspace, self.name)

        # initialize base object with no namespace identifier
        super().__init__()


    @staticmethod
    def init_workspace(root: str, name: str) -> str:
        """
        Given an input sample to analyze, create a workspace with the following structure:

        dir_name/
            - config.json
            - unpacked/
            - recovered/
        """

        # construct the path to the workspace directory, ie `artifacts/File.exe_analyzed`
        workspace = os.path.join(root, name + "_analyzed")

        # if already analyzed before, return path without recreating workspace
        # TODO: useful for testing, remove after
        if os.path.exists(workspace):
            return workspace

        # create the directory if it doesn't exist
        os.mkdir(workspace)

        # create its underlying components
        os.mkdir(os.path.join(workspace, "unpacked"))
        os.mkdir(os.path.join(workspace, "recovered"))

        # create a metadata.json file
        os.mknod(os.path.join(workspace, "metadata.json"))

        # return the name of the workspace plus binary for user to interact with
        return workspace


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
