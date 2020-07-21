"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    Consumes a target, reads it from a mounted storage system, and

"""
import time
import io
import os
import uuid
import pefile
import datetime
import hashlib
import flask_socketio as sio

import boa.core.unpack as unpack

class WorkerException(Exception):
    """ Exception that gets raised with a displayed error message when worker fails """
    pass


class BoaWorker(sio.Namespace):
    """
    Represents a stateful worker that consumes a checked Python-compiled executable path,
    instantiates a workspace, performs the necessary analysis workflow and implements handlers
    for WebSocket connections requesting functionality.
    """

    def __init__(self, name, root, input_file) -> None:

        # sanity-check: do not instantiate if PE is malformed
        filecontent = input_file.read()
        try:
            _ = pefile.PE(data=filecontent)
        except pefile.PEFormatError:
            raise WorkerException("Malformed PE file! Cannot parse.")

        # store copy of file object in-memory for analysis workflow
        self.filecontent = filecontent

        # if a valid executable, then start creating valid metadata for it
        self.name = name
        self.timestamp = datetime.datetime.utcnow
        self.uuid = uuid.uuid1()

        # store file's checksum to check against for file uniquity
        hasher = hashlib.sha256()
        for block in iter(lambda: input_file.read(4096), b""):
            hasher.update(block)
        self.checksum = hasher.hexdigest()

        # instantiate new workspace directory
        self.workspace = BoaWorker.init_workspace(root, self.name)

        # include path to binary in workspace as well, and save
        self.path = os.path.join(self.workspace, self.name)
        input_file.save(self.path)

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
        Server-side message handler used to identify the packer for the specific exeutable
        in context. If not failed, return error to stop analysis flow.
        """

        # identify the packer that was used to compile the binary
        if unpack.is_py2exe(self.filecontent):
            self.packer = "py2exe"
        elif unpack.is_pyinstaller(self.filecontent):
            self.packer = "pyinstaller"

        # delete workspace created since the packer is unknown
        else:
            self.packer = None
            shutil.rmtree(self.workspace)

        # flag is set to continue execution if packer is identified
        cont = self.packer != None
        self.emit("identify_reply", { "packer": self.packer, "continue": cont })


    def on_unpack(self):
        """
        Server-side message handler to call unpacker routine against the executable stored
        in the workspace.
        """
        time.sleep(5)
        self.emit("unpack_reply", { "continue": False })


    def on_finalize(self):
        """
        Finalizes the analysis execution, write all results back into config.json
        """
        pass
