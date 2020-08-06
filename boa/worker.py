"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    A worker first consumes a binary path, validates it, and instantiates a workspace for it in the
    storage medium. The executable is then unpacked, decompiled and patched.

"""
import io
import os
import time
import uuid
import shutil
import pefile
import json
import datetime
import hashlib

import flask_socketio as sio
import flask_sqlalchemy as fsql

import boa.unpack as unpack
import boa.decompile as decompile
import boa.sast as sast
import boa.models as models

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

        # if a valid executable, then start creating valid metadata for it
        self.name = name
        self.timestamp = str(datetime.datetime.utcnow())
        self.uuid = str(uuid.uuid4())

        # store file's checksum to check against for file uniquity
        hasher = hashlib.sha256()
        for block in iter(lambda: input_file.read(4096), b""):
            hasher.update(block)
        self.checksum = hasher.hexdigest()

        # instantiate new workspace directory
        self.workspace = BoaWorker.init_workspace(root, self.name)

        # include path to binary in workspace as well
        self.path = os.path.join(self.workspace, self.name)

        # move file pointer back to beginning, and save
        input_file.stream.seek(0)
        input_file.save(self.path)

        # stores any errors parsed out during execution
        self.error = None

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
        Server-side message handler used to identify and instantiate the packer for the specific exeutable
        in context. If parsing and instantiating failed, return error to stop analysis flow.
        """

        # info parsed out: version
        self.pyver = None

        # identify the packer that was used to compile the binary given a path,
        # and error-handle appropriately by creating error if
        try:
            self.packer = unpack.get_packer(self.path)
            self.pyver = self.packer.pyver
        except Exception as e:
            self.packer = None
            self.error = str(e)

        # delete workspace created if the packer is unknown
        cont = self.packer != None
        if not cont:
            shutil.rmtree(self.workspace)

        # send back payload to UI with appropriate response
        self.emit("identify_reply", {
            "packer": str(self.packer),
            "continue": cont,
            "error": self.error
        })


    def on_unpack(self):
        """
        Server-side message handler to call unpacker routine against the executable stored
        in the workspace.
        """

        # stores bytecode paths parsed out
        self.bytecode_paths = []

        # start unpacking into the workspace directory
        unpacked_dir = os.path.join(self.workspace, "unpacked")
        try:
            self.bytecode_paths = self.packer.unpack(unpacked_dir)
        except Exception as e:
            self.error = str(e)

        # delete workspace if unpacking failed at some point
        cont = False if self.error else True
        if not cont:
            shutil.rmtree(self.workspace)

        # add a bit of latency since this is pretty quick
        time.sleep(1)
        self.emit("unpack_reply", {
            "extracted": len(self.bytecode_paths),
            "continue": cont,
            "error": self.error
        })


    def on_decompile(self):
        """
        Server-side message handler to interface our decompiler abstraction to
        decompile the bytecode source that has been recovered from unpacking.
        """

        # number of relevant files returned
        self.relevant_src = 0

        # throw error if no bytecode to parse
        # TODO: otherwise go straight to final report
        if len(self.bytecode_paths) == 0:
            self.error = "No bytecode to decompile!"

        # otherwise instantiate decompiler and start recovering source
        else:
            try:
                self.decompiler = decompile.BoaDecompiler(self.pyver, self.bytecode_paths)
                self.relevant_src = self.decompiler.decompile_all(self.workspace)

            # exception must be thrown if absolutely no decompilation can be done
            except Exception as e:
                self.error = str(e)

        # delete workspace if decompilation absolutely cannot be done
        cont = False if self.error else True
        if not cont:
            shutil.rmtree(self.workspace)

        # send back response with num of files decompiled
        self.emit("decompile_reply", {
            "src_files": self.relevant_src,
            "continue": cont,
            "error": self.error
        })


    def on_sast(self):
        """
        Runs a `SASTEngine` against all the recovered source files and parse out all potential security issues.
        Issues support leaked secrets and python code quality assurance.

        TODO: be configured not to run if we don't care.
        """

        # stores a mapping between a file-line id (as a tuple) and the issue thats being reported
        self.sec_issues = {}

        # instantiate an engine to conduct code scanning
        engine = sast.SASTEngine(None)

        # TODO: scan and store results

        # send back response with number of potential bugs found
        self.emit("sast_reply", {
            "error": self.error
        })


    def on_finalize(self):
        """
        Finalizes the execution of the analysis, commiting the parsed out information from each step
        to a `metadata.json` file for the
        """

        # stores metadata content for later report generation
        metadata = {
            "basic": {
                "name": self.name,
                "uuid": self.uuid,
                "checksum": self.checksum,
                "timestamp": self.timestamp,
            },
            "py_info": {
                "version": self.pyver,
                "packer": str(self.packer),
                "total_deps": len(self.decompiler.total_deps),
                "dependencies": list(self.decompiler.total_deps),
            },
            "reversing": {
                "pyz": self.packer.pyz_len,
                "pyc": len(self.bytecode_paths),
                "src": self.relevant_src,
            },
            "audit": self.sec_issues,
        }

        # finalize and write to path
        metadata_content = json.dumps(dict(metadata))
        with open(os.path.join(self.workspace, "metadata.json"), "w") as fd:
            fd.write(metadata_content)

        # commit entry to database

        # send the finalized report link back to the user once everything is committed
        self.emit("finalize_reply", {
            "link": "/report/" + str(self.uuid)
        })
