"""
worker.py

    Implements the main execution functionality of the reverse engineering pipeline for Boa.
    A worker first consumes a binary path, validates it, and instantiates a workspace for it in the
    storage medium. The executable is then unpacked, decompiled and patched.

"""
import os
import time
import uuid
import shutil
import json
import datetime
import hashlib
import typing as t

import pefile
from flask import current_app
from flask_sse import sse

from boa import models, config, utils
from boa.core import unpack, decompile, sast


class WorkerException(Exception):
    """ Exception that gets raised with a displayed error message when worker fails """


class BoaWorker:
    """
    Represents a stateful worker that consumes a checked Python-compiled executable path,
    instantiates a workspace, performs the necessary analysis workflow and implements handlers
    for WebSocket connections requesting functionality.
    """

    def __init__(self, name, root, input_file):

        # sanity-check: do not instantiate if PE is malformed
        filecontent = input_file.read()
        try:
            _ = pefile.PE(data=filecontent)
        except pefile.PEFormatError:
            raise WorkerException("Is not a valid PE/EXE file! Cannot parse.")

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

        # parsed out information regarding the executable

        # python version
        self.pyver: int = 0

        # packer object used to generate final executable
        self.packer: t.Optional[unpack.BaseUnpacker] = None

        # stores parsed paths to bytecode files
        self.bytecode_paths: t.List[str] = []

        # decompiler object used to recover source code
        self.decompiler: t.Optional[decompile.BoaDecompiler] = None

        # stores recovered source files that are relevant for analyze
        self.relevant_src = []

        # parsed out security issues from bandit
        self.sec_issues = {}

        # stores any errors parsed out during execution
        self.error = None

        # push event to represent new task initializing
        sse.publish({"uuid": self.uuid}, type="events")

    @staticmethod
    def check_existence(checksum: str) -> t.Optional[str]:
        """
        Given a file's checksum, check if it has already been analyzed before, and return the
        report UUID if found
        """
        queries = models.Scan.query.all()
        for query in queries:
            if query.checksum == checksum:
                return query.uuid

        return None

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

        # return if previously created. Anything that persists on disk has failed.
        if os.path.exists(workspace):
            shutil.rmtree(workspace)

        # create the directory if it doesn't exist
        os.mkdir(workspace)

        # create its underlying components
        os.mkdir(os.path.join(workspace, "unpacked"))
        os.mkdir(os.path.join(workspace, "recovered"))

        # create a metadata.json file
        os.mknod(os.path.join(workspace, "metadata.json"))

        # return the name of the workspace plus binary for user to interact with
        return workspace

    def identify(self):
        """
        Server-side message handler used to identify and instantiate the packer for
        the executable in context. If parsing and instantiating failed, return error
        to stop analysis flow.
        """

        # first, check if the file already exists in our database
        # if not config.BaseConfig.DEBUG_MODE:
        uid = BoaWorker.check_existence(self.checksum)
        if uid is not None:
            sse.publish({"link": "/report/" + uuid, "error": None}, type="events")
            return

        # info parsed out: version
        self.pyver = None

        # identify the packer that was used to compile the binary given a path,
        # and error-handle appropriately by creating error if
        try:
            self.packer = unpack.get_packer(self.path)
            self.pyver = self.packer.pyver
        except Exception as err:
            self.packer = None
            self.error = str(err)

        # TODO: identify if the sample is malware from Virustotal API scan

        # delete workspace created if the packer is unknown
        if self.packer is None:
            shutil.rmtree(self.workspace)

        # send back payload to UI with appropriate response
        sse.publish(
            {"packer": str(self.packer), "error": self.error},
            type="events",
        )

    def unpack(self):
        """
        Server-side message handler to call unpacker routine against the executable stored
        in the workspace.
        """

        # start unpacking into the workspace directory
        unpacked_dir = os.path.join(self.workspace, "unpacked")
        try:
            self.bytecode_paths = self.packer.unpack(unpacked_dir)
        except Exception as err:
            self.error = str(err)

        # delete workspace if unpacking failed at some point
        if self.error:
            shutil.rmtree(self.workspace)

        # get rid of binary on server at this point, we don't want live malware or big files.
        os.remove(self.path)

        # add a bit of latency since this is pretty quick
        time.sleep(1)
        sse.publish(
            {
                "extracted": len(self.bytecode_paths),
                "error": self.error,
            },
            type="events",
        )

    def decompile(self):
        """
        Server-side message handler to interface our decompiler abstraction to
        decompile the bytecode source that has been recovered from unpacking.
        """

        # throw error if no bytecode to parse
        # TODO: otherwise go straight to final report
        if len(self.bytecode_paths) == 0:
            self.error = "No bytecode to decompile!"

        # otherwise instantiate decompiler and start recovering source
        else:
            try:
                self.decompiler = decompile.BoaDecompiler(
                    self.pyver, self.bytecode_paths
                )
                self.relevant_src = self.decompiler.decompile_all(self.workspace)

            # exception must be thrown if absolutely no decompilation can be done
            except Exception as err:
                self.error = str(err)

        # delete workspace if decompilation absolutely cannot be done
        if self.error:
            shutil.rmtree(self.workspace)

        # send back response with num of files decompiled
        sse.publish(
            {
                "src_files": len(self.relevant_src),
                "error": self.error,
            },
            type="events",
        )

    def sast(self):
        """
        Runs a `SASTEngine` against all the recovered source files and parse out all potential
        security issues. Issues support leaked secrets and python code quality assurance.

        TODO: be configured not to run if we don't care.
        """

        # instantiate an engine to conduct code scanning
        engine = sast.SASTEngine()
        engine.scan_vulns(self.relevant_src)

        # stores a mapping between a file-line id (as a tuple) and the issue thats being reported
        self.sec_issues = engine.dump_results()

        # send back response with number of potential bugs found
        sse.publish(
            {"issues_found": len(self.sec_issues["results"]), "error": self.error},
            type="events",
        )

    def finalize(self):
        """
        Finalizes the execution of the analysis, commiting the parsed out information from each step
        to a `metadata.json` file for the
        """

        # stores metadata content for later report generation
        metadata = {
            "py_info": {
                "Python Version": self.pyver,
                "Packer / Installer": str(self.packer),
                "Estimated # of Dependencies": len(self.decompiler.total_deps),
            },
            "dependencies": list(self.decompiler.total_deps),
            "reversing": {
                "Archive (.pyz) Files": self.packer.pyz_len,
                "Bytecode (.pyc) Files": len(self.bytecode_paths),
                "Relevant Source Files Decompiled": len(self.relevant_src),
            },
            "srcfiles": [os.path.basename(srcfile) for srcfile in self.relevant_src],
            "audit": self.sec_issues,
        }

        # finalize and write metadata.json to local path for storing in bucket
        metadata_path = os.path.join(self.workspace, "metadata.json")
        metadata_content = json.dumps(dict(metadata))
        with open(metadata_path, "w") as mdata:
            mdata.write(metadata_content)

        # commit as "key file" to bucket, if not in development build
        if not current_app.config["DEBUG"]:
            bucket_key = self.uuid + "/metadata.json"
            with open(metadata_path, "rb") as mdata:
                _ = utils.upload_file(mdata, bucket_key)

        # zip up folder and commit zipped contents to S3
        zip_path = utils.zipdir(self.workspace)

        # if production, commit to S3 and save url, other save path
        if not current_app.config["DEBUG"]:
            zip_key = self.uuid + "/analyzed.zip"
            with open(zip_path, "rb") as zipf:
                zip_url = utils.upload_file(zipf, zip_key)
        else:
            zip_url = zip_path

        # delete the path to the zipped file and entire workspace once it's uploaded
        os.remove(zip_path)
        shutil.rmtree(self.workspace)

        # create scan entry
        scan = models.Scan(
            self.name,
            self.uuid,
            self.checksum,
            self.timestamp,
            bucket_key,
            zip_url,
        )
        scan.with_stats(len(self.relevant_src), len(metadata["audit"]["results"]))

        # commit to database
        models.db.session.add(scan)
        models.db.session.commit()

        # send the finalized report link back to the user once everything is committed
        sse.publish({"link": "/report/" + str(self.uuid)}, type="events")
