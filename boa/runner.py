"""
runner.py
"""
import io
import os
import sys
import hashlib
import contextlib
import typing as t

import lief
import ssdeep
import requests

from boa.unfreeze import get_installer
from boa.unpack import get_packer


@contextlib.contextmanager
def stdout_redirected(to=os.devnull):
    fd = sys.stdout.fileno()

    def _redirect_stdout(to):
        sys.stdout.close()  # + implicit flush()
        os.dup2(to.fileno(), fd)  # fd writes to 'to' file
        sys.stdout = os.fdopen(fd, "w")  # Python writes to fd

    with os.fdopen(os.dup(fd), "w") as old_stdout:
        with open(to, "w") as file:
            _redirect_stdout(to=file)
        try:
            yield  # allow code to be run with the redirected stdout
        finally:
            _redirect_stdout(to=old_stdout)


def run_detect(data: bytes) -> t.Dict[str, str]:
    """ Parses out preliminary informational for either web or cli """

    # stores parsed information for display
    info: t.Dict[str, str] = {}

    with stdout_redirected():
        binary = lief.parse(raw=data)
        if isinstance(binary, lief.PE.Binary):
            info["Executable Format"] = "PE/EXE"
        elif isinstance(binary, lief.ELF.Binary):
            info["Executable Format"] = "ELF"
        elif isinstance(binary, lief.MachO.Binary):
            info["Executable Format"] = "Mach-O"

    # generate table of hashes useful for analyst
    hashes: t.Dict[str, str] = {}
    hashes["MD5"] = hashlib.md5(data).hexdigest()
    hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    hashes["Similiarity Hash (ssdeep)"] = ssdeep.hash(data)

    # VT checks are optional, and only occur if $VT_API is set
    vt_api: t.Optional[str] = os.environ.get("VT_API")
    if vt_api:
        params = {"apiKey": vt_api}
        files = {"file": binary}
        resp = requests.post(
            "https://www.virustotal.com/vtapi/v2/file/scan", files=files, params=params
        )
        print(resp.json())

    return hashes


def run_unpack_routine(app: str, out_dir=None) -> int:
    """ Implements functionality for detecting any unpackers and extrapolating resources """

    # detect executable packing
    up = get_packer(app)
    if up is None:
        print("Didn't detect any executable packing with the target executable.")
    else:
        with up as unpacker:
            pass

    # instantiate unfreezer
    unfreezer = get_installer(app)
    if unfreezer is None:
        print("Unable to detect the installer used to freeze the executable.")
        return 1

    with unfreezer:
        pyver: t.Optional[float] = unfreezer.parse_pyver()
        if pyver is None:
            print("Unable to determine Python version for this.")
            return 1

        print(f"Compiled with Python version: {pyver}")
        print(f"Detected installer: {unfreezer}", end=" ")

        # get potential version of installer used
        version: t.Optional[float] = unfreezer.parse_version()
        if not version is None:
            print(f"{version}")

        # given the output dir, run the unpacking routine
        unfreezer.thaw(out_dir)

    # TODO: get potential paths to entry points
    print(f"\nDone unpacking all resources to `{out_dir}`")
    return 0
