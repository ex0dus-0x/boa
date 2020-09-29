"""
pyinstaller.py

    Implements an unpacker for PyInstaller-compiled executables,
    based on the previous work done by Extreme Coder's pyintxtractor

    Original Author : Extreme Coders
    URL : https://sourceforge.net/projects/pyinstallerextractor/
"""

import os
import zlib
import uuid
import struct
import marshal


class CTOCEntry:
    def __init__(
        self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name
    ):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstaller:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b"MEI\014\013\012\013\016"  # Magic number which identifies pyinstaller

    def __str__(self):
        return "PyInstaller"

    def __init__(self, path):

        # get file pointer and size for further interaction
        self.file = open(path, "rb")
        self.fileSize = os.stat(path).st_size

        # try to figure out the version of Pyinstaller used
        self.version = 0

        # Check for pyinstaller 2.0 before bailing out
        self.file.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.file.read(len(self.MAGIC))
        if magicFromFile == self.MAGIC:
            self.version = 20
            self.file.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

            (_, lengthofPackage, toc, tocLen, self.pyver) = struct.unpack(
                "!8siiii", self.file.read(self.PYINST20_COOKIE_SIZE)
            )

        # Check for pyinstaller 2.1+ before bailing out
        self.file.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.file.read(len(self.MAGIC))
        if magicFromFile == self.MAGIC:
            self.version = 21
            self.file.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)

            (
                magic,
                lengthofPackage,
                toc,
                tocLen,
                self.pyver,
                pylibname,
            ) = struct.unpack("!8siiii64s", self.file.read(self.PYINST21_COOKIE_SIZE))

        # if no version parsed out, return an exception
        if self.version == 0:
            raise Exception(
                "Cannot determine PyInstaller version. Works with 2.0/2.1+."
            )

        # Overlay is the data appended at the end of the PE
        overlayPos = self.fileSize - lengthofPackage
        tocPos = overlayPos + toc
        tocSize = tocLen

        # Go to the table of contents
        self.file.seek(tocPos, os.SEEK_SET)

        # Parse out all file entries for the table of contents
        self.tocList = []
        parsedLen = 0
        while parsedLen < tocSize:
            (entrySize,) = struct.unpack("!i", self.file.read(4))
            nameLen = struct.calcsize("!iiiiBc")

            (
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData,
                name,
            ) = struct.unpack(
                "!iiiBc{0}s".format(entrySize - nameLen), self.file.read(entrySize - 4)
            )

            # give arbitrary name to file if unamed
            name = name.decode("utf-8").rstrip("\0")
            if len(name) == 0:
                name = str(uuid.uuid4())

            # append new entry of filename to parse
            self.tocList.append(
                CTOCEntry(
                    overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name,
                )
            )
            parsedLen += entrySize

        # other attributes to instantiate for unpacking
        self.pyz_len = 0
        self.bytecode_paths = []

    def unpack(self, unpacked_dir):
        """
        Given a parsed out table of contents, iterate over each file, read it from the
        executable, and write it to the directory. For PYZ files specifically create another
        extracted folder to store bytecode files.

        When finalized, return a list of all bytecode file paths for decompilation.
        """

        # get curr_dir to revert to later
        curr_dir = os.getcwd()

        # go to `workspace/unpacked`
        os.chdir(unpacked_dir)
        for entry in self.tocList:

            # hacky: make paths Unix-friendly
            entry_name = entry.name.replace("\\", "/")

            # check and instantiate if doesn't exist
            basePath = os.path.dirname(entry_name)
            if basePath != "":
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            # go to the specific entries position in file and extract out
            self.file.seek(entry.position, os.SEEK_SET)
            data = self.file.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            # write to directory
            with open(entry_name, "wb") as f:
                f.write(data)

            # check if PYZ file to be extracted
            if entry.typeCmprsData == b"z":
                self._extract_pyz(entry_name)

        # revert and return paths to bytecode
        os.chdir(curr_dir)
        return self.bytecode_paths

    def _extract_pyz(self, name):
        """
        Helper utility to help extract PYZ files into bytecode files in its seperate directory.
        """

        # Create a directory for the contents of the pyz
        dirName = name + "_extracted"
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        # parse out all the bytecode, and store paths for return
        with open(name, "rb") as f:

            # sanity check the magic number
            pyzMagic = f.read(4)
            if pyzMagic != b"PYZ\0":
                raise Exception("Found an invalid PYZ file.")

            # TODO: differing versions, but should be ok
            pycHeader = f.read(4)

            # read out and marshal bytecode files
            (tocPosition,) = struct.unpack("!i", f.read(4))
            f.seek(tocPosition, os.SEEK_SET)
            toc = marshal.load(f)

            # store number of pyz files parsed
            self.pyz_len = len(toc)

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (_, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)

                filename = key
                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    filename = key.decode("utf-8")
                except Exception:
                    pass

                # Make sure destination directory exists, ensuring we keep inside dirName
                destname = os.path.join(dirName, filename.replace("..", "__"))
                destdirname = os.path.dirname(destname)
                if not os.path.exists(destdirname):
                    os.makedirs(destdirname)

                # if anything errors when attempting to read, assume its encrypted and write as is
                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except Exception:
                    with open(destname + ".pyc.encrypted", "wb") as encfile:
                        encfile.write(data)
                    continue

                # finalize the pyc file if valid
                dest = destname + ".pyc"
                with open(dest, "wb") as pycfile:
                    pycfile.write(pycHeader)  # Write pyc magic
                    pycfile.write(b"\0" * 12)  # Write timestamp
                    # if self.pyver >= 33:
                    #    pycfile.write(b'\0' * 4)  # Size parameter added in Python 3.3
                    pycfile.write(data)

                # add valid pyc path
                self.bytecode_paths += [dest]

            # done with executable, close file
            self.file.close()
