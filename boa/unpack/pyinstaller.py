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
    """ Defines a entry from the parsed table of contents """

    def __init__(
        self,
        position,
        cmprs_data_size,
        uncmprs_data_size,
        cmprs_flag,
        type_cmprs_data,
        name,
    ):
        self.position = position
        self.cmprs_data_size = cmprs_data_size
        self.uncmprs_data_size = uncmprs_data_size
        self.cmprs_flag = cmprs_flag
        self.type_cmprs_data = type_cmprs_data
        self.name = name


class PyInstaller:
    """
    Implements unpacker for PyInstaller based applications, parsing out the ToC from a given
    PE executable, and recovering all Python archives from entries.
    """

    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b"MEI\014\013\012\013\016"  # Magic number which identifies pyinstaller

    def __str__(self):
        return "PyInstaller"

    def __init__(self, path):

        # get file pointer and size for further interaction
        self.file = open(path, "rb")
        self.file_size = os.stat(path).st_size

        # try to figure out the version of Pyinstaller used
        self.version = 0

        # Check for pyinstaller 2.0 before bailing out
        self.file.seek(self.file_size - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        file_magic = self.file.read(len(self.MAGIC))
        if file_magic == self.MAGIC:
            self.version = 20
            self.file.seek(self.file_size - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

            (_, pkg_len, toc, toc_len, self.pyver) = struct.unpack(
                "!8siiii", self.file.read(self.PYINST20_COOKIE_SIZE)
            )

        # Check for pyinstaller 2.1+ before bailing out
        self.file.seek(self.file_size - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        file_magic = self.file.read(len(self.MAGIC))
        if file_magic == self.MAGIC:
            self.version = 21
            self.file.seek(self.file_size - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)

            (
                _,
                pkg_len,
                toc,
                toc_len,
                self.pyver,
                _,
            ) = struct.unpack("!8siiii64s", self.file.read(self.PYINST21_COOKIE_SIZE))

        # if no version parsed out, return an exception
        if self.version == 0:
            raise Exception(
                "Cannot determine PyInstaller version. Works with 2.0/2.1+."
            )

        # Overlay is the data appended at the end of the PE
        overlay_pos = self.file_size - pkg_len
        toc_pos = overlay_pos + toc
        toc_size = toc_len

        # Go to the table of contents
        self.file.seek(toc_pos, os.SEEK_SET)

        # Parse out all file entries for the table of contents
        self.toc_list = []
        parsed_len = 0
        while parsed_len < toc_size:
            (entry_size,) = struct.unpack("!i", self.file.read(4))
            name_len = struct.calcsize("!iiiiBc")

            (
                entry_pos,
                cmprs_data_size,
                uncmprs_data_size,
                cmprs_flag,
                type_cmprs_data,
                name,
            ) = struct.unpack(
                "!iiiBc{0}s".format(entry_size - name_len),
                self.file.read(entry_size - 4),
            )

            # give arbitrary name to file if unamed
            name = name.decode("utf-8").rstrip("\0")
            if len(name) == 0:
                name = str(uuid.uuid4())

            # append new entry of filename to parse
            self.toc_list.append(
                CTOCEntry(
                    overlay_pos + entry_pos,
                    cmprs_data_size,
                    uncmprs_data_size,
                    cmprs_flag,
                    type_cmprs_data,
                    name,
                )
            )
            parsed_len += entry_size

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
        for entry in self.toc_list:

            # hacky: make paths Unix-friendly
            entry_name = entry.name.replace("\\", "/")

            # check and instantiate if doesn't exist
            base_path = os.path.dirname(entry_name)
            if base_path != "":
                # Check if path exists, create if not
                if not os.path.exists(base_path):
                    os.makedirs(base_path)

            # go to the specific entries position in file and extract out
            self.file.seek(entry.position, os.SEEK_SET)
            data = self.file.read(entry.cmprs_data_size)

            if entry.cmprs_flag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprs_data_size  # Sanity Check

            # write to directory
            with open(entry_name, "wb") as dirpath:
                dirpath.write(data)

            # check if PYZ file to be extracted
            if entry.type_cmprs_data == b"z":
                self._extract_pyz(entry_name)

        # revert and return paths to bytecode
        os.chdir(curr_dir)
        return self.bytecode_paths

    def _extract_pyz(self, name):
        """
        Helper utility to help extract PYZ files into bytecode files in its seperate directory.
        """

        # Create a directory for the contents of the pyz
        dirname = name + "_extracted"
        if not os.path.exists(dirname):
            os.mkdir(dirname)

        # parse out all the bytecode, and store paths for return
        with open(name, "rb") as bfile:

            # sanity check the magic number
            pyz_magic = bfile.read(4)
            if pyz_magic != b"PYZ\0":
                raise Exception("Found an invalid PYZ file.")

            # TODO: differing versions, but should be ok
            pyc_header = bfile.read(4)

            # read out and marshal bytecode files
            (toc_position,) = struct.unpack("!i", bfile.read(4))
            bfile.seek(toc_position, os.SEEK_SET)
            toc = marshal.load(bfile)

            # store number of pyz files parsed
            self.pyz_len = len(toc)

            # From pyinstaller 3.1+ toc is a list of tuples
            if isinstance(toc, list):
                toc = dict(toc)

            for key in toc.keys():
                (_, pos, length) = toc[key]
                bfile.seek(pos, os.SEEK_SET)

                filename = key
                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    filename = key.decode("utf-8")
                except Exception:
                    pass

                # Make sure destination directory exists, ensuring we keep inside dirname
                destname = os.path.join(dirname, filename.replace("..", "__"))
                destdirname = os.path.dirname(destname)
                if not os.path.exists(destdirname):
                    os.makedirs(destdirname)

                # if anything errors when attempting to read, assume its encrypted and write as is
                try:
                    data = bfile.read(length)
                    data = zlib.decompress(data)
                except Exception:
                    with open(destname + ".pyc.encrypted", "wb") as encfile:
                        encfile.write(data)
                    continue

                # finalize the pyc file if valid
                dest = destname + ".pyc"
                with open(dest, "wb") as pycfile:
                    pycfile.write(pyc_header)  # Write pyc magic
                    pycfile.write(b"\0" * 12)  # Write timestamp
                    # if self.pyver >= 33:
                    #    pycfile.write(b'\0' * 4)  # Size parameter added in Python 3.3
                    pycfile.write(data)

                # add valid pyc path
                self.bytecode_paths += [dest]

            # done with executable, close file
            self.file.close()
