"""
pyinstaller.py

    Implements an unpacker for PyInstaller-compiled executables,
    based on the previous work done by Extreme Coder's pyintxtractor

    Original Author : Extreme Coders
    URL : https://sourceforge.net/projects/pyinstallerextractor/
"""

import os
import zlib
import sys
import types
import uuid
import struct
import marshal


class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstaller:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller


    def __str__(self):
        return "PyInstaller"


    def __init__(self, path):

        # get file pointer and size for further interaction
        self.file = open(path, 'rb')
        self.fileSize = os.stat(path).st_size

        # parse out PyInstaller version
        self.file.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.file.read(len(self.MAGIC))
        if magicFromFile == self.MAGIC:

            # set version as 2.0, and parse out CArchive cookie to get other info
            self.version = 20
            self.file.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

            (magic, lengthofPackage, toc, tocLen, self.pyver) = \
            struct.unpack('!8siiii', self.file.read(self.PYINST20_COOKIE_SIZE))


        # Check for pyinstaller 2.1+ before bailing out
        self.file.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.file.read(len(self.MAGIC))
        if magicFromFile == self.MAGIC:

            # set version as 2.1+, and parse out CArchve cookie to get other info
            self.version = 21
            self.file.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)

            (magic, lengthofPackage, toc, tocLen, self.pyver, pylibname) = \
            struct.unpack('!8siiii64s', self.file.read(self.PYINST21_COOKIE_SIZE))

        # if no version parsed out, return an exception
        if not getattr(self, "version"):
            raise Exception("Cannot determine PyInstaller version. Works with 2.0/2.1+.")


        # Overlay is the data appended at the end of the PE
        overlayPos = self.fileSize - lengthofPackage
        tocPos = overlayPos + toc
        tocSize = tocLen

        # Go to the table of contents
        self.file.seek(tocPos, os.SEEK_SET)

        # Parse out table of contents
        self.tocList = []
        parsedLen = 0
        while parsedLen < tocSize:
            (entrySize, ) = struct.unpack('!i', self.file.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!iiiBc{0}s'.format(entrySize - nameLen), \
                self.file.read(entrySize - 4))

            # give arbitrary name to file if unamed
            name = name.decode('utf-8').rstrip('\0')
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
                    name
            ))
            parsedLen += entrySize


    def unpack(self):
        """
        Given a parsed out table of contents
        """
        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            self.file.seek(entry.position, os.SEEK_SET)
            data = self.file.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check

            with open(entry.name, 'wb') as f:
                f.write(data)

            if entry.typeCmprsData == b'z':
                self._extractPyz(entry.name)


    def _extractPyz(self, name):
        dirName =  name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' # Sanity Check

            pycHeader = f.read(4) # Python magic value

            # TODO: differing versions, but should be ok

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return

            print('[*] Found {0} files in PYZ archive'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)

                fileName = key
                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = key.decode('utf-8')
                except:
                    pass

                # Make sure destination directory exists, ensuring we keep inside dirName
                destName = os.path.join(dirName, fileName.replace("..", "__"))
                destDirName = os.path.dirname(destName)
                if not os.path.exists(destDirName):
                    os.makedirs(destDirName)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(fileName))
                    open(destName + '.pyc.encrypted', 'wb').write(data)
                    continue

                with open(destName + '.pyc', 'wb') as pycFile:
                    pycFile.write(pycHeader)      # Write pyc magic
                    pycFile.write(b'\0' * 4)      # Write timestamp
                    if self.pyver >= 33:
                        pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3
                    pycFile.write(data)
