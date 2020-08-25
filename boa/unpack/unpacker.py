"""
unpacker.py

    Defines a base class used by all packers in order to keep consistent
    across the API definitions. This is still a WIP.

"""

class BaseUnpacker(object):
    """
    Defines a base unpacker class to inherit from for all variants of
    packers used for the Python executable distribution ecosystem.
    """

    def __init__(self, path: str):
        self.filepath = path

        # defines how many pyz files recovered
        self.pyz_len = 0

        # includes path to all bytecode files
        self.bytecode_paths = []

    def __str__(self):
        pass

    def get_py_version(self):
        """ Implements functionality to parse out the Python interpreter version """
        raise NotImplementedError()

    def unpack(self, unpack_dir: str):
        """ Implements the actual process of unpacking PYZ archive files and resources """
        raise NotImplementedError()
