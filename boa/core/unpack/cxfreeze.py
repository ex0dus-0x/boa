"""
cxfreeze.py

    Unpacker for cxfreeze-compiled executable. This is very
    simple to do, as we can either

        - Find the associated `library.zip` and dump bytecode to path
        - Attach hook onto `Py_` and do a memory dump from offset with bytecode
"""

from . import BaseUnpacker, UnpackException

class CxFreeze(BaseUnpacker):
    pass
