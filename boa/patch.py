"""
patch.py

    Provides helper facilities to help patch parsed bytecode, and maintain constants for
    built-in modules that we don't want to reverse.
"""
import time
import struct
import typing as t

# Contains magic number for each Python version, which we'll use for a bytecode header
MAGIC_NUMBERS: t.Dict[float, t.List[int]] = {
    1.5: [20121],
    1.6: [50428],
    2.0: [50823],
    2.1: [60202],
    2.2: [60717],
    2.3: [62011],
    2.4: [62041],
    2.5: [62071, 62081, 62091, 62092, 62101, 62111, 62121, 62131],
    2.6: [62151, 62161],
    2.7: [62171, 62181, 62191, 62201, 62211],
    3.0: [3111, 3131],
    3.1: [3141, 3151],
    3.2: [3160, 3170],
    3.2: [3180],
    3.3: [3190, 3200, 3210, 3220, 3230],
    3.4: [3250, 3260, 3270, 3280, 3290, 3300, 3310],
    3.5: [3320, 3330, 3340, 3350, 3351],
    3.6: [3360, 3361, 3370, 3371, 3372, 3373, 3375, 3376, 3377, 3378, 3379],
    3.7: [3390, 3391, 3392, 3393, 3394],
    3.8: [3400, 3401, 3410, 3411, 3412, 3413],
    3.9: [3420, 3421, 3422, 3423, 3424, 3425],
}


def generate_magic(version: float) -> t.List[bytes]:
    """ Given a version, returns all possible magic numbers """
    if version not in MAGIC_NUMBERS:
        raise Exception("Version not supported for magic header generation")

    return [
        struct.pack(b"Hcc", magic, b"\r", b"\n") for magic in MAGIC_NUMBERS[version]
    ]


def generate_timestamp() -> bytes:
    return struct.pack(b"=L", int(time.time()))


def generate_source_size(size: int) -> bytes:
    return struct.pack(b"=L", int(size))
