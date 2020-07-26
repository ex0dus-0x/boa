"""
sast.py

    Given properly decompiled files from bytecode, apply static analysis to the
    source in the following way:

        1. Check for secrets.
        2. Run `bandit` to lint and do security QA.
"""


class SASTEngine(object):
    pass
