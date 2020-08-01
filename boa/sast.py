"""
sast.py

    Given properly decompiled files from bytecode, apply static analysis to the
    source in the following way:

        1. Check for secrets.
        2. Use Python's `bandit` to do security linting and QA.
"""

class SASTEngine(object):
    """
    A SASTEngine defines the necessary functionality needed in order to
    run static analysis checks upon parsed out Python code in order to identify bugs
    and potential vulnerabilities for exploitation.
    """

    def __init__(self, codebase):
        pass

    def scan_secrets(self) -> int:
        pass

    def scan_vulns(self) -> int:
        pass

    def dump_results(self, high_sev_only=False):
        pass
