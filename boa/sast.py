"""
sast.py

    Given properly decompiled files from bytecode, apply static analysis to the
    source using the Bandit security QA checker.
"""
import os
import json
import tempfile

from bandit.core import manager, config


class SASTEngine(object):
    """
    A SASTEngine defines the necessary functionality needed in order to
    run static analysis checks upon parsed out Python code in order to identify bugs
    and potential vulnerabilities for exploitation.
    """

    def __init__(self, ignore_nosec=False):
        conf = config.BanditConfig()
        self.manager = manager.BanditManager(conf, None, ignore_nosec=ignore_nosec)


    def scan_vulns(self, codebase):
        """
        Runs the bandit manager, and store generated metrics for parsing and return.
        """

        # see if targets can be found
        self.manager.discover_files(codebase)
        if not self.manager.b_ts.tests:
            raise Exception("No tests can be run.")

        # run tests using bandit and internally store results
        self.manager.run_tests()


    def dump_results(self, high_sev_only=False):
        """
        Parse out the results, and return something that can be consumed into a report.
        """
        tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.manager.output_results(1, "HIGH", "HIGH", tmp, "json")

        # reopen file, since bandit closes it, and load as dict for return
        with open(tmp.name, "r") as fd:
            data = dict(json.loads(fd.read()))

        # delete the temporary file manually now
        os.remove(tmp.name)
        return data
