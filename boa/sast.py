"""
sast.py

    Given properly decompiled files from bytecode, apply static analysis to the
    source using the Bandit security QA checker.
"""

from bandit.core import manager


class SASTEngine(object):
    """
    A SASTEngine defines the necessary functionality needed in order to
    run static analysis checks upon parsed out Python code in order to identify bugs
    and potential vulnerabilities for exploitation.
    """

    def __init__(self, codebase, ignore_nosec=False):
        """
        self.manager = manager.BanditManager(b_conf, args.agg_type, args.debug,
                                profile=profile, ignore_nosec=ignore_nosec)
        """
        pass

    def scan_vulns(self) -> int:
        """
        Runs the bandit manager, and store generated metrics for parsing and return.
        """

        # see if targets can be found
        self.manager.discover_files(args.targets, args.recursive, args.excluded_paths)
        if not self.manager.b_ts.tests:
            raise Exception("No tests can be run.")

        # run tests using bandit and internally store results
        self.manager.run_tests()

    def dump_results(self, high_sev_only=False):
        """
        Parse out the results, and return something that can be consumed into a report.
        """
        pass
