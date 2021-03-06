#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching either the standalone executable, or the
    webapp service.
"""
import os
import sys

import boa.argparse as argparse


@argparse.subcommand(
    [argparse.argument("executable", help="Path to Python-compiled executable to reverse engineer.")]
)
def identify(args):
    """ Gathers information about a sample without fully reverse engineering it. """
    app = args.executable


@argparse.subcommand(
    [argparse.argument("bytecode", multiple=True, type=list, help="Path to bytecode file(s) or directory with bytecode files.")]
)
def decompile(args):
    """ Given bytecode files, patch and decompile them back into original Python source code. """
    bytecode_files = args.bytecode


@argparse.subcommand(
    [argparse.argument("executable", help="Path to Python-compiled executable to reverse engineer.")]
)
def reverse(args):
    """ Subcommand to attempt to fully reverse engineering a target executable """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1


def main():
    argparse.parse_args()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
