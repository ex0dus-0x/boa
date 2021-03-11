#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import sys
import typing as t

import boa.argparse as argparse

from boa.core import unpack
from boa.core.decompile import BoaDecompiler


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to Python-compiled executable to reverse engineer."
        ),
        argparse.argument(
            "-j",
            "--json",
            help="Output detection results in JSON."
        )
    ]
)
def detect(args):
    """ Given a target executable, gather metadata about a sample without fully reverse engineering it. """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # detect executable packing

    # detect Python-specific packing


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to packed executable to unpack and dissect apart."
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            help="Path to store unpacked resources in (default is `{executable}_out`)."
        ),
    ]
)
def unpack(args):
    """ Given a packed target executable, do both generic executable unpacking (if detected) and Python-specific unpacking. """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # output path or set default
    out_dir = f"{app}_out" if not args.out_dir else args.out_dir


@argparse.subcommand(
    [
        argparse.argument(
            "--bytecode_files",
            nargs="+",
            help="Path to bytecode file(s) for decompilation.",
        ),
        argparse.argument(
            "--bytecode_dir",
            help="Path to workspace with bytecode files for decompilation.",
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            type=str,
            default="out",
            help="Workspace where multiple decompiled source files are all stored (default is `out`).",
        ),
    ]
)
def decompile(args):
    """ Given bytecode files, patch and decompile them back into original Python source code. """

    bfiles = args.bytecode_files
    bdir = args.bytecode_dir

    # either specific files or a directory, not both
    if bfiles and bdir:
        print("Specify either `--bytecode_files` or `--bytecode_dir` but not both.")
        return 1
    
    # bytecode files that are parsed out
    bytecode: t.List[str] = []
    if bfiles:
        bytecode = [
            bfile
            for bfile in bfiles
            if os.path.exists(bfile) and bfile.endswith(".pyc")
        ]

    elif args.bytecode_dir:
        if not os.path.exists(bdir):
            print("Workspace with bytecode files does not exist.")
            return 1

        bytecode = [
            os.path.join(bdir, bfile)
            for bfile in os.listdir(bdir)
            if bfile.endswith(".pyc")
        ]

    # instantiate decompiler
    decomp = BoaDecomiler(bytecode)

    
@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to Python-compiled executable to reverse engineer."
        )
    ]
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
