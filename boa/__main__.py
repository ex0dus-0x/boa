#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import sys
import typing as t

import boa.argparse as argparse
from boa.core.unpack import get_unpacker
from boa.core.unfreeze import get_installer
from boa.core.decompile import BoaDecompiler

from beautifultable import BeautifulTable


def display_table(header: t.List[str], body: t.List[str]):
    """ Helper for generating and displaying ASCII table """
    table = BeautifulTable()
    table.rows.header = header
    table.columns.append(body)
    print(table)


@argparse.subcommand(
    [
        argparse.argument(
            "executable",
            help="Path to Python-compiled executable to gather information.",
        ),
        argparse.argument("-j", "--json", help="Output detection results in JSON."),
        argparse.argument(
            "--vt_api",
            type=str,
            help="API key used to check sample against VirusTotal.",
        ),
    ]
)
def detect(args):
    """ Given a target executable, gather metadata about a sample without fully reverse engineering it. """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    print("\nBasic Information")
    display_table(["Name", "Executable Format", "Timestamp"], [app, "ELF", "120"])

    print("\nHashing")
    display_table(["MD5", "SHA256", "Similarity"], ["", "", ""])

    print("\nVirusTotal Matches")

    # Python-specific info
    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to packed executable to unpack and dissect apart."
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            help="Path to store unpacked artifacts in (default is `{executable}_out`).",
        ),
    ]
)
def unpack(args):
    """ Given a packed target executable, do both generic executable unpacking (if detected) and Python-specific unpacking. """
    app: str = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # output path or set default
    out_dir: str = f"{app}_out" if not args.out_dir else args.out_dir
    if not os.path.exists(out_dir):
        print("Creating output workspace for storing unpacked resources...")
        os.mkdir(out_dir)

    """
    # detect executable packing
    with get_packer(app) as unpacker:
        pass
    """

    # instantiate unfreezer
    with get_installer(app) as unfreezer:
        if unfreezer is None:
            print("Unable to detect the installer used to freeze the executable.")
            return 1

        # fingerprint packer and Python version
        pyver: t.Optional[float] = unfreezer.parse_pyver()
        if pyver is None:
            raise Exception("Unable to determine Python version for this")

        print(f"Compiled with Python version: {pyver}")
        print(f"Detected installer: {unfreezer}", end=" ")

        # get potential version of installer used
        version: t.Optional[float] = unfreezer.parse_version()
        if not version is None:
            print(f"{version}")

        # given the output dir, run the unpacking routine
        unfreezer.thaw(out_dir)

    print(f"\nDone unpacking all resources to `{out_dir}`")
    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "--bytecode_files",
            nargs="+",
            help="Path to bytecode file(s) for decompilation.",
        ),
        argparse.argument(
            "--bytecode_dir",
            type=str,
            help="Path to workspace with bytecode files for decompilation.",
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            type=str,
            default="decompiled",
            help="Workspace where decompiled source files are all stored (default is `decompiled`).",
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

    # decomp = BoaDecompiler(bytecode)


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to Python-compiled executable to reverse engineer."
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            help="Path to store fully reversed artifacts in (default is `{executable}_out`).",
        ),
    ]
)
def reverse(args):
    """ Subcommand to attempt to fully reverse engineering a target executable """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # output path or set default
    out_dir = f"{app}_out" if not args.out_dir else args.out_dir
    if not os.path.exists(out_dir):
        print("Creating output workspace for storing unpacked resources...")
        os.mkdir(out_dir)

    print("Detecting and unpacking the executable...")
    # run_unpacking_routine(out_dir)

    print("Decompiling unpacked bytecode...")

    print("Running static analysis on the source code...")

    print("Done!")


def main():
    argparse.parse_args()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
