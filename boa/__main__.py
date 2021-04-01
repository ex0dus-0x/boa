#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import sys
import typing as t

import lief
import uncompyle6

import boa.argparse as argparse
from boa.unfreeze import get_installer
from boa.unpack import get_packer
from boa.decompile import BoaDecompiler


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
    app: str = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable.")
        return 1

    print("\nBasic Information")

    print("\nHashing")

    print("\nVirusTotal Matches")

    # Python-specific info
    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "executable",
            help="Path to packaged executable to extrapolate resources from.",
        ),
        argparse.argument(
            "-m",
            "--minify",
            action="store_true",
            help="If set (default), only bytecode de",
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
        print("Cannot find path to executable.")
        return 1

    # output path or set default
    out_dir: str = f"{app}_out" if not args.out_dir else args.out_dir
    if not os.path.exists(out_dir):
        print("Creating output workspace for storing unpacked resources...")
        os.mkdir(out_dir)

    # detect executable packing
    up = get_packer(app)
    if up is None:
        print("Didn't detect any executable packing with the target executable.")
    else:
        with up as unpacker:
            pass

    # instantiate unfreezer
    uf = get_installer(app)
    if uf is None:
        print("Unable to detect the installer used to freeze the executable.")
        return 1

    with uf as unfreezer:
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
            "--bytecode",
            nargs="+",
            required=True,
            help="Path to bytecode file(s) or raw dumped code object(s) for decompilation.",
        ),
        argparse.argument(
            "-p",
            "--pyver",
            type=float,
            help="Specify the major and minor version (x.y) of Python to decompile as. If not set, boa will figure it out.",
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
    # if set, will tune decompiler to patch with version magic number(s) if encountered
    # code objects, otherwise will have to iterate over each
    pyver = args.pyver
    if not pyver:
        print("No Python version specifed to decompile against. Setting as 3.7")
        pyver = 3.7

    outdir: str = args.out_dir
    decomp = BoaDecompiler(outdir, pyver)

    # iterate over each bytecode file and decompile
    bfiles: t.List[str] = args.bytecode
    for bfile in bfiles:
        if not os.path.exists(bfile):
            print(f"`{bfile}` does not exist")
            return 1

        print(f"Decompiling {bfile}...")
        decomp.decompile(bfile)

    return 0


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
        print("Cannot find path to executable.")
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
