"""
argparse.py

    Argument parser helper for both the UWSGI runner and CLI

    Credits: https://mike.depalatis.net/blog/simplifying-argparse.html
"""
import argparse

# globally instantiated parser for simplified subcommand parsing
cli = argparse.ArgumentParser(
    description="Python Malware/App Reverse Engineering Framework"
)
subparsers = cli.add_subparsers(dest="subcommand")


def argument(*name_or_flags, **kwargs):
    """ Helper method to format arguments for subcommand decorator """
    return (list(name_or_flags), kwargs)


def subcommand(args=[], parent=subparsers):
    """ Implements decorator for instantiating subcommand. """

    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)

    return decorator


def parse_args():
    """ Entry for argument parsing """
    args = cli.parse_args()
    if args.subcommand is None:
        cli.print_help()
    else:
        args.func(args)
