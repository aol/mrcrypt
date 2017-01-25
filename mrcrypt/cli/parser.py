"""
mrcrypt.cli
~~~~~~~~~~~

Implements the command-line interface. Is an entry point into the program.
"""
import argparse
import ast
import logging
import sys

from mrcrypt.cli import commands


def _build_encrypt_parser(subparsers):
    """Builds the encryption subparser."""
    encrypt_parser = subparsers.add_parser('encrypt',
                                           description='Encrypts a file or directory recursively')

    encrypt_parser.add_argument('-r', '--regions',
                                nargs='+',
                                help='A list of regions to encrypt with KMS. End the list with --')
    encrypt_parser.add_argument('-e', '--encryption_context', type=ast.literal_eval,
                                action='store', help='An encryption context to use')

    encrypt_parser.add_argument('key_id',
                                help='An identifier for a customer master key.')

    encrypt_parser.add_argument('filename',
                                action='store',
                                help='The file or directory to encrypt. Use a - to read from '
                                     'stdin')


def _build_decrypt_parser(subparsers):
    """Builds the decryption subparser."""
    decrypt_parser = subparsers.add_parser('decrypt',
                                           description='Decrypts a file')

    decrypt_parser.add_argument('filename',
                                action='store',
                                help='The file or directory to decrypt. Use a - to read from '
                                     'stdin')


def parse_args(args=None):
    """Builds the parser and parses the command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Multi Region Encryption. A tool for managing secrets across multiple AWS '
                    'regions.')

    parser.add_argument('-p', '--profile', action='store', help='The profile to use')
    parser.add_argument('-v', '--verbose', action='count',
                        help='More verbose output')
    parser.add_argument('-o', '--outfile', action='store', help='The file to write the results to')

    subparsers = parser.add_subparsers(dest='command')

    _build_encrypt_parser(subparsers)
    _build_decrypt_parser(subparsers)

    return parser.parse_args(args)


def _get_logging_level(verbosity_level):
    """Sets the logger level from the CLI verbosity argument."""
    if verbosity_level is None:
        logging_level = logging.WARN
    elif verbosity_level == 1:
        logging_level = logging.INFO
    else:
        logging_level = logging.DEBUG

    return logging_level


def parse():
    args = parse_args()

    logging.basicConfig(stream=sys.stderr, level=_get_logging_level(args.verbose))

    if args.command == 'decrypt':
        decrypt_command = commands.DecryptCommand(args.filename, outfile=args.outfile,
                                                  profile=args.profile)
        decrypt_command.decrypt()

    elif args.command == 'encrypt':
        if args.encryption_context is not None and type(args.encryption_context) is not dict:
            print('Invalid dictionary in encryption context argument')
            sys.exit(1)

        encrypt_command = commands.EncryptCommand(args.filename, args.key_id,
                                                  outfile=args.outfile, regions=args.regions,
                                                  profile=args.profile,
                                                  encryption_context=args.encryption_context)
        encrypt_command.encrypt()
