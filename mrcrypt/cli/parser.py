"""
mrcrypt.cli
~~~~~~~~~~~

Implements the command-line interface and transforms arguments into correct arguments to call ``aws-encryption-cli``.
"""
import argparse
import ast
import logging
import os
import traceback

import aws_encryption_sdk_cli
from aws_encryption_sdk_cli.exceptions import AWSEncryptionSDKCLIError

from mrcrypt.materials_manager import MrcryptLegacyCompatibilityCryptoMaterialsManager

_LOGGER = logging.getLogger('mrcrypt')


def _build_encrypt_parser(subparsers):
    """Build the encryption subparser."""
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
                                help='The file or directory to encrypt. Use "-" to read from stdin')


def _build_decrypt_parser(subparsers):
    """Build the decryption subparser."""
    decrypt_parser = subparsers.add_parser('decrypt',
                                           description='Decrypts a file')

    decrypt_parser.add_argument('filename',
                                action='store',
                                help='The file or directory to decrypt. Use "-" to read from stdin')


def _build_parser():
    """Build the parser."""
    parser = argparse.ArgumentParser(
        description='Multi Region Encryption. A tool for managing secrets across multiple AWS '
                    'regions.')

    parser.add_argument('-p', '--profile', action='store', help='The profile to use')
    parser.add_argument('-v', '--verbose', action='count',
                        help='More verbose output (ignored if --quiet)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet all output')
    parser.add_argument('-o', '--outfile', action='store',
                        help='The file to write the results to (use "-" to write to stdout')

    subparsers = parser.add_subparsers(dest='command')

    _build_encrypt_parser(subparsers)
    _build_decrypt_parser(subparsers)

    return parser


def _transform_encryption_context(encryption_context):
    """Transform encryption context to raw aws-encryption-cli encryption context arguments.

    :param dict encryption_context: Encryption context
    :returns: Raw aws-encryption-cli encryption context arguments
    :rtype: list of str
    """
    return ['--encryption-context'] + [
        '{key}={value}'.format(key=key, value=value)
        for key, value
        in encryption_context.items()
    ]


def _transform_master_key_providers(key_id, regions, profile):
    """Transform master key provider information to raw aws-encryption-cli arguments.

    :param str key_id: Key ID to use for all regions
    :param list regions: List of region names (may be empty)
    :param str profile: Named profile to use (may be None)
    :returns: Raw aws-encryption-cli master key provider configuration arguments
    :rtype: list of str
    """
    base_config = ['--master-keys', 'key={}'.format(key_id)]
    if profile is not None:
        base_config.append('profile={}'.format(profile))

    if not regions:
        return base_config

    configs = []
    for region in regions:
        configs.extend(base_config + ['region={}'.format(region)])
    return configs


def _transform_args(mrcrypt_args):
    """Transform parsed mrcrypt arguments to parsed aws-encryption-cli arguments.

    :param mrcrypt_args: Parsed mrcrypt arguments
    :type: mrcrypt_args: argparse.Namespace
    :returns: Parsed aws-encryption-cli arguments
    :rtype: argparse.Namespace
    """
    raw_args = []
    if mrcrypt_args.command == 'encrypt':
        raw_args.append('--encrypt')
        raw_args.extend(_transform_master_key_providers(
            mrcrypt_args.key_id,
            mrcrypt_args.regions,
            mrcrypt_args.profile
        ))
        if mrcrypt_args.encryption_context is not None:
            raw_args.extend(_transform_encryption_context(mrcrypt_args.encryption_context))

    elif mrcrypt_args.command == 'decrypt':
        raw_args.append('--decrypt')
        if mrcrypt_args.profile is not None:
            raw_args.extend(['--master-keys', 'profile={}'.format(mrcrypt_args.profile)])

    raw_args.extend(['--input', mrcrypt_args.filename])
    raw_args.append('--output')
    if mrcrypt_args.outfile is not None:
        raw_args.append(mrcrypt_args.outfile)
    else:
        raw_args.append('.')
    raw_args.append('--recursive')
    raw_args.append('--suppress-metadata')

    if mrcrypt_args.verbose is not None:
        raw_args.append('-' + 'v' * mrcrypt_args.verbose)

    return aws_encryption_sdk_cli.parse_args(raw_args)


def _build_crypto_materials_manager(encryption_cli_args):
    """Build a legacy compatible crypto materials manager from parsed aws-encryption-cli arguments.

    :param encryption_cli_args: Parsed aws-encryption-cli arguments
    :type encryption_cli_args: argparse.Namespace
    :returns: Legacy compatible crypto materials manager
    :rtype: mrcrypt.materials_manager.MrcryptLegacyCompatibilityCryptoMaterialsManager
    """
    _default_crypto_materials_manager = aws_encryption_sdk_cli.build_crypto_materials_manager_from_args(
        encryption_cli_args.master_keys,
        caching_config=None  # Force using a Default CMM
    )
    return MrcryptLegacyCompatibilityCryptoMaterialsManager(_default_crypto_materials_manager.master_key_provider)


def parse(raw_args=None):
    """Process input arguments and runs requested operations.

    :param list raw_args: List of arguments
    :returns: parsed arguments
    :rtype: argparse.Namespace
    """
    parser = _build_parser()
    mrcrypt_args = parser.parse_args(raw_args)
    if mrcrypt_args.command is None:
        return parser.format_help()

    try:
        if mrcrypt_args.command == 'encrypt':
            if mrcrypt_args.encryption_context is not None and not isinstance(mrcrypt_args.encryption_context, dict):
                return 'Invalid dictionary in encryption context argument'

        # setup mrcrypt's logger
        if mrcrypt_args.quiet:
            log_level = logging.CRITICAL
        else:
            log_level = logging.WARN if not mrcrypt_args.verbose else logging.DEBUG

        _LOGGER.setLevel(log_level)

        # setup aws_encryption_sdk's logger
        aws_encryption_sdk_cli.setup_logger(
            verbosity=mrcrypt_args.verbose,
            quiet=mrcrypt_args.quiet
        )

        encryption_cli_args = _transform_args(mrcrypt_args)
        crypto_materials_manager = _build_crypto_materials_manager(encryption_cli_args)
        stream_args = aws_encryption_sdk_cli.stream_kwargs_from_args(encryption_cli_args, crypto_materials_manager)

        aws_encryption_sdk_cli.process_cli_request(
            stream_args=stream_args,
            parsed_args=encryption_cli_args
        )

        # NOTE: If any post-processing of the files created as a result of this operation
        # is desired, the best way to approach this would be to use the output metadata to
        # collect a listing of all written files.
        # http://aws-encryption-sdk-cli.readthedocs.io/en/latest/#output-metadata

        return None
    except AWSEncryptionSDKCLIError as error:
        return error.args[0]
    except Exception as error:  # pylint: disable=broad-except
        message = os.linesep.join([
            'Encountered unexpected error: increase verbosity to see details.',
            '{cls}({args})'.format(
                cls=error.__class__.__name__,
                args=', '.join(['"{}"'.format(arg) for arg in error.args])
            )
        ])
        _LOGGER.debug(message)
        # copy.deepcopy can't handle raw exc_info objects, so format it first
        formatted_traceback = traceback.format_exc()
        _LOGGER.debug(formatted_traceback)
        return message
