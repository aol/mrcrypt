"""
mrcrypt.utils
~~~~~~~~~~~~~

Contains utility functions used across mrcrypt.
"""
import string
import random
import os

import boto3


def get_arns(regions, account_id, alias):
    """Get a list of Amazon Resource Names (ARNs).

    :param regions: A list of regions.
    :param account_id: An Amazon Account ID.
    :param alias: The alias of the key on KMS.

    :return: A list of ARNs.
    """
    return ['arn:aws:kms:{}:{}:alias/{}'.format(region, account_id, alias) for region in regions]


def region_from_arn(arn):
    """
    Extracts the region from an ARN.

    :param arn: An ARN.

    :return: The region in ``arn``.
    """
    return arn.split(':')[3]


def bytes_to_int(byte_array):
    """
    Converts a byte string into a number.

    :param byte_array: The byte string to convert.

    :return: The number represented by ``byte_array``.
    """
    return int(byte_array.encode('hex'), 16)


def num_to_bytes(number, length):
    """
    Converts ``number`` to a bytearray of the given length.

    :param number: A positive number.
    :param length: The number of bytes the resulting bytearray should be.

    :return: The number as a byte string.
    """
    hex_str = format(number, 'x').zfill(length * 2)
    return str(bytearray.fromhex(hex_str))


def dict_to_byte_length(dict_):
    """Get the byte length of a dictionary. This returns the sum of the length of the key and the
    value and 4 bytes to store the length of the key/value pair, for every pair in ``dict_``."""
    return sum(len(key) + len(value) + 4 for key, value in dict_.iteritems())


def split(iterable, size):
    """Splits ``iterable`` into parts of size ``size``.

    Wrapped a list inside a tuple because otherwise, for small values, it will return a generator.
    """
    return tuple(iterable[x:x + size] for x in xrange(0, len(iterable), size))


def random_string(length):
    """Generates a random string."""
    return ''.join(random.choice(string.printable) for __ in xrange(length))


def get_kms_clients(regions=None, profile=None):
    """Gets a list of KMS clients for the regions specified. If no regions are specified, a client
    is created with the default region."""
    session = boto3.Session(profile_name=profile)
    if not regions:
        return [session.client('kms')]
    else:
        return [session.client('kms', region_name=region) for region in regions]


def get_file_permissions(filename):
    """Gets the permissions of ``filename``."""
    return os.stat(filename).st_mode & 0777


def get_parent_dir_path(filename):
    """Gets the absolute path of the parent directory that ``filename`` belongs to."""
    return os.path.dirname(os.path.abspath(filename))


def get_umask():
    """Returns the current umask."""
    current_umask = os.umask(0)
    os.umask(current_umask)

    return current_umask


def get_default_file_permissions():
    """Returns default file permissions from the current umask."""
    umask = get_umask()
    return 0666 & ~umask
