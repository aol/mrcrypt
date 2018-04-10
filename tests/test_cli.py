"""Unit tests to verify construction of the mrcrypt argument parser."""
import pytest

from mrcrypt.cli import parser

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_encrypt_arg__all():
    arguments = ('--profile default -q -vv --outfile outfile.txt encrypt '
                 '--encryption_context {"1":"1"} --regions us-east-1 -- '
                 'alias/test-key secrets.txt')
    args = parser._build_parser().parse_args(arguments.split())

    assert args.profile == 'default'
    assert args.verbose == 2
    assert args.encryption_context == {"1": "1"}
    assert args.regions == ['us-east-1']
    assert args.filename == 'secrets.txt'
    assert args.outfile == 'outfile.txt'
    assert args.key_id == 'alias/test-key'
    assert args.command == 'encrypt'
    assert args.quiet == True


def test_encrypt_arg__multiple_regions():
    arguments = 'encrypt --regions us-east-1 us-west-2 eu-west-1 -- alias/test-key secrets.txt'
    args = parser._build_parser().parse_args(arguments.split())

    assert args.command == 'encrypt'
    assert args.key_id == 'alias/test-key'
    assert args.filename == 'secrets.txt'
    assert args.regions == ['us-east-1', 'us-west-2', 'eu-west-1']
    assert args.verbose is None
    assert args.encryption_context is None
    assert args.profile is None
    assert args.outfile is None
    assert args.quiet == False


def test_encrypt_arg__minimum_args():
    arguments = 'encrypt alias/test-key secrets.txt'
    args = parser._build_parser().parse_args(arguments.split())

    assert args.command == 'encrypt'
    assert args.key_id == 'alias/test-key'
    assert args.filename == 'secrets.txt'
    assert args.verbose is None
    assert args.profile is None
    assert args.encryption_context is None
    assert args.regions is None
    assert args.outfile is None
    assert args.quiet == False


def test_decrypt_arg__all():
    arguments = '--profile default --outfile outfile.txt -q -vv decrypt secrets.txt'
    args = parser._build_parser().parse_args(arguments.split())

    assert args.command == 'decrypt'
    assert args.filename == 'secrets.txt'
    assert args.outfile == 'outfile.txt'
    assert args.profile == 'default'
    assert args.verbose == 2
    assert args.quiet == True


def test_decrypt_arg__minimum():
    arguments = 'decrypt secrets.txt'
    args = parser._build_parser().parse_args(arguments.split())

    assert args.command == 'decrypt'
    assert args.filename == 'secrets.txt'
    assert args.verbose is None
    assert args.profile is None
    assert args.outfile is None
    assert args.quiet == False
