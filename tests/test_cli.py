import logging
import os
import stat

import pytest
import moto
import boto3
import mock
import StringIO

from mrcrypt.cli import commands, parser
from mrcrypt import exceptions

SECRET = 'my secret'


def test_encrypt_arg__all():
    arguments = ('--profile default -vv --outfile outfile.txt encrypt '
                 '--encryption_context {"1":"1"} --regions us-east-1 -- '
                 'alias/test-key secrets.txt')
    args = parser.parse_args(arguments.split())

    assert args.profile == 'default'
    assert args.verbose == 2
    assert args.encryption_context == {"1": "1"}
    assert args.regions == ['us-east-1']
    assert args.filename == 'secrets.txt'
    assert args.outfile == 'outfile.txt'
    assert args.key_id == 'alias/test-key'
    assert args.command == 'encrypt'


def test_encrypt_arg__multiple_regions():
    arguments = 'encrypt --regions us-east-1 us-west-2 eu-west-1 -- alias/test-key secrets.txt'
    args = parser.parse_args(arguments.split())

    assert args.command == 'encrypt'
    assert args.key_id == 'alias/test-key'
    assert args.filename == 'secrets.txt'
    assert args.regions == ['us-east-1', 'us-west-2', 'eu-west-1']
    assert args.verbose == None
    assert args.encryption_context is None
    assert args.profile is None
    assert args.outfile is None


def test_encrypt_arg__minimum_args():
    arguments = 'encrypt alias/test-key secrets.txt'
    args = parser.parse_args(arguments.split())

    assert args.command == 'encrypt'
    assert args.key_id == 'alias/test-key'
    assert args.filename == 'secrets.txt'
    assert args.verbose == None
    assert args.profile is None
    assert args.encryption_context is None
    assert args.regions is None
    assert args.outfile is None


def test_decrypt_arg__all():
    arguments = '--profile default --outfile outfile.txt -vv decrypt secrets.txt'
    args = parser.parse_args(arguments.split())

    assert args.command == 'decrypt'
    assert args.filename == 'secrets.txt'
    assert args.outfile == 'outfile.txt'
    assert args.profile == 'default'
    assert args.verbose == 2


def test_decrypt_arg__minimum():
    arguments = 'decrypt secrets.txt'
    args = parser.parse_args(arguments.split())

    assert args.command == 'decrypt'
    assert args.filename == 'secrets.txt'
    assert args.verbose == None
    assert args.profile is None
    assert args.outfile is None


@pytest.mark.parametrize('infile, outfile, expected', (
        ('secrets.txt', None, 'secrets.txt.decrypted'),
        ('secrets.txt.encrypted', None, 'secrets.txt'),
        ('secrets.txt.encrypted', 'decrypted.txt', 'decrypted.txt'),
        ('secrets.properties.encrypted', None, 'secrets.properties'),
        ('secrets.encrypted', None, 'secrets'),
))
def test_generate_decrypt_filename(infile, outfile, expected):
    decrypt_command = commands.DecryptCommand(infile, outfile=outfile)
    assert decrypt_command._generate_outfile(infile) == expected


@pytest.mark.parametrize('infile, outfile, expected', (
        ('secrets.txt', None, 'secrets.txt.encrypted'),
        ('secrets.txt', 'encrypted.txt', 'encrypted.txt'),
))
def test_generate_encrypt_filename(infile, outfile, expected):
    encrypt_command = commands.EncryptCommand(infile, None, outfile=outfile)
    assert encrypt_command._generate_outfile(infile) == expected


@pytest.mark.parametrize('infile, outfile', (
        ('secrets.txt', '/tmp'),
))
def test_encrypt_outfile_is_dir(infile, outfile):
    try:
        encrypt_command = commands.EncryptCommand(infile, None, outfile)
        assert False
    except ValueError as e:
        assert e.args == ('Cannot specify an outfile that is a directory',)


@moto.mock_kms
def test_cli__encrypt_decrypt_flow(setup_files_tuple, kms_master_key_arn):
    secrets_file, encrypted_file, decrypted_file = setup_files_tuple

    with open(secrets_file, 'w') as f:
        f.write(SECRET)

    encrypt_command = commands.EncryptCommand(secrets_file, kms_master_key_arn,
                                              outfile=encrypted_file)
    encrypt_command.encrypt()

    decrypt_command = commands.DecryptCommand(encrypted_file, outfile=decrypted_file)
    decrypt_command.decrypt()

    with open(decrypted_file, 'r') as f:
        assert f.read() == SECRET

    assert stat.S_IRUSR == os.stat(decrypted_file).st_mode & 0777


@moto.mock_kms
def test_cli__encrypt__stdin_decrypt_flow(setup_files_tuple, kms_master_key_arn):
    dummy_secrets_file, encrypted_file, decrypted_file = setup_files_tuple

    # arrange for SECRET to be in stdin
    with mock.patch('sys.stdin', StringIO.StringIO(SECRET)) as mock_in:
        # test that passing no outfile generates an error when secret is in stdin
        try:
            encrypt_command = commands.EncryptCommand('-', kms_master_key_arn,
                                                      outfile=None)
            encrypt_command.encrypt()
            assert False
        except exceptions.OutfileRequired:
            assert True

        encrypt_command = commands.EncryptCommand('-', kms_master_key_arn,
                                                  outfile=encrypted_file)
        encrypt_command.encrypt()

        decrypt_command = commands.DecryptCommand(encrypted_file, outfile=decrypted_file)
        decrypt_command.decrypt()

        with open(decrypted_file, 'r') as f:
            assert f.read() == SECRET

        assert stat.S_IRUSR == os.stat(decrypted_file).st_mode & 0777


@moto.mock_kms
def test_cli__encrypt_decrypt_directory_flow(secrets_dir, kms_master_key_arn):
    encrypt_command = commands.EncryptCommand(secrets_dir, kms_master_key_arn)
    encrypt_command.encrypt()

    assert os.path.isfile(os.path.join(secrets_dir, 'secrets-1.txt.encrypted'))
    assert os.path.isfile(os.path.join(secrets_dir, 'secrets-2.txt.encrypted'))

    os.remove(os.path.join(secrets_dir, 'secrets-1.txt'))
    os.remove(os.path.join(secrets_dir, 'secrets-2.txt'))

    decrypt_command = commands.DecryptCommand(secrets_dir)
    decrypt_command.decrypt()

    with open(os.path.join(secrets_dir, 'secrets-1.txt')) as f:
        assert f.read() == SECRET

    with open(os.path.join(secrets_dir, 'secrets-2.txt')) as f:
        assert f.read() == SECRET


@pytest.mark.parametrize('verbosity_level, expected_level', (
        (None, logging.WARN),
        (1, logging.INFO),
        (2, logging.DEBUG),
        (10, logging.DEBUG),
))
def test_set_logging_level(verbosity_level, expected_level):
    assert expected_level == parser._get_logging_level(verbosity_level)


@pytest.fixture
def setup_files_tuple(tmpdir):
    secrets_file = tmpdir.join('secrets.txt')
    secrets_file.ensure(file=True)
    secrets_file_path = str(secrets_file)

    encrypted_file = tmpdir.join(secrets_file_path + '.encrypted')
    encrypted_file.ensure(file=True)
    encrypted_file_path = str(encrypted_file)

    decrypted_file = tmpdir.join('decrypted.txt')
    decrypted_file.ensure(file=True)
    decrypted_file_path = str(decrypted_file)

    return secrets_file_path, encrypted_file_path, decrypted_file_path


@pytest.fixture
def secrets_dir(tmpdir):
    secrets_file_one = tmpdir.join('secrets-1.txt')
    secrets_file_one.ensure(file=True)

    secrets_file_two = tmpdir.join('secrets-2.txt')
    secrets_file_two.ensure(file=True)

    with open(str(secrets_file_one), 'w') as f:
        f.write(SECRET)

    with open(str(secrets_file_two), 'w') as f:
        f.write(SECRET)

    return str(tmpdir)


@pytest.fixture
@moto.mock_kms
def kms_master_key_arn():
    client = boto3.client('kms')
    response = client.create_key()
    return response['KeyMetadata']['Arn']
