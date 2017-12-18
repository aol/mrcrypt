"""Integration tests for mrcrypt.

These could also be converted to unit tests if moto.mock_kms.generate_data_key supported the "number_of_bytes" argument.
"""
import os
import platform
import shlex
from subprocess import PIPE, Popen

import pytest

from mrcrypt.cli import parser

pytestmark = pytest.mark.integ

AWS_KMS_KEY_ID = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID'
SECRET = b'my secret'
ENCRYPT_TEMPLATE = '--outfile {outfile} encrypt {arn} {input}'
DECRYPT_TEMPLATE = '--outfile {outfile} decrypt {input}'


def is_windows():
    return any(platform.win32_ver())


@pytest.fixture
def setup_files_tuple(tmpdir):
    secrets_file = tmpdir.join('secrets.txt')
    secrets_file.write_binary(SECRET)

    encrypted_file = tmpdir.join('secrets.txt.encrypted')

    decrypted_file = tmpdir.join('decrypted.txt')

    return secrets_file, encrypted_file, decrypted_file


@pytest.fixture
def cmk_arn():
    """Retrieves the target CMK ARN from environment variable."""
    arn = os.environ.get(AWS_KMS_KEY_ID, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID
            )
        )
    if arn.startswith('arn:') and ':alias/' not in arn:
        return arn
    raise ValueError('KMS CMK ARN provided for integration tests much be a key not an alias')


def test_cli__encrypt_decrypt_flow(setup_files_tuple, cmk_arn):
    secrets_file, encrypted_file, decrypted_file = setup_files_tuple

    encrypt_args = ENCRYPT_TEMPLATE.format(
        outfile=str(encrypted_file),
        arn=cmk_arn,
        input=str(secrets_file)
    )
    decrypt_args = DECRYPT_TEMPLATE.format(
        input=str(encrypted_file),
        outfile=str(decrypted_file)
    )

    encrypt_result = parser.parse(shlex.split(encrypt_args, posix=not is_windows()))
    assert encrypt_result is None
    decrypt_result = parser.parse(shlex.split(decrypt_args, posix=not is_windows()))
    assert decrypt_result is None

    assert decrypted_file.read_binary() == SECRET


def test_cli__encrypt__stdin_no_output(cmk_arn):
    encrypt_args = 'encrypt {} -'.format(cmk_arn)
    encrypt_result = parser.parse(shlex.split(encrypt_args, posix=not is_windows()))
    assert encrypt_result == 'Destination may not be a directory when source is stdin'


def test_cli__encrypt__stdin_decrypt_flow(setup_files_tuple, cmk_arn):
    _, encrypted_file, decrypted_file = setup_files_tuple

    encrypt_args = 'mrcrypt ' + ENCRYPT_TEMPLATE.format(
        outfile=str(encrypted_file),
        arn=cmk_arn,
        input='-'
    )
    decrypt_args = DECRYPT_TEMPLATE.format(
        outfile=str(decrypted_file),
        input=str(encrypted_file)
    )

    proc = Popen(shlex.split(encrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    _stdout, stderr = proc.communicate(input=SECRET)
    assert not stderr

    decrypt_results = parser.parse(shlex.split(decrypt_args, posix=not is_windows()))
    assert decrypt_results is None
    assert decrypted_file.read_binary() == SECRET


def test_cli__encrypt_decrypt_directory_flow(tmpdir, cmk_arn):
    plaintext = tmpdir.mkdir('plaintext')
    ciphertext = tmpdir.mkdir('ciphertext')
    decrypted = tmpdir.mkdir('decrypted')

    secrets_file_one = plaintext.join('secrets-1.txt')
    secrets_file_one.write_binary(SECRET)
    encrypted_file_one = ciphertext.join('secrets-1.txt.encrypted')
    decrypted_file_one = decrypted.join('secrets-1.txt.encrypted.decrypted')

    secrets_file_two = plaintext.join('secrets-2.txt')
    secrets_file_two.write_binary(SECRET)
    encrypted_file_two = ciphertext.join('secrets-2.txt.encrypted')
    decrypted_file_two = decrypted.join('secrets-2.txt.encrypted.decrypted')

    encrypt_args = ENCRYPT_TEMPLATE.format(
        outfile=str(ciphertext),
        arn=cmk_arn,
        input=str(plaintext)
    )
    decrypt_args = DECRYPT_TEMPLATE.format(
        outfile=str(decrypted),
        input=str(ciphertext)
    )

    encrypt_results = parser.parse(shlex.split(encrypt_args, posix=not is_windows()))
    assert encrypt_results is None
    assert encrypted_file_one.isfile()
    assert encrypted_file_two.isfile()

    decrypt_results = parser.parse(shlex.split(decrypt_args, posix=not is_windows()))
    assert decrypt_results is None

    assert decrypted_file_one.read_binary() == SECRET
    assert decrypted_file_two.read_binary() == SECRET
