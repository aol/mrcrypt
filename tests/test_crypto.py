import pytest
import boto3
import moto
from cryptography.exceptions import InvalidTag, InvalidSignature

from mrcrypt import message, utils
from mrcrypt.crypto.encryption import encrypt_string
from mrcrypt.crypto.decryption import decrypt_message


@pytest.mark.parametrize('regions', [
    [],
    ['us-east-1'],
    ['us-east-1', 'us-west-2'],
    ['us-east-1', 'us-west-2', 'eu-west-1']
])
@moto.mock_kms
def test_encrypt_and_decrypt(kms_key_id, regions):
    plaintext = 'test string'
    msg = encrypt_string(plaintext, kms_key_id, regions)

    result = decrypt_message(msg)

    assert result == plaintext


@pytest.mark.parametrize('regions', [
    [],
    ['us-east-1'],
    ['us-east-1', 'us-west-2'],
    ['us-east-1', 'us-west-2', 'eu-west-1']
])
@moto.mock_kms
def test_encrypt_decrypt__large_content(kms_key_id, regions):
    plaintext = utils.random_string(5000)
    msg = encrypt_string(plaintext, kms_key_id, regions)

    assert isinstance(msg.body, message.FrameBody)
    assert len(msg.body.frames) == 2

    result = decrypt_message(msg)

    assert result == plaintext


@pytest.mark.parametrize('regions', [
    [],
    ['us-east-1'],
    ['us-east-1', 'us-west-2'],
    ['us-east-1', 'us-west-2', 'eu-west-1']
])
@moto.mock_kms
def test_encrypt_decrypt__encryption_context(kms_key_id, regions):
    plaintext = 'test string'
    encryption_context = {'test_key': 'test_value'}
    msg = encrypt_string(plaintext, kms_key_id, regions, encryption_context=encryption_context)

    byte_array = msg.serialize()

    assert 'test_key' in byte_array
    assert 'test_value' in byte_array

    result = decrypt_message(msg)

    assert result == plaintext


@moto.mock_kms
def test_header_integrity_check(kms_key_id):
    plaintext = 'test string'
    msg = encrypt_string(plaintext, kms_key_id, ['us-east-1'])

    byte_array = bytearray(msg.serialize())

    byte_array[4] = ~byte_array[4] & 0xff  # ensure the number isn't the same

    msg = message.Message()
    msg.deserialize(str(byte_array), 0)

    with pytest.raises(InvalidTag):
        decrypt_message(msg)


@moto.mock_kms
def test_message_integrity_check(kms_key_id):
    plaintext = 'test string'
    msg = encrypt_string(plaintext, kms_key_id, ['us-east-1'])

    byte_array = bytearray(msg.serialize())
    authenticated_fields_byte_array = bytearray(msg.serialize_authenticated_fields())

    authenticated_fields_byte_array[-1] = ~authenticated_fields_byte_array[-1] & 0xff

    byte_array[:len(authenticated_fields_byte_array)] = authenticated_fields_byte_array

    msg = message.Message()
    msg.deserialize(str(byte_array), 0)

    with pytest.raises(InvalidSignature):
        decrypt_message(msg)


@pytest.fixture
@moto.mock_kms
def kms_key_id():
    client = boto3.client('kms')

    response = client.create_key()

    return response['KeyMetadata']['Arn']

