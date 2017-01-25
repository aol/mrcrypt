import struct
import os

import pytest

from mrcrypt import utils


def test_get_arns():
    arns = utils.get_arns(['us-east-1', 'us-west-2', 'eu-west-1'], 1234567890, 'test-alias')

    expected_arns = ['arn:aws:kms:us-east-1:1234567890:alias/test-alias',
                     'arn:aws:kms:us-west-2:1234567890:alias/test-alias',
                     'arn:aws:kms:eu-west-1:1234567890:alias/test-alias']

    assert expected_arns == arns


@pytest.mark.parametrize('arn, expected_region', (
        ('arn:aws:kms:us-east-1:1234567890:alias/test-alias', 'us-east-1'),
        ('arn:aws:ec2:us-west-2:1234567890:key/1234567890', 'us-west-2'),
))
def test_region_from_arn(arn, expected_region):
    region = utils.region_from_arn(arn)
    assert region == expected_region


@pytest.mark.parametrize('number, length, expected', (
        (1, 1, struct.pack('>B', 1)),
        (1, 8, struct.pack('>Q', 1)),
        (2 ** 16 - 1, 2, struct.pack('>H', 2 ** 16 - 1))
))
def test_num_to_bytes(number, length, expected):
    result = utils.num_to_bytes(number, length)
    assert result == expected


@pytest.mark.parametrize('byte_string, expected_int', (
        ('0', 48),
        ('1', 49),
        ('10', 12592),
        ('00', 12336)
))
def test_bytes_to_int(byte_string, expected_int):
    result = utils.bytes_to_int(byte_string)

    assert result == expected_int


@pytest.mark.parametrize('dict_, expected_length', (
        # Add 4 because of the two 2-byte fields for key/value length
        ({'1': '2'}, 2 + 4),
        ({'12': '34'}, 4 + 4)
))
def test_dict_to_byte_length(dict_, expected_length):
    result = utils.dict_to_byte_length(dict_)

    assert result == expected_length


@pytest.mark.parametrize('str_, size, expected', (
        ('11', 1, ('1', '1')),
        ('splitme', 2, ('sp', 'li', 'tm', 'e'))
))
def test_split(str_, size, expected):
    result = utils.split(str_, size)

    assert result == expected


@pytest.mark.parametrize('size', (
    0,
    1,
    100,
    5000
))
def test_random_string(size):
    assert len(utils.random_string(size)) == size


@pytest.mark.parametrize('permissions_octal', (
    0600,
    0660,
    0666
))
def test_get_file_permissions(tmpdir, permissions_octal):
    f = tmpdir.join('test.txt')
    f.write('test')
    os.chmod(f.strpath, permissions_octal)

    assert utils.get_file_permissions(f.strpath) == permissions_octal
