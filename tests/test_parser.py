"""Unit tests to validate the behavior of the ``mrcrypt.cli.parser`` module."""
import shlex

import aws_encryption_sdk_cli
import mock
import pytest
import six

from mrcrypt.cli import parser

pytestmark = [pytest.mark.unit, pytest.mark.local]


def build_args_transforms():
    transformed_suffix = ' --recursive --suppress-metadata'

    transformations = []

    for verbosity in ('', '-v', '-vv', '-vvv', '-vvvv'):
        transformations.append((
            verbosity + ' decrypt input_filename',
            '--decrypt --input input_filename --output . ' + verbosity + transformed_suffix
        ))
    transformations.append((
        '--outfile output_filename decrypt input_filename',
        '--decrypt --input input_filename --output output_filename' + transformed_suffix
    ))
    transformations.append((
        '--profile ex_profile decrypt input_filename',
        '--decrypt --input input_filename --output . --master-keys profile=ex_profile' + transformed_suffix
    ))

    transformations.append((
        'encrypt key_id input_filename',
        '--encrypt --input input_filename --output . --master-keys key=key_id' + transformed_suffix
    ))
    transformations.append((
        '-p my_profile encrypt key_id input_filename',
        '--encrypt --input input_filename --output . --master-keys key=key_id profile=my_profile' + transformed_suffix
    ))
    transformations.append((
        'encrypt --encryption_context \'{"a": "b", "c": "d"}\' key_id input_filename',
        '--encrypt --input input_filename --output . --master-keys key=key_id'
        ' --encryption-context a=b c=d' + transformed_suffix
    ))
    transformations.append((
        'encrypt --regions us-west-2 ca-central-1 -- key_id input_filename',
        '--encrypt --input input_filename --output .'
        ' --master-keys key=key_id region=us-west-2'
        ' --master-keys key=key_id region=ca-central-1' + transformed_suffix
    ))

    return transformations


@pytest.mark.parametrize('mrcrypt_args, expected_aws_encryption_cli_args', build_args_transforms())
def test_aws_encryption_cli_args_transform(mrcrypt_args, expected_aws_encryption_cli_args):
    expected_aws_encryption_cli_namespace = aws_encryption_sdk_cli.parse_args(
        shlex.split(expected_aws_encryption_cli_args)
    )
    parsed_mrcrypt_namespace = parser._build_parser().parse_args(shlex.split(mrcrypt_args))
    transformed_namespace = parser._transform_args(parsed_mrcrypt_namespace)

    assert transformed_namespace == expected_aws_encryption_cli_namespace


@pytest.mark.parametrize('value', (
    '["not", "a", "dict"]',
    '("not", "a", "dict")',
    '"not a dict"',
    '12341235',
    'False'
))
def test_invalid_encryption_context(value):
    test = parser.parse(shlex.split('encrypt --encryption_context \'{}\' key_id input_filename'.format(value)))
    assert test == 'Invalid dictionary in encryption context argument'


@pytest.mark.skipif(
    six.PY2,
    reason='skipping empty argument handling for Python 2 because we fail as desired in Python 2'
)
def test_no_command_selected_py3():
    test = parser.parse([])
    assert test.startswith('usage: ')


@mock.patch.object(parser.aws_encryption_sdk_cli, 'setup_logger')
def test_unexpected_error(patch_setup_logger):
    patch_setup_logger.side_effect = Exception('Unknown Error!')
    test = parser.parse(shlex.split('--outfile - decrypt -'))
    assert test.startswith('Encountered unexpected error: increase verbosity to see details.')
