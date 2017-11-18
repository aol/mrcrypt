""""""
import shlex

import aws_encryption_sdk_cli
import pytest

from mrcrypt.cli import parser


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
    parsed_mrcrypt_namespace  = parser.parse_args(shlex.split(mrcrypt_args))
    transformed_namespace = parser._transform_args(parsed_mrcrypt_namespace)

    assert transformed_namespace == expected_aws_encryption_cli_namespace
