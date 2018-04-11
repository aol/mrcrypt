mrcrypt: Multi-Region Encryption
================================

.. image:: https://img.shields.io/pypi/v/mrcrypt.svg
    :target: https://pypi.python.org/pypi/mrcrypt

.. image:: https://img.shields.io/pypi/pyversions/mrcrypt.svg
    :target: https://pypi.python.org/pypi/mrcrypt

.. image:: https://travis-ci.org/aol/mrcrypt.svg?branch=master
    :target: https://travis-ci.org/aol/mrcrypt

.. image:: https://codecov.io/gh/aol/mrcrypt/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/aol/mrcrypt

mrcrypt is a command-line tool which encrypts secrets that conform to the AWS
Encryption SDK's `message format
<http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html>`__
for envelope encryption. As of v2.0, mrcrypt now wraps the `aws-encryption-sdk-cli <https://github.com/awslabs/aws-encryption-sdk-cli>`__.

For more information about the AWS Encryption SDK see
`<https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html>`__.

Installation
============

You can install the latest release of mrcrypt with `pip`:

::

    pip install mrcrypt

Quick Start
===========

Encrypt a file for use in 3 regions (NOTE: Key alias must exist in specified regions):

::

    mrcrypt encrypt -r us-east-1 us-west-2 eu-west-1 -- alias/master-key secrets.txt

Decrypt the file:

::

    mrcrypt decrypt secrets.txt.encrypted

Usage
=====

::

    usage: mrcrypt [-h] [-p PROFILE] [-v] [-q] [-o OUTFILE] {encrypt,decrypt} ...

    Multi Region Encryption. A tool for managing secrets across multiple AWS
    regions.

    positional arguments:
      {encrypt,decrypt}

    optional arguments:
      -h, --help            show this help message and exit
      -p PROFILE, --profile PROFILE
                            The profile to use
      -v, --verbose         More verbose output (ignored if --quiet)
      -q, --quiet           Quiet all output
      -o OUTFILE, --outfile OUTFILE
                            The file to write the results to (use "-" to write to
                            stdout

Both the encrypt, and decrypt commands can encrypt and decrypt files in
directories recursively.

Named Profiles
''''''''''''''

If you have multiple named profiles in your ``~/.aws/credentials`` file,
you can specify one using the ``-p`` argument.

::

    mrcrypt -p my_profile encrypt alias/master-key secrets.txt

Encryption Context
''''''''''''''''''

You can specify an `encryption
context <http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html>`__
using the ``-e`` argument. This flag takes a JSON object with no spaces:

::

    # encrypt
    mrcrypt -e '{"key":"value","key2":"value2"}' encrypt alias/master-key secrets.txt

    # decrypt
    mrcrypt -e '{"key":"value","key2":"value2"}' decrypt secrets.txt.encrypted

Output file name
''''''''''''''''

If you want to specify the output filename, you can use the ``-o``
argument.

::
    # Encrypt 'file.txt' writing the output into 'encrypted-file.txt'
    mrcrypt -o encrypted-file.txt encrypt alias/master-key file.txt

To write to stdout, you can use `-`

::
    # Encrypt 'file.txt' writing the output to stdout
    mrcrypt -o - encrypt alias/master-key file.txt

When the output filename argument is not specified, mrcrypt will use the input
filename as a base and add a suffix. On encrypt this suffix is ``.encrypted``
and on decrypt this suffix is ``.decrypted``.

Encryption
==========

::

    usage: mrcrypt encrypt [-h] [-r REGIONS [REGIONS ...]] [-e ENCRYPTION_CONTEXT]
                           key_id filename

    Encrypts a file or directory recursively

    positional arguments:
      key_id                An identifier for a customer master key.
      filename              The file or directory to encrypt. Use "-" to read from
                            stdin

    optional arguments:
      -h, --help            show this help message and exit
      -r REGIONS [REGIONS ...], --regions REGIONS [REGIONS ...]
                            A list of regions to encrypt with KMS. End the list
                            with --
      -e ENCRYPTION_CONTEXT, --encryption_context ENCRYPTION_CONTEXT
                            An encryption context to use

**Example:** Encrypt ``secrets.txt`` with the key alias
``alias/master-key`` in the regions ``us-east-1`` and ``us-west-2``:

::

    mrcrypt encrypt -r us-east-1 us-west-2 -- alias/master-key secrets.txt

**Note:** In this example, the key alias `alias/master-key` exists in both the
`us-east-1`, and `us-west-2` regions.

Decryption
==========

::

    usage: mrcrypt decrypt [-h] filename

    Decrypts a file

    positional arguments:
      filename    The file or directory to decrypt. Use "-" to read from stdin

    optional arguments:
      -h, --help  show this help message and exit

**Example:** To decrypt ``secrets.txt.encrypted``:

::

    mrcrypt decrypt secrets.txt.encrypted

**Note:** Be careful when decrypting a directory. If the directory
contains files that are not encrypted, it will fail.

Testing
=======

Running tests for mrcrypt is easy if you have ``tox`` installed. Simply
run ``tox`` at the project's root.

If you have an AWS account with a KMS key, you can run the integration tests using

::

    AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID=<my-key-arn> tox -e py{27,34,35,36}-{local,integ}

Note about files created with mrcrypt before v2.0
=================================================

Upon the release of v2.0, mrcrypt started wrapping the
`aws-encryption-sdk-cli <https://github.com/awslabs/aws-encryption-sdk-cli>`__. Wrapping the
aws-encryption-sdk-cli means that mrcrypt now fully conforms to the AWS
Encryption SDK's `message format
<http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html>`__ and uses
compressed points when encrypting files. Before v2.0, mrcrypt did not use compressed points, and
while still secure, it lead to compatibility issues with other AWS Encryption SDK implementations.
To update your pre-2.0 mrcrypt encrypted files, and improve compatibility with the AWS Encryption
SDK, simply decrypt and re-encrypt your file with the latest version of mrcrypt.
