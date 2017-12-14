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
for envelope encryption. Envelope encryption is used to encrypt a file using a
KMS data key. That data key is then encrypted with regional KMS Customer Master
Keys. Each regionally encrypted data key is then stored in the encrypted
message. When decrypting, the appropriate regional CMK is used to decrypt the
data key, and the data key is then used to decrypt the file. In other words,
encrypt once - decrypt from anywhere.

mrcrypt is compatible with the AWS Encryption SDK message format. For details, see the
section titled `Compatibility with the AWS Encryption SDK`_.

Installation
============

You can install the latest release of mrcrypt with `pip`:

::

    pip install mrcrypt

**Note:** mrcrypt uses the Python package
`Cryptography <https://github.com/pyca/cryptography>`__ which depends on
``libffi``. You may need to install it on your system if
``pip install .`` fails. For more specific instructions for your OS:
https://cryptography.io/en/latest/installation/

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

    usage: mrcrypt [-h] [-p PROFILE] [-e ENCRYPTION_CONTEXT] [-d] [-o OUTFILE]
                       {encrypt,decrypt} ...

    Multi Region Encryption. A tool for managing secrets across multiple AWS
    regions.

    positional arguments:
      {encrypt,decrypt}

    optional arguments:
      -h, --help            show this help message and exit
      -p PROFILE, --profile PROFILE
                            The profile to use
      -e ENCRYPTION_CONTEXT, --encryption_context ENCRYPTION_CONTEXT
                            An encryption context to use. (Cannot have whitespace)
      -d, --debug           Enable more output for debugging
      -o OUTFILE, --outfile OUTFILE
                            The file to write the results to

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

``# Encrypt 'file.txt' writing the output into 'encrypted-file.txt'  mrcrypt -o encrypted-file.txt encrypt alias/master-key file.txt``

By default, when encrypting, mrcrypt will create a file with the same
file name as the input file with ``.encrypted`` appended to the end.
When decrypting, if the file ends with ``.encrypted`` it will write the
plaintext output to a file of the same name but without the
``.encrypted``.

Encryption
==========

::

    usage: mrcrypt encrypt [-h] [-r REGIONS [REGIONS ...]] [-e ENCRYPTION_CONTEXT]
                           key_id filename

    Encrypts a file or directory recursively

    positional arguments:
      key_id                An identifier for a customer master key.
      filename              The file or directory to encrypt. Use a - to read from
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
      filename    The file or directory to decrypt. Use a - to read from stdin

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

Compatibility with the AWS Encryption SDK
=========================================

**From v1.2.0 on, all files encrypted with mrcrypt can be decrypted with any AWS Encryption
SDK client.** v1.2.0+ is backwards compatible with files generated by earlier versions of,
but earlier versions of mrcrypt cannot decrypt files generated by v1.2.0+.
