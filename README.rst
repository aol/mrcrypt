mrcrypt: Multi-Region Encryption
================================

mrcrypt is a command-line tool that allows you to encrypt secrets in
multiple AWS regions using KMS keys using a technique called `Envelope
Encryption <http://docs.aws.amazon.com/kms/latest/developerguide/workflow.html>`__.
It is intended to be used with the `AWS Encryption SDK for
Java <https://github.com/awslabs/aws-encryption-sdk-java>`__, but could
be used on its own.

Compatability with the AWS Encryption SDK
'''''''''''''''''''''''''''''''''''''''''

**All files encrypted with mrcrypt can be decrypted with the AWS
Encryption SDK.** But not all files encrypted with the AWS Encryption
SDK can be decrypted by mrcrypt.

Currently, mrcrypt only supports the AWS Encryption SDK's default (and
most secure) cryptographic algorithm:

-  Content Type: Framed
-  Frame size: 4096
-  Algorithm: ALG\_AES\_256\_GCM\_IV12\_TAG16\_HKDF\_SHA384\_ECDSA\_P384

Support for the remaining algorithms are planned, but files encrypted
with the AWS Encryption SDK using one of the other algorithms are
currently not supported in mrcrypt.

Also, the AWS Encryption SDK creates files using elliptic curve point
compression. Files created with mrcrypt do not use point compression
because they are not currently supported in
`Cryptography <https://github.com/pyca/cryptography>`__, a Python
package mrcrypt uses. The uncompressed points are just as secure as the
compressed points, but files are a few bytes larger. The AWS Encryption
SDK can decrypt files that use uncompressed points, meaning all files
created with mrcrypt are compatible with the AWS Encryption SDK.

Installation
------------

To install mrcrypt simply clone the repo, and run ``pip install .``
inside of the directory:

::

    git clone ssh://git@stash.ops.aol.com:2022/identity_services/mrcrypt.git
    cd mrcrypt
    pip install .

**Note:** mrcrypt uses the Python package
`Cryptography <https://github.com/pyca/cryptography>`__ which depends on
``libffi``. You may need to install it on your system if
``pip install .`` fails. For more specific instructions for your OS:
https://cryptography.io/en/latest/installation/

Usage
-----

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
----------

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

``mrcrypt encrypt -r us-east-1 us-west-2 -- alias/master-key secrets.txt``

Decryption
----------

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
'''''''

Running tests for mrcrypt is easy if you have ``tox`` installed. Simply
run ``tox`` at the project's root.
