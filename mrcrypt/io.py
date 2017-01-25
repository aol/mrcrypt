"""
mrcrypt.io
~~~~~~~~~~

Implements IO related tasks.
"""
from __future__ import absolute_import
import io
import tempfile
import os

from mrcrypt.message import Message
from mrcrypt.exceptions import ParseError
from mrcrypt import utils


def parse_message_file(filename):
    """Reads ``filename`` into a :class:`mrcrypt.message.Message` object."""
    with io.open(filename, 'rb') as infile:
        byte_array = infile.read()

    message = Message()
    parsed_bytes = message.deserialize(byte_array, 0)

    if parsed_bytes != len(byte_array):
        raise ParseError('Did not parse enough bytes')

    return message


def write_message(filename, directory, message, permissions=None):
    """Writes ``message`` to ``filename`` in ``directory``. The file created has ``permissions``
    set as its permissions."""
    message_bytes = str(message.serialize())
    write_str(filename, directory, message_bytes, permissions)


def read_plaintext_file(filename):
    """Reads the contents of ``filename`` and returns it as a string."""
    with io.open(filename, 'rb') as infile:
        contents = infile.read()

    return contents


def write_str(filename, directory, content, permissions=None):
    """Writes ``content`` to ``filename`` in ``directory``. The file created has ``permissions``
    set as it's file permissions. ``content`` is written to a temporary file first, and then that
    file is renamed (atomically) into the correct file."""
    if not permissions:
        permissions = utils.get_default_file_permissions()
    with io.open(tempfile.mkstemp(prefix='.', suffix='.tmp', dir=directory)[1], 'wb+') as outfile:
        outfile.write(content)
        outfile.flush()
        os.fsync(outfile.fileno())

    os.chmod(outfile.name, permissions)
    os.rename(outfile.name, filename)
