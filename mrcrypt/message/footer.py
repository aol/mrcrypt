"""
mrcrypt.message.footer
~~~~~~~~~~~~~~~~~~~~~~

Implements the objects that represent the footer of a message.
"""
from mrcrypt import exceptions, utils


class Footer(object):
    """Represents the footer of a message. The footer only exists if the message uses a signed
    algorithm.

    :param signature: The signature used to authenticate the integrity of the message.
    """

    def __init__(self, signature=None):
        self.signature = signature
        self._signature_length = None

    @property
    def signature_length(self):
        return len(self.signature)

    def deserialize(self, byte_array, off):
        """Load the information from ``byte_array`` into this object."""
        parsed_bytes = 0
        parsed_bytes += self._parse_signature_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_signature(byte_array, off + parsed_bytes)
        return parsed_bytes

    def serialize(self):
        """Write this object into a :class:`bytearray`."""
        byte_array = bytearray()
        byte_array.extend(utils.num_to_bytes(self.signature_length, 2))
        byte_array.extend(self.signature)
        return byte_array

    def _parse_signature_length(self, byte_array, off):
        self._signature_length = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_signature(self, byte_array, off):
        length = len(byte_array) - off
        if length < self._signature_length:
            raise exceptions.ParseError('Not enough bytes to parse signature')
        self.signature = byte_array[off:off + self._signature_length]
        return self._signature_length
