"""
mrcrypt.message.message
~~~~~~~~~~~~~~~~~~~~~~~

Contains a single Message object that represents a message.
"""
from mrcrypt import exceptions
from mrcrypt.message import Header, FrameBody, Footer


class Message(object):
    """Represents the entire message.

    :param header: A message header.
    :param body: The message body.
    :param footer: The message footer (one may not exist).
    """

    def __init__(self, header=None, body=None, footer=None):
        self.header = header
        self.body = body
        self.footer = footer

    def deserialize(self, byte_array, off):
        """Loads information from ``byte_array`` into this object."""
        parsed_bytes = 0

        self.header = Header()
        parsed_bytes += self.header.deserialize(byte_array, off + parsed_bytes)

        if self.header.content_type == 2:
            self.body = FrameBody(header=self.header)
            parsed_bytes += self.body.deserialize(byte_array, off + parsed_bytes)
        else:
            raise NotImplementedError('Non-framed content not supported yet')

        if len(byte_array) - parsed_bytes > 0:
            self.footer = Footer()
            parsed_bytes += self.footer.deserialize(byte_array, off + parsed_bytes)

        if parsed_bytes != len(byte_array):
            raise exceptions.ParseError('Did not parse all the bytes')

        return parsed_bytes

    def serialize(self):
        """Writes this object to a byte string."""
        byte_array = bytearray(self.serialize_authenticated_fields())

        if self.footer is not None:
            byte_array.extend(self.footer.serialize())

        return str(byte_array)

    def serialize_authenticated_fields(self):
        """Writes the header and the body to a byte string. Useful for validating the message's
        integrity."""
        byte_array = bytearray()

        byte_array.extend(self.header.serialize())
        byte_array.extend(self.body.serialize())

        return str(byte_array)
