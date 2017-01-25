"""
mrcrypt.message.body
~~~~~~~~~~~~~~~~~~~~

Implements the objects that represent the body of a message.
"""
from mrcrypt import exceptions, utils

FINAL_FRAME_SEQUENCE_NUMBER = 0xFFFFFFFF


class FrameBody(object):
    """Represents the body of a message with Framed Content.

    :param header: The message header.
    :param frames: A list of :class:`Frame` objects.
    """
    def __init__(self, header=None, frames=None):
        self.header = header
        self.frames = [] if frames is None else frames

    def deserialize(self, byte_array, off):
        """Loads information from ``byte_array`` into this object."""
        complete = False
        parsed_bytes = 0

        while not complete:
            current_frame = Frame()

            parsed_bytes += current_frame.deserialize(byte_array, off + parsed_bytes,
                                                      self.header.iv_length,
                                                      self.header.frame_content_length,
                                                      self.header.algorithm.tag_length)

            self.frames.append(current_frame)

            complete = current_frame.is_final_frame

        return parsed_bytes

    def serialize(self):
        """Writes this object into a :class:`bytearray`."""
        byte_array = bytearray()

        for frame in self.frames:
            byte_array.extend(frame.serialize())

        return byte_array


class Frame(object):
    """Represents a single frame of the message body.

    :param is_final_frame: A boolean indicating whether this frame is the final frame or not.
    :param sequence_number: Indicates which frame number this is in the list of frames.
    :param iv: The IV used to encrypt the content of the frame.
    :param encrypted_content: The encrypted bytes.
    :param authentication_tag: A tag used to verify the integrity of this frame.
    """

    def __init__(self, is_final_frame=None, sequence_number=None, iv=None, encrypted_content=None,
                 authentication_tag=None):
        self.is_final_frame = is_final_frame
        self.sequence_number = sequence_number
        self.iv = iv
        self.encrypted_content = encrypted_content
        self.authentication_tag = authentication_tag

        self._encrypted_content_length = None
        self._iv_length = None
        self._encrypted_content_length = None
        self._authentication_tag_length = None

    @property
    def iv_length(self):
        return len(self.iv)

    @property
    def encrypted_content_length(self):
        return len(self.encrypted_content)

    @property
    def authentication_tag_length(self):
        return len(self.authentication_tag)

    def deserialize(self, byte_array, off, iv_length, encrypted_content_length,
                    authentication_tag_length):
        """Loads information from ``byte_array`` into this object."""
        self._iv_length = iv_length
        self._encrypted_content_length = encrypted_content_length
        self._authentication_tag_length = authentication_tag_length

        parsed_bytes = self._parse_sequence_number(byte_array, off)

        if self.sequence_number == FINAL_FRAME_SEQUENCE_NUMBER:
            self.is_final_frame = True
            parsed_bytes += self._parse_sequence_number(byte_array, off + parsed_bytes)
        else:
            self.is_final_frame = False

        parsed_bytes += self._parse_iv(byte_array, parsed_bytes + off)

        if self.is_final_frame:
            parsed_bytes += self._parse_encrypted_content_length(byte_array, off + parsed_bytes)
            parsed_bytes += self._parse_encrypted_content(byte_array, off + parsed_bytes)
        else:
            parsed_bytes += self._parse_encrypted_content(byte_array, off + parsed_bytes)

        parsed_bytes += self._parse_authentication_tag(byte_array, off + parsed_bytes)

        return parsed_bytes

    def serialize(self):
        """Writes this object into a :class:`bytearray`."""
        byte_array = bytearray()

        if self.is_final_frame:
            byte_array.extend(utils.num_to_bytes(FINAL_FRAME_SEQUENCE_NUMBER, 4))

        byte_array.extend(utils.num_to_bytes(self.sequence_number, 4))
        byte_array.extend(self.iv)

        if self.is_final_frame:
            byte_array.extend(utils.num_to_bytes(self.encrypted_content_length, 4))

        byte_array.extend(self.encrypted_content)
        byte_array.extend(self.authentication_tag)

        return byte_array

    def _parse_sequence_number(self, byte_array, off):
        self.sequence_number = utils.bytes_to_int(byte_array[off:off + 4])
        return 4

    def _parse_iv(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._iv_length:
            raise exceptions.ParseError('Not enough bytes to parse IV')

        self.iv = byte_array[off:off + self._iv_length]

        return self._iv_length

    def _parse_encrypted_content_length(self, byte_array, off):
        self._encrypted_content_length = utils.bytes_to_int(byte_array[off:off + 4])

        if self._encrypted_content_length < 0:
            raise exceptions.BadCipherTextError('Invalid encrypted content length ({})'
                                                .format(self._encrypted_content_length))

        return 4

    def _parse_encrypted_content(self, byte_array, off):
        self.encrypted_content = byte_array[off:off + self._encrypted_content_length]
        return self._encrypted_content_length

    def _parse_authentication_tag(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._authentication_tag_length:
            raise exceptions.ParseError('Not enough bytes to parse authentication tag')

        self.authentication_tag = byte_array[off:off + self._authentication_tag_length]

        return self._authentication_tag_length
