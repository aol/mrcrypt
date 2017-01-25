"""
mrcrypt.message.header
~~~~~~~~~~~~~~~~~~~~~~

Implements the objects that represent the header of a message.
"""
from mrcrypt import algorithms, exceptions, utils


class Header(object):
    """Represents the header of a message.

    :param version: The version of the message.
    :param type: The type of the message format.
    :param algorithm_id: The id of the algorithm used to encrypt the content of the message.
    :param message_id: A random 128-bit value that identifies this message.
    :param content_type: The type of encrypted content: non-framed (1) or framed (2).
    :param reserved_field: An empty field reserved for future use by AWS.
    :param frame_content_length: The length of the encrypted content inside a frame. 0 if
                                 the body is non-framed.
    :param iv: The initialization vector used for the header's authentication tag.
    :param authentication_tag: A tag used to validate the integrity of the header.
    :param encryption_context: A dictionary containing additional authenticated data.
    :param encrypted_data_keys: A list of encrypted data keys. The decrypted data key is what is
                                used to derive the key used for encrypting and decrypting the
                                message content.
    """

    def __init__(self, version=None, type_=None, algorithm_id=None, message_id=None,
                 encryption_context=None, encrypted_data_keys=None, content_type=None,
                 reserved_field=None, frame_content_length=None, iv=None, authentication_tag=None):
        self.version = version
        self.type = type_
        self.algorithm_id = algorithm_id
        self.message_id = message_id
        self.content_type = content_type
        self.reserved_field = reserved_field
        self.frame_content_length = frame_content_length
        self.iv = iv
        self.authentication_tag = authentication_tag

        self.encryption_context = {} if encryption_context is None else encryption_context
        self.encrypted_data_keys = [] if encrypted_data_keys is None else encrypted_data_keys

        # These are only used for validation during deserialization. If this object was not created
        # via deserialize(), then they will remain as `None`.
        self._encryption_context_length = None
        self._encryption_context = None
        self._encrypted_data_key_count = None
        self._iv_length = None

    @property
    def algorithm(self):
        return algorithms.algorithm_from_id(self.algorithm_id)

    @property
    def encryption_context_length(self):
        # Add two for key/value pair count
        return utils.dict_to_byte_length(self.encryption_context) + 2

    @property
    def encrypted_data_key_count(self):
        return len(self.encrypted_data_keys)

    @property
    def iv_length(self):
        return len(self.iv)

    def deserialize(self, byte_array, off):
        """Loads the information from ``byte_array`` into this object."""
        parsed_bytes = 0
        parsed_bytes += self._parse_version(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_type(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_algorithm_id(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_message_id(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_encryption_context_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_encryption_context(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_encrypted_data_key_count(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_encrypted_data_keys(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_content_type(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_reserved_field(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_iv_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_frame_content_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_iv(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_authentication_tag(byte_array, off + parsed_bytes)
        return parsed_bytes

    def serialize(self):
        """Writes this object into a byte string."""
        byte_array = bytearray(self.serialize_authenticated_fields())

        byte_array.extend(self.iv)
        byte_array.extend(self.authentication_tag)

        return str(byte_array)

    def serialize_authenticated_fields(self):
        """Writes all the authenticated fields into a byte string. The every field but the
        authentication tag field is an authenticated field. This function is useful for validating
        the header's integrity."""
        byte_array = bytearray()

        byte_array.extend(utils.num_to_bytes(self.version, 1))
        byte_array.extend(utils.num_to_bytes(self.type, 1))
        byte_array.extend(utils.num_to_bytes(self.algorithm_id, 2))
        byte_array.extend(self.message_id.zfill(16))

        byte_array.extend(utils.num_to_bytes(self.encryption_context_length, 2))
        byte_array.extend(_EncryptionContext.from_dict(self.encryption_context).serialize())

        byte_array.extend(utils.num_to_bytes(self.encrypted_data_key_count, 2))
        for key in self.encrypted_data_keys:
            byte_array.extend(key.serialize())

        byte_array.extend(utils.num_to_bytes(self.content_type, 1))
        byte_array.extend(utils.num_to_bytes(self.reserved_field, 4))
        byte_array.extend(utils.num_to_bytes(self.iv_length, 1))
        byte_array.extend(utils.num_to_bytes(self.frame_content_length, 4))

        return str(byte_array)

    def _parse_version(self, byte_array, off):
        self.version = utils.bytes_to_int(byte_array[off])

        if self.version != 1:
            raise exceptions.BadCipherTextError('Invalid version number ({})'.format(self.version))

        return 1

    def _parse_type(self, byte_array, off):
        self.type = utils.bytes_to_int(byte_array[off])

        if self.type != 0x80:
            raise exceptions.BadCipherTextError('Invalid message type ({})'.format(self.type))

        return 1

    def _parse_algorithm_id(self, byte_array, off):
        self.algorithm_id = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_message_id(self, byte_array, off):
        self.message_id = byte_array[off:off + 16]
        return 16

    def _parse_encryption_context_length(self, byte_array, off):
        self._encryption_context_length = utils.bytes_to_int(byte_array[off:off + 2])

        if self._encryption_context_length < 0:
            raise exceptions.BadCipherTextError('Invalid encryption context length ({})'
                                                .format(self._encryption_context_length))

        return 2

    def _parse_encryption_context(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._encryption_context_length:
            raise exceptions.ParseError('Not enough bytes to parse encryption context')

        self._encryption_context = _EncryptionContext()

        parsed_bytes = self._encryption_context.deserialize(byte_array, off)

        self.encryption_context = self._encryption_context.to_dict()

        if parsed_bytes != self._encryption_context_length:
            raise exceptions.ParseError('Did not properly parse encryption context')

        return self._encryption_context_length

    def _parse_encrypted_data_key_count(self, byte_array, off):
        self._encrypted_data_key_count = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_encrypted_data_keys(self, byte_array, off):
        parsed_bytes = 0

        for i in xrange(self._encrypted_data_key_count):
            data_key = EncryptedDataKey()
            parsed_bytes += data_key.deserialize(byte_array, off + parsed_bytes)
            self.encrypted_data_keys.append(data_key)

        return parsed_bytes

    def _parse_content_type(self, byte_array, off):
        self.content_type = utils.bytes_to_int(byte_array[off])

        if self.content_type not in (1, 2):
            raise exceptions.BadCipherTextError('Invalid content type ({})'
                                                .format(self.content_type))

        return 1

    def _parse_reserved_field(self, byte_array, off):
        self.reserved_field = utils.bytes_to_int(byte_array[off:off + 4])

        if self.reserved_field != 0:
            raise exceptions.BadCipherTextError('Invalid value for reserved field ({})'
                                                .format(self.reserved_field))

        return 4

    def _parse_iv_length(self, byte_array, off):
        self._iv_length = utils.bytes_to_int(byte_array[off])

        if self._iv_length < 0:
            raise exceptions.BadCipherTextError('Invalid IV length ({})'.format(self._iv_length))

        return 1

    def _parse_frame_content_length(self, byte_array, off):
        self.frame_content_length = utils.bytes_to_int(byte_array[off:off + 4])

        if self.frame_content_length < 0:
            raise exceptions.BadCipherTextError('Invalid frame length ({})'
                                                .format(self.frame_content_length))

        return 4

    def _parse_iv(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._iv_length:
            raise exceptions.ParseError('Not enough bytes to parse IV')

        self.iv = byte_array[off:off + self._iv_length]

        return self._iv_length

    def _parse_authentication_tag(self, byte_array, off):
        length = len(byte_array) - off

        tag_length = self.algorithm.tag_length

        if length < tag_length:
            raise exceptions.ParseError('Not enough bytes to parse authentication tag')

        self.authentication_tag = byte_array[off:off + tag_length]

        return tag_length


class _EncryptionContext(object):
    """Represents the encryption context.

    This object is simply a helper to deserialize and serialize the encryption context. The true
    encryption context exposed in the header is a dict.

    :param context_pairs: A list of :class:`_EncryptionContextKeyValuePair` objects.
    """

    def __init__(self, context_pairs=None):
        self.context_pairs = [] if context_pairs is None else context_pairs
        self._key_value_pair_count = None

    def deserialize(self, byte_array, off):
        """Loads the information from ``byte_array`` into this object."""
        parsed_bytes = 0
        parsed_bytes += self._parse_key_value_pair_count(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_key_value_pairs(byte_array, off + parsed_bytes)
        return parsed_bytes

    def serialize(self):
        """Writes this object into a :class:`bytearray`."""
        byte_array = bytearray()

        byte_array.extend(utils.num_to_bytes(len(self.context_pairs), 2))

        for pair in self.context_pairs:
            byte_array.extend(pair.serialize())

        return byte_array

    def _parse_key_value_pair_count(self, byte_array, off):
        self._key_value_pair_count = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_key_value_pairs(self, byte_array, off):
        parsed_bytes = 0

        for i in xrange(self._key_value_pair_count):
            pair = _EncryptionContextKeyValuePair()
            parsed_bytes += pair.deserialize(byte_array, off + parsed_bytes)
            self.context_pairs.append(pair)

        return parsed_bytes

    def to_dict(self):
        """Converts this object into a dict."""
        return dict((pair.key, pair.value) for pair in self.context_pairs)

    @classmethod
    def from_dict(cls, dict_):
        """Creates this object from ``dict_``."""
        pairs = [_EncryptionContextKeyValuePair(k, v) for k, v in dict_.iteritems()]
        return cls(pairs)


class _EncryptionContextKeyValuePair(object):
    """Represents a single key-value pair in the encryption context.

    :param key: The key of the key-value pair.
    :param value: The value of the key-value pair.
    """

    def __init__(self, key=None, value=None):
        self.key = key
        self.value = value

        self._key_length = None
        self._value_length = None

    @property
    def key_length(self):
        return len(self.key)

    @property
    def value_length(self):
        return len(self.value)

    def deserialize(self, byte_array, off):
        """Loads information from ``byte_array`` into this object."""
        parsed_bytes = 0
        parsed_bytes += self._parse_key_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_key(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_value_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_value(byte_array, off + parsed_bytes)
        return parsed_bytes

    def serialize(self):
        """Writes this object into a :class:`bytearray`."""
        byte_array = bytearray()
        byte_array.extend(utils.num_to_bytes(self.key_length, 2))
        byte_array.extend(self.key)
        byte_array.extend(utils.num_to_bytes(self.value_length, 2))
        byte_array.extend(self.value)
        return byte_array

    def _parse_key_length(self, byte_array, off):
        self._key_length = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_key(self, byte_array, off):
        self.key = byte_array[off:off + self._key_length]
        return self._key_length

    def _parse_value_length(self, byte_array, off):
        self._value_length = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_value(self, byte_array, off):
        self.value = byte_array[off:off + self._value_length]
        return self._value_length


class EncryptedDataKey(object):
    """Represents an encrypted data key.

    :param key_provider_id: The provider of the key. This tool only supports KMS.
    :param key_provider_info: Information about the key provider.
    :param encrypted_data_key: The encrypted data key.
    """
    def __init__(self, key_provider_id=None, key_provider_info=None, encrypted_data_key=None):
        self.key_provider_id = key_provider_id
        self.key_provider_info = key_provider_info
        self.encrypted_data_key = encrypted_data_key

        self._key_provider_id_length = None
        self._key_provider_info_length = None
        self._encrypted_data_key_length = None

    @property
    def key_provider_id_length(self):
        return len(self.key_provider_id)

    @property
    def key_provider_info_length(self):
        return len(self.key_provider_info)

    @property
    def encrypted_data_key_length(self):
        return len(self.encrypted_data_key)

    def deserialize(self, byte_array, off):
        """Loads the information in ``byte_array`` into this object."""
        parsed_bytes = 0
        parsed_bytes += self._parse_key_provider_id_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_key_provider_id(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_key_provider_info_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_key_provider_info(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_encrypted_data_key_length(byte_array, off + parsed_bytes)
        parsed_bytes += self._parse_encrypted_data_key(byte_array, off + parsed_bytes)
        return parsed_bytes

    def serialize(self):
        """Writes this object into a :class:`bytearray`."""
        byte_array = bytearray()
        byte_array.extend(utils.num_to_bytes(self.key_provider_id_length, 2))
        byte_array.extend(self.key_provider_id)
        byte_array.extend(utils.num_to_bytes(self.key_provider_info_length, 2))
        byte_array.extend(self.key_provider_info)
        byte_array.extend(utils.num_to_bytes(self.encrypted_data_key_length, 2))
        byte_array.extend(self.encrypted_data_key)
        return byte_array

    def _parse_key_provider_id_length(self, byte_array, off):
        self._key_provider_id_length = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_key_provider_id(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._key_provider_id_length:
            raise exceptions.ParseError('Not enough bytes to parse key provider id')

        self.key_provider_id = byte_array[off:off + self._key_provider_id_length]

        return self._key_provider_id_length

    def _parse_key_provider_info_length(self, byte_array, off):
        self._key_provider_info_length = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_key_provider_info(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._key_provider_info_length:
            raise exceptions.ParseError('Not enough bytes to parse key provider info')

        self.key_provider_info = byte_array[off:off + self._key_provider_info_length]

        return self._key_provider_info_length

    def _parse_encrypted_data_key_length(self, byte_array, off):
        self._encrypted_data_key_length = utils.bytes_to_int(byte_array[off:off + 2])
        return 2

    def _parse_encrypted_data_key(self, byte_array, off):
        length = len(byte_array) - off

        if length < self._encrypted_data_key_length:
            raise exceptions.ParseError('Not enough bytes to parse encrypted data key')

        self.encrypted_data_key = byte_array[off:off + self._encrypted_data_key_length]

        return self._encrypted_data_key_length
