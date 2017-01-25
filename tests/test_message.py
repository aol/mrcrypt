import struct
from collections import OrderedDict

import pytest

from mrcrypt import message

ONE_AS_ONE_BYTE = struct.pack('>B', 0x01)
ONE_AS_TWO_BYTES = struct.pack('>H', 0x0001)
ONE_AS_FOUR_BYTES = struct.pack('>L', 0x0000001)
ONE_AS_EIGHT_BYTES = struct.pack('>Q', 0x0000000000000001)
SIXTEEN_BYTES = struct.pack('>Q', 0x0000000000000000) + struct.pack('>Q', 0x0000000000000001)


def test_header__deserialize(header_bytes):
    header = message.Header()
    parsed_bytes = header.deserialize(header_bytes, 0)

    assert parsed_bytes == len(header_bytes)

    assert header.version == 1
    assert header.type == 0x80
    assert header.algorithm_id == 0x0014

    assert header.message_id == SIXTEEN_BYTES

    assert header.encryption_context_length == 8
    assert len(header.encryption_context) == 1

    context_pair = header.encryption_context.items()[0]
    assert context_pair == (ONE_AS_ONE_BYTE, ONE_AS_ONE_BYTE)

    assert len(header.encrypted_data_keys) == 1
    encrypted_data_key = header.encrypted_data_keys[0]

    assert encrypted_data_key.key_provider_id_length == 1
    assert encrypted_data_key.key_provider_id == ONE_AS_ONE_BYTE
    assert encrypted_data_key.key_provider_info_length == 1
    assert encrypted_data_key.key_provider_info == ONE_AS_ONE_BYTE
    assert encrypted_data_key.encrypted_data_key_length == 1
    assert encrypted_data_key.encrypted_data_key == ONE_AS_ONE_BYTE

    assert header.content_type == 1
    assert header.reserved_field == 0x00000000
    assert header.iv_length == 1
    assert header.frame_content_length == 1
    assert header.iv == ONE_AS_ONE_BYTE

    assert header.authentication_tag == SIXTEEN_BYTES


def test_header__deserialize_not_enough_bytes():
    with pytest.raises(IndexError):
        header = message.Header()
        header.deserialize(struct.pack('>B', 1), 0)


def test_header__serialize(header_bytes):
    encrypted_data_key = message.header.EncryptedDataKey(
        key_provider_id=ONE_AS_ONE_BYTE,
        key_provider_info=ONE_AS_ONE_BYTE,
        encrypted_data_key=ONE_AS_ONE_BYTE,
    )

    header = message.Header(
        version=1,
        type_=0x80,
        algorithm_id=0x0014,
        message_id=SIXTEEN_BYTES,
        encryption_context={ONE_AS_ONE_BYTE: ONE_AS_ONE_BYTE},
        encrypted_data_keys=[encrypted_data_key],
        content_type=1,
        reserved_field=0,
        frame_content_length=1,
        iv=ONE_AS_ONE_BYTE,
        authentication_tag=SIXTEEN_BYTES,
    )

    serialized_bytes = header.serialize()

    assert serialized_bytes == header_bytes


def test_header__serialize_multiple_encryption_contexts(header_bytes_multiple_encryption_contexts):
    encrypted_data_key = message.header.EncryptedDataKey(
        key_provider_id=ONE_AS_ONE_BYTE,
        key_provider_info=ONE_AS_ONE_BYTE,
        encrypted_data_key=ONE_AS_ONE_BYTE,
    )

    # dict's are unordered, which can mess up the tests.
    encryption_context = OrderedDict()
    encryption_context[ONE_AS_ONE_BYTE] = ONE_AS_ONE_BYTE
    encryption_context[ONE_AS_TWO_BYTES] = ONE_AS_TWO_BYTES

    header = message.Header(
        version=1,
        type_=0x80,
        algorithm_id=0x0014,
        message_id=SIXTEEN_BYTES,
        encryption_context=encryption_context,
        encrypted_data_keys=[encrypted_data_key],
        content_type=1,
        reserved_field=0,
        frame_content_length=1,
        iv=ONE_AS_ONE_BYTE,
        authentication_tag=SIXTEEN_BYTES,
    )

    serialized_bytes = header.serialize()

    assert serialized_bytes == header_bytes_multiple_encryption_contexts


def test_frame_body__deserialize(message_header, frame_body_bytes):
    body = message.FrameBody(header=message_header)
    parsed_bytes = body.deserialize(frame_body_bytes, 0)

    assert parsed_bytes == len(frame_body_bytes)

    assert len(body.frames) == 1

    frame = body.frames[0]

    assert frame.is_final_frame == True
    assert frame.sequence_number == 1

    assert frame.iv_length == 12
    assert frame.iv == ONE_AS_ONE_BYTE * 12

    assert frame.encrypted_content_length == 1
    assert frame.encrypted_content == ONE_AS_ONE_BYTE

    assert frame.authentication_tag_length == 16
    assert frame.authentication_tag == SIXTEEN_BYTES


def test_single_frame_body__serialize(message_header):
    iv = ONE_AS_ONE_BYTE * 12
    encrypted_content = ONE_AS_ONE_BYTE
    auth_tag = SIXTEEN_BYTES

    frame = message.body.Frame(True, 1, iv, encrypted_content, auth_tag)
    frame_body = message.FrameBody(header=message_header, frames=[frame])

    result = frame_body.serialize()

    expected_bytes = (struct.pack('>L', 0xFFFFFFFF) + ONE_AS_FOUR_BYTES + iv + ONE_AS_FOUR_BYTES +
                      encrypted_content + auth_tag)

    assert result == expected_bytes


@pytest.mark.parametrize("num_frames", [2, 3, 4, 8, 16])
def test_multi_frame_body__serialize(num_frames, message_header):
    frames = []

    expected_bytes = ""

    iv = ONE_AS_ONE_BYTE * 12
    auth_tag = SIXTEEN_BYTES

    for i in xrange(1, num_frames):
        encrypted_content = ONE_AS_ONE_BYTE * 4096

        frames.append(message.body.Frame(False, i, iv, encrypted_content, auth_tag))

        expected_bytes += struct.pack('>L', i) + iv + encrypted_content + auth_tag

    encrypted_content = ONE_AS_ONE_BYTE

    frames.append(message.body.Frame(True, num_frames, iv, encrypted_content, auth_tag))

    expected_bytes += (struct.pack('>L', 0xFFFFFFFF) + struct.pack('>L', num_frames) + iv +
                       ONE_AS_FOUR_BYTES + encrypted_content + auth_tag)

    body = message.FrameBody(header=message_header, frames=frames)

    result = body.serialize()

    assert result == expected_bytes


def test_footer__deserialize():
    byte_array = ONE_AS_TWO_BYTES + ONE_AS_ONE_BYTE

    footer = message.Footer()

    footer.deserialize(byte_array, 0)

    assert footer.signature == ONE_AS_ONE_BYTE
    assert footer.signature_length == 1


def test_footer__serialize():
    footer = message.Footer(signature=ONE_AS_ONE_BYTE)

    result = footer.serialize()

    expected = ONE_AS_TWO_BYTES + ONE_AS_ONE_BYTE

    assert result == expected


@pytest.fixture
def header_bytes():
    """
    :func:`mrcrypt.utils.num_to_bytes` wasn't used because this function shouldn't be dependent on
    the correctness of it.
    """
    version = struct.pack('>B', 0x01)
    type_ = struct.pack('>B', 0x80)
    algorithm_id = struct.pack('>H', 0x0014)

    message_id = SIXTEEN_BYTES

    encryption_context_pair_count = ONE_AS_TWO_BYTES
    encryption_key_length = ONE_AS_TWO_BYTES
    encryption_context_key = ONE_AS_ONE_BYTE
    encryption_context_value_length = ONE_AS_TWO_BYTES
    encryption_context_value = ONE_AS_ONE_BYTE

    encryption_context = (encryption_context_pair_count + encryption_key_length +
                          encryption_context_key + encryption_context_value_length +
                          encryption_context_value)
    encryption_context_length = struct.pack('>H', len(encryption_context))

    encrypted_data_key_count = ONE_AS_TWO_BYTES

    key_provider_id_length = ONE_AS_TWO_BYTES
    key_provider_id = ONE_AS_ONE_BYTE
    key_provider_info_length = ONE_AS_TWO_BYTES
    key_provider_info = ONE_AS_ONE_BYTE
    encrypted_key_length = ONE_AS_TWO_BYTES
    encrypted_key = ONE_AS_ONE_BYTE

    encrypted_data_key = (key_provider_id_length + key_provider_id + key_provider_info_length +
                          key_provider_info + encrypted_key_length + encrypted_key)

    content_type = ONE_AS_ONE_BYTE
    reserved = struct.pack('>L', 0x00000000)
    iv_length = ONE_AS_ONE_BYTE
    frame_length = ONE_AS_FOUR_BYTES
    iv = ONE_AS_ONE_BYTE

    auth_tag = SIXTEEN_BYTES

    header_bytes_ = (version + type_ + algorithm_id + message_id + encryption_context_length +
                     encryption_context + encrypted_data_key_count + encrypted_data_key +
                     content_type + reserved + iv_length + frame_length + iv + auth_tag)

    return header_bytes_


@pytest.fixture
def header_bytes_multiple_encryption_contexts():
    version = struct.pack('>B', 0x01)
    type_ = struct.pack('>B', 0x80)
    algorithm_id = struct.pack('>H', 0x0014)

    message_id = SIXTEEN_BYTES

    encryption_context_pair_count = struct.pack('>H', 0x0002)
    encryption_context_key_length_one = ONE_AS_TWO_BYTES
    encryption_context_key_one = ONE_AS_ONE_BYTE
    encryption_context_value_length_one = ONE_AS_TWO_BYTES
    encryption_context_value_one = ONE_AS_ONE_BYTE

    encryption_context_key_length_two = struct.pack('>H', 0x0002)
    encryption_context_key_two = ONE_AS_TWO_BYTES
    encryption_context_value_length_two = struct.pack('>H', 0x0002)
    encryption_context_value_two = ONE_AS_TWO_BYTES

    encryption_context = (encryption_context_pair_count + encryption_context_key_length_one +
                          encryption_context_key_one + encryption_context_value_length_one +
                          encryption_context_value_one + encryption_context_key_length_two +
                          encryption_context_key_two + encryption_context_value_length_two +
                          encryption_context_value_two)
    encryption_context_length = struct.pack('>H', len(encryption_context))

    encrypted_data_key_count = ONE_AS_TWO_BYTES

    key_provider_id_length = ONE_AS_TWO_BYTES
    key_provider_id = ONE_AS_ONE_BYTE
    key_provider_info_length = ONE_AS_TWO_BYTES
    key_provider_info = ONE_AS_ONE_BYTE
    encrypted_key_length = ONE_AS_TWO_BYTES
    encrypted_key = ONE_AS_ONE_BYTE

    encrypted_data_key = (key_provider_id_length + key_provider_id + key_provider_info_length +
                          key_provider_info + encrypted_key_length + encrypted_key)

    content_type = ONE_AS_ONE_BYTE
    reserved = struct.pack('>L', 0x00000000)
    iv_length = ONE_AS_ONE_BYTE
    frame_length = ONE_AS_FOUR_BYTES
    iv = ONE_AS_ONE_BYTE

    auth_tag = SIXTEEN_BYTES

    header_bytes_ = (version + type_ + algorithm_id + message_id + encryption_context_length +
                     encryption_context + encrypted_data_key_count + encrypted_data_key +
                     content_type + reserved + iv_length + frame_length + iv + auth_tag)

    return header_bytes_


@pytest.fixture(params=[0x0014, 0x0046, 0x0078, 0x0114, 0x0146, 0x0178, 0x0214, 0x0346, 0x0378])
def message_header(request):
    algorithm_id = request.param

    encrypted_data_key = message.header.EncryptedDataKey(
        key_provider_id=ONE_AS_ONE_BYTE,
        key_provider_info=ONE_AS_ONE_BYTE,
        encrypted_data_key=ONE_AS_ONE_BYTE,
    )

    header = message.Header(
        version=1,
        type_=0x80,
        algorithm_id=algorithm_id,
        message_id=SIXTEEN_BYTES,
        encryption_context={ONE_AS_ONE_BYTE: ONE_AS_ONE_BYTE},
        encrypted_data_keys=[encrypted_data_key],
        content_type=1,
        reserved_field=0,
        frame_content_length=1,
        iv=ONE_AS_ONE_BYTE * 12,
        authentication_tag=SIXTEEN_BYTES,
    )

    return header


@pytest.fixture
def frame_body_bytes():
    sequence_number_end = struct.pack('>L', 0xFFFFFFFF)
    sequence_number = ONE_AS_FOUR_BYTES

    iv = ONE_AS_ONE_BYTE * 12

    encrypted_content_length = ONE_AS_FOUR_BYTES
    encrypted_content = ONE_AS_ONE_BYTE

    authentication_tag = SIXTEEN_BYTES

    return (sequence_number_end + sequence_number + iv + encrypted_content_length +
            encrypted_content + authentication_tag)
