"""
mrcrypt.algorithms
~~~~~~~~~~~~~~~~~~

Contains named tuples that describe different algorithms supported by this tool.
"""
from collections import namedtuple

#: Max unsigned 16 bit number
GCM_MAX_CONTENT_LENGTH_BITS = (1 << 16) - 1

#: All lengths are in bytes, unless stated otherwise.
AlgorithmProfile = namedtuple('AlgorithmProfile',
                              'block_size_bits, iv_length, tag_length, max_content_length_bits, '
                              'key_algorithm, key_length, id, data_key_algorithm, '
                              'data_key_length, trailing_signature_algorithm, '
                              'trailing_signature_length_bits')

alg_aes_128_gcm_iv12_tag16_no_kdf = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=16,
    id=0x0014,
    data_key_algorithm='AES',
    data_key_length=16,
    trailing_signature_algorithm=None,
    trailing_signature_length_bits=None)

alg_aes_192_gcm_iv12_tag16_no_kdf = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=24,
    id=0x0046,
    data_key_algorithm='AES',
    data_key_length=24,
    trailing_signature_algorithm=None,
    trailing_signature_length_bits=None)

alg_aes_256_gcm_iv12_tag16_no_kdf = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=32,
    id=0x0078,
    data_key_algorithm='AES',
    data_key_length=32,
    trailing_signature_algorithm=None,
    trailing_signature_length_bits=None)

alg_aes_128_gcm_iv12_tag16_hkdf_sha256 = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=16,
    id=0x0114,
    data_key_algorithm='HkdfSHA256',
    data_key_length=16,
    trailing_signature_algorithm=None,
    trailing_signature_length_bits=None)

alg_aes_192_gcm_iv12_tag16_hkdf_sha256 = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=24,
    id=0x0146,
    data_key_algorithm='HkdfSHA256',
    data_key_length=24,
    trailing_signature_algorithm=None,
    trailing_signature_length_bits=None)

alg_aes_256_gcm_iv12_tag16_hkdf_sha256 = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=32,
    id=0x0178,
    data_key_algorithm='HkdfSHA256',
    data_key_length=32,
    trailing_signature_algorithm=None,
    trailing_signature_length_bits=None)

alg_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256 = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=16,
    id=0x0214,
    data_key_algorithm='HkdfSHA256',
    data_key_length=16,
    trailing_signature_algorithm='SHA256withECDSA',
    trailing_signature_length_bits=72)

alg_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=24,
    id=0x0346,
    data_key_algorithm='HkdfSHA384',
    data_key_length=24,
    trailing_signature_algorithm='SHA384withECDSA',
    trailing_signature_length_bits=104)

alg_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 = AlgorithmProfile(
    block_size_bits=128,
    iv_length=12,
    tag_length=16,
    max_content_length_bits=GCM_MAX_CONTENT_LENGTH_BITS,
    key_algorithm='AES',
    key_length=32,
    id=0x0378,
    data_key_algorithm='HkdfSHA384',
    data_key_length=32,
    trailing_signature_algorithm='SHA384withECDSA',
    trailing_signature_length_bits=104)


def algorithm_from_id(algorithm_id):
    """Retrieves an :class:`AlgorithmProfile` from ``algorithm_id``."""
    mapping = _get_mapping()
    try:
        return mapping[algorithm_id]
    except KeyError:
        raise ValueError('The number {} does not map to an algorithm'.format(algorithm_id))


def _get_mapping():
    """Builds a dictionary, mapping IDs to their corresponding :class:`AlgorithmProfile`."""
    return dict((v.id, v) for v in globals().values() if type(v) is AlgorithmProfile)


def default_algorithm():
    return alg_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
