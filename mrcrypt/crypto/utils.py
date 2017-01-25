"""
mrcrypt.crypto.utils
~~~~~~~~~~~~~~~~~~~~

Contains utility functions used by the crypto package.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_hkdf_key(plaintext_data_key, info=None):
    """Derive a key from a plaintext data key.

    :param plaintext_data_key: The data key to convert.
    :param info: (optional) A byte string containing application specific context information. In
                 the case of a frame, this should be the algorithm ID and message ID from the
                 header.

    :return: A key derived from ``plaintext_data_key``.
    """
    if len(plaintext_data_key) != 32:
        raise ValueError('Expected a key of length 32')

    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=len(plaintext_data_key),
        salt=None,
        info=info,
        backend=default_backend()
    )

    key = hkdf.derive(plaintext_data_key)

    return key
