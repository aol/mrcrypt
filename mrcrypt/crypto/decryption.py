"""
mrcrypt.crypto.decryption
~~~~~~~~~~~~~~~~~~~~~~~~~

Implements the decryption logic.
"""
import base64
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import boto3

import mrcrypt.crypto.utils
from mrcrypt import utils
from mrcrypt.crypto.constants import FRAME_STRING_ID, FINAL_FRAME_STRING_ID


def decrypt_message(message, profile=None):
    """Decrypts the content inside of the provided :class:`mrcrypt.message.Message` object."""
    validate_message_integrity(message, profile=profile)
    decryption_handler = DecryptionHandler(message)
    return decryption_handler.decrypt_content(profile=profile)


class DecryptionHandler(object):
    """An object that can decrypt the content contained in a :class:`mrcrypt.message.Message`
    object."""
    def __init__(self, message_):
        self._message = message_

    def decrypt_content(self, profile=None):
        """Decrypts the content contained by a message, and returns it as a string."""
        key = get_key_from_header(self._message.header, profile=profile)

        content = ''

        for i, frame in enumerate(self._message.body.frames[:-1]):
            content += decrypt_framed_content(frame, key, self._message.header.message_id,
                                              is_final_frame=False)

        content += decrypt_framed_content(self._message.body.frames[-1], key,
                                          self._message.header.message_id, is_final_frame=True)

        return content


def decrypt_framed_content(frame, key, message_id, is_final_frame):
    """Decrypts the content inside ``frame``.

    :param frame: The frame to decrypt.
    :param key: The key to decrypt with.
    :param message_id: The message ID of the Message that ``frame`` belongs to.
    :param is_final_frame: A boolean representing if ``frame`` is the final frame in the message.

    :return: The decrypted frame content.
    """
    decryptor = get_decryptor(key, frame.iv, frame.authentication_tag)

    frame_string_id = FINAL_FRAME_STRING_ID if is_final_frame else FRAME_STRING_ID

    content_aad = (message_id +
                   frame_string_id +
                   utils.num_to_bytes(frame.sequence_number, 4) +
                   utils.num_to_bytes(frame.encrypted_content_length, 8))

    decryptor.authenticate_additional_data(content_aad)

    return decryptor.update(frame.encrypted_content) + decryptor.finalize()


def get_decryptor(key, iv, authentication_tag):
    """Get a :class:`cryptography.hazmat.primitives.ciphers.CipherContext` object to use for
    decryption, configured with ``encryption_key``, ``iv``, and ``authentication_tag``."""
    return Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.GCM(iv, authentication_tag),
        backend=default_backend()
    ).decryptor()


def get_key_from_header(header, profile=None):
    """Attempts to retrieve a data key from the encrypted data keys contained by
    ``self.message``."""
    # TODO: Accept a region to use when choosing a key from the command-line
    for key in header.encrypted_data_keys:
        region = utils.region_from_arn(key.key_provider_info.decode())

        session = boto3.Session(profile_name=profile)

        client = session.client('kms', region_name=region)

        data_key = client.decrypt(
            CiphertextBlob=key.encrypted_data_key,
            EncryptionContext=header.encryption_context)

        info = (utils.num_to_bytes(header.algorithm_id, 2) +
                header.message_id)

        key = mrcrypt.crypto.utils.derive_hkdf_key(data_key[u'Plaintext'], info)

        return key


def validate_message_integrity(message, profile=None):
    """Simply calls the two validation methods to validate the header and entire message.

    **NOTE:** The body is validated during the decryption of the body's content."""
    validate_header(message.header, profile=profile)
    if message.header.algorithm.trailing_signature_algorithm is not None:
        validate_message(message)


def validate_header(header, profile=None):
    """Validates the header using the header's authentication tag."""
    key = get_key_from_header(header, profile=profile)
    decryptor = get_decryptor(key, header.iv,
                              header.authentication_tag)

    decryptor.authenticate_additional_data(header.serialize_authenticated_fields())
    decryptor.finalize()

    logging.info("Header integrity verified.")


def validate_message(message):
    """Validates the entire message using the signature found in the message footer."""
    encoded_point = base64.b64decode(message.header.encryption_context['aws-crypto-public-key'])
    public_numbers = EllipticCurvePublicNumbers.from_encoded_point(ec.SECP384R1(), encoded_point)
    public_key = public_numbers.public_key(default_backend())
    verifier = public_key.verifier(message.footer.signature, ec.ECDSA(hashes.SHA384()))

    verifier.update(message.serialize_authenticated_fields())
    verifier.verify()

    logging.info("Message integrity verified.")
