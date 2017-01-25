"""
mrcrypt.crypto.encryption
~~~~~~~~~~~~~~~~~~~~~~~~~

Implements the encryption logic.
"""
import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

import mrcrypt.algorithms
import mrcrypt.crypto.utils
from mrcrypt import message, utils
from mrcrypt.crypto.constants import FINAL_FRAME_STRING_ID, FRAME_STRING_ID
from mrcrypt import exceptions


def encrypt_string(s, master_key_id, regions=None, profile=None, encryption_context=None):
    """Encrypts a string with the given CMK in the regions provided.

    :param s: The string to encrypt.
    :param master_key_id: The key id of a CMK (alias, arn, etc.).
    :param regions: (optional) A list of regions.
    :param profile: (optional) A named profile
    :param encryption_context: (optional) An dictionary to use when encrypting.

    :return: A :class:`mrcrypt.message.Message` containing the encrypted string.
    """
    regions = [] if regions is None else regions

    kms_clients = utils.get_kms_clients(regions, profile)

    handler = EncryptionHandler(kms_clients, master_key_id)

    return handler.encrypt_string(s, encryption_context)


class EncryptionHandler(object):
    """An object that can encrypt a string into a :class:`mrcrypt.message.Message` object.

    :param kms_clients: A list of boto3 clients connected to KMS.
    :param master_key_id: The ID of a CMK.
    :param algorithm: (optional) A :class:`mrcrypt.algorithm.AlgorithmProfile` object.
    :param frame_size: (optional) The size of the content in a single frame.
    """

    def __init__(self, kms_clients, master_key_id,
                 algorithm=mrcrypt.algorithms.default_algorithm(), frame_size=4096):
        self.kms_clients = kms_clients
        self.master_key_id = master_key_id
        self.algorithm = algorithm
        self.frame_size = frame_size

        # TODO: Support the other algorithms
        if self.algorithm != mrcrypt.algorithms.default_algorithm():
            raise NotImplementedError

        if self.algorithm.trailing_signature_algorithm is not None:
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

            self.signer = private_key.signer(ec.ECDSA(hashes.SHA384()))

            public_curve_point = get_public_compressed_curve_point(private_key)
            self.encryption_context = {'aws-crypto-public-key': public_curve_point}

    def encrypt_string(self, s, encryption_context=None):
        """Encrypts the given string, returning a :class:`mrcrypt.message.Message` containing that
        encrypted string."""
        encryption_context = {} if encryption_context is None else encryption_context

        self.encryption_context.update(encryption_context)

        data_key = self.get_data_key(self.encryption_context)
        encrypted_data_keys = self.get_encrypted_data_keys(data_key, self.encryption_context)

        header = message.Header(
            version=1,
            type_=0x80,
            algorithm_id=self.algorithm.id,
            message_id=os.urandom(16),
            encryption_context=self.encryption_context,
            encrypted_data_keys=encrypted_data_keys,
            content_type=2,
            reserved_field=0,
            frame_content_length=self.frame_size,
            iv=os.urandom(self.algorithm.iv_length)
        )

        info = utils.num_to_bytes(header.algorithm_id, 2) + header.message_id

        encryption_key = mrcrypt.crypto.utils.derive_hkdf_key(data_key['Plaintext'], info)

        header_authentication_tag = sign_bytes(header.serialize_authenticated_fields(),
                                               encryption_key, header.iv)

        header.authentication_tag = header_authentication_tag

        if header.content_type == 1:
            raise NotImplementedError
        elif header.content_type == 2:
            body = _encrypt_as_framed(s, header, encryption_key, self.frame_size)
        else:
            raise exceptions.InvalidContentTypeError(
                "Header's content type had a value of {}".format(header.content_type))

        message_bytes = str(header.serialize() + body.serialize())

        self.signer.update(message_bytes)

        footer = message.Footer(self.signer.finalize())

        return message.Message(header, body, footer)

    def get_data_key(self, encryption_context=None):
        """Requests a data key from KMS with the first KMS client."""
        return self.kms_clients[0].generate_data_key(
            KeyId=self.master_key_id,
            KeySpec='AES_256',
            EncryptionContext=encryption_context)

    def get_encrypted_data_keys(self, data_key, encryption_context):
        """Returns a list of data keys, encrypted by KMS in every region listed inside
        ``self.region``."""
        encrypted_data_keys = [message.header.EncryptedDataKey(b'aws-kms',
                                                               bytes(data_key['KeyId']),
                                                               bytes(data_key['CiphertextBlob']))]

        for client in self.kms_clients[1:]:
            key = client.encrypt(KeyId=self.master_key_id,
                                 Plaintext=data_key['Plaintext'],
                                 EncryptionContext=encryption_context)
            encrypted_data_key = message.header.EncryptedDataKey(b'aws-kms',
                                                                 bytes(key['KeyId']),
                                                                 bytes(key['CiphertextBlob']))
            encrypted_data_keys.append(encrypted_data_key)

        return encrypted_data_keys


def _encrypt_as_framed(s, header, encryption_key, frame_size=4096):
    """Encrypts the provided string into frames of ``frame_size``.

    :param s: The string to encrypt.
    :param header: A :class:`mrcrypt.message.Header` object.
    :param encryption_key: The key to encrypt the frame content with.
    :param frame_size: (optional) The size of the content inside each frame.

    :return: A list of :class:`mrcrypt.message.body.Frame` objects.
    """
    frames = []

    for i, unencrypted_content in enumerate(utils.split(s, frame_size), start=1):
        final_frame = len(unencrypted_content) != frame_size

        frame_string_id = FINAL_FRAME_STRING_ID if final_frame else FRAME_STRING_ID

        content_aad = (header.message_id + frame_string_id + utils.num_to_bytes(i, 4) +
                       utils.num_to_bytes(len(unencrypted_content), 8))

        frame_iv = os.urandom(header.algorithm.iv_length)

        encryptor = get_encryptor(encryption_key, frame_iv)

        encryptor.authenticate_additional_data(content_aad)

        ciphertext = encryptor.update(unencrypted_content) + encryptor.finalize()

        frame = message.body.Frame(
            is_final_frame=final_frame,
            sequence_number=i,
            iv=frame_iv,
            encrypted_content=ciphertext,
            authentication_tag=encryptor.tag
        )

        frames.append(frame)

    return message.FrameBody(header, frames)


def get_public_compressed_curve_point(private_key):
    """Returns a base-64 encoded compressed curve point from an
    :class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey` object."""
    encoded_point = private_key.public_key().public_numbers().encode_point()
    return base64.b64encode(encoded_point)


def sign_bytes(bytes_, encryption_key, iv):
    """Generates a authentication tag which can authenticate ``bytes_``.

    :param bytes_: The byte string to sign.
    :param encryption_key: The encryption key to use.
    :param iv: The initialization vector.

    :return: The authentication tag.
    """
    encryptor = get_encryptor(encryption_key, iv)

    encryptor.authenticate_additional_data(bytes_)

    encryptor.finalize()

    return encryptor.tag


def get_encryptor(encryption_key, iv):
    """Get a :class:`cryptography.hazmat.primitives.ciphers.CipherContext` object to use for
    encryption, configured with ``encryption_key`` and a ``iv``."""
    return Cipher(
        algorithm=algorithms.AES(encryption_key),
        mode=modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
