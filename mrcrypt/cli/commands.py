import os
import stat

import mrcrypt.io
from mrcrypt import crypto, exceptions, utils

ENCRYPTED_FILE_ENDING = ".encrypted"
DECRYPTED_FILE_ENDING = ".decrypted"


class EncryptCommand(object):
    """Represents the encrypt sub-command from the commandline.

    :param file_path: The path of the file or directory to act on.
    :param master_key_id: The CMK to use when generating a data key.
    :param outfile: (optional) The file to write to.
    :param regions: (optional) A list of regions.
    :param profile: (optional) The named profile to use when making requests to AWS.
    :param encryption_context: (optional) An encryption context to use during encryption.
    """
    def __init__(self, file_path, master_key_id, outfile=None, regions=None, profile=None,
                 encryption_context=None):
        if os.path.isdir(file_path) and outfile:
            raise ValueError("Cannot specify an outfile for a directory")

        self.file_path = file_path
        self.master_key_id = master_key_id
        self.profile = profile
        self.encryption_context = encryption_context
        self.outfile = outfile

        self.regions = [] if regions is None else regions

    def encrypt(self):
        """Handles encryption of both files and directory. If ``self.file_path`` is a directory,
        it recursively encrypts all the files in the directory."""
        if os.path.isfile(self.file_path):
            self._encrypt_file(self.file_path)
        elif os.path.isdir(self.file_path):
            for root, subdirs, files in os.walk(self.file_path):
                for filename in files:
                    self._encrypt_file(os.path.join(root, filename))
        else:
            raise exceptions.UnsupportedFileObject("{} is not a file".format(self.file_path))

    def _encrypt_file(self, filename):
        """Encrypts the contents of ``filename`` and writes the output."""
        parent_dir = utils.get_parent_dir_path(filename)

        contents = mrcrypt.io.read_plaintext_file(filename)

        message = crypto.encrypt_string(contents,
                                        self.master_key_id,
                                        self.regions,
                                        self.profile,
                                        self.encryption_context)

        outfile = self._generate_outfile(filename)
        mrcrypt.io.write_message(outfile, parent_dir, message)

    def _generate_outfile(self, filename):
        """Appends a ``.encrypted`` to infile, if ``self.outfile`` is None."""
        return filename + ENCRYPTED_FILE_ENDING if self.outfile is None else self.outfile


class DecryptCommand(object):
    """Represents the decrypt sub-command from the commandline.

    :param file_path: The path of the file or directory to act on.
    :param outfile: (optional) The file to write to.
    :param profile: (optional) The named profile to use when making requests to AWS.
    """
    def __init__(self, file_path, outfile=None, profile=None):
        self.file_path = file_path
        self.outfile = outfile
        self.profile = profile

    def decrypt(self):
        """Handles decryption of both files and a directory. If ``self.file_path`` is a directory,
        it recursively decrypts all the files in the directory."""
        if os.path.isfile(self.file_path):
            self._decrypt_file(self.file_path)
        elif os.path.isdir(self.file_path):
            for root, subdirs, files in os.walk(self.file_path):
                for filename in files:
                    self._decrypt_file(os.path.join(root, filename))
        else:
            raise exceptions.UnsupportedFileObject("{} is not a file".format(self.file_path))

    def _decrypt_file(self, filename):
        """Decrypts the contents of ``filename`` and writes the output to a file that's read only
        by the owner (0400)."""
        parent_dir = utils.get_parent_dir_path(filename)

        message = mrcrypt.io.parse_message_file(filename)
        content = crypto.decrypt_message(message, profile=self.profile)

        outfile = self._generate_outfile(filename)
        mrcrypt.io.write_str(outfile, parent_dir, content, stat.S_IRUSR)

    def _generate_outfile(self, filename):
        """If ``self.outfile`` is not None, returns ``self.outfile``. Otherwise it checks for the
        ``.encrypted`` extension and removes it. If it doesn't have the ``.encrypted`` extension,
        it appends a ``.decrypted`` to ``filename`` and returns it."""
        if self.outfile is None and filename.endswith(ENCRYPTED_FILE_ENDING):
            return filename[:-len(ENCRYPTED_FILE_ENDING)]
        elif self.outfile is None:
            return filename + DECRYPTED_FILE_ENDING
        else:
            return self.outfile
