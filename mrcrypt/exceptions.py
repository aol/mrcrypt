"""
mrcrypt.exceptions
~~~~~~~~~~~~~~~~~~

Contains the exceptions used by mrcrypt.
"""


class BadCipherTextError(Exception):
    """Raised when a parsed value is invalid."""
    pass


class ParseError(Exception):
    """Raised when something prevents the parsing from continuing."""
    pass


class InvalidContentTypeError(Exception):
    """Raised when the header's content type is not valid/supported."""
    pass


class UnsupportedFileObject(Exception):
    """Raised when the file passed into the command line is not a file."""
    pass
