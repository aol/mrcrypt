"""Main entry point for ``mrcrypt``."""
from mrcrypt.cli import parser


def main():
    """Main entry point for ``mrcrypt``."""
    return parser.parse()


if __name__ == '__main__':
    main()
