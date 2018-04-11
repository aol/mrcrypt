from setuptools import find_packages, setup


with open('README.rst', 'r') as f:
    readme = f.read()

setup(
    name='mrcrypt',
    version='2.0.0',
    description='A command-line tool that can encrypt/decrypt secrets using the AWS Encryption SDK '
                'for use in multiple AWS KMS regions.',
    long_description=readme,

    url='https://github.com/aol/mrcrypt',

    license='Apache 2.0',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],

    packages=find_packages(),

    entry_points={
        'console_scripts': [
            'mrcrypt=mrcrypt.main:main'
        ]
    },

    install_requires=[
        'aws-encryption-sdk-cli>=1.1.3'
    ],
)
