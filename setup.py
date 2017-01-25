from setuptools import setup, find_packages


with open('README.rst', 'r') as f:
    readme = f.read()

setup(
    name='mrcrypt',
    version='1.0.0',
    description='A command-line tool that can encrypt/decrypt secrets using envelope encryption '
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
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
        'boto3>=0.0.17',
        'cryptography>=1.1',
    ],
)
