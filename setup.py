import os

from setuptools import setup

from libpunchq.__init__ import __version__


def _package_files(directory, suffix):
    """
        Get all of the file paths in the directory specified by suffix.

        :param directory:
        :return:
    """

    paths = []

    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith(suffix):
                paths.append(os.path.join('..', path, filename))

    return paths


# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# read the package requirements for install_requires
with open(os.path.join(here, 'requirements.txt'), 'r') as f:
    requirements = f.readlines()

# setup!
setup(
    name='punch-q',
    description='A small utility to play with IBM Websphere MQ',
    long_description='punch-q is a small ultility used to play with IBM MQ',

    license='GPL-3',

    author='Leon Jacobs',
    author_email='leon@sensepost.com',

    url='https://github.com/sensepost/punch-q',
    download_url='https://github.com/sensepost/punch-q/archive/' + __version__ + '.tar.gz',

    keywords=['ibm', 'websphere', 'mq', 'security'],
    version=__version__,

    # include the wordlists!
    package_data={
        '': _package_files(os.path.join(here, 'libpunchq/wordlists'), '.txt')
    },

    python_requires='>=3.6',
    packages=[
        'libpunchq',
    ],
    install_requires=requirements,
    classifiers=[
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
    ],
    entry_points={
        'console_scripts': [
            'punch-q=libpunchq.cli:cli',
        ],
    },
)
