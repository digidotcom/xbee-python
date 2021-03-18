# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright 2017-2020, Digi International Inc. All Rights Reserved.
import os
import sys

from codecs import open

from setuptools import setup, find_namespace_packages

DEPENDENCIES = (
    'pyserial>=3',
    'srp',
)

# 'setup.py build' shortcut.
if sys.argv[-1] == 'build':
    os.system('python setup.py sdist bdist_wheel')
    sys.exit()

# 'setup.py publish' shortcut, uses the .pypirc in your home directory.
if sys.argv[1] == 'publish':
    repo = " -r %s" % sys.argv[2] if len(sys.argv) > 2 else ""
    os.system('python setup.py sdist bdist_wheel')
    os.system('twine upload%s dist/*' % repo)
    sys.exit()

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, 'digi', 'xbee', '__init__.py'), 'r', 'utf-8') as f:
    exec(f.read(), about)

with open(os.path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name=about['__title__'],
    namespace_packages=['digi'],
    version=about['__version__'],
    description=about['__description__'],
    long_description=long_description,
    long_description_content_type='text/x-rst',
    url=about['__url__'],
    author=about['__author__'],
    author_email=about['__author_email__'],
    packages=find_namespace_packages(include=['digi.*']),
    package_data={'': ['LICENSE.txt']},
    include_package_data=True,
    keywords=['xbee', 'IOT', 'wireless', 'radio frequency'],
    license=about['__license__'],
    python_requires=">=3, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*",
    install_requires=[
        'pyserial>=3',
    ],
    extras_require={
        "SRP":  ["srp"],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Software Development :: Libraries',
        'Topic :: Home Automation',
        'Topic :: Games/Entertainment',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Operating System :: OS Independent',
    ],
    project_urls={
        'Documentation': 'https://xbplib.readthedocs.io',
        'Source': 'https://github.com/digidotcom/xbee-python',
        'Tracker': 'https://github.com/digidotcom/xbee-python/issues',
    },
)
