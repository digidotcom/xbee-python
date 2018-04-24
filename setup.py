# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2017, 2018, Digi International Inc. All Rights Reserved.

from setuptools import setup, find_packages
from codecs import open
from os import path


DEPENDENCIES = (
    'pyserial>=3',
)

here = path.abspath(path.dirname(__file__))
 
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()
 
setup(
    name='digi-xbee',
    version='1.1.1',
    description='Digi XBee Python library',
    long_description=long_description,
    url='https://github.com/digidotcom/python-xbee',
    author='Digi International Inc.',
    author_email='tech.support@digi.com',
    packages=find_packages(exclude=('unit_test*', 'functional_tests*', 'demos*')),
    keywords=['xbee', 'IOT', 'wireless', 'radio frequency'],
    license='Mozilla Public License 2.0 (MPL 2.0)',
    python_requires='>=3',
    install_requires=[
        'pyserial>=3',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Software Development :: Libraries',
        'Topic :: Home Automation',
        'Topic :: Games/Entertainment',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
)
