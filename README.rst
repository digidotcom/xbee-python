Digi XBee Python 2 library
======================================================

This project contains the source code of the XBee Python library, an
easy-to-use API developed in Python that allows you to interact with Digi
International's `XBee <https://www.digi.com/xbee>`_ radio frequency (RF)
modules. Modifications were made to satisfy use in python 2 with Digi XTend Modules.

The code is still under development, but it is a working prototype for Python 2 usage of the modules.

Install from Source
-------------------

You can install XBee Python library directly from the source file. To do
so, extract the source code to your computer and, from its root
directory, execute the following command::

    $ python setup.py install


Documentation
-------------

XBee Python library has user guide and API reference documentation hosted on
Read the Docs. You can find the latest, most up to date, documentation at
`latest docs <https://xbplib.readthedocs.io/en/latest>`_. To see only those
features which have been released, check out the
`stable docs <https://xbplib.readthedocs.io/en/stable>`_.

In addition to the official documentation from Digi, the python 2 library "copy" is required.


License
-------

Copyright 2017-2019, Digi International Inc.

The `MPL 2.0 license <https://github.com/digidotcom/xbee-python/blob/master/LICENSE.txt>`_
covers the majority of this project with the following exceptions:

* The `ISC license <https://github.com/digidotcom/xbee-python/blob/master/examples/LICENSE.txt>`_
  covers the contents of the examples directory.

.. |pypiversion| image:: https://badge.fury.io/py/digi-xbee.svg
    :target: https://pypi.org/project/digi-xbee/
.. |pythonversion| image:: https://img.shields.io/pypi/pyversions/digi-xbee.svg
    :alt: PyPI - Python Version