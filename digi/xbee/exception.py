# Copyright 2017-2019, Digi International Inc.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


class XBeeException(Exception):
    """
    Generic XBee API exception. This class and its subclasses indicate
    conditions that an application might want to catch.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class CommunicationException(XBeeException):
    """
    This exception will be thrown when any problem related to the communication 
    with the XBee device occurs.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class ATCommandException(CommunicationException):
    """
    This exception will be thrown when a response of a packet is not success or OK.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "There was a problem sending the AT command packet."

    def __init__(self, message=__DEFAULT_MESSAGE, cmd_status=None):
        super().__init__(message)
        self.status = cmd_status


class ConnectionException(XBeeException):
    """
    This exception will be thrown when any problem related to the connection 
    with the XBee device occurs.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class XBeeDeviceException(XBeeException):
    """
    This exception will be thrown when any problem related to the XBee device 
    occurs.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class InvalidConfigurationException(ConnectionException):
    """
    This exception will be thrown when trying to open an interface with an
    invalid configuration.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "The configuration used to open the interface is invalid."

    def __init__(self, message=__DEFAULT_MESSAGE):
        super().__init__(message)


class InvalidOperatingModeException(ConnectionException):
    """
    This exception will be thrown if the operating mode is different than 
    *OperatingMode.API_MODE* and *OperatingMode.API_MODE*

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "The operating mode of the XBee device is not supported by the library."
    __DEFAULT_MSG_FORMAT = "Unsupported operating mode: %s (%d)"

    def __init__(self, message=None, op_mode=None):
        if op_mode and not message:
            message = InvalidOperatingModeException.__DEFAULT_MSG_FORMAT \
                      % (op_mode.description, op_mode.code)
        elif not message:
            message = InvalidOperatingModeException.__DEFAULT_MESSAGE

        super().__init__(message)
        self.__op_mode = op_mode


class InvalidPacketException(CommunicationException):
    """
    This exception will be thrown when there is an error parsing an API packet 
    from the input stream.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "The XBee API packet is not properly formed."

    def __init__(self, message=__DEFAULT_MESSAGE):
        super().__init__(message)


class OperationNotSupportedException(XBeeDeviceException):
    """
    This exception will be thrown when the operation performed is not supported 
    by the XBee device.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "The requested operation is not supported by either " \
                        "the connection interface or the XBee device."

    def __init__(self, message=__DEFAULT_MESSAGE):
        super().__init__(message)


class TimeoutException(CommunicationException):
    """
    This exception will be thrown when performing synchronous operations and 
    the configured time expires.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "There was a timeout while executing the requested operation."

    def __init__(self, message=__DEFAULT_MESSAGE):
        super().__init__(message)


class TransmitException(CommunicationException):
    """
    This exception will be thrown when receiving a transmit status different 
    than *TransmitStatus.SUCCESS* after sending an XBee API packet.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "There was a problem with a transmitted packet response (status not ok)"

    def __init__(self, message=__DEFAULT_MESSAGE, transmit_status=None):
        super().__init__(message)
        self.status = transmit_status


class XBeeSocketException(XBeeException):
    """
    This exception will be thrown when there is an error performing any socket operation.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    __DEFAULT_MESSAGE = "There was a socket error"
    __DEFAULT_STATUS_MESSAGE = "There was a socket error: %s (%d)"

    def __init__(self, message=__DEFAULT_MESSAGE, status=None):
        super().__init__(self.__DEFAULT_STATUS_MESSAGE % (status.description, status.code) if status is not None else
                         message)
        self.status = status


class FirmwareUpdateException(XBeeException):
    """
    This exception will be thrown when any problem related to the firmware update
    process of the XBee device occurs.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class RecoveryException(XBeeException):
    """
    This exception will be thrown when any problem related to the auto-recovery
    process of the XBee device occurs.

    All functionality of this class is the inherited of `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass
