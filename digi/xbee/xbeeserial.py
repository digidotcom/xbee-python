# Copyright 2017, Digi International Inc.
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

from serial import Serial, EIGHTBITS, STOPBITS_ONE, PARITY_NONE
import enum
import digi.xbee.exception


class FlowControl(enum.Enum):
    """
    This class represents all available flow controls.
    """

    NONE = None
    SOFTWARE = 0
    HARDWARE_RTS_CTS = 1
    HARDWARE_DSR_DTR = 2
    UNKNOWN = 99


class XBeeSerialPort(Serial):
    """
    This class extends the functionality of Serial class (PySerial).

    .. seealso::
       | _PySerial: https://github.com/pyserial/pyserial
    """

    __DEFAULT_PORT_TIMEOUT = 0.1  # seconds
    __DEFAULT_DATA_BITS = EIGHTBITS
    __DEFAULT_STOP_BITS = STOPBITS_ONE
    __DEFAULT_PARITY = PARITY_NONE
    __DEFAULT_FLOW_CONTROL = FlowControl.NONE

    def __init__(self, baud_rate, port,
                 data_bits=__DEFAULT_DATA_BITS, stop_bits=__DEFAULT_STOP_BITS, parity=__DEFAULT_PARITY,
                 flow_control=__DEFAULT_FLOW_CONTROL, timeout=__DEFAULT_PORT_TIMEOUT):
        """
        Class constructor. Instantiates a new ``XBeeSerialPort`` object with the given
        port parameters.

        Args:
            baud_rate (Integer): serial port baud rate.
            port (String): serial port name to use.
            data_bits (Integer, optional): serial data bits. Default to 8.
            stop_bits (Float, optional): serial stop bits. Default to 1.
            parity (Char, optional): serial parity. Default to 'N' (None).
            flow_control (Integer, optional): serial flow control. Default to ``None``.
            timeout (Integer, optional): read timeout. Default to 0.1 seconds.

        .. seealso::
           | _PySerial: https://github.com/pyserial/pyserial
        """
        if flow_control == FlowControl.SOFTWARE:
            Serial.__init__(self, port=port, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout, xonxoff=True)
        elif flow_control == FlowControl.HARDWARE_DSR_DTR:
            Serial.__init__(self, port=port, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout, dsrdtr=True)
        elif flow_control == FlowControl.HARDWARE_RTS_CTS:
            Serial.__init__(self, port=port, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout, rtscts=True)
        else:
            Serial.__init__(self, port=port, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout)
        self._isOpen = True if port is not None else False

    def read_byte(self):
        """
        Synchronous. Reads one byte from serial port.

        Returns:
            Integer: the read byte.

        Raises:
            TimeoutException: if there is no bytes ins serial port buffer.
        """
        byte = bytearray(self.read(1))
        if len(byte) == 0:
            raise digi.xbee.exception.TimeoutException()
        else:
            return byte[0]

    def read_bytes(self, num_bytes):
        """
        Synchronous. Reads the specified number of bytes from the serial port.

        Args:
            num_bytes (Integer): the number of bytes to read.

        Returns:
            Bytearray: the read bytes.

        Raises:
            TimeoutException: if the number of bytes read is less than ``num_bytes``.
        """
        read_bytes = bytearray(self.read(num_bytes))
        if len(read_bytes) != num_bytes:
            raise digi.xbee.exception.TimeoutException()
        return read_bytes

    def read_existing(self):
        """
        Asynchronous. Reads all bytes in the serial port buffer. May read 0 bytes.

        Returns:
            Bytearray: the bytes read.
        """
        return bytearray(self.read(self.inWaiting()))

    def get_read_timeout(self):
        """
        Returns the serial port read timeout.

        Returns:
            Integer: read timeout in seconds.
        """
        return self.timeout

    def set_read_timeout(self, read_timeout):
        """
        Sets the serial port read timeout in seconds.

        Args:
            read_timeout (Integer): the new serial port read timeout in seconds.
        """
        self.timeout = read_timeout
