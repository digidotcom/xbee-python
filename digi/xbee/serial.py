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

import abc
import time
from abc import abstractmethod, ABCMeta

from digi.xbee.comm_interface import XBeeCommunicationInterface
from digi.xbee.models.atcomm import SpecialByte
from digi.xbee.models.mode import OperatingMode
from digi.xbee.packets.base import XBeeAPIPacket, XBeePacket
from digi.xbee.util import utils
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


class XBeeSerialPort(Serial, XBeeCommunicationInterface):
    """
    This class extends the functionality of Serial class (PySerial).

    It also introduces a minor change in its behaviour: the serial port is not automatically open when an object is
    instantiated, only when calling open().

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
            Serial.__init__(self, port=None, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout, xonxoff=True)
        elif flow_control == FlowControl.HARDWARE_DSR_DTR:
            Serial.__init__(self, port=None, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout, dsrdtr=True)
        elif flow_control == FlowControl.HARDWARE_RTS_CTS:
            Serial.__init__(self, port=None, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout, rtscts=True)
        else:
            Serial.__init__(self, port=None, baudrate=baud_rate,
                            bytesize=data_bits, stopbits=stop_bits, parity=parity, timeout=timeout)
        self.__port_to_open = port
        self._isReading = False

    def __str__(self):
        return '{name} {p.portstr!r}'.format(name=self.__class__.__name__, p=self)

    def open(self):
        """
        Opens port with current settings. This may throw a SerialException
        if the port cannot be opened.
        """
        self.port = self.__port_to_open
        super().open()

    @property
    def is_interface_open(self):
        """
        Returns whether the underlying hardware communication interface is active or not.

        Returns:
            Boolean. ``True`` if the interface is active, ``False`` otherwise.
        """
        return self.isOpen()

    def write_frame(self, frame):
        """
        Writes an XBee frame to the underlying hardware interface.

        Subclasses may throw specific exceptions to signal implementation specific
        hardware errors.

        Args:
            frame (:class:`.Bytearray`): The XBee API frame packet to write. If the bytearray does not
                                                  correctly represent an XBee frame, the behaviour is undefined.
        """
        self.write(frame)

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

    def __read_next_byte(self, operating_mode=OperatingMode.API_MODE):
        """
        Returns the next byte in bytearray format. If the operating mode is
        OperatingMode.ESCAPED_API_MODE, the bytearray could contain 2 bytes.

        If in escaped API mode and the byte that was read was the escape byte,
        it will also read the next byte.

        Args:
            operating_mode (:class:`.OperatingMode`): the operating mode in which the byte should be read.

        Returns:
            Bytearray: the read byte or bytes as bytearray, ``None`` otherwise.
        """
        read_data = bytearray()
        read_byte = self.read_byte()
        read_data.append(read_byte)
        # Read escaped bytes in API escaped mode.
        if operating_mode == OperatingMode.ESCAPED_API_MODE and read_byte == XBeePacket.ESCAPE_BYTE:
            read_data.append(self.read_byte())

        return read_data

    def quit_reading(self):
        """
        Makes the thread (if any) blocking on wait_for_frame return.

        If a thread was blocked on wait_for_frame, this method blocks (for a maximum of 'timeout' seconds) until
        the blocked thread is resumed.
        """
        if self._isReading:
            # As this is the only way to stop reading, self._isReading is reused to signal the stop reading request.
            self._isReading = False

            # Ensure we block until the reading thread resumes.
            # (could be improved using locks in the future)
            time.sleep(self.timeout)

    def wait_for_frame(self, operating_mode=OperatingMode.API_MODE):
        """
        Reads the next packet. Starts to read when finds the start delimiter.
        The last byte read is the checksum.

        If there is something in the COM buffer after the
        start delimiter, this method discards it.

        If the method can't read a complete and correct packet,
        it will return ``None``.

        Args:
            operating_mode (:class:`.OperatingMode`): the operating mode in which the packet should be read.

        Returns:
            Bytearray: the read packet as bytearray if a packet is read, ``None`` otherwise.
        """
        self._isReading = True

        try:
            xbee_packet = bytearray(1)
            # Add packet delimiter.
            xbee_packet[0] = self.read_byte()
            while xbee_packet[0] != SpecialByte.HEADER_BYTE.value:
                # May be set to false by self.quit_reading() as a stop reading request.
                if not self._isReading:
                    return None
                xbee_packet[0] = self.read_byte()

            # Add packet length.
            packet_length_byte = bytearray()
            for _ in range(2):
                packet_length_byte += self.__read_next_byte(operating_mode)
            xbee_packet += packet_length_byte
            # Length needs to be un-escaped in API escaped mode to obtain its integer equivalent.
            if operating_mode == OperatingMode.ESCAPED_API_MODE:
                length = utils.length_to_int(XBeeAPIPacket.unescape_data(packet_length_byte))
            else:
                length = utils.length_to_int(packet_length_byte)

            # Add packet payload.
            for _ in range(length):
                xbee_packet += self.__read_next_byte(operating_mode)

            # Add packet checksum.
            xbee_packet += self.__read_next_byte(operating_mode)

            # Return the packet unescaped.
            if operating_mode == OperatingMode.ESCAPED_API_MODE:
                return XBeeAPIPacket.unescape_data(xbee_packet)
            else:
                return xbee_packet
        except digi.xbee.exception.TimeoutException:
            return None

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

    def set_baudrate(self, new_baudrate):
        """
        Changes the serial port baudrate.

        Args:
             new_baudrate (Integer): the new baudrate to set.
        """
        if new_baudrate is None:
            return

        port_settings = self.get_settings()
        port_settings["baudrate"] = new_baudrate
        self.apply_settings(port_settings)

    def purge_port(self):
        """
        Purges the serial port by cleaning the input and output buffers.
        """

        self.reset_input_buffer()
        self.reset_output_buffer()
