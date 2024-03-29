# Copyright 2017-2022, Digi International Inc.
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

from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress
from digi.xbee.models.status import TransmitStatus
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.mode import OperatingMode
from digi.xbee.io import IOSample, IOLine
from digi.xbee.util import utils


class TX64Packet(XBeeAPIPacket):
    """
    This class represents a TX (Transmit) 64 Request packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    A TX Request message will cause the module to transmit data as an RF
    Packet.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 15

    def __init__(self, frame_id, x64bit_addr, tx_opts, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TX64Packet` object with
        the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit destination address.
            tx_opts (Integer): bitfield of supported transmission options.
            rf_data (Bytearray, optional): RF data that is sent to the destination device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.TransmitOptions`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.TX_64, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x64bit_addr = x64bit_addr
        self.__tx_opts = tx_opts
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TX64Packet`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 15.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64bit addr. + transmit options + checksum = 15 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.TX_64`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in(OperatingMode.ESCAPED_API_MODE,
                                 OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TX64Packet.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TX_64.code:
            raise InvalidPacketException(message="This packet is not a TX 64 packet.")

        return TX64Packet(raw[4], XBee64BitAddress(raw[5:13]), raw[13],
                          rf_data=raw[14:-1] if len(raw) > TX64Packet.__MIN_PACKET_LENGTH else None,
                          op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64bit_addr.address
        ret.append(self.__tx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR:      self.__x64bit_addr.address,
                DictKeys.TRANSMIT_OPTIONS: self.__tx_opts,
                DictKeys.RF_DATA:          self.__data}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 8  # Remove 64-bit address

    @property
    def x64bit_dest_addr(self):
        """
        Returns the 64-bit destination address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_dest_addr.setter
    def x64bit_dest_addr(self, x64bit_addr):
        """
        Sets the 64-bit destination address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def transmit_options(self):
        """
        Returns the transmit options bitfield.

        Returns:
            Integer: the transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, transmit_options):
        """
        Sets the transmit options bitfield.

        Args:
            transmit_options (Integer): the new transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        self.__tx_opts = transmit_options

    @property
    def rf_data(self):
        """
        Returns the RF data to send.

        Returns:
            Bytearray: the RF data to send.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the RF data to send.

        Args:
            rf_data (Bytearray): the new RF data to send.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()


class TX16Packet(XBeeAPIPacket):
    """
    This class represents a TX (Transmit) 16 Request packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    A TX request message will cause the module to transmit data as an RF
    packet.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 9

    def __init__(self, frame_id, x16bit_addr, tx_opts, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TX16Packet` object with
        the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit destination address.
            tx_opts (Integer): bitfield of supported transmission options.
            rf_data (Bytearray, optional): RF data that is sent to the destination device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.TransmitOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeeAPIPacket`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.TX_16, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x16bit_addr = x16bit_addr
        self.__tx_opts = tx_opts
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TX16Packet`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 9.
                (start delim. + length (2 bytes) + frame type + frame id
                + 16bit addr. + transmit options + checksum = 9 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.TX_16`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TX16Packet.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TX_16.code:
            raise InvalidPacketException(message="This packet is not a TX 16 packet.")

        return TX16Packet(raw[4], XBee16BitAddress(raw[5:7]), raw[7],
                          rf_data=raw[8:-1] if len(raw) > TX16Packet.__MIN_PACKET_LENGTH else None,
                          op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x16bit_addr.address
        ret.append(self.__tx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X16BIT_ADDR:      self.__x16bit_addr,
                DictKeys.TRANSMIT_OPTIONS: self.__tx_opts,
                DictKeys.RF_DATA:          self.__data}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2  # Remove 16-bit address

    @property
    def x16bit_dest_addr(self):
        """
        Returns the 16-bit destination address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_dest_addr.setter
    def x16bit_dest_addr(self, x16bit_addr):
        """
        Sets the 16-bit destination address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def transmit_options(self):
        """
        Returns the transmit options bitfield.

        Returns:
            Integer: the transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, transmit_options):
        """
        Sets the transmit options bitfield.

        Args:
            transmit_options (Integer): the new transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        self.__tx_opts = transmit_options

    @property
    def rf_data(self):
        """
        Returns the RF data to send.

        Returns:
            Bytearray: the RF data to send.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the RF data to send.

        Args:
            rf_data (Bytearray): the new RF data to send.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()


class TXStatusPacket(XBeeAPIPacket):
    """
    This class represents a TX (Transmit) status packet. Packet is built using
    the parameters of the constructor or providing a valid API payload.

    When a TX request is completed, the module sends a TX status message.
    This message will indicate if the packet was transmitted successfully or if
    there was a failure.

    .. seealso::
       | :class:`.TX16Packet`
       | :class:`.TX64Packet`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, tx_status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TXStatusPacket` object
        with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            tx_status (:class:`.TransmitStatus`): transmit status.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.TransmitStatus`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.TX_STATUS, op_mode=op_mode)
        self._frame_id = frame_id
        self.__tx_status = tx_status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TXStatusPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7.
                (start delim. + length (2 bytes) + frame type + frame id
                + transmit status + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.TX_16`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TXStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TX_STATUS.code:
            raise InvalidPacketException(message="This packet is not a TX status packet.")

        return TXStatusPacket(raw[4], TransmitStatus.get(raw[5]), op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        return utils.int_to_bytes(self.__tx_status.code, num_bytes=1)

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.TS_STATUS: self.__tx_status}

    @property
    def transmit_status(self):
        """
        Returns the transmit status.

        Returns:
            :class:`.TransmitStatus`: the transmit status.

        .. seealso::
           | :class:`.TransmitStatus`
        """
        return self.__tx_status

    @transmit_status.setter
    def transmit_status(self, transmit_status):
        """
        Sets the transmit status.

        Args:
            transmit_status (:class:`.TransmitStatus`): the new transmit status to set.

        .. seealso::
           | :class:`.TransmitStatus`
        """
        self.__tx_status = transmit_status


class RX64Packet(XBeeAPIPacket):
    """
    This class represents an RX (Receive) 64 request packet. Packet is built
    using the parameters of the constructor or providing a valid API byte array.

    When the module receives an RF packet, it is sent out the UART using
    this message type.

    This packet is the response to TX (transmit) 64 request packets.

    .. seealso::
       | :class:`.ReceiveOptions`
       | :class:`.TX64Packet`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 15

    def __init__(self, x64bit_addr, rssi, rx_opts, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a :class:`.RX64Packet` object with the
        provided parameters.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit source address.
            rssi (Integer): received signal strength indicator.
            rx_opts (Integer): bitfield indicating the receive options.
            rf_data (Bytearray, optional): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ReceiveOptions`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """

        super().__init__(ApiFrameType.RX_64, op_mode=op_mode)

        self.__x64bit_addr = x64bit_addr
        self.__rssi = rssi
        self.__rx_opts = rx_opts
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RX64Packet`

        Raises:
            InvalidPacketException: if the bytearray length is less than 15.
                (start delim. + length (2 bytes) + frame type + 64bit addr.
                + rssi + receive options + checksum = 15 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.RX_64`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RX64Packet.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_64.code:
            raise InvalidPacketException(message="This packet is not an RX 64 packet.")

        return RX64Packet(XBee64BitAddress(raw[4:12]), raw[12], raw[13],
                          rf_data=raw[14:-1] if len(raw) > RX64Packet.__MIN_PACKET_LENGTH else None,
                          op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return (utils.is_bit_enabled(self.__rx_opts, 1)
                or utils.is_bit_enabled(self.__rx_opts, 2))

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64bit_addr.address
        ret.append(self.__rssi)
        ret.append(self.__rx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR:     self.__x64bit_addr,
                DictKeys.RSSI:            self.__rssi,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts,
                DictKeys.RF_DATA:         self.__data}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 8  # Remove 64-bit address

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def rssi(self):
        """
        Returns the received Signal Strength Indicator (RSSI).

        Returns:
            Integer: the received Signal Strength Indicator (RSSI).
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the received Signal Strength Indicator (RSSI).

        Args:
            rssi (Integer): the new received Signal Strength Indicator (RSSI).
        """
        self.__rssi = rssi

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()


class RX16Packet(XBeeAPIPacket):
    """
    This class represents an RX (Receive) 16 Request packet. Packet is built
    using the parameters of the constructor or providing a valid API byte array.

    When the module receives an RF packet, it is sent out the UART using this
    message type

    This packet is the response to TX (Transmit) 16 Request packets.

    .. seealso::
       | :class:`.ReceiveOptions`
       | :class:`.TX16Packet`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 9

    def __init__(self, x16bit_addr, rssi, rx_opts, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a :class:`.RX16Packet` object with the
        provided parameters.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit source address.
            rssi (Integer): received signal strength indicator.
            rx_opts (Integer): bitfield indicating the receive options.
            rf_data (Bytearray, optional): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ReceiveOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeeAPIPacket`
        """

        super().__init__(ApiFrameType.RX_16, op_mode=op_mode)

        self.__x16bit_addr = x16bit_addr
        self.__rssi = rssi
        self.__rx_opts = rx_opts
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RX16Packet`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 9.
            (start delim. + length (2 bytes) + frame type + 16bit addr. + rssi
                + receive options + checksum = 9 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.RX_16`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RX16Packet.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_16.code:
            raise InvalidPacketException(message="This packet is not an RX 16 Packet")

        return RX16Packet(XBee16BitAddress(raw[4:6]), raw[6], raw[7],
                          rf_data=raw[8:-1] if len(raw) > RX16Packet.__MIN_PACKET_LENGTH else None,
                          op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return (utils.is_bit_enabled(self.__rx_opts, 1)
                or utils.is_bit_enabled(self.__rx_opts, 2))

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x16bit_addr.address
        ret.append(self.__rssi)
        ret.append(self.__rx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X16BIT_ADDR:     self.__x16bit_addr,
                DictKeys.RSSI:            self.__rssi,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts,
                DictKeys.RF_DATA:         self.__data}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2  # Remove 16-bit address

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def rssi(self):
        """
        Returns the received Signal Strength Indicator (RSSI).

        Returns:
            Integer: the received Signal Strength Indicator (RSSI).
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the received Signal Strength Indicator (RSSI).

        Args:
            rssi (Integer): the new received Signal Strength Indicator (RSSI).

        """
        self.__rssi = rssi

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()


class RX64IOPacket(XBeeAPIPacket):
    """
    This class represents an RX64 address IO packet. Packet is built using the
    parameters of the constructor or providing a valid API payload.

    I/O data is sent out the UART using an API frame.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 20

    def __init__(self, x64bit_addr, rssi, rx_opts, data, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates an :class:`.RX64IOPacket` object with
        the provided parameters.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit source address.
            rssi (Integer): received signal strength indicator.
            rx_opts (Integer): bitfield indicating the receive options.
            data (Bytearray): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ReceiveOptions`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.RX_IO_64, op_mode=op_mode)
        self.__x64bit_addr = x64bit_addr
        self.__rssi = rssi
        self.__rs_opts = rx_opts
        self.__data = data
        self.__io_sample = IOSample(data) if data is not None and len(data) >= 5 else None

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RX64IOPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 20.
                (start delim. + length (2 bytes) + frame type + 64bit addr.
                + rssi + receive options + rf data (5 bytes) + checksum = 20 bytes)
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.RX_IO_64`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RX64IOPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_IO_64.code:
            raise InvalidPacketException(message="This packet is not an RX 64 IO packet.")

        return RX64IOPacket(XBee64BitAddress(raw[4:12]), raw[12], raw[13], raw[14:-1],
                            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return (utils.is_bit_enabled(self.__rs_opts, 1)
                or utils.is_bit_enabled(self.__rs_opts, 2))

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64bit_addr.address
        ret.append(self.__rssi)
        ret.append(self.__rs_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        base = {DictKeys.X16BIT_ADDR:         self.__x64bit_addr.address,
                DictKeys.RSSI:                self.__rssi,
                DictKeys.RECEIVE_OPTIONS:     self.__rs_opts}

        if self.__io_sample is not None:
            base[DictKeys.NUM_SAMPLES] = 1
            base[DictKeys.DIGITAL_MASK] = self.__io_sample.digital_mask
            base[DictKeys.ANALOG_MASK] = self.__io_sample.analog_mask

            # Digital values
            for i in range(16):
                if self.__io_sample.has_digital_value(IOLine.get(i)):
                    base[IOLine.get(i).description + "digital value"] = \
                        utils.hex_to_string(self.__io_sample.get_digital_value(IOLine.get(i)))

            # Analog values
            for i in range(6):
                if self.__io_sample.has_analog_value(IOLine.get(i)):
                    base[IOLine.get(i).description + "analog value"] = \
                        utils.hex_to_string(self.__io_sample.get_analog_value(IOLine.get(i)))

            # Power supply
            if self.__io_sample.has_power_supply_value():
                base["Power supply value "] = "%02X" % self.__io_sample.power_supply_value

        elif self.__data is not None:
            base[DictKeys.RF_DATA] = utils.hex_to_string(self.__data)

        return base

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 8  # Remove 64-bit address

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def rssi(self):
        """
        Returns the received Signal Strength Indicator (RSSI).

        Returns:
            Integer: the received Signal Strength Indicator (RSSI).
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the received Signal Strength Indicator (RSSI).

        Args:
            rssi (Integer): the new received Signal Strength Indicator (RSSI).
        """
        self.__rssi = rssi

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rs_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rs_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()

        # Modify the ioSample accordingly
        if rf_data is not None and len(rf_data) >= 5:
            self.__io_sample = IOSample(self.__data)
        else:
            self.__io_sample = None

    @property
    def io_sample(self):
        """
        Returns the IO sample corresponding to the data contained in the packet.

        Returns:
            :class:`.IOSample`: the IO sample of the packet, `None` if the
                packet has not any data or if the sample could not be generated
                correctly.

        .. seealso::
           | :class:`.IOSample`
        """
        return self.__io_sample

    @io_sample.setter
    def io_sample(self, io_sample):
        """
        Sets the IO sample of the packet.

        Args:
            io_sample (:class:`.IOSample`): the new IO sample to set.

        .. seealso::
           | :class:`.IOSample`
        """
        self.__io_sample = io_sample


class RX16IOPacket(XBeeAPIPacket):
    """
    This class represents an RX16 address IO packet. Packet is built using the
    parameters of the constructor or providing a valid byte array.

    I/O data is sent out the UART using an API frame.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 14

    def __init__(self, x16bit_addr, rssi, rx_opts, data, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates an :class:`.RX16IOPacket` object with
        the provided parameters.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit source address.
            rssi (Integer): received signal strength indicator.
            rx_opts (Integer): bitfield indicating the receive options.
            data (Bytearray): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ReceiveOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.RX_IO_16, op_mode=op_mode)
        self.__x16bit_addr = x16bit_addr
        self.__rssi = rssi
        self.__rx_opts = rx_opts
        self.__data = data
        self.__io_sample = IOSample(data) if data is not None and len(data) >= 5 else None

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RX16IOPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 14.
                (start delim. + length (2 bytes) + frame type + 16bit addr.
                + rssi + receive options + rf data (5 bytes) + checksum = 14 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.RX_IO_16`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RX16IOPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_IO_16.code:
            raise InvalidPacketException(message="This packet is not an RX 16 IO packet.")

        return RX16IOPacket(XBee16BitAddress(raw[4:6]), raw[6], raw[7], raw[8:-1],
                            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return (utils.is_bit_enabled(self.__rx_opts, 1)
                or utils.is_bit_enabled(self.__rx_opts, 2))

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x16bit_addr.address
        ret.append(self.__rssi)
        ret.append(self.__rx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        base = {DictKeys.X16BIT_ADDR:     self.__x16bit_addr.address,
                DictKeys.RSSI:            self.__rssi,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts}

        if self.__io_sample is not None:
            base[DictKeys.NUM_SAMPLES] = 1
            base[DictKeys.DIGITAL_MASK] = self.__io_sample.digital_mask
            base[DictKeys.ANALOG_MASK] = self.__io_sample.analog_mask

            # Digital values
            for i in range(16):
                if self.__io_sample.has_digital_value(IOLine.get(i)):
                    base[IOLine.get(i).description + "digital value"] = \
                        utils.hex_to_string(self.__io_sample.get_digital_value(IOLine.get(i)))

            # Analog values
            for i in range(6):
                if self.__io_sample.has_analog_value(IOLine.get(i)):
                    base[IOLine.get(i).description + "analog value"] = \
                        utils.hex_to_string(self.__io_sample.get_analog_value(IOLine.get(i)))

            # Power supply
            if self.__io_sample.has_power_supply_value():
                base["Power supply value "] = "%02X" % self.__io_sample.power_supply_value

        elif self.__data is not None:
            base[DictKeys.RF_DATA] = utils.hex_to_string(self.__data)

        return base

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2  # Remove 16-bit address

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def rssi(self):
        """
        Returns the received Signal Strength Indicator (RSSI).

        Returns:
            Integer: the received Signal Strength Indicator (RSSI).
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the received Signal Strength Indicator (RSSI).

        Args:
            rssi (Integer): the new received Signal Strength Indicator (RSSI).

        """
        self.__rssi = rssi

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()

        # Modify the ioSample accordingly
        if rf_data is not None and len(rf_data) >= 5:
            self.__io_sample = IOSample(self.__data)
        else:
            self.__io_sample = None

    @property
    def io_sample(self):
        """
        Returns the IO sample corresponding to the data contained in the packet.

        Returns:
            :class:`.IOSample`: the IO sample of the packet, `None` if the
                packet has not any data or if the sample could not be generated
                correctly.

        .. seealso::
           | :class:`.IOSample`
        """
        return self.__io_sample

    @io_sample.setter
    def io_sample(self, io_sample):
        """
        Sets the IO sample of the packet.

        Args:
            io_sample (:class:`.IOSample`): the new IO sample to set.

        .. seealso::
           | :class:`.IOSample`
        """
        self.__io_sample = io_sample
