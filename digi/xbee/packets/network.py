# Copyright 2017-2021, Digi International Inc.
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

from ipaddress import IPv4Address
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.protocol import IPProtocol
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.util import utils
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException


class RXIPv4Packet(XBeeAPIPacket):
    """
    This class represents an RX (Receive) IPv4 packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    .. seealso::
       | :class:`.TXIPv4Packet`
       | :class:`.XBeeAPIPacket`
    """
    __MIN_PACKET_LENGTH = 15

    def __init__(self, src_address, dest_port, src_port, ip_protocol,
                 data=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.RXIPv4Packet` object
        with the provided parameters.

        Args:
            src_address (:class:`.IPv4Address`): IPv4 address of the source device.
            dest_port (Integer): destination port number.
            src_port (Integer): source port number.
            ip_protocol (:class:`.IPProtocol`): IP protocol used for transmitted data.
            data (Bytearray, optional): data that is sent to the destination device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `dest_port` is less than 0 or greater than 65535 or
            ValueError: if `source_port` is less than 0 or greater than 65535.

        .. seealso::
           | :class:`.IPProtocol`
        """
        if dest_port < 0 or dest_port > 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        if src_port < 0 or src_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")

        super().__init__(ApiFrameType.RX_IPV4, op_mode=op_mode)
        self.__src_addr = src_address
        self.__dest_port = dest_port
        self.__src_port = src_port
        self.__ip_prot = ip_protocol
        self.__status = 0  # Reserved
        self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class: `.RXIPv4Packet`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 15.
                (start delim + length (2 bytes) + frame type
                + source address(4 bytes) + dest port (2 bytes)
                + source port (2 bytes) + network protocol + status
                + checksum = 15 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`ApiFrameType.RX_IPV4`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RXIPv4Packet.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_IPV4.code:
            raise InvalidPacketException(message="This packet is not an RXIPv4Packet.")

        return RXIPv4Packet(IPv4Address(bytes(raw[4:8])), utils.bytes_to_int(raw[8:10]),
                            utils.bytes_to_int(raw[10:12]), IPProtocol.get(raw[12]),
                            data=raw[14:-1] if len(raw) > RXIPv4Packet.__MIN_PACKET_LENGTH else None,
                            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    @property
    def source_address(self):
        """
        Returns the IPv4 address of the source device.

        Returns:
            :class:`ipaddress.IPv4Address`: the IPv4 address of the source device.
        """
        return self.__src_addr

    @source_address.setter
    def source_address(self, source_address):
        """
        Sets the IPv4 source address.

        Args:
            source_address (:class:`.IPv4Address`): The new IPv4 source address.
        """
        if source_address is not None:
            self.__src_addr = source_address

    @property
    def dest_port(self):
        """
        Returns the destination port.

        Returns:
            Integer: the destination port.
        """
        return self.__dest_port

    @dest_port.setter
    def dest_port(self, dest_port):
        """
        Sets the destination port.

        Args:
            dest_port (Integer): the new destination port.

        Raises:
            ValueError: if `dest_port` is less than 0 or greater than 65535.
        """
        if dest_port < 0 or dest_port > 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        self.__dest_port = dest_port

    @property
    def source_port(self):
        """
        Returns the source port.

        Returns:
            Integer: the source port.
        """
        return self.__src_port

    @source_port.setter
    def source_port(self, source_port):
        """
        Sets the source port.

        Args:
            source_port (Integer): the new source port.

        Raises:
            ValueError: if `source_port` is less than 0 or greater than 65535.
        """
        if source_port < 0 or source_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")
        self.__src_port = source_port

    @property
    def ip_protocol(self):
        """
        Returns the IP protocol used for transmitted data.

        Returns:
            :class:`.IPProtocol`: the IP protocol used for transmitted data.
        """
        return self.__ip_prot

    @ip_protocol.setter
    def ip_protocol(self, ip_protocol):
        """
        Sets the IP protocol used for transmitted data.

        Args:
            ip_protocol (:class:`.IPProtocol`): the new IP protocol.
        """
        self.__ip_prot = ip_protocol

    @property
    def data(self):
        """
        Returns the data of the packet.

        Returns:
            Bytearray: the data of the packet.
        """
        if self.__data is None:
            return self.__data
        return self.__data.copy()

    @data.setter
    def data(self, data):
        """
        Sets the data of the packet.

        Args:
            data (Bytearray): the new data of the packet.
        """
        if data is None:
            self.__data = None
        else:
            self.__data = data.copy()

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = bytearray(self.__src_addr.packed)
        ret += utils.int_to_bytes(self.__dest_port, num_bytes=2)
        ret += utils.int_to_bytes(self.__src_port, num_bytes=2)
        ret += utils.int_to_bytes(self.__ip_prot.code, num_bytes=1)
        ret += utils.int_to_bytes(self.__status, num_bytes=1)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {
            DictKeys.SRC_IPV4_ADDR: "%s (%s)" % (self.__src_addr.packed, self.__src_addr.exploded),
            DictKeys.DEST_PORT:     self.__dest_port,
            DictKeys.SRC_PORT:      self.__src_port,
            DictKeys.IP_PROTOCOL:   "%s (%s)" % (self.__ip_prot.code, self.__ip_prot.description),
            DictKeys.STATUS:        self.__status,
            DictKeys.RF_DATA:       bytearray(self.__data)}


class TXIPv4Packet(XBeeAPIPacket):
    """
    This class represents an TX (Transmit) IPv4 packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    .. seealso::
       | :class:`.RXIPv4Packet`
       | :class:`.XBeeAPIPacket`
    """

    OPTIONS_CLOSE_SOCKET = 2
    """This option will close the socket after the transmission."""

    OPTIONS_LEAVE_SOCKET_OPEN = 0
    """This option will leave socket open after the transmission."""

    __MIN_PACKET_LENGTH = 16

    def __init__(self, frame_id, dest_address, dest_port, src_port,
                 ip_protocol, tx_opts, data=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TXIPv4Packet` object
        with the provided parameters.

        Args:
            frame_id (Integer): the frame ID. Must be between 0 and 255.
            dest_address (:class:`.IPv4Address`): IPv4 address of the destination device.
            dest_port (Integer): destination port number.
            src_port (Integer): source port number.
            ip_protocol (:class:`.IPProtocol`): IP protocol used for transmitted data.
            tx_opts (Integer): the transmit options of the packet.
            data (Bytearray, optional): data that is sent to the destination device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `dest_port` is less than 0 or greater than 65535.
            ValueError: if `source_port` is less than 0 or greater than 65535.

        .. seealso::
           | :class:`.IPProtocol`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255")
        if dest_port < 0 or dest_port > 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        if src_port < 0 or src_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")

        super().__init__(ApiFrameType.TX_IPV4, op_mode=op_mode)
        self._frame_id = frame_id
        self.__dest_addr = dest_address
        self.__dest_port = dest_port
        self.__src_port = src_port
        self.__ip_prot = ip_protocol
        self.__tx_opts = tx_opts
        self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            TXIPv4Packet.

        Raises:
            InvalidPacketException: if the bytearray length is less than 16.
                (start delim + length (2 bytes) + frame type + frame id
                + dest address (4 bytes) + dest port (2 bytes)
                + source port (2 bytes) + network protocol + transmit options
                + checksum = 16 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`ApiFrameType.TX_IPV4`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TXIPv4Packet.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TX_IPV4.code:
            raise InvalidPacketException(message="This packet is not an TXIPv4Packet.")

        return TXIPv4Packet(raw[4], IPv4Address(bytes(raw[5:9])), utils.bytes_to_int(raw[9:11]),
                            utils.bytes_to_int(raw[11:13]), IPProtocol.get(raw[13]), raw[14],
                            data=raw[15:-1] if len(raw) > TXIPv4Packet.__MIN_PACKET_LENGTH else None,
                            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    @property
    def dest_address(self):
        """
        Returns the IPv4 address of the destination device.

        Returns:
            :class:`ipaddress.IPv4Address`: the IPv4 address of the destination device.
        """
        return self.__dest_addr

    @dest_address.setter
    def dest_address(self, dest_address):
        """
        Sets the IPv4 destination address.

        Args:
            dest_address (:class:`ipaddress.IPv4Address`): The new IPv4 destination address.
        """
        if dest_address is not None:
            self.__dest_addr = dest_address

    @property
    def dest_port(self):
        """
        Returns the destination port.

        Returns:
            Integer: the destination port.
        """
        return self.__dest_port

    @dest_port.setter
    def dest_port(self, dest_port):
        """
        Sets the destination port.

        Args:
            dest_port (Integer): the new destination port.

        Raises:
            ValueError: if `dest_port` is less than 0 or greater than 65535.
        """
        if dest_port < 0 or dest_port > 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        self.__dest_port = dest_port

    @property
    def source_port(self):
        """
        Returns the source port.

        Returns:
            Integer: the source port.
        """
        return self.__src_port

    @source_port.setter
    def source_port(self, source_port):
        """
        Sets the source port.

        Args:
            source_port (Integer): the new source port.

        Raises:
            ValueError: if `source_port` is less than 0 or greater than 65535.
        """
        if source_port < 0 or source_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")

        self.__src_port = source_port

    @property
    def ip_protocol(self):
        """
        Returns the IP protocol used for transmitted data.

        Returns:
            :class:`.IPProtocol`: the IP protocol used for transmitted data.
        """
        return self.__ip_prot

    @ip_protocol.setter
    def ip_protocol(self, ip_protocol):
        """
        Sets the network protocol used for transmitted data.

        Args:
            ip_protocol (:class:`.IPProtocol`): the new IP protocol.
        """
        self.__ip_prot = ip_protocol

    @property
    def transmit_options(self):
        """
        Returns the transmit options of the packet.

        Returns:
            Integer: the transmit options of the packet.
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, transmit_options):
        """
        Sets the transmit options bitfield of the packet.

        Args:
            transmit_options (Integer): the new transmit options. Can
                be :attr:`OPTIONS_CLOSE_SOCKET` or :attr:`OPTIONS_LEAVE_SOCKET_OPEN`.
        """
        self.__tx_opts = transmit_options

    @property
    def data(self):
        """
        Returns the data of the packet.

        Returns:
            Bytearray: the data of the packet.
        """
        return self.__data if self.__data is None else self.__data.copy()

    @data.setter
    def data(self, data):
        """
        Sets the data of the packet.

        Args:
            data (Bytearray): the new data of the packet.
        """
        self.__data = None if data is None else data.copy()

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = bytearray(self.__dest_addr.packed)
        ret += utils.int_to_bytes(self.__dest_port, num_bytes=2)
        ret += utils.int_to_bytes(self.__src_port, num_bytes=2)
        ret += utils.int_to_bytes(self.__ip_prot.code)
        ret += utils.int_to_bytes(self.__tx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {
            DictKeys.DEST_IPV4_ADDR: "%s (%s)" % (self.__dest_addr.packed, self.__dest_addr.exploded),
            DictKeys.DEST_PORT:      self.__dest_port,
            DictKeys.SRC_PORT:       self.__src_port,
            DictKeys.IP_PROTOCOL:    "%s (%s)" % (self.__ip_prot.code, self.__ip_prot.description),
            DictKeys.OPTIONS:        self.__tx_opts,
            DictKeys.RF_DATA:        bytearray(self.__data)}
