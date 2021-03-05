# Copyright 2019-2021, Digi International Inc.
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

from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.models.address import XBee64BitAddress
from digi.xbee.models.mode import OperatingMode
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.util import utils


class RouteInformationPacket(XBeeAPIPacket):
    """
    This class represents a DigiMesh Route Information packet. Packet is built
    using the parameters of the constructor or providing a valid API
    payload.

    A Route Information Packet can be output for DigiMesh unicast transmissions
    on which the NACK enable or the Trace Route enable TX option is enabled.

    .. seealso::
        | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 46

    def __init__(self, src_event, timestamp, ack_timeout_count, tx_block_count,
                 dst_addr, src_addr, responder_addr, successor_addr,
                 additional_data=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.RouteInformationPacket` object with the provided
        parameters.

        Args:
            src_event (Integer): Source event identifier.
                0x11=NACK, 0x12=Trace route
            timestamp (Integer): System timer value on the node generating the
                this packet. The timestamp is in microseconds.
            ack_timeout_count (Integer): The number of MAC ACK timeouts.
            tx_block_count (Integer): The number of times the transmission was
                blocked due to reception in progress.
            dst_addr (:class:`.XBee64BitAddress`): The 64-bit address of the
                final destination node of this network-level transmission.
            src_addr (:class:`.XBee64BitAddress`): The 64-bit address of the
                source node of this network-level transmission.
            responder_addr (:class:`.XBee64BitAddress`): The 64-bit address of
                the node that generates this packet after it sends (or attempts
                to send) the packet to the next hop (successor node).
            successor_addr (:class:`.XBee64BitAddress`): The 64-bit address of
                the next node after the responder in the route towards the
                destination, whether or not the packet arrived successfully at
                the successor node.
            additional_data (Bytearray, optional, default=`None`): Additional
                data of the packet.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `src_event` is not 0x11 or 0x12.
            ValueError: if `timestamp` is not between 0 and 0xFFFFFFFF.
            ValueError: if `ack_timeout_count` or `tx_block_count` are not
                between 0 and 255.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        if src_event not in [0x11, 0x12]:
            raise ValueError("Source event must be 0x11 or 0x12.")
        if timestamp < 0 or timestamp > 0xFFFFFFFF:  # 4 bytes
            raise ValueError("Timestamp must be between 0 and %d." % 0xFFFFFFFF)
        if ack_timeout_count < 0 or ack_timeout_count > 0xFF:  # 1 byte
            raise ValueError("ACK timeout count must be between 0 and 255")
        if tx_block_count < 0 or tx_block_count > 0xFF:  # 1 byte
            raise ValueError("TX blocked count must be between 0 and 255")

        super().__init__(ApiFrameType.DIGIMESH_ROUTE_INFORMATION, op_mode=op_mode)

        self.__src_event = src_event
        self.__timestamp = timestamp
        self.__ack_timeout_count = ack_timeout_count
        self.__tx_block_count = tx_block_count
        self._reserved = 0
        self.__dst_addr = dst_addr
        self.__src_addr = src_addr
        self.__responder_addr = responder_addr
        self.__successor_addr = successor_addr
        self.__additional_data = additional_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RouteInformationPacket`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 46.
                (start delim. + length (2 bytes) + frame type + src_event
                + length + timestamp (4 bytes) + ack timeout count
                + tx blocked count + reserved + dest addr (8 bytes)
                + src addr (8 bytes) + responder addr (8 bytes)
                + successor addr (8 bytes) + checksum = 46 bytes).
            InvalidPacketException: If the length field of `raw` is different
                from its real length. (length field: bytes 1 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is not
                :attr:`.ApiFrameType.DIGIMESH_ROUTE_INFORMATION`.
            InvalidPacketException: If the internal length byte of the rest
                of the frame (without the checksum) is different from its real
                length.
            InvalidOperatingModeException: If `operating_mode` is not
                supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(
                operating_mode.name + " is not supported.")

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RouteInformationPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.DIGIMESH_ROUTE_INFORMATION.code:
            raise InvalidPacketException(
                "This packet is not a Route Information packet.")

        # 7: frame len starting from this byte (index 5) and without the checksum
        if raw[5] != len(raw) - 7:
            raise InvalidPacketException("Length does not match with the data length")

        additional_data = []
        if len(raw) > RouteInformationPacket.__MIN_PACKET_LENGTH:
            additional_data = raw[45:]
        packet = RouteInformationPacket(
            raw[4], utils.bytes_to_int(raw[6:10]), raw[10], raw[11],
            XBee64BitAddress(raw[13:21]), XBee64BitAddress(raw[21:29]),
            XBee64BitAddress(raw[29:37]), XBee64BitAddress(raw[37:45]),
            additional_data, op_mode=operating_mode)
        packet._reserved = raw[12]

        return packet

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = bytearray([self.__src_event])
        ret.append(self.length)
        ret += utils.int_to_bytes(self.__timestamp, num_bytes=4)
        ret.append(self.__ack_timeout_count)
        ret.append(self.__tx_block_count)
        ret.append(self._reserved)
        ret += self.__dst_addr.address
        ret += self.__src_addr.address
        ret += self.__responder_addr.address
        ret += self.__successor_addr.address
        if self.__additional_data:
            ret += self.__additional_data

        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.SRC_EVENT:         self.__src_event,
                DictKeys.LENGTH:            self.length,
                DictKeys.TIMESTAMP:         self.__timestamp,
                DictKeys.ACK_TIMEOUT_COUNT: self.__ack_timeout_count,
                DictKeys.TX_BLOCKED_COUNT:  self.__tx_block_count,
                DictKeys.DEST_ADDR:         self.__dst_addr,
                DictKeys.SRC_ADDR:          self.__src_addr,
                DictKeys.RESPONDER_ADDR:    self.__responder_addr,
                DictKeys.SUCCESSOR_ADDR:    self.__successor_addr,
                DictKeys.ADDITIONAL_DATA:   self.__additional_data}

    @property
    def src_event(self):
        """
        Returns the source event.

        Returns:
            Integer: The source event.
        """
        return self.__src_event

    @src_event.setter
    def src_event(self, src_event):
        """
        Sets the source event identifier. 0x11=NACK, 0x12=Trace route

        Args:
            src_event (Integer): The new source event.

        Raises:
            ValueError: if `src_event` is not 0x11 or 0x12.
        """
        if src_event not in [0x11, 0x12]:
            raise ValueError("Source event must be 0x11 or 0x12.")

        self.__src_event = src_event

    @property
    def length(self):
        """
        Returns the number of bytes that follow, excluding the checksum.

        Returns:
            Integer: Data length.

        """
        # len: len(additional_data) + 4 MACS + timestamp (4 bytes) + 3 bytes
        return len(self.__additional_data) + 8 * 4 + 4 + 3

    @property
    def timestamp(self):
        """
        Returns the system timer value on the node generating this package.
        The timestamp is in microseconds.

        Returns:
            Integer: The system timer value in microseconds.
        """
        return self.__timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        """
        Sets the system timer value on the node generating this package.
        The timestamp is in microseconds.

        Args:
            timestamp (Integer): The number of microseconds.

        Raises:
            ValueError: if `timestamp` is not between 0 and 0xFFFFFFFF.
        """
        if timestamp < 0 or timestamp > 0xFFFFFFFF:  # 4 bytes
            raise ValueError("Timestamp must be between 0 and %d." % 0xFFFFFFFF)

        self.__timestamp = timestamp

    @property
    def ack_timeout_count(self):
        """
        Returns the number of MAC ACK timeouts that occur.

        Returns:
            Integer: The number of MAC ACK timeouts that occur.
        """
        return self.__ack_timeout_count

    @ack_timeout_count.setter
    def ack_timeout_count(self, ack_timeout_count):
        """
        Sets the number of MAC ACK timeouts that occur.

        Args:
            ack_timeout_count (Integer): The number of MAC ACK timeouts that occur.

        Raises:
            ValueError: if `ack_timeout_count` is not between 0 and 255.
        """
        if ack_timeout_count < 0 or ack_timeout_count > 0xFF:  # 1 byte
            raise ValueError("ACK timeout count must be between 0 and 255")

        self.__ack_timeout_count = ack_timeout_count

    @property
    def tx_block_count(self):
        """
        Returns the number of times the transmission was blocked due to reception
        in progress.

        Returns:
            Integer: The number of times the transmission was blocked due to
                reception in progress.
        """
        return self.__tx_block_count

    @tx_block_count.setter
    def tx_block_count(self, tx_block_count):
        """
        Sets the number of times the transmission was blocked due to reception
        in progress.

        Args:
            tx_block_count (Integer): The number of times the transmission was
                blocked due to reception in progress.

        Raises:
            ValueError: if `tx_block_count` is not between 0 and 255.
        """
        if tx_block_count < 0 or tx_block_count > 0xFF:  # 1 byte
            raise ValueError("TX blocked count must be between 0 and 255")

        self.__tx_block_count = tx_block_count

    @property
    def dst_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: The 64-bit address of the final
                destination node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__dst_addr

    @dst_addr.setter
    def dst_addr(self, dst_addr):
        """
        Sets the 64-bit address of the final destination node of this
        network-level transmission.

        Args:
            dst_addr (:class:`.XBee64BitAddress`): The new 64-bit address of the
                final destination node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__dst_addr = dst_addr

    @property
    def src_addr(self):
        """
        Returns the 64-bit address of the source node of this network-level
        transmission.

        Returns:
            :class:`.XBee64BitAddress`: The 64-bit address of the source node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__src_addr

    @src_addr.setter
    def src_addr(self, src_addr):
        """
        Sets the 64-bit address of the source node of this network-level
        transmission.

        Args:
            src_addr (:class:`.XBee64BitAddress`): The new 64-bit address of the
                source node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__src_addr = src_addr

    @property
    def responder_addr(self):
        """
        Returns the 64-bit address of the node that generates this packet after
        it sends (or attempts to send) the packet to the next hop (successor node).

        Returns:
            :class:`.XBee64BitAddress`: The 64-bit address of the responder node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__responder_addr

    @responder_addr.setter
    def responder_addr(self, responder_addr):
        """
        Sets the 64-bit address of the node that generates this packet after it
        sends (or attempts to send) the packet to the next hop (successor node).

        Args:
            responder_addr (:class:`.XBee64BitAddress`): The new 64-bit address
                of the responder node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__responder_addr = responder_addr

    @property
    def successor_addr(self):
        """
        Returns the 64-bit address of the next node after the responder in the
        route towards the destination, whether or not the packet arrived
        successfully at the successor node.

        Returns:
            :class:`.XBee64BitAddress`: The 64-bit address of the successor node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__successor_addr

    @successor_addr.setter
    def successor_addr(self, successor_addr):
        """
        Sets the 64-bit address of the next node after the responder in the
        route towards the destination, whether or not the packet arrived
        successfully at the successor node.

        Args:
            successor_addr (:class:`.XBee64BitAddress`): The new 64-bit address
                of the successor node.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__successor_addr = successor_addr
