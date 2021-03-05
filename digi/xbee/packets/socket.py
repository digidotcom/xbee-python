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
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from ipaddress import IPv4Address

from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import SocketOption
from digi.xbee.models.protocol import IPProtocol
from digi.xbee.models.status import SocketStatus, SocketState
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.util import utils


class SocketCreatePacket(XBeeAPIPacket):
    """
    This class represents a Socket Create packet. Packet is built using the
    parameters of the constructor.

    Use this frame to create a new socket with the following protocols: TCP,
    UDP, or TLS.

    .. seealso::
       | :class:`.SocketCreateResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, protocol, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketCreatePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            protocol (:class:`.IPProtocol`): the protocol used to create the socket.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.IPProtocol`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_CREATE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__prot = protocol

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketCreatePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7.
                (start delim. + length (2 bytes) + frame type + frame id
                + protocol + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_CREATE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketCreatePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_CREATE.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Create packet.")

        return SocketCreatePacket(raw[4], IPProtocol.get(raw[5]), op_mode=operating_mode)

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
        return bytearray([self.__prot.code])

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.IP_PROTOCOL.value: "%s (%s)" % (self.__prot.code, self.__prot.description)}

    @property
    def protocol(self):
        """
        Returns the communication protocol.

        Returns:
            :class:`.IPProtocol`: the communication protocol.

        .. seealso::
           | :class:`.IPProtocol`
        """
        return self.__prot

    @protocol.setter
    def protocol(self, protocol):
        """
        Sets the communication protocol.

        Args:
            protocol (:class:`.IPProtocol`): the new communication protocol.

        .. seealso::
           | :class:`.IPProtocol`
        """
        self.__prot = protocol


class SocketCreateResponsePacket(XBeeAPIPacket):
    """
    This class represents a Socket Create Response packet. Packet is built using
    the parameters of the constructor.

    The device sends this frame in response to a Socket Create (0x40) frame. It
    contains a socket ID that should be used for future transactions with the
    socket and a status field.

    If the status field is non-zero, which indicates an error, the socket ID
    will be set to 0xFF and the socket will not be opened.

    .. seealso::
       | :class:`.SocketCreatePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, socket_id, status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.SocketCreateResponsePacket` object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the unique socket ID to address the socket.
            status (:class:`.SocketStatus`): the socket create status.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.SocketStatus`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_CREATE_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__status = status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketCreateResponsePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket id + status + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_CREATE_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketCreateResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_CREATE_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Create Response packet.")

        return SocketCreateResponsePacket(
            raw[4], raw[5], SocketStatus.get(raw[6]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__status.code)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: utils.hex_to_string(bytearray([self.__socket_id])),
            DictKeys.STATUS.value:    "%s (%s)" % (self.__status.code, self.__status.description)}

    @property
    def socket_id(self):
        """
        Returns the the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

    @property
    def status(self):
        """
        Returns the socket create status.

        Returns:
            :class:`.SocketStatus`: the status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        return self.__status

    @status.setter
    def status(self, status):
        """
        Sets the socket create status.

        Args:
            status (:class:`.SocketStatus`): the new status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        self.__status = status


class SocketOptionRequestPacket(XBeeAPIPacket):
    """
    This class represents a Socket Option Request packet. Packet is built using
    the parameters of the constructor.

    Use this frame to modify the behavior of sockets to be different from the
    normal default behavior.

    If the Option Data field is zero-length, the Socket Option Response Packet
    (0xC1) reports the current effective value.

    .. seealso::
       | :class:`.SocketOptionResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, socket_id, option, option_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketOptionRequestPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the socket ID to modify.
            option (:class:`.SocketOption`): the socket option of the parameter to change.
            option_data (Bytearray, optional): the option data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.SocketOption`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_OPTION_REQUEST, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__opt = option
        self.__opt_data = option_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketOptionRequestPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket id + option + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: byte 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_OPTION_REQUEST`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketOptionRequestPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_OPTION_REQUEST.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Option Request packet.")

        return SocketOptionRequestPacket(
            raw[4], raw[5], SocketOption.get(raw[6]),
            option_data=raw[7:-1] if len(raw) > SocketOptionRequestPacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__opt.code)
        if self.__opt_data is not None:
            ret += self.__opt_data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.SOCKET_ID.value:   utils.hex_to_string(bytearray([self.__socket_id])),
                DictKeys.OPTION_ID.value:   "%s (%s)" % (self.__opt.code, self.__opt.description),
                DictKeys.OPTION_DATA.value: utils.hex_to_string(
                    self.__opt_data, True) if self.__opt_data is not None else None}

    @property
    def socket_id(self):
        """
        Returns the the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

    @property
    def option(self):
        """
        Returns the socket option.

        Returns:
            :class:`.SocketOption`: the socket option.

        .. seealso::
           | :class:`.SocketOption`
        """
        return self.__opt

    @option.setter
    def option(self, option):
        """
        Sets the socket option.

        Args:
            option (:class:`.SocketOption`): the new socket option.

        .. seealso::
           | :class:`.SocketOption`
        """
        self.__opt = option

    @property
    def option_data(self):
        """
        Returns the socket option data.

        Returns:
            Bytearray: the socket option data.
        """
        return self.__opt_data if self.__opt_data is None else self.__opt_data.copy()

    @option_data.setter
    def option_data(self, option_data):
        """
        Sets the socket option data.

        Args:
            option_data (Bytearray): the new socket option data.
        """
        self.__opt_data = None if option_data is None else option_data.copy()


class SocketOptionResponsePacket(XBeeAPIPacket):
    """
    This class represents a Socket Option Response packet. Packet is built using
    the parameters of the constructor.

    Reports the status of requests made with the Socket Option Request (0x41)
    packet.

    .. seealso::
       | :class:`.SocketOptionRequestPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 9

    def __init__(self, frame_id, socket_id, option, status, option_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketOptionResponsePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the socket ID for which modification was requested.
            option (:class:`.SocketOption`): the socket option of the parameter requested.
            status (:class:`.SocketStatus`): the socket option status of the parameter requested.
            option_data (Bytearray, optional): the option data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.SocketOption`
           | :class:`.SocketStatus`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_OPTION_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__opt = option
        self.__status = status
        self.__opt_data = option_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketOptionResponsePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 9.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket id + option + status + checksum = 9 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_OPTION_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketOptionResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_OPTION_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Option Response packet.")

        return SocketOptionResponsePacket(
            raw[4], raw[5], SocketOption.get(raw[6]), SocketStatus.get(raw[7]),
            option_data=raw[8:-1] if len(raw) > SocketOptionResponsePacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__opt.code)
        ret.append(self.__status.code)
        if self.__opt_data is not None:
            ret += self.__opt_data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value:   utils.hex_to_string(bytearray([self.__socket_id])),
            DictKeys.OPTION_ID.value:   "%s (%s)" % (self.__opt.code, self.__opt.description),
            DictKeys.STATUS.value:      "%s (%s)" % (self.__status.code, self.__status.description),
            DictKeys.OPTION_DATA.value: utils.hex_to_string(
                self.__opt_data, True) if self.__opt_data is not None else None}

    @property
    def socket_id(self):
        """
        Returns the the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

    @property
    def option(self):
        """
        Returns the socket option.

        Returns:
            :class:`.SocketOption`: the socket option.

        .. seealso::
           | :class:`.SocketOption`
        """
        return self.__opt

    @option.setter
    def option(self, option):
        """
        Sets the socket option.

        Args:
            option (:class:`.SocketOption`): the new socket option.

        .. seealso::
           | :class:`.SocketOption`
        """
        self.__opt = option

    @property
    def status(self):
        """
        Returns the socket option status.

        Returns:
            :class:`.SocketStatus`: the socket option status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        return self.__status

    @status.setter
    def status(self, status):
        """
        Sets the socket option status.

        Args:
            status (:class:`.SocketStatus`): the new socket option status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        self.__status = status

    @property
    def option_data(self):
        """
        Returns the socket option data.

        Returns:
            Bytearray: the socket option data.
        """
        return self.__opt_data if self.__opt_data is None else self.__opt_data.copy()

    @option_data.setter
    def option_data(self, option_data):
        """
        Sets the socket option data.

        Args:
            option_data (Bytearray): the new socket option data.
        """
        self.__opt_data = None if option_data is None else option_data.copy()


class SocketConnectPacket(XBeeAPIPacket):
    """
    This class represents a Socket Connect packet. Packet is built using the
    parameters of the constructor.

    Use this frame to create a socket connect message that causes the device to
    connect a socket to the given address and port.

    For a UDP socket, this filters out any received responses that are not from
    the specified remote address and port.

    Two frames occur in response:

      * Socket Connect Response frame (:class:`SocketConnectResponsePacket`):
        Arrives immediately and confirms the request.
      * Socket Status frame (:class:`SocketStatePacket`): Indicates if the
        connection was successful.

    .. seealso::
       | :class:`.SocketConnectResponsePacket`
       | :class:`.SocketStatePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 11

    DEST_ADDRESS_BINARY = 0
    """Indicates the destination address field is a binary IPv4 address in network byte order."""

    DEST_ADDRESS_STRING = 1
    """Indicates the destination address field is a string containing either a
    dotted quad value or a domain name to be resolved."""

    def __init__(self, frame_id, socket_id, dest_port, dest_address_type,
                 dest_address, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketConnectPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the ID of the socket to connect.
            dest_port (Integer): the destination port number.
            dest_address_type (Integer): the destination address type. One of
                                         :attr:`SocketConnectPacket.DEST_ADDRESS_BINARY` or
                                         :attr:`SocketConnectPacket.DEST_ADDRESS_STRING`.
            dest_address (Bytearray or String): the destination address.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :attr:`SocketConnectPacket.DEST_ADDRESS_BINARY`
           | :attr:`SocketConnectPacket.DEST_ADDRESS_STRING`
           | :class:`.XBeeAPIPacket`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
            ValueError: if `dest_port` is less than 0 or greater than 65535.
            ValueError: if `dest_address_type` is different than
                :attr:`SocketConnectPacket.DEST_ADDRESS_BINARY` and
                :attr:`SocketConnectPacket.DEST_ADDRESS_STRING`.
            ValueError: if `dest_address` is `None` or does not follow the
                format specified in the configured type.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        if dest_port < 0 or dest_port > 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        if dest_address_type not in (SocketConnectPacket.DEST_ADDRESS_BINARY,
                                     SocketConnectPacket.DEST_ADDRESS_STRING):
            raise ValueError("Destination address type must be %d or %d" % (
                SocketConnectPacket.DEST_ADDRESS_BINARY, SocketConnectPacket.DEST_ADDRESS_STRING))
        if (dest_address is None
                or (dest_address_type == SocketConnectPacket.DEST_ADDRESS_BINARY
                    and (not isinstance(dest_address, bytearray) or len(dest_address) != 4))
                or (dest_address_type == SocketConnectPacket.DEST_ADDRESS_STRING
                    and (not isinstance(dest_address, str) or len(dest_address) < 1))):
            raise ValueError("Invalid destination address")

        super().__init__(ApiFrameType.SOCKET_CONNECT, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__dest_port = dest_port
        self.__dest_addr_type = dest_address_type
        self.__dest_addr = dest_address

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketConnectPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 11.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket id + dest port (2 bytes) + dest address type
                + dest_address + checksum = 11 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_CONNECT`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketConnectPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_CONNECT.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Connect packet.")

        addr_type = raw[8]
        address = raw[9:-1]
        if address is not None and addr_type == SocketConnectPacket.DEST_ADDRESS_STRING:
            address = address.decode(encoding="utf8", errors='ignore')

        return SocketConnectPacket(raw[4], raw[5], utils.bytes_to_int(raw[6:8]),
                                   addr_type, address, op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret += utils.int_to_bytes(self.__dest_port, num_bytes=2)
        ret.append(self.__dest_addr_type)
        if isinstance(self.__dest_addr, str):
            ret += self.__dest_addr.encode(encoding='utf8')
        else:
            ret += self.__dest_addr
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.DEST_PORT.value: "%s (%s)"
                                      % (utils.hex_to_string(utils.int_to_bytes(self.__dest_port, num_bytes=2)),
                                         self.__dest_port),
            DictKeys.DEST_ADDR_TYPE.value: "%02X" % self.__dest_addr_type,
            DictKeys.DEST_ADDR.value:      ("%s (%s)" % (
                utils.hex_to_string(
                    self.__dest_addr.encode(encoding="utf8", errors='ignore')), self.__dest_addr)) if isinstance(self.__dest_addr, str) else utils.hex_to_string(self.__dest_addr)}

    @property
    def socket_id(self):
        """
        Returns the the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

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
    def dest_address_type(self):
        """
        Returns the destination address type.

        Returns:
            Integer: the destination address type.
        """
        return self.__dest_addr_type

    @dest_address_type.setter
    def dest_address_type(self, dest_address_type):
        """
        Sets the destination address type.

        Args:
            dest_address_type (Integer): the new destination address type.

        Raises:
            ValueError: if `dest_address_type` is different from
                :attr:`SocketConnectPacket.DEST_ADDRESS_BINARY` and
                :attr:`SocketConnectPacket.DEST_ADDRESS_STRING`.
        """
        if dest_address_type not in (SocketConnectPacket.DEST_ADDRESS_BINARY,
                                     SocketConnectPacket.DEST_ADDRESS_STRING):
            raise ValueError("Destination address type must be %d or %d" % (
                SocketConnectPacket.DEST_ADDRESS_BINARY, SocketConnectPacket.DEST_ADDRESS_STRING))
        self.__dest_addr_type = dest_address_type

    @property
    def dest_address(self):
        """
        Returns the destination address.

        Returns:
            Bytearray or String: the destination address.
        """
        return self.__dest_addr

    @dest_address.setter
    def dest_address(self, dest_address):
        """
        Sets the destination address.

        Args:
            dest_address (Bytearray or String): the new destination address.

        Raises:
            ValueError: if `dest_address` is `None`.
            ValueError: if `dest_address` does not follow the format specified
                in the configured type.
        """
        if (dest_address is None
                or (self.__dest_addr_type == SocketConnectPacket.DEST_ADDRESS_BINARY
                    and (not isinstance(dest_address, bytearray) or len(dest_address) != 4))
                or (self.__dest_addr_type == SocketConnectPacket.DEST_ADDRESS_STRING
                    and (not isinstance(dest_address, str) or len(dest_address) < 1))):
            raise ValueError("Invalid destination address")
        self.__dest_addr = dest_address


class SocketConnectResponsePacket(XBeeAPIPacket):
    """
    This class represents a Socket Connect Response packet. Packet is built
    using the parameters of the constructor.

    The device sends this frame in response to a Socket Connect (0x42) frame.
    The frame contains a status regarding the initiation of the connect.

    .. seealso::
       | :class:`.SocketConnectPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, socket_id, status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketConnectPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the ID of the socket to connect.
            status (:class:`.SocketStatus`): the socket connect status.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.SocketStatus`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_CONNECT_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__status = status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketConnectResponsePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket id + status + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_CONNECT_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketConnectResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_CONNECT_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Connect Response packet.")

        return SocketConnectResponsePacket(
            raw[4], raw[5], SocketStatus.get(raw[6]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__status.code)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.STATUS.value:    "%s (%s)" % (self.__status.code, self.__status.description)}

    @property
    def socket_id(self):
        """
        Returns the the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

    @property
    def status(self):
        """
        Returns the socket connect status.

        Returns:
            :class:`.SocketStatus`: the socket connect status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        return self.__status

    @status.setter
    def status(self, status):
        """
        Sets the socket connect status.

        Args:
            status (:class:`.SocketStatus`): the new socket connect status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        self.__status = status


class SocketClosePacket(XBeeAPIPacket):
    """
    This class represents a Socket Close packet. Packet is built using the
    parameters of the constructor.

    Use this frame to close a socket when given an identifier.

    .. seealso::
       | :class:`.SocketCloseResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, socket_id, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketClosePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the ID of the socket to close.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_CLOSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketClosePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7.
                (start delim. + length (2 bytes) + frame
                type + frame id + socket id + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_CLOSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=SocketClosePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_CLOSE.code:
            raise InvalidPacketException(message="This packet is not a Socket Close packet.")

        return SocketClosePacket(raw[4], raw[5], op_mode=operating_mode)

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
        return bytearray([self.__socket_id])

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.SOCKET_ID.value: utils.hex_to_string(bytearray([self.__socket_id]))}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id


class SocketCloseResponsePacket(XBeeAPIPacket):
    """
    This class represents a Socket Close Response packet. Packet is built using
    the parameters of the constructor.

    The device sends this frame in response to a Socket Close (0x43) frame.
    Since a close will always succeed for a socket that exists, the status can
    be only one of two values:

      * Success.
      * Bad socket ID.

    .. seealso::
       | :class:`.SocketClosePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, socket_id, status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketCloseResponsePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the ID of the socket to close.
            status (:class:`.SocketStatus`): the socket close status.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.SocketStatus`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")

        super().__init__(ApiFrameType.SOCKET_CLOSE_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__status = status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketCloseResponsePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket id + status + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_CLOSE_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketCloseResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_CLOSE_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a Socket Close Response packet.")

        return SocketCloseResponsePacket(
            raw[4], raw[5], SocketStatus.get(raw[6]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__status.code)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.STATUS.value:    "%s (%s)" % (self.__status.code, self.__status.description)}

    @property
    def socket_id(self):
        """
        Returns the the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): the new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

    @property
    def status(self):
        """
        Returns the socket close status.

        Returns:
            :class:`.SocketStatus`: the socket close status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        return self.__status

    @status.setter
    def status(self, status):
        """
        Sets the socket close status.

        Args:
            status (:class:`.SocketStatus`): the new socket close status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        self.__status = status


class SocketSendPacket(XBeeAPIPacket):
    """
    This class represents a Socket Send packet. Packet is built using the
    parameters of the constructor.

    A Socket Send message causes the device to transmit data using the
    current connection. For a nonzero frame ID, this will elicit a Transmit
    (TX) Status - 0x89 frame (:class:`.TransmitStatusPacket`).

    This frame requires a successful Socket Connect - 0x42 frame first
    (:class:`.SocketConnectPacket`). For a socket that is not connected, the
    device responds with a Transmit (TX) Status - 0x89 frame with an
    error.

    .. seealso::
       | :class:`.TransmitStatusPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, socket_id, payload=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketSendPacket` object
        with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the socket identifier.
            payload (Bytearray, optional): data that is sent.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255.")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")

        super().__init__(ApiFrameType.SOCKET_SEND, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__payload = payload

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketSendPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket ID + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_SEND`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketSendPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_SEND.code:
            raise InvalidPacketException(
                "This packet is not a Socket Send (transmit) packet.")

        return SocketSendPacket(
            raw[4], raw[5],
            payload=raw[7:-1] if len(raw) > SocketSendPacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(0)  # Transmit options (Reserved)
        if self.__payload is not None:
            ret += self.__payload
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value:        "%02X" % self.__socket_id,
            DictKeys.TRANSMIT_OPTIONS.value: "00",
            DictKeys.PAYLOAD.value:          utils.hex_to_string(self.__payload,
                                                                 True) if self.__payload is not None else None}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

    @property
    def payload(self):
        """
        Returns the payload to send.

        Returns:
            Bytearray: the payload to send.
        """
        if self.__payload is None:
            return None
        return self.__payload.copy()

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload to send.

        Args:
            payload (Bytearray): the new payload to send.
        """
        if payload is None:
            self.__payload = None
        else:
            self.__payload = payload.copy()


class SocketSendToPacket(XBeeAPIPacket):
    """
    This class represents a Socket Send packet. Packet is built using the
    parameters of the constructor.

    A Socket SendTo (Transmit Explicit Data) message causes the device to
    transmit data using an IPv4 address and port. For a non-zero frame ID,
    this will elicit a Transmit (TX) Status - 0x89 frame
    (:class:`.TransmitStatusPacket`).

    If this frame is used with a TCP, SSL, or a connected UDP socket, the
    address and port fields are ignored.

    .. seealso::
       | :class:`.TransmitStatusPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 14

    def __init__(self, frame_id, socket_id, dest_address, dest_port,
                 payload=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketSendToPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the socket identifier.
            dest_address (:class:`.IPv4Address`): IPv4 address of the destination device.
            dest_port (Integer): destination port number.
            payload (Bytearray, optional): data that is sent.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
            ValueError: if `dest_port` is less than 0 or greater than 65535.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255.")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        if dest_port < 0 or dest_port > 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        super().__init__(ApiFrameType.SOCKET_SENDTO, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__dest_addr = dest_address
        self.__dest_port = dest_port
        self.__payload = payload

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketSendToPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 14.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket ID + dest address (4 bytes) + dest port (2 bytes)
                + transmit options + checksum = 14 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_SENDTO`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketSendToPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_SENDTO.code:
            raise InvalidPacketException(
                "This packet is not a Socket SendTo (Transmit Explicit Data): "
                "IPv4 packet.")

        return SocketSendToPacket(
            raw[4], raw[5], IPv4Address(bytes(raw[6:10])), utils.bytes_to_int(raw[10:12]),
            payload=raw[13:-1] if len(raw) > SocketSendToPacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret += self.__dest_addr.packed
        ret += utils.int_to_bytes(self.__dest_port, num_bytes=2)
        ret.append(0)  # Transmit options (Reserved)
        if self.__payload is not None:
            ret += self.__payload
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value:        "%02X" % self.__socket_id,
            DictKeys.DEST_IPV4_ADDR.value:   "%s (%s)" % (utils.hex_to_string(self.__dest_addr.packed, True),
                                                          self.__dest_addr.exploded),
            DictKeys.DEST_PORT.value:        "%s (%s)" % (utils.hex_to_string(utils.int_to_bytes(self.__dest_port,
                                                                                                 num_bytes=2)),
                                                          self.__dest_port),
            DictKeys.TRANSMIT_OPTIONS.value: "00",
            DictKeys.PAYLOAD.value:          utils.hex_to_string(self.__payload,
                                                                 True) if self.__payload is not None else None}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

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
    def payload(self):
        """
        Returns the payload to send.

        Returns:
            Bytearray: the payload to send.
        """
        if self.__payload is None:
            return None
        return self.__payload.copy()

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload to send.

        Args:
            payload (Bytearray): the new payload to send.
        """
        if payload is None:
            self.__payload = None
        else:
            self.__payload = payload.copy()


class SocketBindListenPacket(XBeeAPIPacket):
    """
    This class represents a Socket Bind/Listen packet. Packet is built using the
    parameters of the constructor.

    Opens a listener socket that listens for incoming connections.

    When there is an incoming connection on the listener socket, a Socket New
    IPv4 Client - 0xCC frame (:class:`.SocketNewIPv4ClientPacket`) is sent,
    indicating the socket ID for the new connection along with the remote
    address information.

    For a UDP socket, this frame binds the socket to a given port. A bound
    UDP socket can receive data with a Socket Receive From: IPv4 - 0xCE frame
    (:class:`.SocketReceiveFromIPv4Packet`).

    .. seealso::
       | :class:`.SocketNewIPv4ClientPacket`
       | :class:`.SocketReceiveFromIPv4Packet`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 9

    def __init__(self, frame_id, socket_id, src_port, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketBindListenPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): socket ID to listen on.
            src_port (Integer): the port to listen on.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
            ValueError: if `source_port` is less than 0 or greater than 65535.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255.")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        if src_port < 0 or src_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")

        super().__init__(ApiFrameType.SOCKET_BIND, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__src_port = src_port

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketBindListenPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 9.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket ID + source port (2 bytes) + checksum = 9 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_BIND`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketBindListenPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_BIND.code:
            raise InvalidPacketException(
                "This packet is not a Socket Bind/Listen packet.")

        return SocketBindListenPacket(
            raw[4], raw[5], utils.bytes_to_int(raw[6:8]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret += utils.int_to_bytes(self.__src_port, num_bytes=2)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.SRC_PORT.value:  "%s (%s)" % (utils.hex_to_string(utils.int_to_bytes(self.__src_port,
                                                                                          num_bytes=2)),
                                                   self.__src_port)}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

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


class SocketListenResponsePacket(XBeeAPIPacket):
    """
    This class represents a Socket Listen Response packet. Packet is built using
    the parameters of the constructor.

    The device sends this frame in response to a Socket Bind/Listen (0x46)
    frame (:class:`.SocketBindListenPacket`).

    .. seealso::
       | :class:`.SocketBindListenPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, socket_id, status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketListenResponsePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): socket ID.
            status (:class:`.SocketStatus`): socket listen status.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.SocketStatus`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")

        super().__init__(ApiFrameType.SOCKET_LISTEN_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__status = status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketListenResponsePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket ID + status + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_LISTEN_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketListenResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_LISTEN_RESPONSE.code:
            raise InvalidPacketException(
                "This packet is not a Socket Listen Response packet.")

        return SocketListenResponsePacket(
            raw[4], raw[5], SocketStatus.get(raw[6]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__status.code)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.STATUS.value:    "%s (%s)" % (utils.hex_to_string(bytearray([self.__status.code])),
                                                   self.__status.description)}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

    @property
    def status(self):
        """
        Returns the socket listen status.

        Returns:
            :class:`.SocketStatus`: The socket listen status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        return self.__status

    @status.setter
    def status(self, status):
        """
        Sets the socket listen status.

        Args:
            status (:class:`.SocketStatus`): the new socket listen status.

        .. seealso::
           | :class:`.SocketStatus`
        """
        self.__status = status


class SocketNewIPv4ClientPacket(XBeeAPIPacket):
    """
    This class represents a Socket New IPv4 Client packet. Packet is built using
    the parameters of the constructor.

    XBee Cellular modem uses this frame when an incoming connection is
    accepted on a listener socket.

    This frame contains the original listener's socket ID and a new socket ID
    of the incoming connection, along with the connection's remote address
    information.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 13

    def __init__(self, socket_id, client_socket_id, remote_address,
                 remote_port, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketNewIPv4ClientPacket`
        object with the provided parameters.

        Args:
            socket_id (Integer): the socket ID of the listener socket.
            client_socket_id (Integer): the socket ID of the new connection.
            remote_address (:class:`.IPv4Address`): the remote IPv4 address.
            remote_port (Integer): the remote port number.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
            ValueError: if `client_socket_id` is less than 0 or greater than 255.
            ValueError: if `remote_port` is less than 0 or greater than 65535.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        if client_socket_id < 0 or client_socket_id > 255:
            raise ValueError("Client socket ID must be between 0 and 255")
        if remote_port < 0 or remote_port > 65535:
            raise ValueError("Remote port must be between 0 and 65535")

        super().__init__(ApiFrameType.SOCKET_NEW_IPV4_CLIENT, op_mode=op_mode)
        self.__socket_id = socket_id
        self.__client_sock_id = client_socket_id
        self.__remote_addr = remote_address
        self.__remote_port = remote_port

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketNewIPv4ClientPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 13.
                (start delim. + length (2 bytes) + frame type + socket ID
                + client socket ID + remote address (4 bytes)
                + remote port (2 bytes) + checksum = 13 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_NEW_IPV4_CLIENT`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketNewIPv4ClientPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_NEW_IPV4_CLIENT.code:
            raise InvalidPacketException(
                "This packet is not a Socket New IPv4 Client packet.")

        return SocketNewIPv4ClientPacket(raw[4], raw[5], IPv4Address(bytes(raw[6:10])),
                                         utils.bytes_to_int(raw[10:12]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__client_sock_id)
        ret += self.__remote_addr.packed
        ret += utils.int_to_bytes(self.__remote_port, num_bytes=2)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value:        "%02X" % self.__socket_id,
            DictKeys.CLIENT_SOCKET_ID.value: "%02X" % self.__client_sock_id,
            DictKeys.REMOTE_ADDR.value:      "%s (%s)" % (utils.hex_to_string(self.__remote_addr.packed, True),
                                                          self.__remote_addr.exploded),
            DictKeys.REMOTE_PORT.value:      "%s (%s)" % (utils.hex_to_string(utils.int_to_bytes(self.__remote_port,
                                                                                                 num_bytes=2)),
                                                          self.__remote_port)}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__socket_id = socket_id

    @property
    def client_socket_id(self):
        """
        Returns the client socket ID.

        Returns:
            Integer: the client socket ID.
        """
        return self.__client_sock_id

    @client_socket_id.setter
    def client_socket_id(self, client_socket_id):
        """
        Sets the client socket ID.

        Args:
            client_socket_id (Integer): The new client socket ID.

        Raises:
            ValueError: if `client_socket_id` is less than 0 or greater than 255.
        """
        if client_socket_id < 0 or client_socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255")
        self.__client_sock_id = client_socket_id

    @property
    def remote_address(self):
        """
        Returns the remote IPv4 address.

        Returns:
            :class:`ipaddress.IPv4Address`: the remote IPv4 address.
        """
        return self.__remote_addr

    @remote_address.setter
    def remote_address(self, remote_address):
        """
        Sets the remote IPv4 address.

        Args:
            remote_address (:class:`ipaddress.IPv4Address`): The new remote IPv4 address.
        """
        if remote_address is not None:
            self.__remote_addr = remote_address

    @property
    def remote_port(self):
        """
        Returns the remote port.

        Returns:
            Integer: the remote port.
        """
        return self.__remote_port

    @remote_port.setter
    def remote_port(self, remote_port):
        """
        Sets the remote port.

        Args:
            remote_port (Integer): the new remote port.

        Raises:
            ValueError: if `remote_port` is less than 0 or greater than 65535.
        """
        if remote_port < 0 or remote_port > 65535:
            raise ValueError("Remote port must be between 0 and 65535")
        self.__remote_port = remote_port


class SocketReceivePacket(XBeeAPIPacket):
    """
    This class represents a Socket Receive packet. Packet is built using
    the parameters of the constructor.

    XBee Cellular modem uses this frame when it receives RF data on the
    specified socket.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, socket_id, payload=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketReceivePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the ID of the socket the data has been received on.
            payload (Bytearray, optional): data that is received.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255.")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")

        super().__init__(ApiFrameType.SOCKET_RECEIVE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__payload = payload

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketReceivePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket ID + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_RECEIVE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketReceivePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_RECEIVE.code:
            raise InvalidPacketException(
                "This packet is not a Socket Receive packet.")

        return SocketReceivePacket(
            raw[4], raw[5],
            payload=raw[7:-1] if len(raw) > SocketReceivePacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(0)  # Status (Reserved)
        if self.__payload is not None:
            ret += self.__payload
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.STATUS.value:    "00",
            DictKeys.PAYLOAD.value:   utils.hex_to_string(self.__payload) if self.__payload is not None else None}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

    @property
    def payload(self):
        """
        Returns the payload that was received.

        Returns:
            Bytearray: the payload that was received.
        """
        if self.__payload is None:
            return None
        return self.__payload.copy()

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload that was received.

        Args:
            payload (Bytearray): the new payload that was received.
        """
        if payload is None:
            self.__payload = None
        else:
            self.__payload = payload.copy()


class SocketReceiveFromPacket(XBeeAPIPacket):
    """
    This class represents a Socket Receive From packet. Packet is built using
    the parameters of the constructor.

    XBee Cellular modem uses this frame when it receives RF data on the
    specified socket. The frame also contains addressing information about
    the source.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 14

    def __init__(self, frame_id, socket_id, src_address, src_port,
                 payload=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketReceiveFromPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            socket_id (Integer): the ID of the socket the data has been received on.
            src_address (:class:`.IPv4Address`): IPv4 address of the source device.
            src_port (Integer): source port number.
            payload (Bytearray, optional): data that is received.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if `socket_id` is less than 0 or greater than 255.
            ValueError: if `source_port` is less than 0 or greater than 65535.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255.")
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        if src_port < 0 or src_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")

        super().__init__(ApiFrameType.SOCKET_RECEIVE_FROM, op_mode=op_mode)
        self._frame_id = frame_id
        self.__socket_id = socket_id
        self.__src_addr = src_address
        self.__src_port = src_port
        self.__payload = payload

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketReceiveFromPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 13.
                (start delim. + length (2 bytes) + frame type + frame id
                + socket ID + source address (4 bytes) + source port (2 bytes)
                + status + Checksum = 14 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_RECEIVE_FROM`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketReceiveFromPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_RECEIVE_FROM.code:
            raise InvalidPacketException(
                "This packet is not a Socket Receive From packet.")

        return SocketReceiveFromPacket(
            raw[4], raw[5], IPv4Address(bytes(raw[6:10])), utils.bytes_to_int(raw[10:12]),
            payload=raw[13:-1] if len(raw) > SocketReceiveFromPacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret += self.__src_addr.packed
        ret += utils.int_to_bytes(self.__src_port, num_bytes=2)
        ret.append(0)  # Status (Reserved)
        if self.__payload is not None:
            ret += self.__payload
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value:     "%02X" % self.__socket_id,
            DictKeys.SRC_IPV4_ADDR.value: "%s (%s)" % (utils.hex_to_string(self.__src_addr.packed),
                                                       self.__src_addr.exploded),
            DictKeys.SRC_PORT.value:      "%s (%s)" % (utils.hex_to_string(utils.int_to_bytes(self.__src_port,
                                                                                              num_bytes=2)),
                                                       self.__src_port),
            DictKeys.STATUS.value:        "00",
            DictKeys.PAYLOAD.value:       utils.hex_to_string(self.__payload,
                                                              True) if self.__payload is not None else None}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

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
            source_address (:class:`ipaddress.IPv4Address`): The new IPv4 source address.
        """
        if source_address is not None:
            self.__src_addr = source_address

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
        Sets the destination port.

        Args:
            source_port (Integer): the new source port.

        Raises:
            ValueError: if `source_port` is less than 0 or greater than 65535.
        """
        if source_port < 0 or source_port > 65535:
            raise ValueError("Source port must be between 0 and 65535")
        self.__src_port = source_port

    @property
    def payload(self):
        """
        Returns the payload to send.

        Returns:
            Bytearray: the payload that has been received.
        """
        if self.__payload is None:
            return None
        return self.__payload.copy()

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload to send.

        Args:
            payload (Bytearray): the new payload that has been received.
        """
        if payload is None:
            self.__payload = None
        else:
            self.__payload = payload.copy()


class SocketStatePacket(XBeeAPIPacket):
    """
    This class represents a Socket State packet. Packet is built using the
    parameters of the constructor.

    This frame is sent out the device's serial port to indicate the state
    related to the socket.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, socket_id, state, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.SocketStatePacket`
        object with the provided parameters.

        Args:
            socket_id (Integer): the socket identifier.
            state (:class:`.SocketState`): socket status.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.SockeState`
           | :class:`.XBeeAPIPacket`
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")

        super().__init__(ApiFrameType.SOCKET_STATE, op_mode=op_mode)
        self.__socket_id = socket_id
        self.__state = state

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.SocketStatePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7.
                (start delim. + length (2 bytes) + frame type + socket ID
                + state + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.SOCKET_STATUS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=SocketStatePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.SOCKET_STATE.code:
            raise InvalidPacketException(
                "This packet is not a Socket State packet.")

        return SocketStatePacket(raw[4], SocketState.get(raw[5]), op_mode=operating_mode)

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
        ret = bytearray()
        ret.append(self.__socket_id)
        ret.append(self.__state.code)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {
            DictKeys.SOCKET_ID.value: "%02X" % self.__socket_id,
            DictKeys.STATUS.value:    "%s (%s)" % (utils.hex_to_string(bytearray([self.__state.code])),
                                                   self.__state.description)}

    @property
    def socket_id(self):
        """
        Returns the socket ID.

        Returns:
            Integer: the socket ID.
        """
        return self.__socket_id

    @socket_id.setter
    def socket_id(self, socket_id):
        """
        Sets the socket ID.

        Args:
            socket_id (Integer): The new socket ID.

        Raises:
            ValueError: if `socket_id` is less than 0 or greater than 255.
        """
        if socket_id < 0 or socket_id > 255:
            raise ValueError("Socket ID must be between 0 and 255.")
        self.__socket_id = socket_id

    @property
    def state(self):
        """
        Returns the socket state.

        Returns:
            :class:`.SocketState`: The socket state.

        .. seealso::
           | :class:`.SocketState`
        """
        return self.__state

    @state.setter
    def state(self, status):
        """
        Sets the socket state.

        Args:
            status (:class:`.SocketState`): the new socket state.

        .. seealso::
           | :class:`.SocketState`
        """
        self.__state = status
