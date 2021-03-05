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
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import RegisterKeyOptions
from digi.xbee.models.status import ZigbeeRegisterStatus, EmberBootloaderMessageType
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.util import utils


class RegisterJoiningDevicePacket(XBeeAPIPacket):
    """
    This class represents a Register Joining Device packet. Packet is built
    using the parameters of the constructor or providing a valid API
    payload.

    Use this frame to securely register a joining device to a trust center.
    Registration is the process by which a node is authorized to join the
    network using a preconfigured link key or installation code that is
    conveyed to the trust center out-of-band (using a physical interface and
    not over-the-air).

    If registering a device with a centralized trust center (EO = 2), then the
    key entry will only persist for KT seconds before expiring.

    Registering devices in a distributed trust center (EO = 0) is persistent
    and the key entry will never expire unless explicitly removed.

    To remove a key entry on a distributed trust center, this frame should be
    issued with a null (None) key. In a  centralized trust center you cannot
    use this method to explicitly remove the key entries.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 17

    def __init__(self, frame_id, registrant_address, options, key, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.RegisterJoiningDevicePacket` object with the
        provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            registrant_address (:class:`.XBee64BitAddress`): the 64-bit address
                of the destination device.
            options (:class:`.RegisterKeyOptions`): the register options
                indicating the key source.
            key (Bytearray): key of the device to register. Up to 16 bytes if
                entering a Link Key or up to 18 bytes
                (16-byte code + 2 byte CRC) if entering an Install Code.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
           | :class:`.RegisterKeyOptions`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.REGISTER_JOINING_DEVICE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__registrant_addr = registrant_address
        self.__opts = options
        self.__key = key

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RegisterJoiningDevicePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 17.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64-bit registrant addr. (8 bytes)
                + 16-bit registrant addr. (2 bytes) + options
                + checksum = 17 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.REGISTER_JOINING_DEVICE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(
                operating_mode.name + " is not supported.")

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RegisterJoiningDevicePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REGISTER_JOINING_DEVICE.code:
            raise InvalidPacketException(
                "This packet is not a Register Joining Device packet.")

        return RegisterJoiningDevicePacket(raw[4], XBee64BitAddress(raw[5:13]),
                                           RegisterKeyOptions.get(raw[15]),
                                           raw[16:-1], op_mode=operating_mode)

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
        ret = self.__registrant_addr.address
        ret += XBee16BitAddress.UNKNOWN_ADDRESS.address
        ret.append(self.__opts.code)
        if self.__key is not None:
            ret += self.__key
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR: "%s (%s)" % (self.__registrant_addr.packed,
                                                   self.__registrant_addr.exploded),
                DictKeys.RESERVED:    XBee16BitAddress.UNKNOWN_ADDRESS.address,
                DictKeys.OPTIONS:     "%s (%s)" % (self.__opts.code,
                                                   self.__opts.description),
                DictKeys.KEY:         list(self.__key) if self.__key is not None else None}

    @property
    def registrant_address(self):
        """
        Returns the 64-bit registrant address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit registrant address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__registrant_addr

    @registrant_address.setter
    def registrant_address(self, registrant_address):
        """
        Sets the 64-bit registrant address.

        Args:
            registrant_address (:class:`.XBee64BitAddress`): The new 64-bit
                registrant address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        if registrant_address is not None:
            self.__registrant_addr = registrant_address

    @property
    def options(self):
        """
        Returns the register options value.

        Returns:
            :class:`.RegisterKeyOptions`: the register options indicating the key source.

        .. seealso::
           | :class:`.RegisterKeyOptions`
        """
        return self.__opts

    @options.setter
    def options(self, options):
        """
        Sets the register options value.

        Args:
            options (:class:`.RegisterKeyOptions`): the new register options.

        .. seealso::
           | :class:`.RegisterKeyOptions`
        """
        self.__opts = options

    @property
    def key(self):
        """
        Returns the register key.

        Returns:
            Bytearray: the register key.
        """
        if self.__key is None:
            return None
        return self.__key.copy()

    @key.setter
    def key(self, key):
        """
        Sets the register key.

        Args:
            key (Bytearray): the new register key.
        """
        if key is None:
            self.__key = None
        else:
            self.__key = key.copy()


class RegisterDeviceStatusPacket(XBeeAPIPacket):
    """
    This class represents a Register Device Status packet. Packet is built
    using the parameters of the constructor or providing a valid API
    payload.

    This frame is sent out of the UART of the trust center as a response to
    a 0x24 Register Device frame, indicating whether the registration was
    successful or not.

    .. seealso::
       | :class:`.RegisterJoiningDevicePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.RegisterDeviceStatusPacket` object with the
        provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            status (:class:`.ZigbeeRegisterStatus`): status of the register
                device operation.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.ZigbeeRegisterStatus`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.REGISTER_JOINING_DEVICE_STATUS, op_mode=op_mode)
        self._frame_id = frame_id
        self.__status = status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RegisterDeviceStatusPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 17.
                (start delim. + length (2 bytes) + frame type + frame id
                + status + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 1 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.REGISTER_JOINING_DEVICE_STATUS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(
                operating_mode.name + " is not supported.")

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RegisterDeviceStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REGISTER_JOINING_DEVICE_STATUS.code:
            raise InvalidPacketException(
                "This packet is not a Register Device Status packet.")

        return RegisterDeviceStatusPacket(
            raw[4], ZigbeeRegisterStatus.get(raw[5]), op_mode=operating_mode)

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
        return bytearray([self.__status.code])

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.STATUS: "%s (%s)" % (self.__status.code,
                                              self.__status.description)}

    @property
    def status(self):
        """
        Returns the register device status.

        Returns:
            :class:`.ZigbeeRegisterStatus`: the register device status.

        .. seealso::
           | :class:`.ZigbeeRegisterStatus`
        """
        return self.__status

    @status.setter
    def status(self, status):
        """
        Sets the register device status.

        Args:
            status (:class:`.ZigbeeRegisterStatus`): the new register device status.

        .. seealso::
           | :class:`.ZigbeeRegisterStatus`
        """
        self.__status = status


class RouteRecordIndicatorPacket(XBeeAPIPacket):
    """
    This class represents a Zigbee Route Record Indicator packet. Packet is
    built using the parameters of the constructor or providing a valid API
    payload.

    The route record indicator is received whenever a device sends a Zigbee
    route record command. This is used with many-to-one routing to create
    source routes for devices in a network.

    Among received data, some options can also be received indicating
    transmission parameters.

    .. seealso::
       | :class:`.ReceiveOptions`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 17

    def __init__(self, x64bit_addr, x16bit_addr, rx_opts, hops=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.RouteRecordIndicatorPacket` object with the provided
        parameters.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): The 64-bit source address.
            x16bit_addr (:class:`.XBee16BitAddress`): The 16-bit source address.
            rx_opts (Integer): Bitfield indicating the receive options.
            hops (List, optional, default=`None`): List of 16-bit address of
                intermediate hops in the source route (excluding source and
                destination).
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ReceiveOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.ROUTE_RECORD_INDICATOR, op_mode=op_mode)

        self.__x64_addr = x64bit_addr
        self.__x16_addr = x16bit_addr
        self.__rx_opts = rx_opts
        self.__hops = hops if hops else []

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RouteRecordIndicatorPacket`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 17.
                (start delim. + length (2 bytes) + frame type + 64bit addr. +
                16bit addr. + Receive options + num of addrs + checksum
                = 17 bytes).
            InvalidPacketException: If the length field of `raw` is different
                from its real length. (length field: bytes 1 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is not
                :attr:`.ApiFrameType.ROUTE_RECORD_INDICATOR`.
            InvalidPacketException: If the number of hops does not match with
                the number of 16-bit addresses.
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
            raw, min_length=RouteRecordIndicatorPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.ROUTE_RECORD_INDICATOR.code:
            raise InvalidPacketException(
                "This packet is not a Route Record Indicator packet.")

        hops = [XBee16BitAddress(raw[i:i+2]) for i in range(16, len(raw) - 1, 2)]

        if raw[15] != len(hops):
            raise InvalidPacketException("Specified number of hops does not"
                                         "match with the length of addresses.")

        return RouteRecordIndicatorPacket(
            XBee64BitAddress(raw[4:12]), XBee16BitAddress(raw[12:14]),
            raw[14], hops, op_mode=operating_mode)

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
        return utils.is_bit_enabled(self.__rx_opts, 1)

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64_addr.address
        ret += self.__x16_addr.address
        ret.append(self.__rx_opts)
        ret.append(len(self.__hops))
        for hop in self.__hops:
            ret += hop.address

        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        hops_array = [hop.address for hop in self.__hops]

        return {DictKeys.X64BIT_ADDR:     self.__x64_addr.address,
                DictKeys.X16BIT_ADDR:     self.__x16_addr.address,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts,
                DictKeys.NUM_OF_HOPS:     len(hops_array),
                DictKeys.HOPS:            hops_array}

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: The 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): The new 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64_addr = x64bit_addr

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: The 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): The new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16_addr = x16bit_addr

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: The receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): The new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def number_of_hops(self):
        """
        Returns the number of intermediate hops in the source route (excluding
        source and destination).

        Returns:
            Integer: The number of addresses.
        """
        return len(self.__hops)

    @property
    def hops(self):
        """
        Returns the list of intermediate hops starting from the closest to
        destination hop and finishing with the closest to the source (excluding
        source and destination).

        Returns:
            List: The list of 16-bit addresses of intermediate hops.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__hops

    @hops.setter
    def hops(self, hops):
        """
        Sets the hops of the route (excluding source and destination).

        Args:
            hops (List): List of `XBee16BitAddress`.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__hops = hops if hops else []


class CreateSourceRoutePacket(XBeeAPIPacket):
    """
    This class represents a Zigbee Create Source Route packet. This packet is
    built using the parameters of the constructor or providing a valid API
    payload.

    This frame creates a source route in the node. A source route specifies the
    complete route a packet should travese to get from source to destination.
    Source routing should be used with many-to-one routing for best results.

    Note: Both, 64-bit and 16-bit destination addresses are required when
    creating a source route. These are obtained when a Route Record Indicator
    (0xA1) frame is received.

    .. seealso::
       | :class:`.RouteRecordIndicatorPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 18

    def __init__(self, frame_id, x64bit_addr, x16bit_addr, route_options=0,
                 hops=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.CreateSourceRoutePacket`
        object with the provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): The 64-bit destination address.
            x16bit_addr (:class:`.XBee16BitAddress`): The 16-bit destination address.
            route_options (Integer): Route command options.
            hops (List, optional, default=`None`): List of 16-bit addresses of
                intermediate hops in the source route (excluding source and
                destination).
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.CREATE_SOURCE_ROUTE, op_mode=op_mode)

        self._frame_id = frame_id
        self.__x64_addr = x64bit_addr
        self.__x16_addr = x16bit_addr
        self.__route_opts = route_options
        self.__hops = hops if hops else []

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.CreateSourceRoutePacket`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 18.
                (start delim. + length (2 bytes) + frame type + frame id +
                64-bit addr. + 16-bit addr. + Route command options
                + num of addrs + hops 16-bit addrs + checksum = 18 bytes).
            InvalidPacketException: If the length field of `raw` is different
                from its real length. (length field: bytes 1 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is not
                :attr:`.ApiFrameType.CREATE_SOURCE_ROUTE`.
            InvalidPacketException: If the number of hops does not match with
                the number of 16-bit addresses.
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
            raw, min_length=CreateSourceRoutePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.CREATE_SOURCE_ROUTE.code:
            raise InvalidPacketException(
                "This packet is not a Create Source Route packet.")

        hops = [XBee16BitAddress(raw[i:i+2]) for i in range(17, len(raw) - 1, 2)]

        if raw[16] != len(hops):
            raise InvalidPacketException("Specified number of hops does not"
                                         "match with the length of addresses.")

        return CreateSourceRoutePacket(
            raw[4], XBee64BitAddress(raw[5:13]), XBee16BitAddress(raw[13:15]),
            raw[15], hops, op_mode=operating_mode)

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
        ret = self.__x64_addr.address
        ret += self.__x16_addr.address
        ret.append(self.__route_opts)
        ret.append(len(self.__hops))
        for hop in self.__hops:
            ret += hop.address

        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        hops_array = [hop.address for hop in self.__hops]

        return {DictKeys.X64BIT_ADDR:       self.__x64_addr.address,
                DictKeys.X16BIT_ADDR:       self.__x16_addr.address,
                DictKeys.ROUTE_CMD_OPTIONS: self.__route_opts,
                DictKeys.NUM_OF_HOPS:       len(hops_array),
                DictKeys.HOPS:              hops_array}

    @property
    def x64bit_dest_addr(self):
        """
        Returns the 64-bit destination address.

        Returns:
            :class:`.XBee64BitAddress`: The 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64_addr

    @x64bit_dest_addr.setter
    def x64bit_dest_addr(self, x64bit_addr):
        """
        Sets the 64-bit destination address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): The new 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64_addr = x64bit_addr

    @property
    def x16bit_dest_addr(self):
        """
        Returns the 16-bit destination address.

        Returns:
            :class:`.XBee16BitAddress`: The 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16_addr

    @x16bit_dest_addr.setter
    def x16bit_dest_addr(self, x16bit_addr):
        """
        Sets the 16-bit destination address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): The new 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16_addr = x16bit_addr

    @property
    def route_cmd_options(self):
        """
        Returns the route command options bitfield.

        Returns:
            Integer: The route command options bitfield.
        """
        return self.__route_opts

    @route_cmd_options.setter
    def route_cmd_options(self, route_options):
        """
        Sets the route command options bitfield.

        Args:
            route_options (Integer): The new route command options bitfield.
        """
        self.__route_opts = route_options

    @property
    def number_of_hops(self):
        """
        Returns the number of intermediate hops in the source route (excluding
        source and destination).

        Returns:
            Integer: The number of intermediate hops.
        """
        return len(self.__hops)

    @property
    def hops(self):
        """
        Returns the list of intermediate hops starting from the closest to
        destination hop and finishing with the closest to the source (excluding
        source and destination).

        Returns:
            List: The list of 16-bit addresses of intermediate hops.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__hops

    @hops.setter
    def hops(self, hops):
        """
        Sets the hops of the route (excluding source and destination).

        Args:
            hops (List): List of `XBee16BitAddress`.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__hops = hops if hops else []


class OTAFirmwareUpdateStatusPacket(XBeeAPIPacket):
    """
    This class represents a an Over The Air Firmware Update Status packet.
    Packet is built using the parameters of the constructor or providing
    a valid API payload.

    This frame provides a status indication of a firmware update
    transmission.

    If a query request returns a 0x15 (NACK) status, the target is likely
    waiting for a firmware update image. If no messages are sent to it for
    about 75 seconds, the target will timeout and accept new query messages.

    If a query status returns a 0x51 (QUERY) status, then the target's
    bootloader is not active and will not respond to query messages.

    .. seealso::
       | :class:`.EmberBootloaderMessageType`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 26

    def __init__(self, src_address_64, updater_address_16, rx_options, msg_type,
                 block_number, target_address_64, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.OTAFirmwareUpdateStatusPacket` object with the
        provided parameters.

        Args:
            src_address_64 (:class:`.XBee64BitAddress`): the 64-bit address
                of the device returning this answer.
            updater_address_16 (:class:`.XBee16BitAddress`): the 16-bit address
                of the updater device.
            rx_options (Integer): bitfield indicating the receive options.
            msg_type (:class:`.EmberBootloaderMessageType`): Ember bootloader message type
            block_number (Integer): block number used in the update request.
            target_address_64 (:class:`.XBee64BitAddress`): the 64-bit address
                of the device that is being updated.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.ReceiveOptions`
           | :class:`.EmberBootloaderMessageType`
        """
        super().__init__(ApiFrameType.OTA_FIRMWARE_UPDATE_STATUS, op_mode=op_mode)
        self.__src_x64bit_addr = src_address_64
        self.__updater_x16bit_addr = updater_address_16
        self.__rx_opts = rx_options
        self.__msg_type = msg_type
        self.__block_number = block_number
        self.__target_x64bit_addr = target_address_64

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.OTAFirmwareUpdateStatusPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 17.
                (start delim. + length (2 bytes) + frame type
                + source 64bit addr. (8 bytes) + updater 16bit addr. (2 bytes)
                + receive options + bootloader message type + block number
                + source 64bit addr. (8 bytes) + checksum = 27 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 1 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.OTA_FIRMWARE_UPDATE_STATUS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(
                operating_mode.name + " is not supported.")

        XBeeAPIPacket._check_api_packet(
            raw, min_length=OTAFirmwareUpdateStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.OTA_FIRMWARE_UPDATE_STATUS.code:
            raise InvalidPacketException(
                "This packet is not an OTA Firmware Update Status packet.")

        return OTAFirmwareUpdateStatusPacket(
            XBee64BitAddress(raw[4:12]), XBee16BitAddress(raw[12:14]), raw[14],
            EmberBootloaderMessageType.get(raw[15]), raw[16], XBee64BitAddress(raw[17:25]),
            op_mode=operating_mode)

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
        raw = self.__src_x64bit_addr.address
        raw += self.__updater_x16bit_addr.address
        raw.append(self.__rx_opts & 0xFF)
        raw.append(self.__msg_type.code & 0xFF)
        raw.append(self.__block_number & 0xFF)
        raw += self.__target_x64bit_addr.address
        return raw

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.SRC_64BIT_ADDR:        self.__src_x64bit_addr.address,
                DictKeys.UPDATER_16BIT_ADDR:    self.__updater_x16bit_addr.address,
                DictKeys.RECEIVE_OPTIONS:       self.__rx_opts,
                DictKeys.BOOTLOADER_MSG_TYPE:   self.__msg_type,
                DictKeys.BLOCK_NUMBER:          self.__block_number,
                DictKeys.TARGET_64BIT_ADDR:     self.__target_x64bit_addr.address}

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__src_x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_source_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_source_addr (:class:`.XBee64BitAddress`): the new 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__src_x64bit_addr = x64bit_source_addr

    @property
    def x16bit_updater_addr(self):
        """
        Returns the 16-bit updater address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit updater address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__updater_x16bit_addr

    @x16bit_updater_addr.setter
    def x16bit_updater_addr(self, x16bit_updater_addr):
        """
        Sets the 16-bit updater address.

        Args:
            x16bit_updater_addr (:class:`.XBee16BitAddress`): the new 16-bit updater address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__updater_x16bit_addr = x16bit_updater_addr

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
    def bootloader_msg_type(self):
        """
        Returns the bootloader message type.

        Returns:
            :class:`.EmberBootloaderMessageType`: the bootloader message type.

        .. seealso::
           | :class:`.EmberBootloaderMessageType`
        """
        return self.__msg_type

    @bootloader_msg_type.setter
    def bootloader_msg_type(self, bootloader_message_type):
        """
        Sets the receive options bitfield.

        Args:
            bootloader_message_type (:class:`.EmberBootloaderMessageType`): the
                new bootloader message type.

        .. seealso::
           | :class:`.EmberBootloaderMessageType`
        """
        self.__msg_type = bootloader_message_type

    @property
    def block_number(self):
        """
        Returns the block number of the request.

        Returns:
            Integer: the block number of the request.
        """
        return self.__block_number

    @block_number.setter
    def block_number(self, block_number):
        """
        Sets the block number.

        Args:
            block_number (Integer): the new block number.
        """
        self.__block_number = block_number

    @property
    def x64bit_target_addr(self):
        """
        Returns the 64-bit target address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit target address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__target_x64bit_addr

    @x64bit_target_addr.setter
    def x64bit_target_addr(self, x64bit_target_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_target_addr (:class:`.XBee64BitAddress`): the new 64-bit target address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__target_x64bit_addr = x64bit_target_addr
