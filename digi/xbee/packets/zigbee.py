# Copyright 2019, Digi International Inc.
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
from digi.xbee.models.status import ZigbeeRegisterStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys


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

    def __init__(self, frame_id, registrant_address, options, key):
        """
        Class constructor. Instantiates a new :class:`.RegisterJoiningDevicePacket` object with the
        provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            registrant_address (:class:`.XBee64BitAddress`): the 64-bit address of the destination device.
            options (:class:`.RegisterKeyOptions`): the register options indicating the key source.
            key (Bytearray): key of the device to register. Up to 16 bytes if entering a Link Key or up to
                18 bytes (16-byte code + 2 byte CRC) if entering an Install Code.

        Raises:
            ValueError: if ``frame_id`` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
           | :class:`.RegisterKeyOptions`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.REGISTER_JOINING_DEVICE)
        self._frame_id = frame_id
        self.__registrant_address = registrant_address
        self.__options = options
        self.__key = key

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RegisterJoiningDevicePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 17. (start delim. + length (2 bytes) + frame
                type + frame id + 64-bit registrant addr. (8 bytes) + 16-bit registrant addr. (2 bytes) + options
                + checksum = 17 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field: bytes
                2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is not :attr:`.ApiFrameType.REGISTER_JOINING_DEVICE`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in [OperatingMode.ESCAPED_API_MODE, OperatingMode.API_MODE]:
            raise InvalidOperatingModeException(operating_mode.name + " is not supported.")

        XBeeAPIPacket._check_api_packet(raw, min_length=RegisterJoiningDevicePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REGISTER_JOINING_DEVICE.code:
            raise InvalidPacketException("This packet is not a Register Joining Device packet.")

        return RegisterJoiningDevicePacket(raw[4],
                                           XBee64BitAddress(raw[5:13]),
                                           RegisterKeyOptions.get(raw[15]),
                                           raw[16:-1])

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
        ret = self.__registrant_address.address
        ret += XBee16BitAddress.UNKNOWN_ADDRESS.address
        ret.append(self.__options.code)
        if self.__key is not None:
            ret += self.__key
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR: "%s (%s)" % (self.__registrant_address.packed,
                                                   self.__registrant_address.exploded),
                DictKeys.RESERVED:    XBee16BitAddress.UNKNOWN_ADDRESS.address,
                DictKeys.OPTIONS:     "%s (%s)" % (self.__options.code,
                                                   self.__options.description),
                DictKeys.KEY:         list(self.__key) if self.__key is not None else None}

    def __get_registrant_address(self):
        """
        Returns the 64-bit registrant address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit registrant address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__registrant_address

    def __set_registrant_address(self, registrant_address):
        """
        Sets the 64-bit registrant address.

        Args:
            registrant_address (:class:`.XBee64BitAddress`): The new 64-bit registrant address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        if registrant_address is not None:
            self.__registrant_address = registrant_address

    def __get_options(self):
        """
        Returns the register options value.

        Returns:
            :class:`.RegisterKeyOptions`: the register options indicating the key source.

        .. seealso::
           | :class:`.RegisterKeyOptions`
        """
        return self.__options

    def __set_options(self, options):
        """
        Sets the register options value.

        Args:
            options (:class:`.RegisterKeyOptions`): the new register options.

        .. seealso::
           | :class:`.RegisterKeyOptions`
        """
        self.__options = options

    def __get_key(self):
        """
        Returns the register key.

        Returns:
            Bytearray: the register key.
        """
        if self.__key is None:
            return None
        return self.__key.copy()

    def __set_key(self, key):
        """
        Sets the register key.

        Args:
            key (Bytearray): the new register key.
        """
        if key is None:
            self.__key = None
        else:
            self.__key = key.copy()

    registrant_address = property(__get_registrant_address, __set_registrant_address)
    """:class:`.XBee64BitAddress`. Registrant 64-bit address."""

    options = property(__get_options, __set_options)
    """:class:`.RegisterKeyOptions`. Register options."""

    key = property(__get_key, __set_key)
    """Bytearray. Register key."""


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

    def __init__(self, frame_id, status):
        """
        Class constructor. Instantiates a new :class:`.RegisterDeviceStatusPacket` object with the
        provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            status (:class:`.ZigbeeRegisterStatus`): status of the register device operation.

        Raises:
            ValueError: if ``frame_id`` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.ZigbeeRegisterStatus`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.REGISTER_JOINING_DEVICE_STATUS)
        self._frame_id = frame_id
        self.__status = status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RegisterDeviceStatusPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 17. (start delim. + length (2 bytes) + frame
                type + frame id + status + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field: bytes
                1 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is not :attr:`.ApiFrameType.REGISTER_JOINING_DEVICE_STATUS`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in [OperatingMode.ESCAPED_API_MODE, OperatingMode.API_MODE]:
            raise InvalidOperatingModeException(operating_mode.name + " is not supported.")

        XBeeAPIPacket._check_api_packet(raw, min_length=RegisterDeviceStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REGISTER_JOINING_DEVICE_STATUS.code:
            raise InvalidPacketException("This packet is not a Register Device Status packet.")

        return RegisterDeviceStatusPacket(raw[4], ZigbeeRegisterStatus.get(raw[5]))

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

    def __get_status(self):
        """
        Returns the register device status.

        Returns:
            :class:`.ZigbeeRegisterStatus`: the register device status.

        .. seealso::
           | :class:`.ZigbeeRegisterStatus`
        """
        return self.__status

    def __set_status(self, status):
        """
        Sets the register device status.

        Args:
            status (:class:`.ZigbeeRegisterStatus`): the new register device status.

        .. seealso::
           | :class:`.ZigbeeRegisterStatus`
        """
        self.__status = status

    status = property(__get_status, __set_status)
    """:class:`.ZigbeeRegisterStatus`. Register device status."""
