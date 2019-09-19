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
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import XBeeLocalInterface
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException


class UserDataRelayPacket(XBeeAPIPacket):
    """
    This class represents a User Data Relay packet. Packet is built using the
    parameters of the constructor.

    The User Data Relay packet allows for data to come in on an interface with
    a designation of the target interface for the data to be output on.

    The destination interface must be one of the interfaces found in the
    corresponding enumerator (see :class:`.XBeeLocalInterface`).

    .. seealso::
       | :class:`.UserDataRelayOutputPacket`
       | :class:`.XBeeAPIPacket`
       | :class:`.XBeeLocalInterface`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, local_interface, data=None):
        """
        Class constructor. Instantiates a new :class:`.UserDataRelayPacket` object with the provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            local_interface (:class:`.XBeeLocalInterface`): the destination interface.
            data (Bytearray, optional): Data to send to the destination interface.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.XBeeLocalInterface`

        Raises:
            ValueError: if ``local_interface`` is ``None``.
            ValueError: if ``frame_id`` is less than 0 or greater than 255.
        """
        if local_interface is None:
            raise ValueError("Destination interface cannot be None")
        if frame_id > 255 or frame_id < 0:
            raise ValueError("frame_id must be between 0 and 255.")

        super().__init__(ApiFrameType.USER_DATA_RELAY_REQUEST)
        self._frame_id = frame_id
        self.__local_interface = local_interface
        self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.UserDataRelayPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 7. (start delim. + length (2 bytes) + frame
                type + frame id + relay interface + checksum = 7 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field: bytes
                2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is not :attr:`.ApiFrameType.USER_DATA_RELAY_REQUEST`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode != OperatingMode.ESCAPED_API_MODE and operating_mode != OperatingMode.API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=UserDataRelayPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.USER_DATA_RELAY_REQUEST.code:
            raise InvalidPacketException(message="This packet is not a user data relay packet.")

        return UserDataRelayPacket(raw[4], XBeeLocalInterface.get([5]), data=raw[6:-1])

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
        ret.append(self.__local_interface.code)
        if self.__data is not None:
            return ret + self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.DEST_INTERFACE: self.__local_interface.description,
                DictKeys.DATA:           list(self.__data) if self.__data is not None else None}

    def __get_data(self):
        """
        Returns the data to send.

        Returns:
            Bytearray: the data to send.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    def __set_data(self, data):
        """
        Sets the data to send.

        Args:
            data (Bytearray): the new data to send.
        """
        if data is None:
            self.__data = None
        else:
            self.__data = data.copy()

    def __get_dest_interface(self):
        """
        Returns the the destination interface.

        Returns:
            :class:`.XBeeLocalInterface`: the destination interface.

        .. seealso::
           | :class:`.XBeeLocalInterface`
        """
        return self.__local_interface

    def __set_dest_interface(self, local_interface):
        """
        Sets the destination interface.

        Args:
            local_interface (:class:`.XBeeLocalInterface`): the new destination interface.

        .. seealso::
           | :class:`.XBeeLocalInterface`
        """
        self.__local_interface = local_interface

    dest_interface = property(__get_dest_interface, __set_dest_interface)
    """:class:`.XBeeLocalInterface`. Destination local interface."""

    data = property(__get_data, __set_data)
    """Bytearray. Data to send."""


class UserDataRelayOutputPacket(XBeeAPIPacket):
    """
    This class represents a User Data Relay Output packet. Packet is built
    using the parameters of the constructor.

    The User Data Relay Output packet can be received from any relay interface.

    The source interface must be one of the interfaces found in the
    corresponding enumerator (see :class:`.XBeeLocalInterface`).

    .. seealso::
       | :class:`.UserDataRelayPacket`
       | :class:`.XBeeAPIPacket`
       | :class:`.XBeeLocalInterface`
    """

    __MIN_PACKET_LENGTH = 6

    def __init__(self, local_interface, data=None):
        """
        Class constructor. Instantiates a new
        :class:`.UserDataRelayOutputPacket` object with the provided
        parameters.

        Args:
            local_interface (:class:`.XBeeLocalInterface`): the source interface.
            data (Bytearray, optional): Data received from the source interface.

        Raises:
            ValueError: if ``local_interface`` is ``None``.

        .. seealso::
           | :class:`.XBeeAPIPacket`
           | :class:`.XBeeLocalInterface`
        """
        if local_interface is None:
            raise ValueError("Source interface cannot be None")

        super().__init__(ApiFrameType.USER_DATA_RELAY_OUTPUT)
        self.__local_interface = local_interface
        self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.UserDataRelayOutputPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 6. (start delim. + length (2 bytes) + frame
                type + relay interface + checksum = 6 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field: bytes
                2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is not :attr:`.ApiFrameType.USER_DATA_RELAY_OUTPUT`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode != OperatingMode.ESCAPED_API_MODE and operating_mode != OperatingMode.API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=UserDataRelayOutputPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.USER_DATA_RELAY_OUTPUT.code:
            raise InvalidPacketException(message="This packet is not a user data relay output packet.")

        return UserDataRelayOutputPacket(XBeeLocalInterface.get(raw[4]), data=raw[5:-1])

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
        ret.append(self.__local_interface.code)
        if self.__data is not None:
            return ret + self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.SOURCE_INTERFACE: self.__local_interface.description,
                DictKeys.DATA:             list(self.__data) if self.__data is not None else None}

    def __get_data(self):
        """
        Returns the received data.

        Returns:
            Bytearray: the received data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    def __set_data(self, data):
        """
        Sets the received data.

        Args:
            data (Bytearray): the new received data.
        """
        if data is None:
            self.__data = None
        else:
            self.__data = data.copy()

    def __get_src_interface(self):
        """
        Returns the the source interface.

        Returns:
            :class:`.XBeeLocalInterface`: the source interface.

        .. seealso::
           | :class:`.XBeeLocalInterface`
        """
        return self.__local_interface

    def __set_src_interface(self, local_interface):
        """
        Sets the source interface.

        Args:
            local_interface (:class:`.XBeeLocalInterface`): the new source interface.

        .. seealso::
           | :class:`.XBeeLocalInterface`
        """
        self.__local_interface = local_interface

    src_interface = property(__get_src_interface, __set_src_interface)
    """:class:`.XBeeLocalInterface`. Source local interface."""

    data = property(__get_data, __set_data)
    """Bytearray. Received data."""
