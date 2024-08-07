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

import re

from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import TransmitOptions
from digi.xbee.util import utils


PATTERN_PHONE_NUMBER = r"^\+?\d+$"
"""Pattern used to validate the phone number parameter of SMS packets."""


class RXSMSPacket(XBeeAPIPacket):
    """
    This class represents an RX (Receive) SMS packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    .. seealso::
       | :class:`.TXSMSPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 25

    def __init__(self, phone_number, data, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.RXSMSPacket` object with
        the provided parameters.

        Args:
            phone_number (String): Phone number of the device that sent the SMS.
            data (String or bytearray): Packet data (text of the SMS).
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if length of `phone_number` is greater than 20.
            ValueError: if `phone_number` is not a valid phone number.
        """
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")
        super().__init__(ApiFrameType.RX_SMS, op_mode=op_mode)

        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode(encoding="utf8")
        if isinstance(data, str):
            self.__data = data.encode('utf8', errors='ignore')
        else:
            self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RXSMSPacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 25.
                (start delim + length (2 bytes) + frame type
                + phone number (20 bytes) + checksum = 25 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different than
                :py:attr:`.ApiFrameType.RX_SMS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RXSMSPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_SMS.code:
            raise InvalidPacketException(message="This packet is not an RXSMSPacket")

        return RXSMSPacket(raw[4:23].decode(encoding="utf8").replace("\0", ""),
                           raw[24:-1], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def get_phone_number_byte_array(self):
        """
        Returns the phone number byte array.

        Returns:
            Bytearray: phone number of the device that sent the SMS.
        """
        return self.__phone_number

    @property
    def phone_number(self):
        """
        Returns the phone number of the device that sent the SMS.

        Returns:
            String: phone number of the device that sent the SMS.
        """
        return self.__phone_number.decode(encoding="utf8").replace("\0", "")

    @phone_number.setter
    def phone_number(self, phone_number):
        """
        Sets the phone number of the device that sent the SMS.

        Args:
            phone_number (String): the new phone number.

        Raises:
            ValueError: if length of `phone_number` is greater than 20.
            ValueError: if `phone_number` is not a valid phone number.
        """
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")

        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode(encoding="utf8")

    @property
    def data(self):
        """
        Returns the data of the packet (SMS text).

        Returns:
            String: the data of the packet.
        """
        return self.__data.decode(encoding='utf8', errors='ignore')

    @data.setter
    def data(self, data):
        """
        Sets the data of the packet.

        Args:
            data (String or bytearrray): New data of the packet.
        """
        if isinstance(data, str):
            self.__data = data.encode('utf8', errors='ignore')
        else:
            self.__data = data

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = bytearray()
        ret += self.__phone_number
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {DictKeys.PHONE_NUMBER: self.__phone_number,
                DictKeys.RF_DATA:      self.__data}


class TXSMSPacket(XBeeAPIPacket):
    """
    This class represents a TX (Transmit) SMS packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    .. seealso::
       | :class:`.RXSMSPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 27

    def __init__(self, frame_id, phone_number, data, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TXSMSPacket` object with
        the provided parameters.

        Args:
            frame_id (Integer): the frame ID. Must be between 0 and 255.
            phone_number (String): the phone number.
            data (String or bytearray): this packet's data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is not between 0 and 255.
            ValueError: if length of `phone_number` is greater than 20.
            ValueError: if `phone_number` is not a valid phone number.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255")
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")
        super().__init__(ApiFrameType.TX_SMS, op_mode=op_mode)

        self._frame_id = frame_id
        self.__tx_opts = TransmitOptions.NONE.value
        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode(encoding="utf8")
        if isinstance(data, str):
            self.__data = data.encode('utf8', errors='ignore')
        else:
            self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TXSMSPacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 27.
                (start delim, length (2 bytes), frame type, frame id,
                transmit options, phone number (20 bytes), checksum)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different than
                :py:attr:`.ApiFrameType.TX_SMS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TXSMSPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TX_SMS.code:
            raise InvalidPacketException(message="This packet is not a TXSMSPacket")

        data = None
        if len(raw) > TXSMSPacket.__MIN_PACKET_LENGTH:
            data = raw[26:-1]
        return TXSMSPacket(
            raw[4], raw[6:25].decode(encoding="utf8").replace("\0", ""), data)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def get_phone_number_byte_array(self):
        """
        Returns the phone number byte array.

        Returns:
            Bytearray: phone number of the device that sent the SMS.
        """
        return self.__phone_number

    @property
    def phone_number(self):
        """
        Returns the phone number of the transmitter device.

        Returns:
            String: the phone number of the transmitter device.
        """
        return self.__phone_number.decode(encoding="utf8").replace("\0", "")

    @phone_number.setter
    def phone_number(self, phone_number):
        """
        Sets the phone number of the transmitter device.

        Args:
            phone_number (String): the new phone number.

        Raises:
            ValueError: if length of `phone_number` is greater than 20.
            ValueError: if `phone_number` is not a valid phone number.
        """
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")

        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode(encoding="utf8")

    @property
    def data(self):
        """
        Returns the data of the packet (SMS text).

        Returns:
            Bytearray: packet's data.
        """
        return self.__data

    @data.setter
    def data(self, data):
        """
        Sets the data of the packet.

        Args:
            data (String or Bytearray): the new data of the packet.
        """
        if isinstance(data, str):
            self.__data = data.encode('utf8', errors='ignore')
        else:
            self.__data = data

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = utils.int_to_bytes(self.__tx_opts, num_bytes=1)
        ret += self.__phone_number
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {DictKeys.OPTIONS:      self.__tx_opts,
                DictKeys.PHONE_NUMBER: self.__phone_number,
                DictKeys.RF_DATA:      self.__data}
