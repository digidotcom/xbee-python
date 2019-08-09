# Copyright 2017, 2018, Digi International Inc.
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
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import TransmitOptions
from digi.xbee.util import utils
import re


PATTERN_PHONE_NUMBER = "^\+?\d+$"
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

    def __init__(self, phone_number, data):
        """
        Class constructor. Instantiates a new :class:`.RXSMSPacket` object withe the provided parameters.
        
        Args:
            phone_number (String): phone number of the device that sent the SMS.
            data (String): packet data (text of the SMS).
            
        Raises:
            ValueError: if length of ``phone_number`` is greater than 20.
            ValueError: if ``phone_number`` is not a valid phone number.
        """
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")
        super().__init__(ApiFrameType.RX_SMS)

        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode("utf8")
        self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.
        
        Returns:
            :class:`.RXSMSPacket`
            
        Raises:
            InvalidPacketException: if the bytearray length is less than 25. (start delim + length (2 bytes) +
                frame type + phone number (20 bytes) + checksum = 25 bytes)
            InvalidPacketException: if the length field of ``raw`` is different than its real length. (length field:
                bytes 2 and 3)
            InvalidPacketException: if the first byte of ``raw`` is not the header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is different than :py:attr:`.ApiFrameType.RX_SMS`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.
            
        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode != OperatingMode.ESCAPED_API_MODE and operating_mode != OperatingMode.API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)
        
        XBeeAPIPacket._check_api_packet(raw, min_length=RXSMSPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RX_SMS.code:
            raise InvalidPacketException(message="This packet is not an RXSMSPacket")

        return RXSMSPacket(raw[4:23].decode("utf8").replace("\0", ""), raw[24:-1].decode("utf8"))

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

    def __get_phone_number(self):
        """
        Returns the phone number of the device that sent the SMS.

        Returns:
            String: phone number of the device that sent the SMS.
        """
        return self.__phone_number.decode("utf8").replace("\0", "")

    def __set_phone_number(self, phone_number):
        """
        Sets the phone number of the device that sent the SMS.

        Args:
            phone_number (String): the new phone number.

        Raises:
            ValueError: if length of ``phone_number`` is greater than 20.
            ValueError: if ``phone_number`` is not a valid phone number.
        """
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")

        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode("utf8")

    def __get_data(self):
        """
        Returns the data of the packet (SMS text).

        Returns:
            String: the data of the packet.
        """
        return self.__data

    def __set_data(self, data):
        """
        Sets the data of the packet.

        Args:
            data (String): the new data of the packet.
        """
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
            ret += self.__data.encode("utf8")
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {DictKeys.PHONE_NUMBER: self.__phone_number,
                DictKeys.RF_DATA:      self.__data}

    phone_number = property(__get_phone_number, __set_phone_number)
    """String. Phone number that sent the SMS."""

    data = property(__get_data, __set_data)
    """String. Data of the SMS."""


class TXSMSPacket(XBeeAPIPacket):
    """
    This class represents a TX (Transmit) SMS packet. Packet is built 
    using the parameters of the constructor or providing a valid byte array.
    
    .. seealso::
       | :class:`.RXSMSPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 27

    def __init__(self, frame_id, phone_number, data):
        """
        Class constructor. Instantiates a new :class:`.TXSMSPacket` object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID. Must be between 0 and 255.
            phone_number (String): the phone number.
            data (String): this packet's data.

        Raises:
            ValueError: if ``frame_id`` is not between 0 and 255.
            ValueError: if length of ``phone_number`` is greater than 20.
            ValueError: if ``phone_number`` is not a valid phone number.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255")
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")
        super().__init__(ApiFrameType.TX_SMS)
        
        self._frame_id = frame_id
        self.__transmit_options = TransmitOptions.NONE.value
        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode("utf8")
        self.__data = data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TXSMSPacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 27. (start delim, length (2 bytes), frame type,
                frame id, transmit options, phone number (20 bytes), checksum)
            InvalidPacketException: if the length field of ``raw`` is different than its real length. (length field:
                bytes 2 and 3)
            InvalidPacketException: if the first byte of ``raw`` is not the header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is different than :py:attr:`.ApiFrameType.TX_SMS`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode != OperatingMode.ESCAPED_API_MODE and operating_mode != OperatingMode.API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)
        
        XBeeAPIPacket._check_api_packet(raw, min_length=TXSMSPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TX_SMS.code:
            raise InvalidPacketException(message="This packet is not a TXSMSPacket")

        return TXSMSPacket(raw[4], raw[6:25].decode("utf8").replace("\0", ""), raw[26:-1].decode("utf8"))

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

    def __get_phone_number(self):
        """
        Returns the phone number of the transmitter device.

        Returns:
            String: the phone number of the transmitter device.
        """
        return self.__phone_number.decode("utf8").replace("\0", "")

    def __set_phone_number(self, phone_number):
        """
        Sets the phone number of the transmitter device.

        Args:
            phone_number (String): the new phone number.

        Raises:
            ValueError: if length of ``phone_number`` is greater than 20.
            ValueError: if ``phone_number`` is not a valid phone number.
        """
        if len(phone_number) > 20:
            raise ValueError("Phone number length cannot be greater than 20 bytes")
        if not re.match(PATTERN_PHONE_NUMBER, phone_number):
            raise ValueError("Phone number invalid, only numbers and '+' prefix allowed.")

        self.__phone_number = bytearray(20)
        self.__phone_number[0:len(phone_number)] = phone_number.encode("utf8")

    def __get_data(self):
        """
        Returns the data of the packet (SMS text).

        Returns:
            Bytearray: packet's data.
        """
        return self.__data

    def __set_data(self, data):
        """
        Sets the data of the packet.

        Args:
            data (Bytearray): the new data of the packet.
        """
        self.__data = data

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = utils.int_to_bytes(self.__transmit_options, num_bytes=1)
        ret += self.__phone_number
        if self.__data is not None:
            ret += self.__data.encode("utf8")
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {DictKeys.OPTIONS:      self.__transmit_options,
                DictKeys.PHONE_NUMBER: self.__phone_number,
                DictKeys.RF_DATA:      self.__data}

    phone_number = property(__get_phone_number, __set_phone_number)
    """String. Phone number that sent the SMS."""

    data = property(__get_data, __set_data)
    """String. Data of the SMS."""
