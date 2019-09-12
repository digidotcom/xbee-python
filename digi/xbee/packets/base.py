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

from abc import ABCMeta, abstractmethod
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.atcomm import SpecialByte
from digi.xbee.models.mode import OperatingMode
from digi.xbee.exception import InvalidPacketException, InvalidOperatingModeException
from digi.xbee.util import utils
from enum import Enum, unique


@unique
class DictKeys(Enum):
    """
    This enumeration contains all keys used in dictionaries returned by ``to_dict()``
    method of :class:`.XBeePacket`.
    """

    HEADER_BYTE = "header"
    LENGTH = "length"
    FRAME_TYPE = "fr_type"
    FRAME_ID = "fr_id"
    FRAME_SPEC_DATA = "fr_spec_data"
    API_DATA = "api_spec_data"
    RF_DATA = "rf_data"
    CHECKSUM = "checksum"
    COMMAND = "at_command"
    PARAMETER = "parameter"
    X64BIT_ADDR = "x64_addr"
    X16BIT_ADDR = "x16_addr"
    TRANSMIT_OPTIONS = "transmit_options"
    RECEIVE_OPTIONS = "receive_options"
    BROADCAST_RADIUS = "broadcast_radius"
    TRANS_R_COUNT = "transmit_retry_count"
    TS_STATUS = "ts_status"
    DS_STATUS = "ds_status"
    AT_CMD_STATUS = "at_command_status"
    MODEM_STATUS = "modem_status"
    NUM_SAMPLES = "num_samples"
    DIGITAL_MASK = "digital_mask"
    ANALOG_MASK = "analog_mask"
    RSSI = "rssi"
    SOURCE_ENDPOINT = "source_endpoint"
    DEST_ENDPOINT = "dest_endpoint"
    CLUSTER_ID = "cluster_id"
    PROFILE_ID = "profile_id"
    PHONE_NUMBER = "phone_number"
    DEST_IPV4_ADDR = "dest_ipv4_address"
    SRC_IPV4_ADDR = "source_ipv4_address"
    DEST_PORT = "dest_port"
    SRC_PORT = "source_port"
    IP_PROTOCOL = "ip_protocol"
    STATUS = "status"
    TRANSPORT = "transport"
    FLAGS = "flags"
    REQUEST_ID = "request_id"
    TARGET = "target"
    RESERVED = "reserved"
    DC_STATUS = "device_cloud_status"
    FRAME_ERROR = "frame_error"
    PATH_LENGTH = "path_length"
    PATH = "path"
    CONTENT_TYPE_LENGTH = "content_type_length"
    CONTENT_TYPE = "content_type"
    SOURCE_INTERFACE = "source_interface"
    DEST_INTERFACE = "dest_interface"
    DATA = "data"
    OPTIONS = "options"
    KEY = "key"
    SOCKET_ID = "socket_id"
    OPTION_ID = "option_id"
    OPTION_DATA = "option_data"
    DEST_ADDR_TYPE = "dest_address_type"
    DEST_ADDR = "dest_address"
    PAYLOAD = "payload"
    CLIENT_SOCKET_ID = "client_socket_id"
    REMOTE_ADDR = "remote_address"
    REMOTE_PORT = "remote_port"


class XBeePacket:
    """
    This abstract class represents the basic structure of an XBee packet.
 
    Derived classes should implement their own payload generation depending on their type.
    
    Generic actions like checksum compute or packet length calculation is performed here.
    """

    __HASH_SEED = 23

    __metaclass__ = ABCMeta
    __ESCAPE_BYTES = [i.value for i in SpecialByte]
    __ESCAPE_FACTOR = 0x20
    ESCAPE_BYTE = SpecialByte.ESCAPE_BYTE.code

    def __init__(self):
        """
        Class constructor. Instantiates a new :class:`.XBeePacket` object.
        """
        pass

    def __len__(self):
        """
        Returns the length value of the XBeePacket.
        
        The length is the number of bytes between the length field and the checksum field.
        
        Returns:
            Integer: length value of the XBeePacket.
            
        .. seealso::
           | :mod:`.factory`
        """
        return len(self.get_frame_spec_data())

    def __str__(self):
        """
        Returns the packet information as dictionary.
        
        Returns:
            Dictionary: the packet information.
        """
        return str(self.to_dict())

    def __eq__(self, other):
        """
        Returns whether the given object is equal to this one.

        Args:
            other: the object to compare.

        Returns:
            Boolean: ``True`` if the objects are equal, ``False`` otherwise.
        """
        if not isinstance(other, XBeePacket):
            return False
        return other.output() == self.output()

    def __hash__(self):
        """
        Returns a hash code value for the object.

        Returns:
            Integer: hash code value for the object.
        """
        res = self.__HASH_SEED
        for b in self.output():
            res = 31 * (res + b)
        return res

    def get_checksum(self):
        """
        Returns the checksum value of this XBeePacket.
        
        The checksum is the last 8 bits of the sum of the bytes between the length field and the checksum field.
        
        Returns:
            Integer: checksum value of this XBeePacket.
        
        .. seealso::
           | :mod:`.factory`
        """
        return 0xFF - (sum(self.get_frame_spec_data()) & 0xFF)

    def output(self, escaped=False):
        """
        Returns the raw bytearray of this XBeePacket, ready to be send by the serial port.
        
        Args:
            escaped (Boolean): indicates if the raw bytearray will be escaped or not.
        
        Returns:
            Bytearray: raw bytearray of the XBeePacket.
        """
        frame = self.__build_complete_frame_without_header(self.get_frame_spec_data())
        if escaped:
            frame = self._escape_data(frame)
        frame.insert(0, SpecialByte.HEADER_BYTE.code)
        return frame

    def to_dict(self):
        """
        Returns a dictionary with all information of the XBeePacket fields.
        
        Returns:
            Dictionary: dictionary with all information of the XBeePacket fields.
        """
        return {DictKeys.HEADER_BYTE:     SpecialByte.HEADER_BYTE.code,
                DictKeys.LENGTH:          len(self),
                DictKeys.FRAME_SPEC_DATA: self._get_frame_spec_data_dict(),
                DictKeys.CHECKSUM:        self.get_checksum()}

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Abstract method.
        Creates a full XBeePacket with the given parameters.
        This function ensures that the XBeePacket returned is valid and is well built (if not exceptions are raised).
        
        If _OPERATING_MODE is API2 (API escaped) this method des-escape 'raw' and build the XBeePacket.
        Then, you can use :meth:`.XBeePacket.output` to get the escaped bytearray or not escaped.
        
        Args:
            raw (Bytearray): bytearray with which the frame will be built. Must be a full frame
                represented by a bytearray.
            operating_mode (:class:`.OperatingMode`): The mode in which the frame ('byteArray') was captured.
            
        Returns:
            :class:`.XBeePacket`: the XBee packet created.
        
        Raises:
            InvalidPacketException: if something is wrong with ``raw`` and the packet cannot be built well.
        """
        raise NotImplementedError("Implement this function.")

    @abstractmethod
    def get_frame_spec_data(self):
        """
        Returns the data between the length field and the checksum field as bytearray.
        This data is never escaped.
        
        Returns:
            Bytearray: the data between the length field and the checksum field as bytearray.
        
        .. seealso::
           | :mod:`.factory`
        """
        pass

    @abstractmethod
    def _get_frame_spec_data_dict(self):
        """
        Similar to :meth:`.XBeePacket.get_frame_spec_data` but returns the data as dictionary.
        
        Returns:
            Dictionary: the data between the length field and the checksum field as bytearray.
        """
        pass

    @staticmethod
    def _escape_data(data):
        """
        Escapes the bytearray 'data'.

        Args:
            data (Bytearray): the bytearray to escape.

        Returns:
            Bytearray: 'data' escaped.
        """
        esc_data = bytearray()
        for i in data:
            if i in XBeePacket.__ESCAPE_BYTES:
                esc_data.append(SpecialByte.ESCAPE_BYTE.code)
                esc_data.append(i ^ XBeePacket.__ESCAPE_FACTOR)
            else:
                esc_data.append(i)
        return esc_data

    @staticmethod
    def unescape_data(data):
        """
        Un-escapes the provided bytearray data.

        Args:
            data (Bytearray): the bytearray to unescape.

        Returns:
            Bytearray: ``data`` unescaped.
        """
        new_data = bytearray(0)
        des_escape = False
        for byte in data:
            if byte == XBeePacket.ESCAPE_BYTE:
                des_escape = True
            else:
                new_data.append(byte ^ 0x20 if des_escape else byte)
                des_escape = False
        return new_data

    def __build_complete_frame_without_header(self, frame_spec_data):
        """
        Builds a complete non-escaped frame from the given frame specific data.
        Complete frame is: Start delimiter + length + frame specific data + checksum.
        
        Args:
            frame_spec_data (Bytearray): the frame specific data.
            
        Returns:
            Bytearray: the complete frame as bytearray.
        """
        frame = utils.int_to_length(len(frame_spec_data)) + frame_spec_data
        frame.append(self.get_checksum())
        return frame


class XBeeAPIPacket(XBeePacket):
    """
    This abstract class provides the basic structure of a API frame.
    
    Derived classes should implement their own methods to generate the API 
    data and frame ID in case they support it.
    
    Basic operations such as frame type retrieval are performed in this class.
    
    .. seealso::
       | :class:`.XBeePacket`
    """
    __metaclass__ = ABCMeta

    def __init__(self, api_frame_type):
        """
        Class constructor. Instantiates a new :class:`.XBeeAPIPacket` object with the provided parameters.
        
        Args:
            api_frame_type (:class:`.ApiFrameType` or Integer): The API frame type.

        .. seealso::
           | :class:`.ApiFrameType`
           | :class:`.XBeePacket`
        """
        super().__init__()
        # Check the type of the API frame type.
        if isinstance(api_frame_type, ApiFrameType):
            self._frame_type = api_frame_type
            self._frame_type_value = api_frame_type.code
        else:
            self._frame_type = ApiFrameType.get(api_frame_type)
            self._frame_type_value = api_frame_type
        self._frame_id = 0

    def get_frame_spec_data(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.XBeePacket.get_frame_spec_data`
        """
        data = self._get_api_packet_spec_data()
        if self.needs_id():
            data.insert(0, self._frame_id)
        data.insert(0, self._frame_type_value)
        return data

    def get_frame_type(self):
        """
        Returns the frame type of this packet.
        
        Returns:
            :class:`.ApiFrameType`: the frame type of this packet.

        .. seealso::
           | :class:`.ApiFrameType`
        """
        return self._frame_type

    def get_frame_type_value(self):
        """
        Returns the frame type integer value of this packet.

        Returns:
            Integer: the frame type integer value of this packet.

        .. seealso::
           | :class:`.ApiFrameType`
        """
        return self._frame_type_value

    def _get_frame_spec_data_dict(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.XBeePacket.get_frame_spec_data_dict`
        """
        return {DictKeys.FRAME_TYPE: self.get_frame_type(),
                DictKeys.FRAME_ID:   self._frame_id if self.needs_id() else "NO ID",
                DictKeys.API_DATA:   self._get_api_packet_spec_data_dict()}

    def is_broadcast(self):
        """
        Returns whether this packet is broadcast or not.
        
        Returns:
            Boolean: ``True`` if this packet is broadcast, ``False`` otherwise.
        """
        return False

    def __get_frame_id(self):
        """
        Returns the frame ID of the packet.

        Returns:
            Integer: the frame ID of the packet.
        """
        return self._frame_id

    def __set_frame_id(self, frame_id):
        """
        Sets the frame ID of the packet.

        Args:
            frame_id (Integer): the new frame ID of the packet. Must be between 0 and 255.

        Raises:
            ValueError: if ``frame_id`` is less than 0 or greater than 255.
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame ID must be between 0 and 255.")
        self._frame_id = frame_id

    @staticmethod
    def _check_api_packet(raw, min_length=5):
        """
        Checks the not escaped  bytearray 'raw' meets conditions.
        
        Args:
            raw (Bytearray): non-escaped bytearray to be checked.
            min_length (Integer): the minimum length of the packet in bytes.
            
        Raises:
            InvalidPacketException: if the bytearray length is less than 5. (start delim. + length (2 bytes) +
                frame type + checksum = 5 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field:
                bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
        
        .. seealso::
           | :mod:`.factory`
        """
        if len(raw) < min_length:
            raise InvalidPacketException(message="Bytearray must have, at least, 5 of complete length (header, length, "
                                         "frameType, checksum)")

        if raw[0] & 0xFF != SpecialByte.HEADER_BYTE.code:
            raise InvalidPacketException(message="Bytearray must start with the header byte (SpecialByte.HEADER_BYTE.code)")

        # real frame specific data length
        real_length = len(raw[3:-1])
        # length is specified in the length field.
        length_field = utils.length_to_int(raw[1:3])
        if real_length != length_field:
            raise InvalidPacketException(message="The real length of this frame is distinct than the specified by length "
                                         "field (bytes 2 and 3)")

        if 0xFF - (sum(raw[3:-1]) & 0xFF) != raw[-1]:
            raise InvalidPacketException(message="Wrong checksum")

    @abstractmethod
    def _get_api_packet_spec_data(self):
        """
        Returns the frame specific data without frame type and frame ID fields.
        
        Returns:
            Bytearray: the frame specific data without frame type and frame ID fields.
        """
        pass

    @abstractmethod
    def needs_id(self):
        """
        Returns whether the packet requires frame ID or not.
        
        Returns:
            Boolean: ``True`` if the packet needs frame ID, ``False`` otherwise.
        """
        pass

    @abstractmethod
    def _get_api_packet_spec_data_dict(self):
        """
        Similar to :meth:`XBeeAPIPacket._get_api_packet_spec_data` but returns data as dictionary or list.
        
        Returns:
            Dictionary: data as dictionary or list.
        """
        pass

    frame_id = property(__get_frame_id, __set_frame_id)


class GenericXBeePacket(XBeeAPIPacket):
    """
    This class represents a basic and Generic XBee packet.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 5

    def __init__(self, rf_data):
        """
        Class constructor. Instantiates a :class:`.GenericXBeePacket` object with the provided parameters.
        
        Args:
            rf_data (bytearray): the frame specific data without frame type and frame ID.
        
        .. seealso::
           | :mod:`.factory`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(api_frame_type=ApiFrameType.GENERIC)
        self.__rf_data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode=OperatingMode.API_MODE):
        """
        Override method.

        Returns:
            :class:`.GenericXBeePacket`: the GenericXBeePacket generated.
            
        Raises:
            InvalidPacketException: if the bytearray length is less than 5. (start delim. + length (2 bytes) +
                frame type + checksum = 5 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field: bytes
                2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidPacketException: if the frame type is different than :attr:`.ApiFrameType.GENERIC`.
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode != OperatingMode.ESCAPED_API_MODE and operating_mode != OperatingMode.API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=GenericXBeePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.GENERIC.code:
            raise InvalidPacketException(message="Wrong frame type, expected: " + ApiFrameType.GENERIC.description +
                                         ". Value: " + ApiFrameType.GENERIC.code)

        return GenericXBeePacket(raw[4:-1])

    def _get_api_packet_spec_data(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        return bytearray(self.__rf_data)

    def needs_id(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.RF_DATA: self.__rf_data}


class UnknownXBeePacket(XBeeAPIPacket):
    """
    This class represents an unknown XBee packet.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 5

    def __init__(self, api_frame, rf_data):
        """
        Class constructor. Instantiates a :class:`.UnknownXBeePacket` object with the provided parameters.

        Args:
            api_frame (Integer): the API frame integer value of this packet.
            rf_data (bytearray): the frame specific data without frame type and frame ID.

        .. seealso::
           | :mod:`.factory`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(api_frame_type=api_frame)
        self.__rf_data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode=OperatingMode.API_MODE):
        """
        Override method.

        Returns:
            :class:`.UnknownXBeePacket`: the UnknownXBeePacket generated.

        Raises:
            InvalidPacketException: if the bytearray length is less than 5. (start delim. + length (2 bytes) +
                frame type + checksum = 5 bytes).
            InvalidPacketException: if the length field of 'raw' is different than its real length. (length field: bytes
                2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different than the checksum field value (last byte).
            InvalidOperatingModeException: if ``operating_mode`` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode != OperatingMode.ESCAPED_API_MODE and operating_mode != OperatingMode.API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=UnknownXBeePacket.__MIN_PACKET_LENGTH)

        return UnknownXBeePacket(raw[3], raw[4:-1])

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        return bytearray(self.__rf_data)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.RF_DATA: self.__rf_data}
