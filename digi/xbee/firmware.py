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

import logging
import os
import re
import serial
import time

from abc import ABC, abstractmethod
from digi.xbee.exception import XBeeException, FirmwareUpdateException, TimeoutException
from digi.xbee.devices import AbstractXBeeDevice, RemoteXBeeDevice
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.models.status import TransmitStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ExplicitAddressingPacket, TransmitStatusPacket
from digi.xbee.serial import FlowControl
from digi.xbee.serial import XBeeSerialPort
from digi.xbee.util import utils
from digi.xbee.util import xmodem
from digi.xbee.util.xmodem import XModemException, XModemCancelException
from enum import Enum, unique
from pathlib import Path
from serial.serialutil import SerialException
from threading import Event
from threading import Thread
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

_BOOTLOADER_OPTION_RUN_FIRMWARE = "2"
_BOOTLOADER_OPTION_UPLOAD_GBL = "1"
_BOOTLOADER_PROMPT = "BL >"
_BOOTLOADER_PORT_PARAMETERS = {"baudrate": 115200,
                               "bytesize": serial.EIGHTBITS,
                               "parity": serial.PARITY_NONE,
                               "stopbits": serial.STOPBITS_ONE,
                               "xonxoff": False,
                               "dsrdtr": False,
                               "rtscts": False,
                               "timeout": 0.1,
                               "write_timeout": None,
                               "inter_byte_timeout": None
                               }
_BOOTLOADER_TEST_CHARACTER = "\n"
_BOOTLOADER_TIMEOUT = 60  # seconds
_BOOTLOADER_VERSION_SEPARATOR = "."
_BOOTLOADER_VERSION_SIZE = 3
_BOOTLOADER_XBEE3_FILE_PREFIX = "xb3-boot-rf_"

_BUFFER_SIZE_INT = 4
_BUFFER_SIZE_SHORT = 2
_BUFFER_SIZE_STRING = 32

_COMMAND_EXECUTE_RETRIES = 3

_READ_BUFFER_LEN = 256
_READ_DATA_TIMEOUT = 3  # Seconds.

_DEFAULT_RESPONSE_PACKET_PAYLOAD_SIZE = 5

_DEVICE_BREAK_RESET_TIMEOUT = 10  # seconds
_DEVICE_CONNECTION_RETRIES = 3

_ERROR_BOOTLOADER_MODE = "Could not enter in bootloader mode"
_ERROR_COMPATIBILITY_NUMBER = "Device compatibility number (%d) is greater than the firmware one (%d)"
_ERROR_CONNECT_DEVICE = "Could not connect with XBee device after %s retries"
_ERROR_CONNECT_SERIAL_PORT = "Could not connect with serial port: %s"
_ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR = "Unknown error"
_ERROR_DEVICE_PROGRAMMING_MODE = "Could not put XBee device into programming mode"
_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND = "Could not find XBee binary firmware file '%s'"
_ERROR_FILE_XML_FIRMWARE_NOT_FOUND = "XML firmware file does not exist"
_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED = "XML firmware file must be specified"
_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND = "Could not find bootloader binary firmware file '%s'"
_ERROR_FIRMWARE_START = "Could not start the new firmware"
_ERROR_FIRMWARE_UPDATE_BOOTLOADER = "Bootloader update error: %s"
_ERROR_FIRMWARE_UPDATE_XBEE = "XBee firmware update error: %s"
_ERROR_HARDWARE_VERSION_DIFFER = "Device hardware version (%d) differs from the firmware one (%d)"
_ERROR_HARDWARE_VERSION_NOT_SUPPORTED = "XBee hardware version (%d) does not support this firmware update process"
_ERROR_HARDWARE_VERSION_READ = "Could not read device hardware version"
_ERROR_INVALID_OTA_FILE = "Invalid OTA file: %s"
_ERROR_INVALID_BLOCK = "Requested block index '%s' does not exits"
_ERROR_LOCAL_DEVICE_INVALID = "Invalid local XBee device"
_ERROR_NOT_OTA_FILE = "File '%s' is not an OTA file"
_ERROR_PARSING_OTA_FILE = "Error parsing OTA file: %s"
_ERROR_READ_OTA_FILE = "Error reading OTA file: %s"
_ERROR_REGION_LOCK = "Device region (%d) differs from the firmware one (%d)"
_ERROR_REMOTE_DEVICE_INVALID = "Invalid remote XBee device"
_ERROR_RESTORE_TARGET_CONNECTION = "Could not restore target connection: %s"
_ERROR_RESTORE_UPDATER_DEVICE = "Error restoring updater device: %s"
_ERROR_SEND_IMAGE_NOTIFY = "Error sending 'Image notify' frame: %s"
_ERROR_SEND_OTA_BLOCK = "Error sending send OTA block '%s' frame: %s"
_ERROR_SEND_QUERY_NEXT_IMAGE_RESPONSE = "Error sending 'Query next image response' frame: %s"
_ERROR_SEND_UPGRADE_END_RESPONSE = "Error sending 'Upgrade end response' frame: %s"
_ERROR_TARGET_INVALID = "Invalid update target"
_ERROR_TRANSFER_OTA_FILE = "Error transferring OTA file: %s"
_ERROR_UPDATER_READ_PARAMETER = "Error reading updater '%s' parameter"
_ERROR_UPDATER_SET_PARAMETER = "Error setting updater '%s' parameter"
_ERROR_XML_PARSE = "Could not parse XML firmware file %s"
_ERROR_XMODEM_COMMUNICATION = "XModem serial port communication error: %s"
_ERROR_XMODEM_RESTART = "Could not restart firmware transfer sequence"
_ERROR_XMODEM_START = "Could not start XModem firmware upload process"

_EXPLICIT_PACKET_BROADCAST_RADIUS_MAX = 0x00
_EXPLICIT_PACKET_CLUSTER_ID = 0x0019
_EXPLICIT_PACKET_ENDPOINT_DATA = 0xE8
_EXPLICIT_PACKET_PROFILE_DIGI = 0xC105
_EXPLICIT_PACKET_EXTENDED_TIMEOUT = 0x40

_EXTENSION_GBL = ".gbl"
_EXTENSION_OTA = ".ota"
_EXTENSION_OTB = ".otb"

_IMAGE_BLOCK_REQUEST_PACKET_PAYLOAD_SIZE = 17

_NOTIFY_PACKET_DEFAULT_QUERY_JITTER = 0x64
_NOTIFY_PACKET_PAYLOAD_SIZE = 12
_NOTIFY_PACKET_PAYLOAD_TYPE = 0x03

_OTA_FILE_IDENTIFIER = 0x0BEEF11E
_OTA_DEFAULT_BLOCK_SIZE = 64
_OTA_GBL_SIZE_BYTE_COUNT = 6

_PACKET_DEFAULT_SEQ_NUMBER = 0x01

_PARAMETER_BOOTLOADER_VERSION = ATStringCommand.VH.command  # Answer examples: 01 81 -> 1.8.1  -  0F 3E -> 15.3.14
_PARAMETER_READ_RETRIES = 3
_PARAMETER_SET_RETRIES = 3

_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL = "^.*Gecko Bootloader.*\\(([0-9a-fA-F]{4})-([0-9a-fA-F]{2})(.*)\\).*$"
_PATTERN_GECKO_BOOTLOADER_VERSION = "^.*Gecko Bootloader v([0-9a-fA-F]{1}\\.[0-9a-fA-F]{1}\\.[0-9a-fA-F]{1}).*$"

_PROGRESS_TASK_UPDATE_BOOTLOADER = "Updating bootloader"
_PROGRESS_TASK_UPDATE_REMOTE_XBEE = "Updating remote XBee firmware"
_PROGRESS_TASK_UPDATE_XBEE = "Updating XBee firmware"

_REGION_ALL = 0

_REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT = 20  # Seconds

_SEND_BLOCK_RETRIES = 5

_TIME_DAYS_1970TO_2000 = 10957
_TIME_SECONDS_1970_TO_2000 = _TIME_DAYS_1970TO_2000 * 24 * 60 * 60

_UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE = 12

_VALUE_API_OUTPUT_MODE_EXPLICIT = 0x01
_VALUE_BAUDRATE_230400 = 0x08
_VALUE_BROADCAST_ADDRESS = bytearray([0xFF, 0xFF])
_VALUE_UNICAST_RETRIES_MEDIUM = 0x06

_XML_BOOTLOADER_VERSION = "firmware/bootloader_version"
_XML_COMPATIBILITY_NUMBER = "firmware/compatibility_number"
_XML_FIRMWARE = "firmware"
_XML_FIRMWARE_VERSION_ATTRIBUTE = "fw_version"
_XML_HARDWARE_VERSION = "firmware/hw_version"
_XML_REGION_LOCK = "firmware/region"
_XML_UPDATE_TIMEOUT = "firmware/update_timeout_ms"

_XMODEM_READY_TO_RECEIVE_CHAR = "C"
_XMODEM_START_TIMEOUT = 3  # seconds

_ZDO_COMMAND_ID_DEFAULT_RESP = 0x0B
_ZDO_COMMAND_ID_IMG_BLOCK_REQ = 0x03
_ZDO_COMMAND_ID_IMG_BLOCK_RESP = 0x05
_ZDO_COMMAND_ID_IMG_NOTIFY_REQ = 0x00
_ZDO_COMMAND_ID_QUERY_NEXT_IMG_REQ = 0x01
_ZDO_COMMAND_ID_QUERY_NEXT_IMG_RESP = 0x02
_ZDO_COMMAND_ID_UPGRADE_END_REQ = 0x06
_ZDO_COMMAND_ID_UPGRADE_END_RESP = 0x07

_ZDO_FRAME_CONTROL_CLIENT_TO_SERVER = 0x01
_ZDO_FRAME_CONTROL_GLOBAL = 0x00
_ZDO_FRAME_CONTROL_SERVER_TO_CLIENT = 0x09

_ZIGBEE_FW_VERSION_LIMIT_FOR_GBL = int("1003", 16)

SUPPORTED_HARDWARE_VERSIONS = (HardwareVersion.XBEE3.code,
                               HardwareVersion.XBEE3_SMT.code,
                               HardwareVersion.XBEE3_TH.code)

_log = logging.getLogger(__name__)


class _OTAFile(object):
    """
    Helper class that represents an OTA firmware file to be used in remote firmware updates.
    """

    def __init__(self, file_path):
        """
        Class constructor. Instantiates a new :class:`._OTAFile` with the given parameters.

        Args:
            file_path (String): the path of the OTA file.
        """
        self._file_path = file_path
        self._header_version = None
        self._header_length = None
        self._header_field_control = None
        self._manufacturer_code = None
        self._image_type = None
        self._file_version = None
        self._zigbee_stack_version = None
        self._header_string = None
        self._total_size = None
        self._gbl_size = None
        self._chunk_size = _OTA_DEFAULT_BLOCK_SIZE
        self._file_size = 0
        self._num_chunks = 0
        self._discard_size = 0
        self._file = None

    def parse_file(self):
        """
        Parses the OTA file and stores useful information of the file.

        Raises:
            _ParsingOTAException: if there is any problem parsing the OTA file.
        """
        _log.debug("Parsing OTA firmware file %s:" % self._file_path)
        if not _file_exists(self._file_path) or (not self._file_path.endswith(_EXTENSION_OTA) and
                                                 not self._file_path.endswith(_EXTENSION_OTB)):
            raise _ParsingOTAException(_ERROR_INVALID_OTA_FILE % self._file_path)

        try:
            with open(self._file_path, "rb") as file:
                identifier = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                if identifier != _OTA_FILE_IDENTIFIER:
                    raise _ParsingOTAException(_ERROR_NOT_OTA_FILE % self._file_path)
                _log.debug(" - Identifier: %d" % identifier)
                self._header_version = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header version: %d" % self._header_version)
                self._header_length = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header length: %d" % self._header_length)
                self._header_field_control = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header field control: %d" % self._header_field_control)
                self._manufacturer_code = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Manufacturer code: %d" % self._manufacturer_code)
                self._image_type = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Image type: %d" % self._image_type)
                self._file_version = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - File version: %d" % self._file_version)
                self._zigbee_stack_version = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Zigbee stack version: %d" % self._zigbee_stack_version)
                self._header_string = _reverse_bytearray(file.read(_BUFFER_SIZE_STRING)).decode(encoding="utf-8")
                _log.debug(" - Header string: %s" % self._header_string)
                self._total_size = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - Total size: %d" % self._total_size)
                self._gbl_size = self._total_size - self._header_length - _OTA_GBL_SIZE_BYTE_COUNT
                _log.debug(" - GBL size: %d" % self._gbl_size)
                self._file_size = os.path.getsize(self._file_path)
                _log.debug(" - File size: %d" % self._file_size)
                self._discard_size = self._header_length + _OTA_GBL_SIZE_BYTE_COUNT
                _log.debug(" - Discard size: %d" % self._discard_size)
                self._num_chunks = (self._file_size - self._discard_size) // self._chunk_size
                if (self._file_size - self._discard_size) % self._chunk_size:
                    self._num_chunks += 1
                _log.debug(" - Number of chunks: %d" % self._num_chunks)
        except IOError as e:
            raise _ParsingOTAException(_ERROR_PARSING_OTA_FILE % str(e))

    def get_next_data_chunk(self):
        """
        Returns the next data chunk of this file.

        Returns:
            Bytearray: the next data chunk of the file as byte array.

        Raises:
            _ParsingOTAException: if there is any error reading the OTA file.
        """
        try:
            if self._file is None:
                self._file = open(self._file_path, "rb")
                self._file.read(self._discard_size)

            return self._file.read(self._chunk_size)
        except IOError as e:
            self.close_file()
            raise _ParsingOTAException(str(e))

    def close_file(self):
        """
        Closes the file.
        """
        if self._file:
            self._file.close()

    @property
    def file_path(self):
        """
        Returns the OTA file path.

        Returns:
            String: the OTA file path.
        """
        return self._file_path

    @property
    def header_version(self):
        """
        Returns the OTA file header version.

        Returns:
            Integer: the OTA file header version.
        """
        return self._header_version

    @property
    def header_length(self):
        """
        Returns the OTA file header length.

        Returns:
            Integer: the OTA file header length.
        """
        return self._header_length

    @property
    def header_field_control(self):
        """
        Returns the OTA file header field control.

        Returns:
            Integer: the OTA file header field control.
        """
        return self._header_field_control

    @property
    def manufacturer_code(self):
        """
        Returns the OTA file manufacturer code.

        Returns:
            Integer: the OTA file manufacturer code.
        """
        return self._manufacturer_code

    @property
    def image_type(self):
        """
        Returns the OTA file image type.

        Returns:
            Integer: the OTA file image type.
        """
        return self._image_type

    @property
    def file_version(self):
        """
        Returns the OTA file version.

        Returns:
            Integer: the OTA file version.
        """
        return self._file_version

    @property
    def zigbee_stack_version(self):
        """
        Returns the OTA file zigbee stack version.

        Returns:
            Integer: the OTA file zigbee stack version.
        """
        return self._zigbee_stack_version

    @property
    def header_string(self):
        """
        Returns the OTA file header string.

        Returns:
            String: the OTA file header string.
        """
        return self._header_string

    @property
    def total_size(self):
        """
        Returns the OTA file total size.

        Returns:
            Integer: the OTA file total size.
        """
        return self._total_size

    @property
    def gbl_size(self):
        """
        Returns the OTA file gbl size.

        Returns:
            Integer: the OTA file gbl size.
        """
        return self._gbl_size

    @property
    def chunk_size(self):
        """
        Returns the chunk size.

        Returns:
            Integer: the chunk size.
        """
        return self._chunk_size

    @chunk_size.setter
    def chunk_size(self, chunk_size):
        """
        Sets the chunk size.

        Args:
            chunk_size (Integer): the new chunk size.
        """
        self._chunk_size = chunk_size
        self._num_chunks = (self._file_size - self._discard_size) // self._chunk_size
        if (self._file_size - self._discard_size) % self._chunk_size:
            self._num_chunks += 1

    @property
    def num_chunks(self):
        """
        Returns the total number of data chunks of this file.

        Returns:
            Integer: the total number of data chunks of this file.
        """
        return self._num_chunks


class _ParsingOTAException(Exception):
    """
    This exception will be thrown when any problem related with the parsing of OTA files occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


@unique
class _XBee3OTAStatus(Enum):
    """
    This class lists the available file XBee3 OTA status codes.

    | Inherited properties:
    |     **name** (String): The name of this _XBee3OTAStatus.
    |     **value** (Integer): The ID of this _XBee3OTAStatus.
    """
    SUCCESS = (0x00, "Success")
    ERASE_FAILED = (0x05, "Storage erase failed")
    NOT_AUTHORIZED = (0x7E, "Not authorized")
    MALFORMED_CMD = (0x80, "Malformed command")
    UNSUPPORTED_CMD = (0x81, "Unsupported cluster command")
    CONTACT_SUPPORT = (0x87, "Contact tech support")
    TIMED_OUT = (0x94, "Client timed out")
    ABORT = (0x95, "Client aborted upgrade")
    INVALID_IMG = (0x96, "Invalid OTA image")
    WAIT_FOR_DATA = (0x97, "Wait for data")
    NO_IMG_AVAILABLE = (0x98, "No image available")
    REQUIRE_MORE_IMG = (0x99, "Require more image")

    def __init__(self, identifier, description):
        self.__identifier = identifier
        self.__description = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _XBee3OTAStatus for the given identifier.

        Args:
            identifier (Integer): the identifier of the _XBee3OTAStatus to get.

        Returns:
            :class:`._XBee3OTAStatus`: the _XBee3OTAStatus with the given identifier, ``None`` if
                                       there is not a _XBee3OTAStatus with that name.
        """
        for value in _XBee3OTAStatus:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _XBee3OTAStatus element.

        Returns:
            Integer: the identifier of the _XBee3OTAStatus element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the command of the _XBee3OTAStatus element.

        Returns:
            String: the command of the _XBee3OTAStatus element.
        """
        return self.__description


@unique
class _XBeeZigbee3OTAStatus(Enum):
    """
    This class lists the available XBee3 Zigbee OTA status codes.

    | Inherited properties:
    |     **name** (String): The name of this _XBeeZigbee3OTAStatus.
    |     **value** (Integer): The ID of this _XBeeZigbee3OTAStatus.
    """
    SUCCESS = (0x00, "Success")
    ZCL_FAILURE = (0x01, "ZCL failure")
    NOT_AUTHORIZED = (0x7E, "Server is not authorized to upgrade the client")
    INVALID_FIRMWARE = (0x80, "Attempting to upgrade to invalid firmware (Bad Image Type, Wrong Mfg ID, Wrong HW/SW "
                              "compatibility)")
    UNSUPPORTED_CMD_CLUSTER = (0x81, "Such command is not supported on the device cluster")
    UNSUPPORTED_CMD_GENERAL = (0x82, "Such command is not a supported general command")
    UNSUPPORTED_CMD_MFG_CLUSTER = (0x83, "Such command is not a manufacturer cluster supported command")
    UNSUPPORTED_CMD_MFG_GENERAL = (0x84, "Such command is not a manufacturer general supported command")
    INVALID_FIELD = (0x85, "Invalid field")
    UNSUPPORTED_ATTRIBUTE = (0x86, "Unsupported attribute")
    INVALID_VALUE = (0x87, "Invalid value")
    READ_ONLY_CMD = (0x88, "Read only command")
    INSUFFICIENT_SPACE = (0x89, "Insufficient space")
    DUPLICATE_EXISTS = (0x8A, "Duplicate exists")
    NOT_FOUND = (0x8B, "Not found")
    UNREPORTABLE_ATTRIBUTE = (0x8C, "Unreportable attribute")
    INVALID_DATA_TYPE = (0x8D, "Invalid data type")
    ABORT = (0x95, "Client aborted upgrade")
    INVALID_IMG = (0x96, "Invalid OTA image")
    NO_DATA_AVAILABLE = (0x97, "Server does not have data block available yet")
    NO_IMG_AVAILABLE = (0x98, "No OTA upgrade image available for a particular client")
    REQUIRE_MORE_IMG = (0x99, "The client still requires more OTA upgrade image files in order to successfully upgrade")
    HARDWARE_FAILURE = (0xC0, "Hardware failure")
    SOFTWARE_FAILURE = (0xC1, "Software failure")
    CALIBRATION_ERROR = (0xC2, "Calibration error")

    def __init__(self, identifier, description):
        self.__identifier = identifier
        self.__description = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _XBeeZigbee3OTAStatus for the given identifier.

        Args:
            identifier (Integer): the identifier of the _XBeeZigbee3OTAStatus to get.

        Returns:
            :class:`._XBeeZigbee3OTAStatus`: the _XBeeZigbee3OTAStatus with the given identifier, ``None`` if
                                             there is not a _XBeeZigbee3OTAStatus with that name.
        """
        for value in _XBeeZigbee3OTAStatus:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _XBee3OTAStatus element.

        Returns:
            Integer: the identifier of the _XBee3OTAStatus element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the command of the _XBee3OTAStatus element.

        Returns:
            String: the command of the _XBee3OTAStatus element.
        """
        return self.__description


@unique
class _NextImageMessageStatus(Enum):
    """
    This class lists the available XBee3 OTA next image message status codes.

    | Inherited properties:
    |     **name** (String): The name of this _NextImageMessageStatus.
    |     **value** (Integer): The ID of this _NextImageMessageStatus.
    """
    OUT_OF_SEQUENCE = (0x01, "ZCL OTA Message Out of Sequence")
    INCORRECT_FORMAT = (0x80, "Incorrect Query Next Image Response Format")
    INVALID_FIRMWARE = (0x85, "Attempting to upgrade to invalid firmware")
    FILE_TOO_BIG = (0x89, "Image size is too big")
    SAME_FILE = (0x8A, "Please ensure that the image you are attempting to upgrade has a different version than the "
                       "current version")

    def __init__(self, identifier, description):
        self.__identifier = identifier
        self.__description = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _NextImageMessageStatus for the given identifier.

        Args:
            identifier (Integer): the identifier of the _NextImageMessageStatus to get.

        Returns:
            :class:`._NextImageMessageStatus`: the _NextImageMessageStatus with the given identifier, ``None`` if
                                               there is not a _NextImageMessageStatus with that name.
        """
        for value in _NextImageMessageStatus:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _NextImageMessageStatus element.

        Returns:
            Integer: the identifier of the _NextImageMessageStatus element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the command of the _NextImageMessageStatus element.

        Returns:
            String: the command of the _NextImageMessageStatus element.
        """
        return self.__description


@unique
class _ImageBlockMessageStatus(Enum):
    """
    This class lists the available XBee3 OTA image block message status codes.

    | Inherited properties:
    |     **name** (String): The name of this _ImageBlockMessageStatus.
    |     **value** (Integer): The ID of this _ImageBlockMessageStatus.
    """
    OUT_OF_SEQUENCE = (0x01, "ZCL OTA Message Out of Sequence")
    INCORRECT_FORMAT = (0x80, "Incorrect Image Block Response Format")
    FILE_MISMATCH = (0x87, "Upgrade File Mismatch")

    def __init__(self, identifier, description):
        self.__identifier = identifier
        self.__description = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _ImageBlockMessageStatus for the given identifier.

        Args:
            identifier (Integer): the identifier of the _ImageBlockMessageStatus to get.

        Returns:
            :class:`._ImageBlockMessageStatus`: the _ImageBlockMessageStatus with the given identifier, ``None`` if
                                                there is not a _ImageBlockMessageStatus with that name.
        """
        for value in _ImageBlockMessageStatus:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _ImageBlockMessageStatus element.

        Returns:
            Integer: the identifier of the _ImageBlockMessageStatus element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the command of the _ImageBlockMessageStatus element.

        Returns:
            String: the command of the _ImageBlockMessageStatus element.
        """
        return self.__description


@unique
class _UpgradeEndMessageStatus(Enum):
    """
    This class lists the available XBee3 OTA upgrade end message status codes.

    | Inherited properties:
    |     **name** (String): The name of this _UpgradeEndMessageStatus.
    |     **value** (Integer): The ID of this _UpgradeEndMessageStatus.
    """
    WRONG_FILE = (0x87, "Wrong upgrade file")

    def __init__(self, identifier, description):
        self.__identifier = identifier
        self.__description = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _UpgradeEndMessageStatus for the given identifier.

        Args:
            identifier (Integer): the identifier of the _UpgradeEndMessageStatus to get.

        Returns:
            :class:`._UpgradeEndMessageStatus`: the _UpgradeEndMessageStatus with the given identifier, ``None`` if
                                                there is not a _UpgradeEndMessageStatus with that name.
        """
        for value in _UpgradeEndMessageStatus:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _UpgradeEndMessageStatus element.

        Returns:
            Integer: the identifier of the _UpgradeEndMessageStatus element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the command of the _UpgradeEndMessageStatus element.

        Returns:
            String: the command of the _UpgradeEndMessageStatus element.
        """
        return self.__description


class _BreakThread(Thread):
    """
    Helper class used to manage serial port break line in a parallel thread.
    """

    _break_running = False

    def __init__(self, serial_port, duration):
        """
        Class constructor. Instantiates a new :class:`._BreakThread` with the given parameters.

        Args:
            serial_port (:class:`.XBeeSerialPort`): The serial port to send the break signal to.
            duration (Integer): the duration of the break in seconds.
        """
        super().__init__()
        self._xbee_serial_port = serial_port
        self.duration = duration
        self.lock = Event()

    def run(self):
        """
        Override method.
        .. seealso::
           | :meth:`.Thread.run`
        """
        if self._xbee_serial_port is None or _BreakThread.is_running():
            return

        _log.debug("Break thread started")
        _BreakThread._break_running = True
        self._xbee_serial_port.break_condition = True
        self.lock.wait(self.duration)
        self._xbee_serial_port.break_condition = False
        _BreakThread._break_running = False
        _log.debug("Break thread finished")

    def stop_break(self):
        """
        Stops the break thread.
        """
        if not self.is_running:
            return

        self.lock.set()
        # Wait until thread finishes.
        self.join()

    @staticmethod
    def is_running():
        """
        Returns whether the break thread is running or not.

        Returns:
            Boolean: ``True`` if the break thread is running, ``False`` otherwise.
        """
        return _BreakThread._break_running


class _XBeeFirmwareUpdater(ABC):
    """
    Helper class used to handle XBee firmware update processes.
    """

    def __init__(self, xml_firmware_file, timeout=_READ_DATA_TIMEOUT, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._XBeeFirmwareUpdater` with the given parameters.

        Args:
            xml_firmware_file (String): location of the XML firmware file.
            timeout (Integer, optional): the process operations timeout.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        self._xml_firmware_file = xml_firmware_file
        self._progress_callback = progress_callback
        self._progress_task = None
        self._xml_hardware_version = None
        self._xml_compatibility_number = None
        self._xml_bootloader_version = None
        self._xml_region_lock = None
        self._xml_update_timeout_ms = None
        self._bootloader_update_required = False
        self._timeout = timeout

    def _parse_xml_firmware_file(self):
        """
        Parses the XML firmware file and stores the required parameters.

        Raises:
            FirmwareUpdateException: if there is any error parsing the XML firmware file.
        """
        _log.debug("Parsing XML firmware file %s:" % self._xml_firmware_file)
        try:
            root = ElementTree.parse(self._xml_firmware_file).getroot()
            # Firmware version, required.
            element = root.find(_XML_FIRMWARE)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_firmware_version = int(element.get(_XML_FIRMWARE_VERSION_ATTRIBUTE), 16)
            _log.debug(" - Firmware version: %d" % self._xml_firmware_version)
            # Hardware version, required.
            element = root.find(_XML_HARDWARE_VERSION)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_hardware_version = int(element.text, 16)
            _log.debug(" - Hardware version: %d" % self._xml_hardware_version)
            # Compatibility number, required.
            element = root.find(_XML_COMPATIBILITY_NUMBER)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_compatibility_number = int(element.text)
            _log.debug(" - Compatibility number: %d" % self._xml_compatibility_number)
            # Bootloader version, optional.
            element = root.find(_XML_BOOTLOADER_VERSION)
            if element is not None:
                self._xml_bootloader_version = _bootloader_version_to_bytearray(element.text)
            _log.debug(" - Bootloader version: %s" % self._xml_bootloader_version)
            # Region lock, required.
            element = root.find(_XML_REGION_LOCK)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_region_lock = int(element.text)
            _log.debug(" - Region lock: %d" % self._xml_region_lock)
            # Update timeout, optional.
            element = root.find(_XML_UPDATE_TIMEOUT)
            if element is not None:
                self._xml_update_timeout_ms = int(element.text)
            _log.debug(" - Update timeout: %s" % self._xml_update_timeout_ms)
        except ParseError as e:
            _log.exception(e)
            self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)

    def _exit_with_error(self, message, restore_updater=True):
        """
        Finishes the process raising a :class`.FirmwareUpdateException` and leaves updater in the initial state.

        Args:
            message (String): the error message of the exception to raise.
            restore_updater (Boolean): ``True`` to restore updater configuration before exiting, ``False`` otherwise.

        Raises:
            FirmwareUpdateException: the exception is always thrown in this method.
        """
        # Check if updater restore is required.
        if restore_updater:
            try:
                self._restore_updater()
            except (SerialException, XBeeException) as e:
                _log.error("ERROR: %s" % (_ERROR_RESTORE_TARGET_CONNECTION % str(e)))
        _log.error("ERROR: %s" % message)
        raise FirmwareUpdateException(message)

    def _check_target_compatibility(self):
        """
        Checks whether the target device is compatible with the firmware to update by checking:
            - Bootloader version.
            - Compatibility number.
            - Region lock.
            - Hardware version.

        Raises:
            FirmwareUpdateException: if the target device is not compatible with the firmware to update.
        """
        # At the moment the target checks are the same for local and remote updates since only XBee3 devices
        # are supported. This might need to be changed in the future if other hardware is supported.

        # Read device values required for verification steps prior to firmware update.
        _log.debug("Reading device settings:")
        self._target_firmware_version = self._get_target_firmware_version()
        _log.debug(" - Firmware version: %s" % self._target_firmware_version)
        self._target_hardware_version = self._get_target_hardware_version()
        if self._target_hardware_version is None:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_READ)
        _log.debug(" - Hardware version: %s" % self._target_hardware_version)
        self._target_compatibility_number = self._get_target_compatibility_number()
        _log.debug(" - Compatibility number: %s" % self._target_compatibility_number)
        self._target_bootloader_version = self._get_target_bootloader_version()
        _log.debug(" - Bootloader version: %s" % self._target_bootloader_version)
        self._target_region_lock = self._get_target_region_lock()
        _log.debug(" - Region lock: %s" % self._target_region_lock)

        # Check if the hardware version is compatible with the firmware update process.
        if self._target_hardware_version not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

        # Check if device hardware version is compatible with the firmware.
        if self._target_hardware_version != self._xml_hardware_version:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_DIFFER % (self._target_hardware_version,
                                                                    self._xml_hardware_version))

        # Check compatibility number.
        if self._target_compatibility_number and self._target_compatibility_number > \
                self._xml_compatibility_number:
            self._exit_with_error(_ERROR_COMPATIBILITY_NUMBER % (self._target_compatibility_number,
                                                                 self._xml_compatibility_number))

        # Check region lock for compatibility numbers greater than 1.
        if self._target_compatibility_number and self._target_compatibility_number > 1 and \
                self._target_region_lock is not None:
            if self._target_region_lock != _REGION_ALL and self._target_region_lock != self._xml_region_lock:
                self._exit_with_error(_ERROR_REGION_LOCK % (self._target_region_lock, self._xml_region_lock))

        # Check whether bootloader update is required.
        self._bootloader_update_required = self._check_bootloader_update_required()

    def _check_bootloader_update_required(self):
        """
        Checks whether the bootloader needs to be updated or not

        Returns:
            Boolean: ``True`` if the bootloader needs to be updated, ``False`` otherwise
        """
        # If any bootloader version is None (the XML firmware file one or the device one), update is not required.
        if None in (self._xml_bootloader_version, self._target_bootloader_version):
            return False

        # At this point we can ensure both bootloader versions are not None and they are 3 bytes long.
        # Since the bootloader cannot be downgraded, the XML specifies the minimum required bootloader
        # version to update the firmware. Return `True` only if the specified XML bootloader version is
        # greater than the target one.
        for i in range(len(self._xml_bootloader_version)):
            if self._xml_bootloader_version[i] != self._target_bootloader_version[i]:
                return self._xml_bootloader_version[i] > self._target_bootloader_version[i]

        return False

    @abstractmethod
    def _get_default_reset_timeout(self):
        """
        Returns the default timeout to wait for reset.
        """
        pass

    def _wait_for_target_reset(self):
        """
        Waits for the device to reset using the xml firmware file specified timeout or the default one.
        """
        if self._xml_update_timeout_ms is not None:
            time.sleep(self._xml_update_timeout_ms / 1000.0)
        else:
            time.sleep(self._get_default_reset_timeout())

    def update_firmware(self):
        """
        Updates the firmware of the XBee device.
        """
        # Start by parsing the XML firmware file.
        self._parse_xml_firmware_file()

        # Verify that the binary firmware file exists.
        self._check_firmware_binary_file()

        # Configure the updater device.
        self._configure_updater()

        # Check if updater is able to perform firmware updates.
        self._check_updater_compatibility()

        # Check if target is compatible with the firmware to update.
        self._check_target_compatibility()

        # Check bootloader update file exists if required.
        _log.debug("Bootloader update required? %s" % self._bootloader_update_required)
        if self._bootloader_update_required:
            self._check_bootloader_binary_file()

        # Start the firmware update process.
        self._start_firmware_update()

        # Transfer firmware file(s).
        self._transfer_firmware()

        # Finish the firmware update process.
        self._finish_firmware_update()

        # Leave updater in its original state.
        try:
            self._restore_updater()
        except Exception as e:
            raise FirmwareUpdateException(_ERROR_RESTORE_TARGET_CONNECTION % str(e))

        # Wait for target to reset.
        self._wait_for_target_reset()

        _log.info("Update process finished successfully")

    @abstractmethod
    def _check_updater_compatibility(self):
        """
        Verifies whether the updater device is compatible with firmware update or not.
        """
        pass

    @abstractmethod
    def _check_firmware_binary_file(self):
        """
        Verifies that the firmware binary file exists.
        """
        pass

    @abstractmethod
    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.
        """
        pass

    @abstractmethod
    def _get_target_bootloader_version(self):
        """
        Returns the update target bootloader version.

        Returns:
            Bytearray: the update target version as byte array, ``None`` if it could not be read.
        """
        pass

    @abstractmethod
    def _get_target_compatibility_number(self):
        """
        Returns the update target compatibility number.

        Returns:
            Integer: the update target compatibility number as integer, ``None`` if it could not be read.
        """
        pass

    @abstractmethod
    def _get_target_region_lock(self):
        """
        Returns the update target region lock number.

        Returns:
            Integer: the update target region lock number as integer, ``None`` if it could not be read.
        """
        pass

    @abstractmethod
    def _get_target_hardware_version(self):
        """
        Returns the update target hardware version.

        Returns:
            Integer: the update target hardware version as integer, ``None`` if it could not be read.
        """
        pass

    @abstractmethod
    def _get_target_firmware_version(self):
        """
        Returns the update target firmware version.

        Returns:
            Integer: the update target firmware version as integer, ``None`` if it could not be read.
        """
        pass

    @abstractmethod
    def _configure_updater(self):
        """
        Configures the updater device before performing the firmware update operation.
        """
        pass

    @abstractmethod
    def _restore_updater(self):
        """
        Leaves the updater device to its original state before the update operation.
        """
        pass

    @abstractmethod
    def _start_firmware_update(self):
        """
        Starts the firmware update process. Called just before the transfer firmware operation.
        """
        pass

    @abstractmethod
    def _transfer_firmware(self):
        """
        Transfers the firmware file(s) to the target.
        """
        pass

    @abstractmethod
    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer firmware operation.
        """
        pass


class _LocalFirmwareUpdater(_XBeeFirmwareUpdater):
    """
    Helper class used to handle the local firmware update process.
    """

    __DEVICE_RESET_TIMEOUT = 3  # seconds

    def __init__(self, target, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                 timeout=_READ_DATA_TIMEOUT, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._LocalFirmwareUpdater` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: the XBee device to upload its firmware.
            xml_firmware_file (String): location of the XML firmware file.
            xbee_firmware_file (String, optional): location of the XBee binary firmware file.
            bootloader_firmware_file (String, optional): location of the bootloader binary firmware file.
            timeout (Integer, optional): the serial port read data operation timeout.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super(_LocalFirmwareUpdater, self).__init__(xml_firmware_file, timeout=timeout,
                                                    progress_callback=progress_callback)

        self._xbee_firmware_file = xbee_firmware_file
        self._bootloader_firmware_file = bootloader_firmware_file
        self._xbee_serial_port = None
        self._device_port_params = None
        self._updater_was_connected = False
        if isinstance(target, str):
            self._port = target
            self._xbee_device = None
        else:
            self._port = None
            self._xbee_device = target

    def _check_firmware_binary_file(self):
        """
        Verifies that the firmware binary file exists.

        Raises:
            FirmwareUpdateException: if the firmware binary file does not exist or is invalid.
        """
        # If not already specified, the binary firmware file is usually in the same folder as the XML firmware file.
        if self._xbee_firmware_file is None:
            path = Path(self._xml_firmware_file)
            self._xbee_firmware_file = str(Path(path.parent).joinpath(path.stem + _EXTENSION_GBL))

        if not _file_exists(self._xbee_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._xbee_firmware_file, restore_updater=False)

    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.

        Raises:
            FirmwareUpdateException: if the bootloader binary file does not exist or is invalid.
        """
        # If not already specified, the bootloader firmware file is usually in the same folder as the XML firmware file.
        # The file filename starts with a fixed prefix and includes the bootloader version to update to.
        if self._bootloader_firmware_file is None:
            path = Path(self._xml_firmware_file)
            self._bootloader_firmware_file = str(Path(path.parent).joinpath(_BOOTLOADER_XBEE3_FILE_PREFIX +
                                                                            str(self._xml_bootloader_version[0]) +
                                                                            _BOOTLOADER_VERSION_SEPARATOR +
                                                                            str(self._xml_bootloader_version[1]) +
                                                                            _BOOTLOADER_VERSION_SEPARATOR +
                                                                            str(self._xml_bootloader_version[2]) +
                                                                            _EXTENSION_GBL))

        if not _file_exists(self._bootloader_firmware_file):
            self._exit_with_error(_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND % self._bootloader_firmware_file)

    def _is_bootloader_active(self):
        """
        Returns whether the device is in bootloader mode or not.

        Returns:
            Boolean: ``True`` if the device is in bootloader mode, ``False`` otherwise.
        """
        for i in range(3):
            bootloader_header = self._read_bootloader_header()
            # Look for the Ember/Gecko bootloader prompt.
            if bootloader_header is not None and _BOOTLOADER_PROMPT in bootloader_header:
                return True
            time.sleep(0.2)

        return False

    def _read_bootloader_header(self):
        """
        Attempts to read the bootloader header.

        Returns:
            String: the bootloader header, ``None`` if it could not be read.
        """
        try:
            self._xbee_serial_port.purge_port()
            self._xbee_serial_port.write(str.encode(_BOOTLOADER_TEST_CHARACTER))
            read_bytes = self._xbee_serial_port.read(_READ_BUFFER_LEN)
        except SerialException as e:
            _log.exception(e)
            return None

        if len(read_bytes) > 0:
            try:
                return bytes.decode(read_bytes)
            except UnicodeDecodeError:
                pass

        return None

    def _enter_bootloader_mode_with_break(self):
        """
        Attempts to put the device in bootloader mode using the Break line.

        Returns:
            Boolean: ``True`` if the device was set in bootloader mode, ``False`` otherwise.
        """
        _log.debug("Setting device in bootloader mode using the Break line")
        # The process requires RTS line to be disabled and Break line to be asserted during some time.
        self._xbee_serial_port.rts = 0
        break_thread = _BreakThread(self._xbee_serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
        break_thread.start()
        # Loop during some time looking for the bootloader header.
        deadline = _get_milliseconds() + (_BOOTLOADER_TIMEOUT * 1000)
        while _get_milliseconds() < deadline:
            if self._is_bootloader_active():
                if break_thread.is_running():
                    break_thread.stop_break()
                return True

            # Re-assert lines to try break process again until timeout expires.
            if not break_thread.is_running():
                self._xbee_serial_port.rts = 0
                break_thread = _BreakThread(self._xbee_serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
                break_thread.start()

        # Restore break condition.
        if break_thread.is_running():
            break_thread.stop_break()

        return False

    def _get_target_bootloader_version(self):
        """
        Returns the update target bootloader version.

        Returns:
            Bytearray: the update target bootloader version as byte array, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_VERSION, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
                return None

            return _bootloader_version_to_bytearray(result.groups()[0])
        else:
            return _read_device_bootloader_version(self._xbee_device)

    def _get_target_compatibility_number(self):
        """
        Returns the update target compatibility number.

        Returns:
            Integer: the update target compatibility number as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            # Assume the device is already in bootloader mode.
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 2:
                return None

            return int(result.groups()[1])
        else:
            return _read_device_compatibility_number(self._xbee_device)

    def _get_target_region_lock(self):
        """
        Returns the update target region lock number.

        Returns:
            Integer: the update target region lock number as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            # There is no way to retrieve this number from bootloader.
            return None
        else:
            return _read_device_region_lock(self._xbee_device)

    def _get_target_hardware_version(self):
        """
        Returns the update target hardware version.

        Returns:
            Integer: the update target hardware version as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            # Assume the device is already in bootloader mode.
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
                return None

            return int(result.groups()[0][:2], 16)
        else:
            return _read_device_hardware_version(self._xbee_device)

    def _get_target_firmware_version(self):
        """
        Returns the update target firmware version.

        Returns:
            Integer: the update target firmware version as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            # Assume the device is already in bootloader mode.
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
                return None

            return int(result.groups()[0][:2], 16)
        else:
            return _read_device_firmware_version(self._xbee_device)

    def _check_updater_compatibility(self):
        """
        Verifies whether the updater device is compatible with firmware update or not.
        """
        # In local firmware updates, the updater device and target device are the same. Just return and
        # use the target function check instead.
        pass

    def _configure_updater(self):
        """
        Configures the updater device before performing the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        # For local updates, target and update device is the same.
        # Depending on the given target, process has a different flow (serial port or XBee device).
        if self._xbee_device is None:
            # Configure serial port connection with bootloader parameters.
            try:
                _log.debug("Opening port '%s'" % self._port)
                self._xbee_serial_port = XBeeSerialPort(_BOOTLOADER_PORT_PARAMETERS["baudrate"],
                                                        self._port,
                                                        data_bits=_BOOTLOADER_PORT_PARAMETERS["bytesize"],
                                                        stop_bits=_BOOTLOADER_PORT_PARAMETERS["stopbits"],
                                                        parity=_BOOTLOADER_PORT_PARAMETERS["parity"],
                                                        flow_control=FlowControl.NONE,
                                                        timeout=_BOOTLOADER_PORT_PARAMETERS["timeout"])
                self._xbee_serial_port.open()
            except SerialException as e:
                _log.error(_ERROR_CONNECT_SERIAL_PORT % str(e))
                raise FirmwareUpdateException(_ERROR_CONNECT_SERIAL_PORT % str(e))

            # Check if device is in bootloader mode.
            _log.debug("Checking if bootloader is active")
            if not self._is_bootloader_active():
                # If the bootloader is not active, enter in bootloader mode.
                if not self._enter_bootloader_mode_with_break():
                    self._exit_with_error(_ERROR_BOOTLOADER_MODE)
        else:
            self._updater_was_connected = self._xbee_device.is_open()
            _log.debug("Connecting device '%s'" % self._xbee_device)
            if not _connect_device_with_retries(self._xbee_device, _DEVICE_CONNECTION_RETRIES):
                if not self._set_device_in_programming_mode():
                    self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES)

    def _restore_updater(self):
        """
        Leaves the updater device to its original state before the update operation.

        Raises:
            SerialException: if there is any error restoring the serial port connection.
            XBeeException: if there is any error restoring the device connection.
        """
        # For local updates, target and update device is the same.
        if self._xbee_device is not None:
            if self._xbee_serial_port is not None:
                if self._xbee_serial_port.isOpen():
                    self._xbee_serial_port.close()
                if self._device_port_params is not None:
                    self._xbee_serial_port.apply_settings(self._device_port_params)
            if self._updater_was_connected and not self._xbee_device.is_open():
                self._xbee_device.open()
            elif not self._updater_was_connected and self._xbee_device.is_open():
                self._xbee_device.close()
        elif self._xbee_serial_port is not None and self._xbee_serial_port.isOpen():
            self._xbee_serial_port.close()

    def _start_firmware_update(self):
        """
        Starts the firmware update process. Called just before the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the target device.
        """
        if self._xbee_device is not None and not self._set_device_in_programming_mode():
            self._exit_with_error(_ERROR_DEVICE_PROGRAMMING_MODE)

    def _transfer_firmware(self):
        """
        Transfers the firmware file(s) to the target.

        Raises:
            FirmwareUpdateException: if there is any error transferring the firmware to the target device.
        """
        # Update the bootloader using XModem protocol if required.
        if self._bootloader_update_required:
            _log.info("Updating bootloader")
            self._progress_task = _PROGRESS_TASK_UPDATE_BOOTLOADER
            try:
                self._transfer_firmware_file_xmodem(self._bootloader_firmware_file)
            except FirmwareUpdateException as e:
                self._exit_with_error(_ERROR_FIRMWARE_UPDATE_BOOTLOADER % str(e))

        # Update the XBee firmware using XModem protocol.
        _log.info("Updating XBee firmware")
        self._progress_task = _PROGRESS_TASK_UPDATE_XBEE
        try:
            self._transfer_firmware_file_xmodem(self._xbee_firmware_file)
        except FirmwareUpdateException as e:
            self._exit_with_error(_ERROR_FIRMWARE_UPDATE_XBEE % str(e))

    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer firmware operation.
        """
        # Start firmware.
        if not self._run_firmware_operation():
            self._exit_with_error(_ERROR_FIRMWARE_START)

    def _set_device_in_programming_mode(self):
        """
        Attempts to put the XBee device into programming mode (bootloader).

        Returns:
            Boolean: ``True`` if the device was set into programming mode, ``False`` otherwise.
        """
        if self._xbee_device is None:
            return False

        if self._xbee_serial_port is not None and self._is_bootloader_active():
            return True

        _log.debug("Setting device in programming mode")
        try:
            self._xbee_device.execute_command(ATStringCommand.PERCENT_P.command)
        except XBeeException:
            # We can ignore this error as at last instance we will attempt a Break method.
            pass

        self._xbee_device.close()
        self._xbee_serial_port = self._xbee_device.serial_port
        self._device_port_params = self._xbee_serial_port.get_settings()
        try:
            self._xbee_serial_port.apply_settings(_BOOTLOADER_PORT_PARAMETERS)
            self._xbee_serial_port.open()
        except SerialException as e:
            _log.exception(e)
            return False
        if not self._is_bootloader_active():
            # This will force the Break mechanism to reboot in bootloader mode in case previous methods failed.
            return self._enter_bootloader_mode_with_break()

        return True

    def _start_firmware_upload_operation(self):
        """
        Starts the firmware upload operation by selecting option '1' of the bootloader.

        Returns:
            Boolean: ``True`` if the upload process started successfully, ``False`` otherwise
        """
        try:
            # Display bootloader menu and consume it.
            self._xbee_serial_port.write(str.encode(_BOOTLOADER_TEST_CHARACTER))
            time.sleep(1)
            self._xbee_serial_port.purge_port()
            # Write '1' to execute bootloader option '1': Upload gbl and consume answer.
            self._xbee_serial_port.write(str.encode(_BOOTLOADER_OPTION_UPLOAD_GBL))
            time.sleep(0.5)
            self._xbee_serial_port.purge_port()
            # Look for the 'C' character during some time, it indicates device is ready to receive firmware pages.
            self._xbee_serial_port.set_read_timeout(0.5)
            deadline = _get_milliseconds() + (_XMODEM_START_TIMEOUT * 1000)
            while _get_milliseconds() < deadline:
                read_bytes = self._xbee_serial_port.read(1)
                if len(read_bytes) > 0 and read_bytes[0] == ord(_XMODEM_READY_TO_RECEIVE_CHAR):
                    return True
                time.sleep(0.1)
            return False
        except SerialException as e:
            _log.exception(e)
            return False

    def _run_firmware_operation(self):
        """
        Runs the firmware by selecting option '2' of the bootloader.

        If XBee firmware is flashed, it will boot. If no firmware is flashed, the bootloader will be reset.

        Returns:
            Boolean: ``True`` if the run firmware operation was executed, ``False`` otherwise
        """
        try:
            # Display bootloader menu and consume it.
            self._xbee_serial_port.write(str.encode(_BOOTLOADER_TEST_CHARACTER))
            time.sleep(1)
            self._xbee_serial_port.purge_port()
            # Write '2' to execute bootloader option '2': Run.
            self._xbee_serial_port.write(str.encode(_BOOTLOADER_OPTION_RUN_FIRMWARE))

            # Look for the '2' character during some time, it indicates firmware was executed.
            read_bytes = self._xbee_serial_port.read(1)
            while len(read_bytes) > 0 and not read_bytes[0] == ord(_BOOTLOADER_OPTION_RUN_FIRMWARE):
                read_bytes = self._xbee_serial_port.read(1)
            return True
        except SerialException as e:
            _log.exception(e)
            return False

    def _xmodem_write_cb(self, data):
        """
        Callback function used to write data to the serial port when requested from the XModem transfer.

        Args:
            data (Bytearray): the data to write to serial port from the XModem transfer.

        Returns:
            Boolean: ``True`` if the data was successfully written, ``False`` otherwise.
        """
        try:
            self._xbee_serial_port.purge_port()
            self._xbee_serial_port.write(data)
        except SerialException as e:
            _log.exception(e)
            return False

        return True

    def _xmodem_read_cb(self, size, timeout=None):
        """
        Callback function used to read data from the serial port when requested from the XModem transfer.

        Args:
            size (Integer): the size of the data to read.
            timeout (Integer, optional): the maximum time to wait to read the requested data (seconds).

        Returns:
            Bytearray: the read data, ``None`` if data could not be read.
        """
        if not timeout:
            timeout = self._timeout
        deadline = _get_milliseconds() + (timeout * 1000)
        data = bytearray()
        try:
            while len(data) < size and _get_milliseconds() < deadline:
                read_bytes = self._xbee_serial_port.read(size - len(data))
                if len(read_bytes) > 0:
                    data.extend(read_bytes)
            return data
        except SerialException as e:
            _log.exception(e)

        return None

    def _xmodem_progress_cb(self, percent):
        """
        Callback function used to be notified about XModem transfer progress.

        Args:
            percent (Integer): the XModem transfer percentage.
        """
        if self._progress_callback is not None:
            self._progress_callback(self._progress_task, percent)

    def _transfer_firmware_file_xmodem(self, firmware_file_path):
        """
        Transfers the firmware to the device using XModem protocol.

        Args:
            firmware_file_path (String): path of the firmware file to transfer.

        Returns:
            Boolean: ``True`` if the firmware was transferred successfully, ``False`` otherwise

        Raises:
            FirmwareUpdateException: if there is any error transferring the firmware file.
        """
        # Start XModem communication.
        if not self._start_firmware_upload_operation():
            raise FirmwareUpdateException(_ERROR_XMODEM_START)

        # Transfer file.
        try:
            xmodem.send_file_xmodem(firmware_file_path, self._xmodem_write_cb, self._xmodem_read_cb,
                                    progress_cb=self._xmodem_progress_cb, log=_log)
        except XModemCancelException:
            # Retry at least once after resetting device.
            if not self._run_firmware_operation() and not (self._is_bootloader_active() or
                                                           self._enter_bootloader_mode_with_break()):
                raise FirmwareUpdateException(_ERROR_XMODEM_RESTART)
            try:
                self._xbee_serial_port.purge_port()
            except SerialException as e:
                raise FirmwareUpdateException(_ERROR_XMODEM_COMMUNICATION % str(e))
            self._start_firmware_upload_operation()
            try:
                xmodem.send_file_xmodem(firmware_file_path, self._xmodem_write_cb, self._xmodem_read_cb,
                                        progress_cb=self._xmodem_progress_cb, log=_log)
            except XModemException:
                raise
        except XModemException as e:
            raise FirmwareUpdateException(str(e))

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__class__.__DEVICE_RESET_TIMEOUT


class _RemoteFirmwareUpdater(_XBeeFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process.
    """

    __DEVICE_RESET_TIMEOUT_ZB = 3  # seconds
    __DEVICE_RESET_TIMEOUT_DM = 20  # seconds
    __DEVICE_RESET_TIMEOUT_802 = 28  # seconds

    def __init__(self, remote_device, xml_firmware_file, ota_firmware_file=None, otb_firmware_file=None,
                 timeout=_READ_DATA_TIMEOUT, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteFirmwareUpdater` with the given parameters.

        Args:
            remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
            xml_firmware_file (String): path of the XML file that describes the firmware to upload.
            ota_firmware_file (String, optional): path of the OTA firmware file to upload.
            otb_firmware_file (String, optional): path of the OTB firmware file to upload (bootloader bundle).
            timeout (Integer, optional): the timeout to wait for remote frame requests.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: if there is any error performing the remote firmware update.
        """
        super(_RemoteFirmwareUpdater, self).__init__(xml_firmware_file, timeout=timeout,
                                                     progress_callback=progress_callback)

        self._remote_device = remote_device
        self._local_device = remote_device.get_local_xbee_device()
        self._ota_firmware_file = ota_firmware_file
        self._otb_firmware_file = otb_firmware_file
        self._updater_was_connected = False
        self._updater_old_baudrate = None
        self._updater_ao_value = None
        self._updater_bd_value = None
        self._updater_my_value = None
        self._updater_rr_value = None
        self._ota_file = None
        self._receive_lock = Event()
        self._transfer_lock = Event()
        self._img_req_received = False
        self._img_notify_sent = False
        self._transfer_status = None
        self._response_string = None
        self._requested_chunk_index = -1
        self._seq_number = 0

    def _check_firmware_binary_file(self):
        """
        Verifies that the firmware binary file exists.

        Raises:
            FirmwareUpdateException: if the firmware binary file does not exist.
        """
        # If not already specified, the binary firmware file is usually in the same folder as the XML firmware file.
        if self._ota_firmware_file is None:
            path = Path(self._xml_firmware_file)
            self._ota_firmware_file = str(Path(path.parent).joinpath(path.stem + _EXTENSION_OTA))

        if not _file_exists(self._ota_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._ota_firmware_file, restore_updater=False)

        self._ota_file = _OTAFile(self._ota_firmware_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as e:
            self._exit_with_error(str(e))

    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.

        Raises:
            FirmwareUpdateException: if the bootloader binary file does not exist.
        """
        if self._otb_firmware_file is None:
            path = Path(self._xml_firmware_file)
            self._otb_firmware_file = str(Path(path.parent).joinpath(path.stem + _EXTENSION_OTB))

        if not _file_exists(self._otb_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._otb_firmware_file)

        # If asked to check the bootloader file, replace the OTA file with the .otb one.
        # Unlike local firmware updates, remote firmware updates only transfer one file for fw + bootloader.
        self._ota_file = _OTAFile(self._otb_firmware_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as e:
            self._exit_with_error(str(e))

    def _get_target_bootloader_version(self):
        """
        Returns the update target bootloader version.

        Returns:
            Bytearray: the update target bootloader version as byte array, ``None`` if it could not be read.
        """
        return _read_device_bootloader_version(self._remote_device)

    def _get_target_compatibility_number(self):
        """
        Returns the update target compatibility number.

        Returns:
            Integer: the update target compatibility number as integer, ``None`` if it could not be read.
        """
        return _read_device_compatibility_number(self._remote_device)

    def _get_target_region_lock(self):
        """
        Returns the update target region lock number.

        Returns:
            Integer: the update target region lock number as integer, ``None`` if it could not be read.
        """
        return _read_device_region_lock(self._remote_device)

    def _get_target_hardware_version(self):
        """
        Returns the update target hardware version.

        Returns:
            Integer: the update target hardware version as integer, ``None`` if it could not be read.
        """
        return _read_device_hardware_version(self._remote_device)

    def _get_target_firmware_version(self):
        """
        Returns the update target firmware version.

        Returns:
            Integer: the update target firmware version as integer, ``None`` if it could not be read.
        """
        return _read_device_firmware_version(self._remote_device)

    def _check_updater_compatibility(self):
        """
        Verifies whether the updater device is compatible with firmware update or not.
        """
        # At the moment only XBee3 devices are supported as updater devices for remote updates.
        if self._local_device.get_hardware_version().code not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

    def _configure_updater(self):
        """
        Configures the updater device before performing the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        # These configuration steps are specific for XBee3 devices. Since no other hardware is supported
        # yet, it is not a problem. If new hardware is supported in a future, this will need to be changed.

        # Change sync ops timeout.
        self._old_sync_ops_timeout = self._local_device.get_sync_ops_timeout()
        self._local_device.set_sync_ops_timeout(self._timeout)
        # Connect device.
        self._updater_was_connected = self._local_device.is_open()
        _log.debug("Connecting device '%s'" % self._local_device)
        if not _connect_device_with_retries(self._local_device, _DEVICE_CONNECTION_RETRIES):
            self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES)
        # Store AO value.
        self._updater_ao_value = _read_device_parameter_with_retries(self._local_device, ATStringCommand.AO.command)
        if self._updater_ao_value is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.AO.command)
        # Store BD value.
        self._updater_bd_value = _read_device_parameter_with_retries(self._local_device, ATStringCommand.BD.command)
        if self._updater_bd_value is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.BD.command)
        # Set new BD value.
        if not _set_device_parameter_with_retries(self._local_device, ATStringCommand.BD.command,
                                                  bytearray([_VALUE_BAUDRATE_230400])):
            self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.BD.command)
        # Change local port baudrate to 230400.
        self._updater_old_baudrate = self._local_device.serial_port.get_settings()["baudrate"]
        self._local_device.serial_port.set_baudrate(230400)
        # Set new AO value.
        if not _set_device_parameter_with_retries(self._local_device, ATStringCommand.AO.command,
                                                  bytearray([_VALUE_API_OUTPUT_MODE_EXPLICIT])):
            self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.AO.command)
        # Specific settings per protocol.
        if self._local_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            # Store RR value.
            self._updater_rr_value = _read_device_parameter_with_retries(self._local_device,
                                                                         ATStringCommand.RR.command)
            if self._updater_ao_value is None:
                self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.RR.command)
            # Set new RR value.
            if not _set_device_parameter_with_retries(self._local_device, ATStringCommand.RR.command,
                                                      bytearray([_VALUE_UNICAST_RETRIES_MEDIUM])):
                self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.RR.command)
        elif self._local_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # Store MY value.
            self._updater_my_value = _read_device_parameter_with_retries(self._local_device,
                                                                         ATStringCommand.MY.command)
            if self._updater_my_value is None:
                self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.MY.command)
            # Set new MY value.
            if not _set_device_parameter_with_retries(self._local_device, ATStringCommand.MY.command,
                                                      _VALUE_BROADCAST_ADDRESS):
                self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.MY.command)

    def _restore_updater(self, raise_exception=False):
        """
        Leaves the updater device to its original state before the update operation.

        Args:
            raise_exception (Boolean, optional): ``True`` to raise exceptions if they occur, ``False`` otherwise.

        Raises:
            XBeeException: if there is any error restoring the device connection.
        """
        # Close OTA file.
        if self._ota_file:
            self._ota_file.close_file()
        # Restore sync ops timeout.
        self._local_device.set_sync_ops_timeout(self._old_sync_ops_timeout)
        # Restore updater params.
        try:
            if not self._local_device.is_open():
                self._local_device.open()
            # Restore AO.
            if self._updater_ao_value is not None:
                _set_device_parameter_with_retries(self._local_device, ATStringCommand.AO.command,
                                                   self._updater_ao_value)
            # Restore BD.
            if self._updater_bd_value is not None:
                _set_device_parameter_with_retries(self._local_device, ATStringCommand.BD.command,
                                                   self._updater_bd_value)
            # Restore port baudrate.
            if self._updater_old_baudrate is not None:
                self._local_device.serial_port.set_baudrate(self._updater_old_baudrate)
            # Specific settings per protocol.
            if self._local_device.get_protocol() == XBeeProtocol.DIGI_MESH:
                # Restore RR value.
                _set_device_parameter_with_retries(self._local_device, ATStringCommand.RR.command,
                                                   self._updater_rr_value)
            elif self._local_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
                # Restore MY value.
                _set_device_parameter_with_retries(self._local_device, ATStringCommand.MY.command,
                                                   self._updater_my_value)
        except XBeeException as e:
            if raise_exception:
                raise e
        if self._updater_was_connected and not self._local_device.is_open():
            self._local_device.open()
        elif not self._updater_was_connected and self._local_device.is_open():
            self._local_device.close()

    def _create_explicit_frame(self, payload):
        """
        Creates and returns an explicit addressing frame using the given payload.

        Args:
            payload (Bytearray): the payload for the explicit addressing frame.

        Returns:
            :class:`.ExplicitAddressingPacket`: the explicit addressing frame with the given payload.
        """
        packet = ExplicitAddressingPacket(self._local_device.get_next_frame_id(),
                                          self._remote_device.get_64bit_addr(),
                                          self._remote_device.get_16bit_addr(),
                                          _EXPLICIT_PACKET_ENDPOINT_DATA,
                                          _EXPLICIT_PACKET_ENDPOINT_DATA,
                                          _EXPLICIT_PACKET_CLUSTER_ID,
                                          _EXPLICIT_PACKET_PROFILE_DIGI,
                                          _EXPLICIT_PACKET_BROADCAST_RADIUS_MAX,
                                          _EXPLICIT_PACKET_EXTENDED_TIMEOUT,
                                          payload)
        return packet

    def _create_zdo_frame(self, frame_control, seq_number, command_id, payload):
        """
        Creates and returns a ZDO frame with the given parameters.

        Args:
            frame_control (Integer): the ZDO object frame control.
            seq_number (Integer): the ZDO object sequence number.
            command_id (Integer): the ZDO object command ID.
            payload (Bytearray): the payload for the ZDO object.

        Returns:
            Bytearray: the ZDO frame.
        """
        zdo_payload = bytearray()
        zdo_payload.append(frame_control & 0xFF)
        zdo_payload.append(seq_number & 0xFF)
        zdo_payload.append(command_id & 0xFF)
        zdo_payload.extend(payload)

        return self._create_explicit_frame(zdo_payload)

    def _create_image_notify_request_frame(self):
        """
        Creates and returns an image notify request frame for the firmware to transfer.

        Returns:
            Bytearray: the image notify request frame.
        """
        payload = bytearray()
        payload.append(_NOTIFY_PACKET_PAYLOAD_TYPE & 0xFF)
        payload.append(_NOTIFY_PACKET_DEFAULT_QUERY_JITTER & 0xFF)
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))

        return self._create_zdo_frame(_ZDO_FRAME_CONTROL_SERVER_TO_CLIENT, _PACKET_DEFAULT_SEQ_NUMBER,
                                      _ZDO_COMMAND_ID_IMG_NOTIFY_REQ, payload)

    def _create_query_next_image_response_frame(self):
        """
        Creates and returns a query next image response frame.

        Returns:
            Bytearray: the query next image response frame.
        """
        image_size = self._ota_file.total_size

        # If the remote module is an XBee3 using ZigBee protocol and the firmware version
        # is 1003 or lower, use the OTA GBL size instead of total size (exclude header size).
        if self._remote_device.get_protocol() == XBeeProtocol.ZIGBEE and \
                self._target_hardware_version in SUPPORTED_HARDWARE_VERSIONS and \
                self._target_firmware_version < _ZIGBEE_FW_VERSION_LIMIT_FOR_GBL:
            image_size = self._ota_file.gbl_size

        payload = bytearray()
        payload.append(_XBee3OTAStatus.SUCCESS.identifier & 0xFF)
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(image_size, 4)))

        return self._create_zdo_frame(_ZDO_FRAME_CONTROL_SERVER_TO_CLIENT, _PACKET_DEFAULT_SEQ_NUMBER,
                                      _ZDO_COMMAND_ID_QUERY_NEXT_IMG_RESP, payload)

    def _create_image_block_response_frame(self, chunk_index, current_seq_number):
        """
        Creates and returns an image block response frame.

        Args:
            chunk_index (Integer): the chunk index to send.
            current_seq_number (Integer): the current protocol sequence number.

        Returns:
            Bytearray: the image block response frame.

        Raises:
            FirmwareUpdateException: if there is any error generating the image block response frame.
        """
        # Increment protocol sequence number.
        next_seq_number = current_seq_number + 1
        if next_seq_number > 255:
            next_seq_number = 0

        try:
            data = self._ota_file.get_next_data_chunk()
        except _ParsingOTAException as e:
            raise FirmwareUpdateException(_ERROR_READ_OTA_FILE % str(e))
        payload = bytearray()
        payload.append(_XBee3OTAStatus.SUCCESS.identifier & 0xFF)
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(chunk_index * self._ota_file.chunk_size, 4)))
        if data:
            payload.append(len(data) & 0xFF)
            payload.extend(data)
        else:
            payload.extend(utils.int_to_bytes(0))

        return self._create_zdo_frame(_ZDO_FRAME_CONTROL_SERVER_TO_CLIENT, next_seq_number,
                                      _ZDO_COMMAND_ID_IMG_BLOCK_RESP, payload)

    def _create_upgrade_end_response_frame(self):
        """
        Creates and returns an upgrade end response frame.

        Returns:
            Bytearray: the upgrade end response frame.
        """
        payload = bytearray()
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(int(time.time()) - _TIME_SECONDS_1970_TO_2000, 4)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(0, 4)))

        return self._create_zdo_frame(_ZDO_FRAME_CONTROL_SERVER_TO_CLIENT, _PACKET_DEFAULT_SEQ_NUMBER,
                                      _ZDO_COMMAND_ID_UPGRADE_END_RESP, payload)

    @staticmethod
    def _is_img_req_payload_valid(payload):
        """
        Returns whether the given payload is valid for an image request received frame.

        Args:
            payload (Bytearray): the payload to check.

        Returns:
            Boolean: ``True`` if the given payload is valid for an image request received frame, ``False`` otherwise.
        """
        return (len(payload) == _NOTIFY_PACKET_PAYLOAD_SIZE and
                payload[0] == _ZDO_FRAME_CONTROL_CLIENT_TO_SERVER and
                payload[2] == _ZDO_COMMAND_ID_QUERY_NEXT_IMG_REQ)

    def _image_request_frame_callback(self, xbee_frame):
        """
        Callback used to be notified when the image request frame is received by
        the target device and it is ready to start receiving image frames.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the received packet
        """
        if xbee_frame.get_frame_type() == ApiFrameType.TRANSMIT_STATUS:
            _log.debug("Received 'Image notify' status frame: %s" % xbee_frame.transmit_status.description)
            if xbee_frame.transmit_status == TransmitStatus.SUCCESS:
                self._img_notify_sent = True
                # Sometimes the transmit status frame is received after the explicit frame
                # indicator. Notify only if the transmit status frame was also received.
                if self._img_req_received:
                    # Continue execution.
                    self._receive_lock.set()
            else:
                # Remove explicit frame indicator received flag if it was set.
                if self._img_req_received:
                    self._img_req_received = False
                # Continue execution, it will exit with error as received flags are not set.
                self._receive_lock.set()
        elif xbee_frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR:
            if self._img_req_received:
                return
            if not self._is_img_req_payload_valid(xbee_frame.rf_data):
                # This is not the explicit frame we were expecting, keep on listening.
                return
            _log.debug("Received 'Query next image' request frame")
            self._img_req_received = True
            # Sometimes the transmit status frame is received after the explicit frame
            # indicator. Notify only if the transmit status frame was also received.
            if self._img_notify_sent:
                # Continue execution.
                self._receive_lock.set()

    def _firmware_receive_frame_callback(self, xbee_frame):
        """
        Callback used to be notified of image block requests and upgrade end request frames during the
        firmware transfer operation.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the received packet
        """
        if xbee_frame.get_frame_type() != ApiFrameType.EXPLICIT_RX_INDICATOR:
            return

        # Check the type of frame received.
        if self._is_image_block_request_frame(xbee_frame):
            # If the received frame is an 'image block request' frame, retrieve the requested index.
            max_data_size, file_offset, sequence_number = self._parse_image_block_request_frame(xbee_frame)
            # Check if OTA file chunk size must be updated.
            if max_data_size != self._ota_file.chunk_size:
                self._ota_file.chunk_size = max_data_size
            self._requested_chunk_index = file_offset // self._ota_file.chunk_size
            _log.debug("Received 'Image block request' frame for file offset %s - Chunk index: %s - Expected index: %s"
                       % (file_offset, self._requested_chunk_index, self._expected_chunk_index))
            if self._requested_chunk_index != self._expected_chunk_index:
                return
            self._expected_chunk_index += 1
            self._seq_number = sequence_number
        elif self._is_upgrade_end_request_frame(xbee_frame):
            _log.debug("Received 'Upgrade end request' frame")
            # If the received frame is an 'upgrade end request' frame, set transfer status.
            self._transfer_status = _XBee3OTAStatus.get(self._parse_upgrade_end_request_frame(xbee_frame))
        elif self._is_default_response_frame(xbee_frame):
            _log.debug("Received 'Default response' frame")
            # If the received frame is a 'default response' frame, set the corresponding error.
            ota_command, status = self._parse_default_response_frame(xbee_frame)
            response_status = None
            if self._local_device.get_protocol() == XBeeProtocol.ZIGBEE:
                response_status = _XBeeZigbee3OTAStatus.get(status)
            else:
                if ota_command == _ZDO_COMMAND_ID_QUERY_NEXT_IMG_RESP:
                    response_status = _NextImageMessageStatus.get(status)
                elif ota_command == _ZDO_COMMAND_ID_IMG_BLOCK_RESP:
                    response_status = _ImageBlockMessageStatus.get(status)
                elif ota_command == _ZDO_COMMAND_ID_UPGRADE_END_RESP:
                    response_status = _UpgradeEndMessageStatus.get(status)
            self._response_string = response_status.description if response_status is not None \
                else _ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR
        else:
            return
        # Notify transfer thread to continue.
        self._transfer_lock.set()

    def _is_image_block_request_frame(self, xbee_frame):
        """
        Returns whether the given frame is an image block request frame or not.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.

        Returns:
            Boolean: ``True`` if the frame is an image block request frame, ``False`` otherwise.
        """
        return self._parse_image_block_request_frame(xbee_frame) is not None

    @staticmethod
    def _parse_image_block_request_frame(xbee_frame):
        """
        Parses the given image block request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Tuple (Integer, Integer, Integer): the max data size, the file offset and the sequence number of the block
                                               request frame. ``None`` if parsing failed.
        """
        payload = xbee_frame.rf_data
        if len(payload) != _IMAGE_BLOCK_REQUEST_PACKET_PAYLOAD_SIZE or \
                payload[0] != _ZDO_FRAME_CONTROL_CLIENT_TO_SERVER or \
                payload[2] != _ZDO_COMMAND_ID_IMG_BLOCK_REQ:
            return None

        sequence_number = payload[1] & 0xFF
        file_offset = utils.bytes_to_int(_reverse_bytearray(payload[12:16]))
        max_data_size = payload[16] & 0xFF

        return max_data_size, file_offset, sequence_number

    def _is_upgrade_end_request_frame(self, xbee_frame):
        """
        Returns whether the given frame is an upgrade end request frame or not.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.

        Returns:
            Boolean: ``True`` if the frame is an upgrade end request frame, ``False`` otherwise.
        """
        return self._parse_upgrade_end_request_frame(xbee_frame) is not None

    @staticmethod
    def _parse_upgrade_end_request_frame(xbee_frame):
        """
        Parses the given upgrade end request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Integer: the upgrade end request status, ``None`` if parsing failed.
        """
        payload = xbee_frame.rf_data
        if len(payload) != _UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE or \
                payload[0] != _ZDO_FRAME_CONTROL_CLIENT_TO_SERVER or \
                payload[2] != _ZDO_COMMAND_ID_UPGRADE_END_REQ:
            return None

        status = payload[3] & 0xFF

        return status

    def _is_default_response_frame(self, xbee_frame):
        """
        Returns whether the given frame is a default response frame or not.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.

        Returns:
            Boolean: ``True`` if the frame is a default response frame, ``False`` otherwise.
        """
        return self._parse_default_response_frame(xbee_frame) is not None

    @staticmethod
    def _parse_default_response_frame(xbee_frame):
        """
        Parses the given image block request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Tuple (Integer, Integer): the OTA command and the sstatus of the default response frame.
                                      ``None`` if parsing failed.
        """
        payload = xbee_frame.rf_data
        if len(payload) != _DEFAULT_RESPONSE_PACKET_PAYLOAD_SIZE or \
                payload[0] != _ZDO_FRAME_CONTROL_GLOBAL or \
                payload[2] != _ZDO_COMMAND_ID_DEFAULT_RESP:
            return None

        ota_command = payload[3] & 0xFF
        status = payload[4] & 0xFF

        return ota_command, status

    def _send_query_next_img_response(self):
        """
        Sends the query next image response frame.

        Raises:
            FirmwareUpdateException: if there is any error sending the next image response frame.
        """
        retries = _SEND_BLOCK_RETRIES
        query_next_image_response_frame = self._create_query_next_image_response_frame()
        while retries > 0:
            try:
                _log.debug("Sending 'Query next image response' frame")
                status_frame = self._local_device.send_packet_sync_and_get_response(query_next_image_response_frame)
                if not isinstance(status_frame, TransmitStatusPacket):
                    retries -= 1
                    continue
                _log.debug("Received 'Query next image response' status frame: %s" %
                           status_frame.transmit_status.description)
                if status_frame.transmit_status != TransmitStatus.SUCCESS:
                    retries -= 1
                    continue
                return
            except XBeeException as e:
                raise FirmwareUpdateException(_ERROR_SEND_QUERY_NEXT_IMAGE_RESPONSE % str(e))

        raise FirmwareUpdateException(_ERROR_SEND_QUERY_NEXT_IMAGE_RESPONSE % "Timeout sending frame")

    def _send_ota_block(self, chunk_index, seq_number):
        """
        Sends the next OTA block frame.

        Args:
            chunk_index (Integer): the

        Raises:
            FirmwareUpdateException: if there is any error sending the next OTA block frame.
        """
        retries = _SEND_BLOCK_RETRIES
        next_ota_block_frame = self._create_image_block_response_frame(chunk_index, seq_number)
        while retries > 0:
            try:
                _log.debug("Sending 'Image block response' frame for chunk %s" % chunk_index)
                status_frame = self._local_device.send_packet_sync_and_get_response(next_ota_block_frame)
                if not isinstance(status_frame, TransmitStatusPacket):
                    retries -= 1
                    continue
                _log.debug("Received 'Image block response' status frame for chunk %s: %s" %
                           (chunk_index, status_frame.transmit_status.description))
                if status_frame.transmit_status != TransmitStatus.SUCCESS:
                    retries -= 1
                    continue
                return
            except XBeeException as e:
                raise FirmwareUpdateException(_ERROR_SEND_OTA_BLOCK % (chunk_index, str(e)))

        raise FirmwareUpdateException(_ERROR_SEND_OTA_BLOCK % (chunk_index, "Timeout sending frame"))

    def _start_firmware_update(self):
        """
        Starts the firmware update process. Called just before the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error starting the remote firmware update process.
        """
        _log.debug("Sending 'Image notify' frame")
        image_notify_request_frame = self._create_image_notify_request_frame()
        self._local_device.add_packet_received_callback(self._image_request_frame_callback)
        try:
            self._local_device.send_packet(image_notify_request_frame)
            self._receive_lock.wait(self._timeout)
            if not self._img_notify_sent:
                self._exit_with_error(_ERROR_SEND_IMAGE_NOTIFY % "Transmit status not received")
            elif not self._img_req_received:
                self._exit_with_error(_ERROR_SEND_IMAGE_NOTIFY % "Timeout waiting for response")
        except XBeeException as e:
            self._exit_with_error(_ERROR_SEND_IMAGE_NOTIFY % str(e))
        finally:
            self._local_device.del_packet_received_callback(self._image_request_frame_callback)

    def _transfer_firmware(self):
        """
        Transfers the firmware to the target.

        Raises:
            FirmwareUpdateException: if there is any error transferring the firmware to the target device.
        """
        self._transfer_status = None
        self._response_string = None
        self._expected_chunk_index = 0
        self._requested_chunk_index = -1
        self._progress_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        last_chunk_sent = self._requested_chunk_index
        previous_seq_number = 0
        previous_percent = None
        retries = _SEND_BLOCK_RETRIES

        # Add a packet listener to wait for block request packets and send them.
        self._local_device.add_packet_received_callback(self._firmware_receive_frame_callback)
        try:
            self._send_query_next_img_response()
        except FirmwareUpdateException as e:
            self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
            self._exit_with_error(str(e))
        # Wait for answer.
        if self._requested_chunk_index == -1:  # If chunk index is different than -1 it means callback was executed.
            self._transfer_lock.clear()
            self._transfer_lock.wait(self._timeout)
        while self._requested_chunk_index != -1 and \
                self._transfer_status is None and \
                self._response_string is None and \
                retries > 0:
            if self._requested_chunk_index != last_chunk_sent:
                # New chunk requested, increase previous values and reset retries.
                last_chunk_sent = self._requested_chunk_index
                previous_seq_number = self._seq_number
                retries = _SEND_BLOCK_RETRIES
            else:
                # Chunk index was not increased, this means chunk was not sent. Decrease retries.
                _log.debug("Chunk %s not sent, retrying..." % self._requested_chunk_index)
                retries -= 1
            # Check that the requested index is valid.
            if self._requested_chunk_index >= self._ota_file.num_chunks:
                self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
                self._exit_with_error(_ERROR_INVALID_BLOCK % self._requested_chunk_index)
            # Calculate percentage and notify.
            percent = (self._requested_chunk_index * 100) // self._ota_file.num_chunks
            if percent != previous_percent and self._progress_callback:
                self._progress_callback(self._progress_task, percent)
                previous_percent = percent
            # Send the data block.
            try:
                self._send_ota_block(self._requested_chunk_index, previous_seq_number)
            except FirmwareUpdateException as e:
                self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
                self._exit_with_error(str(e))
            # Wait for next request.
            if self._requested_chunk_index == last_chunk_sent:
                self._transfer_lock.clear()
                self._transfer_lock.wait(self._timeout)
        # Transfer finished, remove callback.
        self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
        # Close OTA file.
        self._ota_file.close_file()
        # Check if there was a transfer timeout.
        if self._transfer_status is None and self._response_string is None:
            if last_chunk_sent + 1 == self._ota_file.num_chunks:
                self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % "Timeout waiting for 'Upgrade end request' frame")
            else:
                self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % "Timeout waiting for next 'Image block request' frame")
        # Check if there was a transfer error.
        if self._transfer_status and self._transfer_status != _XBee3OTAStatus.SUCCESS:
            self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % self._transfer_status.description)
        # Check if the client reported an error.
        if self._response_string:
            self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % self._response_string)
        # Reaching this point means the transfer was successful, notify 100% progress.
        if self._progress_callback:
            self._progress_callback(self._progress_task, 100)

    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error finishing the firmware operation.
        """
        retries = _SEND_BLOCK_RETRIES
        error_message = None
        upgrade_end_response_frame = self._create_upgrade_end_response_frame()
        while retries > 0:
            try:
                _log.debug("Sending 'Upgrade end response' frame")
                error_message = None
                status_frame = self._local_device.send_packet_sync_and_get_response(upgrade_end_response_frame)
                if not isinstance(status_frame, TransmitStatusPacket):
                    retries -= 1
                    continue
                _log.debug("Received 'Upgrade end response' status frame: %s" %
                           status_frame.transmit_status.description)

                # Workaround for 'No ack' error on XBee 3 DigiMesh remote firmware updates
                #
                # After sending the explicit frame with the 'Upgrade end response' command,
                # the received transmit status always has a 'No acknowledgement received'
                # error (0x01) instead of a 'Success' (0x00). This happens for 3004 or lower
                # firmware versions at least.
                # The workaround considers as valid the 'No ack' error only for DigiMesh firmwares.
                #
                # See https://jira.digi.com/browse/XBHAWKDM-796
                dm_ack_error = (status_frame.transmit_status == TransmitStatus.NO_ACK
                                and self._remote_device.get_protocol() == XBeeProtocol.DIGI_MESH)

                if status_frame.transmit_status != TransmitStatus.SUCCESS and not dm_ack_error:
                    retries -= 1
                    continue
                try:
                    self._restore_updater(raise_exception=True)
                    return
                except Exception as e:
                    self._exit_with_error(_ERROR_RESTORE_UPDATER_DEVICE % str(e))
            except XBeeException as e:
                retries -= 1
                error_message = str(e)
            time.sleep(1.5)  # Wait some time between timeout retries.

        if error_message:
            self._exit_with_error(_ERROR_SEND_UPGRADE_END_RESPONSE % error_message)
        else:
            self._exit_with_error(_ERROR_SEND_UPGRADE_END_RESPONSE % "Timeout sending frame")

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        protocol = self._remote_device.get_protocol()
        if protocol == XBeeProtocol.ZIGBEE:
            return self.__class__.__DEVICE_RESET_TIMEOUT_ZB
        elif protocol == XBeeProtocol.DIGI_MESH:
            return self.__class__.__DEVICE_RESET_TIMEOUT_DM
        elif protocol == XBeeProtocol.RAW_802_15_4:
            return self.__class__.__DEVICE_RESET_TIMEOUT_802

        return max([self.__class__.__DEVICE_RESET_TIMEOUT_ZB,
                    self.__class__.__DEVICE_RESET_TIMEOUT_DM,
                    self.__class__.__DEVICE_RESET_TIMEOUT_802])


def update_local_firmware(target, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                          timeout=None, progress_callback=None):
    """
    Performs a local firmware update operation in the given target.

    Args:
        target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
            String: serial port identifier.
            :class:`.AbstractXBeeDevice`: the XBee device to upload its firmware.
        xml_firmware_file (String): path of the XML file that describes the firmware to upload.
        xbee_firmware_file (String, optional): location of the XBee binary firmware file.
        bootloader_firmware_file (String, optional): location of the bootloader binary firmware file.
        timeout (Integer, optional): the serial port read data timeout.
        progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FirmwareUpdateException: if there is any error performing the firmware update.
    """
    # Sanity checks.
    if not isinstance(target, str) and not isinstance(target, AbstractXBeeDevice):
        _log.error("ERROR: %s" % _ERROR_TARGET_INVALID)
        raise FirmwareUpdateException(_ERROR_TARGET_INVALID)
    if xml_firmware_file is None:
        _log.error("ERROR: %s" % _ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
    if not _file_exists(xml_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
    if xbee_firmware_file is not None and not _file_exists(xbee_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % xbee_firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % xbee_firmware_file)
    if bootloader_firmware_file is not None and not _file_exists(bootloader_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND)

    # Launch the update process.
    if not timeout:
        timeout = _READ_DATA_TIMEOUT
    update_process = _LocalFirmwareUpdater(target,
                                           xml_firmware_file,
                                           xbee_firmware_file=xbee_firmware_file,
                                           bootloader_firmware_file=bootloader_firmware_file,
                                           timeout=timeout,
                                           progress_callback=progress_callback)
    update_process.update_firmware()


def update_remote_firmware(remote_device, xml_firmware_file, ota_firmware_file=None, otb_firmware_file=None,
                           timeout=None, progress_callback=None):
    """
    Performs a local firmware update operation in the given target.

    Args:
        remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
        xml_firmware_file (String): path of the XML file that describes the firmware to upload.
        ota_firmware_file (String, optional): path of the OTA firmware file to upload.
        otb_firmware_file (String, optional): path of the OTB firmware file to upload (bootloader bundle).
        timeout (Integer, optional): the timeout to wait for remote frame requests.
        progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FirmwareUpdateException: if there is any error performing the remote firmware update.
    """
    # Sanity checks.
    if not isinstance(remote_device, RemoteXBeeDevice):
        _log.error("ERROR: %s" % _ERROR_REMOTE_DEVICE_INVALID)
        raise FirmwareUpdateException(_ERROR_TARGET_INVALID)
    if xml_firmware_file is None:
        _log.error("ERROR: %s" % _ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
    if not _file_exists(xml_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
    if ota_firmware_file is not None and not _file_exists(ota_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % ota_firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % ota_firmware_file)
    if otb_firmware_file is not None and not _file_exists(otb_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % otb_firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % otb_firmware_file)

    # Launch the update process.
    if not timeout:
        timeout = _REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT
    update_process = _RemoteFirmwareUpdater(remote_device,
                                            xml_firmware_file,
                                            ota_firmware_file=ota_firmware_file,
                                            otb_firmware_file=otb_firmware_file,
                                            timeout=timeout,
                                            progress_callback=progress_callback)
    update_process.update_firmware()


def _file_exists(file):
    """
    Returns whether the given file path exists or not.

    Args:
        file (String): the file path to check.

    Returns:
        Boolean: ``True`` if the path exists, ``False`` otherwise
    """
    if file is None:
        return False

    return os.path.isfile(file)


def _bootloader_version_to_bytearray(bootloader_version):
    """
    Transforms the given bootloader version in string format into a byte array.

    Args:
        bootloader_version (String): the bootloader version as string.

    Returns:
        Bytearray: the bootloader version as byte array, ``None`` if transformation failed.
    """
    bootloader_version_array = bytearray(_BOOTLOADER_VERSION_SIZE)
    version_split = bootloader_version.split(_BOOTLOADER_VERSION_SEPARATOR)
    if len(version_split) < _BOOTLOADER_VERSION_SIZE:
        return None

    for i in range(_BOOTLOADER_VERSION_SIZE):
        bootloader_version_array[i] = utils.int_to_bytes((int(version_split[i])))[0]

    return bootloader_version_array


def _get_milliseconds():
    """
    Returns the current time in milliseconds.

    Returns:
         Integer: the current time in milliseconds.
    """
    return int(time.time() * 1000.0)


def _connect_device_with_retries(xbee_device, retries):
    """
    Attempts to connect the XBee device with the given number of retries.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to connect.
        retries (Integer): the number of connection retries.

    Returns:
        Boolean: ``True`` if the device connected, ``False`` otherwise.
    """
    if xbee_device is None:
        return False

    if xbee_device.is_open():
        return True

    while retries > 0:
        try:
            xbee_device.open()
            return True
        except XBeeException:
            retries -= 1
            if retries != 0:
                time.sleep(1)
        except SerialException:
            return False

    return False


def _read_device_parameter_with_retries(xbee_device, parameter, retries=_PARAMETER_READ_RETRIES):
    """
    Reads the given parameter from the XBee device with the given number of retries.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.
        parameter (String): the parameter to read.
        retries (Integer, optional): the number of retries to perform after a :class:`.TimeoutException`

    Returns:
        Bytearray: the read parameter value, ``None`` if the parameter could not be read.
    """
    if xbee_device is None:
        return None

    while retries > 0:
        try:
            return xbee_device.get_parameter(parameter)
        except TimeoutException:
            # On timeout exceptions perform retries.
            retries -= 1
            if retries != 0:
                time.sleep(1)
        except XBeeException as e:
            _log.exception(e)
            return None

    return None


def _set_device_parameter_with_retries(xbee_device, parameter, value, retries=_PARAMETER_SET_RETRIES):
    """
    Reads the given parameter from the XBee device with the given number of retries.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.
        parameter (String): the parameter to set.
        value (Bytearray): the parameter value.
        retries (Integer, optional): the number of retries to perform after a :class:`.TimeoutException`

    Returns:
        Boolean: ``True`` if the parameter was correctly set, ``False`` otherwise.
    """
    if xbee_device is None:
        return None

    while retries > 0:
        try:
            xbee_device.set_parameter(parameter, value)
            return True
        except TimeoutException:
            # On timeout exceptions perform retries.
            retries -= 1
            if retries != 0:
                time.sleep(1)
        except XBeeException as e:
            _log.exception(e)
            return False

    return False


def _read_device_bootloader_version(xbee_device):
    """
    Returns the bootloader version of the given XBee device.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.

    Returns:
        Bytearray: the XBee device bootloader version as byte array, ``None`` if it could not be read.
    """
    bootloader_version_array = bytearray(3)
    bootloader_version = _read_device_parameter_with_retries(xbee_device, _PARAMETER_BOOTLOADER_VERSION,
                                                             _PARAMETER_READ_RETRIES)
    if bootloader_version is None or len(bootloader_version) < 2:
        return None
    bootloader_version_array[0] = bootloader_version[0] & 0x0F
    bootloader_version_array[1] = (bootloader_version[1] & 0xF0) >> 4
    bootloader_version_array[2] = bootloader_version[1] & 0x0F

    return bootloader_version_array


def _read_device_compatibility_number(xbee_device):
    """
    Returns the compatibility number of the given XBee device.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.

    Returns:
        Integer: the XBee device compatibility number as integer, ``None`` if it could not be read.
    """
    compatibility_number = _read_device_parameter_with_retries(xbee_device,
                                                               ATStringCommand.PERCENT_C.command,
                                                               _PARAMETER_READ_RETRIES)
    if compatibility_number is None:
        return None
    compatibility_number = utils.hex_to_string(compatibility_number)[0:2]

    return int(compatibility_number)


def _read_device_region_lock(xbee_device):
    """
    Returns the region lock number of the given XBee device.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.

    Returns:
        Integer: the XBee device region lock number as integer, ``None`` if it could not be read.
    """
    region_lock = _read_device_parameter_with_retries(xbee_device, ATStringCommand.R_QUESTION.command,
                                                      _PARAMETER_READ_RETRIES)
    if region_lock is None:
        return None

    return int(region_lock[0])


def _read_device_hardware_version(xbee_device):
    """
    Returns the hardware version of the given XBee device.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.

    Returns:
        Integer: the XBee device hardware version as integer, ``None`` if it could not be read.
    """
    hardware_version = _read_device_parameter_with_retries(xbee_device, ATStringCommand.HV.command,
                                                           _PARAMETER_READ_RETRIES)
    if hardware_version is None:
        return None

    return int(hardware_version[0])


def _read_device_firmware_version(xbee_device):
    """
    Returns the firmware version of the given XBee device.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.

    Returns:
        Integer: the XBee device firmware version as integer, ``None`` if it could not be read.
    """
    firmware_version = _read_device_parameter_with_retries(xbee_device, ATStringCommand.VR.command,
                                                           _PARAMETER_READ_RETRIES)
    if firmware_version is None:
        return None

    return utils.bytes_to_int(firmware_version)


def _reverse_bytearray(byte_array):
    """
    Reverses the given byte array order.

    Args:
        byte_array (Bytearray): the byte array to reverse.

    Returns:
        Bytearray: the reversed byte array.
    """
    return bytearray(list(reversed(byte_array)))
