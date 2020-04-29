# Copyright 2019, 2020, Digi International Inc.
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
from digi.xbee.devices import AbstractXBeeDevice, RemoteXBeeDevice, NetworkEventReason
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

_BOOTLOADER_INITIALIZATION_TIME = 3  # Seconds
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
_BOOTLOADER_XBEE3_RESET_ENV_VERSION = bytearray([1, 6, 6])

_BUFFER_SIZE_SHORT = 2
_BUFFER_SIZE_INT = 4
_BUFFER_SIZE_IEEE_ADDR = 8
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
_ERROR_FILE_OTA_FILESYSTEM_NOT_FOUND = "OTA filesystem image file does not exist"
_ERROR_FILE_OTA_FILESYSTEM_NOT_SPECIFIED = "OTA filesystem image file must be specified"
_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND = "Could not find XBee binary firmware file '%s'"
_ERROR_FILE_XML_FIRMWARE_NOT_FOUND = "XML firmware file does not exist"
_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED = "XML firmware file must be specified"
_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND = "Could not find bootloader binary firmware file '%s'"
_ERROR_FIRMWARE_START = "Could not start the new firmware"
_ERROR_FIRMWARE_UPDATE_BOOTLOADER = "Bootloader update error: %s"
_ERROR_FIRMWARE_UPDATE_XBEE = "XBee firmware update error: %s"
_ERROR_HARDWARE_VERSION_DIFFER = "Device hardware version (%d) differs from the firmware one (%d)"
_ERROR_HARDWARE_VERSION_NOT_SUPPORTED = "XBee hardware version (%d) does not support this firmware update process"
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
_ERROR_SEND_OTA_BLOCK = "Error sending OTA block '%s' frame: %s"
_ERROR_SEND_FRAME_RESPONSE = "Error sending '%s' frame: %s"
_ERROR_TARGET_INVALID = "Invalid update target"
_ERROR_TRANSFER_OTA_FILE = "Error transferring OTA file: %s"
_ERROR_UPDATE_TARGET_INFORMATION = "Error reading new target information: %s"
_ERROR_UPDATE_TARGET_TIMEOUT = "Timeout communicating with target device after the firmware update"
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

_NOTIFY_PACKET_PAYLOAD_SIZE = 12
# Payload type indicates which fields are present:
#    * 0: No optional fields (Query Jitter only)
#    * 1: Query Jitter, Manufacturer Code
#    * 2: Query Jitter, Manufacturer Code, Image Type
#    * 3: Query Jitter, Manufacturer Code, Image Type, File Version
_NOTIFY_PACKET_PAYLOAD_TYPE = 0x03
# A number between 0-100.
# 100 to ensure all the XBees receiving the notify replies.
_NOTIFY_PACKET_DEFAULT_QUERY_JITTER = 0x64

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
_PROGRESS_TASK_UPDATE_REMOTE_FILESYSTEM = "Updating remote XBee filesystem"
_PROGRESS_TASK_UPDATE_XBEE = "Updating XBee firmware"

_REGION_ALL = 0

_REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT = 20  # Seconds
_REMOTE_FIRMWARE_UPDATE_RESYNC_TIMEOUT = 60  # Seconds

_SEND_BLOCK_RETRIES = 5

_TIME_DAYS_1970TO_2000 = 10957
_TIME_SECONDS_1970_TO_2000 = _TIME_DAYS_1970TO_2000 * 24 * 60 * 60

_IMAGE_BLOCK_RESPONSE_PAYLOAD_DECREMENT = 1
_UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE = 12

_VALUE_API_OUTPUT_MODE_EXPLICIT = 0x01
_VALUE_BAUDRATE_230400 = 0x08
_VALUE_BROADCAST_ADDRESS = bytearray([0xFF, 0xFF])
_VALUE_UNICAST_RETRIES_MEDIUM = 0x06

_XML_BOOTLOADER_VERSION = "firmware/bootloader_version"
_XML_COMPATIBILITY_NUMBER = "firmware/compatibility_number"
_XML_FIRMWARE = "firmware"
_XML_FIRMWARE_VERSION_ATTRIBUTE = "fw_version"
_XML_FLASH_PAGE_SIZE = "firmware/flash_page_size"
_XML_HARDWARE_VERSION = "firmware/hw_version"
_XML_REGION_LOCK = "firmware/region"
_XML_UPDATE_TIMEOUT = "firmware/update_timeout_ms"

_XMODEM_READY_TO_RECEIVE_CHAR = "C"
_XMODEM_START_TIMEOUT = 3  # seconds

_ZDO_COMMAND_ID_IMG_NOTIFY_REQ = 0x00
_ZDO_COMMAND_ID_QUERY_NEXT_IMG_REQ = 0x01
_ZDO_COMMAND_ID_QUERY_NEXT_IMG_RESP = 0x02
_ZDO_COMMAND_ID_IMG_BLOCK_REQ = 0x03
_ZDO_COMMAND_ID_IMG_BLOCK_RESP = 0x05
_ZDO_COMMAND_ID_UPGRADE_END_REQ = 0x06
_ZDO_COMMAND_ID_UPGRADE_END_RESP = 0x07
_ZDO_COMMAND_ID_DEFAULT_RESP = 0x0B

_ZDO_FRAME_CONTROL_CLIENT_TO_SERVER = 0x01

_XB3_ZIGBEE_FW_VERSION_LIMIT_FOR_GBL = 0x1003

# Since the following versions (they included), the XBee firmware includes
# client retries for the same block offset if, for any reason, the block is not
# received (or it is corrupted)
_XB3_FW_VERSION_LIMIT_FOR_CLIENT_RETRIES = {
    XBeeProtocol.ZIGBEE: 0x1009,
    XBeeProtocol.DIGI_MESH: 0x300A,
    XBeeProtocol.RAW_802_15_4: 0x200A
}

# Since the following versions (they included) the complete OTA file (including
# the header) must be sent to the client when blocks are requested.
_XB3_FW_VERSION_LIMIT_SKIP_OTA_HEADER = {
    XBeeProtocol.ZIGBEE: 0x100A,
    XBeeProtocol.DIGI_MESH: 0x300A,
    XBeeProtocol.RAW_802_15_4: 0x200A
}

_XB3_PROTOCOL_FROM_FW_VERSION = {
     0x1: XBeeProtocol.ZIGBEE,
     0x2: XBeeProtocol.RAW_802_15_4,
     0x3: XBeeProtocol.DIGI_MESH
}

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
        self._ota_size = None
        self._gbl_size = None
        self._discard_size = 0
        self._file = None
        self._min_hw_version = 0
        self._max_hw_version = 0xFFFF

    def parse_file(self):
        """
        Parses the OTA file and stores useful information of the file.

        Raises:
            _ParsingOTAException: if there is any problem parsing the OTA file.
        """
        _log.debug("Parsing OTA firmware file %s:", self._file_path)
        if not _file_exists(self._file_path) or (not self._file_path.endswith(_EXTENSION_OTA) and
                                                 not self._file_path.endswith(_EXTENSION_OTB)):
            raise _ParsingOTAException(_ERROR_INVALID_OTA_FILE % self._file_path)

        try:
            with open(self._file_path, "rb") as file:
                identifier = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                if identifier != _OTA_FILE_IDENTIFIER:
                    raise _ParsingOTAException(_ERROR_NOT_OTA_FILE % self._file_path)
                _log.debug(" - Identifier: %04X (%d)", identifier, identifier)
                h_version = _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT))
                self._header_version = utils.bytes_to_int(h_version)
                _log.debug(" - Header version: %d.%d (%04X - %d)", h_version[0], h_version[1],
                           self._header_version, self._header_version)
                self._header_length = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header length: %d", self._header_length)
                # Bit mask to indicate whether additional information are included in the OTA image:
                #    * Bit 0: Security credential version present
                #    * Bit 1: Device specific file
                #    * Bit 2: Hardware versions presents
                self._header_field_control = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header field control: %d", self._header_field_control)
                self._manufacturer_code = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Manufacturer code: %04X (%d)", self._manufacturer_code, self._manufacturer_code)
                self._image_type = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Image type: %s (%d)", "Firmware" if not self._image_type else "File system", self._image_type)
                f_version = _reverse_bytearray(file.read(_BUFFER_SIZE_INT))
                self._file_version = utils.bytes_to_int(f_version)
                _log.debug(" - File version: %s (%d)", utils.hex_to_string(f_version), self._file_version)
                _log.debug("    - Compatibility: %d", f_version[0])
                _log.debug("    - Firmware version: %s", utils.hex_to_string(f_version[1:], pretty=False))
                self._zigbee_stack_version = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Zigbee stack version: %d", self._zigbee_stack_version)
                if utils.bytes_to_int(f_version[1:]) < _XB3_FW_VERSION_LIMIT_SKIP_OTA_HEADER[_XB3_PROTOCOL_FROM_FW_VERSION[f_version[2] >> 4]]:
                    self._header_string = _reverse_bytearray(file.read(_BUFFER_SIZE_STRING)).decode(encoding="utf-8")
                else:
                    self._header_string = file.read(_BUFFER_SIZE_STRING).decode(encoding="utf-8")
                _log.debug(" - Header string: %s", self._header_string)
                self._ota_size = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - OTA size: %d", self._ota_size)
                if self._header_field_control & 0x01:
                    _log.debug(" - Security credential version: %d", utils.bytes_to_int(file.read(1)))
                if self._header_field_control & 0x02:
                    _log.debug(" - Upgrade file destination: %s", utils.hex_to_string(
                        _reverse_bytearray(file.read(_BUFFER_SIZE_IEEE_ADDR))))
                if self._header_field_control & 0x04:
                    self._min_hw_version = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                    self._max_hw_version = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                    _log.debug(" - Minimum hardware version: %02X (%d)", self._min_hw_version, self._min_hw_version)
                    _log.debug(" - Maximum hardware version: %02X (%d)", self._max_hw_version, self._max_hw_version)
                self._gbl_size = self._ota_size - self._header_length - _OTA_GBL_SIZE_BYTE_COUNT
                _log.debug(" - GBL size: %d", self._gbl_size)
                self._total_size = os.path.getsize(self._file_path)
                _log.debug(" - File size: %d", self._total_size)
                self._discard_size = self._header_length + _OTA_GBL_SIZE_BYTE_COUNT
                _log.debug(" - Discard size: %d", self._discard_size)
        except IOError as e:
            raise _ParsingOTAException(_ERROR_PARSING_OTA_FILE % str(e))

    def get_next_data_chunk(self, offset, size):
        """
        Returns the next data chunk of this file.

        Args:
            offset (Integer): Starting offset to read.
            size (Integer): The number of bytes to read.

        Returns:
            Bytearray: the next data chunk of the file as byte array.

        Raises:
            _ParsingOTAException: if there is any error reading the OTA file.
        """
        try:
            if self._file is None:
                self._file = open(self._file_path, "rb")
            self._file.seek(offset)
            return self._file.read(size)
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
        Returns the OTA file image type: 0x0000 for firmware, 0x0100 for file system

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
    def discard_size(self):
        """
        Returns the number of bytes to discard of the OTA file.

        Returns:
            Integer: the number of bytes.
        """
        return self._discard_size

    @property
    def ota_size(self):
        """
        Returns the number of bytes to transmit over the air.

        Returns:
            Integer: the number of bytes.
        """
        return self._ota_size

    @property
    def min_hw_version(self):
        """
        Returns the minimum hardware version this file is for.

        Returns:
             Integer: The minimum firmware version.
        """
        return self._min_hw_version

    @property
    def max_hw_version(self):
        """
        Returns the maximum hardware version this file is for.

        Returns:
             Integer: The maximum firmware version.
        """
        return self._max_hw_version


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
    OUT_OF_SEQUENCE = (0x01, "ZCL OTA message out of sequence")
    ERASE_FAILED = (0x05, "Storage erase failed")
    REQUEST_DENIED = (0x70, "OTA updates have been disabled on the remote")
    NOT_AUTHORIZED = (0x7E, "Server is not authorized to update the client")
    MALFORMED_COMMAND = (0x80, "Received is badly formatted or has incorrect parameters")
    UNSUP_CLUSTER_COMMAND = (0x81, "Unsupported cluster command")
    INVALID_FIELD = (0x85, "Attempting to update to incompatible firmware")
    INVALID_VALUE = (0x87, "Upgrade File Mismatch")
    INSUFFICIENT_SPACE = (0x89, "Image size is too big")
    DUPLICATE_EXISTS = (0x8A, "Please ensure that the image you are attempting to "
                              "update has a different version than the current version")
    TIMEOUT = (0x94, "Client timed out")
    ABORT = (0x95, "Client or server aborted the update")
    INVALID_IMAGE = (0x96, "Invalid OTA update image")
    WAIT_FOR_DATA = (0x97, "Server does not have data block available yet")
    NO_IMAGE_AVAILABLE = (0x98, "No OTA update image available")
    REQUIRE_MORE_IMAGE = (0x99, "Client requires more image files to successfully update")

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
        self._xml_firmware_version = None
        self._xml_compatibility_number = None
        self._xml_bootloader_version = None
        self._xml_region_lock = None
        self._xml_update_timeout_ms = None
        self._xml_flash_page_size = None
        self._bootloader_update_required = False
        self._timeout = timeout
        self._protocol_changed = False
        self._updated = False
        self._bootloader_updated = False
        self._bootloader_reset_settings = False

    def _parse_xml_firmware_file(self):
        """
        Parses the XML firmware file and stores the required parameters.

        Raises:
            FirmwareUpdateException: if there is any error parsing the XML firmware file.
        """
        _log.debug("Parsing XML firmware file %s:", self._xml_firmware_file)
        try:
            root = ElementTree.parse(self._xml_firmware_file).getroot()
            # Firmware version, required.
            element = root.find(_XML_FIRMWARE)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_firmware_version = int(element.get(_XML_FIRMWARE_VERSION_ATTRIBUTE), 16)
            _log.debug(" - Firmware version: %d", self._xml_firmware_version)
            # Hardware version, required.
            element = root.find(_XML_HARDWARE_VERSION)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_hardware_version = int(element.text, 16)
            _log.debug(" - Hardware version: %d", self._xml_hardware_version)
            # Compatibility number, required.
            element = root.find(_XML_COMPATIBILITY_NUMBER)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_compatibility_number = int(element.text)
            _log.debug(" - Compatibility number: %d", self._xml_compatibility_number)
            # Bootloader version, optional.
            element = root.find(_XML_BOOTLOADER_VERSION)
            if element is not None:
                self._xml_bootloader_version = _bootloader_version_to_bytearray(element.text)
            _log.debug(" - Bootloader version: %s", self._xml_bootloader_version)
            # Region lock, required.
            element = root.find(_XML_REGION_LOCK)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_region_lock = int(element.text)
            _log.debug(" - Region lock: %d", self._xml_region_lock)
            # Update timeout, optional.
            element = root.find(_XML_UPDATE_TIMEOUT)
            if element is not None:
                self._xml_update_timeout_ms = int(element.text)
            _log.debug(" - Update timeout: %s", self._xml_update_timeout_ms)
            # Flash page size, optional.
            element = root.find(_XML_FLASH_PAGE_SIZE)
            if element is not None:
                self._xml_flash_page_size = int(element.text, 16)
            _log.debug(" - Flash page size: %s bytes", self._xml_flash_page_size)
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
                _log.error("ERROR: %s", _ERROR_RESTORE_TARGET_CONNECTION % str(e))
        _log.error("ERROR: %s", message)
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
        _log.debug(" - Firmware version: %s", self._target_firmware_version)
        self._target_hardware_version = self._get_target_hardware_version()
        _log.debug(" - Hardware version: %s", self._target_hardware_version)
        self._target_compatibility_number = self._get_target_compatibility_number()
        _log.debug(" - Compatibility number: %s", self._target_compatibility_number)
        self._target_bootloader_version = self._get_target_bootloader_version()
        _log.debug(" - Bootloader version: %s", self._target_bootloader_version)
        self._target_region_lock = self._get_target_region_lock()
        _log.debug(" - Region lock: %s", self._target_region_lock)

        # Check if the hardware version is compatible with the firmware update process.
        if self._target_hardware_version and self._target_hardware_version not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

        # Check if device hardware version is compatible with the firmware.
        if self._target_hardware_version and self._target_hardware_version != self._xml_hardware_version:
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

        # Check whether bootloader reset the device settings.
        self._bootloader_reset_settings = self._check_bootloader_reset_settings()

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
        return self._xml_bootloader_version > self._target_bootloader_version

    def _check_bootloader_reset_settings(self):
        """
        Checks whether the bootloader performed a reset of the device settings or not

        Returns:
            Boolean: ``True`` if the bootloader performed a reset of the device settings, ``False`` otherwise
        """
        if not self._bootloader_update_required:
            return False

        # On XBee 3 devices with a bootloader version below 1.6.6, updating the bootloader implies a reset
        # of the module settings. Return True if the device bootloader version was below 1.6.6.
        return self._target_bootloader_version < _BOOTLOADER_XBEE3_RESET_ENV_VERSION

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

        # Check whether protocol will change or not.
        self._protocol_changed = self._will_protocol_change()

        # Configure the updater device.
        self._configure_updater()

        # Check if updater is able to perform firmware updates.
        self._check_updater_compatibility()

        # Check if target is compatible with the firmware to update.
        self._check_target_compatibility()

        # Check bootloader update file exists if required.
        _log.debug("Bootloader update required? %s", self._bootloader_update_required)
        if self._bootloader_update_required:
            self._check_bootloader_binary_file()

        # Start the firmware update process.
        self._start_firmware_update()

        # Transfer firmware file(s).
        self._transfer_firmware()

        # Finish the firmware update process.
        self._finish_firmware_update()

        # Wait for target to reset.
        self._wait_for_target_reset()

        # Flag the device as updated.
        self._updated = True

        # Leave updater in its original state.
        try:
            self._restore_updater()
        except Exception as e:
            raise FirmwareUpdateException(_ERROR_RESTORE_TARGET_CONNECTION % str(e))

        # Update target information.
        self._update_target_information()

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

    @abstractmethod
    def _update_target_information(self):
        """
        Updates the target information after the firmware update.
        """
        pass

    @abstractmethod
    def _will_protocol_change(self):
        """
        Determines whether the XBee protocol will change after the update or not.

        Returns:
            Boolean: ``True`` if the protocol will change after the update, ``False`` otherwise.
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
                _log.debug("Opening port '%s'", self._port)
                self._xbee_serial_port = XBeeSerialPort(_BOOTLOADER_PORT_PARAMETERS["baudrate"],
                                                        self._port,
                                                        data_bits=_BOOTLOADER_PORT_PARAMETERS["bytesize"],
                                                        stop_bits=_BOOTLOADER_PORT_PARAMETERS["stopbits"],
                                                        parity=_BOOTLOADER_PORT_PARAMETERS["parity"],
                                                        flow_control=FlowControl.NONE,
                                                        timeout=_BOOTLOADER_PORT_PARAMETERS["timeout"])
                self._xbee_serial_port.open()
            except SerialException as e:
                _log.error(_ERROR_CONNECT_SERIAL_PORT, str(e))
                raise FirmwareUpdateException(_ERROR_CONNECT_SERIAL_PORT % str(e))

            # Check if device is in bootloader mode.
            _log.debug("Checking if bootloader is active")
            if not self._is_bootloader_active():
                # If the bootloader is not active, enter in bootloader mode.
                if not self._enter_bootloader_mode_with_break():
                    self._exit_with_error(_ERROR_BOOTLOADER_MODE)
        else:
            self._updater_was_connected = self._xbee_device.is_open()
            _log.debug("Connecting device '%s'", self._xbee_device)
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
            if (self._updated and self._protocol_changed) or \
                    (self._bootloader_updated and self._bootloader_reset_settings):
                # Since the protocol has changed or an old bootloader was updated, a forced port open is
                # required because all the configured settings are restored to default values, including
                # the serial communication ones.
                self._xbee_device.close()
                self._xbee_device.open(force_settings=True)
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
            # Wait some time to initialize the bootloader.
            _log.debug("Setting up bootloader...")
            time.sleep(_BOOTLOADER_INITIALIZATION_TIME)
            # Execute the run operation so that new bootloader is applied and executed. Give it some time afterwards.
            self._run_firmware_operation()
            time.sleep(_BOOTLOADER_INITIALIZATION_TIME)
            self._bootloader_updated = True

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

    def _update_target_information(self):
        """
        Updates the target information after the firmware update.
        """
        _log.debug("Updating target information...")
        if not self._xbee_device:
            return

        # If the protocol of the device has changed, clear the network.
        if self._protocol_changed:
            self._xbee_device.get_network()._clear(NetworkEventReason.FIRMWARE_UPDATE)
        # Read device information again.
        was_open = self._xbee_device.is_open()
        try:
            if not was_open:
                self._xbee_device.open()
            self._xbee_device._read_device_info(NetworkEventReason.FIRMWARE_UPDATE, init=True, fire_event=True)
        except XBeeException as e:
            raise FirmwareUpdateException(_ERROR_UPDATE_TARGET_INFORMATION % str(e))
        finally:
            if not was_open:
                self._xbee_device.close()

    def _will_protocol_change(self):
        """
        Determines whether the XBee protocol will change after the update or not.

        Returns:
            Boolean: ``True`` if the protocol will change after the update, ``False`` otherwise.
        """
        if not self._xbee_device:
            return False  # No matter what we return here, it won't be used.

        orig_protocol = self._xbee_device.get_protocol()
        new_protocol = XBeeProtocol.determine_protocol(self._xml_hardware_version,
                                                       utils.int_to_bytes(self._xml_firmware_version))
        return orig_protocol != new_protocol

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
            _log.debug("Sending bootloader run operation...")
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
            _log.info("File transfer was cancelled by the remote end, retrying...")
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
                 timeout=_READ_DATA_TIMEOUT, max_block_size=0, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteFirmwareUpdater` with the given parameters.

        Args:
            remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
            xml_firmware_file (String): path of the XML file that describes the firmware to upload.
            ota_firmware_file (String, optional): path of the OTA firmware file to upload.
            otb_firmware_file (String, optional): path of the OTB firmware file to upload (bootloader bundle).
            timeout (Integer, optional): the timeout to wait for remote frame requests.
            max_block_size (Integer, optional): Maximum size in bytes of the ota block to send.
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
        self._updater_ao_value = None
        self._updater_my_value = None
        self._updater_rr_value = None
        self._ota_file = None
        self._receive_lock = Event()
        self._transfer_lock = Event()
        self._img_req_received = False
        self._img_notify_sent = False
        self._transfer_status = None
        self._response_string = None
        self._requested_offset = -1
        self._max_chunk_size = _OTA_DEFAULT_BLOCK_SIZE
        self._seq_number = 1
        self._cfg_max_block_size = max_block_size
        self._update_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        if not self._cfg_max_block_size:
            self._cfg_max_block_size = 0xFFFFFFFF

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
        _log.debug("Connecting device '%s'", self._local_device)
        if not _connect_device_with_retries(self._local_device, _DEVICE_CONNECTION_RETRIES):
            self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES)
        # Store AO value.
        self._updater_ao_value = _read_device_parameter_with_retries(self._local_device, ATStringCommand.AO.command)
        if self._updater_ao_value is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.AO.command)
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

    @staticmethod
    def _calculate_frame_control(frame_type=1, manufac_specific=False,
                                 dir_srv_to_cli=True, disable_def_resp=True):
        """
        Calculates the value of the frame control field based on the provided parameters.

        Args:
            frame_type (Integer, optional, default=1): 1 if command is global for all
                clusters, 0 if it is specific or local to a cluster.
            manufac_specific (Boolean, optional, default=`False`): `True` if
                manufacturer code is present in the ZCL header (does not refer
                to the code in the ZCL payload). `False` otherwise.
            dir_srv_to_cli (Boolean, optional, default=`True`): `True` if the command
                is sent from the server to the client. `False` if sent from the
                client to the server.
            disable_def_resp (Boolean, optional, default=`True`): `True` to disable
                default response.

        Returns:
            Integer: The value of the frame control field.
        """
        # Frame control field format:
        #    * Bits 0-1: Frame type
        #    * Bit 2: Manufacturer specific
        #    * Bit 3: Direction
        #    * Bit 4: Disable default response
        #    * Bits 5-7: Reserved

        # Frame type:
        #    * 00: Command is global for all clusters, including manufacturer specific clusters
        #    * 01: Command is specific or local to a cluster
        #    * Other values: Reserved
        frame_control = frame_type
        # Manufacturer specific:
        #    * False (0): manufacturer code is not present in the ZCL header (does not refer to the ZCL payload)
        #    * True (1): manufacturer code is present in the ZCL header (does not refer to the ZCL payload)
        if manufac_specific:
            frame_control |= 0x04
        # Direction:
        #    * False (0): sent from client to server
        #    * True (1): sent from server to client
        if dir_srv_to_cli:
            frame_control |= 0x08
        # Disable default response:
        #    * False (0): Default response is enabled
        #    * True (1): Default response is disabled
        if disable_def_resp:
            frame_control |= 0x10

        return frame_control

    def _create_image_notify_request_frame(self):
        """
        Creates and returns an image notify request frame for the firmware to transfer.

        Returns:
            Bytearray: the image notify request frame.
        """
        payload = bytearray()
        # Indicate which fields are present: Query Jitter, Manufacturer Code, Image Type, File Version
        payload.append(_NOTIFY_PACKET_PAYLOAD_TYPE & 0xFF)
        # Query jitter: 0-100. If the parameters in the received notify command (manufacturer
        # and image type) matches with the client owns values, it determines whether query
        # the server by randomly choosing a number between 1 and 100 and comparing with the
        # received query jitter:
        #   * If client number <= query jitter then it continues the process
        #   * If client number > query jitter then it discards the command and don not continue
        # For unicast (the only one we currently support) we choose the maximum value 100, although
        # the client shall always send a Query Next Image request to the server on receip of a
        # unicast Image Notify command.
        payload.append(_NOTIFY_PACKET_DEFAULT_QUERY_JITTER & 0xFF)
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))

        return self._create_zdo_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=False),
            _PACKET_DEFAULT_SEQ_NUMBER, _ZDO_COMMAND_ID_IMG_NOTIFY_REQ, payload)

    def _create_query_next_image_response_frame(self, status=_XBee3OTAStatus.SUCCESS):
        """
        Creates and returns a query next image response frame.

        Args:
            status (:class:`._XBee3OTAStatus`, optional, default=`_XBee3OTAStatus.SUCCESS`): The
                status to send. It can be: `_XBee3OTAStatus.SUCCESS`,
                `_XBee3OTAStatus.NOT_AUTHORIZED`, `_XBee3OTAStatus.NO_IMG_AVAILABLE`

        Returns:
            Bytearray: the query next image response frame.
        """
        image_size = self._get_ota_size()
        # If the remote module is an XBee3 using ZigBee protocol and the firmware version
        # is 1003 or lower, use the OTA GBL size instead of total size (exclude header size).
        if self._remote_device.get_protocol() == XBeeProtocol.ZIGBEE and \
                self._target_hardware_version in SUPPORTED_HARDWARE_VERSIONS and \
                self._target_firmware_version < _XB3_ZIGBEE_FW_VERSION_LIMIT_FOR_GBL:
            image_size = self._ota_file.gbl_size

        payload = bytearray()
        # The status could be:
        #    * _XBee3OTAStatus.SUCCESS (0x00): An image is available
        #    * _XBee3OTAStatus.NOT_AUTHORIZED (0x7E): This server isn't authorized to perform an upgrade
        #    * _XBee3OTAStatus.NO_IMG_AVAILABLE (0x98): No upgrade image is available
        payload.append(status.identifier & 0xFF)
        # Following fields only for _XBee3OTAStatus.SUCCESS
        if status == _XBee3OTAStatus.SUCCESS:
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))
            payload.extend(_reverse_bytearray(utils.int_to_bytes(image_size, 4)))

        return self._create_zdo_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=True),
            self._seq_number, _ZDO_COMMAND_ID_QUERY_NEXT_IMG_RESP, payload)

    def _create_image_block_response_frame(self, file_offset, size, seq_number, status=_XBee3OTAStatus.SUCCESS):
        """
        Creates and returns an image block response frame.

        Args:
            file_offset (Integer): the file offset to send.
            size (Integer): The number of bytes to send.
            seq_number (Integer): sequence number to be used for the response.
            status (:class:`._XBee3OTAStatus`, optional, default=`_XBee3OTAStatus.SUCCESS`): The
                status to send. It can be: `_XBee3OTAStatus.SUCCESS`, `_XBee3OTAStatus.ABORT`,
                `_XBee3OTAStatus.WAIT_FOR_DATA` (this last is not supported)

        Returns:
            Bytearray: the image block response frame.

        Raises:
            FirmwareUpdateException: if there is any error generating the image block response frame.
        """
        try:
            data_block = self._ota_file.get_next_data_chunk(self._get_ota_offset(file_offset), size)
        except _ParsingOTAException as e:
            raise FirmwareUpdateException(_ERROR_READ_OTA_FILE % str(e))
        payload = bytearray()
        # This status could be:
        #    * _XBee3OTAStatus.SUCCESS (0x00): Image data is available
        #    * _XBee3OTAStatus.ABORT (0x95): Instructs the client to abort the download
        #    * _XBee3OTAStatus.WAIT_FOR_DATA (0x97) is not supported (see ZCL Spec §11.13.8.1)
        payload.append(status.identifier & 0xFF)
        # Following fields only if status is not _XBee3OTAStatus.ABORT
        if status != _XBee3OTAStatus.ABORT:
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))
            payload.extend(_reverse_bytearray(utils.int_to_bytes(file_offset, 4)))
            if data_block:
                payload.append(len(data_block) & 0xFF)
                payload.extend(data_block)
            else:
                payload.extend(utils.int_to_bytes(0))
            _log.debug("Sending 'Image block response' frame for offset %s/%s (size %d)",
                       file_offset, self._get_ota_size(), len(data_block))
        else:
            _log.debug("Sending 'Image block response' frame for with status %d (%s)",
                       status.identifier, status.description)

        return self._create_zdo_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=True),
            seq_number, _ZDO_COMMAND_ID_IMG_BLOCK_RESP, payload)

    def _create_upgrade_end_response_frame(self):
        """
        Creates and returns an upgrade end response frame.

        Returns:
            Bytearray: the upgrade end response frame.
        """
        current_time = utils.int_to_bytes(int(time.time()) - _TIME_SECONDS_1970_TO_2000, 4)

        payload = bytearray()
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(utils.int_to_bytes(self._ota_file.file_version, 4)))
        # The current time, used for scheduled upgrades
        payload.extend(_reverse_bytearray(current_time))
        # The scheduled upgrade time, used for scheduled upgrades
        payload.extend(_reverse_bytearray(current_time))

        return self._create_zdo_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=True),
            self._seq_number, _ZDO_COMMAND_ID_UPGRADE_END_RESP, payload)

    def _image_request_frame_callback(self, xbee_frame):
        """
        Callback used to be notified when the image request frame is received by
        the target device and it is ready to start receiving image frames.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the received packet
        """
        if xbee_frame.get_frame_type() == ApiFrameType.TRANSMIT_STATUS:
            _log.debug("Received 'Image notify' status frame: %s", xbee_frame.transmit_status.description)
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
        elif (xbee_frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR
              and xbee_frame.source_endpoint == _EXPLICIT_PACKET_ENDPOINT_DATA
              and xbee_frame.dest_endpoint == _EXPLICIT_PACKET_ENDPOINT_DATA
              and xbee_frame.cluster_id == _EXPLICIT_PACKET_CLUSTER_ID
              and xbee_frame.profile_id == _EXPLICIT_PACKET_PROFILE_DIGI
              and xbee_frame.x64bit_source_addr == self._remote_device.get_64bit_addr()):
            if self._img_req_received:
                return
            if self._is_next_img_req_frame(xbee_frame):
                _log.debug("Received 'Query next image' request frame")
                self._img_req_received = True
                server_status, self._seq_number = self._parse_next_img_req_frame(xbee_frame)
            elif self._is_default_response_frame(xbee_frame, self._seq_number):
                _log.debug("Received 'Default response' frame")
                # If the received frame is a 'default response' frame, set the corresponding error.
                ota_command, status = self._parse_default_response_frame(xbee_frame, self._seq_number)
                self._response_string = status.description if status is not None \
                    else _ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR
            else:
                # This is not the explicit frame we were expecting, keep on listening.
                return

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
        if (xbee_frame.get_frame_type() != ApiFrameType.EXPLICIT_RX_INDICATOR
                or xbee_frame.source_endpoint != _EXPLICIT_PACKET_ENDPOINT_DATA
                or xbee_frame.dest_endpoint != _EXPLICIT_PACKET_ENDPOINT_DATA
                or xbee_frame.cluster_id != _EXPLICIT_PACKET_CLUSTER_ID
                or xbee_frame.profile_id != _EXPLICIT_PACKET_PROFILE_DIGI
                or xbee_frame.x64bit_source_addr != self._remote_device.get_64bit_addr()):
            return

        # Check the type of frame received.
        if self._is_image_block_request_frame(xbee_frame):
            # If the received frame is an 'image block request' frame, retrieve the requested index.
            server_status, max_data_size, f_offset, self._seq_number = self._parse_image_block_request_frame(xbee_frame)
            if server_status == _XBee3OTAStatus.SUCCESS:
                # Check if OTA file chunk size must be updated.
                if max_data_size != self._max_chunk_size:
                    self._max_chunk_size = min(max_data_size, self._cfg_max_block_size)
                self._requested_offset = f_offset
                _log.debug("Received 'Image block request' frame for file offset %s", f_offset)
            else:
                _log.debug("Received bad 'Image block request' frame, status to send: %s (%d)",
                           server_status.description, server_status.identifier)
        elif self._is_upgrade_end_request_frame(xbee_frame):
            _log.debug("Received 'Upgrade end request' frame")
            # If the received frame is an 'upgrade end request' frame, set transfer status.
            server_status, status, self._seq_number = self._parse_upgrade_end_request_frame(xbee_frame)
            if server_status == _XBee3OTAStatus.SUCCESS:
                self._transfer_status = status
            else:
                _log.debug("Received bad 'Upgrade end request' frame, status to send: %s (%d)",
                           server_status.description, server_status.identifier)
        elif self._is_default_response_frame(xbee_frame, self._seq_number):
            _log.debug("Received 'Default response' frame")
            # If the received frame is a 'default response' frame, set the corresponding error.
            ota_command, status = self._parse_default_response_frame(xbee_frame, self._seq_number)
            self._response_string = status.description if status is not None \
                else _ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR
        else:
            return
        # Notify transfer thread to continue.
        self._transfer_lock.set()

    def _check_img_data(self, payload):
        """
        Checks if the manufacturer code, image type, and firmware version in the
        provided payload are valid.

        Args:
            payload (Bytearray): The payload to check.

        Returns:
             :class:`_XBee3OTAStatus`: The status after parsing the values.
        """
        server_status = _XBee3OTAStatus.SUCCESS
        man_code = utils.bytes_to_int(_reverse_bytearray(payload[4:6]))
        img_type = utils.bytes_to_int(_reverse_bytearray(payload[6:8]))
        fw_version = utils.bytes_to_int(_reverse_bytearray(payload[8:11]))
        compatibility_number = payload[11] & 0xFF

        # Check manufacturer:
        if man_code != self._ota_file.manufacturer_code:
            server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE
        # Check image type:
        #    0x0000: firmware upgrade
        #    0x0100: file system upgrade
        elif img_type != self._ota_file.image_type:
            server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE
        # Check compatibility number
        elif compatibility_number > utils.int_to_bytes(self._ota_file.file_version, _BUFFER_SIZE_INT)[0]:
            server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE

        return server_status

    @staticmethod
    def _is_next_img_req_frame(xbee_frame):
        """
        Returns whether the given payload is valid for an image request received frame.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.

        Returns:
            Boolean: `True` if the frame is a next image request frame, `False` otherwise.
        """
        payload = xbee_frame.rf_data
        return (len(payload) > 2 and payload[0] == _ZDO_FRAME_CONTROL_CLIENT_TO_SERVER
                and payload[2] == _ZDO_COMMAND_ID_QUERY_NEXT_IMG_REQ)

    def _parse_next_img_req_frame(self, xbee_frame):
        """
        Parses the given next image request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Tuple (:class:`_XBee3OTAStatus`, Integer): The status after parsing the values
                and the sequence number of the block request frame. `None` if parsing failed.
        """
        if not self._is_next_img_req_frame(xbee_frame):
            return None

        payload = xbee_frame.rf_data
        sequence_number = payload[1] & 0xFF

        if (len(payload) < _NOTIFY_PACKET_PAYLOAD_SIZE
                # Includes the hardware version
                or (payload[3] & 0xFF == 1 and len(payload) != _NOTIFY_PACKET_PAYLOAD_SIZE + 2)
                # Does not include the hardware version
                or (payload[3] & 0xFF == 0 and len(payload) != _NOTIFY_PACKET_PAYLOAD_SIZE)):
            return _XBee3OTAStatus.MALFORMED_COMMAND, sequence_number

        server_status = self._check_img_data(payload)
        # Field control: indicates if hardware version is available
        if server_status == _XBee3OTAStatus.SUCCESS and payload[3] & 0xFF:
            hw_version = utils.bytes_to_int(_reverse_bytearray(payload[12:14]))
            if hw_version < self._ota_file.min_hw_version or hw_version > self._ota_file.max_hw_version:
                server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE

        return server_status, sequence_number

    @staticmethod
    def _is_image_block_request_frame(xbee_frame):
        """
        Returns whether the given frame is an image block request frame or not.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.

        Returns:
            Boolean: `True` if the frame is an image block request frame, `False` otherwise.
        """
        payload = xbee_frame.rf_data
        return (len(payload) > 2 and payload[0] == _ZDO_FRAME_CONTROL_CLIENT_TO_SERVER
                and payload[2] == _ZDO_COMMAND_ID_IMG_BLOCK_REQ)

    def _parse_image_block_request_frame(self, xbee_frame):
        """
        Parses the given image block request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Tuple (:class:`_XBee3OTAStatus`, Integer, Integer, Integer): The status
                after parsing the values, the max data size, the file offset and
                the sequence number of the block request frame. `None` if parsing failed.
        """
        if not self._is_image_block_request_frame(xbee_frame):
            return None

        payload = xbee_frame.rf_data
        sequence_number = payload[1] & 0xFF

        # The frame control indicates if there are additional optional fields
        # Currently XBee 3 does not use any of those fields
        if len(payload) != _IMAGE_BLOCK_REQUEST_PACKET_PAYLOAD_SIZE:
            server_status = _XBee3OTAStatus.MALFORMED_COMMAND
            server_status.cmd = _ZDO_COMMAND_ID_IMG_BLOCK_REQ
            return server_status, 0, 0, sequence_number

        server_status = self._check_img_data(payload)

        file_offset = utils.bytes_to_int(_reverse_bytearray(payload[12:16]))
        if server_status == _XBee3OTAStatus.SUCCESS and file_offset >= self._get_ota_size():
            server_status = _XBee3OTAStatus.MALFORMED_COMMAND
            server_status.cmd = _ZDO_COMMAND_ID_IMG_BLOCK_REQ

        max_data_size = payload[16] & 0xFF

        return server_status, max_data_size, file_offset, sequence_number

    @staticmethod
    def _is_upgrade_end_request_frame(xbee_frame):
        """
        Returns whether the given frame is an upgrade end request frame or not.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.

        Returns:
            Boolean: `True` if the frame is an upgrade end request frame, `False` otherwise.
        """
        payload = xbee_frame.rf_data
        return (len(payload) > 2
                and payload[0] == _ZDO_FRAME_CONTROL_CLIENT_TO_SERVER
                and payload[2] == _ZDO_COMMAND_ID_UPGRADE_END_REQ)

    def _parse_upgrade_end_request_frame(self, xbee_frame):
        """
        Parses the given upgrade end request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Tuple (:class:`_XBee3OTAStatus`, :class:`_XBee3OTAStatus`, Integer): The status after
                parsing the values, the upgrade end request status and the sequence
                number of the block request frame, `None` if parsing failed.
        """
        if not self._is_upgrade_end_request_frame(xbee_frame):
            return None

        payload = xbee_frame.rf_data
        sequence_number = payload[1] & 0xFF

        if len(payload) != _UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE:
            server_status = _XBee3OTAStatus.MALFORMED_COMMAND
            server_status.cmd = _ZDO_COMMAND_ID_UPGRADE_END_REQ
            return _XBee3OTAStatus.MALFORMED_COMMAND, 0, sequence_number

        server_status = self._check_img_data(payload)

        status = _XBee3OTAStatus.get(payload[3] & 0xFF)
        if not status:
            server_status = _XBee3OTAStatus.MALFORMED_COMMAND
            server_status.cmd = _ZDO_COMMAND_ID_UPGRADE_END_REQ
        else:
            status.cmd = _ZDO_COMMAND_ID_UPGRADE_END_REQ

        return server_status, status, sequence_number

    @staticmethod
    def _is_default_response_frame(xbee_frame, seq_number):
        """
        Returns whether the given frame is a default response frame or not.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to check.
            seq_number (Integer): The sequence number of the last frame sent.

        Returns:
            Boolean: `True` if the frame is a default response frame, `False` otherwise.
        """
        payload = xbee_frame.rf_data
        disable_def_resp = _RemoteFirmwareUpdater._calculate_frame_control(frame_type=0,
                                                                           manufac_specific=False,
                                                                           dir_srv_to_cli=False,
                                                                           disable_def_resp=True)
        enable_def_resp = _RemoteFirmwareUpdater._calculate_frame_control(frame_type=0,
                                                                          manufac_specific=False,
                                                                          dir_srv_to_cli=False,
                                                                          disable_def_resp=False)
        return (len(payload) > 2
                and (payload[0] in [disable_def_resp, enable_def_resp])
                and payload[1] == seq_number
                and payload[2] == _ZDO_COMMAND_ID_DEFAULT_RESP)

    def _parse_default_response_frame(self, xbee_frame, seq_number):
        """
        Parses the given image block request frame and returns the frame values.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.
            seq_number (Integer): The sequence number of the last frame sent.

        Returns:
            Tuple (Integer, :class:`._XBee3OTAStatus`): The OTA command and the
                status of the default response frame. `None` if parsing failed.
        """
        if not self._is_default_response_frame(xbee_frame, seq_number):
            return None

        payload = xbee_frame.rf_data
        ota_command = payload[3] & 0xFF
        status = _XBee3OTAStatus.get(payload[4] & 0xFF)

        return ota_command, status

    def _send_query_next_img_response(self, status=_XBee3OTAStatus.SUCCESS):
        """
        Sends the query next image response frame.

        Args:
            status (:class:`._XBee3OTAStatus`, optional, default=`_XBee3OTAStatus.SUCCESS`): The
                status to send.

        Raises:
            FirmwareUpdateException: if there is any error sending the next image response frame.
        """
        retries = _SEND_BLOCK_RETRIES
        query_next_image_response_frame = self._create_query_next_image_response_frame(status=status)
        while retries > 0:
            try:
                _log.debug("Sending 'Query next image response' frame")
                status_frame = self._local_device.send_packet_sync_and_get_response(query_next_image_response_frame)
                if not isinstance(status_frame, TransmitStatusPacket):
                    retries -= 1
                    continue
                _log.debug("Received 'Query next image response' status frame: %s",
                           status_frame.transmit_status.description)
                if status_frame.transmit_status != TransmitStatus.SUCCESS:
                    retries -= 1
                    continue
                return
            except XBeeException as e:
                raise FirmwareUpdateException(_ERROR_SEND_FRAME_RESPONSE % ("Query next image response", str(e)))

        raise FirmwareUpdateException(_ERROR_SEND_FRAME_RESPONSE % ("Query next image response", "Timeout sending frame"))

    def _send_ota_block(self, file_offset, size, seq_number):
        """
        Sends the next OTA block frame.

        Args:
            file_offset (Integer): The file offset to send.
            size (Integer): The number of bytes to send.
            seq_number (Integer): the protocol sequence number.

        Returns:
            Integer: number of bytes sent.

        Raises:
            FirmwareUpdateException: if there is any error sending the next OTA block frame.
        """
        retries = _SEND_BLOCK_RETRIES
        while retries > 0:
            next_ota_block_frame = self._create_image_block_response_frame(file_offset, size, seq_number)
            # Use 15 seconds as a maximum value to wait for transmit status frames
            # If 'self._timeout' is too big we can lose any optimization waiting for a transmit
            # status, that could be received but corrupted
            self._local_device.set_sync_ops_timeout(min(self._timeout, 15))
            try:
                status_frame = self._local_device.send_packet_sync_and_get_response(next_ota_block_frame)
                if not isinstance(status_frame, TransmitStatusPacket):
                    retries -= 1
                    continue
                if status_frame.transmit_status == TransmitStatus.PAYLOAD_TOO_LARGE:
                    # Do not decrease 'retries' here, as we are calculating the maximum payload
                    size -= _IMAGE_BLOCK_RESPONSE_PAYLOAD_DECREMENT
                    _log.debug("'Image block response' status for offset %s: size too large, retrying with size %d",
                               file_offset, size)
                    continue
                if status_frame.transmit_status not in [TransmitStatus.SUCCESS,
                                                        TransmitStatus.SELF_ADDRESSED]:
                    retries -= 1
                    _log.debug("Received 'Image block response' status frame for offset %s: %s, retrying (%d/%d)",
                               file_offset, status_frame.transmit_status.description,
                               _SEND_BLOCK_RETRIES - retries + 1, _SEND_BLOCK_RETRIES)
                    continue
                _log.debug("Received 'Image block response' status frame for offset %s: %s",
                           file_offset, status_frame.transmit_status.description)
                return size
            except TimeoutException:
                # If the transmit status is not received, let's try again
                retries -= 1
                _log.debug("Not received 'Image block response' status frame for offset %s, %s", file_offset,
                           "aborting" if retries == 0 else
                           "retrying (%d/%d)" % (_SEND_BLOCK_RETRIES - retries + 1, _SEND_BLOCK_RETRIES))
                if not retries:
                    return size
            except XBeeException as e:
                retries -= 1
                if not retries:
                    raise FirmwareUpdateException(_ERROR_SEND_OTA_BLOCK % (file_offset, str(e)))
            finally:
                # Restore the configured timeout
                self._local_device.set_sync_ops_timeout(self._timeout)

        raise FirmwareUpdateException(_ERROR_SEND_OTA_BLOCK % (file_offset, "Timeout sending frame"))

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
                self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % ("Image Notify", "Transmit status not received"))
            elif self._response_string:
                self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % self._response_string)
            elif not self._img_req_received:
                self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % ("Image Notify", "Timeout waiting for response"))
        except XBeeException as e:
            self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % ("Image Notify", str(e)))
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
        self._requested_offset = -1
        self._progress_task = self._update_task
        last_offset_sent = self._requested_offset
        # Dictionary to store block size used for each provided maximum size
        last_size_sent = {self._max_chunk_size: self._max_chunk_size}
        previous_percent = None
        retries = self._get_block_response_max_retries()

        self._transfer_lock.clear()

        # Add a packet listener to wait for block request packets and send them.
        self._local_device.add_packet_received_callback(self._firmware_receive_frame_callback)
        try:
            self._send_query_next_img_response()
        except FirmwareUpdateException as e:
            self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
            self._exit_with_error(str(e))
        # Wait for answer.
        if self._requested_offset == -1:  # If offset is different than -1 it means callback was executed.
            self._transfer_lock.wait(self._timeout)

        while (self._requested_offset != -1 and self._transfer_status is None
               and self._response_string is None and retries > 0):
            self._transfer_lock.clear()

            last_offset_sent = self._requested_offset
            previous_seq_number = self._seq_number
            # Check that the requested offset is valid.
            if self._requested_offset >= self._get_ota_size():
                self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
                self._exit_with_error(_ERROR_INVALID_BLOCK % self._requested_offset)
            # Calculate percentage and notify.
            percent = (self._requested_offset * 100) // self._get_ota_size()
            if percent != previous_percent and self._progress_callback:
                self._progress_callback(self._progress_task, percent)
                previous_percent = percent

            # Send the data block.
            try:
                size_sent = self._send_ota_block(
                    self._requested_offset,
                    min(last_size_sent.get(self._max_chunk_size, self._max_chunk_size), self._max_chunk_size),
                    previous_seq_number)
                last_size_sent[self._max_chunk_size] = size_sent
            except FirmwareUpdateException as e:
                self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
                self._exit_with_error(str(e))
            # Wait for next request.
            if not self._transfer_lock.wait(max(self._timeout, 120)):
                retries -= 1
                if retries > 0:
                    _log.debug("Chunk %s not sent, retrying... (%d/%d)",
                               self._requested_offset, _SEND_BLOCK_RETRIES - retries + 1, _SEND_BLOCK_RETRIES)
            else:
                retries = self._get_block_response_max_retries()

        # Transfer finished, remove callback.
        self._local_device.del_packet_received_callback(self._firmware_receive_frame_callback)
        # Close OTA file.
        self._ota_file.close_file()
        # Check if there was a transfer timeout.
        if self._transfer_status is None and self._response_string is None:
            if last_offset_sent + last_size_sent[self._max_chunk_size] == self._get_ota_size():
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
                _log.debug("Received 'Upgrade end response' status frame: %s",
                           status_frame.transmit_status.description)

                #
                # Workaround for XBHAWKDM-796
                #
                #   - 'No ack' error on XBee 3 DigiMesh remote firmware update
                #   - 'Address not found' on XBee 3 ZB remote firmware update
                #
                # The workaround considers those TX status as valid.
                #
                # See https://jira.digi.com/browse/XBHAWKDM-796
                #
                dm_ack_error = (status_frame.transmit_status == TransmitStatus.NO_ACK
                                and self._remote_device.get_protocol() == XBeeProtocol.DIGI_MESH
                                and self._target_firmware_version <= 0x3004)
                zb_addr_error = (status_frame.transmit_status == TransmitStatus.ADDRESS_NOT_FOUND
                                 and self._remote_device.get_protocol() == XBeeProtocol.ZIGBEE
                                 and self._target_firmware_version <= 0x1009)

                if status_frame.transmit_status == TransmitStatus.SUCCESS or dm_ack_error or zb_addr_error:
                    try:
                        self._restore_updater(raise_exception=True)
                        return
                    except Exception as e:
                        self._exit_with_error(_ERROR_RESTORE_UPDATER_DEVICE % str(e))
            except XBeeException as e:
                error_message = str(e)
            retries -= 1
            time.sleep(1.5)  # Wait some time between timeout retries.

        if error_message:
            self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % ("Upgrade end response", error_message))
        else:
            self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % ("Upgrade end response", "Timeout sending frame"))

    def _update_target_information(self):
        """
        Updates the target information after the firmware update.
        """
        _log.debug("Updating target information...")
        # If the protocol of the device has changed, just skip this step and remove device from
        # the network, it is no longer reachable.
        if self._protocol_changed:
            self._local_device.get_network()._remove_device(self._remote_device, NetworkEventReason.FIRMWARE_UPDATE)
            return

        was_open = self._local_device.is_open()
        try:
            if not was_open:
                self._local_device.open()
            # We need to update target information. Give it some time to be back into the network.
            deadline = _get_milliseconds() + (_REMOTE_FIRMWARE_UPDATE_RESYNC_TIMEOUT * 1000)
            initialized = False
            while _get_milliseconds() < deadline and not initialized:
                try:
                    self._remote_device._read_device_info(NetworkEventReason.FIRMWARE_UPDATE,
                                                          init=True, fire_event=True)
                    initialized = True
                except XBeeException:
                    time.sleep(1)
            if not initialized:
                self._exit_with_error(_ERROR_UPDATE_TARGET_TIMEOUT)
        except XBeeException as e:
            raise FirmwareUpdateException(_ERROR_UPDATE_TARGET_INFORMATION % str(e))
        finally:
            if not was_open:
                self._local_device.close()

    def _will_protocol_change(self):
        """
        Determines whether the XBee protocol will change after the update or not.

        Returns:
            Boolean: ``True`` if the protocol will change after the update, ``False`` otherwise.
        """
        orig_protocol = self._remote_device.get_protocol()
        new_protocol = XBeeProtocol.determine_protocol(self._xml_hardware_version,
                                                       utils.int_to_bytes(self._xml_firmware_version))
        return orig_protocol != new_protocol

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

    def _get_block_response_max_retries(self):
        """
        Returns the maximum number of retries for a block response.

        Returns:
            Integer: The maximum number of retries for a block response.
        """
        protocol = self._remote_device.get_protocol()
        if self._target_firmware_version < _XB3_FW_VERSION_LIMIT_FOR_CLIENT_RETRIES[protocol]:
            return _SEND_BLOCK_RETRIES

        return 1

    def _get_ota_size(self):
        """
        Returns the ota file size to transmit. This value depends on the remote
        firmware version.

        Returns:
            Integer: The ota file size.
        """
        # For firmware version x00A or higher, OTA header must be also sent for
        # the firmware/file system update, not just the image in the OTA file.
        # (although firmware update is compatible backwards)
        return (self._ota_file.ota_size
                if (self._target_firmware_version <
                    _XB3_FW_VERSION_LIMIT_SKIP_OTA_HEADER[self._remote_device.get_protocol()])
                else self._ota_file.total_size)

    def _get_ota_offset(self, offset):
        """
        Returns the offset to read from the ota file. This value depends on the
        remote firmware version.

        Args:
            offset (Integer): Received offset to get from the ota file.

        Returns:
            Integer: The real offset of the ota file based on the remote
                firmware version.
        """
        # For firmware version x00A or higher, OTA header must be also sent for
        # the firmware/file system update, not just the image in the OTA file.
        # (although firmware update is compatible backwards)
        return (offset + self._ota_file.discard_size
                if (self._target_firmware_version <
                    _XB3_FW_VERSION_LIMIT_SKIP_OTA_HEADER[self._remote_device.get_protocol()])
                else offset)


class _RemoteFilesystemUpdater(_RemoteFirmwareUpdater):
    """
    Helper class used to handle the remote filesystem update process.
    """

    def __init__(self, remote_device, filesystem_ota_file, timeout=_READ_DATA_TIMEOUT, max_block_size=0,
                 progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteFilesystemUpdater` with the given parameters.

        Args:
            remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to update its filesystem.
            filesystem_ota_file (String): path of the filesystem OTA file.
            timeout (Integer, optional): the timeout to wait for remote frame requests.
            max_block_size (Integer, optional): Maximum size in bytes of the ota block to send.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: if there is any error performing the remote filesystem update.
        """
        super(_RemoteFilesystemUpdater, self).__init__(remote_device, None, timeout=timeout,
                                                       max_block_size=max_block_size,
                                                       progress_callback=progress_callback)
        self._filesystem_ota_file = filesystem_ota_file
        self._update_task = _PROGRESS_TASK_UPDATE_REMOTE_FILESYSTEM

    def _parse_xml_firmware_file(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._parse_xml_firmware_file`
        """
        # Filesystem update process does not require to parse any XML file.
        pass

    def _check_firmware_binary_file(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._check_firmware_binary_file`
        """
        # Verify the filesystem OTA image file.
        if not _file_exists(self._filesystem_ota_file):
            self._exit_with_error(_ERROR_FILE_OTA_FILESYSTEM_NOT_FOUND, restore_updater=False)

        self._ota_file = _OTAFile(self._filesystem_ota_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as e:
            self._exit_with_error(str(e))

    def _will_protocol_change(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._will_protocol_change`
        """
        # Updating the filesystem image does not imply any protocol change.
        return False

    def _check_target_compatibility(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._check_target_compatibility`
        """
        # Read device values required for verification steps prior to filesystem update.
        _log.debug("Reading device settings:")
        self._target_firmware_version = self._get_target_firmware_version()
        _log.debug(" - Firmware version: %s", self._target_firmware_version)
        self._target_hardware_version = self._get_target_hardware_version()
        _log.debug(" - Hardware version: %s", self._target_hardware_version)

        # Check if the hardware version is compatible with the filesystem update process.
        if self._target_hardware_version and self._target_hardware_version not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

    def _update_target_information(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._update_target_information`
        """
        # Remote filesystem update does not require to update target information after the update.
        pass


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
        _log.error("ERROR: %s", _ERROR_TARGET_INVALID)
        raise FirmwareUpdateException(_ERROR_TARGET_INVALID)
    if xml_firmware_file is None:
        _log.error("ERROR: %s", _ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
    if not _file_exists(xml_firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
    if xbee_firmware_file is not None and not _file_exists(xbee_firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % xbee_firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % xbee_firmware_file)
    if bootloader_firmware_file is not None and not _file_exists(bootloader_firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND)

    # Launch the update process.
    if not timeout:
        timeout = _READ_DATA_TIMEOUT

    if not isinstance(target, str) and target._comm_iface and target._comm_iface.supports_update_firmware():
        target._comm_iface.update_firmware(target, xml_firmware_file,
                                           xbee_fw_file=xbee_firmware_file,
                                           bootloader_fw_file=bootloader_firmware_file,
                                           timeout=timeout,
                                           progress_callback=progress_callback)
        return

    update_process = _LocalFirmwareUpdater(target,
                                           xml_firmware_file,
                                           xbee_firmware_file=xbee_firmware_file,
                                           bootloader_firmware_file=bootloader_firmware_file,
                                           timeout=timeout,
                                           progress_callback=progress_callback)
    update_process.update_firmware()


def update_remote_firmware(remote_device, xml_firmware_file, ota_firmware_file=None, otb_firmware_file=None,
                           max_block_size=0, timeout=None, progress_callback=None):
    """
    Performs a remote firmware update operation in the given target.

    Args:
        remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
        xml_firmware_file (String): path of the XML file that describes the firmware to upload.
        ota_firmware_file (String, optional): path of the OTA firmware file to upload.
        otb_firmware_file (String, optional): path of the OTB firmware file to upload (bootloader bundle).
        max_block_size (Integer, optional): Maximum size of the ota block to send.
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
        _log.error("ERROR: %s", _ERROR_REMOTE_DEVICE_INVALID)
        raise FirmwareUpdateException(_ERROR_TARGET_INVALID)
    if xml_firmware_file is None:
        _log.error("ERROR: %s", _ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED)
    if not _file_exists(xml_firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_XML_FIRMWARE_NOT_FOUND)
    if ota_firmware_file is not None and not _file_exists(ota_firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % ota_firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % ota_firmware_file)
    if otb_firmware_file is not None and not _file_exists(otb_firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % otb_firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % otb_firmware_file)
    if not isinstance(max_block_size, int):
        raise ValueError("Maximum block size must be an integer")
    if max_block_size < 0 or max_block_size > 255:
        raise ValueError("Maximum block size must be between 0 and 255")

    # Launch the update process.
    if not timeout:
        timeout = _REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT

    if remote_device._comm_iface and remote_device._comm_iface.supports_update_firmware():
        remote_device._comm_iface.update_firmware(remote_device, xml_firmware_file,
                                                  xbee_fw_file=ota_firmware_file,
                                                  bootloader_fw_file=otb_firmware_file,
                                                  timeout=timeout,
                                                  progress_callback=progress_callback)
        return

    update_process = _RemoteFirmwareUpdater(remote_device,
                                            xml_firmware_file,
                                            ota_firmware_file=ota_firmware_file,
                                            otb_firmware_file=otb_firmware_file,
                                            timeout=timeout,
                                            max_block_size=max_block_size,
                                            progress_callback=progress_callback)
    update_process.update_firmware()


def update_remote_filesystem(remote_device, ota_filesystem_file, max_block_size=0, timeout=None,
                             progress_callback=None):
    """
    Performs a remote filesystem update operation in the given target.

    Args:
        remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to update its filesystem image.
        ota_filesystem_file (String): path of the OTA filesystem image file to update.
        max_block_size (Integer, optional): Maximum size of the ota block to send.
        timeout (Integer, optional): the timeout to wait for remote frame requests.
        progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FirmwareUpdateException: if there is any error updating the remote filesystem image.
    """
    # Sanity checks.
    if not isinstance(remote_device, RemoteXBeeDevice):
        _log.error("ERROR: %s", _ERROR_REMOTE_DEVICE_INVALID)
        raise FirmwareUpdateException(_ERROR_REMOTE_DEVICE_INVALID)
    if ota_filesystem_file is None:
        _log.error("ERROR: %s", _ERROR_FILE_OTA_FILESYSTEM_NOT_SPECIFIED)
        raise FirmwareUpdateException(_ERROR_FILE_OTA_FILESYSTEM_NOT_SPECIFIED)
    if not _file_exists(ota_filesystem_file):
        _log.error("ERROR: %s", _ERROR_FILE_OTA_FILESYSTEM_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_OTA_FILESYSTEM_NOT_FOUND)
    if not isinstance(max_block_size, int):
        raise ValueError("Maximum block size must be an integer")
    if max_block_size < 0 or max_block_size > 255:
        raise ValueError("Maximum block size must be between 0 and 255")

    # Launch the update process.
    if not timeout:
        timeout = _REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT
    update_process = _RemoteFilesystemUpdater(remote_device,
                                              ota_filesystem_file,
                                              timeout=timeout,
                                              max_block_size=max_block_size,
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
