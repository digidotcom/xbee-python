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
from digi.xbee.exception import XBeeException, FirmwareUpdateException, TimeoutException, ATCommandException
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice, NetworkEventReason
from digi.xbee.models.address import XBee16BitAddress
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import APIOutputModeBit
from digi.xbee.models.options import RemoteATCmdOptions
from digi.xbee.models.protocol import XBeeProtocol, Role
from digi.xbee.models.status import TransmitStatus, ATCommandStatus, EmberBootloaderMessageType
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ExplicitAddressingPacket, TransmitStatusPacket,\
    RemoteATCommandPacket, RemoteATCommandResponsePacket
from digi.xbee.serial import FlowControl
from digi.xbee.serial import XBeeSerialPort
from digi.xbee.util import utils
from digi.xbee.util import xmodem
from digi.xbee.util.xmodem import XModemException, XModemCancelException
from enum import Enum, unique
from itertools import repeat
from pathlib import Path
from serial.serialutil import SerialException
from threading import Event
from threading import Thread
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

_BOOTLOADER_TIMEOUT = 60  # seconds
_BOOTLOADER_VERSION_SEPARATOR = "."
_BOOTLOADER_VERSION_SIZE = 3
_BOOTLOADER_XBEE3_RESET_ENV_VERSION = bytearray([1, 6, 6])

_GECKO_BOOTLOADER_INITIALIZATION_TIME = 3  # Seconds
_GECKO_BOOTLOADER_OPTION_RUN_FIRMWARE = "2"
_GECKO_BOOTLOADER_OPTION_UPLOAD_GBL = "1"
_GECKO_BOOTLOADER_PORT_PARAMETERS = {"baudrate": 115200,
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
_GECKO_BOOTLOADER_PROMPT = "BL >"
_GECKO_BOOTLOADER_TEST_CHARACTER = "\n"

_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL = "^.*Gecko Bootloader.*\\(([0-9a-fA-F]{4})-([0-9a-fA-F]{2})(.*)\\).*$"
_PATTERN_GECKO_BOOTLOADER_VERSION = "^.*Gecko Bootloader v([0-9a-fA-F]{1}\\.[0-9a-fA-F]{1}\\.[0-9a-fA-F]{1}).*$"

_XBEE3_BOOTLOADER_FILE_PREFIX = "xb3-boot-rf_"

_GEN3_BOOTLOADER_ERROR_CHECKSUM = 0x12
_GEN3_BOOTLOADER_ERROR_VERIFY = 0x13
_GEN3_BOOTLOADER_FLASH_CHECKSUM_RETRIES = 3
_GEN3_BOOTLOADER_FLASH_VERIFY_RETRIES = 3
_GEN3_BOOTLOADER_PORT_PARAMETERS = {"baudrate": 38400,
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
_GEN3_BOOTLOADER_PROMPT = "U"
_GEN3_BOOTLOADER_PROTOCOL_VERSION_0 = 0
_GEN3_BOOTLOADER_TEST_CHARACTER = "\n"
_GEN3_BOOTLOADER_TRANSFER_ACK = 0x55

_BUFFER_SIZE_SHORT = 2
_BUFFER_SIZE_INT = 4
_BUFFER_SIZE_IEEE_ADDR = 8
_BUFFER_SIZE_STRING = 32

_READ_BUFFER_LEN = 256
_READ_DATA_TIMEOUT = 3  # Seconds.

_DEVICE_BREAK_RESET_TIMEOUT = 10  # seconds
_DEVICE_CONNECTION_RETRIES = 3

_ERROR_BOOTLOADER_MODE = "Could not enter in bootloader mode"
_ERROR_BOOTLOADER_NOT_SUPPORTED = "XBee does not support firmware update process"
_ERROR_COMPATIBILITY_NUMBER = "Device compatibility number (%d) is greater than the firmware one (%d)"
_ERROR_COMMUNICATION_LOST = "Communication with the device was lost"
_ERROR_COMMUNICATION_TEST = "Communication test with the remote device failed"
_ERROR_CONNECT_DEVICE = "Could not connect with XBee device after %s retries"
_ERROR_CONNECT_SERIAL_PORT = "Could not connect with serial port: %s"
_ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR = "Unknown error"
_ERROR_DETERMINE_BOOTLOADER_TYPE = "Could not determine the bootloader type: %s"
_ERROR_DEVICE_PROGRAMMING_MODE = "Could not put XBee device into programming mode"
_ERROR_END_DEVICE_ORPHAN = "Could not find the parent node of the end device"
_ERROR_FILE_OTA_FILESYSTEM_NOT_FOUND = "OTA filesystem image file does not exist"
_ERROR_FILE_OTA_FILESYSTEM_NOT_SPECIFIED = "OTA filesystem image file must be specified"
_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND = "Could not find XBee binary firmware file '%s'"
_ERROR_FILE_XML_FIRMWARE_NOT_FOUND = "XML firmware file does not exist"
_ERROR_FILE_XML_FIRMWARE_NOT_SPECIFIED = "XML firmware file must be specified"
_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND = "Could not find bootloader binary firmware file '%s'"
_ERROR_FINISH_PROCESS = "Could not finish firmware update process"
_ERROR_FIRMWARE_START = "Could not start the new firmware"
_ERROR_FIRMWARE_UPDATE_BOOTLOADER = "Bootloader update error: %s"
_ERROR_FIRMWARE_UPDATE_RETRIES = "Firmware update failed after %s retries"
_ERROR_FIRMWARE_UPDATE_XBEE = "XBee firmware update error: %s"
_ERROR_GPM_ERASE_COMMAND = "An error occurred erasing the device flash"
_ERROR_GPM_INFO_COMMAND = "An error occurred getting the platform information"
_ERROR_GPM_VERIFY_AND_INSTALL_COMMAND = "An error occurred while installing the new firmware in the device"
_ERROR_GPM_VERIFY_COMMAND = "An error occurred while verifying firmware image in the device"
_ERROR_GPM_WRITE_COMMAND = "An error occurred while writing data in the device"
_ERROR_HARDWARE_VERSION_DIFFER = "Device hardware version (%d) differs from the firmware one (%d)"
_ERROR_IMAGE_VERIFICATION = "Image verification error"
_ERROR_INITIALIZE_PROCESS = "Could not initialize firmware update process"
_ERROR_INVALID_OTA_FILE = "Invalid OTA file: %s"
_ERROR_INVALID_BLOCK = "Requested block index '%s' does not exits"
_ERROR_INVALID_GPM_ANSWER = "Invalid GPM frame answer"
_ERROR_NO_UPDATER_AVAILABLE = "No valid updater available to perform the remote firmware update"
_ERROR_NOT_OTA_FILE = "File '%s' is not an OTA file"
_ERROR_PAGE_CHECKSUM = "Checksum error for page %d"
_ERROR_PAGE_VERIFICATION = "Verification error for page %d"
_ERROR_PARSING_OTA_FILE = "Error parsing OTA file: %s"
_ERROR_RECEIVE_FRAME_TIMEOUT = "Timeout waiting for response"
_ERROR_RECOVERY_MODE = "Could not put updater device in recovery mode"
_ERROR_READ_OTA_FILE = "Error reading OTA file: %s"
_ERROR_REGION_LOCK = "Device region (%d) differs from the firmware one (%d)"
_ERROR_REMOTE_DEVICE_INVALID = "Invalid remote XBee device"
_ERROR_RESTORE_TARGET_CONNECTION = "Could not restore target connection: %s"
_ERROR_RESTORE_UPDATER_DEVICE = "Error restoring updater device: %s"
_ERROR_SEND_FRAME = "Error sending frame: transmit status not received or invalid"
_ERROR_SEND_FRAME_RESPONSE = "Error sending '%s' frame: %s"
_ERROR_SEND_OTA_BLOCK = "Error sending OTA block '%s' frame: %s"
_ERROR_SERIAL_COMMUNICATION = "Serial port communication error: %s"
_ERROR_TARGET_INVALID = "Invalid update target"
_ERROR_TRANSFER_OTA_FILE = "Error transferring OTA file: %s"
_ERROR_UPDATE_FROM_S2C = "An S2C device can be only updated from another S2C device"
_ERROR_UPDATE_TARGET_INFORMATION = "Error reading new target information: %s"
_ERROR_UPDATE_TARGET_TIMEOUT = "Timeout communicating with target device after the firmware update"
_ERROR_UPDATER_READ_PARAMETER = "Error reading updater '%s' parameter"
_ERROR_UPDATER_SET_PARAMETER = "Error setting updater '%s' parameter"
_ERROR_XML_PARSE = "Could not parse XML firmware file %s"
_ERROR_XMODEM_COMMUNICATION = "XModem serial port communication error: %s"
_ERROR_XMODEM_RESTART = "Could not restart firmware transfer sequence"
_ERROR_XMODEM_START = "Could not start XModem firmware upload process"
ERROR_HARDWARE_VERSION_NOT_SUPPORTED = "XBee hardware version (%d) does not support firmware update process"

_EXPLICIT_PACKET_BROADCAST_RADIUS_MAX = 0x00
_EXPLICIT_PACKET_CLUSTER_DATA = 0x0011
_EXPLICIT_PACKET_CLUSTER_ID = 0x0019
_EXPLICIT_PACKET_CLUSTER_GPM = 0x0023
_EXPLICIT_PACKET_CLUSTER_LINK = 0x0014
_EXPLICIT_PACKET_CLUSTER_LINK_ANSWER = 0x0094
_EXPLICIT_PACKET_CLUSTER_LOOPBACK = 0x0012
_EXPLICIT_PACKET_CLUSTER_UPDATE_LOCAL_UPDATER = 0x71FE
_EXPLICIT_PACKET_CLUSTER_UPDATE_REMOTE_UPDATER = 0x71FF
_EXPLICIT_PACKET_ENDPOINT_DATA = 0xE8
_EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE = 0xE6
_EXPLICIT_PACKET_PROFILE_DIGI = 0xC105
_EXPLICIT_PACKET_EXTENDED_TIMEOUT = 0x40

EXTENSION_EBIN = ".ebin"
EXTENSION_EBL = ".ebl"
EXTENSION_GBL = ".gbl"
EXTENSION_EHX2 = ".ehx2"
EXTENSION_OTA = ".ota"
EXTENSION_OTB = ".otb"
EXTENSION_XML = ".xml"

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

_PROGRESS_TASK_UPDATE_BOOTLOADER = "Updating bootloader"
_PROGRESS_TASK_UPDATE_REMOTE_XBEE = "Updating remote XBee firmware"
_PROGRESS_TASK_UPDATE_REMOTE_FILESYSTEM = "Updating remote XBee filesystem"
_PROGRESS_TASK_UPDATE_XBEE = "Updating XBee firmware"

_REGION_ALL = 0

_REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT = 20  # Seconds

_SEND_BLOCK_RETRIES = 5

_TIME_DAYS_1970TO_2000 = 10957
_TIME_SECONDS_1970_TO_2000 = _TIME_DAYS_1970TO_2000 * 24 * 60 * 60

_IMAGE_BLOCK_RESPONSE_PAYLOAD_DECREMENT = 1
_UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE = 12

_VALUE_API_OUTPUT_MODE_EXPLICIT = 0x01
_VALUE_END_OF_FILE_DATA = bytearray([0x01, 0x04])
_VALUE_INITIALIZATION_DATA = bytearray([0x01, 0x51])
_VALUE_PRESERVE_NEWTWORK_SETTINGS = bytearray([0x54, 0x41])
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

_POLYNOMINAL_DIGI_BL = 0x8005

S2C_HARDWARE_VERSIONS = (HardwareVersion.XBP24C.code,
                         HardwareVersion.XB24C.code,
                         HardwareVersion.XBP24C_S2C_SMT.code,
                         HardwareVersion.XBP24C_TH_DIP.code,
                         HardwareVersion.XB24C_TH_DIP.code)

SX_HARDWARE_VERSIONS = (HardwareVersion.SX.code,
                        HardwareVersion.SX_PRO.code,
                        HardwareVersion.XB8X.code)

XBEE3_HARDWARE_VERSIONS = (HardwareVersion.XBEE3.code,
                           HardwareVersion.XBEE3_SMT.code,
                           HardwareVersion.XBEE3_TH.code)

SUPPORTED_HARDWARE_VERSIONS = SX_HARDWARE_VERSIONS + XBEE3_HARDWARE_VERSIONS + S2C_HARDWARE_VERSIONS

_log = logging.getLogger(__name__)


class _EbinFile(object):
    """
    Helper class that represents a local firmware file in 'ebin' format.
    """

    def __init__(self, file_path, page_size):
        """
        Class constructor. Instantiates a new :class:`._EbinFile` with the given parameters.

        Args:
            file_path (String): the path of the ebin file.
            page_size (Integer): the size of the memory pages of the file.
        """
        self._file_path = file_path
        self._page_size = page_size
        self._page_index = 0
        self._num_pages = os.path.getsize(file_path) // self._page_size
        if os.path.getsize(file_path) % self._page_size != 0:
            self._num_pages += 1

    def get_next_mem_page(self):
        """
        Returns the next memory page of this file.

        Returns:
            Bytearray: the next memory page of the file as byte array.
        """
        with open(self._file_path, "rb") as file:
            while True:
                read_bytes = file.read(self._page_size)
                if not read_bytes:
                    break
                # Protocol states that empty pages (pages filled with 0xFF) must not be sent.
                # Check if this page is empty.
                page_is_empty = True
                for byte in read_bytes:
                    if byte != 0xFF:
                        page_is_empty = False
                        break
                # Skip empty page. Still increase page index.
                if not page_is_empty:
                    # Page must have always full size. If not, extend with 0xFF until it is complete.
                    if len(read_bytes) < self._page_size:
                        padded_array = bytearray(read_bytes)
                        padded_array.extend(repeat(0xFF, self._page_size - len(read_bytes)))
                        read_bytes = bytes(padded_array)
                    yield read_bytes
                self._page_index += 1

    @property
    def num_pages(self):
        """
        Returns the total number of memory pages of this file.

        Returns:
            Integer: the total number of data chunks of this file.
        """
        return self._num_pages

    @property
    def page_index(self):
        """
        Returns the current memory page index.

        Returns:
            Integer: the current memory page index.
        """
        return self._page_index

    @property
    def percent(self):
        """
        Returns the transfer progress percent.

        Returns:
            Integer: the transfer progress percent.
        """
        return ((self._page_index + 1) * 100) // self._num_pages


class _EBLFile(object):
    """
    Helper class that represents a local firmware file in 'ebl' format.
    """

    def __init__(self, file_path, page_size):
        """
        Class constructor. Instantiates a new :class:`._EBLFile` with the given parameters.

        Args:
            file_path (String): the path of the ebl file.
            page_size (Integer): the size of the memory pages of the file.
        """
        self._file_path = file_path
        self._page_size = page_size
        self._page_index = 0
        self._num_pages = os.path.getsize(file_path) // self._page_size
        if os.path.getsize(file_path) % self._page_size != 0:
            self._num_pages += 1

    def get_next_mem_page(self):
        """
        Returns the next memory page of this file.

        Returns:
            Bytearray: the next memory page of the file as byte array.
        """
        with open(self._file_path, "rb") as file:
            while True:
                read_bytes = file.read(self._page_size)
                if not read_bytes:
                    break
                # Page must have always full size. If not, extend with 0xFF until it is complete.
                if len(read_bytes) < self._page_size:
                    padded_array = bytearray(read_bytes)
                    padded_array.extend(repeat(0xFF, self._page_size - len(read_bytes)))
                    read_bytes = bytes(padded_array)
                yield read_bytes
                self._page_index += 1

    @property
    def num_pages(self):
        """
        Returns the total number of memory pages of this file.

        Returns:
            Integer: the total number of data chunks of this file.
        """
        return self._num_pages

    @property
    def page_index(self):
        """
        Returns the current memory page index.

        Returns:
            Integer: the current memory page index.
        """
        return self._page_index

    @property
    def percent(self):
        """
        Returns the transfer progress percent.

        Returns:
            Integer: the transfer progress percent.
        """
        return ((self._page_index + 1) * 100) // self._num_pages


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
        if not _file_exists(self._file_path) or (not self._file_path.endswith(EXTENSION_OTA) and
                                                 not self._file_path.endswith(EXTENSION_OTB)):
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
                bad_ota_size = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - Discard OTA size field: %d", bad_ota_size)
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
                file.seek(self._header_length + 2, 0)
                self._ota_size = utils.bytes_to_int(_reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - OTA size: %d", self._ota_size)
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


@unique
class _BootloaderType(Enum):
    """
    This class lists the available bootloader types

    | Inherited properties:
    |     **name** (String): The name of this _BootloaderType.
    |     **value** (Integer): The ID of this _BootloaderType.
    """
    GEN3_BOOTLOADER = (0x01, "Generation 3 bootloader")
    GECKO_BOOTLOADER = (0x02, "Gecko bootloader")
    EMBER_BOOTLOADER = (0x03, "Ember bootloader")

    def __init__(self, identifier, description):
        self.__identifier = identifier
        self.__description = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _BootloaderType for the given identifier.

        Args:
            identifier (Integer): the identifier of the _BootloaderType to get.

        Returns:
            :class:`._BootloaderType`: the _BootloaderType with the given identifier, ``None`` if
                                       there is not a _BootloaderType with that name.
        """
        for value in _BootloaderType:
            if value.identifier == identifier:
                return value

        return None

    @classmethod
    def determine_bootloader_type(cls, hardware_version):
        """
        Determines the _BootloaderType for the given hardware version.

        Args:
            hardware_version (Integer): the hardware version to retrieve its bootloader type.

        Returns:
            :class:`._BootloaderType`: the _BootloaderType of the given hardware version, ``None`` if
                                       there is not a _BootloaderType for that hardware version.
        """
        if hardware_version in SX_HARDWARE_VERSIONS:
            return _BootloaderType.GEN3_BOOTLOADER
        elif hardware_version in XBEE3_HARDWARE_VERSIONS:
            return _BootloaderType.GECKO_BOOTLOADER
        elif hardware_version in S2C_HARDWARE_VERSIONS:
            return _BootloaderType.EMBER_BOOTLOADER
        else:
            return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _BootloaderType element.

        Returns:
            Integer: the identifier of the _BootloaderType element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the description of the _BootloaderType element.

        Returns:
            String: the description of the _BootloaderType element.
        """
        return self.__description


@unique
class _Gen3BootloaderCommand(Enum):
    """
    This class lists the available Gen3 bootloader commands.

    | Inherited properties:
    |     **name** (String): The name of this _Gen3BootloaderCommand.
    |     **value** (Integer): The ID of this _Gen3BootloaderCommand.
    """
    BOOTLOADER_VERSION = (0x01, "Retrieve the bootloader version", "B", 6, 200)
    HARDWARE_VERSION = (0x02, "Retrieve hardware version", "V", 17, 1000)
    REGION_LOCK = (0x03, "Retrieve region lock number", "N", 1, 300)
    PROTOCOL_VERSION = (0x04, "Retrieve firmware update protocol version", "L", 1, 500)
    INITIALIZE_UPDATE = (0x05, "Initialize firmware update process", "I", 1, 4000)
    FINISH_UPDATE = (0x06, "Finish firmware update process", "F", 1, 100)
    CHANGE_BAUDRATE = (0x07, "Change serial baudrate", "R", 6, 300)
    PROGRAM_PAGE = (0x08, "Program firmware memory page", "P", 1, -1)  # Negative timeout means do not wait for answer.
    VERIFY = (0x09, "Verify the transferred image", "C", 1, 30000)

    def __init__(self, identifier, description, command, answer_length, timeout):
        self.__identifier = identifier
        self.__description = description
        self.__command = command
        self.__answer_length = answer_length
        self.__timeout = timeout

    @classmethod
    def get(cls, identifier):
        """
        Returns the _Gen3BootloaderCommand for the given identifier.

        Args:
            identifier (Integer): the identifier of the _Gen3BootloaderCommand to get.

        Returns:
            :class:`._Gen3BootloaderCommand`: the _Gen3BootloaderCommand with the given identifier, ``None`` if
                                              there is not a _Gen3BootloaderCommand with that identifier.
        """
        for value in _BootloaderType:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _Gen3BootloaderCommand element.

        Returns:
            Integer: the identifier of the _Gen3BootloaderCommand element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the description of the _Gen3BootloaderCommand element.

        Returns:
            String: the description of the _Gen3BootloaderCommand element.
        """
        return self.__description

    @property
    def command(self):
        """
        Returns the command of the _Gen3BootloaderCommand element.

        Returns:
            String: the command of the _Gen3BootloaderCommand element.
        """
        return self.__command

    @property
    def answer_length(self):
        """
        Returns the answer length of the _Gen3BootloaderCommand element.

        Returns:
            Integer: the answer length of the _Gen3BootloaderCommand element.
        """
        return self.__answer_length

    @property
    def timeout(self):
        """
        Returns the timeout of the _Gen3BootloaderCommand element.

        Returns:
            Integer: the timeout of the _Gen3BootloaderCommand element (milliseconds).
        """
        return self.__timeout


@unique
class _GPMCommand(Enum):
    """
    This class lists the available GPM (General Purpose Memory) commands.

    | Inherited properties:
    |     **name** (String): The name of this _GPMCommand.
    |     **value** (Integer): The ID of this _GPMCommand.
    """
    GET_PLATFORM_INFO = (0x01, "Reads the device information", 0x00, 0x80, _ERROR_GPM_INFO_COMMAND)
    ERASE_FLASH = (0x02, "Erases the device flash", 0x01, 0x81, _ERROR_GPM_ERASE_COMMAND)
    WRITE_DATA = (0x03, "Writes data in the device", 0x02, 0x82, _ERROR_GPM_WRITE_COMMAND)
    VERIFY_IMAGE = (0x04, "Verifies the firmware image in the device", 0x05, 0x85, _ERROR_GPM_VERIFY_COMMAND)
    VERIFY_AND_INSTALL = (0x05, "Verifies and installs the firmware image in the device", 0x06, 0x86,
                          _ERROR_GPM_VERIFY_AND_INSTALL_COMMAND)

    def __init__(self, identifier, description, command_id, answer_id, execution_error):
        self.__identifier = identifier
        self.__description = description
        self.__command_id = command_id
        self.__answer_id = answer_id
        self.__execution_error = execution_error

    @classmethod
    def get(cls, identifier):
        """
        Returns the _GPMCommand for the given identifier.

        Args:
            identifier (Integer): the identifier of the _GPMCommand to get.

        Returns:
            :class:`._GPMCommand`: the _GPMCommand with the given identifier, ``None`` if
                                   there is not a _GPMCommand with that identifier.
        """
        for value in _GPMCommand:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _GPMCommand element.

        Returns:
            Integer: the identifier of the _GPMCommand element.
        """
        return self.__identifier

    @property
    def description(self):
        """
        Returns the description of the _GPMCommand element.

        Returns:
            String: the description of the _GPMCommand element.
        """
        return self.__description

    @property
    def command_id(self):
        """
        Returns the command identifier of the _GPMCommand element.

        Returns:
            Integer: the command identifier of the _GPMCommand element.
        """
        return self.__command_id

    @property
    def answer_id(self):
        """
        Returns the answer identifier of the _GPMCommand element.

        Returns:
            Integer: the answer identifier of the _GPMCommand element.
        """
        return self.__answer_id

    @property
    def execution_error(self):
        """
        Returns the execution error message of the _GPMCommand element.

        Returns:
            String: the execution error message of the _GPMCommand element.
        """
        return self.__execution_error


class _LoopbackTest(object):
    """
    Helper class used to perform a loopback test between a local and a remote device.
    """

    _LOOPBACK_DATA = "Loopback test %s"

    def __init__(self, local_device, remote_device, loops=10, failures_allowed=2, timeout=2):
        """
        Class constructor. Instantiates a new :class:`._LoopbackTest` with the given parameters.

        Args:
            local_device (:class:`.XBeeDevice`): local device to perform the loopback test with.
            remote_device (:class:`.RemoteXBeeDevice`): remote device against which to perform the loopback test.
            loops (Integer, optional): number of loops to execute in the test. Defaults to 10.
            failures_allowed (Integer, optional): number of allowed failed loops before considering the test failed.
                                                  Defaults to 1.
            timeout (Integer, optional): the timeout in seconds to wait for the loopback answer. Defaults to 2 seconds.
        """
        self._local_device = local_device
        self._remote_device = remote_device
        self._num_loops = loops
        self._failures_allowed = failures_allowed
        self._loopback_timeout = timeout
        self._receive_lock = Event()
        self._packet_sent = False
        self._packet_received = False
        self._loop_failed = False
        self._total_loops_failed = 0
        self._frame_id = 1

    def _generate_loopback_packet(self):
        packet = ExplicitAddressingPacket(self._frame_id,
                                          self._remote_device.get_64bit_addr(),
                                          self._remote_device.get_16bit_addr(),
                                          _EXPLICIT_PACKET_ENDPOINT_DATA,
                                          _EXPLICIT_PACKET_ENDPOINT_DATA,
                                          _EXPLICIT_PACKET_CLUSTER_LOOPBACK,
                                          _EXPLICIT_PACKET_PROFILE_DIGI,
                                          _EXPLICIT_PACKET_BROADCAST_RADIUS_MAX,
                                          _EXPLICIT_PACKET_EXTENDED_TIMEOUT if
                                          self._local_device.get_protocol() == XBeeProtocol.ZIGBEE else 0x00,
                                          (self._LOOPBACK_DATA % self._frame_id).encode())
        return packet

    def _loopback_callback(self, xbee_frame):
        if xbee_frame.get_frame_type() == ApiFrameType.TRANSMIT_STATUS and xbee_frame.frame_id == self._frame_id:
            if xbee_frame.transmit_status == TransmitStatus.SUCCESS:
                self._packet_sent = True
            else:
                self._receive_lock.set()
        elif (xbee_frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR
              and xbee_frame.source_endpoint == _EXPLICIT_PACKET_ENDPOINT_DATA
              and xbee_frame.dest_endpoint == _EXPLICIT_PACKET_ENDPOINT_DATA
              and xbee_frame.cluster_id == _EXPLICIT_PACKET_CLUSTER_DATA
              and xbee_frame.profile_id == _EXPLICIT_PACKET_PROFILE_DIGI
              and xbee_frame.x64bit_source_addr == self._remote_device.get_64bit_addr()):
            # If frame was already received, ignore this frame, just notify.
            if self._packet_received:
                self._receive_lock.set()
                return
            # Check received payload.
            payload = xbee_frame.rf_data
            if not payload or len(payload) < 2:
                return
            if payload.decode('utf-8') == (self._LOOPBACK_DATA % self._frame_id):
                self._packet_received = True
                self._receive_lock.set()

    def execute_test(self):
        """
        Performs the loopback test.

        Returns:
            Boolean: `True` if the test succeed, `False` otherwise.
        """
        _log.debug("Executing loopback test against %s" % self._remote_device)
        # Clear vars.
        self._frame_id = 1
        self._total_loops_failed = 0
        # Store AO value.
        success, old_ao = _enable_explicit_mode(self._local_device)
        if not success:
            return False
        # Perform the loops test.
        for loop in range(self._num_loops):
            # Clear vars
            self._receive_lock.clear()
            self._packet_sent = False
            self._packet_received = False
            self._loop_failed = False
            # Add loopback callback.
            self._local_device.add_packet_received_callback(self._loopback_callback)
            try:
                # Send frame.
                self._local_device.send_packet(self._generate_loopback_packet())
                # Wait for answer.
                self._receive_lock.wait(self._loopback_timeout)
            except XBeeException as e:
                _log.warning("Could not send loopback test packet %s: %s" % (loop, str(e)))
                self._loop_failed = True
            finally:
                # Remove frame listener.
                self._local_device.del_packet_received_callback(self._loopback_callback)
            # Check if packet was sent and answer received.
            if not self._packet_sent or not self._packet_received:
                self._loop_failed = True
            # Increase failures count in case of failure.
            if self._loop_failed:
                self._total_loops_failed += 1
                # Do no continue with the test if there are already too many failures.
                if self._total_loops_failed > self._failures_allowed:
                    break
            self._frame_id += 1
        # Restore AO value.
        if old_ao is not None and not _set_device_parameter_with_retries(
                self._local_device, ATStringCommand.AO.command, old_ao, apply=True):
            return False
        # Return test result.
        _log.debug("Loopback test result: %s loops failed out of %s" % (self._total_loops_failed, self._num_loops))
        return self._total_loops_failed <= self._failures_allowed


class _TraceRouteTest(object):
    """
    Helper class used to perform a trace route test between a local device and a remote device to verify that a
    third device is not in the route between them in DigiMesh networks.
    """

    def __init__(self, local_device, remote_device, test_device, timeout=20):
        """
        Class constructor. Instantiates a new :class:`._TraceRouteTest` with the given parameters.

        Args:
            local_device (:class:`.XBeeDevice`): local device to initiate the trace route test with.
            remote_device (:class:`.RemoteXBeeDevice`): remote device against which to perform the trace route test.
            test_device (:class:`.RemoteXBeeDevice`): remote device to verify that is not part of the route.
            timeout (Integer, optional): the timeout in seconds to wait for the trace route answer.
                                         Defaults to 20 seconds.
        """
        self._local_device = local_device
        self._remote_device = remote_device
        self._test_device = test_device
        self._timeout = timeout

    def execute_test(self):
        """
        Performs the trace route test.

        Returns:
            Boolean: `True` if the test succeed, `False` otherwise.
        """
        _log.debug("Executing trace route test against %s" % self._remote_device)
        status, route = self._local_device.get_route_to_node(self._remote_device, timeout=self._timeout)
        if not status:
            _log.warning("Could not send trace route test packet")
            return False
        if status != TransmitStatus.SUCCESS:
            _log.warning("Error sending trace route test packet: %s" % (str(status.description)))
            return False
        if not route or len(route) < 3:
            _log.warning("Route not received")
            return False
        return self._test_device not in route[2]


class _LinkTest(object):
    """
    Helper class used to perform a link test between the updater device and a remote device to verify connectivity
    in DigiMesh networks.
    """

    _LINK_TEST_ANSWER_PAYLOAD_LEN = 21

    def __init__(self, local_device, target_device, updater_device, loops=10, data_length=16, failures_allowed=1,
                 timeout=20):
        """
        Class constructor. Instantiates a new :class:`._LinkTest` with the given parameters.

        Args:
            local_device (:class:`.XBeeDevice`): local device to initiate the test.
            target_device (:class:`.RemoteXBeeDevice`): remote device to communicate with.
            updater_device (:class:`.RemoteXBeeDevice`): remote device that will communicate with the target node.
            loops (Integer, optional): number of loops to execute in the test. Defaults to 10.
            data_length (Integer, optional): number data bytes to use in the test. Defaults to 16.
            failures_allowed (Integer, optional): number of allowed failed loops before considering the test failed.
                                                  Defaults to 1.
            timeout (Integer, optional): the timeout in seconds to wait for the link test answer. Defaults to 2 seconds.
        """
        self._local_device = local_device
        self._target_device = target_device
        self._updater_device = updater_device
        self._num_loops = loops
        self._data_length = data_length
        self._failures_allowed = failures_allowed
        self._loopback_timeout = timeout
        self._receive_lock = Event()
        self._packet_received = False
        self._test_succeed = False
        self._total_loops_failed = 0

    def _generate_link_test_packet(self):
        payload = bytearray()
        payload.extend(self._target_device.get_64bit_addr().address)
        payload.extend(utils.int_to_bytes(self._data_length, 2))
        payload.extend(utils.int_to_bytes(self._num_loops, 2))
        packet = ExplicitAddressingPacket(1,
                                          self._updater_device.get_64bit_addr(),
                                          self._updater_device.get_16bit_addr(),
                                          _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE,
                                          _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE,
                                          _EXPLICIT_PACKET_CLUSTER_LINK,
                                          _EXPLICIT_PACKET_PROFILE_DIGI,
                                          _EXPLICIT_PACKET_BROADCAST_RADIUS_MAX,
                                          0x00,
                                          payload)
        return packet

    def _link_test_callback(self, xbee_frame):
        if (xbee_frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR
                and xbee_frame.source_endpoint == _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE
                and xbee_frame.dest_endpoint == _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE
                and xbee_frame.cluster_id == _EXPLICIT_PACKET_CLUSTER_LINK_ANSWER
                and xbee_frame.profile_id == _EXPLICIT_PACKET_PROFILE_DIGI
                and xbee_frame.x64bit_source_addr == self._updater_device.get_64bit_addr()):
            # If frame was already received, ignore this frame, just notify.
            if self._packet_received:
                self._receive_lock.set()
                return
            # Check received payload.
            payload = xbee_frame.rf_data
            if not payload or len(payload) < self._LINK_TEST_ANSWER_PAYLOAD_LEN:
                return
            self._test_succeed = payload[16] == 0
            self._total_loops_failed = self._num_loops - utils.bytes_to_int(payload[12:14])
            self._packet_received = True
            self._receive_lock.set()

    def execute_test(self):
        """
        Performs the link test.

        Returns:
            Boolean: `True` if the test succeed, `False` otherwise.
        """
        _log.debug("Executing link test between %s and %s" % (self._updater_device, self._target_device))
        # Clear vars.
        self._packet_received = False
        self._test_succeed = False
        self._total_loops_failed = 0
        # Store AO value.
        success, old_ao = _enable_explicit_mode(self._local_device)
        if not success:
            return False
        # Add trace route callback.
        self._local_device.add_packet_received_callback(self._link_test_callback)
        try:
            # Send frame.
            self._local_device.send_packet(self._generate_link_test_packet())
            # Wait for answer.
            self._receive_lock.wait(self._loopback_timeout)
        except XBeeException as e:
            _log.error("Could not send Link test packet: %s" % (str(e)))
            self._test_succeed = False
        finally:
            # Remove frame listener.
            self._local_device.del_packet_received_callback(self._link_test_callback)
        # Restore AO value.
        if old_ao is not None and not _set_device_parameter_with_retries(
                self._local_device, ATStringCommand.AO.command, old_ao, apply=True):
            return False
        if not self._packet_received or not self._test_succeed:
            return False
        # Return test result.
        _log.debug("Link test result: %s loops failed out of %s" % (self._total_loops_failed, self._num_loops))
        return self._total_loops_failed <= self._failures_allowed


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
            _log.debug(" - Firmware version: %s",
                       utils.hex_to_string([self._xml_firmware_version], pretty=False)
                       if self._xml_firmware_version is not None else "-")
            # Hardware version, required.
            element = root.find(_XML_HARDWARE_VERSION)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_firmware_file, restore_updater=False)
            self._xml_hardware_version = int(element.text, 16)
            _log.debug(" - Hardware version: %s",
                       utils.hex_to_string([self._xml_hardware_version], pretty=False)
                       if self._xml_hardware_version is not None else "-")
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
        _log.debug(" - Firmware version: %s",
                   utils.hex_to_string([self._target_firmware_version], pretty=False)
                   if self._target_firmware_version is not None else "-")
        self._target_hardware_version = self._get_target_hardware_version()
        _log.debug(" - Hardware version: %s",
                   utils.hex_to_string([self._target_hardware_version], pretty=False)
                   if self._target_hardware_version is not None else "-")
        self._target_compatibility_number = self._get_target_compatibility_number()
        _log.debug(" - Compatibility number: %s", self._target_compatibility_number)
        self._target_bootloader_version = self._get_target_bootloader_version()
        _log.debug(" - Bootloader version: %s", self._target_bootloader_version)
        self._target_region_lock = self._get_target_region_lock()
        _log.debug(" - Region lock: %s", self._target_region_lock)

        # Check if the hardware version is compatible with the firmware update process.
        if self._target_hardware_version and self._target_hardware_version not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

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

    def __init__(self, target, xml_firmware_file, xbee_firmware_file=None, timeout=_READ_DATA_TIMEOUT,
                 progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._LocalFirmwareUpdater` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: the XBee device to upload its firmware.
            xml_firmware_file (String): location of the XML firmware file.
            xbee_firmware_file (String, optional): location of the XBee binary firmware file.
            timeout (Integer, optional): the serial port read data operation timeout.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super(_LocalFirmwareUpdater, self).__init__(xml_firmware_file, timeout=timeout,
                                                    progress_callback=progress_callback)

        self._xbee_firmware_file = xbee_firmware_file
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
            self._xbee_firmware_file = str(Path(path.parent).joinpath(path.stem +
                                                                      self._get_firmware_binary_file_extension()))

        if not _file_exists(self._xbee_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._xbee_firmware_file, restore_updater=False)

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
            return self._get_target_bootloader_version_bootloader()
        else:
            return _read_device_bootloader_version(self._xbee_device)

    def _get_target_compatibility_number(self):
        """
        Returns the update target compatibility number.

        Returns:
            Integer: the update target compatibility number as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            return self._get_target_compatibility_number_bootloader()
        else:
            return _read_device_compatibility_number(self._xbee_device)

    def _get_target_region_lock(self):
        """
        Returns the update target region lock number.

        Returns:
            Integer: the update target region lock number as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            return self._get_target_region_lock_bootloader()
        else:
            return _read_device_region_lock(self._xbee_device)

    def _get_target_hardware_version(self):
        """
        Returns the update target hardware version.

        Returns:
            Integer: the update target hardware version as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            return self._get_target_hardware_version_bootloader()
        else:
            return _read_device_hardware_version(self._xbee_device)

    def _get_target_firmware_version(self):
        """
        Returns the update target firmware version.

        Returns:
            Integer: the update target firmware version as integer, ``None`` if it could not be read.
        """
        if self._xbee_serial_port is not None:
            # Firmware version cannot be read from bootloader.
            return None
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
                self._xbee_serial_port = _create_serial_port(self._port, self._get_bootloader_serial_parameters())
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
        force_reset_sent = False
        try:
            self._xbee_device.execute_command(ATStringCommand.PERCENT_P.command, apply=False)
        except XBeeException:
            # If the command failed, try with 'FR' command
            try:
                self._xbee_device.execute_command(ATStringCommand.FR.command, apply=False)
                force_reset_sent = True
            except XBeeException:
                # We can ignore this error as at last instance we will attempt a Break method.
                pass

        self._xbee_serial_port = self._xbee_device.serial_port
        self._device_port_params = self._xbee_serial_port.get_settings()
        try:
            self._xbee_serial_port.apply_settings(self._get_bootloader_serial_parameters())
            if force_reset_sent:
                # If we sent a force reset command, play with the serial lines so that device boots in bootloader.
                self._xbee_serial_port.rts = 0
                self._xbee_serial_port.dtr = 1
                self._xbee_serial_port.break_condition = True
                time.sleep(2)
                self._xbee_serial_port.break_condition = False
                self._xbee_serial_port.rts = 0
            self._xbee_device.close()
            self._xbee_serial_port.open()
        except SerialException as e:
            _log.exception(e)
            return False
        if not self._is_bootloader_active():
            # This will force the Break mechanism to reboot in bootloader mode in case previous methods failed.
            return self._enter_bootloader_mode_with_break()

        return True

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__class__.__DEVICE_RESET_TIMEOUT

    @abstractmethod
    def _get_bootloader_serial_parameters(self):
        """
        Returns a dictionary with the serial port parameters required to communicate with the bootloader.

        Returns:
            Dictionary: dictionary with the serial port parameters required to communicate with the bootloader.
        """
        pass

    @abstractmethod
    def _is_bootloader_active(self):
        """
        Returns whether the device is in bootloader mode or not.

        Returns:
            Boolean: ``True`` if the device is in bootloader mode, ``False`` otherwise.
        """
        pass

    @abstractmethod
    def _get_target_bootloader_version_bootloader(self):
        """
        Returns the update target bootloader version from bootloader.

        Returns:
            Bytearray: the update target bootloader version as byte array from bootloader, ``None`` if it
                       could not be read.
        """
        pass

    @abstractmethod
    def _get_target_compatibility_number_bootloader(self):
        """
        Returns the update target compatibility number from bootloader.

        Returns:
            Integer: the update target compatibility number as integer from bootloader, ``None`` if it
                     could not be read.
        """
        pass

    @abstractmethod
    def _get_target_region_lock_bootloader(self):
        """
        Returns the update target region lock number from the bootloader.

        Returns:
            Integer: the update target region lock number as integer fronm the bootloader, ``None`` if it
                     could not be read.
        """
        pass

    @abstractmethod
    def _get_target_hardware_version_bootloader(self):
        """
        Returns the update target hardware version from bootloader.

        Returns:
            Integer: the update target hardware version as integer from bootloader, ``None`` if it could not be read.
        """
        pass

    @abstractmethod
    def _get_firmware_binary_file_extension(self):
        """
        Returns the firmware binary file extension.

        Returns:
            String: the firmware binary file extension.
        """
        pass


class _RemoteFirmwareUpdater(_XBeeFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process.
    """

    def __init__(self, remote_device, xml_firmware_file, timeout=_READ_DATA_TIMEOUT, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteFirmwareUpdater` with the given parameters.

        Args:
            remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
            xml_firmware_file (String): location of the XML firmware file.
            timeout (Integer, optional): the timeout to wait for remote frame requests.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super(_RemoteFirmwareUpdater, self).__init__(xml_firmware_file, timeout=timeout,
                                                     progress_callback=progress_callback)

        self._remote_device = remote_device
        self._local_device = remote_device.get_local_xbee_device()
        self._receive_lock = Event()

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

    def _configure_updater(self):
        """
        Configures the updater device before performing the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        # Change sync ops timeout.
        self._old_sync_ops_timeout = self._local_device.get_sync_ops_timeout()
        self._local_device.set_sync_ops_timeout(self._timeout)
        # Connect device.
        self._updater_was_connected = self._local_device.is_open()
        _log.debug("Connecting device '%s'", self._local_device)
        if not _connect_device_with_retries(self._local_device, _DEVICE_CONNECTION_RETRIES):
            self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES)
        if self._configure_ao_parameter():
            # Store AO value.
            success, self._updater_ao_value = _enable_explicit_mode(
                self._local_device)
            if not success:
                self._exit_with_error(
                    _ERROR_UPDATER_READ_PARAMETER % ATStringCommand.AO.command)
        # Perform extra configuration.
        self._configure_updater_extra()

    def _restore_updater(self, raise_exception=False):
        """
        Leaves the updater device to its original state before the update operation.

        Args:
            raise_exception (Boolean, optional): ``True`` to raise exceptions if they occur, ``False`` otherwise.

        Raises:
            XBeeException: if there is any error restoring the device connection.
        """
        # Restore sync ops timeout.
        self._local_device.set_sync_ops_timeout(self._old_sync_ops_timeout)
        # Restore updater params.
        try:
            if not self._local_device.is_open():
                self._local_device.open()
            # Restore AO.
            if self._configure_ao_parameter() and self._updater_ao_value is not None:
                _set_device_parameter_with_retries(
                    self._local_device, ATStringCommand.AO.command,
                    self._updater_ao_value, apply=True)
            # Restore extra configuration.
            self._restore_updater_extra()
        except XBeeException as e:
            if raise_exception:
                raise e
        if self._updater_was_connected and not self._local_device.is_open():
            self._local_device.open()
        elif not self._updater_was_connected and self._local_device.is_open():
            self._local_device.close()

    def _check_updater_compatibility(self):
        """
        Verifies whether the updater device is compatible with firmware update or not.
        """
        if self._local_device.get_hardware_version().code not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

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
            # Change sync options timeout. Remote device might be an end device, so use the firmware update
            # timeout instead of the default one for this operation.
            self._old_sync_ops_timeout = self._local_device.get_sync_ops_timeout()
            self._local_device.set_sync_ops_timeout(self._timeout)
            if not was_open:
                self._local_device.open()
            # We need to update target information. Give it some time to be back into the network.
            deadline = _get_milliseconds() + 3 * self._timeout * 1000
            initialized = False
            while _get_milliseconds() < deadline and not initialized:
                try:
                    self._remote_device._read_device_info(NetworkEventReason.FIRMWARE_UPDATE,
                                                          init=True, fire_event=True)
                    initialized = True
                except XBeeException as e:
                    _log.warning("Could not initialize remote device: %s" % str(e))
                    time.sleep(1)
            if not initialized:
                self._exit_with_error(_ERROR_UPDATE_TARGET_TIMEOUT)
        except XBeeException as e:
            raise FirmwareUpdateException(_ERROR_UPDATE_TARGET_INFORMATION % str(e))
        finally:
            self._local_device.set_sync_ops_timeout(self._old_sync_ops_timeout)
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

    @abstractmethod
    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during updater configuration or not.

        Returns:
            Boolean: `True` if AO parameter should be configured, `False` otherwise.
        """
        pass

    @abstractmethod
    def _configure_updater_extra(self):
        """
        Performs extra updater device configuration before the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        pass

    @abstractmethod
    def _restore_updater_extra(self):
        """
        Performs extra updater configuration to leave it in its original state as it was before the update operation.

        Raises:
            XBeeException: if there is any error restoring the device connection.
        """
        pass


class _LocalXBee3FirmwareUpdater(_LocalFirmwareUpdater):
    """
    Helper class used to handle the local firmware update process of XBee 3 devices.
    """

    def __init__(self, target, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                 timeout=_READ_DATA_TIMEOUT, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._LocalXBee3FirmwareUpdater` with the given parameters.

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
        super(_LocalXBee3FirmwareUpdater, self).__init__(target, xml_firmware_file,
                                                         xbee_firmware_file=xbee_firmware_file, timeout=timeout,
                                                         progress_callback=progress_callback)

        self._bootloader_firmware_file = bootloader_firmware_file

    def _is_bootloader_active(self):
        """
        Returns whether the device is in bootloader mode or not.

        Returns:
            Boolean: ``True`` if the device is in bootloader mode, ``False`` otherwise.
        """
        return _is_bootloader_active_generic(self._xbee_serial_port, _GECKO_BOOTLOADER_TEST_CHARACTER,
                                             _GECKO_BOOTLOADER_PROMPT)

    def _read_bootloader_header(self):
        """
        Attempts to read the bootloader header.

        Returns:
            String: the bootloader header, ``None`` if it could not be read.
        """
        return _read_bootloader_header_generic(self._xbee_serial_port, _GECKO_BOOTLOADER_TEST_CHARACTER)

    def _get_bootloader_serial_parameters(self):
        """
        Returns a dictionary with the serial port parameters required to communicate with the bootloader.

        Returns:
            Dictionary: dictionary with the serial port parameters required to communicate with the bootloader.
        """
        return _GECKO_BOOTLOADER_PORT_PARAMETERS

    def _get_target_bootloader_version_bootloader(self):
        """
        Returns the update target bootloader version from bootloader.

        Returns:
            Bytearray: the update target bootloader version as byte array from bootloader, ``None`` if it
                       could not be read.
        """
        bootloader_header = self._read_bootloader_header()
        if bootloader_header is None:
            return None
        result = re.match(_PATTERN_GECKO_BOOTLOADER_VERSION, bootloader_header, flags=re.M | re.DOTALL)
        if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
            return None

        return _bootloader_version_to_bytearray(result.groups()[0])

    def _get_target_compatibility_number_bootloader(self):
        """
        Returns the update target compatibility number from bootloader.

        Returns:
            Integer: the update target compatibility number as integer from bootloader, ``None`` if it
                     could not be read.
        """
        # Assume the device is already in bootloader mode.
        bootloader_header = self._read_bootloader_header()
        if bootloader_header is None:
            return None
        result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
        if result is None or result.string is not result.group(0) or len(result.groups()) < 2:
            return None

        return int(result.groups()[1])

    def _get_target_region_lock_bootloader(self):
        """
        Returns the update target region lock number from the bootloader.

        Returns:
            Integer: the update target region lock number as integer fronm the bootloader, ``None`` if it
                     could not be read.
        """
        # There is no way to retrieve this number from bootloader.
        return None

    def _get_target_hardware_version_bootloader(self):
        """
        Returns the update target hardware version from bootloader.

        Returns:
            Integer: the update target hardware version as integer from bootloader, ``None`` if it could not be read.
        """
        # Assume the device is already in bootloader mode.
        bootloader_header = self._read_bootloader_header()
        if bootloader_header is None:
            return None
        result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
        if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
            return None

        return int(result.groups()[0][:2], 16)

    def _get_firmware_binary_file_extension(self):
        """
        Returns the firmware binary file extension.

        Returns:
            String: the firmware binary file extension.
        """
        return EXTENSION_GBL

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
            self._bootloader_firmware_file = str(Path(path.parent).joinpath(_XBEE3_BOOTLOADER_FILE_PREFIX +
                                                                            str(self._xml_bootloader_version[0]) +
                                                                            _BOOTLOADER_VERSION_SEPARATOR +
                                                                            str(self._xml_bootloader_version[1]) +
                                                                            _BOOTLOADER_VERSION_SEPARATOR +
                                                                            str(self._xml_bootloader_version[2]) +
                                                                            EXTENSION_GBL))

        if not _file_exists(self._bootloader_firmware_file):
            self._exit_with_error(_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND % self._bootloader_firmware_file)

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
            time.sleep(_GECKO_BOOTLOADER_INITIALIZATION_TIME)
            # Execute the run operation so that new bootloader is applied and executed. Give it some time afterwards.
            self._run_firmware_operation()
            time.sleep(_GECKO_BOOTLOADER_INITIALIZATION_TIME)
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

    def _start_firmware_upload_operation(self):
        """
        Starts the firmware upload operation by selecting option '1' of the bootloader.

        Returns:
            Boolean: ``True`` if the upload process started successfully, ``False`` otherwise
        """
        try:
            # Display bootloader menu and consume it.
            self._xbee_serial_port.write(str.encode(_GECKO_BOOTLOADER_TEST_CHARACTER))
            time.sleep(1)
            self._xbee_serial_port.purge_port()
            # Write '1' to execute bootloader option '1': Upload gbl and consume answer.
            self._xbee_serial_port.write(str.encode(_GECKO_BOOTLOADER_OPTION_UPLOAD_GBL))
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
            self._xbee_serial_port.write(str.encode(_GECKO_BOOTLOADER_TEST_CHARACTER))
            time.sleep(1)
            self._xbee_serial_port.purge_port()
            # Write '2' to execute bootloader option '2': Run.
            self._xbee_serial_port.write(str.encode(_GECKO_BOOTLOADER_OPTION_RUN_FIRMWARE))

            # Look for the '2' character during some time, it indicates firmware was executed.
            read_bytes = self._xbee_serial_port.read(1)
            while len(read_bytes) > 0 and not read_bytes[0] == ord(_GECKO_BOOTLOADER_OPTION_RUN_FIRMWARE):
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


class _LocalXBeeGEN3FirmwareUpdater(_LocalFirmwareUpdater):
    """
    Helper class used to handle the local firmware update process of GEN3 XBee devices.
    """

    def __init__(self, target, xml_firmware_file, xbee_firmware_file=None, timeout=_READ_DATA_TIMEOUT,
                 progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._LocalXBeeGEN3FirmwareUpdater` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: the XBee device to upload its firmware.
            xml_firmware_file (String): location of the XML firmware file.
            xbee_firmware_file (String, optional): location of the XBee binary firmware file.
            timeout (Integer, optional): the serial port read data operation timeout.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super(_LocalXBeeGEN3FirmwareUpdater, self).__init__(target, xml_firmware_file,
                                                            xbee_firmware_file=xbee_firmware_file, timeout=timeout,
                                                            progress_callback=progress_callback)

    def _is_bootloader_active(self):
        """
        Returns whether the device is in bootloader mode or not.

        Returns:
            Boolean: ``True`` if the device is in bootloader mode, ``False`` otherwise.
        """
        return _is_bootloader_active_generic(self._xbee_serial_port, _GEN3_BOOTLOADER_TEST_CHARACTER,
                                             _GEN3_BOOTLOADER_PROMPT)

    def _read_bootloader_header(self):
        """
        Attempts to read the bootloader header.

        Returns:
            String: the bootloader header, ``None`` if it could not be read.
        """
        return _read_bootloader_header_generic(self._xbee_serial_port, _GEN3_BOOTLOADER_TEST_CHARACTER)

    def _get_bootloader_serial_parameters(self):
        """
        Returns a dictionary with the serial port parameters required to communicate with the bootloader.

        Returns:
            Dictionary: dictionary with the serial port parameters required to communicate with the bootloader.
        """
        return _GEN3_BOOTLOADER_PORT_PARAMETERS

    def _get_firmware_binary_file_extension(self):
        """
        Returns the firmware binary file extension.

        Returns:
            String: the firmware binary file extension.
        """
        return EXTENSION_EBIN

    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.

        Raises:
            FirmwareUpdateException: if the bootloader binary file does not exist or is invalid.
        """
        # SX XBee family does not support bootloader update.
        pass

    def _execute_bootloader_command(self, command):
        """
        Attempts to execute the given bootloader command and read a number of bytes.

        Args:
            command (:class:`._Gen3BootloaderCommand`:): the bootloader command to execute.

        Returns:
            Bytearray: the bootloader command execution answer, ``None`` if it could not be read.
        """
        deadline = _get_milliseconds() + command.timeout
        data = bytearray()
        try:
            self._xbee_serial_port.purge_port()
            self._xbee_serial_port.write(str.encode(command.command))
            while len(data) < command.answer_length and _get_milliseconds() < deadline:
                read_bytes = self._xbee_serial_port.read(command.answer_length - len(data))
                if len(read_bytes) > 0:
                    data.extend(read_bytes)
            return data
        except SerialException as e:
            _log.exception(e)
            return None

    def _get_target_bootloader_version_bootloader(self):
        """
        Returns the update target bootloader version from bootloader.

        Returns:
            Bytearray: the update target bootloader version as byte array from bootloader, ``None`` if it
                       could not be read.
        """
        # GEN3 bootloader does not support retrieving its version.
        version = self._execute_bootloader_command(_Gen3BootloaderCommand.BOOTLOADER_VERSION)
        if not version or len(version) < 1:
            return None
        version_byte_array = bytearray()
        for byte in version:
            try:
                if _GEN3_BOOTLOADER_PROMPT == bytes.decode(bytes([byte])):
                    break
                version_byte_array.append(byte)
            except TypeError:
                pass
        return version_byte_array

    def _get_target_compatibility_number_bootloader(self):
        """
        Returns the update target compatibility number from bootloader.

        Returns:
            Integer: the update target compatibility number as integer from bootloader, ``None`` if it
                     could not be read.
        """
        # Assume the device is already in bootloader mode.
        version_information = self._execute_bootloader_command(_Gen3BootloaderCommand.HARDWARE_VERSION)
        if not version_information or len(version_information) < 5:
            return 0

        return version_information[4]

    def _get_target_region_lock_bootloader(self):
        """
        Returns the update target region lock number from the bootloader.

        Returns:
            Integer: the update target region lock number as integer fronm the bootloader, ``None`` if it
                     could not be read.
        """
        # Assume the device is already in bootloader mode.
        region_information = self._execute_bootloader_command(_Gen3BootloaderCommand.REGION_LOCK)
        if not region_information or len(region_information) < 1:
            return _REGION_ALL

        return region_information[0]

    def _get_target_hardware_version_bootloader(self):
        """
        Returns the update target hardware version from bootloader.

        Returns:
            Integer: the update target hardware version as integer from bootloader, ``None`` if it could not be read.
        """
        # Assume the device is already in bootloader mode.
        version_information = self._execute_bootloader_command(_Gen3BootloaderCommand.HARDWARE_VERSION)
        if not version_information or len(version_information) < 2:
            return None

        return version_information[1]

    def _get_bootloader_protocol_version(self):
        """
        Returns the bootloader protocol version.

        Returns:
            Integer: the bootloader protocol version.
        """
        # Assume the device is already in bootloader mode.
        protocol_answer = self._execute_bootloader_command(_Gen3BootloaderCommand.PROTOCOL_VERSION)
        try:
            if not protocol_answer or len(protocol_answer) < 1 or _GEN3_BOOTLOADER_PROMPT in \
                    bytes.decode(bytes(protocol_answer)):
                return _GEN3_BOOTLOADER_PROTOCOL_VERSION_0
            return int(bytes.decode(protocol_answer))
        except TypeError:
            return _GEN3_BOOTLOADER_PROTOCOL_VERSION_0

    def _send_change_baudrate_command(self):
        """
        Sends the "R" command to attempt a baudrate change of the serial port in order to improve the
        firmware transfer speed.
        """
        answer = self._execute_bootloader_command(_Gen3BootloaderCommand.CHANGE_BAUDRATE)
        try:
            # Change baudrate only if a new value was given and it is different than the current one.
            if answer and _GEN3_BOOTLOADER_PROMPT not in bytes.decode(bytes(answer)):
                new_baudrate = int(bytes.decode(bytes(answer)))
                if new_baudrate != _GEN3_BOOTLOADER_PORT_PARAMETERS["baudrate"]:
                    self._xbee_serial_port.set_baudrate(new_baudrate)
                    _log.debug("Changed port baudrate to %s", new_baudrate)
        except TypeError:
            # Do nothing, device didn't change its baudrate if an invalid value is read.
            pass

    def _send_initialize_command(self):
        """
        Initializes the firmware update operation by sending the command "I" to erase the current firmware.

        Raises:
            FirmwareUpdateException: if the initialization command could not be sent.
        """
        _log.debug("Sending Initialize command...")
        answer = self._execute_bootloader_command(_Gen3BootloaderCommand.INITIALIZE_UPDATE)
        try:
            if not answer or _GEN3_BOOTLOADER_PROMPT not in bytes.decode(bytes(answer)):
                raise FirmwareUpdateException(_ERROR_INITIALIZE_PROCESS)
        except TypeError:
            raise FirmwareUpdateException(_ERROR_INITIALIZE_PROCESS)

    def _send_finish_command(self):
        """
        Finishes the firmware update operation by sending the command "F".

        Raises:
            FirmwareUpdateException: if the finish command could not be sent.
        """
        _log.debug("Sending finish command...")
        answer = self._execute_bootloader_command(_Gen3BootloaderCommand.FINISH_UPDATE)
        try:
            if not answer or _GEN3_BOOTLOADER_PROMPT not in bytes.decode(bytes(answer)):
                raise FirmwareUpdateException(_ERROR_FINISH_PROCESS)
        except TypeError:
            raise FirmwareUpdateException(_ERROR_FINISH_PROCESS)

    def _send_verify_command(self):
        """
        Verifies the firmware image sent by sending the command "C".

        Raises:
            FirmwareUpdateException: if the verify command fails.
        """
        _log.debug("Sending verify command...")
        answer = self._execute_bootloader_command(_Gen3BootloaderCommand.VERIFY)
        if not answer:
            raise FirmwareUpdateException(_ERROR_COMMUNICATION_LOST)
        if answer[0] != _GEN3_BOOTLOADER_TRANSFER_ACK:
            raise FirmwareUpdateException(_ERROR_IMAGE_VERIFICATION)

    def _transfer_firmware(self):
        """
        Transfers the firmware file(s) to the target.

        Raises:
            FirmwareUpdateException: if there is any error transferring the firmware to the target device.
        """
        # Read bootloader protocol version.
        self._protocol_version = self._get_bootloader_protocol_version()
        _log.debug("Bootloader protocol version: %s", self._protocol_version)
        # Try to improve serial speed.
        self._send_change_baudrate_command()
        # Initialize firmware update process.
        self._send_initialize_command()
        _log.info("Updating XBee firmware")
        self._progress_task = _PROGRESS_TASK_UPDATE_XBEE
        # Perform file transfer.
        self._ebin_file = _EbinFile(self._xbee_firmware_file, self._xml_flash_page_size)
        previous_percent = None
        for memory_page in self._ebin_file.get_next_mem_page():
            if self._progress_callback is not None and self._ebin_file.percent != previous_percent:
                self._progress_callback(self._progress_task, self._ebin_file.percent)
                previous_percent = self._ebin_file.percent
            self._send_memory_page(memory_page)

    def _send_memory_page(self, memory_page):
        """
        Sends the given memory page to the target device during the firmware update.

        Args:
            memory_page (Bytearray): the memory page to send.

        Raises:
            FirmwareUpdateException: if there is any error sending the memory page.
        """
        page_flashed = False
        checksum_retries = _GEN3_BOOTLOADER_FLASH_CHECKSUM_RETRIES
        verify_retries = _GEN3_BOOTLOADER_FLASH_VERIFY_RETRIES
        retry = 1
        while not page_flashed and checksum_retries > 0 and verify_retries > 0:
            _log.debug("Sending page %d/%d %d%% - retry %d" % (self._ebin_file.page_index + 1,
                                                               self._ebin_file.num_pages,
                                                               self._ebin_file.percent,
                                                               retry))
            try:
                # Send program page command.
                self._xbee_serial_port.write(str.encode(_Gen3BootloaderCommand.PROGRAM_PAGE.command))
                # Write page index. This depends on the protocol version.
                if self._protocol_version == _GEN3_BOOTLOADER_PROTOCOL_VERSION_0:
                    self._xbee_serial_port.write(bytes([self._ebin_file.page_index & 0xFF]))  # Truncate to one byte.
                else:
                    page_index = self._ebin_file.page_index & 0xFFFF  # Truncate to two bytes.
                    page_index_bytes = utils.int_to_bytes(page_index, num_bytes=2)
                    page_index_bytes = bytearray(reversed(page_index_bytes))  # Swap the array order.
                    self._xbee_serial_port.write(page_index_bytes)
                # Write the page data.
                self._xbee_serial_port.write(memory_page)
                # Write the page verification. This depends on the protocol version.
                self._xbee_serial_port.write(self._calculate_page_verification(memory_page))
                # Read the programming answer.
                deadline = _get_milliseconds() + 500
                answer = None
                while not answer and _get_milliseconds() < deadline:
                    answer = self._xbee_serial_port.read(1)
                if not answer:
                    raise FirmwareUpdateException(_ERROR_COMMUNICATION_LOST)
                elif answer == _GEN3_BOOTLOADER_ERROR_CHECKSUM:
                    checksum_retries -= 1
                    retry += 1
                    if checksum_retries == 0:
                        raise FirmwareUpdateException(_ERROR_PAGE_CHECKSUM % self._ebin_file.page_index)
                elif answer == _GEN3_BOOTLOADER_ERROR_VERIFY:
                    verify_retries -= 1
                    retry += 1
                    if verify_retries == 0:
                        raise FirmwareUpdateException(_ERROR_PAGE_VERIFICATION % self._ebin_file.page_index)
                else:
                    page_flashed = True
            except SerialException as e:
                raise FirmwareUpdateException(_ERROR_SERIAL_COMMUNICATION % str(e))

    def _calculate_page_verification(self, memory_page):
        """
        Calculates and returns the verification sequence for the given memory page.

        Args:
            memory_page (Bytearray): memory page to calculate its verification sequence.

        Returns
            Bytearray: the calculated verification sequence for the given memory page.
        """
        if self._protocol_version == _GEN3_BOOTLOADER_PROTOCOL_VERSION_0:
            value = 0x00
            for byte in memory_page:
                value += byte
            value = value & 0xFF
            return bytearray([((~value & 0xFF) - len(memory_page)) & 0xFF])
        else:
            crc = 0x0000
            for i in range(0, len(memory_page)):
                crc ^= memory_page[i] << 8
                for j in range(0, 8):
                    if (crc & 0x8000) > 0:
                        crc = (crc << 1) ^ _POLYNOMINAL_DIGI_BL
                    else:
                        crc = crc << 1
                    crc &= 0xFFFF
            return (crc & 0xFFFF).to_bytes(2, byteorder='little')

    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error finishing the firmware update process.
        """
        # Send the finish command.
        self._send_finish_command()
        # Verify the transferred image.
        self._send_verify_command()


class _RemoteXBee3FirmwareUpdater(_RemoteFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process on XBee 3 devices.
    """

    __DEVICE_RESET_TIMEOUT_ZB = 3  # seconds
    __DEVICE_RESET_TIMEOUT_DM = 20  # seconds
    __DEVICE_RESET_TIMEOUT_802 = 28  # seconds

    def __init__(self, remote_device, xml_firmware_file, ota_firmware_file=None, otb_firmware_file=None,
                 timeout=_READ_DATA_TIMEOUT, max_block_size=0, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteXBee3FirmwareUpdater` with the given parameters.

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
        super(_RemoteXBee3FirmwareUpdater, self).__init__(remote_device, xml_firmware_file, timeout=timeout,
                                                          progress_callback=progress_callback)

        self._ota_firmware_file = ota_firmware_file
        self._otb_firmware_file = otb_firmware_file
        self._updater_was_connected = False
        self._updater_ao_value = None
        self._updater_my_value = None
        self._updater_rr_value = None
        self._ota_file = None
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
            self._ota_firmware_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_OTA))

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
            self._otb_firmware_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_OTB))

        if not _file_exists(self._otb_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._otb_firmware_file)

        # If asked to check the bootloader file, replace the OTA file with the .otb one.
        # Unlike local firmware updates, remote firmware updates only transfer one file for fw + bootloader.
        self._ota_file = _OTAFile(self._otb_firmware_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as e:
            self._exit_with_error(str(e))

    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during updater configuration or not.

        Returns:
            Boolean: `True` if AO parameter should be configured, `False` otherwise.
        """
        return True

    def _configure_updater_extra(self):
        """
        Performs extra updater device configuration before the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        # Specific settings per protocol.
        if self._local_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            # Store RR value.
            self._updater_rr_value = _read_device_parameter_with_retries(self._local_device,
                                                                         ATStringCommand.RR.command)
            if self._updater_rr_value is None:
                self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.RR.command)
            # Set new RR value.
            if not _set_device_parameter_with_retries(
                    self._local_device, ATStringCommand.RR.command,
                    bytearray([_VALUE_UNICAST_RETRIES_MEDIUM]), apply=True):
                self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.RR.command)
        elif self._local_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # Store MY value.
            self._updater_my_value = _read_device_parameter_with_retries(self._local_device,
                                                                         ATStringCommand.MY.command)
            if self._updater_my_value is None:
                self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.MY.command)
            # Set new MY value.
            if not _set_device_parameter_with_retries(
                    self._local_device, ATStringCommand.MY.command,
                    XBee16BitAddress.BROADCAST_ADDRESS.address, apply=True):
                self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.MY.command)

    def _restore_updater_extra(self):
        """
        Performs extra updater configuration to leave it in its original state as it was before the update operation.

        Raises:
            XBeeException: if there is any error restoring the device connection.
        """
        # Close OTA file.
        if self._ota_file:
            self._ota_file.close_file()
        # Specific settings per protocol.
        if self._local_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            # Restore RR value.
            _set_device_parameter_with_retries(
                self._local_device, ATStringCommand.RR.command,
                self._updater_rr_value, apply=True)
        elif self._updater_my_value and self._local_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # Restore MY value.
            _set_device_parameter_with_retries(
                self._local_device, ATStringCommand.MY.command,
                self._updater_my_value, apply=True)

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
                                          _EXPLICIT_PACKET_EXTENDED_TIMEOUT if
                                          self._local_device.get_protocol() == XBeeProtocol.ZIGBEE else 0x00,
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
            payload.extend(_reverse_bytearray(utils.int_to_bytes(self._get_ota_size(), 4)))

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
        disable_def_resp = _RemoteXBee3FirmwareUpdater._calculate_frame_control(frame_type=0,
                                                                                manufac_specific=False,
                                                                                dir_srv_to_cli=False,
                                                                                disable_def_resp=True)
        enable_def_resp = _RemoteXBee3FirmwareUpdater._calculate_frame_control(frame_type=0,
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
                    # DigiMesh: Updating from 3004 to 300A/300B, we are
                    # receiving Transmit status responses with 0x25 error
                    # (Route not found). If we wait a little between retries,
                    # the response contains a 0x00 (success) after 3 retries
                    time.sleep(2)
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
                #   - 'Route not found' error on XBee 3 DigiMesh remote firmware
                #     update from 3004 to 300A/300B
                #   - 'Address not found' on XBee 3 ZB remote firmware update
                #
                # The workaround considers those TX status as valid.
                #
                # See https://jira.digi.com/browse/XBHAWKDM-796
                #
                dm_ack_error = (status_frame.transmit_status in (TransmitStatus.NO_ACK,
                                                                 TransmitStatus.ROUTE_NOT_FOUND)
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


class _RemoteFilesystemUpdater(_RemoteXBee3FirmwareUpdater):
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
        _log.debug(" - Firmware version: %s",
                   utils.hex_to_string([self._target_firmware_version], pretty=False)
                   if self._target_firmware_version is not None else "-")
        self._target_hardware_version = self._get_target_hardware_version()
        _log.debug(" - Hardware version: %s",
                   utils.hex_to_string([self._target_hardware_version], pretty=False)
                   if self._target_hardware_version is not None else "-")

        # Check if the hardware version is compatible with the filesystem update process.
        if self._target_hardware_version and self._target_hardware_version not in XBEE3_HARDWARE_VERSIONS:
            self._exit_with_error(ERROR_HARDWARE_VERSION_NOT_SUPPORTED % self._target_hardware_version)

    def _update_target_information(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._update_target_information`
        """
        # Remote filesystem update does not require to update target information after the update.
        pass


class _RemoteGPMFirmwareUpdater(_RemoteFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process of general purpose memory (GPM) devices.
    """

    __DEVICE_RESET_TIMEOUT = 10  # seconds
    __DEFAULT_PAGE_SIZE = 128
    __DEFAULT_TIMEOUT = 20  # Seconds.

    def __init__(self, remote_device, xml_firmware_file, xbee_firmware_file=None, timeout=__DEFAULT_TIMEOUT,
                 progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteGPMFirmwareUpdater` with the given parameters.

        Args:
            remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
            xml_firmware_file (String): path of the XML file that describes the firmware to upload.
            xbee_firmware_file (String, optional): path of the binary firmware file to upload.
            timeout (Integer, optional): the timeout to wait for remote frame answers.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: if there is any error performing the remote firmware update.
        """
        super(_RemoteGPMFirmwareUpdater, self).__init__(remote_device, xml_firmware_file, timeout=timeout,
                                                        progress_callback=progress_callback)

        self._xbee_firmware_file = xbee_firmware_file

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__class__.__DEVICE_RESET_TIMEOUT

    def _check_firmware_binary_file(self):
        """
        Verifies that the firmware binary file exists.

        Raises:
            FirmwareUpdateException: if the firmware binary file does not exist or is invalid.
        """
        # If not already specified, the binary firmware file is usually in the same folder as the XML firmware file.
        if self._xbee_firmware_file is None:
            path = Path(self._xml_firmware_file)
            self._xbee_firmware_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_EBIN))

        if not _file_exists(self._xbee_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._xbee_firmware_file, restore_updater=False)

    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.

        Raises:
            FirmwareUpdateException: if the bootloader binary file does not exist.
        """
        # General Purpose Memory devices do not have bootloader update file.
        pass

    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during updater configuration or not.

        Returns:
            Boolean: `True` if AO parameter should be configured, `False` otherwise.
        """
        return True

    def _configure_updater_extra(self):
        """
        Performs extra updater device configuration before the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        # GPM devices do not require extra configuration prior to firmware update process.
        pass

    def _restore_updater_extra(self):
        """
        Performs extra updater configuration to leave it in its original state as it was before the update operation.

        Raises:
            XBeeException: if there is any error restoring the device configuration.
        """
        # GPM devices do not require extra configuration to restore it to its original state.
        pass

    def _create_explicit_frame(self, payload):
        """
        Creates and returns an explicit addressing GPM frame using the given payload.

        Args:
            payload (Bytearray): the payload for the explicit addressing GPM frame.

        Returns:
            :class:`.ExplicitAddressingPacket`: the explicit addressing GPM frame with the given payload.
        """
        packet = ExplicitAddressingPacket(self._local_device.get_next_frame_id(),
                                          self._remote_device.get_64bit_addr(),
                                          self._remote_device.get_16bit_addr(),
                                          _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE,
                                          _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE,
                                          _EXPLICIT_PACKET_CLUSTER_GPM,
                                          _EXPLICIT_PACKET_PROFILE_DIGI,
                                          _EXPLICIT_PACKET_BROADCAST_RADIUS_MAX,
                                          0x00,
                                          payload)
        return packet

    def _create_gpm_command_frame(self, command, options=0, block_index=0, byte_index=0, gpm_data=None):
        """
        Creates and returns a GPM command frame with the given parameters.

        Args:
            command (:class:`.GPMCommand`): the GPM command to create the frame for.
            options (Integer, optional): command options byte, defaults to 0.
            block_index (Integer, optional): the block number addressed in the GPM command, defaults to 0.
            byte_index (Integer, optional): the byte index within the addressed GPM command, defaults to 0.
            gpm_data (Bytearray, optional): the command GPM data. Defaults to None.

        Returns:
            :class:`.ExplicitAddressingPacket`: the GPM command frame.
        """
        payload = bytearray()
        payload.append(command.command_id)  # Command ID.
        payload.append(options & 0xFF)  # Command options
        payload.extend(utils.int_to_bytes(block_index & 0xFFFF, 2))  # Block index
        payload.extend(utils.int_to_bytes(byte_index & 0xFFFF, 2))  # Byte index
        if gpm_data:
            payload.extend(utils.int_to_bytes(len(gpm_data) & 0xFFFF, 2))  # Data length
            payload.extend(gpm_data)  # Data
        else:
            payload.extend(bytearray([0x00, 0x00]))  # Data length
        return self._create_explicit_frame(payload)

    def _gpm_receive_frame_callback(self, xbee_frame):
        """
        Callback used to be notified on GPM frame reception.

        Args:
            xbee_frame (:class:`.XBeeAPIPacket`): the received frame
        """
        if xbee_frame.get_frame_type() == ApiFrameType.TRANSMIT_STATUS:
            if xbee_frame.transmit_status == TransmitStatus.SUCCESS:
                self._gpm_frame_sent = True
                # Sometimes the transmit status frame is received after the explicit frame
                # indicator. Notify only if the transmit status frame was also received.
                if self._gpm_frame_received:
                    # Continue execution.
                    self._receive_lock.set()
            else:
                # Remove explicit frame indicator received flag if it was set.
                if self._gpm_frame_received:
                    self._gpm_frame_received = False
                # Continue execution, it will exit with error as received flags are not set.
                self._receive_lock.set()
        elif (xbee_frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR
              and xbee_frame.source_endpoint == _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE
              and xbee_frame.dest_endpoint == _EXPLICIT_PACKET_ENDPOINT_DIGI_DEVICE
              and xbee_frame.cluster_id == _EXPLICIT_PACKET_CLUSTER_GPM
              and xbee_frame.profile_id == _EXPLICIT_PACKET_PROFILE_DIGI
              and xbee_frame.x64bit_source_addr == self._remote_device.get_64bit_addr()):
            # If GPM frame was already received, ignore this frame.
            if self._gpm_frame_received:
                return
            # Store GPM answer payload.
            self._gpm_answer_payload = xbee_frame.rf_data
            # Flag frame as received.
            self._gpm_frame_received = True
            # Sometimes the transmit status frame is received after the explicit frame
            # indicator. Notify only if the transmit status frame was also received.
            if self._gpm_frame_sent:
                # Continue execution.
                self._receive_lock.set()

    def _send_explicit_gpm_frame(self, frame, expect_answer=True):
        """
        Sends the given explicit GPM frame to the remote device.

        Args:
            frame (:class:`.ExplicitAddressingPacket`): the explicit GPM frame to send.
            expect_answer (Boolean, optional): ``True`` if after sending the frame an answer is expected,
                                               ``False`` otherwise. Optional, defaults to ``True``.

        Raises:
            FirmwareUpdateException: if there is any error sending the explicit GPM frame.
        """
        # Clear vars.
        self._receive_lock.clear()
        self._gpm_answer_payload = None
        self._gpm_frame_sent = False
        self._gpm_frame_received = False

        # Add a frame listener to wait for answer.
        self._local_device.add_packet_received_callback(self._gpm_receive_frame_callback)
        try:
            # Send frame.
            self._local_device.send_packet(frame)
            # Wait for answer.
            self._receive_lock.wait(self._timeout)
        except XBeeException as e:
            self._exit_with_error(_ERROR_SERIAL_COMMUNICATION % str(e))
        finally:
            # Remove frame listener.
            self._local_device.del_packet_received_callback(self._gpm_receive_frame_callback)

        # Check if packet was correctly sent.
        if not self._gpm_frame_sent:
            raise FirmwareUpdateException(_ERROR_SEND_FRAME)
        if not self._gpm_frame_received and expect_answer:
            raise FirmwareUpdateException(_ERROR_RECEIVE_FRAME_TIMEOUT)

    def _execute_gpm_command(self, command, options=0, block_index=0, byte_index=0, gpm_data=None, retries=1,
                             expect_answer=True):
        """
        Executes the given GPM command.

        Args:
            command (:class:`.GPMCommand`): the GPM command to execute.
            options (Integer, optional): command options byte, defaults to 0.
            block_index (Integer, optional): the block number addressed in the GPM command, defaults to 0.
            byte_index (Integer, optional): the byte index within the addressed GPM command, defaults to 0.
            gpm_data (Bytearray, optional): the command GPM data, defaults to None.
            retries (Integer, optional): the number of retries to execute the command. Defaults to 1.
            expect_answer (Boolean, optional): ``True`` if the command execution should expect an answer,
                                               ``False`` otherwise. Optional, defaults to ``True``.

        Raises:
            FirmwareUpdateException: if there is any error executing the GPM command.
        """
        error = None
        while retries > 0:
            error = None
            try:
                self._send_explicit_gpm_frame(self._create_gpm_command_frame(command, options=options,
                                                                             block_index=block_index,
                                                                             byte_index=byte_index,
                                                                             gpm_data=gpm_data),
                                              expect_answer=expect_answer)
                if not expect_answer:
                    break
                # Check for communication error.
                if not self._gpm_answer_payload or len(self._gpm_answer_payload) < 8 or \
                        self._gpm_answer_payload[0] != command.answer_id:
                    error = _ERROR_INVALID_GPM_ANSWER
                    retries -= 1
                elif (self._gpm_answer_payload[1] & 0x1) == 1:  # Check for command error.
                    error = command.execution_error
                    retries -= 1
                else:
                    break
            except FirmwareUpdateException as e:
                error = str(e)
                retries -= 1
        if error:
            self._exit_with_error(error)

    def _read_device_gpm_info(self):
        """
        Reads specific GPM device information required to perform the remote firmware update.

        The relevant information to retrieve is the number of blocks and bytes per block of the flash.

        Raises:
            FirmwareUpdateException: if there is any error reading the GPM device flash information.
        """
        _log.debug("Reading GPM device info")
        self._execute_gpm_command(_GPMCommand.GET_PLATFORM_INFO)
        # Store relevant values.
        self._num_gpm_blocks = utils.bytes_to_int(self._gpm_answer_payload[2:4])
        _log.debug(" - Number of memory blocks: %s", self._num_gpm_blocks)
        self._num_bytes_per_blocks = utils.bytes_to_int(self._gpm_answer_payload[4:6])
        _log.debug(" - Number of bytes per block: %s", self._num_bytes_per_blocks)

    def _erase_flash(self):
        """
        Erases the device flash.

        Raises:
            FirmwareUpdateException: if there is any error erasing the device flash.
        """
        _log.debug("Erasing device flash")
        self._execute_gpm_command(_GPMCommand.ERASE_FLASH)

    def _write_data(self, block_index, byte_index, data, retries):
        """
        Writes data to the device.

        Args:
            block_index (Integer): the block index to write data to.
            byte_index (Integer): the byte index in the block to write data to.
            data (Bytearray): the data to write.
            retries (Integer): number of retries to write data.

        Raises:
            FirmwareUpdateException: if there is any error writing the given data.
        """
        self._execute_gpm_command(_GPMCommand.WRITE_DATA, block_index=block_index, byte_index=byte_index,
                                  gpm_data=data, retries=retries)

    def _verify_firmware(self):
        """
        Verifies the firmware image in the device.

        Raises:
            FirmwareUpdateException: if there is any error verifying the firmware in the device.
        """
        _log.debug("Verifying firmware")
        self._execute_gpm_command(_GPMCommand.VERIFY_IMAGE)

    def _install_firmware(self):
        """
        Installs the firmware in the device.

        Raises:
            FirmwareUpdateException: if there is any error installing the firmware in the device.
        """
        _log.debug("Installing firmware")
        self._execute_gpm_command(_GPMCommand.VERIFY_AND_INSTALL, expect_answer=False)

    def _start_firmware_update(self):
        """
        Starts the firmware update process. Called just before the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error starting the remote firmware update process.
        """
        self._read_device_gpm_info()
        self._erase_flash()

    def _transfer_firmware(self):
        """
        Transfers the firmware to the target.

        Raises:
            FirmwareUpdateException: if there is any error transferring the firmware to the target device.
        """
        _log.info("Updating remote XBee firmware")
        self._progress_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        # Perform file transfer.
        self._ebin_file = _EbinFile(self._xbee_firmware_file, self.__DEFAULT_PAGE_SIZE)
        previous_percent = None
        block_index = 0
        byte_index = 0
        for data_chunk in self._ebin_file.get_next_mem_page():
            if self._progress_callback is not None and self._ebin_file.percent != previous_percent:
                self._progress_callback(self._progress_task, self._ebin_file.percent)
                previous_percent = self._ebin_file.percent
            _log.debug("Sending chunk %d/%d %d%%" % (self._ebin_file.page_index + 1,
                                                     self._ebin_file.num_pages,
                                                     self._ebin_file.percent))
            self._write_data(block_index, byte_index, data_chunk, 3)
            byte_index += len(data_chunk)
            # Increment block index if required.
            if byte_index >= self._num_bytes_per_blocks:
                byte_index = 0
                block_index += 1

    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error finishing the firmware operation.
        """
        self._verify_firmware()
        self._install_firmware()


class _RemoteEmberFirmwareUpdater(_RemoteFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process of Ember devices.
    """
    __DEVICE_RESET_TIMEOUT = 10  # seconds
    __DEFAULT_PAGE_SIZE = 64
    __DEFAULT_TIMEOUT = 20  # Seconds.
    __FIRMWARE_UPDATE_RETRIES = 2
    __INITIALIZATION_RETRIES = 2
    __FIRMWARE_DATA_RETRIES = 5
    __CLEAR_UPDATER_RECOVERY_RETRIES = 3
    __SET_UPDATER_RECOVERY_RETRIES = 3

    def __init__(self, remote_device, xml_firmware_file, xbee_firmware_file=None, timeout=__DEFAULT_TIMEOUT,
                 force_update=True, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteEmberFirmwareUpdater` with the given parameters.

        Args:
            remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
            xml_firmware_file (String): path of the XML file that describes the firmware to upload.
            xbee_firmware_file (String, optional): path of the binary firmware file to upload.
            timeout (Integer, optional): the timeout to wait for remote frame answers.
            force_update (Boolean, optional): `True` to force firmware update even if connectivity tests fail,
                                              `False` otherwise. Defaults to `True`.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: if there is any error performing the remote firmware update.
        """
        super(_RemoteEmberFirmwareUpdater, self).__init__(remote_device, xml_firmware_file, timeout=timeout,
                                                          progress_callback=progress_callback)

        self._xbee_firmware_file = xbee_firmware_file
        self._force_update = force_update
        self._updater_device = None
        self._updater_dh_value = None
        self._updater_dl_value = None
        self._ota_packet_received = False
        self._expected_ota_block = -1
        self._ota_message_type = None
        self._any_data_sent = False

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__class__.__DEVICE_RESET_TIMEOUT

    def _check_firmware_binary_file(self):
        """
        Verifies that the firmware binary file exists.

        Raises:
            FirmwareUpdateException: if the firmware binary file does not exist or is invalid.
        """
        # If not already specified, the binary firmware file is usually in the same folder as the XML firmware file.
        if self._xbee_firmware_file is None:
            path = Path(self._xml_firmware_file)
            self._xbee_firmware_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_EBL))

        if not _file_exists(self._xbee_firmware_file):
            self._exit_with_error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self._xbee_firmware_file, restore_updater=False)

    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.

        Raises:
            FirmwareUpdateException: if the bootloader binary file does not exist.
        """
        # Ember devices do not have bootloader update file.
        pass

    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during updater configuration or not.

        Returns:
            Boolean: `True` if AO parameter should be configured, `False` otherwise.
        """
        # AO parameter is configured in the updater device instead of the local one and only for 802.15.4 devices.
        # Return False and configure it in the extra step, once local device connection is open and we can determine
        # the real updater device.
        return False

    def _configure_updater_extra(self):
        """
        Performs extra updater device configuration before the firmware update operation.

        Raises:
            FirmwareUpdateException: if there is any error configuring the updater device.
        """
        # Determine updater device.
        _log.debug("Looking for best updater device")
        if self._local_device.get_protocol() == XBeeProtocol.ZIGBEE:
            self._updater_device = self._determine_updater_device_zigbee()
        elif self._local_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            self._updater_device = self._determine_updater_device_digimesh()
        elif self._local_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            self._updater_device = self._determine_updater_device_802()
        else:
            self._updater_device = self._local_device
        if not self._updater_device:
            self._exit_with_error(_ERROR_NO_UPDATER_AVAILABLE, restore_updater=True)
        _log.debug("Updater device: %s" % self._updater_device)
        # Save DH parameter.
        self._updater_dh_value = _read_device_parameter_with_retries(self._updater_device, ATStringCommand.DH.command)
        if self._updater_dh_value is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.DH.command)
        # Set new DH value.
        if not _set_device_parameter_with_retries(
                self._updater_device, ATStringCommand.DH.command,
                self._remote_device.get_64bit_addr().address[0:4], apply=True):
            self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.DH.command)
        # Save DL parameter.
        self._updater_dl_value = _read_device_parameter_with_retries(self._updater_device, ATStringCommand.DL.command)
        if self._updater_dl_value is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAMETER % ATStringCommand.DL.command)
        # Set new DL value.
        if not _set_device_parameter_with_retries(
                self._updater_device, ATStringCommand.DL.command,
                self._remote_device.get_64bit_addr().address[4:], apply=True):
            self._exit_with_error(_ERROR_UPDATER_SET_PARAMETER % ATStringCommand.DL.command)

    def _restore_updater_extra(self):
        """
        Performs extra updater configuration to leave it in its original state as it was before the update operation.

        Raises:
            XBeeException: if there is any error restoring the device configuration.
        """
        # Restore DH parameter
        if self._updater_dh_value:
            _set_device_parameter_with_retries(
                self._updater_device, ATStringCommand.DH.command,
                self._updater_dh_value, apply=bool(not self._updater_dl_value))
        # Restore DL parameter
        if self._updater_dl_value:
            _set_device_parameter_with_retries(
                self._updater_device, ATStringCommand.DL.command,
                self._updater_dl_value, apply=True)

    def _determine_updater_device_zigbee(self):
        """
        Determines the updater device that will handle the update process of the remote device in a Zigbee network.

        Returns:
            :class:`.RemoteXBeeDevice`: The updater device that will handle the update process in a Zigbee network.

        Raises:
            FirmwareUpdateException: if there is any error determining the updater device.
        """
        # Check if the remote node is an end device and has a parent that will be the updater. If it has no parent,
        # then the node cannot be updated.
        if self._remote_device.get_role() == Role.END_DEVICE:
            updater = self._remote_device.parent
            if not updater:
                # Discover parent device.
                parent_16bit_address = _read_device_parameter_with_retries(self._remote_device,
                                                                           ATStringCommand.MP.command)
                if not parent_16bit_address:
                    # The end device node is orphan, we cannot update it.
                    self._exit_with_error(_ERROR_END_DEVICE_ORPHAN, restore_updater=True)
                updater = self._local_device.get_network().get_device_by_16(XBee16BitAddress(parent_16bit_address))
                if not updater:
                    self._local_device.get_network().start_discovery_process()
                    while self._local_device.get_network().is_discovery_running():
                        time.sleep(0.5)
                    updater = self._local_device.get_network().get_device_by_16(XBee16BitAddress(parent_16bit_address))
                if not updater:
                    # The end device node is orphan, we cannot update it.
                    self._exit_with_error(_ERROR_END_DEVICE_ORPHAN, restore_updater=True)
            # Verify the updater hardware version.
            if not updater.get_hardware_version():
                updater_hw_version = _read_device_parameter_with_retries(updater, ATStringCommand.HV.command)
            else:
                updater_hw_version = updater.get_hardware_version().code
            if not updater_hw_version or updater_hw_version[0] not in S2C_HARDWARE_VERSIONS:
                self._exit_with_error(_ERROR_UPDATE_FROM_S2C, restore_updater=True)
            return updater
        # Look for updater using the current network connections.
        updater_candidates = self._get_updater_candidates_from_network_connections()
        updater = self._determine_best_updater_from_candidates_list_zigbee(updater_candidates)
        if updater:
            return updater
        # Could not retrieve updater from current network connections, try discovering neighbors.
        updater_candidates = self._get_updater_candidates_from_neighbor_discover()
        updater = self._determine_best_updater_from_candidates_list_zigbee(updater_candidates)
        return updater

    def _determine_updater_device_digimesh(self):
        """
        Determines the updater device that will handle the update process of the remote device in a DigiMesh network.

        Returns:
            :class:`.RemoteXBeeDevice`: The updater device that will handle the update process in a DigiMesh network.

        Raises:
            FirmwareUpdateException: if there is any error determining the updater device.
        """
        # Look for updater using the current network connections.
        updater_candidates = self._get_updater_candidates_from_network_connections()
        updater = self._determine_best_updater_from_candidates_list_digimesh(updater_candidates)
        if updater:
            return updater
        # Could not retrieve updater from current network connections, try discovering neighbors.
        updater_candidates = self._get_updater_candidates_from_neighbor_discover()
        updater = self._determine_best_updater_from_candidates_list_digimesh(updater_candidates)
        return updater

    def _determine_updater_device_802(self):
        """
        Determines the updater device that will handle the update process of the remote device in a 802.15.4 network.

        Returns:
            :class:`.RemoteXBeeDevice`: The updater device that will handle the update process in a 802.15.4 network.

        Raises:
            FirmwareUpdateException: if there is any error determining the updater device.
        """
        # In a 802.15.4 network, the updater device is the local device. The only restriction is that local and
        # remote devices mut be of the same hardware type (S2C <> S2C)
        if self._local_device.get_hardware_version().code in S2C_HARDWARE_VERSIONS and \
                self._get_target_hardware_version() in S2C_HARDWARE_VERSIONS:
            return self._local_device
        self._exit_with_error(_ERROR_UPDATE_FROM_S2C, restore_updater=True)

    def _get_updater_candidates_from_network_connections(self):
        """
        Returns a list of updater candidates extracted from the current network connections.

        Returns:
            List: the list of possible XBee updater devices.
        """
        xbee_network = self._local_device.get_network()
        connections = xbee_network.get_connections()
        if not connections:
            return None
        # Sort the connections list by link quality from 'node a' to 'node b'.
        connections.sort(key=lambda conn: conn.lq_a2b)
        updater_candidates = []
        for connection in connections:
            # Only use connections that have remote device as 'node b'.
            if not connection.node_b == self._remote_device:
                continue
            # Do not use connections that have 'node a' as end devices.
            if connection.node_a.get_role() == Role.END_DEVICE:
                continue
            # Do not use connections that have 'node a' as the remote device.
            if connection.node_a == self._remote_device:
                continue
            # The 'node a' must be an S2C.
            if not connection.node_a.get_hardware_version():
                updater_hw_version = _read_device_parameter_with_retries(connection.node_a, ATStringCommand.HV.command)
            else:
                updater_hw_version = connection.node_a.get_hardware_version().code
            if not updater_hw_version or updater_hw_version[0] not in S2C_HARDWARE_VERSIONS:
                continue
            # If the 'node_a' is the local device, return only it.
            if connection.node_a == self._local_device:
                updater_candidates.append(self._local_device)
                break
            # The connection passed the tests, add connection 'node a' as updater candidate.
            updater_candidates.append(connection.node_a)
        return updater_candidates if updater_candidates else None

    def _get_updater_candidates_from_neighbor_discover(self):
        """
        Returns a list of updater candidates extracted from a neighbor discover.

        Returns:
            List: the list of possible XBee updater devices.
        """
        neighbors = self._remote_device.get_neighbors()
        if not neighbors:
            return None
        # Sort the connections list by link quality from 'node a' to 'node b'.
        neighbors.sort(key=lambda neigh: neigh.lq)
        updater_candidates = []
        for neighbor in neighbors:
            # Neighbor cannot be an end device.
            if neighbor.node.get_role() == Role.END_DEVICE:
                continue
            # Neighbor cannot be the remote node itself.
            if neighbor.node == self._remote_device:
                continue
            # The neighbor must be an S2C device.
            if not neighbor.node.get_hardware_version():
                neighbor_hw_version = _read_device_parameter_with_retries(neighbor.node, ATStringCommand.HV.command)
            else:
                neighbor_hw_version = neighbor.node.get_hardware_version().code
            if not neighbor_hw_version or neighbor_hw_version[0] not in S2C_HARDWARE_VERSIONS:
                continue
            # If the neighbor is the local device, return only it.
            if neighbor == self._local_device:
                updater_candidates.append(self._local_device)
                break
            # The neighbor passed the tests, add it as an updater candidate.
            updater_candidates.append(neighbor.node)
        return updater_candidates if updater_candidates else None

    def _determine_best_updater_from_candidates_list_zigbee(self, updater_candidates):
        """
        Determines which is the best updater node of the given list for a Zigbee network.

        Params:
            updater_candidates (List): the list of possible XBee updater devices.

        Returns:
            :class:`.AbstractXBeeDevice`: the best updater XBee device, `None` if no candidate found.
        """
        if updater_candidates:
            # Check if it is the local device.
            if len(updater_candidates) == 1 and updater_candidates[0] == self._local_device:
                return self._local_device
            # Iterate the list of updater candidates performing a loopback test. Return the first successful one.
            for candidate in updater_candidates:
                loopback_test = _LoopbackTest(self._local_device, candidate)
                if loopback_test.execute_test():
                    return candidate
        return None

    def _determine_best_updater_from_candidates_list_digimesh(self, updater_candidates):
        """
        Determines which is the best updater node of the given list for a DigiMesh network.

        Params:
            updater_candidates (List): the list of possible XBee updater devices.

        Returns:
            :class:`.AbstractXBeeDevice`: the best updater XBee device, `None` if no candidate found.
        """
        if updater_candidates:
            # Check if it is the local device.
            if len(updater_candidates) == 1 and updater_candidates[0] == self._local_device:
                return self._local_device
            # Iterate the list of updater candidates and test each one.
            for candidate in updater_candidates:
                # First perform a Trace Route test and skip the candidate if the remote device is in the route.
                traceroute_test = _TraceRouteTest(self._local_device, candidate, self._remote_device)
                if not traceroute_test.execute_test():
                    continue
                # Second perform a loopback test against the candidate and return it if the test passes.
                loopback_test = _LoopbackTest(self._local_device, candidate)
                if loopback_test.execute_test():
                    return candidate
        return None

    def _clear_updater_recovery_mode(self):
        """
        Clears the recovery mode of the updater device.

        Returns:
            Boolean: `True` if recovery mode was successfully cleared in updater, `False` otherwise.
        """
        _log.debug("Clearing recovery mode from updater device...")
        # Frame ID must be greater than 2 for OTA commands, otherwise response will be processed incorrectly.
        packet = RemoteATCommandPacket(3,
                                       self._updater_device.get_64bit_addr(),
                                       self._updater_device.get_16bit_addr(),
                                       RemoteATCmdOptions.NONE.value,
                                       ATStringCommand.PERCENT_U.command,
                                       parameter=bytearray([0]))
        retries = self.__CLEAR_UPDATER_RECOVERY_RETRIES
        recovery_cleared = False
        while not recovery_cleared and retries > 0:
            try:
                response = self._local_device.send_packet_sync_and_get_response(packet)
                if not response or not isinstance(response, RemoteATCommandResponsePacket) or not \
                        response.status == ATCommandStatus.OK:
                    _log.warning("Invalid 'clear recovery' command answer: %s" % response.status.description)
                    retries -= 1
                    time.sleep(1)
                else:
                    recovery_cleared = True
            except XBeeException as e:
                _log.warning("Could not send 'clear recovery' command: %s" % str(e))
                retries -= 1
                time.sleep(1)
        if not recovery_cleared:
            _log.warning("Could not send 'clear recovery' command after %s retries" %
                         self.__CLEAR_UPDATER_RECOVERY_RETRIES)
        return recovery_cleared

    def _set_updater_recovery_mode(self):
        """
        Puts the updater device in recovery mode.

        Returns:
            Boolean: `True` if recovery mode was successfully set in updater, `False` otherwise.
        """
        _log.debug("Setting updater device in recovery mode...")
        # Frame ID must be greater than 2 for OTA commands, otherwise response will be processed incorrectly.
        packet = RemoteATCommandPacket(3,
                                       self._updater_device.get_64bit_addr(),
                                       self._updater_device.get_16bit_addr(),
                                       RemoteATCmdOptions.NONE.value,
                                       ATStringCommand.PERCENT_U.command,
                                       self._remote_device.get_64bit_addr().address)
        retries = self.__SET_UPDATER_RECOVERY_RETRIES
        recovery_set = False
        while not recovery_set and retries > 0:
            # Clear vars.
            self._receive_lock.clear()
            self._ota_packet_received = False
            self._expected_ota_block = -1
            self._ota_message_type = None
            try:
                response = self._local_device.send_packet_sync_and_get_response(packet)
                if not response or not isinstance(response, RemoteATCommandResponsePacket) or not \
                        response.status == ATCommandStatus.OK:
                    if not response:
                        _log.warning("Answer for 'set recovery' command not received")
                    else:
                        _log.warning("Invalid 'set recovery' command answer: %s" % response.status.description)
                    return False
                else:
                    # Register OTA callback.
                    self._local_device.add_packet_received_callback(self._ota_callback)
                    # Wait for answer.
                    self._receive_lock.wait(self._timeout)
                    # Remove frame listener.
                    self._local_device.del_packet_received_callback(self._ota_callback)
                    # Check if OTA answer was received.
                    if self._packet_received and self._ota_message_type == EmberBootloaderMessageType.QUERY_RESPONSE:
                        recovery_set = True
                    else:
                        _log.warning("Invalid OTA message type for 'set recovery' command: %s" %
                                     self._ota_message_type.description)
                        retries -= 1
            except XBeeException as e:
                _log.warning("Could not send 'set recovery' command: %s" % str(e))
                return False
        if not recovery_set:
            _log.warning("Could not send 'set recovery' command after %s retries" %
                         self.__SET_UPDATER_RECOVERY_RETRIES)
        return recovery_set

    def _set_remote_programming_mode(self):
        """
        Puts the remote (target) device in programming mode.

        Returns:
            Boolean: `True` if programming mode was successfully set in remote device, `False` otherwise.
        """
        _log.debug("Setting remote device in programming mode...")
        # Frame ID must be greater than 2 for OTA commands, otherwise response will be processed incorrectly.
        packet = RemoteATCommandPacket(3,
                                       self._remote_device.get_64bit_addr(),
                                       self._remote_device.get_16bit_addr(),
                                       RemoteATCmdOptions.NONE.value,
                                       ATStringCommand.PERCENT_P.command,
                                       _VALUE_PRESERVE_NEWTWORK_SETTINGS)
        try:
            response = self._local_device.send_packet_sync_and_get_response(packet)
            if not response or not isinstance(response, RemoteATCommandResponsePacket) or not \
                    response.status == ATCommandStatus.OK:
                if not response:
                    _log.warning("Answer for 'programming mode' command not received")
                else:
                    _log.warning("Invalid 'programming mode' command answer: %s" % response.status.description)
                return False
            else:
                return True
        except XBeeException as e:
            _log.warning("Could not send 'programming mode' command: %s" % str(e))
            return False

    def _ota_callback(self, xbee_frame):
        """
        Callback used to receive OTA firmware update process status frames.

        Params:
            :class:`.XBeePacket`: the received XBee packet
        """
        # If frame was already received, ignore this frame, just notify.
        if self._packet_received:
            self._receive_lock.set()
            return
        if xbee_frame.get_frame_type() == ApiFrameType.OTA_FIRMWARE_UPDATE_STATUS:
            # Check received data.
            self._ota_message_type = xbee_frame.bootloader_msg_type
            received_ota_block = xbee_frame.block_number
        elif xbee_frame.get_frame_type() == ApiFrameType.RECEIVE_PACKET or \
                xbee_frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR:
            # Check received data.
            data = xbee_frame.rf_data
            if len(data) < 10:
                return
            self._ota_message_type = EmberBootloaderMessageType.get(data[0])
            received_ota_block = data[1]
        else:
            return
        if self._expected_ota_block != -1:
            if self._expected_ota_block == received_ota_block:
                self._packet_received = True
            else:
                return
        else:
            self._packet_received = True
        self._receive_lock.set()

    def _create_ota_explicit_packet(self, frame_id, payload):
        """
        Creates and returns an OTA firmware update explicit packet using the given parameters.

        Params:
            frame_id (Integer): the frame ID of the packet.
            payload (Bytearray): the packet payload.

        Returns:
            :class:.`ExplicitAddressingPacket`: the generated OTA packet.
        """
        packet = ExplicitAddressingPacket(frame_id,
                                          self._updater_device.get_64bit_addr(),
                                          self._updater_device.get_16bit_addr(),
                                          _EXPLICIT_PACKET_ENDPOINT_DATA,
                                          _EXPLICIT_PACKET_ENDPOINT_DATA,
                                          _EXPLICIT_PACKET_CLUSTER_UPDATE_LOCAL_UPDATER
                                          if self._updater_device == self._local_device else
                                          _EXPLICIT_PACKET_CLUSTER_UPDATE_REMOTE_UPDATER,
                                          _EXPLICIT_PACKET_PROFILE_DIGI,
                                          _EXPLICIT_PACKET_BROADCAST_RADIUS_MAX,
                                          _EXPLICIT_PACKET_EXTENDED_TIMEOUT if
                                          self._local_device.get_protocol() == XBeeProtocol.ZIGBEE else 0x00,
                                          payload)
        return packet

    def _send_initialization_command(self):
        """
        Sends the firmware transfer initialization command to the updater device.

        Returns:
            Boolean: `True` if the initialization command was sent successfully, `False` otherwise.
        """
        _log.debug("Sending firmware update initialization command...")
        # Clear vars.
        retries = self.__INITIALIZATION_RETRIES
        initialization_succeed = False
        # Generate initialization packet.
        packet = self._create_ota_explicit_packet(0, _VALUE_INITIALIZATION_DATA)
        # Send initialization command.
        while not initialization_succeed and retries > 0:
            # Clear vars.
            self._receive_lock.clear()
            self._packet_received = False
            self._expected_ota_block = -1
            self._ota_message_type = None
            # Register OTA callback.
            self._local_device.add_packet_received_callback(self._ota_callback)
            try:
                # Send frame.
                self._local_device.send_packet(packet)
                # Wait for answer.
                self._receive_lock.wait(self._timeout)
            except XBeeException as e:
                _log.warning("Could not send initialization command: %s" % str(e))
                return False
            finally:
                # Remove frame listener.
                self._local_device.del_packet_received_callback(self._ota_callback)
            # Check if OTA answer was received.
            if not self._packet_received or self._ota_message_type != EmberBootloaderMessageType.QUERY_RESPONSE:
                if not self._packet_received:
                    _log.warning("Answer for data initialization command not received")
                else:
                    _log.warning("Invalid answer for initialization command: %s" % self._ota_message_type.description)
                retries -= 1
                if retries > 0:
                    time.sleep(2)
            else:
                initialization_succeed = True
        if not initialization_succeed:
            _log.warning("Could not send initialization command after %s retries" % self.__INITIALIZATION_RETRIES)
        return initialization_succeed

    def _send_firmware(self):
        """
        Sends the firmware to the updater device.

        Returns:
            Boolean: `True` if the firmware was sent successfully, `False` otherwise.
        """
        # Initialize vars.
        previous_percent = None
        self._ebl_file = _EBLFile(self._xbee_firmware_file, self.__DEFAULT_PAGE_SIZE)
        # Send firmware in chunks.
        for data_chunk in self._ebl_file.get_next_mem_page():
            if self._progress_callback is not None and self._ebl_file.percent != previous_percent:
                self._progress_callback(self._progress_task, self._ebl_file.percent)
                previous_percent = self._ebl_file.percent
            _log.debug("Sending chunk %d/%d %d%%" % (self._ebl_file.page_index + 1,
                                                     self._ebl_file.num_pages,
                                                     self._ebl_file.percent))
            if not self._send_firmware_data(data_chunk):
                return False
            self._any_data_sent = True
        return True

    def _send_firmware_data(self, data):
        """
        Sends the given firmware data to the updater device.

        Params:
            Bytearray: the firmware data to send.

        Returns:
            Boolean: `True` if the firmware data was sent successfully, `False` otherwise.
        """
        # Clear vars.
        retries = self.__FIRMWARE_DATA_RETRIES
        data_sent = False
        ota_block_number = (self._ebl_file.page_index + 1) & 0xFF  # Block number matches page index + 1
        # Build payload.
        payload = bytearray([0x1])  # This byte is always 1.
        payload.append(ota_block_number & 0xFF)  # This byte is the block number.
        payload.extend(data)  # Append the given data.
        # Build the packet.
        packet = self._create_ota_explicit_packet((payload[1] + 2) & 0xFF, payload)
        # Send the data.
        while not data_sent and retries > 0:
            # Clear vars.
            self._receive_lock.clear()
            self._packet_received = False
            self._expected_ota_block = ota_block_number
            self._ota_message_type = None
            # Register OTA callback.
            self._local_device.add_packet_received_callback(self._ota_callback)
            try:
                # Send frame.
                self._local_device.send_packet(packet)
                # Wait for answer.
                self._receive_lock.wait(self._timeout)
            except XBeeException as e:
                _log.warning("Could not send firmware data block %s: %s" % (ota_block_number, str(e)))
                return False
            finally:
                # Remove frame listener.
                self._local_device.del_packet_received_callback(self._ota_callback)
            # Check if OTA answer was received.
            if not self._packet_received or self._ota_message_type != EmberBootloaderMessageType.ACK:
                if not self._packet_received:
                    _log.warning("Answer for data block %s not received" % ota_block_number)
                else:
                    _log.warning("Invalid answer for data block %s: %s" % (ota_block_number,
                                                                           self._ota_message_type.description))
                retries -= 1
                if retries > 0:
                    time.sleep(0.5)
            else:
                data_sent = True
        if not data_sent:
            _log.warning("Could not send data block %s after %s retries" % (ota_block_number,
                                                                            self.__FIRMWARE_DATA_RETRIES))
        return data_sent

    def _start_firmware_update(self):
        """
        Starts the firmware update process. Called just before the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error starting the remote firmware update process.
        """
        # Test connectivity with remote device.
        if self._local_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # There is not a test for 802.15.4, assume connection with device works.
            connectivity_test_success = True
        elif self._local_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            link_test = _LinkTest(self._local_device, self._remote_device, self._updater_device)
            connectivity_test_success = link_test.execute_test()
        else:
            loopback_test = _LoopbackTest(self._local_device, self._remote_device)
            connectivity_test_success = loopback_test.execute_test()
        if not connectivity_test_success:
            if not self._force_update:
                self._exit_with_error(_ERROR_COMMUNICATION_TEST, restore_updater=True)
            else:
                _log.warning("Communication test with remote device failed, forcing update...")
        # Clear recovery mode in updater device, ignore answer.
        self._clear_updater_recovery_mode()
        # Put remote device in programming mode, ignore answer.
        self._set_remote_programming_mode()
        # Wait some time for Ember bootloader to start.
        time.sleep(5)

    def _transfer_firmware(self):
        """
        Transfers the firmware to the target.

        Raises:
            FirmwareUpdateException: if there is any error transferring the firmware to the target device.
        """
        _log.info("Updating remote XBee firmware")
        # Reset variables.
        self._progress_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        retries = self.__FIRMWARE_UPDATE_RETRIES
        firmware_updated = False
        while not firmware_updated and retries > 0:
            # Reset variables.
            self._any_data_sent = False
            # Initialize transfer.
            if not self._send_initialization_command():
                self._exit_with_error(_ERROR_INITIALIZE_PROCESS, restore_updater=True)
            # Send the firmware.
            if not self._send_firmware():
                # Recover the module.
                if self._any_data_sent:
                    # Wait for the bootloader to reset.
                    time.sleep(6)
                if not self._set_updater_recovery_mode():
                    self._clear_updater_recovery_mode()
                    self._exit_with_error(_ERROR_RECOVERY_MODE, restore_updater=True)
                retries -= 1
            else:
                firmware_updated = True
        if not firmware_updated:
            self._exit_with_error(_ERROR_FIRMWARE_UPDATE_RETRIES % self.__FIRMWARE_UPDATE_RETRIES,
                                  restore_updater=True)

    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer firmware operation.

        Raises:
            FirmwareUpdateException: if there is any error finishing the firmware operation.
        """
        _log.debug("Finishing firmware update...")
        # Clear vars.
        both_frames_sent = True
        # Generate finish packet 1.
        packet_1 = self._create_ota_explicit_packet(5, _VALUE_INITIALIZATION_DATA)
        # Generate finish packet 2.
        packet_2 = self._create_ota_explicit_packet(5, _VALUE_END_OF_FILE_DATA)
        # Send first frame, do not wait for answer.
        try:
            self._local_device.send_packet(packet_1)
        except XBeeException as e:
            _log.warning("Could not send first finalize update frame: %s" % str(e))
            both_frames_sent = False
        # Wait some time before sending the second frame.
        time.sleep(2)
        # Send second frame, do not wait for answer.
        try:
            self._local_device.send_packet(packet_2)
        except XBeeException as e:
            _log.warning("Could not send second finalize update frame: %s" % str(e))
            both_frames_sent = False
        if not both_frames_sent:
            self._exit_with_error(_ERROR_FINISH_PROCESS, restore_updater=True)


def update_local_firmware(target, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                          timeout=None, progress_callback=None):
    """
    Performs a local firmware update operation in the given target.

    Args:
        target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
            String: serial port identifier.
            :class:`.XBeeDevice`: XBee to upload its firmware.
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
    if not isinstance(target, str) and not isinstance(target, XBeeDevice):
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

    if (isinstance(target, XBeeDevice) and target.comm_iface
            and target.comm_iface.supports_update_firmware()):
        target.comm_iface.update_firmware(target, xml_firmware_file,
                                          xbee_fw_file=xbee_firmware_file,
                                          bootloader_fw_file=bootloader_firmware_file,
                                          timeout=timeout,
                                          progress_callback=progress_callback)
        return

    bootloader_type = _determine_bootloader_type(target)
    if bootloader_type == _BootloaderType.GECKO_BOOTLOADER:
        update_process = _LocalXBee3FirmwareUpdater(target,
                                                    xml_firmware_file,
                                                    xbee_firmware_file=xbee_firmware_file,
                                                    bootloader_firmware_file=bootloader_firmware_file,
                                                    timeout=timeout,
                                                    progress_callback=progress_callback)
    elif bootloader_type == _BootloaderType.GEN3_BOOTLOADER:
        update_process = _LocalXBeeGEN3FirmwareUpdater(target,
                                                       xml_firmware_file,
                                                       xbee_firmware_file=xbee_firmware_file,
                                                       timeout=timeout,
                                                       progress_callback=progress_callback)
    else:
        # Bootloader not supported.
        _log.error("ERROR: %s", _ERROR_BOOTLOADER_NOT_SUPPORTED)
        raise FirmwareUpdateException(_ERROR_BOOTLOADER_NOT_SUPPORTED)
    update_process.update_firmware()


def update_remote_firmware(remote_device, xml_firmware_file, firmware_file=None, bootloader_file=None,
                           max_block_size=0, timeout=None, progress_callback=None):
    """
    Performs a remote firmware update operation in the given target.

    Args:
        remote_device (:class:`.RemoteXBeeDevice`): remote XBee device to upload its firmware.
        xml_firmware_file (String): path of the XML file that describes the firmware to upload.
        firmware_file (String, optional): path of the binary firmware file to upload.
        bootloader_file (String, optional): path of the bootloader firmware file to upload.
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
    if firmware_file is not None and not _file_exists(firmware_file):
        _log.error("ERROR: %s", _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % firmware_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % firmware_file)
    if bootloader_file is not None and not _file_exists(bootloader_file):
        _log.error("ERROR: %s", _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % bootloader_file)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % bootloader_file)
    if not isinstance(max_block_size, int):
        raise ValueError("Maximum block size must be an integer")
    if max_block_size < 0 or max_block_size > 255:
        raise ValueError("Maximum block size must be between 0 and 255")

    # Launch the update process.
    if not timeout:
        timeout = _REMOTE_FIRMWARE_UPDATE_DEFAULT_TIMEOUT

    comm_iface = remote_device.get_comm_iface()
    if comm_iface and comm_iface.supports_update_firmware():
        comm_iface.update_firmware(remote_device, xml_firmware_file,
                                   xbee_fw_file=firmware_file,
                                   bootloader_fw_file=bootloader_file,
                                   timeout=timeout,
                                   progress_callback=progress_callback)
        return

    bootloader_type = _determine_bootloader_type(remote_device)
    if bootloader_type == _BootloaderType.GECKO_BOOTLOADER:
        update_process = _RemoteXBee3FirmwareUpdater(remote_device,
                                                     xml_firmware_file,
                                                     ota_firmware_file=firmware_file,
                                                     otb_firmware_file=bootloader_file,
                                                     timeout=timeout,
                                                     max_block_size=max_block_size,
                                                     progress_callback=progress_callback)
    elif bootloader_type == _BootloaderType.GEN3_BOOTLOADER:
        update_process = _RemoteGPMFirmwareUpdater(remote_device,
                                                   xml_firmware_file,
                                                   xbee_firmware_file=firmware_file,
                                                   timeout=timeout,
                                                   progress_callback=progress_callback)
    elif bootloader_type == _BootloaderType.EMBER_BOOTLOADER:
        update_process = _RemoteEmberFirmwareUpdater(remote_device,
                                                     xml_firmware_file,
                                                     xbee_firmware_file=firmware_file,
                                                     timeout=timeout,
                                                     force_update=True,
                                                     progress_callback=progress_callback)
    else:
        # Bootloader not supported.
        _log.error("ERROR: %s", _ERROR_BOOTLOADER_NOT_SUPPORTED)
        raise FirmwareUpdateException(_ERROR_BOOTLOADER_NOT_SUPPORTED)
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
            return xbee_device.get_parameter(parameter, apply=False)
        except TimeoutException:
            # On timeout exceptions perform retries.
            retries -= 1
            if retries != 0:
                time.sleep(1)
        except ATCommandException as e:
            _log.warning("Could not read setting '%s': %s (%s)" % (parameter, str(e), e.status.description))
            return None
        except XBeeException as e:
            _log.warning("Could not read setting '%s': %s" % (parameter, str(e)))
            return None

    return None


def _set_device_parameter_with_retries(xbee_device, parameter, value,
                                       apply=False, retries=_PARAMETER_SET_RETRIES):
    """
    Reads the given parameter from the XBee device with the given number of retries.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): the XBee device to read the parameter from.
        parameter (String): the parameter to set.
        value (Bytearray): the parameter value.
        apply (Boolean, optional, default=`False`): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.
        retries (Integer, optional): the number of retries to perform after a :class:`.TimeoutException`

    Returns:
        Boolean: ``True`` if the parameter was correctly set, ``False`` otherwise.
    """
    if xbee_device is None:
        return False

    while retries > 0:
        try:
            xbee_device.set_parameter(parameter, value, apply=apply)
            return True
        except TimeoutException:
            # On timeout exceptions perform retries.
            retries -= 1
            if retries != 0:
                time.sleep(1)
        except ATCommandException as e:
            _log.warning("Could not configure setting '%s': %s (%s)" % (parameter, str(e), e.status.description))
            return False
        except XBeeException as e:
            _log.warning("Could not configure setting '%s': %s" % (parameter, str(e)))
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


def _create_serial_port(port_name, serial_params):
    """
    Creates a serial port object with the given parameters.

    Args:
        port_name (String): name of the serial port.
        serial_params (Dictionary): the serial port parameters as a dictionary.

    Returns:
        :class:`.XBeeSerialPort`: the serial port created with the given parameters.
    """
    return XBeeSerialPort(serial_params["baudrate"],
                          port_name,
                          data_bits=serial_params["bytesize"],
                          stop_bits=serial_params["stopbits"],
                          parity=serial_params["parity"],
                          flow_control=FlowControl.NONE if not serial_params["rtscts"] else
                          FlowControl.HARDWARE_RTS_CTS,
                          timeout=serial_params["timeout"])


def _read_bootloader_header_generic(serial_port, test_character):
    """
    Attempts to read the bootloader header.

    Args:
        serial_port (:class:`.XBeeSerialPort`): The serial port to communicate with.
        test_character (String): The test character to send and check bootloader is active.

    Returns:
        String: the bootloader header, ``None`` if it could not be read.
    """
    try:
        serial_port.purge_port()
        serial_port.write(str.encode(test_character))
        read_bytes = serial_port.read(_READ_BUFFER_LEN)
    except SerialException as e:
        _log.exception(e)
        return None

    if len(read_bytes) > 0:
        try:
            return bytes.decode(read_bytes)
        except UnicodeDecodeError:
            pass

    return None


def _is_bootloader_active_generic(serial_port, test_character, bootloader_prompt):
    """
    Returns whether the device is in bootloader mode or not.

    Args:
        serial_port (:class:`.XBeeSerialPort`): The serial port to communicate with.
        test_character (String): The test character to send and check bootloader is active.
        bootloader_prompt (String): The expected bootloader prompt.

    Returns:
        Boolean: ``True`` if the device is in bootloader mode, ``False`` otherwise.
    """
    for i in range(3):
        bootloader_header = _read_bootloader_header_generic(serial_port, test_character)
        # Look for the Ember/Gecko bootloader prompt.
        if bootloader_header is not None and bootloader_prompt in bootloader_header:
            return True
        time.sleep(0.2)

    return False


def _determine_bootloader_type(target):
    """
    Determines the bootloader type of the given update target.

    Update process varies depending on the bootloader. This method determines the
    bootloader type of the connected device so that a specific update method is used.

    Args:
        target (String or :class:`.AbstractXBeeDevice`): target of the firmware upload operation.
            String: serial port identifier.
            :class:`.AbstractXBeeDevice`: the XBee device to upload its firmware.

    Return:
        :class:`._BootloaderType`: the bootloader type of the connected target.
    """
    if not isinstance(target, str):
        # An XBee device was given. Bootloader type is determined using the device hardware version.
        try:
            was_connected = True
            if not target.is_remote() and not target.is_open():
                target.open()
                was_connected = False
            hardware_version = _read_device_hardware_version(target)
            if not target.is_remote() and not was_connected:
                target.close()
            return _BootloaderType.determine_bootloader_type(hardware_version)
        except XBeeException as e:
            raise FirmwareUpdateException(_ERROR_DETERMINE_BOOTLOADER_TYPE % str(e))
    else:
        # A serial port was given, determine the bootloader by testing prompts and baud rates.
        # -- 1 -- Check if bootloader is active.
        # Create a serial port object. Start with 38400 bps for GEN3 bootloaders.
        try:
            serial_port = _create_serial_port(target, _GEN3_BOOTLOADER_PORT_PARAMETERS)
            serial_port.open()
        except SerialException as e:
            _log.error(_ERROR_CONNECT_SERIAL_PORT, str(e))
            raise FirmwareUpdateException(_ERROR_DETERMINE_BOOTLOADER_TYPE % str(e))
        # Check if GEN3 bootloader is active.
        if _is_bootloader_active_generic(serial_port, _GEN3_BOOTLOADER_TEST_CHARACTER, _GEN3_BOOTLOADER_PROMPT):
            serial_port.close()
            return _BootloaderType.GEN3_BOOTLOADER
        # Check if GECKO bootloader is active.
        serial_port.apply_settings(_GECKO_BOOTLOADER_PORT_PARAMETERS)
        if _is_bootloader_active_generic(serial_port, _GECKO_BOOTLOADER_TEST_CHARACTER, _GECKO_BOOTLOADER_PROMPT):
            serial_port.close()
            return _BootloaderType.GECKO_BOOTLOADER

        # -- 2 -- Bootloader is not active, force bootloader mode.
        break_thread = _BreakThread(serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
        break_thread.start()
        # Loop during some time looking for the bootloader prompt.
        deadline = _get_milliseconds() + (_BOOTLOADER_TIMEOUT * 1000)
        bootloader_type = None
        while _get_milliseconds() < deadline:
            # Check GEN3 bootloader prompt.
            serial_port.apply_settings(_GEN3_BOOTLOADER_PORT_PARAMETERS)
            if _is_bootloader_active_generic(serial_port, _GEN3_BOOTLOADER_TEST_CHARACTER, _GEN3_BOOTLOADER_PROMPT):
                bootloader_type = _BootloaderType.GEN3_BOOTLOADER
                break
            # Check GECKO bootloader prompt.
            serial_port.apply_settings(_GECKO_BOOTLOADER_PORT_PARAMETERS)
            if _is_bootloader_active_generic(serial_port, _GECKO_BOOTLOADER_TEST_CHARACTER, _GECKO_BOOTLOADER_PROMPT):
                bootloader_type = _BootloaderType.GECKO_BOOTLOADER
                break
            # Re-assert lines to try break process again until timeout expires.
            if not break_thread.is_running():
                serial_port.rts = 0
                break_thread = _BreakThread(serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
                break_thread.start()
        # Restore break condition.
        if break_thread.is_running():
            break_thread.stop_break()

        serial_port.close()
        return bootloader_type


def _enable_explicit_mode(xbee):
    """
    Enables explicit mode by modifying the value of 'AO' parameter if it is
    needed.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): The XBee device to configure

    Returns:
        Tuple (Boolean, Bytearray): A tuple with a boolean value indicating
            if the operation finished successfully, and a bytearray with the
            original value of 'AO' parameter. If the last is `None` means the
            value has not been changed.
    """
    # Store AO value.
    ao_value = _read_device_parameter_with_retries(xbee,
                                                   ATStringCommand.AO.command)
    if ao_value is None:
        return False, None

    # Set new AO value.
    # Do not configure AO if it is already:
    #   * Bit 0: Native/Explicit API output (1)
    #   * Bit 5: Prevent ZDO msgs from going out the serial port (0)
    value = bytearray([ao_value[0]])
    protocol = xbee.get_protocol()
    if protocol == XBeeProtocol.ZIGBEE:
        if (value[0] & APIOutputModeBit.EXPLICIT.code
                and not value[0] & APIOutputModeBit.SUPPRESS_ALL_ZDO_MSG.code):
            return True, None
        # Set new AO value.
        value[0] = value[0] | APIOutputModeBit.EXPLICIT.code
        value[0] = value[0] & ~APIOutputModeBit.SUPPRESS_ALL_ZDO_MSG.code
    else:
        if value[0] == APIOutputModeBit.EXPLICIT.code:
            return True, None
        # Set new AO value.
        value[0] = APIOutputModeBit.EXPLICIT.code

    if not _set_device_parameter_with_retries(xbee,
                                              ATStringCommand.AO.command,
                                              value, apply=True):
        return False, ao_value

    return True, ao_value
