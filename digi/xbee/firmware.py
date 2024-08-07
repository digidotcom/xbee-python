# Copyright 2019-2024, Digi International Inc.
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
import time

from abc import ABC, abstractmethod
from enum import Enum, unique
from itertools import repeat
from pathlib import Path
from threading import Event
from threading import Thread
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

import serial

from serial.serialutil import SerialException

from digi.xbee.exception import XBeeException, FirmwareUpdateException, \
    TimeoutException, OperationNotSupportedException
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice,\
    NetworkEventReason, AbstractXBeeDevice
from digi.xbee.models.address import XBee16BitAddress
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import APIOutputModeBit
from digi.xbee.models.options import RemoteATCmdOptions
from digi.xbee.models.protocol import XBeeProtocol, Role, Region, OTAMethod
from digi.xbee.models.status import TransmitStatus, ATCommandStatus, \
    EmberBootloaderMessageType, ModemStatus, UpdateProgressStatus, NodeUpdateType
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ExplicitAddressingPacket, \
    TransmitStatusPacket, RemoteATCommandPacket, RemoteATCommandResponsePacket
from digi.xbee.serial import FlowControl
from digi.xbee.serial import XBeeSerialPort
from digi.xbee.util import utils
from digi.xbee.util import xmodem
from digi.xbee.util.xmodem import XModemException, XModemCancelException


_BOOTLOADER_TIMEOUT = 60  # seconds
_BOOTLOADER_VERSION_SEPARATOR = "."
_BOOTLOADER_VERSION_SIZE = 3
_BOOTLOADER_XBEE3_RESET_ENV_VERSION = bytearray([1, 6, 6])

_GECKO_BOOTLOADER_INIT_TIME = 3  # Seconds
_GECKO_BOOTLOADER_OPTION_RUN_FW = "2"
_GECKO_BOOTLOADER_OPTION_UPLOAD_GBL = "1"
_GECKO_BOOTLOADER_PORT_PARAMS = {"baudrate": 115200,
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
_GECKO_BOOTLOADER_TEST_CHAR = "\n"

_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL = \
    "^.*Gecko Bootloader.*\\(([0-9a-fA-F]{4})-([0-9a-fA-F]{2})(.*)\\).*$"
_PATTERN_GECKO_BOOTLOADER_VERSION = \
    "^.*Gecko Bootloader v([0-9a-fA-F]{1,}\\.[0-9a-fA-F]{1,}\\.[0-9a-fA-F]{1,}).*$"

_XBEE3_BL_DEF_PREFIX = "xb3-boot-rf_"
_XBEE3_RR_BL_DEF_PREFIX = "xb3-boot-rr_"
_XBEE3_XR_BL_DEF_PREFIX = "xb3-boot-lr_"
_XBEE3_BOOTLOADER_FILE_PREFIX = {
    HardwareVersion.XBEE3.code: _XBEE3_BL_DEF_PREFIX,
    HardwareVersion.XBEE3_SMT.code: _XBEE3_BL_DEF_PREFIX,
    HardwareVersion.XBEE3_TH.code: _XBEE3_BL_DEF_PREFIX,
    HardwareVersion.XBEE3_RR.code: _XBEE3_RR_BL_DEF_PREFIX,
    HardwareVersion.XBEE3_RR_TH.code: _XBEE3_RR_BL_DEF_PREFIX,
    HardwareVersion.XBEE3_DM_LR.code: _XBEE3_XR_BL_DEF_PREFIX,
    HardwareVersion.XBEE3_DM_LR_868.code: _XBEE3_XR_BL_DEF_PREFIX,
    HardwareVersion.XBEE_XR_900_TH.code: _XBEE3_XR_BL_DEF_PREFIX,
    HardwareVersion.XBEE_XR_868_TH.code: _XBEE3_XR_BL_DEF_PREFIX,
    HardwareVersion.XBEE_BLU.code: _XBEE3_RR_BL_DEF_PREFIX,
    HardwareVersion.XBEE_BLU_TH.code: _XBEE3_RR_BL_DEF_PREFIX
}

_GEN3_BOOTLOADER_ERROR_CHECKSUM = 0x12
_GEN3_BOOTLOADER_ERROR_VERIFY = 0x13
_GEN3_BOOTLOADER_FLASH_CHECKSUM_RETRIES = 3
_GEN3_BOOTLOADER_FLASH_VERIFY_RETRIES = 3
_GEN3_BOOTLOADER_PORT_PARAMS = {"baudrate": 38400,
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
_GEN3_BOOTLOADER_TEST_CHAR = "\n"
_GEN3_BOOTLOADER_TRANSFER_ACK = 0x55

_BUFFER_SIZE_SHORT = 2
_BUFFER_SIZE_INT = 4
_BUFFER_SIZE_IEEE_ADDR = 8
_BUFFER_SIZE_STR = 32

_READ_BUFFER_LEN = 256
_READ_DATA_TIMEOUT = 3  # Seconds.

_DEVICE_BREAK_RESET_TIMEOUT = 10  # seconds
_DEVICE_CONNECTION_RETRIES = 3

_ERROR_BOOTLOADER_MODE = "Could not enter in bootloader mode"
_ERROR_BOOTLOADER_NOT_SUPPORTED = "XBee does not support firmware update process"
_ERROR_COMPATIBILITY_NUMBER = "Device compatibility number (%d) is greater " \
                              "than the firmware one (%d)"
_ERROR_COMMUNICATION_LOST = "Communication with the device was lost"
_ERROR_COMMUNICATION_TEST = "Communication test with the remote device failed"
_ERROR_CONNECT_DEVICE = "Could not connect with XBee device after %s retries"
_ERROR_CONNECT_SERIAL_PORT = "Could not connect with serial port: %s"
_ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR = "Unknown error"
_ERROR_DETERMINE_BOOTLOADER_TYPE = "Could not determine the bootloader type: %s"
_ERROR_DEVICE_PROGRAMMING_MODE = "Could not put XBee device into programming mode"
_ERROR_END_DEVICE_ORPHAN = "Could not find the parent node of the end device"
_ERROR_FILE_NOT_FOUND = "%s file '%s' not found"
_ERROR_FILE_NOT_SPECIFIED = "%s file must be specified"
_ERROR_FINISH_PROCESS = "Could not finish firmware update process"
_ERROR_FW_START = "Could not start the new firmware"
_ERROR_FW_UPDATE_BOOTLOADER = "Bootloader update error: %s"
_ERROR_FW_UPDATE_RETRIES = "Firmware update failed after %s retries"
_ERROR_FW_UPDATE_XBEE = "XBee firmware update error: %s"
_ERROR_GPM_ERASE_CMD = "An error occurred erasing the device flash"
_ERROR_GPM_INFO_CMD = "An error occurred getting the platform information"
_ERROR_GPM_VERIFY_AND_INSTALL_CMD = "An error occurred while installing the " \
                                    "new firmware in the device"
_ERROR_GPM_VERIFY_CMD = "An error occurred while verifying firmware " \
                        "image in the device"
_ERROR_GPM_WRITE_CMD = "An error occurred while writing data in the device"
_ERROR_HW_VERSION_DIFFER = "Device hardware version (%d) differs from the " \
                           "firmware one (%d)"
_ERROR_IMAGE_VERIFICATION = "Image verification error"
_ERROR_INITIALIZE_PROCESS = "Could not initialize firmware update process"
_ERROR_INVALID_OTA_FILE = "Invalid OTA file: %s"
_ERROR_INVALID_BLOCK = "Requested block index '%s' does not exits"
_ERROR_INVALID_GPM_ANSWER = "Invalid GPM frame answer"
_ERROR_NO_UPDATER_AVAILABLE = "No valid updater available to perform the " \
                              "remote firmware update"
_ERROR_NOT_OTA_FILE = "File '%s' is not an OTA file"
_ERROR_PAGE_CHECKSUM = "Checksum error for page %d"
_ERROR_PAGE_VERIFICATION = "Verification error for page %d"
_ERROR_PARSING_OTA_FILE = "Error parsing OTA file: %s"
_ERROR_RECEIVE_FRAME_TIMEOUT = "Timeout waiting for response"
_ERROR_RECOVERY_MODE = "Could not put updater device in recovery mode"
_ERROR_READ_OTA_FILE = "Error reading OTA file: %s"
_ERROR_REGION_LOCK = "Device region (%s) differs from the firmware one (%s)"
_ERROR_REMOTE_DEVICE_INVALID = "Invalid remote XBee device"
_ERROR_RESTORE_TARGET_CONNECTION = "Could not restore target connection: %s"
_ERROR_RESTORE_LOCAL_CONNECTION = "Could not restore local connection: %s"
_ERROR_RESTORE_UPDATER_DEVICE = "Error restoring updater device: %s"
_ERROR_SEND_FRAME = "Error sending frame: transmit status not received or invalid"
_ERROR_SEND_FRAME_RESPONSE = "Error sending '%s' frame: %s"
_ERROR_SEND_OTA_BLOCK = "Error sending OTA block '%s' frame: %s"
_ERROR_SERIAL_COMMUNICATION = "Serial port communication error: %s"
_ERROR_TARGET_INVALID = "Invalid update target"
_ERROR_TRANSFER_OTA_FILE = "Error transferring OTA file: %s"
_ERROR_UPDATE_FROM_S2C = "An S2C device can be only updated from another S2C device"
_ERROR_UPDATE_TARGET_INFO = "Error reading new target information: %s"
_ERROR_UPDATE_TARGET_TIMEOUT = "Timeout communicating with target device " \
                               "after the firmware update"
_ERROR_UPDATER_READ_PARAM = "Error reading updater '%s' parameter"
_ERROR_UPDATER_SET_PARAM = "Error setting updater '%s' parameter"
_ERROR_XML_PARSE = "Could not parse XML firmware file %s"
_ERROR_XMODEM_COMMUNICATION = "XModem serial port communication error: %s"
_ERROR_XMODEM_RESTART = "Could not restart firmware transfer sequence"
_ERROR_XMODEM_START = "Could not start XModem firmware upload process"
_ERROR_HW_VERSION_NOT_SUPPORTED = "XBee hardware version (%d) does not " \
                                  "support firmware update process"

_EXPL_PACKET_BROADCAST_RADIUS_MAX = 0x00
_EXPL_PACKET_CLUSTER_DATA = 0x0011
_EXPL_PACKET_CLUSTER_ID = 0x0019
_EXPL_PACKET_CLUSTER_GPM = 0x0023
_EXPL_PACKET_CLUSTER_LINK = 0x0014
_EXPL_PACKET_CLUSTER_LINK_ANSWER = 0x0094
_EXPL_PACKET_CLUSTER_LOOPBACK = 0x0012
_EXPL_PACKET_CLUSTER_UPDATE_LOCAL_UPDATER = 0x71FE
_EXPL_PACKET_CLUSTER_UPDATE_REMOTE_UPDATER = 0x71FF
_EXPL_PACKET_ENDPOINT_DATA = 0xE8
_EXPL_PACKET_ENDPOINT_DIGI_DEVICE = 0xE6
_EXPL_PACKET_PROFILE_DIGI = 0xC105
_EXPL_PACKET_EXTENDED_TIMEOUT = 0x40

EXTENSION_EBIN = ".ebin"
EXTENSION_EBL = ".ebl"
EXTENSION_GBL = ".gbl"
EXTENSION_EHX2 = ".ehx2"
EXTENSION_OTA = ".ota"
EXTENSION_OTB = ".otb"
EXTENSION_FSOTA = ".fsota"
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
_OTA_DEFAULT_BLOCK_SIZE_ENC = 44
_OTA_GBL_SIZE_BYTE_COUNT = 6

_PACKET_DEFAULT_SEQ_NUMBER = 0x01

# Answer examples: 01 81 -> 1.8.1  -  0F 3E -> 15.3.14
_PARAM_BOOTLOADER_VERSION = ATStringCommand.VH.command
_PARAM_READ_RETRIES = 3
_PARAM_SET_RETRIES = 3

_PROGRESS_TASK_UPDATE_BOOTLOADER = "Updating bootloader"
_PROGRESS_TASK_UPDATE_REMOTE_XBEE = "Updating remote XBee firmware"
_PROGRESS_TASK_UPDATE_REMOTE_FILESYSTEM = "Updating remote XBee filesystem"
_PROGRESS_TASK_UPDATE_XBEE = "Updating XBee firmware"

_REMOTE_FW_UPDATE_DEFAULT_TIMEOUT = 30  # Seconds

_TIME_DAYS_1970TO_2000 = 10957
_TIME_SECONDS_1970_TO_2000 = _TIME_DAYS_1970TO_2000 * 24 * 60 * 60

_IMAGE_BLOCK_RESPONSE_PAYLOAD_DECREMENT = 1
_UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE = 12

_VALUE_API_OUTPUT_MODE_EXPLICIT = 0x01
_VALUE_END_OF_FILE_DATA = bytearray([0x01, 0x04])
_VALUE_INITIALIZATION_DATA = bytearray([0x01, 0x51])
_VALUE_PRESERVE_NETWORK_SETTINGS = bytearray([0x54, 0x41])
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

_ZCL_CMD_ID_IMG_NOTIFY_REQ = 0x00
_ZCL_CMD_ID_QUERY_NEXT_IMG_REQ = 0x01
_ZCL_CMD_ID_QUERY_NEXT_IMG_RESP = 0x02
_ZCL_CMD_ID_IMG_BLOCK_REQ = 0x03
_ZCL_CMD_ID_IMG_BLOCK_RESP = 0x05
_ZCL_CMD_ID_UPGRADE_END_REQ = 0x06
_ZCL_CMD_ID_UPGRADE_END_RESP = 0x07
_ZCL_CMD_ID_DEFAULT_RESP = 0x0B

_ZCL_FRAME_CONTROL_CLIENT_TO_SERVER = 0x01

_POLYNOMINAL_DIGI_BL = 0x8005

S2C_HW_VERSIONS = (HardwareVersion.XBP24C.code,
                   HardwareVersion.XB24C.code,
                   HardwareVersion.XBP24C_S2C_SMT.code,
                   HardwareVersion.XBP24C_TH_DIP.code,
                   HardwareVersion.XB24C_TH_DIP.code,
                   HardwareVersion.S2C_P5.code)

SX_HW_VERSIONS = (HardwareVersion.SX.code,
                  HardwareVersion.SX_PRO.code,
                  HardwareVersion.XB8X.code)

XBEE3_HW_VERSIONS = (HardwareVersion.XBEE3.code,
                     HardwareVersion.XBEE3_SMT.code,
                     HardwareVersion.XBEE3_TH.code,
                     HardwareVersion.XBEE3_RR.code,
                     HardwareVersion.XBEE3_RR_TH.code,
                     HardwareVersion.XBEE_BLU.code,
                     HardwareVersion.XBEE_BLU_TH.code)

XR_HW_VERSIONS = (HardwareVersion.XBEE3_DM_LR.code,
                  HardwareVersion.XBEE3_DM_LR_868.code,
                  HardwareVersion.XBEE_XR_900_TH.code,
                  HardwareVersion.XBEE_XR_868_TH.code)

LOCAL_SUPPORTED_HW_VERSIONS = SX_HW_VERSIONS + XBEE3_HW_VERSIONS + XR_HW_VERSIONS
REMOTE_SUPPORTED_HW_VERSIONS = SX_HW_VERSIONS + XBEE3_HW_VERSIONS + S2C_HW_VERSIONS + XR_HW_VERSIONS

_log = logging.getLogger(__name__)


class _EbinFile:
    """
    Helper class that represents a local firmware file in 'ebin' format.
    """

    def __init__(self, file_path, page_size):
        """
        Class constructor. Instantiates a new :class:`._EbinFile` with the
        given parameters.

        Args:
            file_path (String): Path of the ebin file.
            page_size (Integer): Size of the memory pages of the file.
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
            Bytearray: Next memory page of the file as byte array.
        """
        with open(self._file_path, "rb") as file:
            while True:
                read_bytes = file.read(self._page_size)
                if not read_bytes:
                    break
                # Protocol states that empty pages (pages filled with 0xFF)
                # must not be sent. Check if this page is empty.
                page_is_empty = True
                for byte in read_bytes:
                    if byte != 0xFF:
                        page_is_empty = False
                        break
                # Skip empty page. Still increase page index.
                if not page_is_empty:
                    # Page must have always full size.
                    # If not, extend with 0xFF until it is complete.
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
            Integer: Total number of data chunks of this file.
        """
        return self._num_pages

    @property
    def page_index(self):
        """
        Returns the current memory page index.

        Returns:
            Integer: Current memory page index.
        """
        return self._page_index

    @property
    def percent(self):
        """
        Returns the transfer progress percent.

        Returns:
            Integer: Transfer progress percent.
        """
        return ((self._page_index + 1) * 100) // self._num_pages


class _EBLFile:
    """
    Helper class that represents a local firmware file in 'ebl' format.
    """

    def __init__(self, file_path, page_size):
        """
        Class constructor. Instantiates a new :class:`._EBLFile` with the
        given parameters.

        Args:
            file_path (String): Path of the ebl file.
            page_size (Integer): Size of the memory pages of the file.
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
            Bytearray: Next memory page of the file as byte array.
        """
        with open(self._file_path, "rb") as file:
            while True:
                read_bytes = file.read(self._page_size)
                if not read_bytes:
                    break
                # Page must have always full size.
                # If not, extend with 0xFF until it is complete.
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
            Integer: Total number of data chunks of this file.
        """
        return self._num_pages

    @property
    def page_index(self):
        """
        Returns the current memory page index.

        Returns:
            Integer: Current memory page index.
        """
        return self._page_index

    @property
    def percent(self):
        """
        Returns the transfer progress percent.

        Returns:
            Integer: Transfer progress percent.
        """
        return ((self._page_index + 1) * 100) // self._num_pages


class _OTAFile:
    """
    Helper class that represents an OTA firmware file to be used in remote
    firmware updates.
    """

    def __init__(self, file_path):
        """
        Class constructor. Instantiates a new :class:`._OTAFile` with the
        given parameters.

        Args:
            file_path (String): Path of the OTA file.
        """
        self._file_path = file_path
        self._header_version = None
        self._header_length = None
        self._header_field_control = None
        self._manufacturer_code = None
        self._image_type = None
        self._file_version = None
        self._zb_stack_version = None
        self._header_str = None
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
            _ParsingOTAException: If there is any problem parsing the OTA file.
        """
        _log.debug("Parsing OTA firmware file %s:", self._file_path)
        if (not _file_exists(self._file_path)
                or os.path.splitext(self._file_path)[1] not in (EXTENSION_OTA,
                                                                EXTENSION_OTB,
                                                                EXTENSION_FSOTA)):
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
                self._header_length = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header length: %d", self._header_length)
                # Bit mask to indicate whether additional information are included in the OTA image:
                #    * Bit 0: Security credential version present
                #    * Bit 1: Device specific file
                #    * Bit 2: Hardware versions presents
                self._header_field_control = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Header field control: %d", self._header_field_control)
                self._manufacturer_code = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Manufacturer code: %04X (%d)",
                           self._manufacturer_code, self._manufacturer_code)
                self._image_type = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Image type: %s (%d)",
                           "Firmware" if self._image_type in (0, 1) else "File system", self._image_type)
                f_version = _reverse_bytearray(file.read(_BUFFER_SIZE_INT))
                self._file_version = utils.bytes_to_int(f_version)
                _log.debug(" - File version: %s (%d)",
                           utils.hex_to_string(f_version), self._file_version)
                _log.debug("    - Compatibility: %d", f_version[0])
                _log.debug("    - Firmware version: %s",
                           utils.hex_to_string(f_version[1:], pretty=False))
                self._zb_stack_version = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                _log.debug(" - Zigbee stack version: %d", self._zb_stack_version)
                desc = _XBee3OTAClientDescription(utils.bytes_to_int(f_version[1:]))
                if desc.must_send_complete_ota():
                    self._header_str = str(file.read(_BUFFER_SIZE_STR),
                                           encoding="utf8", errors="ignore")
                else:
                    self._header_str = str(_reverse_bytearray(
                        file.read(_BUFFER_SIZE_STR)), encoding="utf8", errors="ignore")
                _log.debug(" - Header string: %s", self._header_str)
                bad_ota_size = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - Discard OTA size field: %d", bad_ota_size)
                if self._header_field_control & 0x01:
                    _log.debug(" - Security credential version: %d",
                               utils.bytes_to_int(file.read(1)))
                if self._header_field_control & 0x02:
                    _log.debug(" - Upgrade file destination: %s", utils.hex_to_string(
                        _reverse_bytearray(file.read(_BUFFER_SIZE_IEEE_ADDR))))
                if self._header_field_control & 0x04:
                    self._min_hw_version = utils.bytes_to_int(
                        _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                    self._max_hw_version = utils.bytes_to_int(
                        _reverse_bytearray(file.read(_BUFFER_SIZE_SHORT)))
                    _log.debug(" - Minimum hardware version: %02X (%d)",
                               self._min_hw_version, self._min_hw_version)
                    _log.debug(" - Maximum hardware version: %02X (%d)",
                               self._max_hw_version, self._max_hw_version)
                file.seek(self._header_length + 2, 0)
                self._ota_size = utils.bytes_to_int(
                    _reverse_bytearray(file.read(_BUFFER_SIZE_INT)))
                _log.debug(" - OTA size: %d", self._ota_size)
                self._total_size = os.path.getsize(self._file_path)
                _log.debug(" - File size: %d", self._total_size)
                self._discard_size = self._header_length + _OTA_GBL_SIZE_BYTE_COUNT
                _log.debug(" - Discard size: %d", self._discard_size)
        except IOError as exc:
            raise _ParsingOTAException(_ERROR_PARSING_OTA_FILE % str(exc)) from None

    def get_next_data_chunk(self, offset, size):
        """
        Returns the next data chunk of this file.

        Args:
            offset (Integer): Starting offset to read.
            size (Integer): The number of bytes to read.

        Returns:
            Bytearray: Next data chunk of the file as byte array.

        Raises:
            _ParsingOTAException: If there is any error reading the OTA file.
        """
        try:
            if self._file is None:
                self._file = open(self._file_path, "rb")
            self._file.seek(offset)
            return self._file.read(size)
        except IOError as exc:
            self.close_file()
            raise _ParsingOTAException(str(exc)) from None

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
            String: OTA file path.
        """
        return self._file_path

    @property
    def header_version(self):
        """
        Returns the OTA file header version.

        Returns:
            Integer: OTA file header version.
        """
        return self._header_version

    @property
    def header_length(self):
        """
        Returns the OTA file header length.

        Returns:
            Integer: OTA file header length.
        """
        return self._header_length

    @property
    def header_field_control(self):
        """
        Returns the OTA file header field control.

        Returns:
            Integer: OTA file header field control.
        """
        return self._header_field_control

    @property
    def manufacturer_code(self):
        """
        Returns the OTA file manufacturer code.

        Returns:
            Integer: OTA file manufacturer code.
        """
        return self._manufacturer_code

    @property
    def image_type(self):
        """
        Returns the OTA file image type: 0x0000 for XBee 3 firmware,
        0x0001 for XBee 3 RR firmware, 0x0100 for file system.

        Returns:
            Integer: OTA file image type.
        """
        return self._image_type

    @property
    def file_version(self):
        """
        Returns the OTA file version.

        Returns:
            Integer: OTA file version.
        """
        return self._file_version

    @property
    def zigbee_stack_version(self):
        """
        Returns the OTA file zigbee stack version.

        Returns:
            Integer: OTA file zigbee stack version.
        """
        return self._zb_stack_version

    @property
    def header_string(self):
        """
        Returns the OTA file header string.

        Returns:
            String: OTA file header string.
        """
        return self._header_str

    @property
    def total_size(self):
        """
        Returns the OTA file total size.

        Returns:
            Integer: OTA file total size.
        """
        return self._total_size

    @property
    def discard_size(self):
        """
        Returns the number of bytes to discard of the OTA file.

        Returns:
            Integer: Number of bytes.
        """
        return self._discard_size

    @property
    def ota_size(self):
        """
        Returns the number of bytes to transmit over the air.

        Returns:
            Integer: Number of bytes.
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


class _XBee3OTAClientDescription:
    """
    Helper class used to get OTA client capabilities depending on its firmware version.
    OTA considerations at:
       * Zigbee (1009 an prior)
         https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
       * DigiMesh (older than 300A)
         https://www.digi.com/resources/documentation/Digidocs/90002277/#Reference/r_considerations.htm
       * 802.15.4 (older than 200A)
         https://www.digi.com/resources/documentation/digidocs/90002273/#reference/r_considerations.htm
    """

    # Since the following versions (they included) the complete OTA file
    # (including the header) must be sent to the client when blocks are
    # requested. OTA header must be escaped for prior versions (only the GBL
    # must be sent)
    _XB3_FW_MIN_VERSION_COMPLETE_OTA = {
        XBeeProtocol.ZIGBEE: 0x100A,
        XBeeProtocol.DIGI_MESH: 0x300A,
        XBeeProtocol.RAW_802_15_4: 0x200A
    }

    # Since the following versions (they included), network ACK for the
    # transmission is sent once it is received.
    # In prior versions, the network ACK is not sent until after the operation
    # completes. This may result in a timeout, since 'Query Next Image Response'
    # and the final 'Image Block Response' both cause the client to perform a
    # long operation (erasing/verifying OTA update data in the storage slot)
    _XB3_FW_MIN_VERSION_IMMEDIATE_ACK = {
        XBeeProtocol.ZIGBEE: 0x100A,
        XBeeProtocol.DIGI_MESH: 0,
        XBeeProtocol.RAW_802_15_4: 0
    }

    # Since the following versions (they included), the XBee firmware includes
    # client retries for the same block offset if, for any reason, the block is
    # not received (or it is corrupted)
    # For previous versions:
    # Do not retry the same packet if the next request does not arrive, just
    # send the following response as if the corresponding request arrived.
    _XB3_FW_MIN_VERSION_WITH_CLIENT_RETRIES = {
        XBeeProtocol.ZIGBEE: 0x1009,
        XBeeProtocol.DIGI_MESH: 0x300A,
        XBeeProtocol.RAW_802_15_4: 0x200A
    }

    # Maximum number of packets that can be lost in a row for firmware without
    # client retries feature (_XB3_FW_MIN_VERSION_WITH_CLIENT_RETRIES)
    _XB3_FW_MAX_OTA_LOST_CLIENT_REQUESTS = {
        XBeeProtocol.ZIGBEE: 3,
        XBeeProtocol.DIGI_MESH: 1,
        XBeeProtocol.RAW_802_15_4: 1
    }

    # Zigbee firmwares 0x1007 and prior do not support fragmentation during an
    # OTA update. Fragmentation is not supported in DigiMesh nor in 802.15.4
    _XB3_FW_MIN_VERSION_WITH_FRAGMENTATION = {
        XBeeProtocol.ZIGBEE: 0x1008,
        XBeeProtocol.DIGI_MESH: 0xFFFF,
        XBeeProtocol.RAW_802_15_4: 0xFFFF
    }

    # Prior firmwares only support default ota block size (sent in Image requests)
    _XB3_FW_MIN_VERSION_DIFF_OTA_BLOCK = {
        XBeeProtocol.ZIGBEE: 0x1009,
        XBeeProtocol.DIGI_MESH: 0x300A,
        XBeeProtocol.RAW_802_15_4: 0x200A
    }

    _XB3_PROTOCOL_FROM_FW_VERSION = {
        0x1: XBeeProtocol.ZIGBEE,
        0x2: XBeeProtocol.RAW_802_15_4,
        0x3: XBeeProtocol.DIGI_MESH
    }

    _SEND_BLOCK_RETRIES = 1

    def __init__(self, fw_version):
        """
        Class constructor. Instantiates a new :class:`._XBee3OTAClientDescription`
        with the given parameters.

        Args:
            fw_version (Integer): Firmware version of the OTA client (remote to be updated)
        """
        self._fw_version = fw_version
        self._protocol = _XBee3OTAClientDescription.get_protocol_from_fw(fw_version)
        self._extended_timeout = 0

    @classmethod
    def get_protocol_from_fw(cls, fw_version):
        """
        Get protocol from firmware version.

        Args:
            fw_version (Integer): Firmware version.

        Returns:
            :class:`.XBeeProtocol`: The protocol of the firmware version.
        """
        return cls._XB3_PROTOCOL_FROM_FW_VERSION[fw_version >> 12]

    @property
    def extended_timeout(self):
        """
        Returns the extended timeout in seconds.

        Returns:
             Float: Extended timeout in seconds.
        """
        return self._extended_timeout

    @extended_timeout.setter
    def extended_timeout(self, value):
        """
        Configures the extended timeout in seconds.

        Args:
            value (Float): The extended timeout in seconds.
        """
        self._extended_timeout = value

    def must_send_complete_ota(self):
        """
        Returns `True` if the complete OTA file must be sent in a remote update.
        Without skipping the OTA header (that results in the GBL)

        Returns:
            Boolean: `True` if OTA must be completely sent, `False` otherwise.
        """
        return self._get_fw_to_check() >= self._XB3_FW_MIN_VERSION_COMPLETE_OTA[self._protocol]

    def is_ack_immediate(self):
        """
        Returns `True` if all network ACK are sent once a transmission is
        received and not after a long operation finishes.

        Returns:
            Boolean: `True` if network ACK is immediately sent, `False` otherwise.
        """
        return self._get_fw_to_check() >= self._XB3_FW_MIN_VERSION_IMMEDIATE_ACK[self._protocol]

    def wait_for_client_retry(self):
        """
        Returns `True` if the client firmware has the client retries feature
        implemented.

        Returns:
            Boolean: `True` if the client firmware has the client retries
                feature implemented, `False` otherwise.
        """
        return self._get_fw_to_check() >= self._XB3_FW_MIN_VERSION_WITH_CLIENT_RETRIES[self._protocol]

    def get_block_response_max_retries(self):
        """
        Returns the maximum number of retries for a block response.

        Returns:
            Integer: The maximum number of retries for a block response.
        """
        if self.wait_for_client_retry():
            return 1

        return self._SEND_BLOCK_RETRIES

    def get_max_ota_lost_client_requests_in_a_row(self):
        """
        Returns the maximum number of client requests lost in a row.
        This is only valid if client retry feature is not implemented, if
        wait_for_client_retry return `False`.

        Returns:
            Integer: Maximum number of client requests lost in a row.
        """
        if self.wait_for_client_retry():
            return 0

        return self._XB3_FW_MAX_OTA_LOST_CLIENT_REQUESTS[self._protocol]

    def support_ota_fragmentation(self):
        """
        Returns `True` if the client firmware supports fragmentation of OTA commands.

        Returns:
            Boolean: `True` if the client firmware supports fragmentation of
                OTA commands, `False` otherwise.
        """
        return self._get_fw_to_check() >= self._XB3_FW_MIN_VERSION_WITH_FRAGMENTATION[self._protocol]

    def support_different_ota_block_size(self):
        """
        Returns `True` if the client firmware supports different ota block sizes.

        Returns:
            Boolean: `True` if the client firmware supports different ota block
                sizes, `False` otherwise.
        """
        return self._get_fw_to_check() >= self._XB3_FW_MIN_VERSION_DIFF_OTA_BLOCK[self._protocol]

    def _get_fw_to_check(self):
        """
        Returns the firmware version to check.

        Returns:
             Integer: The firmware version to check.
        """
        # Consider intermediate 1B04 firmware as a 1009 in terms of behavior.
        # Firmware 1B04 is an intermediate firmware to be able to remotely update
        # remote nodes with 1003 version.
        return self._fw_version if self._fw_version != 0x1B04 else 0x1009


class _ParsingOTAException(Exception):
    """
    This exception will be thrown when any problem related with the parsing of
    OTA files occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """


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
    MALFORMED_CMD = (0x80, "Received is badly formatted or has incorrect parameters")
    UNSUP_CLUSTER_CMD = (0x81, "Unsupported cluster command")
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
        self.__id = identifier
        self.__desc = description

    @classmethod
    def get(cls, identifier):
        """
        Returns the _XBee3OTAStatus for the given identifier.

        Args:
            identifier (Integer): Identifier of the _XBee3OTAStatus to get.

        Returns:
            :class:`._XBee3OTAStatus`: _XBee3OTAStatus with the given
                identifier, `None` if there is not found.
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
            Integer: Identifier of the _XBee3OTAStatus element.
        """
        return self.__id

    @property
    def description(self):
        """
        Returns the command of the _XBee3OTAStatus element.

        Returns:
            String: Description of the _XBee3OTAStatus element.
        """
        return self.__desc


class _BreakThread(Thread):
    """
    Helper class used to manage serial port break line in a parallel thread.
    """

    _break_running = False

    def __init__(self, serial_port, duration):
        """
        Class constructor. Instantiates a new :class:`._BreakThread` with the
        given parameters.

        Args:
            serial_port (:class:`.XBeeSerialPort`): The serial port to send the
                break signal to.
            duration (Integer): Duration of the break in seconds.
        """
        super().__init__()
        self._xbee_serial_port = serial_port
        self.duration = duration
        self.lock = Event()

    def run(self):
        """
        Override.

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
            Boolean: `True` if the break thread is running, `False` otherwise.
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
    GEN3_BOOTLOADER = (0x01, "Generation 3 bootloader", OTAMethod.GPM)
    GECKO_BOOTLOADER = (0x02, "Gecko bootloader", OTAMethod.ZCL)
    EMBER_BOOTLOADER = (0x03, "Ember bootloader", OTAMethod.EMBER)
    GECKO_BOOTLOADER_XR = (0x04, "Gecko bootloader with GPM OTA", OTAMethod.GPM)

    def __init__(self, identifier, description, ota_method):
        self.__id = identifier
        self.__desc = description
        self.__ota_method = ota_method

    @classmethod
    def get(cls, identifier):
        """
        Returns the _BootloaderType for the given identifier.

        Args:
            identifier (Integer): Identifier of the _BootloaderType to get.

        Returns:
            :class:`._BootloaderType`: _BootloaderType with the given
                identifier, `None` if not found.
        """
        for value in _BootloaderType:
            if value.identifier == identifier:
                return value

        return None

    @classmethod
    def determine_bootloader_type(cls, hw_version):
        """
        Determines the _BootloaderType for the given hardware version.

        Args:
            hw_version (Integer): Hardware version to retrieve its bootloader type.

        Returns:
            :class:`._BootloaderType`: _BootloaderType of the given hardware
                version, `None` if not found.
        """
        if hw_version in SX_HW_VERSIONS:
            return _BootloaderType.GEN3_BOOTLOADER
        if hw_version in XBEE3_HW_VERSIONS:
            return _BootloaderType.GECKO_BOOTLOADER
        if hw_version in XR_HW_VERSIONS:
            return _BootloaderType.GECKO_BOOTLOADER_XR
        if hw_version in S2C_HW_VERSIONS:
            return _BootloaderType.EMBER_BOOTLOADER

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _BootloaderType element.

        Returns:
            Integer: Identifier of the _BootloaderType element.
        """
        return self.__id

    @property
    def description(self):
        """
        Returns the description of the _BootloaderType element.

        Returns:
            String: Description of the _BootloaderType element.
        """
        return self.__desc

    @property
    def ota_method(self):
        """
        Returns the over-the-air update method for this bootloader type.

        Returns:
            :class:`OTAMethod`: OTA method to use with this bootloader.
        """
        return self.__ota_method


@unique
class _Gen3BootloaderCmd(Enum):
    """
    This class lists the available Gen3 bootloader commands.

    | Inherited properties:
    |     **name** (String): The name of this _Gen3BootloaderCommand.
    |     **value** (Integer): The ID of this _Gen3BootloaderCommand.
    """
    BOOTLOADER_VERSION = (0x01, "Retrieve the bootloader version", "B", 6, 200)
    HW_VERSION = (0x02, "Retrieve hardware version", "V", 17, 1000)
    REGION_LOCK = (0x03, "Retrieve region lock number", "N", 1, 300)
    PROTOCOL_VERSION = (0x04, "Retrieve firmware update protocol version", "L", 1, 500)
    INIT_UPDATE = (0x05, "Initialize firmware update process", "I", 1, 4000)
    FINISH_UPDATE = (0x06, "Finish firmware update process", "F", 1, 100)
    CHANGE_BAUDRATE = (0x07, "Change serial baudrate", "R", 6, 300)
    # Negative timeout means do not wait for answer.
    PROGRAM_PAGE = (0x08, "Program firmware memory page", "P", 1, -1)
    VERIFY = (0x09, "Verify the transferred image", "C", 1, 30000)

    def __init__(self, identifier, desc, cmd, answer_len, timeout):
        self.__id = identifier
        self.__desc = desc
        self.__cmd = cmd
        self.__answer_len = answer_len
        self.__timeout = timeout

    @classmethod
    def get(cls, identifier):
        """
        Returns the _Gen3BootloaderCommand for the given identifier.

        Args:
            identifier (Integer): Identifier of the _Gen3BootloaderCommand to get.

        Returns:
            :class:`._Gen3BootloaderCommand`: _Gen3BootloaderCommand with the
                given identifier, `None` if not found.
        """
        for value in _Gen3BootloaderCmd:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _Gen3BootloaderCommand element.

        Returns:
            Integer: Identifier of the _Gen3BootloaderCommand element.
        """
        return self.__id

    @property
    def description(self):
        """
        Returns the description of the _Gen3BootloaderCommand element.

        Returns:
            String: Description of the _Gen3BootloaderCommand element.
        """
        return self.__desc

    @property
    def command(self):
        """
        Returns the command of the _Gen3BootloaderCommand element.

        Returns:
            String: Command of the _Gen3BootloaderCommand element.
        """
        return self.__cmd

    @property
    def answer_length(self):
        """
        Returns the answer length of the _Gen3BootloaderCommand element.

        Returns:
            Integer: Answer length of the _Gen3BootloaderCommand element.
        """
        return self.__answer_len

    @property
    def timeout(self):
        """
        Returns the timeout of the _Gen3BootloaderCommand element.

        Returns:
            Integer: Timeout of the _Gen3BootloaderCommand element (milliseconds).
        """
        return self.__timeout


@unique
class _GPMCmd(Enum):
    """
    This class lists the available GPM (General Purpose Memory) commands.

    | Inherited properties:
    |     **name** (String): The name of this _GPMCommand.
    |     **value** (Integer): The ID of this _GPMCommand.
    """
    GET_PLATFORM_INFO = (0x01, "Reads the device information",
                         0x00, 0x80, _ERROR_GPM_INFO_CMD)
    ERASE_FLASH = (0x02, "Erases the device flash",
                   0x01, 0x81, _ERROR_GPM_ERASE_CMD)
    WRITE_DATA = (0x03, "Writes data in the device",
                  0x02, 0x82, _ERROR_GPM_WRITE_CMD)
    VERIFY_IMAGE = (0x04, "Verifies the firmware image in the device",
                    0x05, 0x85, _ERROR_GPM_VERIFY_CMD)
    VERIFY_AND_INSTALL = (0x05, "Verifies and installs the firmware image in the device",
                          0x06, 0x86, _ERROR_GPM_VERIFY_AND_INSTALL_CMD)

    def __init__(self, identifier, desc, cmd_id, answer_id, execution_error):
        self.__id = identifier
        self.__desc = desc
        self.__cmd_id = cmd_id
        self.__answer_id = answer_id
        self.__exec_error = execution_error

    @classmethod
    def get(cls, identifier):
        """
        Returns the _GPMCommand for the given identifier.

        Args:
            identifier (Integer): Identifier of the _GPMCommand to get.

        Returns:
            :class:`._GPMCommand`: _GPMCommand with the given identifier,
                `None` if not found.
        """
        for value in _GPMCmd:
            if value.identifier == identifier:
                return value

        return None

    @property
    def identifier(self):
        """
        Returns the identifier of the _GPMCommand element.

        Returns:
            Integer: Identifier of the _GPMCommand element.
        """
        return self.__id

    @property
    def description(self):
        """
        Returns the description of the _GPMCommand element.

        Returns:
            String: Description of the _GPMCommand element.
        """
        return self.__desc

    @property
    def command_id(self):
        """
        Returns the command identifier of the _GPMCommand element.

        Returns:
            Integer: Command identifier of the _GPMCommand element.
        """
        return self.__cmd_id

    @property
    def answer_id(self):
        """
        Returns the answer identifier of the _GPMCommand element.

        Returns:
            Integer: Answer identifier of the _GPMCommand element.
        """
        return self.__answer_id

    @property
    def execution_error(self):
        """
        Returns the execution error message of the _GPMCommand element.

        Returns:
            String: Execution error message of the _GPMCommand element.
        """
        return self.__exec_error


class _LoopbackTest:
    """
    Helper class used to perform a loopback test between a local and a remote
    device.
    """

    _LOOPBACK_DATA = "Loopback test %s"

    def __init__(self, local, remote, loops=10, failures_allowed=2, timeout=2):
        """
        Class constructor. Instantiates a new :class:`._LoopbackTest` with the
        given parameters.

        Args:
            local (:class:`.XBeeDevice`): Local device to perform the test.
            remote (:class:`.RemoteXBeeDevice`): Remote device to perform the test.
            loops (Integer, optional, default=10): Number of loops to execute in the test.
            failures_allowed (Integer, optional, default=2): Number of allowed
                failed loops before considering the test failed.
            timeout (Integer, optional, default=2): Timeout in seconds to wait
                for the loopback answer.
        """
        self._local = local
        self._remote = remote
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
        return ExplicitAddressingPacket(
            self._frame_id, self._remote.get_64bit_addr(),
            self._remote.get_16bit_addr(), _EXPL_PACKET_ENDPOINT_DATA,
            _EXPL_PACKET_ENDPOINT_DATA, _EXPL_PACKET_CLUSTER_LOOPBACK,
            _EXPL_PACKET_PROFILE_DIGI, _EXPL_PACKET_BROADCAST_RADIUS_MAX,
            _EXPL_PACKET_EXTENDED_TIMEOUT if self._local.get_protocol() == XBeeProtocol.ZIGBEE else 0x00,
            (self._LOOPBACK_DATA % self._frame_id).encode(encoding='utf8'))

    def _loopback_callback(self, frame):
        f_type = frame.get_frame_type()
        if f_type == ApiFrameType.TRANSMIT_STATUS and frame.frame_id == self._frame_id:
            if frame.transmit_status == TransmitStatus.SUCCESS:
                self._packet_sent = True
            else:
                self._receive_lock.set()
        elif (f_type == ApiFrameType.EXPLICIT_RX_INDICATOR
              and frame.source_endpoint == _EXPL_PACKET_ENDPOINT_DATA
              and frame.dest_endpoint == _EXPL_PACKET_ENDPOINT_DATA
              and frame.cluster_id == _EXPL_PACKET_CLUSTER_DATA
              and frame.profile_id == _EXPL_PACKET_PROFILE_DIGI
              and frame.x64bit_source_addr == self._remote.get_64bit_addr()):
            # If frame was already received, ignore this frame, just notify.
            if self._packet_received:
                self._receive_lock.set()
                return
            # Check received payload.
            if not frame.rf_data:
                return
            if str(frame.rf_data, encoding='utf8', errors='ignore') == \
                    (self._LOOPBACK_DATA % self._frame_id):
                self._packet_received = True
                self._receive_lock.set()

    def execute_test(self):
        """
        Performs the loopback test.

        Returns:
            Boolean: `True` if the test succeed, `False` otherwise.
        """
        _log.debug("Executing loopback test against %s", self._remote)
        # Clear vars.
        self._frame_id = 1
        self._total_loops_failed = 0
        # Store AO value.
        success, old_ao = _enable_explicit_mode(self._local)
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
            self._local.add_packet_received_callback(self._loopback_callback)
            try:
                # Send frame.
                self._local.send_packet(self._generate_loopback_packet())
                # Wait for answer.
                self._receive_lock.wait(self._loopback_timeout)
            except XBeeException as exc:
                _log.warning("Could not send loopback test packet %s: %s", loop, str(exc))
                self._loop_failed = True
            finally:
                # Remove frame listener.
                self._local.del_packet_received_callback(self._loopback_callback)
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
        if old_ao is not None and not _set_parameter_with_retries(
                self._local, ATStringCommand.AO, old_ao, apply=True):
            return False
        # Return test result.
        _log.debug("Loopback test result: %s loops failed out of %s",
                   self._total_loops_failed, self._num_loops)
        return self._total_loops_failed <= self._failures_allowed


class _TraceRouteTest:
    """
    Helper class used to perform a trace route test between a local device and
    a remote device to verify that a third device is not in the route between
    them in DigiMesh networks.
    """

    def __init__(self, local, remote, test_device, timeout=20):
        """
        Class constructor. Instantiates a new :class:`._TraceRouteTest` with the given parameters.

        Args:
            local (:class:`.XBeeDevice`): Local node to initiate the
                trace route test.
            remote (:class:`.RemoteXBeeDevice`): Remote node to perform
                the trace route test.
            test_device (:class:`.RemoteXBeeDevice`): Remote node to verify that
                is not part of the route.
            timeout (Integer, optional, default=20): Timeout in seconds to wait
                for the trace route answer.
        """
        self._local = local
        self._remote = remote
        self._test_device = test_device
        self._timeout = timeout

    def execute_test(self):
        """
        Performs the trace route test.

        Returns:
            Boolean: `True` if the test succeed, `False` otherwise.
        """
        _log.debug("Executing trace route test against %s", self._remote)
        status, route = self._local.get_route_to_node(self._remote, timeout=self._timeout)
        if not status:
            _log.warning("Could not send trace route test packet")
            return False
        if status != TransmitStatus.SUCCESS:
            _log.warning(
                "Error sending trace route test packet: %s", status.description)
            return False
        if not route or len(route) < 3:
            _log.warning("Route not received")
            return False
        return self._test_device not in route[2]


class _LinkTest:
    """
    Helper class used to perform a link test between the updater device and a
    remote device to verify connectivity in DigiMesh networks.
    """

    _LINK_TEST_ANSWER_PAYLOAD_LEN = 21

    def __init__(self, local, target, updater, loops=10, data_len=16, failures_allowed=1,
                 timeout=20):
        """
        Class constructor. Instantiates a new :class:`._LinkTest` with the
        given parameters.

        Args:
            local (:class:`.XBeeDevice`): Local device to initiate the test.
            target (:class:`.RemoteXBeeDevice`): Remote device to communicate with.
            updater (:class:`.RemoteXBeeDevice`): Remote device that will
                communicate with the target node.
            loops (Integer, optional, default=10): Number of loops to execute in the test.
            data_len (Integer, optional, default=16): Number of data bytes to use.
            failures_allowed (Integer, optional, default=1): Number of allowed
                failed loops before considering the test failed.
            timeout (Integer, optional, default=20): Timeout in seconds to wait
                for the link test answer.
        """
        self._local = local
        self._target = target
        self._updater = updater
        self._num_loops = loops
        self._data_len = data_len
        self._failures_allowed = failures_allowed
        self._timeout = timeout
        self._receive_lock = Event()
        self._packet_received = False
        self._test_succeed = False
        self._total_loops_failed = 0

    def _generate_link_test_packet(self):
        payload = bytearray()
        payload.extend(self._target.get_64bit_addr().address)
        payload.extend(utils.int_to_bytes(self._data_len, 2))
        payload.extend(utils.int_to_bytes(self._num_loops, 2))
        return ExplicitAddressingPacket(
            1, self._updater.get_64bit_addr(), self._updater.get_16bit_addr(),
            _EXPL_PACKET_ENDPOINT_DIGI_DEVICE, _EXPL_PACKET_ENDPOINT_DIGI_DEVICE,
            _EXPL_PACKET_CLUSTER_LINK, _EXPL_PACKET_PROFILE_DIGI,
            _EXPL_PACKET_BROADCAST_RADIUS_MAX, 0x00, payload)

    def _link_test_callback(self, frame):
        if (frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR
                and frame.source_endpoint == _EXPL_PACKET_ENDPOINT_DIGI_DEVICE
                and frame.dest_endpoint == _EXPL_PACKET_ENDPOINT_DIGI_DEVICE
                and frame.cluster_id == _EXPL_PACKET_CLUSTER_LINK_ANSWER
                and frame.profile_id == _EXPL_PACKET_PROFILE_DIGI
                and frame.x64bit_source_addr == self._updater.get_64bit_addr()):
            # If frame was already received, ignore this frame, just notify.
            if self._packet_received:
                self._receive_lock.set()
                return
            # Check received payload.
            payload = frame.rf_data
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
        _log.debug("Executing link test between %s and %s", self._updater, self._target)
        # Clear vars.
        self._packet_received = False
        self._test_succeed = False
        self._total_loops_failed = 0
        # Store AO value.
        success, old_ao = _enable_explicit_mode(self._local)
        if not success:
            return False
        # Add trace route callback.
        self._local.add_packet_received_callback(self._link_test_callback)
        try:
            # Send frame.
            self._local.send_packet(self._generate_link_test_packet())
            # Wait for answer.
            self._receive_lock.wait(self._timeout)
        except XBeeException as exc:
            _log.error("Could not send Link test packet: %s", str(exc))
            self._test_succeed = False
        finally:
            # Remove frame listener.
            self._local.del_packet_received_callback(self._link_test_callback)
        # Restore AO value.
        if old_ao is not None and not _set_parameter_with_retries(
                self._local, ATStringCommand.AO, old_ao, apply=True):
            return False
        if not self._packet_received or not self._test_succeed:
            return False
        # Return test result.
        _log.debug("Link test result: %s loops failed out of %s",
                   self._total_loops_failed, self._num_loops)
        return self._total_loops_failed <= self._failures_allowed


class UpdateConfigurer:
    """
    For internal use only. Helper class used to prepare nodes and/or network
    for an update.
    """

    TASK_PREPARE = "Preparing for update"
    TASK_RESTORE = "Restoring after update"

    _DM_SYNC_WAKE_TIME = 30

    def __init__(self, node, timeout=None, callback=None):
        """
        Class constructor. Instantiates a new :class:`.UpdateConfigurer` with
        the given parameters.

        Args:
            node (:class:`.AbstractXBeeDevice`): Target being updated.
            timeout (Float, optional, default=`None`): Operations timeout.
            callback (Function): Function to notify about the progress.
        """
        self._xbee = node
        self._timeout = timeout
        self._callback = callback
        self._op_timeout = None
        self._sync_sleep = None
        self._task_done = {self.TASK_PREPARE: 0,
                           self.TASK_RESTORE: 0}
        self._task_total = {self.TASK_PREPARE: 3,
                            self.TASK_RESTORE: 2}
        self.cmd_dict = {}

    @property
    def sync_sleep(self):
        """
        Returns whether node is part of a DigiMesh synchronous sleeping network.

        Returns:
             Boolean: `True` if it synchronous sleeps, `False` otherwise.
        """
        if self._sync_sleep is None:
            self._sync_sleep = self._is_sync_sleep()
        return self._sync_sleep

    @property
    def prepare_total(self):
        """
        Returns the total work for update preparation step.

        Returns:
             Integer: Total prepare work.
        """
        return self._task_total[self.TASK_PREPARE]

    @prepare_total.setter
    def prepare_total(self, total):
        """
        Sets the total work for update preparation step.

        Args:
             total (Integer): Total prepare work.
        """
        self._task_total[self.TASK_PREPARE] = total

    @property
    def restore_total(self):
        """
        Returns the total work for update restoration step.

        Returns:
             Integer: Total restore work.
        """
        return self._task_total[self.TASK_RESTORE]

    @restore_total.setter
    def restore_total(self, total):
        """
        Sets the total work for update restoration step.

        Args:
             total (Integer): Total restore work.
        """
        self._task_total[self.TASK_RESTORE] = total

    def prepare_for_update(self, prepare_node=True, prepare_net=True, restore_later=True):
        """
        Prepares the node for an update process.

        Args:
            prepare_node (Boolean, optional, default=`True`): `True` to prepare
                the node.
            prepare_net (Boolean, optional, default=`True`): `True` to prepare
                the network.
            restore_later (Boolean, optional, default=`True`): `True` to
                restore node original values when finish the update process.

        Raises:
            XBeeException: If cannot get network synchronous sleep configuration,
                or cannot prepare the network.
        """
        _log.info("'%s' - %s", self._xbee, self.TASK_PREPARE)

        # Change sync ops timeout
        self._op_timeout = self._xbee.get_sync_ops_timeout()
        if self._timeout:
            self._xbee.set_sync_ops_timeout(max(self._op_timeout, self._timeout))

        if not prepare_node and not prepare_net:
            return

        self.cmd_dict.clear()
        self._task_done[self.TASK_PREPARE] = 0
        self.progress_cb(self.TASK_PREPARE)

        if prepare_node:
            # Try to read information
            if not self._xbee.is_device_info_complete():
                try:
                    self._xbee.read_device_info(init=True, fire_event=False)
                except XBeeException:
                    pass

        self.progress_cb(self.TASK_PREPARE)

        if prepare_node:
            self._prepare_node_for_update(restore_later=restore_later)
        self.progress_cb(self.TASK_PREPARE)

        if prepare_net and self._xbee.is_remote():
            self._prepare_network_for_update()
        self.progress_cb(self.TASK_PREPARE)

    def restore_after_update(self, restore_settings=True, port_settings=None):
        """
        Restores the node after an update process.

        Args:
            restore_settings(Boolean, optional, default=`True`): `True` to
                restore stored settings, `False` otherwise.
            port_settings(Dictionary, optional, default=`None`): Dictionary
                with the new serial port configuration, `None` for remote node
                or if the serial config has not changed.
        """
        _log.info("'%s' - %s", self._xbee, self.TASK_RESTORE)

        if restore_settings and self.cmd_dict:
            self.progress_cb(self.TASK_RESTORE)
            self._restore_node_after_update(self._xbee, port_settings=port_settings)

            self.progress_cb(self.TASK_RESTORE)
            self._restore_network_after_update()
            self.progress_cb(self.TASK_RESTORE)

        if self._op_timeout is not None:
            self._xbee.set_sync_ops_timeout(self._op_timeout)

    @staticmethod
    def exec_at_cmd(func, node, cmd, value=None, retries=5, apply=False):
        """
        Reads the given parameter from the XBee with the given number of retries.

        Args:
            func (Function): Function to execute.
            node (:class:`.AbstractXBeeDevice`): XBee to get/set parameter.
            cmd (String or :class: `ATStringCommand`): Parameter to get/set.
            value (Bytearray, optional, default=`None`): Value to set.
            retries (Integer, optional, default=5): Number of retries to perform.
            apply (Boolean, optional, default=`False`): `True` to apply.

        Returns:
            Bytearray: Read parameter value.

        Raises:
            XBeeException: If the value could be get/set after the retries.
        """
        if func not in (AbstractXBeeDevice.get_parameter,
                        AbstractXBeeDevice.set_parameter,
                        XBeeDevice.get_parameter, XBeeDevice.set_parameter,
                        RemoteXBeeDevice.get_parameter, RemoteXBeeDevice.set_parameter):
            raise ValueError("Invalid function")

        error_msg = None

        total = retries
        for retry in range(retries):
            try:
                if value:
                    _log.debug("'%s' Setting parameter '%s' to '%s' (%d/%d)", node,
                               cmd.command, utils.hex_to_string(value, pretty=False),
                               (retry + 1), total)
                    return func(node, cmd, value, apply=apply)
                return func(node, cmd, apply=apply)
            except XBeeException as exc:
                error_msg = ("Unable to %s command '%s': %s"
                             % ("set" if value else "get", cmd.command, str(exc)))
            time.sleep(0.2)

        if error_msg:
            raise XBeeException(error_msg)

    def progress_cb(self, task, done=0):
        """
        If a callback was provided in the constructor, notifies it with the
        provided task and the corresponding percentage.

        Args:
            task (String): The task to inform about, it must be `TASK_PREPARE`
                or `TASK_RESTORE`.
            done (Integer, optional, default=0): Total amount of done job. If 0,
                it is increased by one.

        Returns:
            Integer: Total work done for the task.
        """
        if self._xbee.is_remote():
            xnet = self._xbee.get_local_xbee_device().get_network()
        else:
            xnet = self._xbee.get_network()

        net_progress_cbs = None
        if xnet:
            net_progress_cbs = xnet.get_update_progress_callbacks()

        if (not self._callback and not net_progress_cbs
                and not _log.isEnabledFor(logging.DEBUG)):
            return 0

        percentage = 0
        total_done = 0
        active_task = None

        if task.startswith(self.TASK_PREPARE):
            active_task = self.TASK_PREPARE
        elif task.startswith(self.TASK_RESTORE):
            active_task = self.TASK_RESTORE

        if active_task:
            if done > 0:
                self._task_done[active_task] = done
            total_done = self._task_done[active_task]
            percentage = total_done * 100 // self._task_total[active_task]
            if done == 0:
                self._task_done[active_task] += 1
            percentage = max(min(percentage, 100), 0)

        _log.debug("%s: %d", task, percentage)
        if self._callback:
            self._callback(task, percentage)
        if net_progress_cbs:
            update_type = self._xbee._active_update_type
            net_progress_cbs(self._xbee,
                             UpdateProgressStatus(update_type,
                                                  task, percentage, False))

        return total_done

    def _is_sync_sleep(self):
        """
        Checks if the network is a DigiMesh synchronous sleeping network.

        Returns:
             Boolean: `True` if is a sync sleeping network, `False` otherwise.
        """
        if self._xbee.is_remote():
            local = self._xbee.get_local_xbee_device()
        else:
            local = self._xbee

        if local.get_protocol() != XBeeProtocol.DIGI_MESH:
            return False

        try:
            value = self.exec_at_cmd(AbstractXBeeDevice.get_parameter, local, ATStringCommand.SM)
            return int.from_bytes(value, "big") in (7, 8)
        except XBeeException as exc:
            _log.debug("Could not read '%s': %s", ATStringCommand.SM.command, str(exc))
            return False

    def _prepare_node_for_update(self, restore_later=True):
        """
        Prepares the node for an update. It reconfigures 'SP' and 'SN' params
        to their minimum value, in asynchronous sleep nodes.

        Args:
            restore_later (Boolean, optional, default=`True`): `True` to store
                'SP' and 'SN' original values to restore them later.
        """
        _log.debug("'%s' - %s: node", self._xbee, self.TASK_PREPARE)

        self.cmd_dict = {self._xbee: {}}

        if self._xbee.get_protocol() == XBeeProtocol.ZIGBEE:
            # For end devices, sleep the minimum possible
            if self._xbee.get_role() not in (Role.END_DEVICE, Role.UNKNOWN, None):
                return
        elif self._xbee.get_protocol() == XBeeProtocol.DIGI_MESH:
            # For sync sleeping routers, do nothing
            if self.sync_sleep:
                return
        elif self._xbee.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # Read SM value, if not enabled is not a sleeping device
            try:
                sm_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter,
                                          self._xbee, ATStringCommand.SM)
                if sm_val is not None and int.from_bytes(sm_val, "big") == 0:
                    return
            except XBeeException as exc:
                _log.info("Unable to read '%s' configuration: %s", self._xbee, str(exc))
        elif self._xbee.get_protocol() == XBeeProtocol.DIGI_POINT:
            # P2MP does not require settings preparation
            return

        default_sp = self._get_min_value(ATStringCommand.SP, self._xbee.get_protocol())
        default_sn = self._get_min_value(ATStringCommand.SN, self._xbee.get_protocol())
        to_prepare = {
            ATStringCommand.SP: bytearray([default_sp]),
            ATStringCommand.SN: bytearray([default_sn])
        }

        if restore_later:
            sp_val = None
            sn_val = None
            try:
                sp_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter, self._xbee,
                                          ATStringCommand.SP)
                sn_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter, self._xbee,
                                          ATStringCommand.SN)
            except XBeeException as exc:
                _log.info("Unable to read '%s' configuration: %s", self._xbee, str(exc))
            if sp_val is not None and int.from_bytes(sp_val, "big") != default_sp:
                self.cmd_dict[self._xbee][ATStringCommand.SP] = sp_val
            if sn_val is not None and int.from_bytes(sn_val, "big") != default_sn:
                self.cmd_dict[self._xbee][ATStringCommand.SN] = sn_val

        try:
            for cmd, val in to_prepare.items():
                self.exec_at_cmd(AbstractXBeeDevice.set_parameter, self._xbee, cmd,
                                 value=val, apply=True)
            if restore_later:
                self.exec_at_cmd(AbstractXBeeDevice.set_parameter, self._xbee,
                                 ATStringCommand.WR, value=bytearray([0]),
                                 apply=True)
        except XBeeException as exc:
            _log.info("Unable to set '%s' to minimum sleep temporally: %s",
                      self._xbee, str(exc))

    def _prepare_network_for_update(self):
        """
        Prepares a DigiMesh sync sleep network for an update process. It changes
        the sleep time of the network to the minimum value (1) by modifying the
        'SP' value of the local XBee and waits a maximum of original sleep cycle
        to start the update process.
        It also modifies 'SO' of the local XBee to be eligible to be a sleep
        coordinator (bit 1 = 0) and enable modem status network sleep frames
        (bit 2 = 1). It stores original values to restore them later.

        Raises:
            XBeeException: If cannot get network synchronous sleep configuration,
                or cannot prepare the network.
        """
        if not self.sync_sleep:
            return

        _log.debug("'%s' - %s: network", self._xbee, self.TASK_PREPARE)

        if self._xbee.is_remote():
            local = self._xbee.get_local_xbee_device()
        else:
            local = self._xbee

        old_timeout = local.get_sync_ops_timeout()
        if self._timeout:
            local.set_sync_ops_timeout(max(old_timeout, self._timeout))

        error_format = "Unable to perform update: %s"

        # Read the sleep time
        try:
            os_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter, local,
                                      ATStringCommand.OS)
            ow_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter, local,
                                      ATStringCommand.OW)
            if os_val is None or ow_val is None:
                msg = error_format % "Cannot get network synchronous sleep configuration"
                _log.error(msg)
                self.progress_cb("%s: %s" % (self.TASK_PREPARE, msg), done=100)
                raise XBeeException(msg)

            # Read the sleep options
            so_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter, local,
                                      ATStringCommand.SO)
            orig_so_val = so_val
            if so_val is None:
                msg = error_format % "Cannot get network synchronous sleep configuration"
                _log.error(msg)
                self.progress_cb("%s: %s" % (self.TASK_PREPARE, msg), done=100)
                raise XBeeException(msg)

            so_val = utils.int_to_bytes(utils.bytes_to_int(so_val), 2)
            # Ensure the local node can be a sleep coordinator:
            # SO bit 1: Non-sleep coordinator (0)
            so_val[1] = so_val[1] & ~0x02 if so_val[1] & 0x02 else so_val[1]

            # SO bit 2: Enable API sleep status messages (1)
            so_val[1] = so_val[1] | 0x04 if so_val[1] & 0x04 != 4 else so_val[1]

            self.cmd_dict.update({local: {}})

            to_apply = {}
            # Configure SO
            if utils.bytes_to_int(orig_so_val) != utils.bytes_to_int(so_val):
                to_apply[ATStringCommand.SO] = so_val
                self.cmd_dict[local][ATStringCommand.SO] = orig_so_val

            sleep_time = utils.bytes_to_int(os_val) / 100
            wake_time = utils.bytes_to_int(ow_val) / 1000

            # Configure SP with the minimum value
            if sleep_time != 0.01:  # 10 ms
                to_apply[ATStringCommand.SP] = bytearray([1])
                self.cmd_dict[local][ATStringCommand.ST] = ow_val
                self.cmd_dict[local][ATStringCommand.SP] = os_val

            # Configure ST with a minimum value of 30 seconds
            if wake_time != self._DM_SYNC_WAKE_TIME:
                to_apply[ATStringCommand.ST] = utils.int_to_bytes(self._DM_SYNC_WAKE_TIME*1000)
                self.cmd_dict[local][ATStringCommand.ST] = ow_val

            msg = ""
            for cmd, val in to_apply.items():
                try:
                    self.exec_at_cmd(AbstractXBeeDevice.set_parameter, local, cmd,
                                     value=val)
                except XBeeException:
                    msg = error_format % "Cannot prepare local XBee for update"

            try:
                self.exec_at_cmd(AbstractXBeeDevice.set_parameter, local,
                                 ATStringCommand.AC, value=bytearray([0]), apply=True)
            except XBeeException:
                pass

            if not msg:
                self.progress_cb(
                    "%s: %s" % (self.TASK_PREPARE, "waiting for network to wake"))
                if not self._wait_for_dm_network_up(sleep_time + wake_time):
                    msg = error_format % "Network is not awake"

            # Restore in case of error
            if msg:
                self._restore_network_after_update()
                _log.error(msg)
                self.progress_cb("%s: %s" % (self.TASK_PREPARE, msg), done=100)
                raise XBeeException(msg)
            if so_val[1] & 0x04 != 4:
                # Restore SO not to have so many modem status frames
                # SO bit 2: Disable API sleep status messages (0)
                so_val[1] = so_val[1] & ~0x04
                try:
                    self.exec_at_cmd(AbstractXBeeDevice.set_parameter, local,
                                     ATStringCommand.SO, value=so_val, apply=True)
                except XBeeException:
                    pass
        finally:
            local.set_sync_ops_timeout(old_timeout)

    def _restore_node_after_update(self, node, port_settings=None):
        """
        Restores the node parameters after an update process.

        Args:
             node (:class: `.AbstractXBeeDevice): The node to restore.
             port_settings(Dictionary, optional, default=`None`): Dictionary
                with the new serial port configuration, `None` for remote node
                or if the serial config has not changed.
        """
        to_restore = self.cmd_dict.pop(node, {})
        if not to_restore:
            self._update_node_info(node, self.TASK_RESTORE)
            return

        _log.debug("'%s' - %s: node", node, self.TASK_RESTORE)

        # Set stored parameter values
        for cmd, val in to_restore.items():
            try:
                self.exec_at_cmd(AbstractXBeeDevice.set_parameter, node, cmd, value=val)
            except XBeeException as exc:
                _log.info("'%s' - %s: Unable to restore configuration: %s", node,
                          self.TASK_RESTORE, str(exc))

        # Write to flash changed values
        try:
            self.exec_at_cmd(AbstractXBeeDevice.set_parameter, node,
                             ATStringCommand.WR, value=bytearray([0]), apply=False)
        except XBeeException as exc:
            _log.info("'%s' - %s: Unable to restore configuration: %s", node,
                      self.TASK_RESTORE, str(exc))

        # For DigiMesh sync sleep network, calculate sleep period to wait to
        # properly apply final sleep settings
        wait_time = 0
        if self.sync_sleep and self._must_wait_for_network(node, to_restore):
            if node.is_remote():
                wait_time = self._DM_SYNC_WAKE_TIME + 1
            else:
                try:
                    sp_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter,
                                              node, ATStringCommand.OS)
                except XBeeException:
                    sp_val = [1]
                try:
                    st_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter,
                                              node, ATStringCommand.OW)
                except XBeeException:
                    st_val = [self._DM_SYNC_WAKE_TIME]

                wait_time = (utils.bytes_to_int(sp_val) / 100
                             + utils.bytes_to_int(st_val) / 1000)

        error_applying = False
        # Apply changed values
        try:
            self.exec_at_cmd(AbstractXBeeDevice.set_parameter, node,
                             ATStringCommand.AC, value=bytearray([0]), apply=True)
        except XBeeException as exc:
            _log.info("'%s' - %s: Unable to restore configuration: %s", node,
                      self.TASK_RESTORE, str(exc))
            error_applying = True

        # Check if port settings have changed on local devices.
        if not error_applying and port_settings and not node.is_remote():
            # Apply the new port configuration.
            try:
                node.close()  # This is necessary to stop the frames read thread.
                node.serial_port.apply_settings(port_settings)
                node.open()
            except (XBeeException, SerialException) as exc:
                _log.info("Error re-configuring XBee serial port: %s", str(exc))
                error_applying = True

        if not error_applying and not node.is_remote():
            self._update_node_info(node, self.TASK_RESTORE)

        # Wait for sync sleep configuration to apply
        if wait_time:
            _log.debug("'%s' - %s: Waiting for network to awake", node, self.TASK_RESTORE)
            if not self._wait_for_dm_network_up(wait_time):
                _log.info("'%s' - %s: Network is not awake", node, self.TASK_RESTORE)

    def _restore_network_after_update(self):
        """
        Restores a network previously configured for update.
        """
        if not self.cmd_dict:
            return

        _log.debug("'%s' - %s: network", self._xbee, self.TASK_RESTORE)

        if self._xbee.is_remote():
            local = self._xbee.get_local_xbee_device()
        else:
            local = self._xbee

        old_timeout = local.get_sync_ops_timeout()
        if self._timeout:
            local.set_sync_ops_timeout(max(old_timeout, self._timeout))

        self._restore_node_after_update(local)

        local.set_sync_ops_timeout(old_timeout)

    def _must_wait_for_network(self, node, node_config):
        """
        Checks which sync sleep values must be restored, the stored ones or
        new ones from the node.

        Args:
            node (:class: `.AbstractXBeeDevice`): The node that has just been
                updated.
            node_config (Dictionary): The dictionary with the restored node
                configuration.

        Returns:
            Boolean: `True` if must wait for network to wake up, `False`
                otherwise.
        """
        if not self.sync_sleep:
            return False
        # If no SP nor ST are configured, do not wait
        sp_val = node_config.get(ATStringCommand.SP, None)
        st_val = node_config.get(ATStringCommand.ST, None)
        if sp_val is None and st_val is None:
            return False
        # If SM is modified and is not a synchronous sleep mode, do not wait
        sm_val = node_config.get(ATStringCommand.SM, None)
        if sm_val is not None and int.from_bytes(sm_val, "big") not in (7, 8):
            return False

        if node.is_remote():
            # If the node is not eligible as sleep coordinator, do not remove
            # already stored values
            so_val = node_config.get(ATStringCommand.SO, None)
            if so_val is None:
                try:
                    so_val = self.exec_at_cmd(AbstractXBeeDevice.get_parameter,
                                              node, ATStringCommand.SO)
                except XBeeException:
                    pass

            if so_val is None:
                remove_stored = False
            else:
                so_val = utils.int_to_bytes(utils.bytes_to_int(so_val), 2)
                remove_stored = bool(so_val[1] & 0x02 != 0x02)

            if remove_stored:
                local_cmds = self.cmd_dict.get(node.get_local_xbee_device(), {})
                # Do not restore stored values, the already configured values
                # for the node are the valid ones
                if sp_val:
                    local_cmds.pop(ATStringCommand.SP, None)
                if st_val:
                    local_cmds.pop(ATStringCommand.ST, None)

        return True

    def _update_node_info(self, node, task):
        """
        Tries to read the node information.
        """
        retries = _PARAM_READ_RETRIES
        while retries > 0:
            _log.debug("'%s' - %s: Reading node info (%d/%d)", node, task,
                       (_PARAM_READ_RETRIES + 1 - retries),
                       _PARAM_READ_RETRIES)
            try:
                node.read_device_info(init=True, fire_event=True)
                break
            except XBeeException as exc:
                retries -= 1
                if not retries:
                    _log.info("'%s' - %s: %s", self._xbee, task,
                              _ERROR_UPDATE_TARGET_INFO % str(exc))
                    break
                time.sleep(0.2 if not self._xbee.is_remote else 5)

    def _wait_for_dm_network_up(self, timeout):
        """
        Waits for a sync sleep DigiMesh network to update the maximum provided
        timeout. It returns when the network wakes up or when the timeout
        expires.

        Args:
            timeout(Float): Maximum number of seconds to wait.

        Returns:
            Boolean: `True` when the network is awake, `False` if the timeout
                expired.
        """
        if not self._xbee.is_remote() or not self._sync_sleep:
            return True

        local = self._xbee.get_local_xbee_device()

        wait_timeout = timeout * 1.2  # 20% more

        awake = Event()

        # Register a callback to check if the local XBee is configured to
        # 'Enable API sleep status messages' (bit 2 of 'SO')
        def modem_st_cb(modem_status):
            if modem_status == ModemStatus.NETWORK_WOKE_UP:
                local.del_modem_status_received_callback(modem_st_cb)
                awake.set()

        local.add_modem_status_received_callback(modem_st_cb)
        return awake.wait(timeout=wait_timeout)

    @staticmethod
    def _get_min_value(cmd, protocol):
        """
        Returns the minimum value.
        TODO: A class with firmware XML file parsed should be provided. These
              values are stored there and we do not need to hardcode them.
        """
        min_values = {
            ATStringCommand.SN: {XBeeProtocol.ZIGBEE: 1,
                                 XBeeProtocol.DIGI_MESH: 1,
                                 XBeeProtocol.RAW_802_15_4: 1},
            ATStringCommand.SP: {XBeeProtocol.ZIGBEE: 0x20,
                                 XBeeProtocol.DIGI_MESH: 1,
                                 XBeeProtocol.RAW_802_15_4: 0}
        }
        return min_values.get(cmd, {}).get(protocol, None)


class _XBeeFirmwareUpdater(ABC):
    """
    Helper class used to handle XBee firmware update processes.
    """

    def __init__(self, xml_fw_file, timeout=_READ_DATA_TIMEOUT, progress_cb=None):
        """
        Class constructor. Instantiates a new :class:`._XBeeFirmwareUpdater`
        with the given parameters.

        Args:
            xml_fw_file (String): Location of the XML firmware file.
            timeout (Integer, optional, default=3): Process operations timeout.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        self._xml_fw_file = xml_fw_file
        self._progress_callback = progress_cb
        self._progress_task = None
        self._xml_hw_version = None
        self._xml_fw_version = None
        self._xml_compat_number = None
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
        self._target_fw_version = None
        self._target_hw_version = None
        self._target_compat_number = None
        self._target_region_lock = None
        self._target_bootloader_version = None

    def _notify_progress(self, task_str, percent, finished=False):
        """
        Notifies update progress information.

        Args:
            task_str (String): Current update task.
            percent (Integer): Current update progress percent.
            finished (Boolean, optional, default=`False`): `True` if the update
                process finished, `False` otherwise.
        """
        if self._progress_callback:
            self._progress_callback(task_str, percent)

    def _parse_xml_firmware_file(self):
        """
        Parses the XML firmware file and stores the required parameters.

        Raises:
            FirmwareUpdateException: If there is any error parsing the XML
                firmware file.
        """
        _log.debug("Parsing XML firmware file %s:", self._xml_fw_file)
        try:
            root = ElementTree.parse(self._xml_fw_file).getroot()
            # Firmware version, required.
            element = root.find(_XML_FIRMWARE)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_fw_file, restore_updater=False)
            self._xml_fw_version = int(element.get(_XML_FIRMWARE_VERSION_ATTRIBUTE), 16)
            _log.debug(" - Firmware version: %s",
                       utils.hex_to_string([self._xml_fw_version], pretty=False)
                       if self._xml_fw_version is not None else "-")
            # Hardware version, required.
            element = root.find(_XML_HARDWARE_VERSION)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_fw_file, restore_updater=False)
            self._xml_hw_version = int(element.text, 16)
            _log.debug(" - Hardware version: %s",
                       utils.hex_to_string([self._xml_hw_version], pretty=False)
                       if self._xml_hw_version is not None else "-")
            # Compatibility number, required.
            element = root.find(_XML_COMPATIBILITY_NUMBER)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_fw_file, restore_updater=False)
            self._xml_compat_number = int(element.text)
            _log.debug(" - Compatibility number: %d", self._xml_compat_number)
            # Bootloader version, optional.
            element = root.find(_XML_BOOTLOADER_VERSION)
            if element is not None:
                self._xml_bootloader_version = _bootloader_version_to_bytearray(element.text)
            _log.debug(" - Bootloader version: %s", self._xml_bootloader_version)
            # Region lock, required.
            element = root.find(_XML_REGION_LOCK)
            if element is None:
                self._exit_with_error(_ERROR_XML_PARSE % self._xml_fw_file, restore_updater=False)
            self._xml_region_lock = Region.get(int(element.text))
            if self._xml_region_lock is None:
                self._xml_region_lock = Region.ALL
            _log.debug(" - Region lock: %s", self._xml_region_lock)
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
        except ParseError as exc:
            _log.exception(exc)
            self._exit_with_error(_ERROR_XML_PARSE % self._xml_fw_file, restore_updater=False)

    def _exit_with_error(self, msg, restore_updater=True):
        """
        Finishes the process raising a :class`.FirmwareUpdateException` and
        leaves updater in the initial state.

        Args:
            msg (String): Error message of the exception to raise.
            restore_updater (Boolean): `True` to restore updater configuration
                before exiting, `False` otherwise.

        Raises:
            FirmwareUpdateException: Exception is always thrown in this method.
        """
        # Check if updater restore is required.
        if restore_updater:
            try:
                self._restore_updater()
            except (SerialException, XBeeException) as exc:
                _log.error("ERROR: %s", _ERROR_RESTORE_TARGET_CONNECTION % str(exc))

        try:
            self._restore_local_connection()
        except Exception as exc:
            _log.error("ERROR: %s", _ERROR_RESTORE_LOCAL_CONNECTION % str(exc))

        _log.error("ERROR: %s", msg)
        raise FirmwareUpdateException(msg)

    def _check_target_compatibility(self):
        """
        Checks whether the target device is compatible with the firmware to
        update by checking:
            - Bootloader version.
            - Compatibility number.
            - Region lock.
            - Hardware version.

        Raises:
            FirmwareUpdateException: If the target device is not compatible
                with the firmware to update.
        """
        # At the moment the target checks are the same for local and remote
        # updates since only XBee3 devices are supported. This might need to be
        # changed in the future if other hardware is supported.

        # Read device values required for verification steps prior to firmware update.
        _log.debug("Reading device settings:")
        self._target_fw_version = self._get_target_fw_version()
        _log.debug(" - Firmware version: %s",
                   utils.hex_to_string([self._target_fw_version], pretty=False)
                   if self._target_fw_version is not None else "-")
        self._target_hw_version = self._get_target_hw_version()
        _log.debug(" - Hardware version: %s",
                   utils.hex_to_string([self._target_hw_version], pretty=False)
                   if self._target_hw_version is not None else "-")
        self._target_compat_number = self._get_target_compatibility_number()
        _log.debug(" - Compatibility number: %s", self._target_compat_number)
        self._target_bootloader_version = self._get_target_bootloader_version()
        _log.debug(" - Bootloader version: %s", self._target_bootloader_version)
        self._target_region_lock = self._get_target_region_lock()
        _log.debug(" - Region lock: %s", self._target_region_lock)

        # Check if the hardware version is compatible with the firmware update process.
        if (self._target_hw_version
                and self._target_hw_version not in LOCAL_SUPPORTED_HW_VERSIONS + REMOTE_SUPPORTED_HW_VERSIONS):
            self._exit_with_error(_ERROR_HW_VERSION_NOT_SUPPORTED % self._target_hw_version,
                                  restore_updater=False)

        # Check if device hardware version is compatible with the firmware.
        if self._target_hw_version and self._target_hw_version != self._xml_hw_version:
            self._exit_with_error(_ERROR_HW_VERSION_DIFFER %
                                  (self._target_hw_version, self._xml_hw_version),
                                  restore_updater=False)

        # Check compatibility number.
        if self._target_compat_number and self._target_compat_number > \
                self._xml_compat_number:
            self._exit_with_error(_ERROR_COMPATIBILITY_NUMBER %
                                  (self._target_compat_number, self._xml_compat_number),
                                  restore_updater=False)

        # Check region lock for compatibility numbers greater than 1.
        if self._target_compat_number and self._target_compat_number > 1 and \
                self._target_region_lock is not None:
            if (not self._target_region_lock.allows_any()
                    and self._xml_region_lock not in (Region.SKIP, self._target_region_lock)):
                self._exit_with_error(
                    _ERROR_REGION_LOCK % (self._target_region_lock, self._xml_region_lock),
                    restore_updater=False)

        # Check whether bootloader update is required.
        self._bootloader_update_required = self._check_bootloader_update_required()

        # Check whether bootloader reset the device settings.
        self._bootloader_reset_settings = self._check_bootloader_reset_settings()

    def _check_bootloader_update_required(self):
        """
        Checks whether the bootloader needs to be updated.

        Returns:
            Boolean: `True` if the bootloader needs to be updated, `False` otherwise.
        """
        # If any bootloader version is None (the XML firmware file one or the
        # device one), update is not required.
        if None in (self._xml_bootloader_version, self._target_bootloader_version):
            return False

        # At this point we can ensure both bootloader versions are not None and
        # they are 3 bytes long. Since the bootloader cannot be downgraded, the
        # XML specifies the minimum required bootloader version to update the
        # firmware. Return `True` only if the specified XML bootloader version
        # is greater than the target one.
        return self._xml_bootloader_version > self._target_bootloader_version

    def _check_bootloader_reset_settings(self):
        """
        Checks whether the bootloader performed a reset of the device settings.

        Returns:
            Boolean: `True` if the bootloader performed a reset of the device
                settings, `False` otherwise
        """
        if not self._bootloader_update_required:
            return False

        # On XBee 3 devices with a bootloader version below 1.6.6, updating the
        # bootloader implies a reset of the module settings. Return True if the
        # device bootloader version was below 1.6.6.
        return self._target_bootloader_version < _BOOTLOADER_XBEE3_RESET_ENV_VERSION

    @abstractmethod
    def _get_default_reset_timeout(self):
        """
        Returns the default timeout to wait for reset.
        """

    def _wait_for_target_reset(self):
        """
        Waits for the device to reset using the xml firmware file specified
        timeout or the default one.
        """
        if self._xml_update_timeout_ms is not None:
            time.sleep(self._xml_update_timeout_ms / 1000.0)
        else:
            time.sleep(self._get_default_reset_timeout())

    def update_firmware(self):
        """
        Updates the firmware of the XBee.
        """
        # Start by parsing the XML firmware file.
        self._parse_xml_firmware_file()

        # Verify that the binary firmware file exists.
        self._check_fw_binary_file()

        # Check whether protocol will change or not.
        self._protocol_changed = self._will_protocol_change()

        # Connect local XBee
        self._connect_local()

        # Check if updater is able to perform firmware updates.
        self._check_updater_compatibility()

        # Check if target is compatible with the firmware to update.
        self._check_target_compatibility()

        # Check bootloader update file exists if required.
        _log.debug("Bootloader update required? %s", self._bootloader_update_required)
        if self._bootloader_update_required:
            self._check_bootloader_binary_file()

        # Configure the updater device.
        self._configure_updater()

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
        except Exception as exc:
            self._exit_with_error(str(exc), restore_updater=False)

        # Leave local connection in its original state.
        try:
            self._restore_local_connection()
        except Exception as exc:
            _log.error("ERROR: %s", str(exc))
            raise FirmwareUpdateException(_ERROR_RESTORE_LOCAL_CONNECTION % str(exc)) from None

        # Update target information.
        try:
            self._update_target_information()
        except FirmwareUpdateException as exc:
            raise exc

        _log.info("Update process finished successfully")

    def check_protocol_changed_by_fw(self, orig_protocol):
        """
        Determines whether the XBee protocol will change after the firmware
        update.

        Args:
            orig_protocol (:class: `.XBeeProtocol): The original protocol
                before the update.

        Returns:
            Boolean: `True` if the protocol will change after the firmware
                update, `False` otherwise.
        """
        new_protocol = XBeeProtocol.determine_protocol(
            self._xml_hw_version, utils.int_to_bytes(self._xml_fw_version))
        return orig_protocol != new_protocol

    @abstractmethod
    def _check_updater_compatibility(self):
        """
        Verifies whether the updater device is compatible with firmware update.
        """

    @abstractmethod
    def _check_fw_binary_file(self):
        """
        Verifies that the firmware binary file exists.

        Raises:
            FirmwareUpdateException: If the firmware binary file does not
                exist or is invalid.
        """

    @abstractmethod
    def _check_bootloader_binary_file(self):
        """
        Verifies that the bootloader binary file exists.

        Raises:
            FirmwareUpdateException: If the bootloader binary file does not
                exist or is invalid.
        """

    @abstractmethod
    def _get_target_bootloader_version(self):
        """
        Returns the update target bootloader version.

        Returns:
            Bytearray: Update target version as byte array, `None` if it could
                not be read.
        """

    @abstractmethod
    def _get_target_compatibility_number(self):
        """
        Returns the update target compatibility number.

        Returns:
            Integer: Update target compatibility number as integer, `None` if
                it could not be read.
        """

    @abstractmethod
    def _get_target_region_lock(self):
        """
        Returns the update target region lock number.

        Returns:
            :class:`.Region`: Update target region lock, `None` if it
                could not be read.
        """

    @abstractmethod
    def _get_target_hw_version(self):
        """
        Returns the update target hardware version.

        Returns:
            Integer: Update target hardware version as integer, `None` if it
                could not be read.
        """

    @abstractmethod
    def _get_target_fw_version(self):
        """
        Returns the update target firmware version.

        Returns:
            Integer: Update target firmware version as integer, `None` if it
                could not be read.
        """

    @abstractmethod
    def _connect_local(self):
        """
        Connects the local XBee.

        Raises:
            FirmwareUpdateException: If there is any error connecting the
                local device.
        """

    @abstractmethod
    def _configure_updater(self):
        """
        Configures the updater device before performing the firmware update
        operation.

        Raises:
            FirmwareUpdateException: If there is any error configuring the
                updater device.
        """

    @abstractmethod
    def _restore_updater(self):
        """
        Leaves the updater device to its original state before the update operation.

        Raises:
            SerialException: If there is any error restoring the serial port connection.
            XBeeException: If there is any error restoring the device connection.
        """

    @abstractmethod
    def _restore_local_connection(self):
        """
        Leaves the local connection to its original state before the update operation.

        Raises:
            SerialException: If there is any error restoring the serial port connection.
        """

    @abstractmethod
    def _start_firmware_update(self):
        """
        Starts the firmware update process. Called just before the transfer
        firmware operation.

        Raises:
            FirmwareUpdateException: If there is any error configuring the target device.
        """

    @abstractmethod
    def _transfer_firmware(self):
        """
        Transfers the firmware file(s) to the target.

        Raises:
            FirmwareUpdateException: If there is any error transferring the
                firmware to the target device.
        """

    @abstractmethod
    def _finish_firmware_update(self):
        """
        Finishes the firmware update process. Called just after the transfer
        firmware operation.

        Raises:
            FirmwareUpdateException: If there is any error finishing the
                firmware update process.
        """

    @abstractmethod
    def _update_target_information(self):
        """
        Updates the target information after the firmware update.

        Raises:
            FirmwareUpdateException: If there is any error getting info.
        """

    @abstractmethod
    def _will_protocol_change(self):
        """
        Determines whether the XBee protocol will change after the update.

        Returns:
            Boolean: `True` if the protocol will change after the update,
                `False` otherwise.
        """


class _LocalFirmwareUpdater(_XBeeFirmwareUpdater):
    """
    Helper class used to handle the local firmware update process.
    """

    __DEVICE_RESET_TIMEOUT = 3  # seconds

    def __init__(self, target, xml_fw_file, xbee_fw_file=None,
                 timeout=_READ_DATA_TIMEOUT, progress_cb=None):
        """
        Class constructor. Instantiates a new :class:`._LocalFirmwareUpdater`
        with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): Target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: XBee to upload its firmware.
            xml_fw_file (String): Location of the XML firmware file.
            xbee_fw_file (String, optional): Location of the XBee binary firmware file.
            timeout (Integer, optional): Serial port read data operation timeout.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super().__init__(xml_fw_file, timeout=timeout, progress_cb=progress_cb)

        self._fw_file = xbee_fw_file
        self._serial_port = None
        self._port_params = None
        self._updater_was_connected = False
        if isinstance(target, str):
            self._port = target
            self._xbee = None
        else:
            self._port = None
            self._xbee = target

    def _notify_progress(self, task_str, percent, finished=False):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._notify_progress`
        """
        super()._notify_progress(task_str, percent, finished=finished)

        if not self._xbee:
            return

        update_type = self._xbee._active_update_type

        xnet = self._xbee.get_network()
        if xnet:
            progress_cbs = xnet.get_update_progress_callbacks()
            if progress_cbs:
                progress_cbs(self._xbee,
                             UpdateProgressStatus(update_type, task_str, percent, finished))

        if finished and update_type == NodeUpdateType.FIRMWARE:
            self._xbee._active_update_type = None

    def _check_fw_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_fw_binary_file`
        """
        # If not already specified, the binary firmware file is usually in the
        # same folder as the XML firmware file.
        if self._fw_file is None:
            path = Path(self._xml_fw_file)
            self._fw_file = str(Path(path.parent).joinpath(
                path.stem + self._get_fw_binary_file_extension()))

        if not _file_exists(self._fw_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("XBee firmware", self._fw_file),
                                  restore_updater=False)

    def _enter_bootloader_mode_with_break(self):
        """
        Attempts to put the device in bootloader mode using the Break line.

        Returns:
            Boolean: `True` if the device was set in bootloader mode,
                `False` otherwise.
        """
        _log.debug("Setting device in bootloader mode using the Break line")
        # The process requires RTS line to be disabled and Break line to be
        # asserted during some time.
        self._serial_port.rts = 0
        break_thread = _BreakThread(self._serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
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
                self._serial_port.rts = 0
                break_thread = _BreakThread(self._serial_port,
                                            _DEVICE_BREAK_RESET_TIMEOUT)
                break_thread.start()

        # Restore break condition.
        if break_thread.is_running():
            break_thread.stop_break()

        return False

    def _get_target_bootloader_version(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_bootloader_version`
        """
        if self._serial_port is not None:
            return self._get_target_bootloader_version_bootloader()
        return _get_bootloader_version(self._xbee)

    def _get_target_compatibility_number(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_compatibility_number`
        """
        if self._serial_port is not None:
            return self._get_target_compatibility_number_bootloader()
        return _get_compatibility_number(self._xbee)

    def _get_target_region_lock(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_region_lock`
        """
        if self._serial_port is not None:
            return self._get_target_region_lock_bootloader()
        return _get_region_lock(self._xbee)

    def _get_target_hw_version(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_hw_version`
        """
        if self._serial_port is not None:
            return self._get_target_hw_version_bootloader()
        return _get_hw_version(self._xbee)

    def _get_target_fw_version(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_fw_version`
        """
        if self._serial_port is not None:
            # Firmware version cannot be read from bootloader.
            return None
        return _get_fw_version(self._xbee)

    def _check_updater_compatibility(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_updater_compatibility`
        """
        # In local firmware updates, the updater device and target device are
        # the same. Just return and use the target function check instead.

    def _connect_local(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._connect_local`
        """
        # For local updates, target and update device is the same.
        # Depending on the given target, process has a different flow
        # (serial port or XBee).
        if self._xbee is None:
            # Configure serial port connection with bootloader parameters.
            try:
                _log.debug("Opening port '%s'", self._port)
                self._serial_port = _create_serial_port(
                    self._port, self._get_bootloader_serial_params())
                self._serial_port.open()
            except SerialException as exc:
                _log.error(_ERROR_CONNECT_SERIAL_PORT, str(exc))
                raise FirmwareUpdateException(_ERROR_CONNECT_SERIAL_PORT % str(exc)) from exc

            # Check if device is in bootloader mode.
            _log.debug("Checking if bootloader is active")
            if not self._is_bootloader_active():
                # If the bootloader is not active, enter in bootloader mode.
                if not self._enter_bootloader_mode_with_break():
                    self._exit_with_error(_ERROR_BOOTLOADER_MODE, restore_updater=False)
        else:
            self._updater_was_connected = self._xbee.is_open()
            _log.debug("Connecting device '%s'", self._xbee)
            if not _connect_device_with_retries(self._xbee, _DEVICE_CONNECTION_RETRIES):
                if not self._set_device_in_programming_mode():
                    self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES,
                                          restore_updater=False)

    def _configure_updater(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._configure_updater`
        """
        # In local firmware updates, the updater and target device are the same.

    def _restore_updater(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._restore_updater`
        """
        # For local updates, target and update device is the same.

    def _restore_local_connection(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._restore_local_connection`
        """
        # For local updates, target and update device is the same.
        if self._xbee is not None:
            if self._serial_port is not None:
                if self._serial_port.isOpen():
                    self._serial_port.close()
                if self._port_params is not None:
                    self._serial_port.apply_settings(self._port_params)
            if (self._updated and self._protocol_changed) or \
                    (self._bootloader_updated and self._bootloader_reset_settings):
                # Since the protocol has changed or an old bootloader was
                # updated, a forced port open is required because all the
                # configured settings are restored to default values, including
                # the serial communication ones.
                self._xbee.close()
                self._xbee.open(force_settings=True)
            if self._updater_was_connected and not self._xbee.is_open():
                self._xbee.open()
            elif not self._updater_was_connected and self._xbee.is_open():
                self._xbee.close()
        elif self._serial_port is not None and self._serial_port.isOpen():
            self._serial_port.close()

    def _start_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._start_firmware_update`
        """
        if self._xbee is not None and not self._set_device_in_programming_mode():
            self._exit_with_error(_ERROR_DEVICE_PROGRAMMING_MODE)

    def _update_target_information(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._update_target_information`
        """
        _log.debug("Updating target information...")
        if not self._xbee:
            return

        # If the protocol of the device has changed, clear the network.
        if self._protocol_changed:
            self._xbee.get_network()._clear(NetworkEventReason.FIRMWARE_UPDATE)
        # Read device information again.
        was_open = self._xbee.is_open()
        try:
            if not was_open:
                self._xbee.open()
            self._xbee._read_device_info(NetworkEventReason.FIRMWARE_UPDATE,
                                         init=True, fire_event=True)
        except XBeeException as exc:
            msg = _ERROR_UPDATE_TARGET_INFO % str(exc)
            _log.error(msg)
            raise FirmwareUpdateException(msg) from None
        finally:
            if not was_open:
                self._xbee.close()

    def _will_protocol_change(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._will_protocol_change`
        """
        if not self._xbee:
            return False  # No matter what we return here, it won't be used.

        orig_protocol = self._xbee.get_protocol()
        new_protocol = XBeeProtocol.determine_protocol(
            self._xml_hw_version, utils.int_to_bytes(self._xml_fw_version))
        return orig_protocol != new_protocol

    def _set_device_in_programming_mode(self):
        """
        Attempts to put the XBee into programming mode (bootloader).

        Returns:
            Boolean: `True` if the device was set into programming mode,
                `False` otherwise.
        """
        if self._xbee is None:
            return False

        if self._serial_port is not None and self._is_bootloader_active():
            return True

        _log.debug("Setting device in programming mode")
        force_reset_sent = False
        try:
            self._xbee.execute_command(ATStringCommand.PERCENT_P, apply=False)
        except XBeeException:
            # If the command failed, try with 'FR' command
            try:
                self._xbee.execute_command(ATStringCommand.FR, apply=False)
                force_reset_sent = True
            except XBeeException:
                # We can ignore this error as at last instance we will attempt
                # a Break method.
                pass

        self._serial_port = self._xbee.serial_port
        self._port_params = self._serial_port.get_settings()
        try:
            self._serial_port.apply_settings(self._get_bootloader_serial_params())
            if force_reset_sent:
                # If we sent a force reset command, play with the serial lines
                # so that device boots in bootloader.
                self._serial_port.rts = 0
                self._serial_port.dtr = 1
                self._serial_port.break_condition = True
                time.sleep(2)
                self._serial_port.break_condition = False
                self._serial_port.rts = 0
            self._xbee.close()
            self._serial_port.open()
        except SerialException as exc:
            _log.exception(exc)
            return False
        if not self._is_bootloader_active():
            # This will force the Break mechanism to reboot in bootloader mode
            # in case previous methods failed.
            return self._enter_bootloader_mode_with_break()

        return True

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__DEVICE_RESET_TIMEOUT

    @abstractmethod
    def _get_bootloader_serial_params(self):
        """
        Returns a dictionary with the serial port parameters required to
        communicate with the bootloader.

        Returns:
            Dictionary: Dictionary with the serial port parameters required to
                communicate with the bootloader.
        """

    @abstractmethod
    def _is_bootloader_active(self):
        """
        Returns whether the device is in bootloader mode or not.

        Returns:
            Boolean: `True` if the device is in bootloader mode, `False` otherwise.
        """

    @abstractmethod
    def _get_target_bootloader_version_bootloader(self):
        """
        Returns the update target bootloader version from bootloader.

        Returns:
            Bytearray: Update target bootloader version as byte array read from
                bootloader, `None` if it could not be read.
        """

    @abstractmethod
    def _get_target_compatibility_number_bootloader(self):
        """
        Returns the update target compatibility number from bootloader.

        Returns:
            Integer: Update target compatibility number as integer read from
                bootloader, `None` if it could not be read.
        """

    @abstractmethod
    def _get_target_region_lock_bootloader(self):
        """
        Returns the update target region lock number from the bootloader.

        Returns:
            :class:`.Region`: Update target region lock read from the
                bootloader, `None` if it could not be read.
        """

    @abstractmethod
    def _get_target_hw_version_bootloader(self):
        """
        Returns the update target hardware version from bootloader.

        Returns:
            Integer: Update target hardware version as integer read from
                bootloader, `None` if it could not be read.
        """

    @abstractmethod
    def _get_fw_binary_file_extension(self):
        """
        Returns the firmware binary file extension.

        Returns:
            String: Firmware binary file extension.
        """


class _RemoteFirmwareUpdater(_XBeeFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process.
    """

    def __init__(self, remote, xml_fw_file, timeout=_READ_DATA_TIMEOUT,
                 progress_cb=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteFirmwareUpdater`
        with the given parameters.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to upload.
            xml_fw_file (String): Location of the XML firmware file.
            timeout (Integer, optional): Timeout to wait for remote frame requests.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super().__init__(xml_fw_file, timeout=timeout, progress_cb=progress_cb)

        self._remote = remote
        self._local = remote.get_local_xbee_device()
        self._receive_lock = Event()
        self._old_sync_ops_timeout = None
        self._updater_was_connected = False
        self._updater_ao_val = None

    def _notify_progress(self, task_str, percent, finished=False):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._notify_progress`
        """
        super()._notify_progress(task_str, percent, finished=finished)

        update_type = self._remote._active_update_type

        xnet = self._local.get_network()
        if xnet:
            progress_cbs = xnet.get_update_progress_callbacks()
            if progress_cbs:
                progress_cbs(self._remote,
                             UpdateProgressStatus(update_type, task_str, percent, finished))

        if finished and update_type in (NodeUpdateType.FIRMWARE, NodeUpdateType.FILESYSTEM):
            self._remote._active_update_type = None

    def _get_target_bootloader_version(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_bootloader_version`
        """
        return _get_bootloader_version(self._remote)

    def _get_target_compatibility_number(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_compatibility_number`
        """
        return _get_compatibility_number(self._remote)

    def _get_target_region_lock(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_region_lock`
        """
        return _get_region_lock(self._remote)

    def _get_target_hw_version(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_hw_version`
        """
        return _get_hw_version(self._remote)

    def _get_target_fw_version(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_target_fw_version`
        """
        return _get_fw_version(self._remote)

    def _connect_local(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._connect_local`
        """
        # Change sync ops timeout.
        self._old_sync_ops_timeout = self._local.get_sync_ops_timeout()
        self._local.set_sync_ops_timeout(self._timeout)
        # Connect device.
        self._updater_was_connected = self._local.is_open()
        _log.debug("Connecting device '%s'", self._local)
        if not _connect_device_with_retries(self._local, _DEVICE_CONNECTION_RETRIES):
            self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES,
                                  restore_updater=False)

    def _configure_updater(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._configure_updater`
        """
        if self._configure_ao_parameter():
            # Store AO value.
            success, self._updater_ao_val = _enable_explicit_mode(self._local)
            if not success:
                self._exit_with_error(
                    _ERROR_UPDATER_READ_PARAM % ATStringCommand.AO.command)
        # Perform extra configuration.
        self._configure_updater_extra()

    def _restore_updater(self, raise_exception=False):
        """
        Leaves the updater device to its original state before the update operation.

        Args:
            raise_exception (Boolean, optional): `True` to raise exceptions if
                they occur, `False` otherwise.

        Raises:
            XBeeException: If there is any error restoring the device connection.
        """
        # Restore updater params.
        try:
            if not self._local.is_open():
                self._local.open()
            # Restore AO.
            if self._configure_ao_parameter() and self._updater_ao_val is not None:
                _set_parameter_with_retries(self._local, ATStringCommand.AO,
                                            self._updater_ao_val, apply=True)
            # Restore extra configuration.
            self._restore_updater_extra()
        except XBeeException as exc:
            if raise_exception:
                raise exc

    def _restore_local_connection(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._restore_local_connection`
        """
        # Restore sync ops timeout.
        if self._old_sync_ops_timeout is not None:
            self._local.set_sync_ops_timeout(self._old_sync_ops_timeout)
        if self._updater_was_connected and not self._local.is_open():
            self._local.open()
        elif not self._updater_was_connected and self._local.is_open():
            self._local.close()

    def _check_updater_compatibility(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_updater_compatibility`
        """
        if self._local.get_hardware_version().code not in REMOTE_SUPPORTED_HW_VERSIONS:
            self._exit_with_error(_ERROR_HW_VERSION_NOT_SUPPORTED % self._target_hw_version,
                                  restore_updater=False)

    def _update_target_information(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._update_target_information`
        """
        _log.debug("Updating target information...")
        # If the protocol of the device has changed, just skip this step and
        # remove device from the network, it is no longer reachable.
        if self._protocol_changed:
            self._local.get_network()._remove_device(
                self._remote, NetworkEventReason.FIRMWARE_UPDATE)
            return

        was_open = self._local.is_open()
        try:
            # Change sync options timeout. Remote device might be an end device,
            # so use the firmware update timeout instead of the default one for
            # this operation.
            self._old_sync_ops_timeout = self._local.get_sync_ops_timeout()
            self._local.set_sync_ops_timeout(self._timeout)
            if not was_open:
                self._local.open()
            # We need to update target information. Give it some time to be
            # back into the network.
            deadline = _get_milliseconds() + 3 * self._timeout * 1000
            initialized = False
            while _get_milliseconds() < deadline and not initialized:
                try:
                    self._remote._read_device_info(NetworkEventReason.FIRMWARE_UPDATE,
                                                   init=True, fire_event=True)
                    initialized = True
                except XBeeException as exc:
                    _log.warning("Could not initialize remote device: %s", str(exc))
                    time.sleep(1)
            if not initialized:
                self._exit_with_error(_ERROR_UPDATE_TARGET_TIMEOUT, restore_updater=False)
        except XBeeException as exc:
            msg = _ERROR_UPDATE_TARGET_INFO % str(exc)
            _log.error(msg)
            raise FirmwareUpdateException(msg) from None
        finally:
            if self._old_sync_ops_timeout is not None:
                self._local.set_sync_ops_timeout(self._old_sync_ops_timeout)
            if not was_open:
                self._local.close()

    def _will_protocol_change(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._will_protocol_change`
        """
        orig_protocol = self._remote.get_protocol()
        new_protocol = XBeeProtocol.determine_protocol(
            self._xml_hw_version, utils.int_to_bytes(self._xml_fw_version))
        return orig_protocol != new_protocol

    @abstractmethod
    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during
        updater configuration.

        Returns:
            Boolean: `True` if AO parameter should be configured,
                `False` otherwise.
        """

    @abstractmethod
    def _configure_updater_extra(self):
        """
        Performs extra updater device configuration before the firmware
        update operation.

        Raises:
            FirmwareUpdateException: If there is any error configuring the
                updater device.
        """

    @abstractmethod
    def _restore_updater_extra(self):
        """
        Performs extra updater configuration to leave it in its original state
        as it was before the update operation.

        Raises:
            XBeeException: If there is any error restoring the device connection.
        """


class _LocalXBee3FirmwareUpdater(_LocalFirmwareUpdater):
    """
    Helper class used to handle the local firmware update process of XBee 3 devices.
    """

    def __init__(self, target, xml_fw_file, xbee_fw_file=None, bootloader_fw_file=None,
                 timeout=_READ_DATA_TIMEOUT, progress_cb=None):
        """
        Class constructor. Instantiates a new
        :class:`._LocalXBee3FirmwareUpdater` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): Target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: XBee to upload its firmware.
            xml_fw_file (String): Location of the XML firmware file.
            xbee_fw_file (String, optional): Location of the XBee binary firmware file.
            bootloader_fw_file (String, optional): Location of the bootloader binary firmware file.
            timeout (Integer, optional): Serial port read data operation timeout.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super().__init__(target, xml_fw_file, xbee_fw_file=xbee_fw_file,
                         timeout=timeout, progress_cb=progress_cb)

        self._bootloader_fw_file = bootloader_fw_file

    def _is_bootloader_active(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._is_bootloader_active`
        """
        return _is_bootloader_active_generic(
            self._serial_port, _GECKO_BOOTLOADER_TEST_CHAR, _GECKO_BOOTLOADER_PROMPT)

    def _read_bootloader_header(self):
        """
        Attempts to read the bootloader header.

        Returns:
            String: the bootloader header, `None` if it could not be read.
        """
        return _read_bootloader_header_generic(self._serial_port,
                                               _GECKO_BOOTLOADER_TEST_CHAR)

    def _get_bootloader_serial_params(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_bootloader_serial_params`
        """
        return _GECKO_BOOTLOADER_PORT_PARAMS

    def _get_target_bootloader_version_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_bootloader_version_bootloader`
        """
        bootloader_header = self._read_bootloader_header()
        if bootloader_header is None:
            return None
        res = re.match(_PATTERN_GECKO_BOOTLOADER_VERSION,
                       bootloader_header, flags=re.M | re.DOTALL)
        if res is None or res.string is not res.group(0) or len(res.groups()) < 1:
            return None

        return _bootloader_version_to_bytearray(res.groups()[0])

    def _get_target_compatibility_number_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_compatibility_number_bootloader`
        """
        # Assume the device is already in bootloader mode.
        bootloader_header = self._read_bootloader_header()
        if bootloader_header is None:
            return None
        res = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL,
                       bootloader_header, flags=re.M | re.DOTALL)
        if res is None or res.string is not res.group(0) or len(res.groups()) < 2:
            return None

        return int(res.groups()[1])

    def _get_target_region_lock_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_region_lock_bootloader`
        """
        # There is no way to retrieve this number from bootloader.
        return None

    def _get_target_hw_version_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_hw_version_bootloader`
        """
        # Assume the device is already in bootloader mode.
        bootloader_header = self._read_bootloader_header()
        if bootloader_header is None:
            return None
        res = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL,
                       bootloader_header, flags=re.M | re.DOTALL)
        if res is None or res.string is not res.group(0) or len(res.groups()) < 1:
            return None

        return int(res.groups()[0][:2], 16)

    def _get_fw_binary_file_extension(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_fw_binary_file_extension`
        """
        return EXTENSION_GBL

    def _check_bootloader_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_bootloader_binary_file`
        """
        # If not already specified, the bootloader firmware file is usually in
        # the same folder as the XML firmware file.
        # The file filename starts with a fixed prefix and includes the
        # bootloader version to update to.
        if self._bootloader_fw_file is None:
            path = Path(self._xml_fw_file)
            self._bootloader_fw_file = str(Path(path.parent).joinpath(
                _XBEE3_BOOTLOADER_FILE_PREFIX[self._target_hw_version]
                + str(self._xml_bootloader_version[0])
                + _BOOTLOADER_VERSION_SEPARATOR + str(self._xml_bootloader_version[1])
                + _BOOTLOADER_VERSION_SEPARATOR + str(self._xml_bootloader_version[2])
                + EXTENSION_GBL))

        if not _file_exists(self._bootloader_fw_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("booloader firmware", self._bootloader_fw_file),
                                  restore_updater=False)

    def _transfer_firmware(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._transfer_firmware`
        """
        # Update the bootloader using XModem protocol if required.
        if self._bootloader_update_required:
            _log.info("%s - %s", self._xbee if self._xbee is not None else self._port,
                      _PROGRESS_TASK_UPDATE_BOOTLOADER)
            self._progress_task = _PROGRESS_TASK_UPDATE_BOOTLOADER
            try:
                self._transfer_firmware_file_xmodem(self._bootloader_fw_file)
            except FirmwareUpdateException as exc:
                self._exit_with_error(_ERROR_FW_UPDATE_BOOTLOADER % str(exc))
            # Wait some time to initialize the bootloader.
            _log.debug("Setting up bootloader...")
            time.sleep(_GECKO_BOOTLOADER_INIT_TIME)
            # Execute the run operation so that new bootloader is applied and
            # executed. Give it some time afterwards.
            self._run_fw_operation()
            time.sleep(_GECKO_BOOTLOADER_INIT_TIME)
            self._bootloader_updated = True

        # Update the XBee firmware using XModem protocol.
        _log.info("%s - %s", self._xbee if self._xbee is not None else self._port,
                  _PROGRESS_TASK_UPDATE_XBEE)
        self._progress_task = _PROGRESS_TASK_UPDATE_XBEE
        try:
            self._transfer_firmware_file_xmodem(self._fw_file)
        except FirmwareUpdateException as exc:
            self._exit_with_error(_ERROR_FW_UPDATE_XBEE % str(exc))

    def _finish_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._finish_firmware_update`
        """
        # Start firmware.
        if not self._run_fw_operation():
            self._exit_with_error(_ERROR_FW_START)

    def _start_firmware_upload_operation(self):
        """
        Starts the firmware upload operation by selecting option '1' of the
        bootloader.

        Returns:
            Boolean: `True` if the upload process started successfully,
                `False` otherwise.
        """
        try:
            # Display bootloader menu and consume it.
            self._serial_port.write(str.encode(_GECKO_BOOTLOADER_TEST_CHAR, encoding='utf8'))
            time.sleep(1)
            self._serial_port.purge_port()
            # Write '1' to execute bootloader option '1': Upload gbl and consume answer.
            self._serial_port.write(
                str.encode(_GECKO_BOOTLOADER_OPTION_UPLOAD_GBL, encoding='utf8'))
            time.sleep(0.5)
            self._serial_port.purge_port()
            # Look for the 'C' character during some time, it indicates device
            # is ready to receive firmware pages.
            self._serial_port.set_read_timeout(0.5)
            deadline = _get_milliseconds() + (_XMODEM_START_TIMEOUT * 1000)
            while _get_milliseconds() < deadline:
                read_bytes = self._serial_port.read(1)
                if len(read_bytes) > 0 and read_bytes[0] == ord(_XMODEM_READY_TO_RECEIVE_CHAR):
                    return True
                time.sleep(0.1)
            return False
        except SerialException as exc:
            _log.exception(exc)
            return False

    def _run_fw_operation(self):
        """
        Runs the firmware by selecting option '2' of the bootloader.

        If XBee firmware is flashed, it will boot. If no firmware is flashed,
        the bootloader will be reset.

        Returns:
            Boolean: `True` if the run firmware operation was executed,
                `False` otherwise
        """
        try:
            _log.debug("Sending bootloader run operation...")
            # Display bootloader menu and consume it.
            self._serial_port.write(str.encode(_GECKO_BOOTLOADER_TEST_CHAR, encoding='utf8'))
            time.sleep(1)
            self._serial_port.purge_port()
            # Write '2' to execute bootloader option '2': Run.
            self._serial_port.write(str.encode(_GECKO_BOOTLOADER_OPTION_RUN_FW, encoding='utf8'))

            # Look for the '2' character during some time, it indicates firmware was executed.
            read_bytes = self._serial_port.read(1)
            while (len(read_bytes) > 0
                   and not read_bytes[0] == ord(_GECKO_BOOTLOADER_OPTION_RUN_FW)):
                read_bytes = self._serial_port.read(1)
            return True
        except SerialException as exc:
            _log.exception(exc)
            return False

    def _xmodem_write_cb(self, data):
        """
        Callback function used to write data to the serial port when requested
        from the XModem transfer.

        Args:
            data (Bytearray): Data to write to serial port from the XModem transfer.

        Returns:
            Boolean: `True` if the data was successfully written, `False` otherwise.
        """
        try:
            self._serial_port.purge_port()
            self._serial_port.write(data)
        except SerialException as exc:
            _log.exception(exc)
            return False

        return True

    def _xmodem_read_cb(self, size, timeout=None):
        """
        Callback function used to read data from the serial port when requested
        from the XModem transfer.

        Args:
            size (Integer): Size of the data to read.
            timeout (Integer, optional): Maximum time to wait to read the
                requested data (seconds).

        Returns:
            Bytearray: Read data, `None` if data could not be read.
        """
        if not timeout:
            timeout = self._timeout
        deadline = _get_milliseconds() + (timeout * 1000)
        data = bytearray()
        try:
            while len(data) < size and _get_milliseconds() < deadline:
                read_bytes = self._serial_port.read(size - len(data))
                if len(read_bytes) > 0:
                    data.extend(read_bytes)
            return data
        except SerialException as exc:
            _log.exception(exc)

        return None

    def _xmodem_progress_cb(self, percent):
        """
        Callback function used to be notified about XModem transfer progress.

        Args:
            percent (Integer): XModem transfer percentage.
        """
        self._notify_progress(self._progress_task, percent)

    def _transfer_firmware_file_xmodem(self, fw_file_path):
        """
        Transfers the firmware to the device using XModem protocol.

        Args:
            fw_file_path (String): Path of the firmware file to transfer.

        Returns:
            Boolean: `True` if the firmware was transferred successfully,
                `False` otherwise

        Raises:
            FirmwareUpdateException: If there is any error transferring the
                firmware file.
        """
        # Start XModem communication.
        if not self._start_firmware_upload_operation():
            raise FirmwareUpdateException(_ERROR_XMODEM_START)

        # Transfer file.
        try:
            xmodem.send_file_xmodem(fw_file_path, self._xmodem_write_cb,
                                    self._xmodem_read_cb,
                                    progress_cb=self._xmodem_progress_cb, log=_log)
        except XModemCancelException:
            # Retry at least once after resetting device.
            _log.info("File transfer was cancelled by the remote end, retrying...")
            if (not self._run_fw_operation()
                    and not (self._is_bootloader_active()
                             or self._enter_bootloader_mode_with_break())):
                raise FirmwareUpdateException(_ERROR_XMODEM_RESTART) from None
            try:
                self._serial_port.purge_port()
            except SerialException as exc:
                raise FirmwareUpdateException(_ERROR_XMODEM_COMMUNICATION % str(exc)) from None
            self._start_firmware_upload_operation()
            try:
                xmodem.send_file_xmodem(fw_file_path, self._xmodem_write_cb,
                                        self._xmodem_read_cb,
                                        progress_cb=self._xmodem_progress_cb, log=_log)
            except XModemException:
                raise
        except XModemException as exc:
            raise FirmwareUpdateException(str(exc)) from exc


class _LocalXBeeGEN3FirmwareUpdater(_LocalFirmwareUpdater):
    """
    Helper class used to handle the local firmware update process of GEN3 XBee
    devices.
    """

    def __init__(self, target, xml_fw_file, xbee_fw_file=None,
                 timeout=_READ_DATA_TIMEOUT, progress_cb=None):
        """
        Class constructor. Instantiates a new
        :class:`._LocalXBeeGEN3FirmwareUpdater` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): Target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: XBee to upload its firmware.
            xml_fw_file (String): Location of the XML firmware file.
            xbee_fw_file (String, optional): Location of the XBee binary firmware file.
            timeout (Integer, optional): Serial port read data operation timeout.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        super().__init__(target, xml_fw_file, xbee_fw_file=xbee_fw_file,
                         timeout=timeout, progress_cb=progress_cb)

        self._protocol_version = None

    def _is_bootloader_active(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._is_bootloader_active`
        """
        return _is_bootloader_active_generic(
            self._serial_port, _GEN3_BOOTLOADER_TEST_CHAR, _GEN3_BOOTLOADER_PROMPT)

    def _read_bootloader_header(self):
        """
        Attempts to read the bootloader header.

        Returns:
            String: Bootloader header, `None` if it could not be read.
        """
        return _read_bootloader_header_generic(self._serial_port, _GEN3_BOOTLOADER_TEST_CHAR)

    def _get_bootloader_serial_params(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_bootloader_serial_params`
        """
        return _GEN3_BOOTLOADER_PORT_PARAMS

    def _get_fw_binary_file_extension(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_fw_binary_file_extension`
        """
        return EXTENSION_EBIN

    def _check_bootloader_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_bootloader_binary_file`
        """
        # SX XBee family does not support bootloader update.

    def _execute_bootloader_cmd(self, cmd):
        """
        Attempts to execute the given bootloader command and read a number of bytes.

        Args:
            cmd (:class:`._Gen3BootloaderCommand`:): Bootloader command to execute.

        Returns:
            Bytearray: Bootloader command execution answer, `None` if it could
                not be read.
        """
        deadline = _get_milliseconds() + cmd.timeout
        data = bytearray()
        try:
            self._serial_port.purge_port()
            self._serial_port.write(str.encode(cmd.command, encoding='utf8'))
            while len(data) < cmd.answer_length and _get_milliseconds() < deadline:
                read_bytes = self._serial_port.read(cmd.answer_length - len(data))
                if len(read_bytes) > 0:
                    data.extend(read_bytes)
            return data
        except SerialException as exc:
            _log.exception(exc)
            return None

    def _get_target_bootloader_version_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_bootloader_version_bootloader`
        """
        # GEN3 bootloader does not support retrieving its version.
        version = self._execute_bootloader_cmd(_Gen3BootloaderCmd.BOOTLOADER_VERSION)
        if not version:
            return None
        version_byte_array = bytearray()
        for byte in version:
            try:
                if _GEN3_BOOTLOADER_PROMPT == \
                        bytes([byte]).decode(encoding='utf8', errors='ignore'):
                    break
                version_byte_array.append(byte)
            except TypeError:
                pass
        return version_byte_array

    def _get_target_compatibility_number_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_compatibility_number_bootloader`
        """
        # Assume the device is already in bootloader mode.
        version_information = self._execute_bootloader_cmd(_Gen3BootloaderCmd.HW_VERSION)
        if not version_information or len(version_information) < 5:
            return 0

        return version_information[4]

    def _get_target_region_lock_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_region_lock_bootloader`
        """
        # Assume the device is already in bootloader mode.
        region_info = self._execute_bootloader_cmd(_Gen3BootloaderCmd.REGION_LOCK)
        if not region_info:
            return Region.ALL

        return Region.get(region_info[0])

    def _get_target_hw_version_bootloader(self):
        """
        Override.

        .. seealso::
           | :meth:`._LocalFirmwareUpdater._get_target_hw_version_bootloader`
        """
        # Assume the device is already in bootloader mode.
        version_info = self._execute_bootloader_cmd(_Gen3BootloaderCmd.HW_VERSION)
        if not version_info or len(version_info) < 2:
            return None

        return version_info[1]

    def _get_bootloader_protocol_version(self):
        """
        Returns the bootloader protocol version.

        Returns:
            Integer: Bootloader protocol version.
        """
        # Assume the device is already in bootloader mode.
        answer = self._execute_bootloader_cmd(_Gen3BootloaderCmd.PROTOCOL_VERSION)
        if not answer:
            return _GEN3_BOOTLOADER_PROTOCOL_VERSION_0
        try:
            answer_str = answer.decode(encoding='utf8', errors='ignore')
            if _GEN3_BOOTLOADER_PROMPT in answer_str:
                return _GEN3_BOOTLOADER_PROTOCOL_VERSION_0
            return int(answer_str)
        except (TypeError, ValueError):
            return _GEN3_BOOTLOADER_PROTOCOL_VERSION_0

    def _send_change_baudrate_cmd(self):
        """
        Sends the "R" command to attempt a baudrate change of the serial port
        in order to improve the firmware transfer speed.
        """
        answer = self._execute_bootloader_cmd(_Gen3BootloaderCmd.CHANGE_BAUDRATE)
        if not answer:
            return
        try:
            # Change baudrate only if a new value was given and it is different
            # from the current one.
            answer_str = str(answer, encoding='utf8', errors='ignore')
            if _GEN3_BOOTLOADER_PROMPT in answer_str:
                return
            new_baudrate = int(answer_str)
            if new_baudrate != _GEN3_BOOTLOADER_PORT_PARAMS["baudrate"]:
                self._serial_port.set_baudrate(new_baudrate)
                _log.debug("Changed port baudrate to %s", new_baudrate)
        except (TypeError, ValueError):
            # Do nothing, device did not change its baudrate if an invalid value is read.
            pass

    def _send_initialize_cmd(self):
        """
        Initializes the firmware update operation by sending the command "I"
        to erase the current firmware.

        Raises:
            FirmwareUpdateException: If the initialization command could not
                be sent.
        """
        _log.debug("Sending Initialize command...")
        answer = self._execute_bootloader_cmd(_Gen3BootloaderCmd.INIT_UPDATE)
        if not answer:
            raise FirmwareUpdateException(_ERROR_INITIALIZE_PROCESS)
        try:
            answer_str = str(answer, encoding='utf8', errors='ignore')
            if _GEN3_BOOTLOADER_PROMPT not in answer_str:
                raise FirmwareUpdateException(_ERROR_INITIALIZE_PROCESS)
        except TypeError:
            raise FirmwareUpdateException(_ERROR_INITIALIZE_PROCESS) from None

    def _send_finish_cmd(self):
        """
        Finishes the firmware update operation by sending the command "F".

        Raises:
            FirmwareUpdateException: If the finish command could not be sent.
        """
        _log.debug("Sending finish command...")
        answer = self._execute_bootloader_cmd(_Gen3BootloaderCmd.FINISH_UPDATE)
        if not answer:
            raise FirmwareUpdateException(_ERROR_FINISH_PROCESS)
        try:
            answer_str = str(answer, encoding='utf8', errors='ignore')
            if _GEN3_BOOTLOADER_PROMPT not in answer_str:
                raise FirmwareUpdateException(_ERROR_FINISH_PROCESS)
        except TypeError:
            raise FirmwareUpdateException(_ERROR_FINISH_PROCESS) from None

    def _send_verify_cmd(self):
        """
        Verifies the firmware image sent by sending the command "C".

        Raises:
            FirmwareUpdateException: If the verify command fails.
        """
        _log.debug("Sending verify command...")
        answer = self._execute_bootloader_cmd(_Gen3BootloaderCmd.VERIFY)
        if not answer:
            raise FirmwareUpdateException(_ERROR_COMMUNICATION_LOST)
        if answer[0] != _GEN3_BOOTLOADER_TRANSFER_ACK:
            raise FirmwareUpdateException(_ERROR_IMAGE_VERIFICATION)

    def _transfer_firmware(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._transfer_firmware`
        """
        self._protocol_version = self._get_bootloader_protocol_version()
        _log.debug("Bootloader protocol version: %s", self._protocol_version)

        self._send_change_baudrate_cmd()
        try:
            self._send_initialize_cmd()
        except FirmwareUpdateException as exc:
            self._exit_with_error(str(exc))
        _log.info("%s - %s",
                  self._xbee if self._xbee is not None else self._port,
                  _PROGRESS_TASK_UPDATE_XBEE)
        self._progress_task = _PROGRESS_TASK_UPDATE_XBEE
        # Perform file transfer.
        ebin_file = _EbinFile(self._fw_file, self._xml_flash_page_size)
        previous_percent = None
        for page in ebin_file.get_next_mem_page():
            if ebin_file.percent != previous_percent:
                self._notify_progress(self._progress_task, ebin_file.percent)
                previous_percent = ebin_file.percent
            try:
                self._send_memory_page(page, ebin_file)
            except FirmwareUpdateException as exc:
                self._exit_with_error(str(exc))

    def _send_memory_page(self, page, ebin_file):
        """
        Sends the given memory page to the target device.

        Args:
            page (Bytearray): Memory page to send.
            ebin_file (:class:`._EbinFile`): Ebin file being transferred.

        Raises:
            FirmwareUpdateException: If there is any error sending the memory page.
        """
        page_flashed = False
        checksum_retries = _GEN3_BOOTLOADER_FLASH_CHECKSUM_RETRIES
        verify_retries = _GEN3_BOOTLOADER_FLASH_VERIFY_RETRIES
        retry = 1
        while not page_flashed and checksum_retries > 0 and verify_retries > 0:
            _log.debug("Sending page %d/%d %d%% - retry %d",
                       ebin_file.page_index + 1, ebin_file.num_pages,
                       ebin_file.percent, retry)
            try:
                # Send program page command.
                self._serial_port.write(
                    str.encode(_Gen3BootloaderCmd.PROGRAM_PAGE.command, encoding='utf8'))
                # Write page index. This depends on the protocol version.
                if self._protocol_version == _GEN3_BOOTLOADER_PROTOCOL_VERSION_0:
                    # Truncate to one byte.
                    self._serial_port.write(bytes([ebin_file.page_index & 0xFF]))
                else:
                    # Truncate to two bytes.
                    page_index = ebin_file.page_index & 0xFFFF
                    page_index_bytes = utils.int_to_bytes(page_index, num_bytes=2)
                    # Swap the array order.
                    page_index_bytes = bytearray(reversed(page_index_bytes))
                    self._serial_port.write(page_index_bytes)
                # Write the page data.
                self._serial_port.write(page)
                # Write the page verification. This depends on the protocol version.
                self._serial_port.write(self._calculate_page_verification(page))
                # Read the programming answer.
                deadline = _get_milliseconds() + 500
                answer = None
                while not answer and _get_milliseconds() < deadline:
                    answer = self._serial_port.read(1)
                if not answer:
                    raise FirmwareUpdateException(_ERROR_COMMUNICATION_LOST)
                if answer == _GEN3_BOOTLOADER_ERROR_CHECKSUM:
                    checksum_retries -= 1
                    retry += 1
                    if checksum_retries == 0:
                        raise FirmwareUpdateException(
                            _ERROR_PAGE_CHECKSUM % ebin_file.page_index)
                elif answer == _GEN3_BOOTLOADER_ERROR_VERIFY:
                    verify_retries -= 1
                    retry += 1
                    if verify_retries == 0:
                        raise FirmwareUpdateException(
                            _ERROR_PAGE_VERIFICATION % ebin_file.page_index)
                else:
                    page_flashed = True
            except SerialException as exc:
                raise FirmwareUpdateException(_ERROR_SERIAL_COMMUNICATION % str(exc)) from exc

    def _calculate_page_verification(self, page):
        """
        Calculates and returns the verification sequence for the given memory page.

        Args:
            page (Bytearray): Memory page to calculate its verification sequence.

        Returns
            Bytearray: Calculated verification sequence for the given memory page.
        """
        if self._protocol_version == _GEN3_BOOTLOADER_PROTOCOL_VERSION_0:
            value = 0x00
            for byte in page:
                value += byte
            value = value & 0xFF
            return bytearray([((~value & 0xFF) - len(page)) & 0xFF])

        crc = 0x0000
        for i in range(0, len(page)):
            crc ^= page[i] << 8
            for _ in range(0, 8):
                if (crc & 0x8000) > 0:
                    crc = (crc << 1) ^ _POLYNOMINAL_DIGI_BL
                else:
                    crc = crc << 1
                crc &= 0xFFFF
        return (crc & 0xFFFF).to_bytes(2, byteorder='little')

    def _finish_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._finish_firmware_update`
        """
        try:
            self._send_finish_cmd()
            self._send_verify_cmd()
        except FirmwareUpdateException as exc:
            self._exit_with_error(str(exc))


class _RemoteXBee3FirmwareUpdater(_RemoteFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process on XBee 3
    devices.
    """

    __DEVICE_RESET_TIMEOUT_ZB = 3  # seconds
    __DEVICE_RESET_TIMEOUT_DM = 20  # seconds
    __DEVICE_RESET_TIMEOUT_802 = 28  # seconds

    __REC_TRANSMIT_STATUS_RETRIES = 5

    def __init__(self, remote, xml_fw_file, ota_fw_file=None, otb_fw_file=None,
                 timeout=_READ_DATA_TIMEOUT, max_block_size=0, progress_cb=None):
        """
        Class constructor. Instantiates a new
        :class:`._RemoteXBee3FirmwareUpdater` with the given parameters.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to upload its firmware.
            xml_fw_file (String): Path of the XML file that describes the firmware.
            ota_fw_file (String, optional): Path of the OTA firmware file to upload.
            otb_fw_file (String, optional): Path of the OTB firmware file to
                upload (bootloader bundle).
            timeout (Integer, optional): Timeout to wait for remote frame requests.
            max_block_size (Integer, optional): Maximum size in bytes of the
                ota block to send.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: If there is any error performing the
                remote firmware update.
        """
        super().__init__(remote, xml_fw_file, timeout=timeout, progress_cb=progress_cb)

        self._ota_fw_file = ota_fw_file
        self._otb_fw_file = otb_fw_file
        self._updater_my_val = None
        self._updater_rr_val = None
        self._updater_ar_val = None
        self._ota_file = None
        self._remote_fw_desc = None
        self._transfer_lock = Event()
        self._img_req_received = False
        self._img_notify_sent = False
        self._transfer_status = None
        self._response_str = None
        self._requested_offset = -1
        self._max_chunk_size = max_block_size
        if not self._max_chunk_size:
            self._max_chunk_size = _OTA_DEFAULT_BLOCK_SIZE
        self._seq_number = 1
        self._cfg_max_block_size = max_block_size
        self._update_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        if not self._cfg_max_block_size:
            self._cfg_max_block_size = 0xFFFFFFFF

    def _check_fw_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_fw_binary_file`
        """
        # If not already specified, the binary firmware file is usually in the
        # same folder as the XML firmware file.
        if self._ota_fw_file is None:
            path = Path(self._xml_fw_file)
            self._ota_fw_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_OTA))

        if not _file_exists(self._ota_fw_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("XBee firmware", self._ota_fw_file),
                                  restore_updater=False)

        self._ota_file = _OTAFile(self._ota_fw_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as exc:
            self._exit_with_error(str(exc), restore_updater=False)

    def _check_bootloader_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_bootloader_binary_file`
        """
        if self._otb_fw_file is None:
            path = Path(self._xml_fw_file)
            self._otb_fw_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_OTB))

        if not _file_exists(self._otb_fw_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("XBee firmware", self._otb_fw_file),
                                  restore_updater=False)

        # If asked to check the bootloader file, replace the OTA file with the
        # .otb one.
        # Unlike local firmware updates, remote firmware updates only transfer
        # one file for fw + bootloader.
        self._ota_file = _OTAFile(self._otb_fw_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as exc:
            self._exit_with_error(str(exc), restore_updater=False)

    def _configure_ao_parameter(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._configure_ao_parameter`
        """
        return True

    def _configure_updater_extra(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._configure_updater_extra`
        """
        self._remote_fw_desc = _XBee3OTAClientDescription(self._target_fw_version)

        if not self._remote_fw_desc.support_different_ota_block_size():
            self._max_chunk_size = _OTA_DEFAULT_BLOCK_SIZE

        # Specific settings per protocol.
        if self._local.get_protocol() == XBeeProtocol.ZIGBEE:
            enc_value = _get_parameter_with_retries(self._local, ATStringCommand.EE)
            if enc_value and utils.bytes_to_int(enc_value) == 1:
                # Set maximum chunk size to encrypted Zigbee network max chuck
                # size without fragmentation
                # Workaround for client (remote) fw version 1008 and prior, see
                # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
                self._max_chunk_size = min(_OTA_DEFAULT_BLOCK_SIZE_ENC, self._max_chunk_size)

            # Disable many-to-one on the local XBee.
            # Workaround for client (remote) fw version 1007 and prior, see
            # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
            if not self._remote_fw_desc.support_ota_fragmentation():
                # Store AR value.
                ar_val = _get_parameter_with_retries(self._local, ATStringCommand.AR)
                if ar_val and utils.bytes_to_int(ar_val) != 0xFF:
                    self._updater_ar_val = ar_val
                    _set_parameter_with_retries(self._local, ATStringCommand.AR,
                                                bytearray([0xFF]), apply=True)

            # Delayed ACK for some packets.
            # Workaround for client (remote) fw version 1009 and prior, see
            # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
            sp_val = 1000  # minimum value in milliseconds
            if self._remote.get_role() in (Role.END_DEVICE, Role.UNKNOWN):
                sp_val = _get_parameter_with_retries(self._local, ATStringCommand.SP)
                # Value of SP in seconds
                sp_val = utils.bytes_to_int(sp_val) / 100 if sp_val else 28  # 28=Max SP value

            nh_val = _get_parameter_with_retries(self._local, ATStringCommand.NH)
            # Value of NH
            nh_val = utils.bytes_to_int(nh_val) if nh_val else 255  # 255=Max NH value
            self._remote_fw_desc.extended_timeout = 3 * (50 * nh_val + 1.2 * sp_val) / 1000
        elif self._local.get_protocol() == XBeeProtocol.DIGI_MESH:
            # Store RR value.
            self._updater_rr_val = _get_parameter_with_retries(
                self._local, ATStringCommand.RR)
            if self._updater_rr_val is None:
                self._exit_with_error(
                    _ERROR_UPDATER_READ_PARAM % ATStringCommand.RR.command)
            # Set new RR value.
            if not _set_parameter_with_retries(
                    self._local, ATStringCommand.RR,
                    bytearray([_VALUE_UNICAST_RETRIES_MEDIUM]), apply=True):
                self._exit_with_error(
                    _ERROR_UPDATER_SET_PARAM % ATStringCommand.RR.command)
        elif self._local.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # Store MY value.
            self._updater_my_val = _get_parameter_with_retries(
                self._local, ATStringCommand.MY)
            if self._updater_my_val is None:
                self._exit_with_error(
                    _ERROR_UPDATER_READ_PARAM % ATStringCommand.MY.command)
            # Set new MY value.
            if not _set_parameter_with_retries(
                    self._local, ATStringCommand.MY,
                    XBee16BitAddress.BROADCAST_ADDRESS.address, apply=True):
                self._exit_with_error(
                    _ERROR_UPDATER_SET_PARAM % ATStringCommand.MY.command)

    def _restore_updater_extra(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._restore_updater_extra`
        """
        # Close OTA file.
        if self._ota_file:
            self._ota_file.close_file()
        # Restore many-to-one on the local XBee.
        # Workaround for client (remote) fw version 1007 and prior, see
        # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
        if self._updater_ar_val and self._remote_fw_desc.support_ota_fragmentation():
            # Store AR value.
            _set_parameter_with_retries(self._local, ATStringCommand.AR,
                                        self._updater_ar_val, apply=True)
        # Specific settings per protocol.
        if self._updater_rr_val and self._local.get_protocol() == XBeeProtocol.DIGI_MESH:
            # Restore RR value.
            _set_parameter_with_retries(self._local, ATStringCommand.RR,
                                        self._updater_rr_val, apply=True)
        elif self._updater_my_val and self._local.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # Restore MY value.
            _set_parameter_with_retries(self._local, ATStringCommand.MY,
                                        self._updater_my_val, apply=True)

    def _create_explicit_frame(self, payload):
        """
        Creates and returns an explicit addressing frame using the given payload.

        Args:
            payload (Bytearray): Payload for the explicit addressing frame.

        Returns:
            :class:`.ExplicitAddressingPacket`: Explicit addressing frame with
                the given payload.
        """
        return ExplicitAddressingPacket(
            self._local.get_next_frame_id(), self._remote.get_64bit_addr(),
            self._remote.get_16bit_addr(), _EXPL_PACKET_ENDPOINT_DATA,
            _EXPL_PACKET_ENDPOINT_DATA, _EXPL_PACKET_CLUSTER_ID,
            _EXPL_PACKET_PROFILE_DIGI, broadcast_radius=_EXPL_PACKET_BROADCAST_RADIUS_MAX,
            transmit_options=_EXPL_PACKET_EXTENDED_TIMEOUT if self._local.get_protocol() == XBeeProtocol.ZIGBEE else 0x00,
            rf_data=payload)

    def _create_zcl_frame(self, frame_control, seq_number, cmd_id, payload):
        """
        Creates and returns a ZCL frame with the given parameters.

        Args:
            frame_control (Integer): ZCL object frame control.
            seq_number (Integer): ZCL object sequence number.
            cmd_id (Integer): ZCL object command ID.
            payload (Bytearray): Payload for the ZDO object.

        Returns:
            Bytearray: ZCL frame.
        """
        zcl_payload = bytearray()
        zcl_payload.append(frame_control & 0xFF)
        zcl_payload.append(seq_number & 0xFF)
        zcl_payload.append(cmd_id & 0xFF)
        zcl_payload.extend(payload)

        return self._create_explicit_frame(zcl_payload)

    @staticmethod
    def _calculate_frame_control(frame_type=1, manufac_specific=False,
                                 dir_srv_to_cli=True, disable_def_resp=True):
        """
        Calculates the value of the frame control field based on the provided
        parameters.

        Args:
            frame_type (Integer, optional, default=1): 1 if command is global
                for all clusters, 0 if it is specific or local to a cluster.
            manufac_specific (Boolean, optional, default=`False`): `True` if
                manufacturer code is present in the ZCL header (does not refer
                to the code in the ZCL payload). `False` otherwise.
            dir_srv_to_cli (Boolean, optional, default=`True`): `True` if the
                command is sent from the server to the client. `False` if sent
                from the client to the server.
            disable_def_resp (Boolean, optional, default=`True`): `True` to
                disable default response.

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
        #    * 00: Command is global for all clusters, including manufacturer
        #          specific clusters
        #    * 01: Command is specific or local to a cluster
        #    * Other values: Reserved
        frame_control = frame_type
        # Manufacturer specific:
        #    * False (0): manufacturer code is not present in the ZCL header
        #                 (does not refer to the ZCL payload)
        #    * True (1): manufacturer code is present in the ZCL header
        #                (does not refer to the ZCL payload)
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
            Bytearray: Image notify request frame.
        """
        payload = bytearray()
        # Indicate which fields are present: Query Jitter, Manufacturer Code,
        # Image Type, File Version
        payload.append(_NOTIFY_PACKET_PAYLOAD_TYPE & 0xFF)
        # Query jitter: 0-100. If the parameters in the received notify
        # command (manufacturer and image type) matches with the client owns
        # values, it determines whether query the server by randomly choosing a
        # number between 1 and 100 and comparing with the received query jitter:
        #   * If client number <= query jitter then it continues the process
        #   * If client number > query jitter then it discards the command and
        #     do not continue
        # For unicast (the only one we currently support) we choose the maximum
        # value 100, although the client shall always send a Query Next Image
        # request to the server on receipt of a unicast Image Notify command.
        payload.append(_NOTIFY_PACKET_DEFAULT_QUERY_JITTER & 0xFF)
        payload.extend(_reverse_bytearray(
            utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(
            utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(
            utils.int_to_bytes(self._ota_file.file_version, 4)))

        return self._create_zcl_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=False),
            _PACKET_DEFAULT_SEQ_NUMBER, _ZCL_CMD_ID_IMG_NOTIFY_REQ, payload)

    def _create_query_next_image_response_frame(self, status=_XBee3OTAStatus.SUCCESS):
        """
        Creates and returns a query next image response frame.

        Args:
            status (:class:`._XBee3OTAStatus`, optional, default=`_XBee3OTAStatus.SUCCESS`): The
                status to send. It can be: `_XBee3OTAStatus.SUCCESS`,
                `_XBee3OTAStatus.NOT_AUTHORIZED`, `_XBee3OTAStatus.NO_IMG_AVAILABLE`

        Returns:
            Bytearray: Query next image response frame.
        """
        payload = bytearray()

        # The status could be:
        #    * _XBee3OTAStatus.SUCCESS (0x00): An image is available
        #    * _XBee3OTAStatus.NOT_AUTHORIZED (0x7E): This server is not
        #      authorized to perform an upgrade
        #    * _XBee3OTAStatus.NO_IMG_AVAILABLE (0x98): No upgrade image is available
        payload.append(status.identifier & 0xFF)
        # Following fields only for _XBee3OTAStatus.SUCCESS
        if status == _XBee3OTAStatus.SUCCESS:
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._ota_file.image_type, 2)))
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._ota_file.file_version, 4)))
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._get_ota_size(), 4)))

        return self._create_zcl_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=True),
            self._seq_number, _ZCL_CMD_ID_QUERY_NEXT_IMG_RESP, payload)

    def _create_image_block_response_frame(self, file_offset, size, seq_number,
                                           status=_XBee3OTAStatus.SUCCESS):
        """
        Creates and returns an image block response frame.

        Args:
            file_offset (Integer): File offset to send.
            size (Integer): Number of bytes to send.
            seq_number (Integer): Sequence number to be used for the response.
            status (:class:`._XBee3OTAStatus`, optional, default=`_XBee3OTAStatus.SUCCESS`): The
                status to send. It can be: `_XBee3OTAStatus.SUCCESS`,
                `_XBee3OTAStatus.ABORT`, `_XBee3OTAStatus.WAIT_FOR_DATA`
                (this last is not supported)

        Returns:
            Bytearray: Image block response frame.

        Raises:
            FirmwareUpdateException: If there is any error generating the image
                block response frame.
        """
        try:
            data_block = self._ota_file.get_next_data_chunk(
                self._get_ota_offset(file_offset), size)
        except _ParsingOTAException as exc:
            raise FirmwareUpdateException(_ERROR_READ_OTA_FILE % str(exc)) from exc
        payload = bytearray()
        # This status could be:
        #    * _XBee3OTAStatus.SUCCESS (0x00): Image data is available
        #    * _XBee3OTAStatus.ABORT (0x95): Instructs the client to abort the
        #      download
        #    * _XBee3OTAStatus.WAIT_FOR_DATA (0x97) is not supported
        #      (see ZCL Spec §11.13.8.1)
        payload.append(status.identifier & 0xFF)
        # Following fields only if status is not _XBee3OTAStatus.ABORT
        if status != _XBee3OTAStatus.ABORT:
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._ota_file.image_type, 2)))
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(self._ota_file.file_version, 4)))
            payload.extend(_reverse_bytearray(
                utils.int_to_bytes(file_offset, 4)))
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

        return self._create_zcl_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=True),
            seq_number, _ZCL_CMD_ID_IMG_BLOCK_RESP, payload)

    def _create_upgrade_end_response_frame(self):
        """
        Creates and returns an upgrade end response frame.

        Returns:
            Bytearray: Upgrade end response frame.
        """
        current_time = utils.int_to_bytes(int(time.time()) - _TIME_SECONDS_1970_TO_2000, 4)

        payload = bytearray()
        payload.extend(_reverse_bytearray(
            utils.int_to_bytes(self._ota_file.manufacturer_code, 2)))
        payload.extend(_reverse_bytearray(
            utils.int_to_bytes(self._ota_file.image_type, 2)))
        payload.extend(_reverse_bytearray(
            utils.int_to_bytes(self._ota_file.file_version, 4)))
        # The current time, used for scheduled upgrades
        payload.extend(_reverse_bytearray(current_time))
        # The scheduled upgrade time, used for scheduled upgrades
        payload.extend(_reverse_bytearray(current_time))

        return self._create_zcl_frame(
            self._calculate_frame_control(frame_type=1, manufac_specific=False,
                                          dir_srv_to_cli=True, disable_def_resp=True),
            self._seq_number, _ZCL_CMD_ID_UPGRADE_END_RESP, payload)

    def _image_request_frame_cb(self, frame):
        """
        Callback used to be notified when the image request frame is received by
        the target device and it is ready to start receiving image frames.

        Args:
            frame (:class:`.XBeeAPIPacket`): Received packet.
        """
        f_type = frame.get_frame_type()
        if f_type == ApiFrameType.TRANSMIT_STATUS:
            _log.debug("Received 'Image notify' status frame: %s",
                       frame.transmit_status.description)
            if frame.transmit_status == TransmitStatus.SUCCESS:
                self._img_notify_sent = True
                # Sometimes the transmit status frame is received after the
                # explicit frame indicator. Notify only if the transmit status
                # frame was also received.
                if self._img_req_received:
                    # Continue execution.
                    self._receive_lock.set()
            else:
                # Remove explicit frame indicator received flag if it was set.
                if self._img_req_received:
                    self._img_req_received = False
                # Continue execution, it exits with error as received flags are not set.
                self._receive_lock.set()
        elif (f_type == ApiFrameType.EXPLICIT_RX_INDICATOR
              and frame.source_endpoint == _EXPL_PACKET_ENDPOINT_DATA
              and frame.dest_endpoint == _EXPL_PACKET_ENDPOINT_DATA
              and frame.cluster_id == _EXPL_PACKET_CLUSTER_ID
              and frame.profile_id == _EXPL_PACKET_PROFILE_DIGI
              and frame.x64bit_source_addr == self._remote.get_64bit_addr()):
            if self._img_req_received:
                return
            if self._is_next_img_req_frame(frame):
                _log.debug("Received 'Query next image' request frame")
                self._img_req_received = True
                _server_status, self._seq_number = self._parse_next_img_req_frame(frame)
            elif self._is_default_response_frame(frame, self._seq_number):
                _log.debug("Received 'Default response' frame")
                # If the received frame is a 'default response' frame, set the corresponding error.
                _ota_cmd, status = self._parse_default_response_frame(frame, self._seq_number)
                self._response_str = (status.description if status is not None
                                      else _ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR)
            else:
                # This is not the explicit frame we were expecting, keep on listening.
                return

            # Sometimes the transmit status frame is received after the
            # explicit frame indicator. Notify only if the transmit status
            # frame was also received.
            if self._img_notify_sent:
                # Continue execution.
                self._receive_lock.set()

    def _fw_receive_frame_cb(self, frame):
        """
        Callback used to be notified of image block requests and upgrade end
        request frames during the firmware transfer operation.

        Args:
            frame (:class:`.XBeeAPIPacket`): Received packet
        """
        if (frame.get_frame_type() != ApiFrameType.EXPLICIT_RX_INDICATOR
                or frame.source_endpoint != _EXPL_PACKET_ENDPOINT_DATA
                or frame.dest_endpoint != _EXPL_PACKET_ENDPOINT_DATA
                or frame.cluster_id != _EXPL_PACKET_CLUSTER_ID
                or frame.profile_id != _EXPL_PACKET_PROFILE_DIGI
                or frame.x64bit_source_addr != self._remote.get_64bit_addr()):
            return

        # Check the type of frame received.
        if self._is_image_block_request_frame(frame):
            name = "Image block request"
            # If the received frame is an 'image block request' frame,
            # retrieve the requested index.
            server_status, max_data_size, f_offset, self._seq_number = self._parse_image_block_request_frame(frame)
            if server_status == _XBee3OTAStatus.SUCCESS:
                # Check if OTA file chunk size must be updated.
                if max_data_size != self._max_chunk_size:
                    self._max_chunk_size = max_data_size
                    if self._remote_fw_desc.support_different_ota_block_size():
                        self._max_chunk_size = min(max_data_size, self._cfg_max_block_size)
                self._requested_offset = f_offset
                _log.debug("Received '%s' frame for file offset %d", name, f_offset)
            else:
                _log.debug("Received bad '%s' frame, status to send: %s (%d)", name,
                           server_status.description, server_status.identifier)
        elif self._is_upgrade_end_request_frame(frame):
            name = "Upgrade end request"
            _log.debug("Received '%s' frame", name)
            # If the received frame is an 'upgrade end request' frame, set transfer status.
            server_status, status, self._seq_number = self._parse_upgrade_end_request_frame(frame)
            if server_status == _XBee3OTAStatus.SUCCESS:
                self._transfer_status = status
            else:
                _log.debug("Received bad '%s' frame, status to send: %s (%d)", name,
                           server_status.description, server_status.identifier)
        elif self._is_default_response_frame(frame, self._seq_number):
            _log.debug("Received 'Default response' frame")
            # If the received frame is a 'default response' frame, set the corresponding error.
            _ota_cmd, status = self._parse_default_response_frame(frame, self._seq_number)
            self._response_str = (status.description if status is not None
                                  else _ERROR_DEFAULT_RESPONSE_UNKNOWN_ERROR)
        else:
            return
        # Notify transfer thread to continue.
        self._transfer_lock.set()

    def _check_img_data(self, payload):
        """
        Checks if the manufacturer code, image type, and firmware version in the
        provided payload are valid.

        Args:
            payload (Bytearray): Payload to check.

        Returns:
             :class:`_XBee3OTAStatus`: Status after parsing the values.
        """
        server_status = _XBee3OTAStatus.SUCCESS
        man_code = utils.bytes_to_int(_reverse_bytearray(payload[4:6]))
        img_type = utils.bytes_to_int(_reverse_bytearray(payload[6:8]))
        _fw_version = utils.bytes_to_int(_reverse_bytearray(payload[8:11]))
        compatibility_number = payload[11] & 0xFF

        # Check manufacturer:
        if man_code != self._ota_file.manufacturer_code:
            server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE
        # Check image type:
        #    0x0000: XBee 3 firmware upgrade
        #    0x0001: XBee 3 RR firmware upgrade
        #    0x0100: XBee 3 file system upgrade
        elif img_type != self._ota_file.image_type:
            server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE
        # Check compatibility number
        elif compatibility_number > utils.int_to_bytes(self._ota_file.file_version,
                                                       _BUFFER_SIZE_INT)[0]:
            server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE

        return server_status

    @staticmethod
    def _is_next_img_req_frame(frame):
        """
        Returns whether the given payload is valid for an image request received frame.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to check.

        Returns:
            Boolean: `True` if the frame is a next image request frame,
                `False` otherwise.
        """
        payload = frame.rf_data
        return (len(payload) > 2 and payload[0] == _ZCL_FRAME_CONTROL_CLIENT_TO_SERVER
                and payload[2] == _ZCL_CMD_ID_QUERY_NEXT_IMG_REQ)

    def _parse_next_img_req_frame(self, frame):
        """
        Parses the given next image request frame and returns the frame values.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to parse.

        Returns:
            Tuple (:class:`_XBee3OTAStatus`, Integer): The status after parsing
                the values and the sequence number of the block request frame.
                `None` if parsing failed.
        """
        if not self._is_next_img_req_frame(frame):
            return None

        payload = frame.rf_data
        sequence_number = payload[1] & 0xFF

        if (len(payload) < _NOTIFY_PACKET_PAYLOAD_SIZE
                # Includes the hardware version
                or (payload[3] & 0xFF == 1 and len(payload) != _NOTIFY_PACKET_PAYLOAD_SIZE + 2)
                # Does not include the hardware version
                or (payload[3] & 0xFF == 0 and len(payload) != _NOTIFY_PACKET_PAYLOAD_SIZE)):
            return _XBee3OTAStatus.MALFORMED_CMD, sequence_number

        server_status = self._check_img_data(payload)
        # Field control: indicates if hardware version is available
        if server_status == _XBee3OTAStatus.SUCCESS and payload[3] & 0xFF:
            hw_version = utils.bytes_to_int(_reverse_bytearray(payload[12:14]))
            if (hw_version < self._ota_file.min_hw_version
                    or hw_version > self._ota_file.max_hw_version):
                server_status = _XBee3OTAStatus.NO_IMAGE_AVAILABLE

        return server_status, sequence_number

    @staticmethod
    def _is_image_block_request_frame(frame):
        """
        Returns whether the given frame is an image block request frame.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to check.

        Returns:
            Boolean: `True` if the frame is an image block request frame,
                `False` otherwise.
        """
        payload = frame.rf_data
        return (len(payload) > 2 and payload[0] == _ZCL_FRAME_CONTROL_CLIENT_TO_SERVER
                and payload[2] == _ZCL_CMD_ID_IMG_BLOCK_REQ)

    def _parse_image_block_request_frame(self, frame):
        """
        Parses the given image block request frame and returns the frame values.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to parse.

        Returns:
            Tuple (:class:`_XBee3OTAStatus`, Integer, Integer, Integer): Status
                after parsing the values, the max data size, the file offset
                and the sequence number of the block request frame. `None` if
                parsing failed.
        """
        if not self._is_image_block_request_frame(frame):
            return None

        payload = frame.rf_data
        sequence_number = payload[1] & 0xFF

        # The frame control indicates if there are additional optional fields
        # Currently XBee 3 does not use any of those fields
        if len(payload) != _IMAGE_BLOCK_REQUEST_PACKET_PAYLOAD_SIZE:
            server_status = _XBee3OTAStatus.MALFORMED_CMD
            server_status.cmd = _ZCL_CMD_ID_IMG_BLOCK_REQ
            return server_status, 0, 0, sequence_number

        server_status = self._check_img_data(payload)

        file_offset = utils.bytes_to_int(_reverse_bytearray(payload[12:16]))
        if (server_status == _XBee3OTAStatus.SUCCESS
                and file_offset >= self._get_ota_size()):
            server_status = _XBee3OTAStatus.MALFORMED_CMD
            server_status.cmd = _ZCL_CMD_ID_IMG_BLOCK_REQ

        max_data_size = payload[16] & 0xFF

        return server_status, max_data_size, file_offset, sequence_number

    @staticmethod
    def _is_upgrade_end_request_frame(frame):
        """
        Returns whether the given frame is an upgrade end request frame.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to check.

        Returns:
            Boolean: `True` if the frame is an upgrade end request frame,
                `False` otherwise.
        """
        payload = frame.rf_data
        return (len(payload) > 2
                and payload[0] == _ZCL_FRAME_CONTROL_CLIENT_TO_SERVER
                and payload[2] == _ZCL_CMD_ID_UPGRADE_END_REQ)

    def _parse_upgrade_end_request_frame(self, frame):
        """
        Parses the given upgrade end request frame and returns the frame values.

        Args:
            frame (:class:`.XBeeAPIPacket`): the XBee frame to parse.

        Returns:
            Tuple (:class:`_XBee3OTAStatus`, :class:`_XBee3OTAStatus`, Integer): Status
                after parsing the values, the upgrade end request status and
                the sequence number of the block request frame, `None` if
                parsing failed.
        """
        if not self._is_upgrade_end_request_frame(frame):
            return None

        payload = frame.rf_data
        sequence_number = payload[1] & 0xFF

        if len(payload) != _UPGRADE_END_REQUEST_PACKET_PAYLOAD_SIZE:
            server_status = _XBee3OTAStatus.MALFORMED_CMD
            server_status.cmd = _ZCL_CMD_ID_UPGRADE_END_REQ
            return _XBee3OTAStatus.MALFORMED_CMD, 0, sequence_number

        server_status = self._check_img_data(payload)

        status = _XBee3OTAStatus.get(payload[3] & 0xFF)
        if not status:
            server_status = _XBee3OTAStatus.MALFORMED_CMD
            server_status.cmd = _ZCL_CMD_ID_UPGRADE_END_REQ
        else:
            status.cmd = _ZCL_CMD_ID_UPGRADE_END_REQ

        return server_status, status, sequence_number

    @staticmethod
    def _is_default_response_frame(frame, seq_number):
        """
        Returns whether the given frame is a default response frame.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to check.
            seq_number (Integer): Sequence number of the last frame sent.

        Returns:
            Boolean: `True` if the frame is a default response frame, `False`
                otherwise.
        """
        payload = frame.rf_data
        disable_def_resp = _RemoteXBee3FirmwareUpdater._calculate_frame_control(
            frame_type=0, manufac_specific=False, dir_srv_to_cli=False,
            disable_def_resp=True)
        enable_def_resp = _RemoteXBee3FirmwareUpdater._calculate_frame_control(
            frame_type=0, manufac_specific=False, dir_srv_to_cli=False,
            disable_def_resp=False)
        return (len(payload) > 2
                and (payload[0] in [disable_def_resp, enable_def_resp])
                and payload[1] == seq_number
                and payload[2] == _ZCL_CMD_ID_DEFAULT_RESP)

    def _parse_default_response_frame(self, frame, seq_number):
        """
        Parses the given image block request frame and returns the frame values.

        Args:
            frame (:class:`.XBeeAPIPacket`): XBee frame to parse.
            seq_number (Integer): Sequence number of the last frame sent.

        Returns:
            Tuple (Integer, :class:`._XBee3OTAStatus`): OTA command and the
                status of the default response frame. `None` if parsing failed.
        """
        if not self._is_default_response_frame(frame, seq_number):
            return None

        payload = frame.rf_data
        ota_cmd = payload[3] & 0xFF
        status = _XBee3OTAStatus.get(payload[4] & 0xFF)

        return ota_cmd, status

    def _send_query_next_img_response(self, status=_XBee3OTAStatus.SUCCESS):
        """
        Sends the query next image response frame.

        Args:
            status (:class:`._XBee3OTAStatus`, optional, default=`_XBee3OTAStatus.SUCCESS`): The
                status to send.

        Raises:
            FirmwareUpdateException: If there is any error sending the next
                image response frame.
        """
        name = "Query next image response"
        total_retries = self.__REC_TRANSMIT_STATUS_RETRIES
        retries = total_retries
        resp_frame = self._create_query_next_image_response_frame(status=status)
        while retries > 0:
            try:
                _log.debug("Sending '%s' frame", name)
                # Delayed ACK for some packets.
                # Workaround for client (remote) fw version 1009 and prior, see
                # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
                timeout = self._timeout
                if not self._remote_fw_desc.is_ack_immediate():
                    timeout = max(self._timeout, self._remote_fw_desc.extended_timeout)
                st_frame = self._local.send_packet_sync_and_get_response(resp_frame, timeout=timeout)
                if not isinstance(st_frame, TransmitStatusPacket):
                    retries -= 1
                elif st_frame.transmit_status != TransmitStatus.SUCCESS:
                    _log.debug(
                        "Received '%s' status frame: %s, retrying (%d/%d)",
                        name, st_frame.transmit_status.description,
                        total_retries - retries + 1, total_retries)
                    retries -= 1
                    # DigiMesh: Updating from 3004 to 300A/300B, we are
                    # receiving Transmit status responses with 0x25 error
                    # (Route not found). If we wait a little between retries,
                    # the response contains a 0x00 (success) after 3 retries
                    time.sleep(2)
                else:
                    _log.debug("Received '%s' status frame: %s", name,
                               st_frame.transmit_status.description)
                    return
                # If the corresponding transmit status is not received, but a
                # Image Block Request does, continue.
                if self._check_received_request(self._requested_offset):
                    return
            except XBeeException as exc:
                # If the corresponding transmit status is not received, but a
                # Image Block Request does, continue.
                if self._check_received_request(self._requested_offset):
                    return
                # If the transmit status is not received, let's try again
                retries -= 1
                if not retries:
                    raise FirmwareUpdateException(_ERROR_SEND_FRAME_RESPONSE %
                                                  (name, str(exc))) from None
                time.sleep(2)

        raise FirmwareUpdateException(
            _ERROR_SEND_FRAME_RESPONSE % (name, "Timeout sending frame"))

    def _send_ota_block(self, file_offset, size, seq_number, timeout=None):
        """
        Sends the next OTA block frame.

        Args:
            file_offset (Integer): File offset to send.
            size (Integer): Number of bytes to send.
            seq_number (Integer): Protocol sequence number.
            timeout (Integer): Timeout to wait for the transmit status, if not
                specified or is 0, the minimum value between 15s and configured
                timeout for the update operation (`self._timeout`) is used.

        Returns:
            Integer: Number of bytes sent.

        Raises:
            FirmwareUpdateException: If there is any error sending the next OTA
                block frame.
        """
        name = "Image block response"
        total_retries = self.__REC_TRANSMIT_STATUS_RETRIES
        retries = total_retries
        while retries > 0:
            next_ota_block_frame = self._create_image_block_response_frame(
                file_offset, size, seq_number)
            # Use 15s as a maximum value to wait for transmit status frames
            # If 'self._timeout' is too big we can lose any optimization waiting
            # waiting for a transmit status, that could be received but
            if not timeout:
                timeout = min(self._timeout, 15)
            try:
                status_frame = self._local.send_packet_sync_and_get_response(
                    next_ota_block_frame, timeout=timeout)
                if not isinstance(status_frame, TransmitStatusPacket):
                    retries -= 1
                elif status_frame.transmit_status == TransmitStatus.PAYLOAD_TOO_LARGE:
                    # Do not decrease 'retries' here, as we are calculating the
                    # maximum payload
                    size -= _IMAGE_BLOCK_RESPONSE_PAYLOAD_DECREMENT
                    _log.debug(
                        "'%s' status for offset %d: size too large, retrying with size %d",
                        name, file_offset, size)
                elif status_frame.transmit_status not in (TransmitStatus.SUCCESS,
                                                          TransmitStatus.SELF_ADDRESSED):
                    retries -= 1
                    _log.debug(
                        "Received '%s' status frame for offset %d: %s, retrying (%d/%d)",
                        name, file_offset, status_frame.transmit_status.description,
                        total_retries - retries + 1, total_retries)
                else:
                    _log.debug("Received '%s' status frame for offset %d: %s",
                               name, file_offset, status_frame.transmit_status.description)
                    return size
                # If the corresponding transmit status is not received, but a
                # Image Block Request or a Upgrade End Request does, continue.
                if self._check_received_request(file_offset):
                    return size
                continue
            except XBeeException as exc:
                # If the corresponding transmit status is not received, but a
                # Image Block Request or a Upgrade End Request does, continue.
                if self._check_received_request(file_offset):
                    return size
                # If the transmit status is not received, let's try again
                retries -= 1
                if isinstance(exc, TimeoutException):
                    _log.debug("Not received '%s' status frame for offset %d, %s",
                               name, file_offset, "aborting" if retries == 0 else
                               "retrying (%d/%d)" % (total_retries - retries + 1,
                                                     total_retries))
                    if not retries:
                        return size
                elif not retries:
                    raise FirmwareUpdateException(_ERROR_SEND_OTA_BLOCK
                                                  % (file_offset, str(exc))) from None

        raise FirmwareUpdateException(_ERROR_SEND_OTA_BLOCK
                                      % (file_offset, "Timeout sending frame"))

    def _check_received_request(self, offset):
        """
        Check if a new ota block request or an 'Upgrade end request' was received.

        Args:
            offset (Integer): Last offset sent to the client.

        Returns:
            Boolean: `True` if a new request from client was received, `False`
                otherwise.
        """
        # A new block offset or an 'Upgrade end request' was received
        if ((self._transfer_lock.is_set() and offset != self._requested_offset)
                or self._transfer_status):
            msg = "Received new offset to transfer (current: %d, new: %d)" \
                  % (offset, self._requested_offset)
            if self._transfer_status:
                msg = "Received 'Upgrade end request'"
            _log.debug(msg)
            return True

        return False

    def _start_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._start_firmware_update`
        """
        retries = self.__REC_TRANSMIT_STATUS_RETRIES
        name = "Image notify"
        error = None

        image_notify_request_frame = self._create_image_notify_request_frame()
        self._local.add_packet_received_callback(self._image_request_frame_cb)

        while retries > 0:
            _log.debug("Sending '%s' frame", name)
            self._receive_lock.clear()
            try:
                self._local.send_packet(image_notify_request_frame)
                self._receive_lock.wait(self._timeout)
            except XBeeException as exc:
                retries -= 1
                if not retries:
                    error = _ERROR_SEND_FRAME_RESPONSE % (name, str(exc))
                continue

            if not self._img_notify_sent:
                retries -= 1
                if not retries:
                    error = _ERROR_SEND_FRAME_RESPONSE \
                            % (name, "Transmit status not received")
            elif self._response_str:
                retries -= 1
                if not retries:
                    error = _ERROR_TRANSFER_OTA_FILE % self._response_str
            elif not self._img_req_received:
                retries -= 1
                if not retries:
                    error = _ERROR_SEND_FRAME_RESPONSE \
                            % (name, "Timeout waiting for 'Query next image request'")
            else:
                break

        self._local.del_packet_received_callback(self._image_request_frame_cb)

        if error:
            self._exit_with_error(error)

    def _transfer_firmware(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._transfer_firmware`
        """
        self._transfer_status = None
        self._response_str = None
        self._requested_offset = -1
        self._progress_task = self._update_task
        last_offset_sent = self._requested_offset
        # Dictionary to store block size used for each provided maximum size
        last_size_sent = {self._max_chunk_size: self._max_chunk_size}
        previous_percent = None
        timeout_for_request = max(45, self._remote_fw_desc.extended_timeout)
        max_retries = self._remote_fw_desc.get_block_response_max_retries()
        retries = max_retries
        # Count the number of missing requests, if there are more than 3 in a row, update failed.
        # Workaround for client (remote) fw version 1008 and prior, see
        # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
        max_lost_requests = self._remote_fw_desc.get_max_ota_lost_client_requests_in_a_row()
        lost_requests = 0

        self._transfer_lock.clear()

        # Add a packet listener to wait for block request packets and send them.
        self._local.add_packet_received_callback(self._fw_receive_frame_cb)
        try:
            self._send_query_next_img_response()
        except FirmwareUpdateException as exc:
            self._local.del_packet_received_callback(self._fw_receive_frame_cb)
            self._exit_with_error(str(exc))
        # Wait for answer.
        if self._requested_offset == -1:
            # If offset is different from -1 it means the callback was executed.

            # Ensure to wait at least 45 seconds for the first Image Block Request.
            # Workaround for client (remote) fw version 1008 and prior, see
            # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
            _log.debug("Waiting for first 'Image Block Request' request (%f s)",
                       max(self._timeout, timeout_for_request))
            if (not self._transfer_lock.wait(max(self._timeout, timeout_for_request))
                    and not self._remote_fw_desc.wait_for_client_retry()):
                # Send the first chunk of the ota file.
                # Workaround for client (remote) fw version 1008 and prior, see
                # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
                lost_requests += 1
                # Failure if there are too many lost client requests in a row
                if lost_requests > max_lost_requests:
                    _log.warning("Lost %d/%d requests from client (in a row), update failed",
                                 lost_requests, max_lost_requests)
                else:
                    self._requested_offset = 0
                    if self._remote_fw_desc.support_different_ota_block_size():
                        self._max_chunk_size = min(self._max_chunk_size, self._cfg_max_block_size)
                    self._seq_number += 1

        while (self._requested_offset != -1 and self._transfer_status is None
               and self._response_str is None and retries > 0):
            self._transfer_lock.clear()

            last_offset_sent = self._requested_offset
            previous_seq_number = self._seq_number
            # Check that the requested offset is valid.
            if self._requested_offset >= self._get_ota_size():
                self._local.del_packet_received_callback(self._fw_receive_frame_cb)
                self._exit_with_error(_ERROR_INVALID_BLOCK % self._requested_offset)
            # Calculate percentage and notify.
            percent = (self._requested_offset * 100) // self._get_ota_size()
            if percent != previous_percent:
                self._notify_progress(self._progress_task, percent)
                previous_percent = percent

            # Delayed ACK for some packets. Only for the last block.
            # Workaround for client (remote) fw version 1009 and prior, see
            # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
            timeout = None
            stored_last_size_sent = last_size_sent.get(self._max_chunk_size, self._max_chunk_size)
            if (not self._remote_fw_desc.is_ack_immediate()
                    and self._requested_offset + stored_last_size_sent < self._get_ota_size()):
                timeout = max(self._timeout, self._remote_fw_desc.extended_timeout)

            # Send the data block.
            try:
                size_sent = self._send_ota_block(
                    self._requested_offset,
                    min(stored_last_size_sent, self._max_chunk_size),
                    previous_seq_number, timeout=timeout)
                last_size_sent[self._max_chunk_size] = size_sent
            except FirmwareUpdateException as exc:
                self._local.del_packet_received_callback(self._fw_receive_frame_cb)
                self._exit_with_error(str(exc))

            # Wait for next request.
            # Ensure to wait for the Image Block Request
            # Workaround for client (remote) fw version 1008 and prior, see
            # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
            _log.debug("Waiting for next request (%f s)", max(self._timeout, timeout_for_request))
            if not self._transfer_lock.wait(max(self._timeout, timeout_for_request)):
                retries -= 1
                if retries > 0:
                    _log.info("Last chunk %d not sent, retrying... (%d/%d)",
                              self._requested_offset, max_retries - retries + 1,
                              max_retries)
                    continue
                # Send the next chunk of the ota file, or send the Upgrade End Response
                # Workaround for client (remote) fw version 1008 and prior, see
                # https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm
                if not self._remote_fw_desc.wait_for_client_retry():
                    lost_requests += 1
                    # Fail if there are too many lost client requests in a row.
                    if lost_requests > max_lost_requests:
                        _log.warning("Lost %d/%d requests from client (in a row), update failed",
                                     lost_requests, max_lost_requests)
                        continue
                    self._seq_number += 1
                    # Calculate next offset to send or break to send the 'Upgrade end response'
                    last_offset = self._requested_offset
                    self._requested_offset += last_size_sent.get(self._max_chunk_size, self._max_chunk_size)
                    if self._requested_offset < self._get_ota_size():
                        _log.info("Chunk request %d not received, sending next chunk %d "
                                  "(lost in a row %d/%d)", last_offset,
                                  self._requested_offset, lost_requests, max_lost_requests)
                        retries = max_retries
                        continue
                    self._transfer_status = _XBee3OTAStatus.SUCCESS
                    _log.info("'Upgrade end request' not received, sending 'Upgrade end response'"
                              "(lost in a row %d/%d)", lost_requests, max_lost_requests)
            else:
                retries = max_retries
                lost_requests = 0

        # Transfer finished, remove callback.
        self._local.del_packet_received_callback(self._fw_receive_frame_cb)
        # Close OTA file.
        self._ota_file.close_file()
        # Check if there was a transfer timeout.
        if self._transfer_status is None and self._response_str is None:
            if last_offset_sent + last_size_sent.get(self._max_chunk_size, self._max_chunk_size) == self._get_ota_size():
                self._exit_with_error(_ERROR_TRANSFER_OTA_FILE
                                      % "Timeout waiting for 'Upgrade end request' frame")
            else:
                self._exit_with_error(_ERROR_TRANSFER_OTA_FILE
                                      % "Timeout waiting for next 'Image block request' frame")
        # Check if there was a transfer error.
        if self._transfer_status and self._transfer_status != _XBee3OTAStatus.SUCCESS:
            self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % self._transfer_status.description)
        # Check if the client reported an error.
        if self._response_str:
            self._exit_with_error(_ERROR_TRANSFER_OTA_FILE % self._response_str)
        # Reaching this point means the transfer was successful, notify 100% progress.
        self._notify_progress(self._progress_task, 100)

    def _finish_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._finish_firmware_update`
        """
        name = "Upgrade end response"
        total_retries = self.__REC_TRANSMIT_STATUS_RETRIES
        retries = total_retries
        error_msg = None
        upgrade_end_response_frame = self._create_upgrade_end_response_frame()
        timeout = self._timeout
        if not self._remote_fw_desc.is_ack_immediate():
            timeout = max(self._timeout, self._remote_fw_desc.extended_timeout)
        while retries > 0:
            try:
                _log.debug("Sending '%s' frame (%d/%d)", name,
                           total_retries - retries + 1, total_retries)
                error_msg = None
                st_frame = self._local.send_packet_sync_and_get_response(
                    upgrade_end_response_frame, timeout=timeout)
                if not isinstance(st_frame, TransmitStatusPacket):
                    retries -= 1
                    continue
                _log.debug("Received '%s' status frame: %s", name,
                           st_frame.transmit_status.description)

                #
                # Workaround for XBHAWKDM-796
                #
                #   - 'No ack' error on XBee 3 DigiMesh remote firmware update
                #   - 'Route not found' error on XBee 3 DigiMesh remote firmware
                #     update from 3004 to 300A/300B
                #   - 'Address not found' on XBee 3 ZB remote firmware update
                #   - 'No ack' error on XBee 3 802.15.4 remote firmware update
                #
                # The workaround considers those TX status as valid.
                #
                # See https://jira.digi.com/browse/XBHAWKDM-796
                #
                dm_ack_error = (st_frame.transmit_status in (TransmitStatus.NO_ACK,
                                                             TransmitStatus.ROUTE_NOT_FOUND)
                                and self._remote.get_protocol() == XBeeProtocol.DIGI_MESH
                                and self._target_fw_version <= 0x3004)
                raw_802_error = (st_frame.transmit_status == TransmitStatus.NO_ACK
                                 and self._remote.get_protocol() == XBeeProtocol.RAW_802_15_4
                                 and self._target_fw_version <= 0x2002)
                zb_addr_error = (st_frame.transmit_status == TransmitStatus.ADDRESS_NOT_FOUND
                                 and self._remote.get_protocol() == XBeeProtocol.ZIGBEE
                                 and self._target_fw_version <= 0x1009)

                if (st_frame.transmit_status == TransmitStatus.SUCCESS
                        or dm_ack_error or zb_addr_error or raw_802_error):
                    try:
                        self._restore_updater(raise_exception=True)
                        return
                    except Exception as exc:
                        self._exit_with_error(_ERROR_RESTORE_UPDATER_DEVICE % str(exc))
            except XBeeException as exc:
                error_msg = str(exc)
            retries -= 1
            time.sleep(1.5)  # Wait some time between timeout retries.

        if error_msg:
            self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % (name, error_msg))
        else:
            self._exit_with_error(_ERROR_SEND_FRAME_RESPONSE % (name, "Timeout sending frame"))

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        protocol = self._remote.get_protocol()
        if protocol == XBeeProtocol.ZIGBEE:
            return self.__DEVICE_RESET_TIMEOUT_ZB
        if protocol == XBeeProtocol.DIGI_MESH:
            return self.__DEVICE_RESET_TIMEOUT_DM
        if protocol == XBeeProtocol.RAW_802_15_4:
            return self.__DEVICE_RESET_TIMEOUT_802

        return max([self.__DEVICE_RESET_TIMEOUT_ZB,
                    self.__DEVICE_RESET_TIMEOUT_DM,
                    self.__DEVICE_RESET_TIMEOUT_802])

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
        return (self._ota_file.total_size
                if self._remote_fw_desc.must_send_complete_ota() else self._ota_file.ota_size)

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
        return (offset
                if self._remote_fw_desc.must_send_complete_ota() else offset + self._ota_file.discard_size)


class _RemoteFilesystemUpdater(_RemoteXBee3FirmwareUpdater):
    """
    Helper class used to handle the remote filesystem update process.
    """

    def __init__(self, remote, fs_ota_file, timeout=_READ_DATA_TIMEOUT,
                 max_block_size=0, progress_cb=None):
        """
        Class constructor. Instantiates a new :class:`._RemoteFilesystemUpdater`
        with the given parameters.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to update its filesystem.
            fs_ota_file (String): Path of the filesystem OTA file.
            timeout (Integer, optional): Timeout to wait for remote frame requests.
            max_block_size (Integer, optional): Maximum size in bytes of the ota block to send.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: If there is any error performing the
                remote filesystem update.
        """
        super().__init__(remote, None, timeout=timeout,
                         max_block_size=max_block_size, progress_cb=progress_cb)
        self._fs_ota_file = fs_ota_file
        self._update_task = _PROGRESS_TASK_UPDATE_REMOTE_FILESYSTEM

    def _parse_xml_firmware_file(self):
        """
        Override method.
        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._parse_xml_firmware_file`
        """
        # Filesystem update process does not require to parse any XML file.

    def _check_fw_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_fw_binary_file`
        """
        # Verify the filesystem OTA image file.
        if not _file_exists(self._fs_ota_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("OTA filesystem image", self._fs_ota_file),
                                  restore_updater=False)

        self._ota_file = _OTAFile(self._fs_ota_file)
        try:
            self._ota_file.parse_file()
        except _ParsingOTAException as exc:
            self._exit_with_error(str(exc), restore_updater=False)

    def _will_protocol_change(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._will_protocol_change`
        """
        # Updating the filesystem image does not imply any protocol change.
        return False

    def _check_target_compatibility(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_target_compatibility`
        """
        # Read device values required for verification steps prior to filesystem update.
        _log.debug("Reading device settings:")
        self._target_fw_version = self._get_target_fw_version()
        _log.debug(" - Firmware version: %s",
                   utils.hex_to_string([self._target_fw_version], pretty=False)
                   if self._target_fw_version is not None else "-")
        self._target_hw_version = self._get_target_hw_version()
        _log.debug(" - Hardware version: %s",
                   utils.hex_to_string([self._target_hw_version], pretty=False)
                   if self._target_hw_version is not None else "-")

        # Check if the hardware version is compatible with the filesystem update process.
        if self._target_hw_version and self._target_hw_version not in XBEE3_HW_VERSIONS:
            self._exit_with_error(_ERROR_HW_VERSION_NOT_SUPPORTED % self._target_hw_version,
                                  restore_updater=False)

    def _update_target_information(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._update_target_information`
        """
        # Remote filesystem update does not require to update target information after the update.


class _RemoteGPMFirmwareUpdater(_RemoteFirmwareUpdater):
    """
    Helper class used to handle the remote firmware update process of general
    purpose memory (GPM) devices.
    """

    __DEVICE_RESET_TIMEOUT = 10  # seconds
    __DEFAULT_PAGE_SIZE = 128
    __DEFAULT_TIMEOUT = 20  # Seconds.

    def __init__(self, remote, xml_fw_file, xbee_fw_file=None,
                 timeout=__DEFAULT_TIMEOUT, progress_cb=None,
                 bootloader_type=_BootloaderType.GEN3_BOOTLOADER):
        """
        Class constructor. Instantiates a new
        :class:`._RemoteGPMFirmwareUpdater` with the given parameters.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to upload its firmware.
            xml_fw_file (String): Path of the XML file that describes the firmware.
            xbee_fw_file (String, optional): Path of the binary firmware file.
            timeout (Integer, optional): Timeout to wait for remote frame answers.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

            bootloader_type (:class:`_BootloaderType`): Bootloader type of the
                remote node.

        Raises:
            FirmwareUpdateException: If there is any error performing the
                remote firmware update.
        """
        super().__init__(remote, xml_fw_file, timeout=timeout, progress_cb=progress_cb)

        self._fw_file = xbee_fw_file
        self._gpm_answer_payload = None
        self._gpm_frame_sent = False
        self._gpm_frame_received = False
        self._num_bytes_per_blocks = 0
        self._bootloader_type = bootloader_type

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__DEVICE_RESET_TIMEOUT

    def _check_fw_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_fw_binary_file`
        """
        # If not already specified, the binary firmware file is usually in the
        # same folder as the XML firmware file.
        if self._fw_file is None:
            path = Path(self._xml_fw_file)
            self._fw_file = str(
                Path(path.parent).joinpath(
                    path.stem + (
                        EXTENSION_EBIN
                        if self._bootloader_type == _BootloaderType.GEN3_BOOTLOADER
                        else EXTENSION_GBL
                    )
                )
            )

        if not _file_exists(self._fw_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("XBee firmware", self._fw_file),
                                  restore_updater=False)

    def _check_bootloader_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_bootloader_binary_file`
        """
        # General Purpose Memory devices do not have bootloader update file.

    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during updater
        configuration or not.

        Returns:
            Boolean: `True` if AO parameter should be configured, `False` otherwise.
        """
        return True

    def _configure_updater_extra(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._configure_updater_extra`
        """
        # GPM devices do not require extra configuration prior to firmware update process.

    def _restore_updater_extra(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._restore_updater_extra`
        """
        # GPM devices do not require extra configuration to restore it to its original state.

    def _create_explicit_frame(self, payload):
        """
        Creates and returns an explicit addressing GPM frame using the given payload.

        Args:
            payload (Bytearray): Payload for the explicit addressing GPM frame.

        Returns:
            :class:`.ExplicitAddressingPacket`: Explicit addressing GPM frame
                with the given payload.
        """
        return ExplicitAddressingPacket(
            self._local.get_next_frame_id(), self._remote.get_64bit_addr(),
            self._remote.get_16bit_addr(), _EXPL_PACKET_ENDPOINT_DIGI_DEVICE,
            _EXPL_PACKET_ENDPOINT_DIGI_DEVICE, _EXPL_PACKET_CLUSTER_GPM,
            _EXPL_PACKET_PROFILE_DIGI, _EXPL_PACKET_BROADCAST_RADIUS_MAX,
            0x00, payload)

    def _create_gpm_cmd_frame(self, cmd, options=0, block_index=0, byte_index=0, gpm_data=None):
        """
        Creates and returns a GPM command frame with the given parameters.

        Args:
            cmd (:class:`.GPMCommand`): GPM command to create the frame for.
            options (Integer, optional, default=0): Command options byte.
            block_index (Integer, optional, default=0): Block number addressed in the GPM command.
            byte_index (Integer, optional, default=0): Byte index within the addressed GPM command.
            gpm_data (Bytearray, optional, default=`None`): Command GPM data.

        Returns:
            :class:`.ExplicitAddressingPacket`: GPM command frame.
        """
        payload = bytearray()
        payload.append(cmd.command_id)  # Command ID.
        payload.append(options & 0xFF)  # Command options
        payload.extend(utils.int_to_bytes(block_index & 0xFFFF, 2))  # Block index
        payload.extend(utils.int_to_bytes(byte_index & 0xFFFF, 2))  # Byte index
        if gpm_data:
            payload.extend(utils.int_to_bytes(len(gpm_data) & 0xFFFF, 2))  # Data length
            payload.extend(gpm_data)  # Data
        else:
            payload.extend(bytearray([0x00, 0x00]))  # Data length
        return self._create_explicit_frame(payload)

    def _gpm_receive_frame_callback(self, frame):
        """
        Callback used to be notified on GPM frame reception.

        Args:
            frame (:class:`.XBeeAPIPacket`): Received frame
        """
        f_type = frame.get_frame_type()
        if f_type == ApiFrameType.TRANSMIT_STATUS:
            if frame.transmit_status == TransmitStatus.SUCCESS:
                self._gpm_frame_sent = True
                # Sometimes the transmit status frame is received after the
                # explicit frame indicator.
                # Notify only if the transmit status frame was also received.
                if self._gpm_frame_received:
                    # Continue execution.
                    self._receive_lock.set()
            else:
                # Remove explicit frame indicator received flag if it was set.
                if self._gpm_frame_received:
                    self._gpm_frame_received = False
                # Continue execution, it will exit with error as received flags are not set.
                self._receive_lock.set()
        elif (f_type == ApiFrameType.EXPLICIT_RX_INDICATOR
              and frame.source_endpoint == _EXPL_PACKET_ENDPOINT_DIGI_DEVICE
              and frame.dest_endpoint == _EXPL_PACKET_ENDPOINT_DIGI_DEVICE
              and frame.cluster_id == _EXPL_PACKET_CLUSTER_GPM
              and frame.profile_id == _EXPL_PACKET_PROFILE_DIGI
              and frame.x64bit_source_addr == self._remote.get_64bit_addr()):
            # If GPM frame was already received, ignore this frame.
            if self._gpm_frame_received:
                return
            # Store GPM answer payload.
            self._gpm_answer_payload = frame.rf_data
            # Flag frame as received.
            self._gpm_frame_received = True
            # Sometimes the transmit status frame is received after the
            # explicit frame indicator. Notify only if the transmit status
            # frame was also received.
            if self._gpm_frame_sent:
                # Continue execution.
                self._receive_lock.set()

    def _send_explicit_gpm_frame(self, frame, expect_answer=True):
        """
        Sends the given explicit GPM frame to the remote device.

        Args:
            frame (:class:`.ExplicitAddressingPacket`): Explicit GPM frame to send.
            expect_answer (Boolean, optional, default=`True`): `True` if after
                sending the frame an answer is expected, `False` otherwise.

        Raises:
            FirmwareUpdateException: If there is any error sending the explicit GPM frame.
        """
        # Clear vars.
        self._receive_lock.clear()
        self._gpm_answer_payload = None
        self._gpm_frame_sent = False
        self._gpm_frame_received = False

        # Add a frame listener to wait for answer.
        self._local.add_packet_received_callback(self._gpm_receive_frame_callback)
        try:
            # Send frame.
            self._local.send_packet(frame)
            # Wait for answer.
            self._receive_lock.wait(self._timeout)
        except XBeeException as exc:
            self._exit_with_error(_ERROR_SERIAL_COMMUNICATION % str(exc))
        finally:
            # Remove frame listener.
            self._local.del_packet_received_callback(self._gpm_receive_frame_callback)

        # Check if packet was correctly sent.
        if not self._gpm_frame_sent:
            raise FirmwareUpdateException(_ERROR_SEND_FRAME)
        if not self._gpm_frame_received and expect_answer:
            raise FirmwareUpdateException(_ERROR_RECEIVE_FRAME_TIMEOUT)

    def _execute_gpm_cmd(self, cmd, options=0, block_index=0, byte_index=0,
                         gpm_data=None, retries=1, expect_answer=True):
        """
        Executes the given GPM command.

        Args:
            cmd (:class:`.GPMCommand`): GPM command to execute.
            options (Integer, optional, default=0): Command options byte, defaults to 0.
            block_index (Integer, optional, default=0): Block number addressed in the GPM command.
            byte_index (Integer, optional, default=0): Byte index within the addressed GPM command.
            gpm_data (Bytearray, optional, default=`None`): Command GPM data.
            retries (Integer, optional, default=1): Number of retries to execute the command.
            expect_answer (Boolean, optional, default=`True`): `True` if the
                command execution should expect an answer, `False` otherwise.

        Raises:
            FirmwareUpdateException: If there is any error executing the GPM command.
        """
        error = None
        while retries > 0:
            error = None
            try:
                self._send_explicit_gpm_frame(
                    self._create_gpm_cmd_frame(
                        cmd, options=options, block_index=block_index,
                        byte_index=byte_index, gpm_data=gpm_data),
                    expect_answer=expect_answer)
                if not expect_answer:
                    break
                # Check for communication error.
                if (not self._gpm_answer_payload
                        or len(self._gpm_answer_payload) < 8
                        or self._gpm_answer_payload[0] != cmd.answer_id):
                    error = _ERROR_INVALID_GPM_ANSWER
                    retries -= 1
                elif (self._gpm_answer_payload[1] & 0x1) == 1:  # Check for command error.
                    error = cmd.execution_error
                    retries -= 1
                else:
                    break
            except FirmwareUpdateException as exc:
                error = str(exc)
                retries -= 1
        if error:
            self._exit_with_error(error)

    def _read_device_gpm_info(self):
        """
        Reads specific GPM device information required to perform the remote
        firmware update.
        The relevant information to retrieve is the number of blocks and bytes
        per block of the flash.

        Raises:
            FirmwareUpdateException: If there is any error reading the GPM
                device flash information.
        """
        _log.debug("Reading GPM device info")
        self._execute_gpm_cmd(_GPMCmd.GET_PLATFORM_INFO)
        # Store relevant values.
        num_gpm_blocks = utils.bytes_to_int(self._gpm_answer_payload[2:4])
        _log.debug(" - Number of memory blocks: %s", num_gpm_blocks)
        self._num_bytes_per_blocks = utils.bytes_to_int(self._gpm_answer_payload[4:6])
        _log.debug(" - Number of bytes per block: %s", self._num_bytes_per_blocks)

    def _erase_flash(self):
        """
        Erases the device flash.

        Raises:
            FirmwareUpdateException: If there is any error erasing the device flash.
        """
        _log.debug("Erasing device flash")
        self._execute_gpm_cmd(_GPMCmd.ERASE_FLASH)

    def _write_data(self, block_index, byte_index, data, retries):
        """
        Writes data to the device.

        Args:
            block_index (Integer): Block index to write data to.
            byte_index (Integer): Byte index in the block to write data to.
            data (Bytearray): Data to write.
            retries (Integer): Number of retries to write data.

        Raises:
            FirmwareUpdateException: If there is any error writing the given data.
        """
        self._execute_gpm_cmd(_GPMCmd.WRITE_DATA, block_index=block_index,
                              byte_index=byte_index, gpm_data=data, retries=retries)

    def _verify_firmware(self):
        """
        Verifies the firmware image in the device.

        Raises:
            FirmwareUpdateException: If there is any error verifying the
                firmware in the device.
        """
        _log.debug("Verifying firmware")
        self._execute_gpm_cmd(_GPMCmd.VERIFY_IMAGE)

    def _install_firmware(self):
        """
        Installs the firmware in the device.

        Raises:
            FirmwareUpdateException: If there is any error installing the
                firmware in the device.
        """
        _log.debug("Installing firmware")
        self._execute_gpm_cmd(_GPMCmd.VERIFY_AND_INSTALL, expect_answer=False)

    def _start_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._start_firmware_update`
        """
        self._read_device_gpm_info()
        self._erase_flash()

    def _transfer_firmware(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._transfer_firmware`
        """
        _log.info("%s - %s", self._remote, _PROGRESS_TASK_UPDATE_REMOTE_XBEE)
        self._progress_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        # Perform file transfer.
        ebin_file = _EbinFile(self._fw_file, self.__DEFAULT_PAGE_SIZE)
        previous_percent = None
        block_index = 0
        byte_index = 0
        for data_chunk in ebin_file.get_next_mem_page():
            if ebin_file.percent != previous_percent:
                self._notify_progress(self._progress_task, ebin_file.percent)
                previous_percent = ebin_file.percent
            _log.debug("Sending chunk %d/%d %d%%", ebin_file.page_index + 1,
                       ebin_file.num_pages, ebin_file.percent)
            self._write_data(block_index, byte_index, data_chunk, 3)
            byte_index += len(data_chunk)
            # Increment block index if required.
            if byte_index >= self._num_bytes_per_blocks:
                byte_index = 0
                block_index += 1

    def _finish_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._finish_firmware_update`
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
    __FW_UPDATE_RETRIES = 2
    __INIT_RETRIES = 2
    __FW_DATA_RETRIES = 5
    __CLEAR_UPDATER_RECOVERY_RETRIES = 3
    __SET_UPDATER_RECOVERY_RETRIES = 3

    def __init__(self, remote, xml_fw_file, xbee_fw_file=None,
                 timeout=__DEFAULT_TIMEOUT, force_update=True, progress_cb=None):
        """
        Class constructor. Instantiates a new
        :class:`._RemoteEmberFirmwareUpdater` with the given parameters.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to upload its firmware.
            xml_fw_file (String): Path of the XML file that describes the firmware.
            xbee_fw_file (String, optional): Path of the binary firmware file.
            timeout (Integer, optional): Timeout to wait for remote frame answers.
            force_update (Boolean, optional, default=`True`): `True` to force
                firmware update even if connectivity tests fail, `False` otherwise.
            progress_cb (Function, optional): Function to receive progress
                information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            FirmwareUpdateException: If there is any error performing the
                remote firmware update.
        """
        super().__init__(remote, xml_fw_file, timeout=timeout, progress_cb=progress_cb)

        self._fw_file = xbee_fw_file
        self._force_update = force_update
        self._updater = None
        self._updater_dh_val = None
        self._updater_dl_val = None
        self._ota_packet_received = False
        self._expected_ota_block = -1
        self._ota_msg_type = None
        self._any_data_sent = False
        self._packet_received = False
        self._updater_configurer = None

    def _get_default_reset_timeout(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._get_default_reset_timeout`
        """
        return self.__DEVICE_RESET_TIMEOUT

    def _check_fw_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_fw_binary_file`
        """
        # If not already specified, the binary firmware file is usually in the
        # same folder as the XML firmware file.
        if self._fw_file is None:
            path = Path(self._xml_fw_file)
            self._fw_file = str(Path(path.parent).joinpath(path.stem + EXTENSION_EBL))

        if not _file_exists(self._fw_file):
            self._exit_with_error(_ERROR_FILE_NOT_FOUND % ("XBee firmware", self._fw_file),
                                  restore_updater=False)

    def _check_bootloader_binary_file(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._check_bootloader_binary_file`
        """
        # Ember devices do not have bootloader update file.

    def _configure_ao_parameter(self):
        """
        Determines whether the AO parameter should be configured during updater
        configuration or not.

        Returns:
            Boolean: `True` if AO parameter should be configured, `False` otherwise.
        """
        # AO parameter is configured in the updater device instead of the local
        # one and only for 802.15.4 devices. Return False and configure it in
        # the extra step, once local device connection is open and we can
        # determine the real updater device.
        return False

    def _configure_updater_extra(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._configure_updater_extra`
        """
        # Determine updater device.
        _log.debug("Looking for best updater device")
        if self._local.get_protocol() == XBeeProtocol.ZIGBEE:
            self._updater = self._determine_updater_device_zigbee()
        elif self._local.get_protocol() == XBeeProtocol.DIGI_MESH:
            self._updater = self._determine_updater_device_digimesh()
        elif self._local.get_protocol() == XBeeProtocol.RAW_802_15_4:
            self._updater = self._determine_updater_device_802()
        else:
            self._updater = self._local
        if not self._updater:
            self._exit_with_error(_ERROR_NO_UPDATER_AVAILABLE)
        _log.debug("Updater device: %s", self._updater)
        # For async sleep devices: reconfigure updater to stay awake the maximum time
        self._updater_configurer = UpdateConfigurer(self._updater, timeout=self._timeout)
        try:
            self._updater_configurer.prepare_for_update(
                prepare_node=True, prepare_net=False, restore_later=True)
        except XBeeException as exc:
            self._exit_with_error(str(exc))

        # Save DH parameter.
        self._updater_dh_val = _get_parameter_with_retries(self._updater,
                                                           ATStringCommand.DH)
        if self._updater_dh_val is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAM % ATStringCommand.DH.command)
        # Set new DH value.
        if not _set_parameter_with_retries(
                self._updater, ATStringCommand.DH,
                self._remote.get_64bit_addr().address[0:4], apply=True):
            self._exit_with_error(_ERROR_UPDATER_SET_PARAM % ATStringCommand.DH.command)
        # Save DL parameter.
        self._updater_dl_val = _get_parameter_with_retries(self._updater,
                                                           ATStringCommand.DL)
        if self._updater_dl_val is None:
            self._exit_with_error(_ERROR_UPDATER_READ_PARAM % ATStringCommand.DL.command)
        # Set new DL value.
        if not _set_parameter_with_retries(
                self._updater, ATStringCommand.DL,
                self._remote.get_64bit_addr().address[4:], apply=True):
            self._exit_with_error(_ERROR_UPDATER_SET_PARAM % ATStringCommand.DL.command)

    def _restore_updater_extra(self):
        """
        Override.

        .. seealso::
           | :meth:`._RemoteFirmwareUpdater._restore_updater_extra`
        """
        # Restore DH parameter
        if self._updater_dh_val:
            _set_parameter_with_retries(self._updater, ATStringCommand.DH,
                                        self._updater_dh_val,
                                        apply=bool(not self._updater_dl_val))
        # Restore DL parameter
        if self._updater_dl_val:
            _set_parameter_with_retries(self._updater, ATStringCommand.DL,
                                        self._updater_dl_val, apply=True)

        if self._updater_configurer:
            self._updater_configurer.restore_after_update(restore_settings=True)

    def _determine_updater_device_zigbee(self):
        """
        Determines the updater device that will handle the update process of
        the remote node in a Zigbee network.

        Returns:
            :class:`.RemoteXBeeDevice`: Updater device that will handle the
                update process in a Zigbee network.

        Raises:
            FirmwareUpdateException: If there is any error determining the
                updater device.
        """
        # Check if the remote node is an end device and has a parent that will
        # be the updater. If it has no parent, then the node cannot be updated.
        if self._remote.get_role() == Role.END_DEVICE:
            updater = self._remote.parent
            if not updater:
                # Discover parent device.
                parent_16bit = _get_parameter_with_retries(self._remote,
                                                           ATStringCommand.MP)
                xnet = self._local.get_network()
                if not parent_16bit:
                    # The end device node is orphan, we cannot update it.
                    self._exit_with_error(_ERROR_END_DEVICE_ORPHAN)
                updater = xnet.get_device_by_16(XBee16BitAddress(parent_16bit))
                if not updater:
                    xnet.start_discovery_process()
                    while xnet.is_discovery_running():
                        time.sleep(0.5)
                    updater = xnet.get_device_by_16(XBee16BitAddress(parent_16bit))
                if not updater:
                    # The end device node is orphan, we cannot update it.
                    self._exit_with_error(_ERROR_END_DEVICE_ORPHAN)
            # Verify the updater hardware version.
            if not updater.get_hardware_version():
                updater_hw_version = _get_parameter_with_retries(updater, ATStringCommand.HV)
            else:
                updater_hw_version = [updater.get_hardware_version().code]
            if not updater_hw_version or updater_hw_version[0] not in S2C_HW_VERSIONS:
                self._exit_with_error(_ERROR_UPDATE_FROM_S2C)
            return updater
        # Look for updater using the current network connections.
        candidates = self._get_updater_candidates(net_discover=False)
        updater = self._determine_best_updater_from_candidates_list_zigbee(candidates)
        if updater:
            return updater
        # Could not retrieve updater from current network connections, try discovering neighbors.
        candidates = self._get_updater_candidates(net_discover=True)
        updater = self._determine_best_updater_from_candidates_list_zigbee(candidates)
        return updater

    def _determine_updater_device_digimesh(self):
        """
        Determines the updater device that will handle the update process of
        the remote node in a DigiMesh network.

        Returns:
            :class:`.RemoteXBeeDevice`: Updater device that will handle the
                update process in a DigiMesh network.

        Raises:
            FirmwareUpdateException: If there is any error determining the
                updater device.
        """
        # Look for updater using the current network connections.
        candidates = self._get_updater_candidates(net_discover=False)
        updater = self._determine_best_updater_from_candidates_list_digimesh(candidates)
        if updater:
            return updater
        # Could not retrieve updater from current network connections, try discovering neighbors.
        candidates = self._get_updater_candidates(net_discover=True)
        updater = self._determine_best_updater_from_candidates_list_digimesh(candidates)
        return updater

    def _determine_updater_device_802(self):
        """
        Determines the updater device that will handle the update process of
        the remote node in a 802.15.4 network.

        Returns:
            :class:`.RemoteXBeeDevice`: Updater device that will handle the
                update process in a 802.15.4 network.

        Raises:
            FirmwareUpdateException: If there is any error determining the
                updater device.
        """
        # In a 802.15.4 network, the updater device is the local device. The
        # only restriction is that local and remote devices mut be of the same
        # hardware type (S2C <> S2C)
        if self._local.get_hardware_version().code in S2C_HW_VERSIONS and \
                self._get_target_hw_version() in S2C_HW_VERSIONS:
            return self._local
        self._exit_with_error(_ERROR_UPDATE_FROM_S2C)

    def _get_updater_candidates(self, net_discover=False):
        """
        Returns a list of updater candidates extracted from the current
        network connections or from a neighbor discover.

        Args:
            net_discover (Boolean, optional, default=False): `True` to perform
                a neighbor discover, `False` to use current network connections.

        Returns:
            List: List of possible XBee updater devices.
        """
        from digi.xbee.models.zdo import Neighbor
        from digi.xbee.devices import Connection

        def get_lq(element):
            if isinstance(element, Connection):
                dest_node = element.node_b
                lq = element.lq_a2b.lq
                if dest_node == self._remote:
                    dest_node = element.node_a
                    lq = element.lq_b2a.lq
            elif isinstance(element, Neighbor):
                lq = element.lq
                dest_node = element.node
            else:
                return 0

            return lq * (Role.UNKNOWN.id - dest_node.get_role().id + 1)

        if net_discover:
            neighbor_list = self._remote.get_neighbors()
            if not neighbor_list:
                return None
            neighbor_list.sort(key=lambda neighbor: get_lq(neighbor))
            node_list = (neighbor.node for neighbor in neighbor_list)
        else:
            conn_list = self._local.get_network().get_node_connections(self._remote)
            if not conn_list:
                return None
            conn_list.sort(key=lambda conn: get_lq(conn))
            node_list = (conn.node_a
                         if conn.node_a != self._remote else conn.node_b
                         for conn in conn_list)

        candidates = []
        for candidate in node_list:
            if not self._is_valid_updater_candidate(candidate):
                continue
            # If the candidate is the local device, return only it
            if candidate == self._local:
                candidates.append(self._local)
                break
            candidates.append(candidate)

        return candidates if candidates else None

    def _is_valid_updater_candidate(self, node):
        """
        Checks if the provided node is a valid candidate to be the updater node
        for the update process of the remote.

        Args:
            node (:class: `.RemoteXBeeDevice`): The node to check if it is a
                possible updater.
        """
        # Updater cannot be the remote node itself
        if node == self._remote:
            return False
        # Updater cannot be an end device
        if node.get_role() == Role.END_DEVICE:
            return False
        # Updater must be an S2C device
        if not node.get_hardware_version():
            hw_version = _get_parameter_with_retries(node, ATStringCommand.HV)
        else:
            hw_version = [node.get_hardware_version().code]
        if not hw_version or hw_version[0] not in S2C_HW_VERSIONS:
            return False

        return True

    def _determine_best_updater_from_candidates_list_zigbee(self, candidates):
        """
        Determines which is the best updater node of the given list for a
        Zigbee network.

        Args:
            candidates (List): List of possible XBee updater devices.

        Returns:
            :class:`.AbstractXBeeDevice`: Best updater XBee, `None` if no
                candidate found.
        """
        if candidates:
            # Check if it is the local device.
            if len(candidates) == 1 and candidates[0] == self._local:
                return self._local
            # Iterate the list of updater candidates performing a loopback test.
            # Return the first successful one.
            for candidate in candidates:
                loopback_test = _LoopbackTest(self._local, candidate)
                if loopback_test.execute_test():
                    return candidate
        return None

    def _determine_best_updater_from_candidates_list_digimesh(self, candidates):
        """
        Determines which is the best updater node of the given list for a
        DigiMesh network.

        Args:
            candidates (List): List of possible XBee updater devices.

        Returns:
            :class:`.AbstractXBeeDevice`: Best updater XBee, `None` if no
                candidate found.
        """
        if candidates:
            # Check if it is the local device.
            if len(candidates) == 1 and candidates[0] == self._local:
                return self._local
            # Iterate the list of updater candidates and test each one.
            for candidate in candidates:
                # First perform a Trace Route test and skip the candidate if
                # the remote device is in the route.
                traceroute_test = _TraceRouteTest(self._local, candidate, self._remote)
                if not traceroute_test.execute_test():
                    continue
                # Second perform a loopback test against the candidate and
                # return it if the test passes.
                loopback_test = _LoopbackTest(self._local, candidate)
                if loopback_test.execute_test():
                    return candidate
        return None

    def _clear_updater_recovery_mode(self):
        """
        Clears the recovery mode of the updater device.

        Returns:
            Boolean: `True` if recovery mode was successfully cleared in
                updater, `False` otherwise.
        """
        _log.debug("Clearing recovery mode from updater device...")
        # Frame ID must be greater than 2 for OTA commands, otherwise response
        # will be processed incorrectly.
        packet = RemoteATCommandPacket(
            3, self._updater.get_64bit_addr(), self._updater.get_16bit_addr(),
            RemoteATCmdOptions.NONE.value, ATStringCommand.PERCENT_U.command,
            parameter=bytearray([0]))
        retries = self.__CLEAR_UPDATER_RECOVERY_RETRIES
        recovery_cleared = False
        while not recovery_cleared and retries > 0:
            try:
                response = self._local.send_packet_sync_and_get_response(packet)
                if (not response
                        or not isinstance(response, RemoteATCommandResponsePacket)
                        or response.status != ATCommandStatus.OK):
                    _log.warning("Invalid 'clear recovery' command answer: %s",
                                 response.status.description)
                    retries -= 1
                    time.sleep(1)
                else:
                    recovery_cleared = True
            except XBeeException as exc:
                _log.warning("Could not send 'clear recovery' command: %s", str(exc))
                retries -= 1
                time.sleep(1)
        if not recovery_cleared:
            _log.warning("Could not send 'clear recovery' command after %s retries",
                         self.__CLEAR_UPDATER_RECOVERY_RETRIES)
        return recovery_cleared

    def _set_updater_recovery_mode(self):
        """
        Puts the updater device in recovery mode.

        Returns:
            Boolean: `True` if recovery mode was successfully set in updater,
                `False` otherwise.
        """
        _log.debug("Setting updater device in recovery mode...")
        # Frame ID must be greater than 2 for OTA commands, otherwise response
        # are incorrectly processed.
        packet = RemoteATCommandPacket(
            3, self._updater.get_64bit_addr(), self._updater.get_16bit_addr(),
            RemoteATCmdOptions.NONE.value, ATStringCommand.PERCENT_U.command,
            self._remote.get_64bit_addr().address)
        retries = self.__SET_UPDATER_RECOVERY_RETRIES
        recovery_set = False
        while not recovery_set and retries > 0:
            # Clear vars.
            self._receive_lock.clear()
            self._ota_packet_received = False
            self._expected_ota_block = -1
            self._ota_msg_type = None
            try:
                response = self._local.send_packet_sync_and_get_response(packet)
                if (not response
                        or not isinstance(response, RemoteATCommandResponsePacket)
                        or response.status != ATCommandStatus.OK):
                    if not response:
                        _log.warning("Answer for 'set recovery' command not received")
                    else:
                        _log.warning("Invalid 'set recovery' command answer: %s",
                                     response.status.description)
                    return False
                # Register OTA callback.
                self._local.add_packet_received_callback(self._ota_callback)
                # Wait for answer.
                self._receive_lock.wait(self._timeout)
                # Remove frame listener.
                self._local.del_packet_received_callback(self._ota_callback)
                # Check if OTA answer was received.
                if (self._packet_received
                        and self._ota_msg_type == EmberBootloaderMessageType.QUERY_RESPONSE):
                    recovery_set = True
                else:
                    _log.warning(
                        "Invalid OTA message type for 'set recovery' command: %s",
                        self._ota_msg_type.description if self._ota_msg_type else "no OTA message")
                    retries -= 1
            except XBeeException as exc:
                _log.warning("Could not send 'set recovery' command: %s", str(exc))
                return False
        if not recovery_set:
            _log.warning("Could not send 'set recovery' command after %s retries",
                         self.__SET_UPDATER_RECOVERY_RETRIES)
        return recovery_set

    def _set_remote_programming_mode(self):
        """
        Puts the remote (target) device in programming mode.

        Returns:
            Boolean: `True` if programming mode was successfully set in
                remote device, `False` otherwise.
        """
        _log.debug("Setting remote device in programming mode...")
        # Frame ID must be greater than 2 for OTA commands, otherwise response
        # will be processed incorrectly.
        packet = RemoteATCommandPacket(
            3, self._remote.get_64bit_addr(), self._remote.get_16bit_addr(),
            RemoteATCmdOptions.NONE.value, ATStringCommand.PERCENT_P.command,
            _VALUE_PRESERVE_NETWORK_SETTINGS)
        try:
            response = self._local.send_packet_sync_and_get_response(packet)
            if (not response
                    or not isinstance(response, RemoteATCommandResponsePacket)
                    or response.status != ATCommandStatus.OK):
                if not response:
                    _log.warning("Answer for 'programming mode' command not received")
                else:
                    _log.warning("Invalid 'programming mode' command answer: %s",
                                 response.status.description)
                return False
            return True
        except XBeeException as exc:
            _log.warning("Could not send 'programming mode' command: %s", str(exc))
            return False

    def _ota_callback(self, frame):
        """
        Callback used to receive OTA firmware update process status frames.

        Args:
            frame (:class:`.XBeePacket`): Received XBee packet.
        """
        # If frame was already received, ignore this frame, just notify.
        if self._packet_received:
            self._receive_lock.set()
            return
        f_type = frame.get_frame_type()
        if f_type == ApiFrameType.OTA_FIRMWARE_UPDATE_STATUS:
            # Check received data.
            self._ota_msg_type = frame.bootloader_msg_type
            received_ota_block = frame.block_number
        elif f_type in (ApiFrameType.RECEIVE_PACKET,
                        ApiFrameType.EXPLICIT_RX_INDICATOR):
            # Check received data.
            data = frame.rf_data
            if len(data) < 10:
                return
            self._ota_msg_type = EmberBootloaderMessageType.get(data[0])
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
        Creates and returns an OTA firmware update explicit packet using the
        given parameters.

        Args:
            frame_id (Integer): Frame ID of the packet.
            payload (Bytearray): Packet payload.

        Returns:
            :class:.`ExplicitAddressingPacket`: Generated OTA packet.
        """
        return ExplicitAddressingPacket(
            frame_id, self._updater.get_64bit_addr(), self._updater.get_16bit_addr(),
            _EXPL_PACKET_ENDPOINT_DATA, _EXPL_PACKET_ENDPOINT_DATA,
            _EXPL_PACKET_CLUSTER_UPDATE_LOCAL_UPDATER
            if self._updater == self._local else _EXPL_PACKET_CLUSTER_UPDATE_REMOTE_UPDATER,
            _EXPL_PACKET_PROFILE_DIGI, _EXPL_PACKET_BROADCAST_RADIUS_MAX,
            _EXPL_PACKET_EXTENDED_TIMEOUT if self._local.get_protocol() == XBeeProtocol.ZIGBEE else 0x00,
            payload)

    def _send_initialization_cmd(self):
        """
        Sends the firmware transfer initialization command to the updater device.

        Returns:
            Boolean: `True` if the initialization command was sent successfully,
                `False` otherwise.
        """
        _log.debug("Sending firmware update initialization command...")
        # Clear vars.
        retries = self.__INIT_RETRIES
        init_succeed = False
        # Generate initialization packet.
        packet = self._create_ota_explicit_packet(0, _VALUE_INITIALIZATION_DATA)
        # Send initialization command.
        while not init_succeed and retries > 0:
            # Clear vars.
            self._receive_lock.clear()
            self._packet_received = False
            self._expected_ota_block = -1
            self._ota_msg_type = None
            # Register OTA callback.
            self._local.add_packet_received_callback(self._ota_callback)
            try:
                # Send frame.
                self._local.send_packet(packet)
                # Wait for answer.
                self._receive_lock.wait(self._timeout)
            except XBeeException as exc:
                _log.warning("Could not send initialization command: %s", str(exc))
                return False
            finally:
                # Remove frame listener.
                self._local.del_packet_received_callback(self._ota_callback)
            # Check if OTA answer was received.
            if (not self._packet_received
                    or self._ota_msg_type != EmberBootloaderMessageType.QUERY_RESPONSE):
                if not self._packet_received:
                    _log.warning("Answer for data initialization command not received")
                else:
                    _log.warning(
                        "Invalid answer for initialization command: %s",
                        self._ota_msg_type.description if self._ota_msg_type else "no OTA message")
                retries -= 1
                if retries > 0:
                    time.sleep(2)
            else:
                init_succeed = True
        if not init_succeed:
            _log.warning("Could not send initialization command after %s retries",
                         self.__INIT_RETRIES)
        return init_succeed

    def _send_firmware(self):
        """
        Sends the firmware to the updater device.

        Returns:
            Boolean: `True` if the firmware was sent successfully, `False` otherwise.
        """
        # Initialize vars.
        previous_percent = None
        ebl_file = _EBLFile(self._fw_file, self.__DEFAULT_PAGE_SIZE)
        # Send firmware in chunks.
        for data_chunk in ebl_file.get_next_mem_page():
            if ebl_file.percent != previous_percent:
                self._notify_progress(self._progress_task, ebl_file.percent)
                previous_percent = ebl_file.percent
            _log.debug("Sending chunk %d/%d %d%%", ebl_file.page_index + 1,
                       ebl_file.num_pages, ebl_file.percent)
            if not self._send_firmware_data(data_chunk, ebl_file):
                return False
            self._any_data_sent = True
        return True

    def _send_firmware_data(self, data, ebl_file):
        """
        Sends the given firmware data to the updater device.

        Args:
            Bytearray: Firmware data to send.
            ebl_file (:class:`._EBLFile`): Ebl file being transferred.

        Returns:
            Boolean: `True` if the firmware data was sent successfully,
                `False` otherwise.
        """
        # Clear vars.
        retries = self.__FW_DATA_RETRIES
        data_sent = False
        ota_block_number = (ebl_file.page_index + 1) & 0xFF  # Block number matches page index + 1
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
            self._ota_msg_type = None
            # Register OTA callback.
            self._local.add_packet_received_callback(self._ota_callback)
            try:
                # Send frame.
                self._local.send_packet(packet)
                # Wait for answer.
                self._receive_lock.wait(self._timeout)
            except XBeeException as exc:
                _log.warning("Could not send firmware data block %s: %s",
                             ota_block_number, str(exc))
                return False
            finally:
                # Remove frame listener.
                self._local.del_packet_received_callback(self._ota_callback)
            # Check if OTA answer was received.
            if (not self._packet_received
                    or self._ota_msg_type != EmberBootloaderMessageType.ACK):
                if not self._packet_received:
                    _log.warning("Answer for data block %s not received", ota_block_number)
                else:
                    _log.warning(
                        "Invalid answer for data block %s: %s", ota_block_number,
                        self._ota_msg_type.description if self._ota_msg_type else "no OTA message")
                retries -= 1
                if retries > 0:
                    time.sleep(0.5)
            else:
                data_sent = True
        if not data_sent:
            _log.warning("Could not send data block %s after %s retries",
                         ota_block_number, self.__FW_DATA_RETRIES)
        return data_sent

    def _start_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._start_firmware_update`
        """
        # Test connectivity with remote device.
        if self._local.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # There is not a test for 802.15.4, assume connection with device works.
            connectivity_test_success = True
        elif self._local.get_protocol() == XBeeProtocol.DIGI_MESH:
            link_test = _LinkTest(self._local, self._remote, self._updater)
            connectivity_test_success = link_test.execute_test()
        else:
            loopback_test = _LoopbackTest(self._local, self._remote)
            connectivity_test_success = loopback_test.execute_test()
        if not connectivity_test_success:
            if not self._force_update:
                self._exit_with_error(_ERROR_COMMUNICATION_TEST)
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
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._transfer_firmware`
        """
        _log.info("%s - %s", self._remote, _PROGRESS_TASK_UPDATE_REMOTE_XBEE)
        # Reset variables.
        self._progress_task = _PROGRESS_TASK_UPDATE_REMOTE_XBEE
        retries = self.__FW_UPDATE_RETRIES
        firmware_updated = False
        while not firmware_updated and retries > 0:
            # Reset variables.
            self._any_data_sent = False
            # Initialize transfer.
            if not self._send_initialization_cmd():
                self._exit_with_error(_ERROR_INITIALIZE_PROCESS)
            # Send the firmware.
            if not self._send_firmware():
                # Recover the module.
                if self._any_data_sent:
                    # Wait for the bootloader to reset.
                    time.sleep(6)
                if not self._set_updater_recovery_mode():
                    self._clear_updater_recovery_mode()
                    self._exit_with_error(_ERROR_RECOVERY_MODE)
                retries -= 1
            else:
                firmware_updated = True
        if not firmware_updated:
            self._exit_with_error(_ERROR_FW_UPDATE_RETRIES % self.__FW_UPDATE_RETRIES)

    def _finish_firmware_update(self):
        """
        Override.

        .. seealso::
           | :meth:`._XBeeFirmwareUpdater._finish_firmware_update`
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
            self._local.send_packet(packet_1)
        except XBeeException as exc:
            _log.warning("Could not send first finalize update frame: %s", str(exc))
            both_frames_sent = False
        # Wait some time before sending the second frame.
        time.sleep(2)
        # Send second frame, do not wait for answer.
        try:
            self._local.send_packet(packet_2)
        except XBeeException as exc:
            _log.warning("Could not send second finalize update frame: %s", str(exc))
            both_frames_sent = False
        if not both_frames_sent:
            self._exit_with_error(_ERROR_FINISH_PROCESS)


class FwUpdateTask:
    """
    This class represents a firmware update process for a given XBee.
    """

    def __init__(self, xbee, xml_fw_path, fw_path=None, bl_fw_path=None,
                 timeout=None, progress_cb=None):
        """
        Class constructor. Instantiates a new :class:`.FwUpdateTask` object.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): XBee to update.
            xml_fw_path (String): Path of the XML file that describes the firmware.
            fw_path (String, optional): Location of the XBee binary firmware file.
            bl_fw_path (String, optional): Location of the bootloader binary
                firmware file.
            timeout (Integer, optional): Serial port read data timeout.
            progress_cb (Function, optional): Function to receive progress
               information. Receives two arguments:

                  * The current update task as a String
                  * The current update task percentage as an Integer

        Raises:
            ValueError: If the XBee device or the XML firmware file path are
                `None` or invalid. Also if the firmware binary file path or the
                bootloader file path are specified and does not exist.
        """
        # Sanity checks.
        if not isinstance(xbee, (XBeeDevice, RemoteXBeeDevice)):
            raise ValueError("Invalid XBee")
        if xml_fw_path is None:
            raise ValueError(_ERROR_FILE_NOT_SPECIFIED % "XML firmware")
        if not _file_exists(xml_fw_path):
            raise ValueError(_ERROR_FILE_NOT_FOUND % ("XML firmware", xml_fw_path))
        if fw_path is not None and not _file_exists(fw_path):
            raise ValueError(_ERROR_FILE_NOT_FOUND % ("XBee firmware", fw_path))
        if bl_fw_path is not None and not _file_exists(bl_fw_path):
            raise ValueError(_ERROR_FILE_NOT_FOUND % ("booloader firmware", bl_fw_path))

        self.__xbee = xbee
        self.__xml_path = xml_fw_path
        self.__fw_path = fw_path
        self.__bl_path = bl_fw_path
        self.__timeout = timeout
        self.__cb = progress_cb

    @property
    def xbee(self):
        """
        Gets the XBee for this task.

        Returns:
            :class:`.AbstractXBeeDevice`: The XBee to update.
        """
        return self.__xbee

    @property
    def xml_path(self):
        """
        Gets the XML firmware file path.

        Returns:
            String: The XML file path for the update task.
        """
        return self.__xml_path

    @property
    def fw_path(self):
        """
        Gets the binary firmware file path.

        Returns:
            String: The binary file path for the update task.
        """
        return self.__fw_path

    @property
    def bl_path(self):
        """
        Gets the bootloader file path.

        Returns:
            String: The bootloader file path for the update task.
        """
        return self.__bl_path

    @property
    def timeout(self):
        """
        Gets the maximum time to wait for read operations.

        Returns:
            Integer: The maximum time to wait for read operations.
        """
        return self.__timeout

    @property
    def callback(self):
        """
        Returns the function to receive progress status information.

        Returns:
             Function: The callback method to received progress information.
                `None` if not registered.
        """
        return self.__cb


def update_local_firmware(target, xml_fw_file, xbee_firmware_file=None,
                          bootloader_firmware_file=None, timeout=None,
                          progress_callback=None):
    """
    Performs a local firmware update operation in the given target.

    Args:
        target (String or :class:`.XBeeDevice`): Target of the firmware upload operation.
            String: serial port identifier.
            :class:`.XBeeDevice`: XBee to upload its firmware.
        xml_fw_file (String): Path of the XML file that describes the firmware.
        xbee_firmware_file (String, optional): Location of the XBee binary firmware file.
        bootloader_firmware_file (String, optional): Location of the bootloader
            binary firmware file.
        timeout (Integer, optional): Serial port read data timeout.
        progress_callback (Function, optional): Function to receive progress
            information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FirmwareUpdateException: If there is any error performing the firmware update.
    """
    # Sanity checks.
    if not isinstance(target, str) and not isinstance(target, XBeeDevice):
        _log.error("ERROR: %s", _ERROR_TARGET_INVALID)
        raise FirmwareUpdateException(_ERROR_TARGET_INVALID)
    if xml_fw_file is None:
        error = _ERROR_FILE_NOT_SPECIFIED % "XML firmware"
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if not _file_exists(xml_fw_file):
        error = _ERROR_FILE_NOT_FOUND % ("XML firmware", xml_fw_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if xbee_firmware_file is not None and not _file_exists(xbee_firmware_file):
        error = _ERROR_FILE_NOT_FOUND % ("XBee firmware", xbee_firmware_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if bootloader_firmware_file is not None and not _file_exists(bootloader_firmware_file):
        error = _ERROR_FILE_NOT_FOUND % ("bootloader firmware", bootloader_firmware_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)

    if isinstance(target, XBeeDevice):
        hw_version = target.get_hardware_version()
        if hw_version and hw_version.code not in LOCAL_SUPPORTED_HW_VERSIONS:
            raise OperationNotSupportedException(
                "Firmware update only supported in XBee 3, XBee SX 868/900, "
                "and XBee XR 868/900"
            )

    # Launch the update process.
    if not timeout:
        timeout = _READ_DATA_TIMEOUT

    if (isinstance(target, XBeeDevice) and target.comm_iface
            and target.comm_iface.supports_update_firmware()):
        target.comm_iface.update_firmware(
            target, xml_fw_file, xbee_fw_file=xbee_firmware_file,
            bootloader_fw_file=bootloader_firmware_file, timeout=timeout,
            progress_callback=progress_callback)
        return

    if isinstance(target, XBeeDevice) and not target._active_update_type:
        target._active_update_type = NodeUpdateType.FIRMWARE
    bootloader_type = _determine_bootloader_type(target)
    if bootloader_type in (
        _BootloaderType.GECKO_BOOTLOADER,
        _BootloaderType.GECKO_BOOTLOADER_XR,
    ):
        update_process = _LocalXBee3FirmwareUpdater(
            target, xml_fw_file, xbee_fw_file=xbee_firmware_file,
            bootloader_fw_file=bootloader_firmware_file,
            timeout=timeout, progress_cb=progress_callback)
    elif bootloader_type == _BootloaderType.GEN3_BOOTLOADER:
        update_process = _LocalXBeeGEN3FirmwareUpdater(
            target, xml_fw_file, xbee_fw_file=xbee_firmware_file,
            timeout=timeout, progress_cb=progress_callback)
    else:
        # Bootloader not supported.
        if (isinstance(target, XBeeDevice)
                and target._active_update_type == NodeUpdateType.FIRMWARE):
            target._active_update_type = None
        _log.error("ERROR: %s", _ERROR_BOOTLOADER_NOT_SUPPORTED)
        raise FirmwareUpdateException(_ERROR_BOOTLOADER_NOT_SUPPORTED)

    msg = "Success"
    try:
        update_process.update_firmware()
    except FirmwareUpdateException as exc:
        msg = "Error: %s" % exc
        raise exc
    finally:
        finished = (isinstance(target, str)
                    or target._active_update_type == NodeUpdateType.FIRMWARE)
        if finished or msg != "Success":
            update_process._notify_progress(msg, 100, finished=finished)


def update_remote_firmware(remote, xml_fw_file, firmware_file=None, bootloader_file=None,
                           max_block_size=0, timeout=None, progress_callback=None):
    """
    Performs a remote firmware update operation in the given target.

    Args:
        remote (:class:`.RemoteXBeeDevice`): Remote XBee to upload.
        xml_fw_file (String): Path of the XML file that describes the firmware.
        firmware_file (String, optional): Path of the binary firmware file.
        bootloader_file (String, optional): Path of the bootloader firmware file.
        max_block_size (Integer, optional): Maximum size of the ota block to send.
        timeout (Integer, optional): Timeout to wait for remote frame requests.
        progress_callback (Function, optional): Function to receive progress
            information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FirmwareUpdateException: if there is any error performing the remote
            firmware update.
    """
    # Sanity checks.
    if not isinstance(remote, RemoteXBeeDevice):
        _log.error("ERROR: %s", _ERROR_REMOTE_DEVICE_INVALID)
        raise FirmwareUpdateException(_ERROR_TARGET_INVALID)
    if xml_fw_file is None:
        error = _ERROR_FILE_NOT_SPECIFIED % "XML firmware"
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if not _file_exists(xml_fw_file):
        error = _ERROR_FILE_NOT_FOUND % ("XML firmware", xml_fw_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if firmware_file is not None and not _file_exists(firmware_file):
        error = _ERROR_FILE_NOT_FOUND % ("XBee firmware", firmware_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if bootloader_file is not None and not _file_exists(bootloader_file):
        error = _ERROR_FILE_NOT_FOUND % ("XBee firmware", bootloader_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if not isinstance(max_block_size, int):
        raise ValueError("Maximum block size must be an integer")
    if max_block_size < 0 or max_block_size > 255:
        raise ValueError("Maximum block size must be between 0 and 255")

    hw_version = remote.get_hardware_version()
    if hw_version and hw_version.code not in REMOTE_SUPPORTED_HW_VERSIONS:
        raise OperationNotSupportedException(
            "Firmware update only supported in XBee 3, XBee SX 868/900, "
            "XBee S2C, and XBee XR 868/900 devices"
        )

    # Launch the update process.
    if not timeout:
        timeout = _REMOTE_FW_UPDATE_DEFAULT_TIMEOUT

    comm_iface = remote.get_comm_iface()
    if comm_iface and comm_iface.supports_update_firmware():
        comm_iface.update_firmware(
            remote, xml_fw_file, xbee_fw_file=firmware_file,
            bootloader_fw_file=bootloader_file, timeout=timeout,
            progress_callback=progress_callback)
        return

    if not remote._active_update_type:
        remote._active_update_type = NodeUpdateType.FIRMWARE

    orig_op_timeout = remote.get_sync_ops_timeout()
    remote.set_sync_ops_timeout(max(orig_op_timeout, timeout))
    bootloader_type = _determine_bootloader_type(remote)
    remote.set_sync_ops_timeout(orig_op_timeout)
    if bootloader_type.ota_method == OTAMethod.ZCL:
        update_process = _RemoteXBee3FirmwareUpdater(
            remote, xml_fw_file, ota_fw_file=firmware_file,
            otb_fw_file=bootloader_file, timeout=timeout,
            max_block_size=max_block_size, progress_cb=progress_callback)
    elif bootloader_type.ota_method == OTAMethod.GPM:
        update_process = _RemoteGPMFirmwareUpdater(
            remote, xml_fw_file, xbee_fw_file=firmware_file,
            timeout=timeout, progress_cb=progress_callback,
            bootloader_type=bootloader_type)
    elif bootloader_type.ota_method == OTAMethod.EMBER:
        update_process = _RemoteEmberFirmwareUpdater(
            remote, xml_fw_file, xbee_fw_file=firmware_file,
            timeout=timeout, force_update=True, progress_cb=progress_callback)
    else:
        # Bootloader not supported.
        if remote._active_update_type == NodeUpdateType.FIRMWARE:
            remote._active_update_type = None
        _log.error("ERROR: %s", _ERROR_BOOTLOADER_NOT_SUPPORTED)
        raise FirmwareUpdateException(_ERROR_BOOTLOADER_NOT_SUPPORTED)

    orig_protocol = remote.get_protocol()
    configurer = UpdateConfigurer(remote, timeout=timeout,
                                  callback=progress_callback)
    if remote._active_update_type != NodeUpdateType.PROFILE:
        try:
            configurer.prepare_for_update(restore_later=False)
        except XBeeException as exc:
            raise FirmwareUpdateException(str(exc)) from None
    msg = "Success"
    try:
        update_process.update_firmware()
    except FirmwareUpdateException as exc:
        msg = "Error: %s" % exc
        raise exc
    finally:
        configurer.restore_after_update(
            restore_settings=not update_process.check_protocol_changed_by_fw(orig_protocol))
        finished = remote._active_update_type == NodeUpdateType.FIRMWARE
        if finished or msg != "Success":
            update_process._notify_progress(msg, 100, finished=finished)


def update_remote_filesystem(remote, ota_fs_file, max_block_size=0, timeout=None,
                             progress_callback=None):
    """
    Performs a remote filesystem update operation in the given target.

    Args:
        remote (:class:`.RemoteXBeeDevice`): Remote XBee to update its filesystem.
        ota_fs_file (String): Path of the OTA filesystem image file.
        max_block_size (Integer, optional): Maximum size of the ota block to send.
        timeout (Integer, optional): Timeout to wait for remote frame requests.
        progress_callback (Function, optional): Function to receive progress
            information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FirmwareUpdateException: If there is any error updating the remote
            filesystem image.
    """
    # Sanity checks.
    if not isinstance(remote, RemoteXBeeDevice):
        _log.error("ERROR: %s", _ERROR_REMOTE_DEVICE_INVALID)
        raise FirmwareUpdateException(_ERROR_REMOTE_DEVICE_INVALID)
    if ota_fs_file is None:
        error = _ERROR_FILE_NOT_SPECIFIED % "OTA filesystem image"
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if not _file_exists(ota_fs_file):
        error = _ERROR_FILE_NOT_FOUND % ("OTA filesystem image", ota_fs_file)
        _log.error("ERROR: %s", error)
        raise FirmwareUpdateException(error)
    if not isinstance(max_block_size, int):
        raise ValueError("Maximum block size must be an integer")
    if max_block_size < 0 or max_block_size > 255:
        raise ValueError("Maximum block size must be between 0 and 255")

    # Launch the update process.
    if not timeout:
        timeout = _REMOTE_FW_UPDATE_DEFAULT_TIMEOUT
    if not remote._active_update_type:
        remote._active_update_type = NodeUpdateType.FILESYSTEM
    update_process = _RemoteFilesystemUpdater(
        remote, ota_fs_file, timeout=timeout, max_block_size=max_block_size,
        progress_cb=progress_callback)
    configurer = UpdateConfigurer(remote, timeout=timeout,
                                  callback=progress_callback)
    if remote._active_update_type == NodeUpdateType.FILESYSTEM:
        try:
            configurer.prepare_for_update(restore_later=False)
        except XBeeException as exc:
            raise FirmwareUpdateException(str(exc)) from None
    msg = "Success"
    try:
        update_process.update_firmware()
    except FirmwareUpdateException as exc:
        msg = "Error: %s" % exc
        raise exc
    finally:
        configurer.restore_after_update()
        finished = remote._active_update_type == NodeUpdateType.FILESYSTEM
        if finished or msg != "Success":
            update_process._notify_progress(msg, 100, finished=finished)


def _file_exists(file):
    """
    Returns whether the given file path exists or not.

    Args:
        file (String): File path to check.

    Returns:
        Boolean: `True` if the path exists, `False` otherwise
    """
    if file is None:
        return False

    return os.path.isfile(file)


def _bootloader_version_to_bytearray(bootloader_version):
    """
    Transforms the given bootloader version in string format into a byte array.

    Args:
        bootloader_version (String): Bootloader version as string.

    Returns:
        Bytearray: Bootloader version as byte array, `None` if transformation failed.
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
         Integer: Current time in milliseconds.
    """
    return int(time.time() * 1000.0)


def _connect_device_with_retries(xbee_device, retries):
    """
    Attempts to connect the XBee with the given number of retries.

    Args:
        xbee_device (:class:`.AbstractXBeeDevice`): XBee to connect.
        retries (Integer): Number of connection retries.

    Returns:
        Boolean: `True` if the device connected, `False` otherwise.
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


def _get_parameter_with_retries(xbee, parameter, retries=_PARAM_READ_RETRIES):
    """
    Reads the given parameter from the XBee with the given number of retries.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.
        parameter (String or :class: `ATStringCommand`): Parameter to read.
        retries (Integer, optional): Number of retries to perform after a
            :class:`.TimeoutException`

    Returns:
        Bytearray: Read parameter value, `None` if the parameter could not be read.
    """
    if xbee is None:
        return None

    while retries > 0:
        try:
            return xbee.get_parameter(parameter, apply=False)
        except XBeeException:
            retries -= 1
            if retries != 0:
                time.sleep(1)

    return None


def _set_parameter_with_retries(xbee, parameter, value,
                                apply=False, retries=_PARAM_SET_RETRIES):
    """
    Reads the given parameter from the XBee with the given number of retries.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.
        parameter (String or :class: `ATStringCommand`): Parameter to set.
        value (Bytearray): Parameter value.
        apply (Boolean, optional, default=`False`): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.
        retries (Integer, optional): Number of retries to perform after a
            :class:`.TimeoutException`

    Returns:
        Boolean: `True` if the parameter was correctly set, `False` otherwise.
    """
    if xbee is None:
        return False

    while retries > 0:
        try:
            xbee.set_parameter(parameter, value, apply=apply)
            return True
        except XBeeException:
            retries -= 1
            if retries != 0:
                time.sleep(1)
    return False


def _get_bootloader_version(xbee):
    """
    Returns the bootloader version of the given XBee

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.

    Returns:
        Bytearray: XBee bootloader version as byte array, `None` if it could not be read.
    """
    bootloader_version_array = bytearray(3)
    bootloader_version = _get_parameter_with_retries(xbee, _PARAM_BOOTLOADER_VERSION,
                                                     _PARAM_READ_RETRIES)
    if bootloader_version is None or len(bootloader_version) < 2:
        return None
    if len(bootloader_version) == 3:
        # XR returns VH value as three bytes: 0XYYZZ.
        return bootloader_version

    bootloader_version_array[0] = bootloader_version[0] & 0x0F
    bootloader_version_array[1] = (bootloader_version[1] & 0xF0) >> 4
    bootloader_version_array[2] = bootloader_version[1] & 0x0F

    return bootloader_version_array


def _get_compatibility_number(xbee):
    """
    Returns the compatibility number of the given XBee.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.

    Returns:
        Integer: XBee compatibility number as integer, `None` if it could not be read.
    """
    compatibility_number = _get_parameter_with_retries(
        xbee, ATStringCommand.PERCENT_C, _PARAM_READ_RETRIES)
    if compatibility_number is None:
        return None
    compatibility_number = utils.hex_to_string(compatibility_number)[0:2]

    return int(compatibility_number)


def _get_region_lock(xbee):
    """
    Returns the region lock number of the given XBee.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.

    Returns:
        :class:`.Region`: XBee region lock, `None` if it could not be read.
    """
    region_lock = _get_parameter_with_retries(
        xbee, ATStringCommand.R_QUESTION, _PARAM_READ_RETRIES)
    if region_lock is None:
        return None

    return Region.get(int(region_lock[0]))


def _get_hw_version(xbee):
    """
    Returns the hardware version of the given XBee.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.

    Returns:
        Integer: XBee hardware version as integer, `None` if it could not be read.
    """
    hardware_version = _get_parameter_with_retries(
        xbee, ATStringCommand.HV, _PARAM_READ_RETRIES)
    if hardware_version is None:
        return None

    return int(hardware_version[0])


def _get_fw_version(xbee):
    """
    Returns the firmware version of the given XBee.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to read the parameter from.

    Returns:
        Integer: XBee firmware version as integer, `None` if it could not be read.
    """
    firmware_version = _get_parameter_with_retries(
        xbee, ATStringCommand.VR, _PARAM_READ_RETRIES)
    if firmware_version is None:
        return None

    return utils.bytes_to_int(firmware_version)


def _reverse_bytearray(byte_array):
    """
    Reverses the given byte array order.

    Args:
        byte_array (Bytearray): Byte array to reverse.

    Returns:
        Bytearray: Reversed byte array.
    """
    return bytearray(list(reversed(byte_array)))


def _create_serial_port(port_name, serial_params):
    """
    Creates a serial port object with the given parameters.

    Args:
        port_name (String): Name of the serial port.
        serial_params (Dictionary): Serial port parameters as a dictionary.

    Returns:
        :class:`.XBeeSerialPort`: Serial port created with the given parameters.
    """
    return XBeeSerialPort(serial_params["baudrate"],
                          port_name,
                          data_bits=serial_params["bytesize"],
                          stop_bits=serial_params["stopbits"],
                          parity=serial_params["parity"],
                          flow_control=FlowControl.NONE if not serial_params["rtscts"] else
                          FlowControl.HARDWARE_RTS_CTS,
                          timeout=serial_params["timeout"])


def _read_bootloader_header_generic(serial_port, test_char):
    """
    Attempts to read the bootloader header.

    Args:
        serial_port (:class:`.XBeeSerialPort`): Serial port to communicate with.
        test_char (String): Test character to send and check bootloader is active.

    Returns:
        String: Bootloader header, `None` if it could not be read.
    """
    try:
        serial_port.purge_port()
        serial_port.write(str.encode(test_char, encoding='utf8', errors='ignore'))
        read_bytes = serial_port.read(_READ_BUFFER_LEN)
    except SerialException as exc:
        _log.exception(exc)
        return None

    if not read_bytes:
        return None

    try:
        return str(read_bytes, encoding='utf8', errors='strict')
    except UnicodeDecodeError:
        return None


def _is_bootloader_active_generic(serial_port, test_char, bootloader_prompt):
    """
    Returns whether the device is in bootloader mode or not.

    Args:
        serial_port (:class:`.XBeeSerialPort`): Serial port to communicate with.
        test_char (String): Test character to send and check bootloader is active.
        bootloader_prompt (String): Expected bootloader prompt.

    Returns:
        Boolean: `True` if the device is in bootloader mode, `False` otherwise.
    """
    for _ in range(3):
        bootloader_header = _read_bootloader_header_generic(serial_port, test_char)
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
        target (String or :class:`.AbstractXBeeDevice`): Target of the firmware
            upload operation.
            String: serial port identifier.
            :class:`.AbstractXBeeDevice`: XBee to upload its firmware.

    Return:
        :class:`._BootloaderType`: Bootloader type of the connected target.

    Raises:
        FirmwareUpdateException: If it cannot determine the bootloader type.
    """
    if not isinstance(target, str):
        # An XBee was given. Bootloader type is determined using the device hardware version.
        try:
            was_connected = True
            if not target.is_remote() and not target.is_open():
                target.open()
                was_connected = False
            hardware_version = _get_hw_version(target)
            if not target.is_remote() and not was_connected:
                target.close()
            return _BootloaderType.determine_bootloader_type(hardware_version)
        except XBeeException as exc:
            if target._active_update_type == NodeUpdateType.FIRMWARE:
                target._active_update_type = None
            raise FirmwareUpdateException(_ERROR_DETERMINE_BOOTLOADER_TYPE % str(exc)) from exc
    else:
        # A serial port was given, determine the bootloader by testing prompts and baud rates.
        # -- 1 -- Check if bootloader is active.
        # Create a serial port object. Start with 38400 bps for GEN3 bootloaders.
        try:
            port = _create_serial_port(target, _GEN3_BOOTLOADER_PORT_PARAMS)
            port.open()
        except SerialException as exc:
            _log.error(_ERROR_CONNECT_SERIAL_PORT, str(exc))
            raise FirmwareUpdateException(_ERROR_DETERMINE_BOOTLOADER_TYPE % str(exc)) from exc
        # Check if GEN3 bootloader is active.
        if _is_bootloader_active_generic(
                port, _GEN3_BOOTLOADER_TEST_CHAR, _GEN3_BOOTLOADER_PROMPT):
            port.close()
            return _BootloaderType.GEN3_BOOTLOADER
        # Check if GECKO bootloader is active.
        port.apply_settings(_GECKO_BOOTLOADER_PORT_PARAMS)
        if _is_bootloader_active_generic(
                port, _GECKO_BOOTLOADER_TEST_CHAR, _GECKO_BOOTLOADER_PROMPT):
            port.close()
            return _BootloaderType.GECKO_BOOTLOADER

        # -- 2 -- Bootloader is not active, force bootloader mode.
        break_thread = _BreakThread(port, _DEVICE_BREAK_RESET_TIMEOUT)
        break_thread.start()
        # Loop during some time looking for the bootloader prompt.
        deadline = _get_milliseconds() + (_BOOTLOADER_TIMEOUT * 1000)
        bootloader_type = None
        while _get_milliseconds() < deadline:
            # Check GEN3 bootloader prompt.
            port.apply_settings(_GEN3_BOOTLOADER_PORT_PARAMS)
            if _is_bootloader_active_generic(
                    port, _GEN3_BOOTLOADER_TEST_CHAR, _GEN3_BOOTLOADER_PROMPT):
                bootloader_type = _BootloaderType.GEN3_BOOTLOADER
                break
            # Check GECKO bootloader prompt.
            port.apply_settings(_GECKO_BOOTLOADER_PORT_PARAMS)
            if _is_bootloader_active_generic(
                    port, _GECKO_BOOTLOADER_TEST_CHAR, _GECKO_BOOTLOADER_PROMPT):
                bootloader_type = _BootloaderType.GECKO_BOOTLOADER
                break
            # Re-assert lines to try break process again until timeout expires.
            if not break_thread.is_running():
                port.rts = 0
                break_thread = _BreakThread(port, _DEVICE_BREAK_RESET_TIMEOUT)
                break_thread.start()
        # Restore break condition.
        if break_thread.is_running():
            break_thread.stop_break()

        port.close()
        return bootloader_type


def _enable_explicit_mode(xbee):
    """
    Enables explicit mode by modifying the value of 'AO' parameter if it is
    needed.

    Args:
        xbee (:class:`.AbstractXBeeDevice`): XBee to configure.

    Returns:
        Tuple (Boolean, Bytearray): A tuple with a boolean value indicating
            if the operation finished successfully, and a bytearray with the
            original value of 'AO' parameter. If the last is `None` means the
            value has not been changed.
    """
    # Store AO value.
    ao_value = _get_parameter_with_retries(xbee, ATStringCommand.AO)
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

    if not _set_parameter_with_retries(
            xbee, ATStringCommand.AO, value, apply=True):
        return False, ao_value

    return True, ao_value
