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
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import fnmatch
import logging
import os
import shutil
import tempfile
import time

from enum import Enum, unique
from pathlib import Path
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

import zipfile
import serial

from digi.xbee.firmware import UpdateConfigurer, EXTENSION_GBL, EXTENSION_XML, \
    EXTENSION_EBIN, EXTENSION_EHX2, EXTENSION_OTB, EXTENSION_OTA, \
    EXTENSION_EBL, update_local_firmware, update_remote_firmware, \
    SX_HW_VERSIONS
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice, NetworkEventReason, \
    DigiMeshDevice, DigiPointDevice
from digi.xbee.exception import XBeeException, FirmwareUpdateException, \
    InvalidOperatingModeException
from digi.xbee.filesystem import LocalXBeeFileSystemManager, \
    FileSystemException, FileSystemNotSupportedException, check_fs_support, \
    XB3_MIN_FW_VERSION_FS_API_SUPPORT, update_remote_filesystem_image
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion, LegacyHardwareVersion
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.models.status import UpdateProgressStatus, NodeUpdateType
from digi.xbee.util import utils

_ERROR_TARGET_INVALID = "Invalid update target"
_ERROR_FS_NOT_SUPPORTED = "XBee device does not have file system support"
_ERROR_FW_FOLDER_NOT_EXIST = "Firmware folder does not exist"
_ERROR_FW_NOT_COMPATIBLE = "The XBee profile is not compatible with the device firmware"
_ERROR_FW_XML_INVALID = "Invalid firmware XML file contents: %s"
_ERROR_FW_XML_NOT_EXIST = "Firmware XML file does not exist"
_ERROR_FW_XML_PARSE = "Error parsing firmware XML file: %s"
_ERROR_HW_NOT_COMPATIBLE = "The XBee profile is not compatible with the device  hardware"
_ERROR_OPEN_DEVICE = "Error opening XBee device: %s"
_ERROR_PROFILE_NOT_VALID = "The XBee profile is not valid"
_ERROR_PROFILE_INVALID = "Invalid XBee profile: %s"
_ERROR_PROFILE_PATH_INVALID = "Profile path '%s' is not valid"
_ERROR_PROFILE_READ = "Error reading profile: %s"
_ERROR_PROFILE_UNCOMPRESS = "Error opening profile: %s"
_ERROR_PROFILE_OPEN = "Error opening profile, unable to create temporary directory: %s"
_ERROR_PROFILE_XML_NOT_EXIST = "Profile XML file does not exist"
_ERROR_PROFILE_XML_INVALID = "Invalid profile XML file contents: %s"
_ERROR_PROFILE_XML_PARSE = "Error parsing profile XML file: %s"
_ERROR_READ_REMOTE_PARAMETER = "Error reading remote parameter: %s"
_ERROR_UPDATE_FS = "Error updating XBee filesystem: %s"
_ERROR_UPDATE_FW = "Error updating XBee firmware: %s"
_ERROR_UPDATE_SETTINGS = "Error updating XBee settings: %s"
_ERROR_PROTOCOL_CHANGE = "Cannot %s as the protocol changed and it is no" \
                         " longer reachable"

_REMOTE_DEFAULT_TIMEOUT = 20  # Seconds
_LOCAL_DEFAULT_TIMEOUT = 3  # Seconds.

_LOCAL_FS_DIR = "filesystem"
_REMOTE_FS_DIR = "remote_filesystem"

_FW_DIR_NAME = "radio_fw"

_IPV4_SEPARATOR = "."
_IPV6_SEPARATOR = ":"

_PARAM_READ_RETRIES = 3
_PARAM_WRITE_RETRIES = 3
_PARAMS_SERIAL_PORT = [ATStringCommand.BD.command,
                       ATStringCommand.NB.command,
                       ATStringCommand.SB.command,
                       ATStringCommand.D7.command]
_PARAMS_CACHE = [ATStringCommand.NI.command,
                 ATStringCommand.CE.command,
                 ATStringCommand.SM.command,
                 ATStringCommand.BR.command,  # This may affect the role
                 ATStringCommand.MY.command]
_PARAMS_NETWORK = [ATStringCommand.ID.command,
                   ATStringCommand.CH.command,
                   ATStringCommand.HP.command,
                   ATStringCommand.CM.command,
                   ATStringCommand.BR.command,
                   ATStringCommand.EE.command,
                   ATStringCommand.KY.command]


_PROFILE_XML_FILE_NAME = "profile%s" % EXTENSION_XML

_TASK_CONNECT_FILESYSTEM = "Connecting with device filesystem"
_TASK_FORMAT_FILESYSTEM = "Formatting filesystem"
_TASK_UPDATE_FILE = "Updating file '%s'"
_TASK_UPDATE_SETTINGS = "Updating XBee settings"

_VALUE_CTS_ON = "1"

_WILDCARD_BOOTLOADER = "xb3-boot*%s" % EXTENSION_GBL
_WILDCARD_CELLULAR_FIRMWARE = "fw_.*"
_WILDCARD_CELLULAR_BOOTLOADER = "bl_.*"
_WILDCARD_XML = "*%s" % EXTENSION_XML
_WILDCARDS_FW_LOCAL_BINARY_FILES = (EXTENSION_EBIN, EXTENSION_EHX2, EXTENSION_GBL)
_WILDCARDS_FW_REMOTE_BINARY_FILES = (
    EXTENSION_OTA, EXTENSION_OTB, EXTENSION_EBL, EXTENSION_EBIN, EXTENSION_GBL,
)

_XML_COMMAND = "command"
_XML_CONTROL_TYPE = "control_type"
_XML_DEFAULT_VALUE = "default_value"
_XML_FW_FIRMWARE = "firmware"
_XML_FW_FIRMWARE_VERSION = "fw_version"
_XML_FW_HARDWARE_VERSION = "firmware/hw_version"
_XML_COMPATIBILITY_NUMBER = "firmware/compatibility_number"
_XML_REGION_LOCK = "firmware/region"
_XML_FW_SETTING = ".//setting"
_XML_FORMAT = "format"
_XML_PROFILE_AT_SETTING = "profile/settings/setting"
_XML_PROFILE_DESC = "profile/description"
_XML_PROFILE_FLASH_FW_OPTION = "profile/flash_fw_action"
_XML_PROFILE_RESET_SETTINGS = "profile/reset_settings"
_XML_PROFILE_VERSION = "profile/profile_version"
_XML_PROFILE_XML_FW_FILE = "profile/description_file"


_log = logging.getLogger(__name__)


@unique
class FirmwareBaudrate(Enum):
    """
    This class lists the available firmware baudrate options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this `FirmwareBaudrate`.
    |     **value** (Integer): The ID of this `FirmwareBaudrate`.
    """
    BD_1200 = (0x0, 1200)
    BD_2400 = (0x1, 2400)
    BD_4800 = (0x2, 4800)
    BD_9600 = (0x3, 9600)
    BD_19200 = (0x4, 19200)
    BD_38400 = (0x5, 38400)
    BD_57600 = (0x6, 57600)
    BD_115200 = (0x7, 115200)
    BD_230400 = (0x8, 230400)
    BD_460800 = (0x9, 460800)
    BD_921600 = (0xA, 921600)

    def __init__(self, index, baudrate):
        self.__index = index
        self.__baudrate = baudrate

    @classmethod
    def get(cls, index):
        """
        Returns the `FirmwareBaudrate` for the given index.

        Args:
            index (Integer): Index of the `FirmwareBaudrate` to get.

        Returns:
            :class:`.FirmwareBaudrate`: `FirmwareBaudrate` with the given
                index, `None` if there is not a `FirmwareBaudrate` with that
                index.
        """
        if index is None:
            return FirmwareBaudrate.BD_9600
        for value in FirmwareBaudrate:
            if value.index == index:
                return value

        return None

    @classmethod
    def get_by_baudrate(cls, baudrate):
        """
        Returns the `FirmwareBaudrate` for the given baudrate.

        Args:
            baudrate (Integer): Baudrate value of the `FirmwareBaudrate` to get.

        Returns:
            :class:`.FirmwareBaudrate`: `FirmwareBaudrate` with the given
                baudrate, `None` if there is not a `FirmwareBaudrate` with that
                baudrate.
        """
        if baudrate is None:
            return FirmwareBaudrate.BD_9600
        for value in FirmwareBaudrate:
            if value.baudrate == baudrate:
                return value

        return None

    @property
    def index(self):
        """
        Returns the index of the `FirmwareBaudrate` element.

        Returns:
            Integer: Index of the `FirmwareBaudrate` element.
        """
        return self.__index

    @property
    def baudrate(self):
        """
        Returns the baudrate of the `FirmwareBaudrate` element.

        Returns:
            Integer: Baudrate of the `FirmwareBaudrate` element.
        """
        return self.__baudrate


FirmwareBaudrate.__doc__ += utils.doc_enum(FirmwareBaudrate)


@unique
class FirmwareParity(Enum):
    """
    This class lists the available firmware parity options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this `FirmwareParity`.
    |     **value** (Integer): The ID of this `FirmwareParity`.
    """
    NONE = (0, serial.PARITY_NONE)
    EVEN = (1, serial.PARITY_EVEN)
    ODD = (2, serial.PARITY_ODD)
    MARK = (3, serial.PARITY_MARK)
    SPACE = (4, serial.PARITY_SPACE)

    def __init__(self, index, parity):
        self.__index = index
        self.__parity = parity

    @classmethod
    def get(cls, index):
        """
        Returns the `FirmwareParity` for the given index.

        Args:
            index (Integer): the index of the `FirmwareParity` to get.

        Returns:
            :class:`.FirmwareParity`: `FirmwareParity` with the given index,
                `None` if there is not a `FirmwareParity` with that index.
        """
        if index is None:
            return FirmwareParity.NONE
        for value in FirmwareParity:
            if value.index == index:
                return value

        return None

    @classmethod
    def get_by_parity(cls, parity):
        """
        Returns the `FirmwareParity` for the given parity.

        Args:
            parity (String): Parity value of the `FirmwareParity` to get.

        Returns:
            :class:`.FirmwareParity`: `FirmwareParity` with the given parity,
                `None` if there is not a `FirmwareParity` with that parity.
        """
        if parity is None:
            return FirmwareParity.NONE
        for value in FirmwareParity:
            if value.parity == parity:
                return value

        return None

    @property
    def index(self):
        """
        Returns the index of the `FirmwareParity` element.

        Returns:
            Integer: Index of the `FirmwareParity` element.
        """
        return self.__index

    @property
    def parity(self):
        """
        Returns the parity of the `FirmwareParity` element.

        Returns:
            String: Parity of the `FirmwareParity` element.
        """
        return self.__parity


FirmwareParity.__doc__ += utils.doc_enum(FirmwareParity)


@unique
class FirmwareStopbits(Enum):
    """
    This class lists the available firmware stop bits options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this `FirmwareStopbits`.
    |     **value** (Integer): The ID of this `FirmwareStopbits`.
    """
    SB_1 = (0, serial.STOPBITS_ONE)
    SB_2 = (1, serial.STOPBITS_TWO)
    SB_1_5 = (2, serial.STOPBITS_ONE_POINT_FIVE)

    def __init__(self, index, stop_bits):
        self.__index = index
        self.__stop_bits = stop_bits

    @classmethod
    def get(cls, index):
        """
        Returns the `FirmwareStopbits` for the given index.

        Args:
            index (Integer): Index of the `FirmwareStopbits` to get.

        Returns:
            :class:`.FirmwareStopbits`: `FirmwareStopbits` with the given
                index, `None` if there is not a `FirmwareStopbits` with that
                index.
        """
        if index is None:
            return FirmwareStopbits.SB_1
        for value in FirmwareStopbits:
            if value.index == index:
                return value

        return None

    @classmethod
    def get_by_stopbits(cls, stopbits):
        """
        Returns the `FirmwareStopbits` for the given number of stop bits.

        Args:
            stopbits (Integer): Stop bis value of the `FirmwareStopbits` to get.

        Returns:
            :class:`.FirmwareStopbits`: `FirmwareStopbits` with the given stop
                bits, `None` if there is not a `FirmwareStopbits` with that value.
        """
        if stopbits is None:
            return FirmwareStopbits.SB_1
        for value in FirmwareStopbits:
            if value.stop_bits == stopbits:
                return value

        return None

    @property
    def index(self):
        """
        Returns the index of the `FirmwareStopbits` element.

        Returns:
            Integer: Index of the `FirmwareStopbits` element.
        """
        return self.__index

    @property
    def stop_bits(self):
        """
        Returns the stop bits of the `FirmwareStopbits` element.

        Returns:
            Float: Stop bits of the `FirmwareStopbits` element.
        """
        return self.__stop_bits


FirmwareStopbits.__doc__ += utils.doc_enum(FirmwareStopbits)


@unique
class FlashFirmwareOption(Enum):
    """
    This class lists the available flash firmware options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this `FlashFirmwareOption`.
    |     **value** (Integer): The ID of this `FlashFirmwareOption`.
    """
    FLASH_ALWAYS = (0, "Flash always")
    FLASH_DIFFERENT = (1, "Flash firmware if it is different")
    DONT_FLASH = (2, "Do not flash firmware")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    @classmethod
    def get(cls, code):
        """
        Returns the `FlashFirmwareOption` for the given code.

        Args:
            code (Integer): Code of the flash firmware option to get.

        Returns:
            :class:`.FlashFirmwareOption`: `FlashFirmwareOption` with the
                given code, `None` if there is not a `FlashFirmwareOption` with
                that code.
        """
        for value in FlashFirmwareOption:
            if value.code == code:
                return value

        return None

    @property
    def code(self):
        """
        Returns the code of the `FlashFirmwareOption` element.

        Returns:
            Integer: Code of the `FlashFirmwareOption` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `FlashFirmwareOption` element.

        Returns:
            String: Description of the `FlashFirmwareOption` element.
        """
        return self.__description


FlashFirmwareOption.__doc__ += utils.doc_enum(FlashFirmwareOption)


@unique
class XBeeSettingType(Enum):
    """
    This class lists the available firmware setting types.

    | Inherited properties:
    |     **name** (String): The name of this `XBeeSettingType`.
    |     **value** (Integer): The ID of this `XBeeSettingType`.
    """
    NUMBER = ("number", "Number")
    COMBO = ("combo", "Combo")
    TEXT = ("text", "Text")
    BUTTON = ("button", "Button")
    NO_TYPE = ("none", "No type")

    def __init__(self, tag, description):
        self.__tag = tag
        self.__description = description

    @classmethod
    def get(cls, tag):
        """
        Returns the `XBeeSettingType` for the given tag.

        Args:
            tag (String): Tag of the `XBeeSettingType` to get.

        Returns:
            :class:`.XBeeSettingType`: `XBeeSettingType` with the given tag,
                `None` if there is not a `XBeeSettingType` with that tag.
        """
        for value in XBeeSettingType:
            if value.tag == tag:
                return value

        return None

    @property
    def tag(self):
        """
        Returns the tag of the `XBeeSettingType` element.

        Returns:
            String: Tag of the `XBeeSettingType` element.
        """
        return self.__tag

    @property
    def description(self):
        """
        Returns the description of the `XBeeSettingType` element.

        Returns:
            String: Description of the `XBeeSettingType` element.
        """
        return self.__description


XBeeSettingType.__doc__ += utils.doc_enum(XBeeSettingType)


@unique
class XBeeSettingFormat(Enum):
    """
    This class lists the available text firmware setting formats.

    | Inherited properties:
    |     **name** (String): The name of this `XBeeSettingFormat`.
    |     **value** (Integer): The ID of this `XBeeSettingFormat`.
    """
    HEX = ("HEX", "Hexadecimal")
    ASCII = ("ASCII", "ASCII")
    IPV4 = ("IPV4", "IPv4")
    IPV6 = ("IPV6", "IPv6")
    PHONE = ("PHONE", "phone")
    NO_FORMAT = ("none", "No format")

    def __init__(self, tag, description):
        self.__tag = tag
        self.__description = description

    @classmethod
    def get(cls, tag):
        """
        Returns the `XBeeSettingFormat` for the given tag.

        Args:
            tag (String): Tag of the `XBeeSettingFormat` to get.

        Returns:
            :class:`.XBeeSettingFormat`: `XBeeSettingFormat` with the given
                tag, `None` if there is not a `XBeeSettingFormat` with that tag.
        """
        for value in XBeeSettingFormat:
            if value.tag == tag:
                return value

        return None

    @property
    def tag(self):
        """
        Returns the tag of the `XBeeSettingFormat` element.

        Returns:
            String: Tag of the `XBeeSettingFormat` element.
        """
        return self.__tag

    @property
    def description(self):
        """
        Returns the description of the `XBeeSettingFormat` element.

        Returns:
            String: Description of the `XBeeSettingFormat` element.
        """
        return self.__description


XBeeSettingFormat.__doc__ += utils.doc_enum(XBeeSettingFormat)


class XBeeProfileSetting:
    """
    This class represents an XBee profile setting and provides information like
    the setting name, type, format and value.
    """

    def __init__(self, name, setting_type, setting_format, value):
        """
        Class constructor. Instantiates a new :class:`.XBeeProfileSetting`
        with the given parameters.

        Args:
            name (String): Setting name.
            setting_type (:class:`.XBeeSettingType`): Setting type.
            setting_format (:class:`.XBeeSettingType`): Setting format.
            value (String): Setting value.
        """
        self._name = name
        self._type = setting_type
        self._format = setting_format
        self._value = value
        self._bytearray_value = self._setting_value_to_bytearray()

    def _setting_value_to_bytearray(self):
        """
        Transforms the setting value to a byte array to be written in the XBee.

        Returns:
            (Bytearray): Setting value formatted as byte array
        """
        if self._type in (XBeeSettingType.COMBO, XBeeSettingType.NUMBER):
            return utils.hex_string_to_bytes(self._value)
        if self._type is XBeeSettingType.TEXT:
            if self._format in (XBeeSettingFormat.ASCII, XBeeSettingFormat.PHONE):
                return bytearray(self._value, encoding='utf8')
            if self._format in (XBeeSettingFormat.HEX, XBeeSettingFormat.NO_FORMAT):
                return utils.hex_string_to_bytes(self._value)
            if self._format is XBeeSettingFormat.IPV4:
                octets = list(map(int, self._value.split(_IPV4_SEPARATOR)))
                return bytearray(octets)
            if (self._format is XBeeSettingFormat.IPV6
                    and _IPV6_SEPARATOR in self._value):
                return bytearray(self._value, encoding='utf8')
        elif self._type in (XBeeSettingType.BUTTON, XBeeSettingType.NO_TYPE):
            return bytearray(0)

        return self._value

    @property
    def name(self):
        """
        Returns the XBee setting name.

        Returns:
            String: XBee setting name.
         """
        return self._name

    @property
    def type(self):
        """
        Returns the XBee setting type.

        Returns:
            :class:`.XBeeSettingType`: XBee setting type.
         """
        return self._type

    @property
    def format(self):
        """
        Returns the XBee setting format.

        Returns:
            :class:`.XBeeSettingFormat`: XBee setting format.
         """
        return self._format

    @property
    def value(self):
        """
        Returns the XBee setting value as string.

        Returns:
            String: XBee setting value as string.
         """
        return self._value

    @property
    def bytearray_value(self):
        """
        Returns the XBee setting value as bytearray to be set in the device.

        Returns:
            Bytearray: XBee setting value as bytearray to be set in the device.
         """
        return self._bytearray_value


class ReadProfileException(XBeeException):
    """
    This exception will be thrown when any problem reading the XBee profile
    occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """


class UpdateProfileException(XBeeException):
    """
    This exception will be thrown when any problem updating the XBee profile
    into a device occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """


class XBeeProfile:
    """
    Helper class used to manage serial port break line in a parallel thread.
    """

    def __init__(self, profile_file):
        """
        Class constructor. Instantiates a new :class:`.XBeeProfile` with the
        given parameters.

        Args:
            profile_file (String): Path of the '.xpro' profile file.

        Raises:
            ProfileReadException: If there is any error reading the profile file.
            ValueError: If the provided profile file is not valid
        """
        if not os.path.isfile(profile_file):
            raise ValueError(_ERROR_PROFILE_PATH_INVALID % profile_file)
        self._profile_file = profile_file
        self._profile_xml_file = None
        self._fw_xml_filename = None

        self._profile_dir = None
        self._fw_xml_file = None
        self._fs_path = None
        self._remote_fs_image = None
        self._bootloader_file = None
        self._cellular_fw_files = []
        self._cellular_bootloader_files = []

        self._version = 0
        self._flash_fw_option = FlashFirmwareOption.FLASH_DIFFERENT
        self._description = None
        self._reset_settings = True
        self._raw_settings = {}
        self._profile_settings = {}
        self._fw_version = None
        self._hw_version = None
        self._compatibility_number = None
        self._region_lock = None
        self._has_local_fs = False
        self._has_remote_fs = False
        self._has_local_fw = False
        self._has_remote_fw = False
        self._protocol = XBeeProtocol.UNKNOWN

        self._initialize_profile()

        self._profile_dir = None
        self._profile_xml_file = None
        self._fw_xml_file = None
        self._fs_path = None
        self._remote_fs_image = None
        self._bootloader_file = None
        self._cellular_fw_files = []
        self._cellular_bootloader_files = []

    def open(self):
        """
        Opens the profile so its components are accessible from properties
        `firmware_description_file`, `file_system_path`,
        `remote_file_system_image`, and `bootloader_file`.

        The user is responsible for closing the profile when done with it.

        Raises:
            ProfileReadException: If there is any error opening the profile.

        .. seealso::
           | :meth:`.close`
           | :meth:`.is_open`
        """
        # If already open, just return
        if self._profile_dir:
            return self._profile_dir
        try:
            self._profile_dir = tempfile.mkdtemp()
        except (PermissionError, FileExistsError) as exc:
            self._throw_read_exception(_ERROR_PROFILE_OPEN % str(exc))

        _log.debug("Extracting profile into '%s'", self._profile_dir)
        try:
            with zipfile.ZipFile(self._profile_file, "r") as zip_ref:
                zip_ref.extractall(self._profile_dir)
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            self.close()
            self._throw_read_exception(_ERROR_PROFILE_UNCOMPRESS % str(exc))
        # Fill paths.
        firmware_path = Path(os.path.join(self._profile_dir, _FW_DIR_NAME))
        # Firmware XML file.
        self._fw_xml_file = os.path.join(firmware_path, self._fw_xml_filename)
        # Profile XML file.
        self._profile_xml_file = os.path.join(self._profile_dir, _PROFILE_XML_FILE_NAME)
        # Local filesystem folder.
        if self._has_local_fs:
            self._fs_path = os.path.join(self._profile_dir, _LOCAL_FS_DIR)
        # Remote filesystem OTA file.
        if self._has_remote_fs:
            self._remote_fs_image = os.path.join(
                self._profile_dir, _REMOTE_FS_DIR,
                os.listdir(os.path.join(self._profile_dir, _REMOTE_FS_DIR))[0])
        # Bootloader file.
        if len(list(firmware_path.rglob(_WILDCARD_BOOTLOADER))) != 0:
            self._bootloader_file = str(
                list(firmware_path.rglob(_WILDCARD_BOOTLOADER))[0])
        # Cellular firmware files.
        for file in list(firmware_path.rglob(_WILDCARD_CELLULAR_FIRMWARE)):
            self._cellular_fw_files.append(str(file))
        # Cellular bootloader files.
        for file in list(firmware_path.rglob(_WILDCARD_CELLULAR_BOOTLOADER)):
            self._cellular_bootloader_files.append(str(file))

        return self._profile_dir

    def close(self):
        """
        Closes the profile. Its components are no more accessible.

        .. seealso::
           | :meth:`.open`
           | :meth:`.is_open`
        """
        if self._profile_dir and os.path.isdir(self._profile_dir):
            shutil.rmtree(self._profile_dir)

        self._profile_dir = None
        self._profile_xml_file = None
        self._fw_xml_file = None
        self._fs_path = None
        self._remote_fs_image = None
        self._bootloader_file = None
        self._cellular_fw_files.clear()
        self._cellular_bootloader_files.clear()

    def is_open(self):
        """
        Returns `True` if the profile is opened, `False` otherwise.

        .. seealso::
           | :meth:`.open`
           | :meth:`.close`
        """
        return self._profile_dir is not None

    def get_setting_default_value(self, setting_name):
        """
        Returns the default value of the given firmware setting.

        Args:
            setting_name (String or :class:`.ATStringCommand`): Name of the
                setting to retrieve its default value.

        Returns:
            String: Default value of the setting, `None` if the setting is not
                found or it has no default value.
        """
        if isinstance(setting_name, ATStringCommand):
            setting_name = setting_name.command

        try:
            with zipfile.ZipFile(self._profile_file, "r") as zip_file:
                # Do not use os.path.join for a path inside a zip file
                xml_file = zip_file.open(_FW_DIR_NAME + "/" + self._fw_xml_filename)
                fw_root = ElementTree.parse(xml_file).getroot()
                for fw_setting_element in fw_root.findall(_XML_FW_SETTING):
                    if fw_setting_element.get(_XML_COMMAND) != setting_name:
                        continue
                    def_value_element = fw_setting_element.find(_XML_DEFAULT_VALUE)
                    if def_value_element is None:
                        return None
                    return def_value_element.text
        except (ParseError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            _log.exception(exc)

        return None

    def _parse_xml_profile_file(self, zip_file):
        """
        Parses the XML profile file and stores the required parameters.

        Args:
            zip_file (ZipFile): Profile read as zip file.

        Raises:
            ProfileReadException: If there is any error parsing the XML
                profile file.
        """
        _log.debug("Parsing XML profile file")
        try:
            root = ElementTree.parse(zip_file.open(_PROFILE_XML_FILE_NAME)).getroot()
            # XML firmware file. Mandatory.
            fw_xml_file_element = root.find(_XML_PROFILE_XML_FW_FILE)
            if fw_xml_file_element is None:
                self._throw_read_exception(_ERROR_PROFILE_XML_INVALID
                                           % "missing firmware file element")
            self._fw_xml_filename = fw_xml_file_element.text
            # Store XML firmware file name.
            self._fw_xml_file = _FW_DIR_NAME + "/" + self._fw_xml_filename
            _log.debug(" - XML firmware file: %s", self._fw_xml_file)
            # Version. Optional.
            version_element = root.find(_XML_PROFILE_VERSION)
            if version_element is not None:
                self._version = int(version_element.text)
            _log.debug(" - Version: %d", self._version)
            # Flash firmware option. Required.
            flash_fw_element = root.find(_XML_PROFILE_FLASH_FW_OPTION)
            if flash_fw_element is not None:
                self._flash_fw_option = FlashFirmwareOption.get(int(flash_fw_element.text))
            if self._flash_fw_option is None:
                self._throw_read_exception(
                    _ERROR_PROFILE_XML_INVALID % "invalid flash firmware option")
            _log.debug(" - Flash firmware option: %s", self._flash_fw_option.description)
            # Description. Optional.
            description_element = root.find(_XML_PROFILE_DESC)
            if description_element is not None:
                self._description = description_element.text
            _log.debug(" - Description: %s", self._description)
            # Reset settings. Optional.
            reset_settings_element = root.find(_XML_PROFILE_RESET_SETTINGS)
            if reset_settings_element is not None:
                self._reset_settings = reset_settings_element.text in ("True", "true", "1")
            _log.debug(" - Reset settings: %s", self._reset_settings)
            # Read AT settings.
            setting_elements = root.findall(_XML_PROFILE_AT_SETTING)
            if not setting_elements:
                return
            for setting_element in setting_elements:
                setting_name = setting_element.get(_XML_COMMAND)
                setting_value = setting_element.text
                self._raw_settings[setting_name] = setting_value
        except ParseError as exc:
            self._throw_read_exception(_ERROR_PROFILE_XML_PARSE % str(exc))

    def _initialize_profile(self):
        """
        Initializes the profile information by checking its integrity and
        parsing the XML files.

        Raises:
            ProfileReadException: If there is any error checking the profile
                integrity.
        """
        try:
            with zipfile.ZipFile(self._profile_file, "r") as zip_file:
                self._check_profile_integrity(zip_file)
                self._parse_xml_profile_file(zip_file)
                self._parse_xml_firmware_file(zip_file)
                files = [name for name in zip_file.namelist() if
                         name.endswith(_WILDCARDS_FW_LOCAL_BINARY_FILES)]
                self._has_local_fw = bool(files)
                files = [name for name in zip_file.namelist() if
                         name.endswith(_WILDCARDS_FW_REMOTE_BINARY_FILES)]
                self._has_remote_fw = bool(files)
        except Exception as exc:
            self._throw_read_exception(_ERROR_PROFILE_READ % str(exc))

    def _check_profile_integrity(self, zip_file):
        """
        Checks the profile integrity.

        Args:
            zip_file (ZipFile): Profile read as zip file.

        Raises:
            ProfileReadException: If there is any error checking the profile
                integrity.
        """
        # Profile XML file.
        files = list(map(lambda f: f.filename, zip_file.filelist))
        # Profile XML file.
        if _PROFILE_XML_FILE_NAME not in files:
            self._throw_read_exception(_ERROR_PROFILE_XML_NOT_EXIST)
        # Firmware folder.
        if not any(f.startswith(_FW_DIR_NAME) for f in files):
            self._throw_read_exception(_ERROR_FW_FOLDER_NOT_EXIST)
        # Firmware XML file.
        if len(fnmatch.filter(files, _FW_DIR_NAME + _WILDCARD_XML)) == 0:
            self._throw_read_exception(_ERROR_FW_XML_NOT_EXIST)
        # Check local file system.
        self._has_local_fs = any(f.startswith(_LOCAL_FS_DIR) for f in files)
        # Check remote file system.
        self._has_remote_fs = any(f.startswith(_REMOTE_FS_DIR) for f in files)

    def _parse_xml_firmware_file(self, zip_file):
        """
        Parses the XML firmware file and stores the required parameters.

        Args:
            zip_file (ZipFile): Profile read as zip file.

        Raises:
            ProfileReadException: If there is any error parsing the XML
                firmware file.
        """
        _log.debug("Parsing XML firmware file %s:", self._fw_xml_file)
        try:
            root = ElementTree.parse(zip_file.open(self._fw_xml_file)).getroot()
            # Firmware version.
            element = root.find(_XML_FW_FIRMWARE)
            if element is None:
                self._throw_read_exception(
                    _ERROR_FW_XML_INVALID % "missing firmware element")
            self._fw_version = int(element.get(_XML_FW_FIRMWARE_VERSION), 16)
            if self._fw_version is None:
                self._throw_read_exception(
                    _ERROR_FW_XML_INVALID % "missing firmware version")
            _log.debug(" - Firmware version: %s",
                       utils.hex_to_string([self._fw_version], pretty=False))
            # Hardware version.
            element = root.find(_XML_FW_HARDWARE_VERSION)
            if element is None:
                self._throw_read_exception(
                    _ERROR_FW_XML_INVALID % "missing hardware version element")
            try:
                self._hw_version = int(element.text, 16)
            except ValueError:
                self._hw_version = LegacyHardwareVersion.get_by_letter(
                    element.text).code if \
                    LegacyHardwareVersion.get_by_letter(element.text) else None
            _log.debug(" - Hardware version: %s",
                       utils.hex_to_string([self._hw_version], pretty=False))
            # Compatibility number.
            element = root.find(_XML_COMPATIBILITY_NUMBER)
            if element is None:
                self._compatibility_number = None
            else:
                self._compatibility_number = int(element.text)
            _log.debug(" - Compatibility number: %d", self._compatibility_number)
            # Region lock, required.
            element = root.find(_XML_REGION_LOCK)
            if element is None:
                self._region_lock = None
            else:
                self._region_lock = int(element.text)
            # 99: Unknown region
            if self._region_lock == 99:
                fw_version_str = utils.hex_to_string(
                    utils.int_to_bytes(self._fw_version, num_bytes=2), pretty=False)
                if len(fw_version_str) != 4:
                    # 0: All regions
                    self._region_lock = 0
                else:
                    self._region_lock = int(fw_version_str[1:2], base=16)
            _log.debug(" - Region lock: %d", self._region_lock)
            # Determine protocol.
            br_value = self._raw_settings.get(ATStringCommand.BR.command, None)
            if br_value is None:
                br_value = 1  # It may be different but for the protocol it does not matter
            self._protocol = XBeeProtocol.determine_protocol(
                self._hw_version, utils.int_to_bytes(self._fw_version), br_value=int(br_value))
            _log.debug(" - Protocol: %s",
                       self._protocol.description if self.protocol else "None")
            # Parse AT settings.
            _log.debug(" - AT settings:")
            if not self._raw_settings:
                _log.debug("  - None")
                return
            for name, value in self._raw_settings.items():
                for setting_element in root.findall(_XML_FW_SETTING):
                    if setting_element.get(_XML_COMMAND) != name:
                        continue
                    type_element = setting_element.find(_XML_CONTROL_TYPE)
                    setting_type = XBeeSettingType.NO_TYPE
                    if type_element is not None:
                        setting_type = XBeeSettingType.get(type_element.text)
                    format_element = setting_element.find(_XML_FORMAT)
                    setting_format = XBeeSettingFormat.NO_FORMAT
                    if format_element is not None:
                        setting_format = XBeeSettingFormat.get(format_element.text)
                    profile_setting = XBeeProfileSetting(
                        name.upper(), setting_type, setting_format, value)
                    _log.debug(
                        "  - Setting '%s' - type: %s - format: %s - value: %s",
                        profile_setting.name, profile_setting.type.description,
                        profile_setting.format.description, profile_setting.value)
                    self._profile_settings.update({profile_setting.name: profile_setting})
        except ParseError as exc:
            self._throw_read_exception(_ERROR_FW_XML_PARSE % str(exc))

    @staticmethod
    def _throw_read_exception(message):
        """
        Throws an XBee profile read exception with the given message and logs it.

        Args:
            message (String): Exception message

        Raises:
            ProfileReadException: Exception thrown wit the given message.
        """
        _log.error("ERROR: %s", message)
        raise ReadProfileException(message)

    @property
    def profile_file(self):
        """
        Returns the profile file.

        Returns:
            String: Profile file.
        """
        return self._profile_file

    @property
    def version(self):
        """
        Returns the profile version.

        Returns:
            String: Profile version.
        """
        return self._version

    @property
    def flash_firmware_option(self):
        """
        Returns the profile flash firmware option.

        Returns:
            :class:`.FlashFirmwareOption`: Profile flash firmware option.

        .. seealso::
           | :class:`.FlashFirmwareOption`
        """
        return self._flash_fw_option

    @property
    def description(self):
        """
        Returns the profile description.

        Returns:
            String: Profile description.
        """
        return self._description

    @property
    def reset_settings(self):
        """
        Returns whether the settings of the XBee will be reset before applying
        the profile ones or not.

        Returns:
            Boolean: `True` if the settings of the XBee will be reset before
                applying the profile ones, `False` otherwise.
        """
        return self._reset_settings

    @property
    def has_local_filesystem(self):
        """
        Returns whether the profile has local filesystem information or not.

        Returns:
            Boolean: `True` if the profile has local filesystem information,
                `False` otherwise.
         """
        return self._has_local_fs

    @property
    def has_remote_filesystem(self):
        """
        Returns whether the profile has remote filesystem information or not.

        Returns:
            Boolean: `True` if the profile has remote filesystem information,
                `False` otherwise.
        """
        return self._has_remote_fs

    @property
    def has_filesystem(self):
        """
        Returns whether the profile has filesystem information (local or
        remote) or not.

        Returns:
            Boolean: `True` if the profile has filesystem information (local or
                remote), `False` otherwise.
        """
        return self._has_local_fs or self._has_remote_fs

    @property
    def has_local_firmware_files(self):
        """
        Returns whether the profile has local firmware binaries.

        Returns:
            Boolean: `True` if the profile has local firmware files,
                `False` otherwise.
        """
        return self._has_local_fw

    @property
    def has_remote_firmware_files(self):
        """
        Returns whether the profile has remote firmware binaries.

        Returns:
            Boolean: `True` if the profile has remote firmware files,
                `False` otherwise.
        """
        return self._has_remote_fw

    @property
    def has_firmware_files(self):
        """
        Returns whether the profile has firmware binaries (local or remote).

        Returns:
            Boolean: `True` if the profile has local or remote firmware files,
                `False` otherwise.
        """
        return self.has_local_firmware_files or self.has_remote_firmware_files

    @property
    def profile_settings(self):
        """
        Returns all the firmware settings that the profile configures.

        Returns:
            Dict: List with all the firmware settings that the profile
                configures (:class:`.XBeeProfileSetting`).
        """
        return self._profile_settings

    @property
    def firmware_version(self):
        """
        Returns the compatible firmware version of the profile.

        Returns:
            Integer: Compatible firmware version of the profile.
        """
        return self._fw_version

    @property
    def hardware_version(self):
        """
        Returns the compatible hardware version of the profile.

        Returns:
            Integer: Compatible hardware version of the profile.
        """
        return self._hw_version

    @property
    def compatibility_number(self):
        """
        Returns the compatibility number of the profile.

        Returns:
            Integer: The compatibility number, `None` if not defined.
        """
        return self._compatibility_number

    @property
    def region_lock(self):
        """
        Returns the region lock of the profile.

        Returns:
            Integer: The region lock, `None` if not defined.
        """
        return self._region_lock

    @property
    def profile_description_file(self):
        """
        Returns the path of the profile description file.

        Returns:
            String: Path of the profile description file.
        """
        return self._profile_xml_file

    @property
    def firmware_description_file(self):
        """
        Returns the path of the profile firmware description file.

        Returns:
            String: Path of the profile firmware description file.
        """
        return self._fw_xml_file

    @property
    def file_system_path(self):
        """
        Returns the profile file system path.
        `None` until the profile is extracted.

        Returns:
            String: Path of the profile file system directory.
        """
        return self._fs_path

    @property
    def remote_file_system_image(self):
        """
        Returns the path of the remote OTA file system image.
        `None` until the profile is extracted.

        Returns:
            String: Path of the remote OTA file system image.
        """
        return self._remote_fs_image

    @property
    def bootloader_file(self):
        """
        Returns the profile bootloader file path.
        `None` until the profile is extracted.

        Returns:
            String: Path of the profile bootloader file.
        """
        return self._bootloader_file

    @property
    def protocol(self):
        """
        Returns the profile XBee protocol.

        Returns:
             XBeeProtocol: Profile XBee protocol.
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol):
        """
        Sets the profile XBee protocol.

        Args:
             protocol (:class: `.XBeeProtocol`): Profile XBee protocol.
        """
        self._protocol = protocol


class ProfileUpdateTask:
    """
    This class represents a profile update process for a given XBee.
    """

    def __init__(self, xbee, profile_path, timeout=None, progress_cb=None):
        """
        Class constructor. Instantiates a new :class:`.ProfileUpdateTask` object.

        Args:
            xbee (String or :class:`.AbstractXBeeDevice`): XBee to apply the profile.
            profile_path (String): Path of the XBee profile file to apply.
            timeout (Integer, optional): Maximum time to wait for read operations
                while applying the profile.
            progress_cb (Function, optional): Function to execute to receive
                progress information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            ValueError: If the XBee device or the profile path are `None`
                or invalid.
        """
        # Sanity checks.
        if not isinstance(xbee, (XBeeDevice, RemoteXBeeDevice)):
            raise ValueError("Invalid XBee")
        if not isinstance(profile_path, str) or not os.path.isfile(profile_path):
            raise ValueError(_ERROR_PROFILE_NOT_VALID)

        self.__xbee = xbee
        self.__profile_path = profile_path
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
    def profile_path(self):
        """
        Gets the `*.xpro` file path.

        Returns:
            String: The profile path for the update task.
        """
        return self.__profile_path

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


class _UpdateConfigurer:
    """
    Class to store and restore an XBee configuration for the update process.
    """

    def __init__(self, node, timeout=None, callback=None):
        """
        Class constructor. Instantiates a new :class:`._UpdateConfigurer` with
        the given parameters.

        Args:
            node (:class:`.AbstractXBeeDevice`): Target being updated.
            timeout (Integer, optional, default=`None`): Operations timeout.
            callback (Function): Function to notify about the progress.
        """
        self._configurer = UpdateConfigurer(node, timeout=timeout, callback=callback)
        self._xbee = node

    @property
    def cmd_dict(self):
        """
        Returns the dictionary to store values to be configured at the end
        of the update process.

        Returns:
            Dictionary: The dictionary with the values to restore at the end
                of the process.
        """
        return self._configurer.cmd_dict

    def prepare_for_update(self):
        """
        Prepares the node for an update process. This implies to store some
        configuration values so they can be restored later.
        """
        self._configurer.prepare_for_update(restore_later=True)

    def restore_after_update(self, net_changed, protocol_changed_by_settings, port_settings):
        """
        Restores the node configuration.

        Args:
            net_changed (Boolean): `True` if any network parameter has changed
                after the update, `False` otherwise.
            protocol_changed_by_settings (Boolean): `True` if the protocol of
                the node changed after the update, `False` otherwise.
            port_settings (Dictionary): Dictionary with the serial port
                configuration after applying settings, `None` for remote node
                or if the serial config has not changed.
        """
        self._configurer.restore_total = self._configurer.restore_total + 3

        self._configurer.progress_cb(self._configurer.TASK_RESTORE)

        ap_val = self._configurer.cmd_dict.get(self._xbee, {}).pop(ATStringCommand.AP, None)
        # Restore AP mode only for local XBees and valid operating modes.
        # If the value is not 1 (API mode) or 2 (escaped API mode)
        restore_ap = (ap_val and not self._xbee.is_remote()
                      and ap_val[0] != self._xbee.operating_mode.code
                      and (ap_val[0] in (OperatingMode.API_MODE.code,
                                         OperatingMode.ESCAPED_API_MODE.code)))
        if restore_ap:
            self._configurer.cmd_dict.get(self._xbee, {}).update({ATStringCommand.AP: ap_val})

        self._configurer.progress_cb(self._configurer.TASK_RESTORE)

        self._configurer.restore_after_update(
            restore_settings=not self._xbee.is_remote() or not protocol_changed_by_settings,
            port_settings=port_settings)

        # Check if network or cache settings have changed.
        if net_changed or protocol_changed_by_settings:
            if not self._xbee.is_remote():
                # Clear the full network as it is no longer valid.
                self._xbee.get_network()._clear(NetworkEventReason.PROFILE_UPDATE)
            else:
                # Remove node from the network as it might be no longer part of it.
                self._xbee.get_local_xbee_device().get_network(). \
                    _remove_device(self._xbee, NetworkEventReason.PROFILE_UPDATE)

        self._configurer.progress_cb(self._configurer.TASK_RESTORE,
                                     done=self._configurer.restore_total)


class _ProfileUpdater:
    """
    Helper class used to handle the update XBee profile process.
    """

    def __init__(self, target, xbee_profile, timeout=None, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._ProfileUpdater` with
        the given parameters.

        Args:
            target (String or :class:`.AbstractXBeeDevice`): Target to apply
                profile to. String: serial port identifier.
                :class:`.AbstractXBeeDevice`: XBee to apply the profile.
            xbee_profile (:class:`.XBeeProfile`): XBee profile to apply.
            timeout (Integer, optional): Maximum time to wait for target
                read operations during the apply profile.
            progress_callback (Function, optional): Function to execute to
                receive progress information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        self._profile = xbee_profile
        self._target = target
        self._xbee = None
        self._configurer = None
        if not isinstance(target, str):
            self._xbee = target
            self._configurer = _UpdateConfigurer(self._xbee, timeout=timeout,
                                                 callback=progress_callback)
        self._timeout = timeout
        self._progress_callback = progress_callback
        self._was_connected = True
        self._device_fw_version = None
        self._device_hw_version = None
        self._protocol_changed_by_fw = False
        self._is_local = bool(not isinstance(self._xbee, RemoteXBeeDevice))

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
        if isinstance(self._target, str):
            return

        update_type = self._xbee._active_update_type

        if self._xbee.is_remote():
            xnet = self._xbee.get_local_xbee_device().get_network()
        else:
            xnet = self._xbee.get_network()

        if xnet:
            progress_cbs = xnet.get_update_progress_callbacks()
            if progress_cbs:
                progress_cbs(self._xbee,
                             UpdateProgressStatus(update_type, task_str, percent, finished))

        if finished and update_type == NodeUpdateType.PROFILE:
            self._xbee._active_update_type = None

    def _update_firmware(self):
        """
        Updates the XBee device firmware.

        Raises:
            UpdateProfileException: If there is any error updating the XBee
                firmware.
        """
        _log.info("%s - Updating XBee firmware",
                  self._xbee if self._xbee is not None else self._target)
        try:
            if self._xbee and self._xbee.is_remote():
                if not self._profile.has_remote_firmware_files:
                    raise UpdateProfileException(
                        _ERROR_UPDATE_FW % "Profile does not contain remote firmware")
                update_remote_firmware(
                    self._xbee, self._profile.firmware_description_file,
                    timeout=self._timeout,
                    max_block_size=self._xbee.get_ota_max_block_size(),
                    progress_callback=self._progress_callback)
            else:
                if not self._profile.has_local_firmware_files:
                    raise UpdateProfileException(
                        _ERROR_UPDATE_FW % "Profile does not contain local firmware")
                update_local_firmware(
                    self._target, self._profile.firmware_description_file,
                    bootloader_firmware_file=self._profile.bootloader_file,
                    timeout=self._timeout, progress_callback=self._progress_callback)
        except FirmwareUpdateException as exc:
            raise UpdateProfileException(_ERROR_UPDATE_FW % str(exc)) from exc

    def _check_port_settings_changed(self):
        """
        Checks whether the port settings of the device have changed in order
        to update serial port connection.

        Returns:
            Dictionary: A dictionary with the new serial port configuration,
                `None` if no serial parameter has changed.

        Raises:
            UpdateProfileException: If there is any error checking serial port
                settings changes.
        """
        port_params = self._xbee.serial_port.get_settings()
        baudrate_changed = False
        parity_changed = False
        stop_bits_changed = False
        cts_flow_control_changed = False
        for setting in self._profile.profile_settings.values():
            if setting.name.upper() not in _PARAMS_SERIAL_PORT:
                continue
            if setting.name.upper() == ATStringCommand.BD.command:
                baudrate_changed = True
                port_params["baudrate"] = FirmwareBaudrate.get(
                    int(setting.value, 16)).baudrate
            elif setting.name.upper() == ATStringCommand.NB.command:
                parity_changed = True
                port_params["parity"] = FirmwareParity.get(
                    int(setting.value, 16)).parity
            elif setting.name.upper() == ATStringCommand.SB.command:
                stop_bits_changed = True
                port_params["stopbits"] = FirmwareStopbits.get(
                    int(setting.value, 16)).stop_bits
            elif setting.name.upper() == ATStringCommand.D7.command:
                cts_flow_control_changed = True
                port_params["rtscts"] = bool(setting.value == _VALUE_CTS_ON)
        if self._profile.reset_settings or isinstance(self._target, str):
            if not baudrate_changed:
                baudrate_changed = True
                default_baudrate = self._profile.get_setting_default_value(
                    ATStringCommand.BD.command)
                port_params["baudrate"] = FirmwareBaudrate.get(
                    int(default_baudrate, 16)).baudrate
            if not parity_changed:
                parity_changed = True
                default_parity = self._profile.get_setting_default_value(
                    ATStringCommand.NB.command)
                port_params["parity"] = FirmwareParity.get(
                    int(default_parity, 16)).parity
            if not stop_bits_changed:
                stop_bits_changed = True
                default_stop_bits = self._profile.get_setting_default_value(
                    ATStringCommand.SB.command)
                port_params["stopbits"] = FirmwareStopbits.get(
                    int(default_stop_bits, 16)).stop_bits
            if not cts_flow_control_changed:
                cts_flow_control_changed = True
                port_params["rtscts"] = True  # Default CTS value is always on.

        if baudrate_changed or parity_changed or stop_bits_changed or cts_flow_control_changed:
            return port_params

        return None

    def _check_protocol_changed_by_fw(self):
        """
        Determines whether the XBee protocol will change after the
        firmware update.

        Returns:
            Boolean: `True` if the protocol will change after the firmware
                update, `False` otherwise.
        """
        # SX devices cannot change the protocol by only updating the firmware.
        if self._device_hw_version.code in SX_HW_VERSIONS:
            return False

        orig_protocol = self._xbee.get_protocol()
        new_protocol = XBeeProtocol.determine_protocol(
            self._profile.hardware_version,
            utils.int_to_bytes(self._profile.firmware_version))
        return (orig_protocol != new_protocol
                and self._profile.flash_firmware_option.code < 2)

    def _check_protocol_changed_by_settings(self):
        """
        Determines whether the XBee protocol will change after the application
        of profiles settings.

        Returns:
            Boolean: `True` if the protocol will change after the application
                of profiles settings, `False` otherwise.
        """
        if self._device_hw_version.code not in SX_HW_VERSIONS:
            return False

        br_val = None
        br_setting = self._profile.profile_settings.get(ATStringCommand.BR.command, None)
        if br_setting:
            br_val = br_setting.value
        elif self._profile.reset_settings:
            br_val = self._profile.get_setting_default_value(ATStringCommand.BR)

        if not br_val:
            return False

        self._profile.protocol = XBeeProtocol.determine_protocol(
            self._profile.hardware_version,
            utils.int_to_bytes(self._profile.firmware_version),
            br_value=int(br_val, base=16))

        return self._xbee.get_protocol() != self._profile.protocol

    def _update_device_settings(self):
        """
        Updates the device settings using the profile.

        Returns:
            Tuple (Boolean, Boolean, Dictionary):
                - `True` if network settings changed, `False` otherwise.
                - `True` if cache settings changed, `False` otherwise.
                - A dictionary with the new serial port configuration if it
                  it is a local XBee and the port configuration has changed,
                  `None` otherwise.

        Raises:
            UpdateProfileException: If there is any error updating device
                settings from the profile.
        """
        # If there are no settings to apply or reset, skip this method.
        if (len(self._profile.profile_settings) == 0
                and not self._profile.reset_settings
                and not isinstance(self._target, str)):
            return False, False, None

        # For remote nodes that changed the protocol, raise an exception if
        # there are settings to apply or reset as the node is no longer reachable.
        if (self._xbee.is_remote() and self._protocol_changed_by_fw
                and (len(self._profile.profile_settings) > 0
                     or self._profile.reset_settings)):
            raise UpdateProfileException(_ERROR_PROTOCOL_CHANGE % "apply profile settings")

        _log.info("'%s' - %s", self._xbee, _TASK_UPDATE_SETTINGS)
        network_settings_changed = False
        cache_settings_changed = False
        try:
            previous_percent = 0
            percent = 0
            setting_index = 1
            # 1 more setting for 'WR'
            num_settings = len(self._profile.profile_settings) + 1

            self._notify_progress(_TASK_UPDATE_SETTINGS, percent)
            # Check if reset settings is required or if we are applying to a
            # serial port (recovery).
            cmd_dict = self._configurer.cmd_dict.get(self._xbee, None)
            if cmd_dict is None:
                cmd_dict = {}
                self._configurer.cmd_dict[self._xbee] = cmd_dict
            if self._profile.reset_settings or isinstance(self._target, str):
                num_settings += 1  # One more setting for 'RE'
                percent = setting_index * 100 // num_settings
                if percent != previous_percent:
                    self._notify_progress(_TASK_UPDATE_SETTINGS, percent)
                    previous_percent = percent
                self.set_parameter_with_retries(ATStringCommand.RE, bytearray(0),
                                                _PARAM_WRITE_RETRIES, apply=False)
                setting_index += 1
                # Reset settings to defaults implies network and cache settings have changed
                network_settings_changed = True
                cache_settings_changed = True

                cmd_dict[ATStringCommand.SM] = utils.hex_string_to_bytes(
                    self._profile.get_setting_default_value(ATStringCommand.SM))
                # 'SN' parameter does not exist in all firmwares
                sn_def = self._profile.get_setting_default_value(ATStringCommand.SN)
                if sn_def is not None:
                    cmd_dict[ATStringCommand.SN] = utils.hex_string_to_bytes(sn_def)
                cmd_dict[ATStringCommand.SO] = utils.hex_string_to_bytes(
                    self._profile.get_setting_default_value(ATStringCommand.SO))
                cmd_dict[ATStringCommand.SP] = utils.hex_string_to_bytes(
                    self._profile.get_setting_default_value(ATStringCommand.SP))
                cmd_dict[ATStringCommand.ST] = utils.hex_string_to_bytes(
                    self._profile.get_setting_default_value(ATStringCommand.ST))
                if self._is_local:
                    cmd_dict[ATStringCommand.AP] = utils.hex_string_to_bytes(
                        self._profile.get_setting_default_value(ATStringCommand.AP))
                    # Restore the previous operating mode to be able to continue
                    self.set_parameter_with_retries(
                        ATStringCommand.AP,
                        bytearray([self._xbee.operating_mode.code]),
                        _PARAM_WRITE_RETRIES, apply=False)
            # Set settings.
            for setting in self._profile.profile_settings.values():
                percent = setting_index * 100 // num_settings
                if percent != previous_percent:
                    self._notify_progress(_TASK_UPDATE_SETTINGS, percent)
                    previous_percent = percent
                name = setting.name.upper()
                # Do not apply wake up period until the end of the process
                if name in ATStringCommand.ST.command:
                    cmd_dict[ATStringCommand.ST] = setting.bytearray_value
                # Do not apply sleep period until the end of the process
                if name in ATStringCommand.SP.command:
                    cmd_dict[ATStringCommand.SP] = setting.bytearray_value
                # Do not apply number of sleep periods until the end of the process
                elif name == ATStringCommand.SN.command:
                    cmd_dict[ATStringCommand.SN] = setting.bytearray_value
                # Do not apply sleep mode until the end of the process
                elif name == ATStringCommand.SM.command:
                    cmd_dict[ATStringCommand.SM] = setting.bytearray_value
                # Do not apply sleep options until the end of the process
                elif name == ATStringCommand.SO.command:
                    cmd_dict[ATStringCommand.SO] = setting.bytearray_value
                # Do not apply operating mode until the end of the process
                elif name == ATStringCommand.AP.command and self._is_local:
                    cmd_dict[ATStringCommand.AP] = setting.bytearray_value
                # Do not apply auto-start of MicroPython until the end of the process
                elif (name == ATStringCommand.PS.command
                      and int.from_bytes(setting.bytearray_value, "big")):
                    cmd_dict[ATStringCommand.PS] = setting.bytearray_value
                else:
                    self.set_parameter_with_retries(
                        name, setting.bytearray_value, _PARAM_WRITE_RETRIES,
                        apply=False)
                setting_index += 1
                # Check if the setting was sensitive for network or cache information
                if name in _PARAMS_NETWORK:
                    network_settings_changed = True
                if name in _PARAMS_CACHE:
                    cache_settings_changed = True

            # Write settings.
            percent = setting_index * 100 // num_settings
            if percent != previous_percent:
                self._notify_progress(_TASK_UPDATE_SETTINGS, percent)
            self.set_parameter_with_retries(ATStringCommand.WR, bytearray(0),
                                            _PARAM_WRITE_RETRIES, apply=bool(not cmd_dict))
        except XBeeException as exc:
            raise UpdateProfileException(_ERROR_UPDATE_SETTINGS % str(exc)) from None

        # Check if port settings have changed on local devices.
        port_params = None
        if self._is_local:
            port_params = self._check_port_settings_changed()

        # If the target is a serial port, we do not need to continue
        if isinstance(self._target, str):
            return False, False, port_params

        return network_settings_changed, cache_settings_changed, port_params

    def _update_file_system(self):
        """
        Updates the device file system.

        Raises:
            UpdateProfileException: If there is any error during updating the
                device file system.
        """
        _log.info("%s - Uploading file system", self._xbee)

        if (self._profile.has_local_filesystem
                and check_fs_support(self._xbee,
                                     min_fw_vers=XB3_MIN_FW_VERSION_FS_API_SUPPORT)):
            # For remote nodes that changed the protocol, raise an exception if
            # there is a filesystem to update as the node is no longer reachable
            if self._xbee.is_remote() and self._protocol_changed_by_fw:
                raise UpdateProfileException(_ERROR_PROTOCOL_CHANGE % "update filesystem")

            try:
                fs_mng = self._xbee.get_file_manager()
                # Format file system to ensure resulting file system is exactly
                # the same as the profile one.
                self._notify_progress(_TASK_FORMAT_FILESYSTEM, 0)
                fs_mng.format()
                self._notify_progress(_TASK_FORMAT_FILESYSTEM, 100)
                # Transfer the file system folder.
                fs_mng.put_dir(
                    self._profile.file_system_path, dest=None, verify=True,
                    progress_cb=lambda percent, src, _:
                    self._notify_progress(_TASK_UPDATE_FILE % src, percent))
            except FileSystemNotSupportedException:
                raise UpdateProfileException(_ERROR_FS_NOT_SUPPORTED) from None
            except FileSystemException as exc:
                raise UpdateProfileException(_ERROR_UPDATE_FS % str(exc)) from exc
        else:
            self._legacy_update_file_system()

    def _legacy_update_file_system(self):
        """
        Updates the device file system using the legacy mode, with AT commands
        for local XBee and a OTA update for remote XBee modules.

        Raises:
            UpdateProfileException: If there is any error during updating the
                device file system.
        """
        if self._is_local and self._profile.has_local_filesystem:
            fs_manager = None
            try:
                fs_manager = LocalXBeeFileSystemManager(self._xbee)
                self._notify_progress(_TASK_CONNECT_FILESYSTEM, 0)
                time.sleep(0.2)
                fs_manager.connect()
                self._notify_progress(_TASK_CONNECT_FILESYSTEM, 100)
                # Format file system to ensure resulting file system is exactly
                # the same as the profile one.
                self._notify_progress(_TASK_FORMAT_FILESYSTEM, 0)
                fs_manager.format_filesystem()
                self._notify_progress(_TASK_FORMAT_FILESYSTEM, 100)
                # Transfer the file system folder.
                fs_manager.put_dir(
                    self._profile.file_system_path, dest_dir=None,
                    progress_callback=lambda file, percent:
                    self._notify_progress(_TASK_UPDATE_FILE % file, percent))
            except FileSystemNotSupportedException:
                raise UpdateProfileException(_ERROR_FS_NOT_SUPPORTED) from None
            except FileSystemException as exc:
                raise UpdateProfileException(_ERROR_UPDATE_FS % str(exc)) from exc
            finally:
                if fs_manager:
                    try:
                        fs_manager.disconnect()
                    except InvalidOperatingModeException:
                        # This exception is thrown while trying to reconnect the
                        # device after finishing with the FileSystem Manager but
                        # the device Operating Mode was changed to '0' or '4'. Just
                        # ignore it, profile has been successfully applied.
                        pass

        elif not self._is_local and self._profile.has_remote_filesystem:
            # For remote nodes that changed the protocol, raise an exception if
            # there is a filesystem to update as the node is no longer reachable
            if self._xbee.is_remote() and self._protocol_changed_by_fw:
                raise UpdateProfileException(_ERROR_PROTOCOL_CHANGE % "update filesystem")
            try:
                update_remote_filesystem_image(
                    self._xbee, self._profile.remote_file_system_image,
                    max_block_size=self._xbee.get_ota_max_block_size(),
                    timeout=self._timeout, progress_callback=self._progress_callback)
            except FileSystemException as exc:
                raise UpdateProfileException(_ERROR_UPDATE_FS % str(exc)) from exc

    def _should_update_fw(self):
        """
        Returns if firmware should be updated based on the flash firmware option
        in the XBee profile.

        Returns:
            Boolean: `True` if firmware should be update, `False` otherwise.

        Raises:
            UpdateProfileException: If the profile is configured not to update
                firmware but the profile is for a version different from the
                current version running in the target XBee.
        """
        # Check flash firmware option.
        firmware_is_the_same = self._device_fw_version == self._profile.firmware_version
        if self._profile.flash_firmware_option == FlashFirmwareOption.FLASH_ALWAYS:
            return True
        if self._profile.flash_firmware_option == FlashFirmwareOption.FLASH_DIFFERENT:
            return not firmware_is_the_same
        if (self._profile.flash_firmware_option == FlashFirmwareOption.DONT_FLASH
                and not firmware_is_the_same):
            raise UpdateProfileException(_ERROR_FW_NOT_COMPATIBLE)

        return False

    def read_device_parameters(self):
        """
        Reads and stores the required XBee parameters in order to apply the
        XBee profile.

        Raises:
            UpdateProfileException: If there is any error reading the required
                XBee parameters.
        """
        _log.debug("Reading device parameters")
        if self._is_local:
            # Connect the device.
            if not self._xbee.is_open():
                self._was_connected = False
                try:
                    self._xbee.open()
                except XBeeException as exc:
                    raise UpdateProfileException(_ERROR_OPEN_DEVICE % str(exc)) from None
            # For local devices, required parameters are read on 'open()'
            # method, just use them.
            self._device_fw_version = self._xbee.get_firmware_version()
            self._device_hw_version = self._xbee.get_hardware_version()
        else:
            # For remote devices, parameters are read with 'get_parameter()' method.
            try:
                self._device_fw_version = self.read_parameter_with_retries(
                    ATStringCommand.VR, _PARAM_READ_RETRIES)
                self._device_hw_version = HardwareVersion.get(
                    self.read_parameter_with_retries(
                        ATStringCommand.HV, _PARAM_READ_RETRIES)[0])
            except XBeeException as exc:
                raise UpdateProfileException(_ERROR_READ_REMOTE_PARAMETER % str(exc)) from None

        # Sanitize firmware version.
        self._device_fw_version = int(utils.hex_to_string(
            self._device_fw_version).replace(" ", ""), 16)
        _log.debug("  - Firmware version: %s",
                   utils.hex_to_string([self._device_fw_version], pretty=False))
        _log.debug("  - Hardware version: %s",
                   utils.hex_to_string([self._device_hw_version.code], pretty=False))

    def read_parameter_with_retries(self, parameter, retries):
        """
        Reads a parameter from the XBee within the given number of retries.

        Args:
            parameter (String or :class: `ATStringCommand`): Parameter to read.
            retries (Integer): Number of retries to read the parameter.

        Returns:
            Bytearray: Read parameter value.

        Raises:
            XBeeException: If there is any error reading the parameter.
        """
        while retries > 0:
            try:
                return self._xbee.get_parameter(parameter, apply=False)
            except XBeeException:
                retries -= 1
                time.sleep(0.2)

        at_str = parameter.command if isinstance(parameter, ATStringCommand) else parameter
        raise XBeeException("Timeout reading parameter '%s'" % at_str)

    def set_parameter_with_retries(self, parameter, value, retries, apply=False):
        """
        Sets the given parameter in the XBee within the given number of retries.

        Args:
            parameter (String or :class: `ATStringCommand`): Parameter to set.
            value (Bytearray): Parameter value to set.
            retries (Integer): Number of retries to set the parameter.
            apply (Boolean, optional, default=`False`): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.

        Raises:
            XBeeException: If there is any error setting the parameter.
        """
        msg = ""
        total = retries
        while retries > 0:
            try:
                at_str = parameter.command if isinstance(parameter, ATStringCommand) else parameter
                _log.debug("Setting parameter '%s' to '%s' (%d/%d)",
                           at_str, utils.hex_to_string(value, pretty=False),
                           (total + 1 - retries), total)
                return self._xbee.set_parameter(parameter, value, apply=apply)
            except XBeeException as exc:
                msg = str(exc)
                retries -= 1
                if retries:
                    time.sleep(0.2 if self._is_local else 5)

        raise XBeeException("Error setting parameter '%s': %s" % (parameter, msg))

    def update_profile(self):
        """
        Starts the update profile process.

        Raises:
            UpdateProfileException: If there is any error during the update
                XBee profile operation.
        """
        net_changed = False
        protocol_changed_by_settings = False
        port_settings = None
        update_result = "Success"
        try:
            if self._xbee:
                # Retrieve device parameters.
                self._configurer.prepare_for_update()

                self.read_device_parameters()

                # Verify hardware compatibility of the profile.
                if self._device_hw_version.code != self._profile.hardware_version:
                    raise UpdateProfileException(_ERROR_HW_NOT_COMPATIBLE)
                # Determine if protocol will be changed.
                self._protocol_changed_by_fw = self._check_protocol_changed_by_fw()
                protocol_changed_by_settings = self._check_protocol_changed_by_settings()
            else:
                # Serial port given (recovery)
                self._was_connected = False
                self._device_fw_version = 0
                self._device_hw_version = None
                self._protocol_changed_by_fw = False

            flash_firmware = self._should_update_fw()

            # Update firmware if required.
            if not self._xbee or flash_firmware:
                self._profile.open()
                self._update_firmware()
            if not self._xbee:
                self._xbee = XBeeDevice(port=self._target, baud_rate=9600)
                self._configurer = _UpdateConfigurer(self._xbee, timeout=self._timeout,
                                                     callback=self._progress_callback)
                self._xbee.open(force_settings=True)
                self._device_hw_version = self._xbee.get_hardware_version()
            # Update the file system if required.
            if self._profile.has_filesystem:
                if not self._profile.is_open():
                    self._profile.open()
                self._update_file_system()
            # Update the settings.
            net_changed, _info_changed, port_settings = self._update_device_settings()
            # In SX devices, protocol changes are not linked to the firmware file applied.
            # SX devices can change the protocol by updating the value of the BR parameter.
            # Checking whether the protocol has changed after applying the settings is
            # mandatory to avoid future failures with XBee device class instances.
            #
            # BR setting value:
            # - 0: DigiPoint (P2MP point to multi-point)
            # - 1, 2: DigiMesh
            #
            # If the protocol has changed by the profile settings, raise an exception
            # so upper layers can instantiate the correct XBee device class.
            if self._device_hw_version.code in SX_HW_VERSIONS:
                if (isinstance(self._xbee, (DigiMeshDevice, DigiPointDevice)) and
                        protocol_changed_by_settings):
                    raise UpdateProfileException("Check if you are using the appropriate device class.")
        except UpdateProfileException as exc:
            update_result = "Error: %s" % str(exc)
            raise exc
        finally:
            if self._configurer:
                self._configurer.restore_after_update(
                    net_changed, protocol_changed_by_settings, port_settings)

            self._profile.close()

            if self._is_local and self._xbee:
                if self._was_connected and not self._xbee.is_open():
                    self._xbee.open()
                elif not self._was_connected and self._xbee.is_open():
                    self._xbee.close()

            self._notify_progress(update_result, 100, finished=True)


def apply_xbee_profile(target, profile_path, timeout=None, progress_callback=None):
    """
    Applies the given XBee profile into the given XBee.
    If a serial port is provided as `target`, the XBee profile must include
    the firmware binaries, that are always programmed. In this case, a restore
    defaults is also performed before applying settings in the profile (no
    matter if the profile is configured to do so or not). If the value of 'AP'
    (operating mode) in the profile is not an API mode or it is not defined,
    XBee is configured to use API 1.

    Args:
        target (String or :class:`.AbstractXBeeDevice`): Target to apply
            profile to. String: serial port identifier.
            :class:`.AbstractXBeeDevice`: XBee to apply the profile.
        profile_path (String): path of the XBee profile file to apply.
        timeout (Integer, optional): Maximum time to wait for target read
            operations during the apply profile.
        progress_callback (Function, optional): Function to execute to receive
            progress information. Receives two arguments:

            * The current update task as a String
            * The current update task percentage as an Integer

    Raises:
        ValueError: If the XBee profile or the XBee device is not valid.
        UpdateProfileException: If there is any error during the update XBee
            profile operation.
    """
    # Sanity checks.
    if not isinstance(target, (str, XBeeDevice, RemoteXBeeDevice)):
        _log.error("ERROR: %s", _ERROR_TARGET_INVALID)
        raise ValueError(_ERROR_TARGET_INVALID)
    if not isinstance(profile_path, str):
        _log.error("ERROR: %s", _ERROR_PROFILE_NOT_VALID)
        raise ValueError(_ERROR_PROFILE_NOT_VALID)

    try:
        xbee_profile = XBeeProfile(profile_path)
    except (ValueError, ReadProfileException) as exc:
        error = _ERROR_PROFILE_INVALID % str(exc)
        _log.error("ERROR: %s", error)
        raise UpdateProfileException(error) from exc

    if not timeout:
        timeout = _REMOTE_DEFAULT_TIMEOUT \
            if (isinstance(target, str) or target.is_remote()) else _LOCAL_DEFAULT_TIMEOUT

    # With a serial port as target the profile must include the firmware file
    if isinstance(target, str) and not xbee_profile.has_local_firmware_files:
        error = _ERROR_PROFILE_INVALID % " Profile must include the firmware " \
                                         "binary files to use with a serial port"
        _log.error("ERROR: %s", error)
        raise UpdateProfileException(error)

    if not isinstance(target, str):
        comm_iface = target.get_comm_iface() if target.is_remote() else target.comm_iface
        if comm_iface and comm_iface.supports_apply_profile():
            comm_iface.apply_profile(target, profile_path, timeout=timeout,
                                     progress_callback=progress_callback)
            return

        target._active_update_type = NodeUpdateType.PROFILE

    profile_updater = _ProfileUpdater(target, xbee_profile, timeout=timeout,
                                      progress_callback=progress_callback)
    profile_updater.update_profile()
