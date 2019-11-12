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
import shutil
import tempfile
import serial
import time
import zipfile

from digi.xbee import firmware
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice
from digi.xbee.exception import XBeeException, TimeoutException, FirmwareUpdateException, ATCommandException
from digi.xbee.filesystem import LocalXBeeFileSystemManager, FileSystemException, FileSystemNotSupportedException
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.util import utils
from enum import Enum, unique
from pathlib import Path
from serial.serialutil import SerialException
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

_ERROR_ACCESS_FILESYSTEM = "Could not access XBee device file system"
_ERROR_DEVICE_NOT_VALID = "The XBee device is not valid"
_ERROR_FILESYSTEM_NOT_SUPPORTED = "XBee device does not have file system support"
_ERROR_FIRMWARE_FOLDER_NOT_EXIST = "Firmware folder does not exist"
_ERROR_FIRMWARE_NOT_COMPATIBLE = "The XBee profile is not compatible with the device firmware"
_ERROR_FIRMWARE_SETTING_NOT_EXIST = "Firmware setting '%s' does not exist"
_ERROR_FIRMWARE_XML_INVALID = "Invalid firmware XML file contents: %s"
_ERROR_FIRMWARE_XML_NOT_EXIST = "Firmware XML file does not exist"
_ERROR_FIRMWARE_XML_PARSE = "Error parsing firmware XML file: %s"
_ERROR_HARDWARE_NOT_COMPATIBLE = "The XBee profile is not compatible with the device hardware"
_ERROR_HARDWARE_NOT_COMPATIBLE_XBEE3 = "Only XBee 3 devices support firmware update in the XBee profile"
_ERROR_OPEN_DEVICE = "Error opening XBee device: %s"
_ERROR_PROFILE_NOT_VALID = "The XBee profile is not valid"
_ERROR_PROFILE_INVALID = "Invalid XBee profile: %s"
_ERROR_PROFILE_PATH_INVALID = "Profile path '%s' is not valid"
_ERROR_PROFILE_UNCOMPRESS = "Error un-compressing profile file: %s"
_ERROR_PROFILE_TEMP_DIR = "Error creating temporary directory: %s"
_ERROR_PROFILE_XML_NOT_EXIST = "Profile XML file does not exist"
_ERROR_PROFILE_XML_INVALID = "Invalid profile XML file contents: %s"
_ERROR_PROFILE_XML_PARSE = "Error parsing profile XML file: %s"
_ERROR_PROFILES_NOT_SUPPORTED = "XBee profiles are only supported in XBee 3 devices"
_ERROR_READ_REMOTE_PARAMETER = "Error reading remote parameter: %s"
_ERROR_UPDATE_FILESYSTEM = "Error updating XBee filesystem: %s"
_ERROR_UPDATE_FIRMWARE = "Error updating XBee firmware: %s"
_ERROR_UPDATE_SERIAL_PORT = "Error re-configuring XBee device serial port: %s"
_ERROR_UPDATE_SETTINGS = "Error updating XBee settings: %s"

_FILESYSTEM_FOLDER = "filesystem"

_FIRMWARE_FOLDER_NAME = "radio_fw"
_FIRMWARE_XML_FILE_NAME = "radio_fw.xml"

_IPV4_SEPARATOR = "."
_IPV6_SEPARATOR = ":"

_PARAMETER_READ_RETRIES = 3
_PARAMETER_WRITE_RETRIES = 3
_PARAMETERS_SERIAL_PORT = [ATStringCommand.BD.command,
                           ATStringCommand.NB.command,
                           ATStringCommand.SB.command,
                           ATStringCommand.D7.command]

_PROFILE_XML_FILE_NAME = "profile.xml"

SUPPORTED_HARDWARE_VERSIONS = (HardwareVersion.XBEE3.code,
                               HardwareVersion.XBEE3_SMT.code,
                               HardwareVersion.XBEE3_TH.code)

_TASK_CONNECT_FILESYSTEM = "Connecting with device filesystem"
_TASK_FORMAT_FILESYSTEM = "Formatting filesystem"
_TASK_READING_DEVICE_PARAMETERS = "Reading device parameters"
_TASK_UPDATE_FILE = "Updating file '%s'"
_TASK_UPDATE_SETTINGS = "Updating XBee settings"

_VALUE_CTS_ON = "1"

_WILDCARD_BOOTLOADER = "xb3-boot*.gbl"
_WILDCARD_CELLULAR_FIRMWARE = "fw_.*"
_WILDCARD_CELLULAR_BOOTLOADER = "bl_.*"
_WILDCARD_EBIN = "*.ebin"
_WILDCARD_EHX2 = "*.ehx2"
_WILDCARD_GBL = "*.gbl"
_WILDCARD_OTA = "*.ota"
_WILDCARD_OTB = "*.otb"
_WILDCARD_XML = "*.xml"
_WILDCARDS_FIRMWARE_BINARY_FILES = [_WILDCARD_EBIN, _WILDCARD_EHX2, _WILDCARD_GBL, _WILDCARD_OTA, _WILDCARD_OTB]

_XML_COMMAND = "command"
_XML_CONTROL_TYPE = "control_type"
_XML_DEFAULT_VALUE = "default_value"
_XML_FIRMWARE_FIRMWARE = "firmware"
_XML_FIRMWARE_FIRMWARE_VERSION = "fw_version"
_XML_FIRMWARE_HARDWARE_VERSION = "firmware/hw_version"
_XML_FIRMWARE_SETTING = ".//setting"
_XML_FORMAT = "format"
_XML_PROFILE_AT_SETTING = "profile/settings/setting"
_XML_PROFILE_DESCRIPTION = "profile/description"
_XML_PROFILE_FLASH_FIRMWARE_OPTION = "profile/flash_fw_action"
_XML_PROFILE_RESET_SETTINGS = "profile/reset_settings"
_XML_PROFILE_ROOT = "data"
_XML_PROFILE_VERSION = "profile/profile_version"
_XML_PROFILE_XML_FIRMWARE_FILE = "profile/description_file"

_log = logging.getLogger(__name__)


@unique
class FirmwareBaudrate(Enum):
    """
    This class lists the available firmware baudrate options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this FirmwareBaudrate.
    |     **value** (Integer): The ID of this FirmwareBaudrate.
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
        Returns the FirmwareBaudrate for the given index.

        Args:
            index (Integer): the index of the FirmwareBaudrate to get.

        Returns:
            :class:`.FirmwareBaudrate`: the FirmwareBaudrate with the given index, ``None`` if
                                         there is not a FirmwareBaudrate with that index.
        """
        if index is None:
            return FirmwareBaudrate.BD_9600
        for value in FirmwareBaudrate:
            if value.index == index:
                return value

        return None

    @property
    def index(self):
        """
        Returns the index of the FirmwareBaudrate element.

        Returns:
            Integer: the index of the FirmwareBaudrate element.
        """
        return self.__index

    @property
    def baudrate(self):
        """
        Returns the baudrate of the FirmwareBaudrate element.

        Returns:
            Integer: the baudrate of the FirmwareBaudrate element.
        """
        return self.__baudrate


FirmwareBaudrate.__doc__ += utils.doc_enum(FirmwareBaudrate)


@unique
class FirmwareParity(Enum):
    """
    This class lists the available firmware parity options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this FirmwareParity.
    |     **value** (Integer): The ID of this FirmwareParity.
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
        Returns the FirmwareParity for the given index.

        Args:
            index (Integer): the index of the FirmwareParity to get.

        Returns:
            :class:`.FirmwareParity`: the FirmwareParity with the given index, ``None`` if
                                       there is not a FirmwareParity with that index.
        """
        if index is None:
            return FirmwareParity.NONE
        for value in FirmwareParity:
            if value.index == index:
                return value

        return None

    @property
    def index(self):
        """
        Returns the index of the FirmwareParity element.

        Returns:
            Integer: the index of the FirmwareParity element.
        """
        return self.__index

    @property
    def parity(self):
        """
        Returns the parity of the FirmwareParity element.

        Returns:
            String: the parity of the FirmwareParity element.
        """
        return self.__parity


FirmwareParity.__doc__ += utils.doc_enum(FirmwareParity)


@unique
class FirmwareStopbits(Enum):
    """
    This class lists the available firmware stop bits options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this FirmwareStopbits.
    |     **value** (Integer): The ID of this FirmwareStopbits.
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
        Returns the FirmwareStopbits for the given index.

        Args:
            index (Integer): the index of the FirmwareStopbits to get.

        Returns:
            :class:`.FirmwareStopbits`: the FirmwareStopbits with the given index, ``None`` if
                                         there is not a FirmwareStopbits with that index.
        """
        if index is None:
            return FirmwareStopbits.SB_1
        for value in FirmwareStopbits:
            if value.index == index:
                return value

        return None

    @property
    def index(self):
        """
        Returns the index of the FirmwareStopbits element.

        Returns:
            Integer: the index of the FirmwareStopbits element.
        """
        return self.__index

    @property
    def stop_bits(self):
        """
        Returns the stop bits of the FirmwareStopbits element.

        Returns:
            Float: the stop bits of the FirmwareStopbits element.
        """
        return self.__stop_bits


FirmwareStopbits.__doc__ += utils.doc_enum(FirmwareStopbits)


@unique
class FlashFirmwareOption(Enum):
    """
    This class lists the available flash firmware options for XBee Profiles.

    | Inherited properties:
    |     **name** (String): The name of this FlashFirmwareOption.
    |     **value** (Integer): The ID of this FlashFirmwareOption.
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
        Returns the FlashFirmwareOption for the given code.

        Args:
            code (Integer): the code of the flash firmware option to get.

        Returns:
            :class:`.FlashFirmwareOption`: the FlashFirmwareOption with the given code, ``None`` if
                                           there is not a FlashFirmwareOption with that code.
        """
        for value in FlashFirmwareOption:
            if value.code == code:
                return value

        return None

    @property
    def code(self):
        """
        Returns the code of the FlashFirmwareOption element.

        Returns:
            Integer: the code of the FlashFirmwareOption element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the FlashFirmwareOption element.

        Returns:
            String: the description of the FlashFirmwareOption element.
        """
        return self.__description


FlashFirmwareOption.__doc__ += utils.doc_enum(FlashFirmwareOption)


@unique
class XBeeSettingType(Enum):
    """
    This class lists the available firmware setting types.

    | Inherited properties:
    |     **name** (String): The name of this XBeeSettingType.
    |     **value** (Integer): The ID of this XBeeSettingType.
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
        Returns the XBeeSettingType for the given tag.

        Args:
            tag (String): the tag of the XBeeSettingType to get.

        Returns:
            :class:`.XBeeSettingType`: the XBeeSettingType with the given tag, ``None`` if
                                       there is not a XBeeSettingType with that tag.
        """
        for value in XBeeSettingType:
            if value.tag == tag:
                return value

        return None

    @property
    def tag(self):
        """
        Returns the tag of the XBeeSettingType element.

        Returns:
            String: the tag of the XBeeSettingType element.
        """
        return self.__tag

    @property
    def description(self):
        """
        Returns the description of the XBeeSettingType element.

        Returns:
            String: the description of the XBeeSettingType element.
        """
        return self.__description


XBeeSettingType.__doc__ += utils.doc_enum(XBeeSettingType)


@unique
class XBeeSettingFormat(Enum):
    """
    This class lists the available text firmware setting formats.

    | Inherited properties:
    |     **name** (String): The name of this XBeeSettingFormat.
    |     **value** (Integer): The ID of this XBeeSettingFormat.
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
        Returns the XBeeSettingFormat for the given tag.

        Args:
            tag (String): the tag of the XBeeSettingFormat to get.

        Returns:
            :class:`.XBeeSettingFormat`: the XBeeSettingFormat with the given tag, ``None`` if
                                         there is not a XBeeSettingFormat with that tag.
        """
        for value in XBeeSettingFormat:
            if value.tag == tag:
                return value

        return None

    @property
    def tag(self):
        """
        Returns the tag of the XBeeSettingFormat element.

        Returns:
            String: the tag of the XBeeSettingFormat element.
        """
        return self.__tag

    @property
    def description(self):
        """
        Returns the description of the XBeeSettingFormat element.

        Returns:
            String: the description of the XBeeSettingFormat element.
        """
        return self.__description


XBeeSettingFormat.__doc__ += utils.doc_enum(XBeeSettingFormat)


class XBeeProfileSetting(object):
    """
    This class represents an XBee profile setting and provides information like
    the setting name, type, format and value.
    """

    def __init__(self, name, setting_type, setting_format, value):
        """
        Class constructor. Instantiates a new :class:`.XBeeProfileSetting` with the given parameters.

        Args:
            name (String): the setting name
            setting_type (:class:`.XBeeSettingType`): the setting type
            setting_format (:class:`.XBeeSettingType`): the setting format
            value (String): the setting value
        """
        self._name = name
        self._type = setting_type
        self._format = setting_format
        self._value = value
        self._bytearray_value = self._setting_value_to_bytearray()

    def _setting_value_to_bytearray(self):
        """
        Transforms the setting value to a byte array to be written in the XBee device.

        Returns:
            (Bytearray): the setting value formatted as byte array
        """
        if self._type in (XBeeSettingType.COMBO, XBeeSettingType.NUMBER):
            return utils.hex_string_to_bytes(self._value)
        elif self._type is XBeeSettingType.TEXT:
            if self._format in (XBeeSettingFormat.ASCII, XBeeSettingFormat.PHONE):
                return bytearray(self._value, 'utf8')
            elif self._format in (XBeeSettingFormat.HEX, XBeeSettingFormat.NO_FORMAT):
                return utils.hex_string_to_bytes(self._value)
            elif self._format is XBeeSettingFormat.IPV4:
                octets = list(map(int, self._value.split(_IPV4_SEPARATOR)))
                return bytearray(octets)
            elif self._format is XBeeSettingFormat.IPV6:
                if _IPV6_SEPARATOR in self._value:
                    return bytearray(self._value, 'utf8')
        elif self._type in (XBeeSettingType.BUTTON, XBeeSettingType.NO_TYPE):
            return bytearray(0)

        return self._value

    @property
    def name(self):
        """
        Returns the XBee setting name.

        Returns:
            String: the XBee setting name.
         """
        return self._name

    @property
    def type(self):
        """
        Returns the XBee setting type.

        Returns:
            :class:`.XBeeSettingType`: the XBee setting type.
         """
        return self._type

    @property
    def format(self):
        """
        Returns the XBee setting format.

        Returns:
            :class:`.XBeeSettingFormat`: the XBee setting format.
         """
        return self._format

    @property
    def value(self):
        """
        Returns the XBee setting value as string.

        Returns:
            String: the XBee setting value as string.
         """
        return self._value

    @property
    def bytearray_value(self):
        """
        Returns the XBee setting value as bytearray to be set in the device.

        Returns:
            Bytearray: the XBee setting value as bytearray to be set in the device.
         """
        return self._bytearray_value


class ReadProfileException(XBeeException):
    """
    This exception will be thrown when any problem reading the XBee profile occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class UpdateProfileException(XBeeException):
    """
    This exception will be thrown when any problem updating the XBee profile into a device occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class XBeeProfile(object):
    """
    Helper class used to manage serial port break line in a parallel thread.
    """

    def __init__(self, profile_file):
        """
        Class constructor. Instantiates a new :class:`.XBeeProfile` with the given parameters.

        Args:
            profile_file (String): path of the '.xpro' profile file.

        Raises:
            ProfileReadException: if there is any error reading the profile file.
            ValueError: if the provided profile file is not valid
        """
        if not os.path.isfile(profile_file):
            raise ValueError(_ERROR_PROFILE_PATH_INVALID % profile_file)
        self._profile_file = profile_file
        self._profile_folder = None
        self._profile_xml_file = None
        self._firmware_xml_file = None
        self._bootloader_file = None
        self._version = 0
        self._flash_firmware_option = FlashFirmwareOption.FLASH_DIFFERENT
        self._description = None
        self._reset_settings = True
        self._profile_settings = []
        self._firmware_binary_files = []
        self._file_system_path = None
        self._cellular_firmware_files = []
        self._cellular_bootloader_files = []
        self._firmware_version = None
        self._hardware_version = None

        self._uncompress_profile()
        self._check_profile_integrity()
        self._parse_xml_profile_file()
        self._parse_xml_firmware_file()

    def __del__(self):
        if not hasattr(self, 'profile_folder'):
            return

        if self._profile_folder is not None and os.path.isdir(self._profile_folder):
            shutil.rmtree(self._profile_folder)

    def _parse_xml_profile_file(self):
        """
        Parses the XML profile file and stores the required parameters.

        Raises:
            ProfileReadException: if there is any error parsing the XML profile file.
        """
        _log.debug("Parsing XML profile file %s:" % self._profile_xml_file)
        try:
            root = ElementTree.parse(self._profile_xml_file).getroot()
            # XML firmware file. Mandatory.
            firmware_xml_file_element = root.find(_XML_PROFILE_XML_FIRMWARE_FILE)
            if firmware_xml_file_element is None:
                self._throw_read_exception(_ERROR_PROFILE_XML_INVALID % "missing firmware file element")
            self._firmware_xml_file = os.path.join(self._profile_folder, _FIRMWARE_FOLDER_NAME,
                                                   firmware_xml_file_element.text)
            if not os.path.isfile(self._firmware_xml_file):
                self._throw_read_exception(_ERROR_FIRMWARE_XML_NOT_EXIST)
            _log.debug(" - XML firmware file: %s" % self._firmware_xml_file)
            # Version. Optional.
            version_element = root.find(_XML_PROFILE_VERSION)
            if version_element is not None:
                self._version = int(version_element.text)
            _log.debug(" - Version: %d" % self._version)
            # Flash firmware option. Required.
            flash_firmware_option_element = root.find(_XML_PROFILE_FLASH_FIRMWARE_OPTION)
            if flash_firmware_option_element is not None:
                self._flash_firmware_option = FlashFirmwareOption.get(int(flash_firmware_option_element.text))
            if self._flash_firmware_option is None:
                self._throw_read_exception(_ERROR_PROFILE_XML_INVALID % "invalid flash firmware option")
            _log.debug(" - Flash firmware option: %s" % self._flash_firmware_option.description)
            # Description. Optional.
            description_element = root.find(_XML_PROFILE_DESCRIPTION)
            if description_element is not None:
                self._description = description_element.text
            _log.debug(" - Description: %s" % self._description)
            # Reset settings. Optional.
            reset_settings_element = root.find(_XML_PROFILE_RESET_SETTINGS)
            if reset_settings_element is not None:
                self._reset_settings = reset_settings_element.text in ("True", "true", "1")
            _log.debug(" - Reset settings: %s" % self._reset_settings)
            # Parse AT settings.
            _log.debug(" - AT settings:")
            firmware_root = ElementTree.parse(self._firmware_xml_file).getroot()
            setting_elements = root.findall(_XML_PROFILE_AT_SETTING)
            if not setting_elements:
                _log.debug("  - None")
                return
            for setting_element in setting_elements:
                setting_name = setting_element.get(_XML_COMMAND)
                setting_value = setting_element.text
                for firmware_setting_element in firmware_root.findall(_XML_FIRMWARE_SETTING):
                    if firmware_setting_element.get(_XML_COMMAND) == setting_name:
                        setting_type_element = firmware_setting_element.find(_XML_CONTROL_TYPE)
                        setting_type = XBeeSettingType.NO_TYPE
                        if setting_type_element is not None:
                            setting_type = XBeeSettingType.get(setting_type_element.text)
                        setting_format_element = firmware_setting_element.find(_XML_FORMAT)
                        setting_format = XBeeSettingFormat.NO_FORMAT
                        if setting_format_element is not None:
                            setting_format = XBeeSettingFormat.get(setting_format_element.text)
                        profile_setting = XBeeProfileSetting(setting_name, setting_type, setting_format,
                                                             setting_value)
                        _log.debug("  - Setting '%s' - type: %s - format: %s - value: %s" %
                                   (profile_setting.name, profile_setting.type.description,
                                    profile_setting.format.description, profile_setting.value))
                        self._profile_settings.append(profile_setting)

        except ParseError as e:
            self._throw_read_exception(_ERROR_PROFILE_XML_PARSE % str(e))

    def _uncompress_profile(self):
        """
        Un-compresses the profile into a temporary folder and saves the folder location.

        Raises:
            ProfileReadException: if there is any error un-compressing the profile file.
        """
        try:
            self._profile_folder = tempfile.mkdtemp()
        except (PermissionError, FileExistsError) as e:
            self._throw_read_exception(_ERROR_PROFILE_TEMP_DIR % str(e))

        _log.debug("Un-compressing profile into '%s'" % self._profile_folder)
        try:
            with zipfile.ZipFile(self._profile_file, "r") as zip_ref:
                zip_ref.extractall(self._profile_folder)
        except Exception as e:
            _log.error(_ERROR_PROFILE_UNCOMPRESS % str(e))
            self._throw_read_exception(_ERROR_PROFILE_UNCOMPRESS % str(e))

    def _check_profile_integrity(self):
        """
        Checks the profile integrity and stores the required information.

        Raises:
            ProfileReadException: if there is any error checking the profile integrity.
        """
        # Profile XML file.
        self._profile_xml_file = os.path.join(self._profile_folder, _PROFILE_XML_FILE_NAME)
        if not os.path.isfile(self._profile_xml_file):
            self._throw_read_exception(_ERROR_PROFILE_XML_NOT_EXIST)
        # Firmware folder.
        if not os.path.isdir(os.path.join(self._profile_folder, _FIRMWARE_FOLDER_NAME)):
            self._throw_read_exception(_ERROR_FIRMWARE_FOLDER_NOT_EXIST)
        # Firmware XML file pattern.
        firmware_path = Path(os.path.join(self._profile_folder, _FIRMWARE_FOLDER_NAME))
        if len(list(firmware_path.rglob(_WILDCARD_XML))) is 0:
            self._throw_read_exception(_ERROR_FIRMWARE_XML_NOT_EXIST)
        # Filesystem folder.
        if os.path.isdir(os.path.join(self._profile_folder, _FILESYSTEM_FOLDER)):
            self._file_system_path = os.path.join(self._profile_folder, _FILESYSTEM_FOLDER)
        # Bootloader file.
        if len(list(firmware_path.rglob(_WILDCARD_BOOTLOADER))) is not 0:
            self._bootloader_file = str(list(firmware_path.rglob(_WILDCARD_BOOTLOADER))[0])
        # Firmware binary files.
        for wildcard in _WILDCARDS_FIRMWARE_BINARY_FILES:
            for file in list(firmware_path.rglob(wildcard)):
                self._firmware_binary_files.append(str(file))
        # Cellular firmware files.
        for file in list(firmware_path.rglob(_WILDCARD_CELLULAR_FIRMWARE)):
            self._cellular_firmware_files.append(str(file))
        # Cellular bootloader files.
        for file in list(firmware_path.rglob(_WILDCARD_CELLULAR_BOOTLOADER)):
            self._cellular_bootloader_files.append(str(file))

    def _parse_xml_firmware_file(self):
        """
        Parses the XML firmware file and stores the required parameters.

        Raises:
            ProfileReadException: if there is any error parsing the XML firmware file.
        """
        _log.debug("Parsing XML firmware file %s:" % self._firmware_xml_file)
        try:
            root = ElementTree.parse(self._firmware_xml_file).getroot()
            # Firmware version.
            firmware_element = root.find(_XML_FIRMWARE_FIRMWARE)
            if firmware_element is None:
                self._throw_read_exception(_ERROR_FIRMWARE_XML_INVALID % "missing firmware element")
            self._firmware_version = int(firmware_element.get(_XML_FIRMWARE_FIRMWARE_VERSION))
            if self._firmware_version is None:
                self._throw_read_exception(_ERROR_FIRMWARE_XML_INVALID % "missing firmware version")
            _log.debug(" - Firmware version: %s" % self._firmware_version)
            # Hardware version.
            hardware_version_element = root.find(_XML_FIRMWARE_HARDWARE_VERSION)
            if hardware_version_element is None:
                self._throw_read_exception(_ERROR_FIRMWARE_XML_INVALID % "missing hardware version element")
            self._hardware_version = int(hardware_version_element.text, 16)
            _log.debug(" - Hardware version: %s" % self._hardware_version)
        except ParseError as e:
            self._throw_read_exception(_ERROR_FIRMWARE_XML_PARSE % str(e))

    def get_setting_default_value(self, setting_name):
        """
        Returns the default value of the given firmware setting.

        Args:
            setting_name (String): the name of the setting to retrieve its default value.

        Returns:
            String: the default value of the setting, ``None`` if the setting is not found or it has no default value.
        """
        try:
            firmware_root = ElementTree.parse(self._firmware_xml_file).getroot()
            for firmware_setting_element in firmware_root.findall(_XML_FIRMWARE_SETTING):
                if firmware_setting_element.get(_XML_COMMAND) == setting_name:
                    default_value_element = firmware_setting_element.find(_XML_DEFAULT_VALUE)
                    if default_value_element is None:
                        return None
                    return default_value_element.text
        except ParseError as e:
            _log.exception(e)

        return None

    @staticmethod
    def _throw_read_exception(message):
        """
        Throws an XBee profile read exception with the given message and logs it.

        Args:
            message (String): the exception message

        Raises:
            ProfileReadException: the exception thrown wit the given message.
        """
        _log.error("ERROR: %s" % message)
        raise ReadProfileException(message)

    @property
    def profile_file(self):
        """
        Returns the profile file.

        Returns:
            String: the profile file.
         """
        return self._profile_file

    @property
    def version(self):
        """
        Returns the profile version.

        Returns:
            String: the profile version.
         """
        return self._version

    @property
    def flash_firmware_option(self):
        """
        Returns the profile flash firmware option.

        Returns:
            :class:`.FlashFirmwareOption`: the profile flash firmware option.

        .. seealso::
           | :class:`.FlashFirmwareOption`
         """
        return self._flash_firmware_option

    @property
    def description(self):
        """
        Returns the profile description.

        Returns:
            String: the profile description.
         """
        return self._description

    @property
    def reset_settings(self):
        """
        Returns whether the settings of the XBee device will be reset before applying the profile ones or not.

        Returns:
            Boolean: ``True`` if the settings of the XBee device will be reset before applying the profile ones,
                     ``False`` otherwise.
         """
        return self._reset_settings

    @property
    def has_filesystem(self):
        """
        Returns whether the profile has filesystem information or not.

        Returns:
            Boolean: ``True`` if the profile has filesystem information, ``False`` otherwise.
         """
        return self._file_system_path is not None

    @property
    def profile_settings(self):
        """
        Returns all the firmware settings that the profile configures.

        Returns:
            List: a list with all the firmware settings that the profile configures (:class:`.XBeeProfileSetting`).
         """
        return self._profile_settings

    @property
    def firmware_version(self):
        """
        Returns the compatible firmware version of the profile.

        Returns:
            Integer: the compatible firmware version of the profile.
        """
        return self._firmware_version

    @property
    def hardware_version(self):
        """
        Returns the compatible hardware version of the profile.

        Returns:
            Integer: the compatible hardware version of the profile.
        """
        return self._hardware_version

    @property
    def firmware_description_file(self):
        """
        Returns the path of the profile firmware description file.

        Returns:
            String: the path of the profile firmware description file.
        """
        return self._firmware_xml_file

    @property
    def file_system_path(self):
        """
        Returns the profile file system path.

        Returns:
            String: the path of the profile file system directory.
        """
        return self._file_system_path


class _ProfileUpdater(object):
    """
    Helper class used to handle the update XBee profile process.
    """

    def __init__(self, xbee_device, xbee_profile, progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._ProfileUpdater` with the given parameters.

        Args:
            xbee_device (:class:`.XBeeDevice` or :class:`.RemoteXBeeDevice`): The XBee device to apply profile to.
            xbee_profile (:class:`.XBeeProfile`): The XBee profile to apply.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        self._xbee_profile = xbee_profile
        self._xbee_device = xbee_device
        self._progress_callback = progress_callback
        self._was_connected = True
        self._device_firmware_version = None
        self._device_hardware_version = None
        self._old_port_parameters = None
        self._is_local = True
        if isinstance(self._xbee_device, RemoteXBeeDevice):
            self._is_local = False

    def _firmware_progress_callback(self, task, percent):
        """
        Receives firmware update progress information

        Args:
            task (String): the current firmware update task.
            percent (Integer): the current firmware update progress percent.
        """
        if self._progress_callback is not None:
            self._progress_callback(task, percent)

    def _read_device_parameters(self):
        """
        Reads and stores the required XBee device parameters in order to apply the XBee profile.

        Raises:
            UpdateProfileException: if there is any error reading the required XBee device parameters.
        """
        _log.debug("Reading device parameters:")
        if self._progress_callback is not None:
            self._progress_callback(_TASK_READING_DEVICE_PARAMETERS, None)
        if self._is_local:
            # Connect the device.
            if not self._xbee_device.is_open():
                self._was_connected = False
                try:
                    self._xbee_device.open()
                except XBeeException as e:
                    raise UpdateProfileException(_ERROR_OPEN_DEVICE % str(e))
            # For local devices, required parameters are read on 'open()' method, just use them.
            self._device_firmware_version = self._xbee_device.get_firmware_version()
            self._device_hardware_version = self._xbee_device.get_hardware_version()
        else:
            # For remote devices, parameters are read with 'get_parameter()' method.
            try:
                self._device_firmware_version = self._read_parameter_with_retries(ATStringCommand.VR.command,
                                                                                  _PARAMETER_READ_RETRIES)
                self._device_hardware_version = HardwareVersion.get(self._read_parameter_with_retries(
                    ATStringCommand.HV.command, _PARAMETER_READ_RETRIES)[0])
            except XBeeException as e:
                raise UpdateProfileException(_ERROR_READ_REMOTE_PARAMETER % str(e))

        # Sanitize firmware version.
        self._device_firmware_version = int(utils.hex_to_string(self._device_firmware_version).replace(" ", ""))
        _log.debug("  - Firmware version: %s" % self._device_firmware_version)
        _log.debug("  - Hardware version: %s" % self._device_hardware_version.code)

    def _read_parameter_with_retries(self, parameter, retries):
        """
        Reads the given parameter from the XBee device within the given number of retries.

        Args:
            parameter (String): the parameter to read.
            retries (Integer): the number of retries to read the parameter.

        Returns:
            Bytearray: the read parameter value.

        Raises:
            XBeeException: if there is any error reading the parameter.
        """
        while retries > 0:
            try:
                return self._xbee_device.get_parameter(parameter)
            except TimeoutException:
                retries -= 1
                time.sleep(0.2)
            except XBeeException:
                raise

        raise XBeeException("Timeout reading parameter '%s'" % parameter)

    def _set_parameter_with_retries(self, parameter, value, retries):
        """
        Sets the given parameter in the XBee device within the given number of retries.

        Args:
            parameter (String): the parameter to set.
            value (Bytearray): the parameter value to set.
            retries (Integer): the number of retries to set the parameter.

        Raises:
            XBeeException: if there is any error setting the parameter.
        """
        _log.debug("Setting parameter '%s' to '%s'" % (parameter, value))
        msg = ""
        while retries > 0:
            try:
                return self._xbee_device.set_parameter(parameter, value)
            except (TimeoutException, ATCommandException) as e:
                msg = str(e)
                retries -= 1
                time.sleep(0.2)
            except XBeeException:
                raise

        raise XBeeException("Error setting parameter '%s': %s" % parameter, msg)

    def _update_firmware(self):
        """
        Updates the XBee device firmware.

        Raises:
            UpdateProfileException: if there is any error updating the XBee firmware.
        """
        try:
            self._xbee_device.update_firmware(self._xbee_profile.firmware_description_file,
                                              progress_callback=self._firmware_progress_callback)
        except FirmwareUpdateException as e:
            raise UpdateProfileException(_ERROR_UPDATE_FIRMWARE % str(e))

    def _check_port_settings_changed(self):
        """
        Checks whether the port settings of the device have changed in order to update serial port connection.

        Raises:
            UpdateProfileException: if there is any error checking serial port settings changes.
        """
        port_parameters = self._xbee_device.serial_port.get_settings()
        baudrate_changed = False
        parity_changed = False
        stop_bits_changed = False
        cts_flow_control_changed = False
        for setting in self._xbee_profile.profile_settings:
            if setting.name in _PARAMETERS_SERIAL_PORT:
                if setting.name == ATStringCommand.BD.command:
                    baudrate_changed = True
                    port_parameters["baudrate"] = FirmwareBaudrate.get(int(setting.value, 16)).baudrate
                elif setting.name == ATStringCommand.NB.command:
                    parity_changed = True
                    port_parameters["parity"] = FirmwareParity.get(int(setting.value, 16)).parity
                elif setting.name == ATStringCommand.SB.command:
                    stop_bits_changed = True
                    port_parameters["stopbits"] = FirmwareStopbits.get(int(setting.value, 16)).stop_bits
                elif setting.name == ATStringCommand.D7.command:
                    cts_flow_control_changed = True
                    if setting.value == _VALUE_CTS_ON:
                        port_parameters["rtscts"] = True
                    else:
                        port_parameters["rtscts"] = False
        if self._xbee_profile.reset_settings:
            if not baudrate_changed:
                baudrate_changed = True
                default_baudrate = self._xbee_profile.get_setting_default_value(
                    ATStringCommand.BD.command)
                port_parameters["baudrate"] = FirmwareBaudrate.get(int(default_baudrate, 16)).baudrate
            if not parity_changed:
                parity_changed = True
                default_parity = self._xbee_profile.get_setting_default_value(ATStringCommand.NB.command)
                port_parameters["parity"] = FirmwareParity.get(int(default_parity, 16)).parity
            if not stop_bits_changed:
                stop_bits_changed = True
                default_stop_bits = self._xbee_profile.get_setting_default_value(
                    ATStringCommand.SB.command)
                port_parameters["stopbits"] = FirmwareStopbits.get(int(default_stop_bits, 16)).stop_bits
            if not cts_flow_control_changed:
                cts_flow_control_changed = True
                port_parameters["rtscts"] = True  # Default CTS value is always on.

        if baudrate_changed or parity_changed or stop_bits_changed or cts_flow_control_changed:
            # Apply the new port configuration.
            try:
                self._xbee_device.close()  # This is necessary to stop the frames read thread.
                self._xbee_device.serial_port.apply_settings(port_parameters)
                self._xbee_device.open()
            except (XBeeException, SerialException) as e:
                raise UpdateProfileException(_ERROR_UPDATE_SERIAL_PORT % str(e))

    def _update_device_settings(self):
        """
        Updates the device settings using the profile.

        Raises:
            UpdateProfileException: if there is any error updating device settings from the profile.
        """
        # Disable apply settings so Queue AT commands are issued instead of AT commands
        old_apply_settings_value = self._xbee_device.is_apply_changes_enabled
        self._xbee_device.enable_apply_changes(False)
        try:
            previous_percent = 0
            percent = 0
            setting_index = 1
            num_settings = len(self._xbee_profile.profile_settings) + 2  # 2 more settings for 'WR' and 'AC'
            _log.info("Updating device settings")
            if self._progress_callback is not None:
                self._progress_callback(_TASK_UPDATE_SETTINGS, percent)
            # Check if reset settings is required.
            if self._xbee_profile.reset_settings:
                num_settings += 1  # One more setting for 'RE'
                percent = setting_index * 100 // num_settings
                if self._progress_callback is not None and percent != previous_percent:
                    self._progress_callback(_TASK_UPDATE_SETTINGS, percent)
                    previous_percent = percent
                self._set_parameter_with_retries(ATStringCommand.RE.command,
                                                 bytearray(0), _PARAMETER_WRITE_RETRIES)
                setting_index += 1
            # Set settings.
            for setting in self._xbee_profile.profile_settings:
                percent = setting_index * 100 // num_settings
                if self._progress_callback is not None and percent != previous_percent:
                    self._progress_callback(_TASK_UPDATE_SETTINGS, percent)
                    previous_percent = percent
                self._set_parameter_with_retries(setting.name, setting.bytearray_value, _PARAMETER_WRITE_RETRIES)
                setting_index += 1
            # Write settings.
            percent = setting_index * 100 // num_settings
            if self._progress_callback is not None and percent != previous_percent:
                self._progress_callback(_TASK_UPDATE_SETTINGS, percent)
                previous_percent = percent
            self._set_parameter_with_retries(ATStringCommand.WR.command,
                                             bytearray(0), _PARAMETER_WRITE_RETRIES)
            setting_index += 1
            # Apply changes.
            percent = setting_index * 100 // num_settings
            if self._progress_callback is not None and percent != previous_percent:
                self._progress_callback(_TASK_UPDATE_SETTINGS, percent)
            self._set_parameter_with_retries(ATStringCommand.AC.command, bytearray(0),
                                             _PARAMETER_WRITE_RETRIES)
        except XBeeException as e:
            raise UpdateProfileException(_ERROR_UPDATE_SETTINGS % str(e))

        # Restore apply changes state.
        self._xbee_device.enable_apply_changes(old_apply_settings_value)

        # Check if port settings have changed on local devices.
        if self._is_local:
            self._check_port_settings_changed()

    def _update_file_system(self):
        """
        Updates the device file system.

        Raises:
            UpdateProfileException: if there is any error during updating the device file system.
        """
        _log.info("Updating device file system")
        if self._is_local:
            filesystem_manager = LocalXBeeFileSystemManager(self._xbee_device)
            try:
                if self._progress_callback is not None:
                    self._progress_callback(_TASK_CONNECT_FILESYSTEM, None)
                time.sleep(0.2)
                filesystem_manager.connect()
                # Format file system to ensure resulting file system is exactly the same as the profile one.
                if self._progress_callback is not None:
                    self._progress_callback(_TASK_FORMAT_FILESYSTEM, None)
                filesystem_manager.format_filesystem()
                # Transfer the file system folder.
                filesystem_manager.put_dir(self._xbee_profile.file_system_path, dest_dir=None,
                                           progress_callback=lambda file, percent:
                                           self._progress_callback(_TASK_UPDATE_FILE % file, percent) if
                                           self._progress_callback is not None else None)
            except FileSystemNotSupportedException:
                raise UpdateProfileException(_ERROR_FILESYSTEM_NOT_SUPPORTED)
            except FileSystemException as e:
                raise UpdateProfileException(_ERROR_UPDATE_FILESYSTEM % str(e))
            finally:
                filesystem_manager.disconnect()
        else:
            # TODO: remote filesystem update is not implemented yet.
            _log.info("Remote filesystem update is not yet supported, skipping.")
            pass

    def update_profile(self):
        """
        Starts the update profile process.

        Raises:
            UpdateProfileException: if there is any error during the update XBee profile operation.
        """
        # Retrieve device parameters.
        self._read_device_parameters()
        # Check if device supports profiles.
        # TODO: reduce limitations when more hardware is supported.
        if self._device_hardware_version.code not in SUPPORTED_HARDWARE_VERSIONS:
            raise UpdateProfileException(_ERROR_PROFILES_NOT_SUPPORTED)
        # Verify hardware compatibility of the profile.
        if self._device_hardware_version.code != self._xbee_profile.hardware_version:
            raise UpdateProfileException(_ERROR_HARDWARE_NOT_COMPATIBLE)
        # Check flash firmware option.
        flash_firmware = False
        firmware_is_the_same = self._device_firmware_version == self._xbee_profile.firmware_version
        if self._xbee_profile.flash_firmware_option == FlashFirmwareOption.FLASH_ALWAYS:
            flash_firmware = True
        elif self._xbee_profile.flash_firmware_option == FlashFirmwareOption.FLASH_DIFFERENT:
            flash_firmware = not firmware_is_the_same
        elif self._xbee_profile.flash_firmware_option == FlashFirmwareOption.DONT_FLASH and not firmware_is_the_same:
            raise UpdateProfileException(_ERROR_FIRMWARE_NOT_COMPATIBLE)
        # Update firmware if required.
        if flash_firmware:
            if self._device_hardware_version.code not in firmware.SUPPORTED_HARDWARE_VERSIONS:
                raise UpdateProfileException(_ERROR_HARDWARE_NOT_COMPATIBLE_XBEE3)
            self._update_firmware()
        # Update the settings.
        self._update_device_settings()
        # Update the file system if required.
        if self._xbee_profile.has_filesystem:
            self._update_file_system()


def apply_xbee_profile(xbee_device, profile_path, progress_callback=None):
    """
    Applies the given XBee profile into the given XBee device.

    Args:
        xbee_device (:class:`.XBeeDevice` or :class:`.RemoteXBeeDevice`): the XBee device to apply profile to.
        profile_path (String): path of the XBee profile file to apply.
        progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                arguments:

            * The current update task as a String
            * The current update task percentage as an Integer

    Raises:
        ValueError: if the XBee profile or the XBee device is not valid.
        UpdateProfileException: if there is any error during the update XBee profile operation.
    """
    # Sanity checks.
    if profile_path is None or not isinstance(profile_path, str):
        _log.error("ERROR: %s" % _ERROR_PROFILE_NOT_VALID)
        raise ValueError(_ERROR_PROFILE_NOT_VALID)
    if xbee_device is None or (not isinstance(xbee_device, XBeeDevice) and
                               not isinstance(xbee_device, RemoteXBeeDevice)):
        _log.error("ERROR: %s" % _ERROR_DEVICE_NOT_VALID)
        raise ValueError(_ERROR_DEVICE_NOT_VALID)

    try:
        xbee_profile = XBeeProfile(profile_path)
    except (ValueError, ReadProfileException) as e:
        error = _ERROR_PROFILE_INVALID % str(e)
        _log.error("ERROR: %s" % error)
        raise UpdateProfileException(error)

    profile_updater = _ProfileUpdater(xbee_device, xbee_profile, progress_callback=progress_callback)
    profile_updater.update_profile()
