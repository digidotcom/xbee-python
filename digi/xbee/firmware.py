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

from digi.xbee.exception import XBeeException, FirmwareUpdateException, TimeoutException
from digi.xbee.devices import AbstractXBeeDevice
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.serial import FlowControl
from digi.xbee.serial import XBeeSerialPort
from digi.xbee.util import utils
from digi.xbee.util import xmodem
from digi.xbee.util.xmodem import XModemException, XModemCancelException
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

_COMMAND_ENTER_PROGRAMMING_MODE = "%P"
_COMMAND_EXECUTE_RETRIES = 3

_READ_BUFFER_LEN = 256
_READ_DATA_TIMEOUT = 3  # Seconds.

_DEVICE_BREAK_RESET_TIMEOUT = 10  # seconds
_DEVICE_CONNECTION_RETRIES = 3
_DEVICE_RESET_TIMEOUT = 3  # seconds

_ERROR_BOOTLOADER_MODE = "Could not enter in bootloader mode"
_ERROR_COMPATIBILITY_NUMBER = "Device compatibility number (%d) is greater than the firmware one (%d)"
_ERROR_CONNECT_DEVICE = "Could not connect with XBee device after %s retries"
_ERROR_CONNECT_SERIAL_PORT = "Could not connect with serial port: %s"
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
_ERROR_REGION_LOCK = "Device region (%d) differs from the firmware one (%d)"
_ERROR_RESTORE_TARGET_CONNECTION = "Could not restore target connection: %s"
_ERROR_TARGET_INVALID = "Invalid update target"
_ERROR_XML_PARSE = "Could not parse XML firmware file %s"
_ERROR_XMODEM_COMMUNICATION = "XModem serial port communication error: %s"
_ERROR_XMODEM_RESTART = "Could not restart firmware transfer sequence"
_ERROR_XMODEM_START = "Could not start XModem firmware upload process"

_EXTENSION_GBL = ".gbl"

_PARAMETER_BOOTLOADER_VERSION = "VH"  # Answer examples: 01 81 -> 1.8.1  -  0F 3E -> 15.3.14
_PARAMETER_COMPATIBILITY_NUMBER = "%C"
_PARAMETER_HARDWARE_VERSION = "HV"
_PARAMETER_READ_RETRIES = 3
_PARAMETER_REGION_LOCK = "R?"

_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL = "^.*Gecko Bootloader.*\\(([0-9a-fA-F]{4})-([0-9a-fA-F]{2})(.*)\\).*$"
_PATTERN_GECKO_BOOTLOADER_VERSION = "^.*Gecko Bootloader v([0-9a-fA-F]{1}\\.[0-9a-fA-F]{1}\\.[0-9a-fA-F]{1}).*$"

_PROGRESS_TASK_UPDATE_BOOTLOADER = "Updating bootloader"
_PROGRESS_TASK_UPDATE_XBEE = "Updating XBee firmware"

_REGION_ALL = 0

_XML_BOOTLOADER_VERSION = "firmware/bootloader_version"
_XML_COMPATIBILITY_NUMBER = "firmware/compatibility_number"
_XML_HARDWARE_VERSION = "firmware/hw_version"
_XML_REGION_LOCK = "firmware/region"
_XML_UPDATE_TIMEOUT = "firmware/update_timeout_ms"

_XMODEM_READY_TO_RECEIVE_CHAR = "C"
_XMODEM_START_TIMEOUT = 3  # seconds

SUPPORTED_HARDWARE_VERSIONS = (HardwareVersion.XBEE3.code,
                               HardwareVersion.XBEE3_SMT.code,
                               HardwareVersion.XBEE3_TH.code)

_log = logging.getLogger(__name__)


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
        self.xbee_serial_port = serial_port
        self.duration = duration
        self.lock = Event()

    def run(self):
        """
        Override method.
        .. seealso::
           | :meth:`.Thread.run`
        """
        if self.xbee_serial_port is None or _BreakThread.is_running():
            return

        _log.debug("Break thread started")
        _BreakThread._break_running = True
        self.xbee_serial_port.break_condition = True
        self.lock.wait(self.duration)
        self.xbee_serial_port.break_condition = False
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


class _LocalFirmwareUpdater(object):
    """
    Helper class used to handle the local firmware update process.
    """

    def __init__(self, target, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                 progress_callback=None):
        """
        Class constructor. Instantiates a new :class:`._LocalFirmwareUpdater` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: the XBee device to upload its firmware.
            xml_firmware_file (String): location of the XML firmware file.
            xbee_firmware_file (String, optional): location of the XBee binary firmware file.
            bootloader_firmware_file (String, optional): location of the bootloader binary firmware file.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer
        """
        self.xml_firmware_file = xml_firmware_file
        self.progress_callback = progress_callback
        self.xbee_firmware_file = xbee_firmware_file
        self.bootloader_firmware_file = bootloader_firmware_file
        self.xbee_serial_port = None
        self.device_port_params = None
        self.device_was_connected = False
        self.progress_task = None
        if isinstance(target, str):
            self.port = target
            self.xbee_device = None
        else:
            self.port = None
            self.xbee_device = target

    def _parse_xml_firmware_file(self):
        """
        Parses the XML firmware file and stores the required parameters.

        Returns:
            Boolean: ``True`` if the XML firmware file was correctly parsed, ``False`` otherwise.
        """
        _log.debug("Parsing XML firmware file %s:" % self.xml_firmware_file)
        try:
            root = ElementTree.parse(self.xml_firmware_file).getroot()
            # Hardware version, required.
            element = root.find(_XML_HARDWARE_VERSION)
            if element is None:
                return False
            self.xml_hardware_version = int(element.text, 16)
            _log.debug(" - Hardware version: %d" % self.xml_hardware_version)
            # Compatibility number, required.
            element = root.find(_XML_COMPATIBILITY_NUMBER)
            if element is None:
                return False
            self.xml_compatibility_number = int(element.text)
            _log.debug(" - Compatibility number: %d" % self.xml_compatibility_number)
            # Bootloader version, optional.
            element = root.find(_XML_BOOTLOADER_VERSION)
            if element is not None:
                self.xml_bootloader_version = _bootloader_version_to_bytearray(element.text)
            else:
                self.xml_bootloader_version = None
            _log.debug(" - Bootloader version: %s" % self.xml_bootloader_version)
            # Region lock, required.
            element = root.find(_XML_REGION_LOCK)
            if element is None:
                return False
            self.xml_region_lock = int(element.text)
            _log.debug(" - Region lock: %d" % self.xml_region_lock)
            # Update timeout, optional.
            element = root.find(_XML_UPDATE_TIMEOUT)
            if element is not None:
                self.xml_update_timeout_ms = int(element.text)
            else:
                self.xml_update_timeout_ms = None
            _log.debug(" - Update timeout: %s" % self.xml_update_timeout_ms)
        except ParseError as e:
            _log.exception(e)
            return False

        return True

    def _check_firmware_binary_file(self):
        """
        Checks whether the firmware binary file exists or not and stores its path.

        Returns:
             Boolean: ``True`` if the firmware binary file exists, ``False`` otherwise.
        """
        # If not already specified, the binary firmware file is usually in the same folder as the XML firmware file.
        if self.xbee_firmware_file is None:
            path = Path(self.xml_firmware_file)
            self.xbee_firmware_file = str(Path(path.parent).joinpath(path.stem + _EXTENSION_GBL))

        return _file_exists(self.xbee_firmware_file)

    def _check_bootloader_binary_file(self):
        """
        Checks whether the bootloader binary file exists or not and stores its path.

        Returns:
             Boolean: ``True`` if bootloader binary file exists, ``False`` otherwise.
        """
        # If not already specified, the bootloader firmware file is usually in the same folder as the XML firmware file.
        # The file filename starts with a fixed prefix and includes the bootloader version to update to.
        if self.bootloader_firmware_file is None:
            path = Path(self.xml_firmware_file)
            self.bootloader_firmware_file = str(Path(path.parent).joinpath(_BOOTLOADER_XBEE3_FILE_PREFIX +
                                                                           str(self.xml_bootloader_version[0]) +
                                                                           _BOOTLOADER_VERSION_SEPARATOR +
                                                                           str(self.xml_bootloader_version[1]) +
                                                                           _BOOTLOADER_VERSION_SEPARATOR +
                                                                           str(self.xml_bootloader_version[2]) +
                                                                           _EXTENSION_GBL))

        return _file_exists(self.bootloader_firmware_file)

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
            self.xbee_serial_port.purge_port()
            self.xbee_serial_port.write(str.encode(_BOOTLOADER_TEST_CHARACTER))
            read_bytes = self.xbee_serial_port.read(_READ_BUFFER_LEN)
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
        self.xbee_serial_port.rts = 0
        break_thread = _BreakThread(self.xbee_serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
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
                self.xbee_serial_port.rts = 0
                break_thread = _BreakThread(self.xbee_serial_port, _DEVICE_BREAK_RESET_TIMEOUT)
                break_thread.start()

        # Restore break condition.
        if break_thread.is_running():
            break_thread.stop_break()

        return False

    def _get_bootloader_version(self):
        """
        Returns the device bootloader version.

        Returns:
            Bytearray: the bootloader version as byte array, ``None`` if it could not be read.
        """
        bootloader_version_array = bytearray(3)
        if self.xbee_serial_port is not None:
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_VERSION, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
                return None

            return _bootloader_version_to_bytearray(result.groups()[0])
        else:
            bootloader_version = self._read_device_parameter_with_retries(_PARAMETER_BOOTLOADER_VERSION,
                                                                          _PARAMETER_READ_RETRIES)
            if bootloader_version is None or len(bootloader_version) < 2:
                return None
            bootloader_version_array[0] = bootloader_version[0] & 0x0F
            bootloader_version_array[1] = (bootloader_version[1] & 0xF0) >> 4
            bootloader_version_array[2] = bootloader_version[1] & 0x0F

            return bootloader_version_array

    def _get_compatibility_number(self):
        """
        Returns the device compatibility number.

        Returns:
            Integer: the device compatibility number as integer, ``None`` if it could not be read.
        """
        if self.xbee_serial_port is not None:
            # Assume the device is already in bootloader mode.
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 2:
                return None

            return int(result.groups()[1])
        else:
            compatibility_number = self._read_device_parameter_with_retries(_PARAMETER_COMPATIBILITY_NUMBER,
                                                                            _PARAMETER_READ_RETRIES)
            if compatibility_number is None:
                return None
            compatibility_number = utils.hex_to_string(compatibility_number)[0:2]

            return int(compatibility_number)

    def _get_hardware_version(self):
        """
        Returns the device hardware version.

        Returns:
            Integer: the hardware version as integer, ``None`` if it could not be read.
        """
        if self.xbee_serial_port is not None:
            # Assume the device is already in bootloader mode.
            bootloader_header = self._read_bootloader_header()
            if bootloader_header is None:
                return None
            result = re.match(_PATTERN_GECKO_BOOTLOADER_COMPATIBILITY_FULL, bootloader_header, flags=re.M | re.DOTALL)
            if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
                return None

            return int(result.groups()[0][:2], 16)
        else:
            hardware_version = self._read_device_parameter_with_retries(_PARAMETER_HARDWARE_VERSION,
                                                                        _PARAMETER_READ_RETRIES)
            if hardware_version is None:
                return None

            return int(hardware_version[0])

    def _get_region_lock(self):
        """
        Returns the device region lock number.

        Returns:
            Integer: the device region lock number as integer, ``None`` if it could not be read.
        """
        if self.xbee_serial_port is not None:
            # There is no way to retrieve this number from bootloader.
            return None
        else:
            region_lock = self._read_device_parameter_with_retries(_PARAMETER_REGION_LOCK,
                                                                   _PARAMETER_READ_RETRIES)
            if region_lock is None:
                return None

            return int(region_lock[0])

    def _connect_device_with_retries(self, retries):
        """
        Attempts to connect the device with the given number of retries.

        Args:
            retries (Integer): the number of connection retries.

        Returns:
            Boolean: ``True`` if the device connected, ``False`` otherwise.
        """
        if self.xbee_device is None:
            return False

        if self.xbee_device.is_open():
            return True

        while retries > 0:
            try:
                self.xbee_device.open()
                return True
            except XBeeException:
                retries -= 1
                if retries != 0:
                    time.sleep(1)
            except SerialException:
                return False

        return False

    def _read_device_parameter_with_retries(self, parameter, retries):
        """
        Reads the given parameter from the XBee device with the given number of retries.

        Args:
            parameter (String): the parameter to read.
            retries (Integer): the number of retries to perform after a :class:`.TimeoutException`

        Returns:
            Bytearray: the read parameter value, ``None`` if the parameter could not be read.
        """
        if self.xbee_device is None:
            return None

        while retries > 0:
            try:
                return self.xbee_device.get_parameter(parameter)
            except TimeoutException as e:
                # On timeout exceptions perform retries.
                _log.exception(e)
                retries -= 1
                if retries != 0:
                    time.sleep(0.5)
            except XBeeException as e:
                _log.exception(e)
                return None

        return None

    def _set_device_in_programming_mode(self):
        """
        Attempts to put the XBee device into programming mode (bootloader).

        Returns:
            Boolean: ``True`` if the device was set into programming mode, ``False`` otherwise.
        """
        if self.xbee_device is None:
            return False

        if self.xbee_serial_port is not None and self._is_bootloader_active():
            return True

        _log.debug("Setting device in programming mode")
        try:
            self.xbee_device.execute_command(_COMMAND_ENTER_PROGRAMMING_MODE)
        except XBeeException:
            # We can ignore this error as at last instance we will attempt a Break method.
            pass

        self.xbee_device.close()
        self.xbee_serial_port = self.xbee_device.serial_port
        self.device_port_params = self.xbee_serial_port.get_settings()
        try:
            self.xbee_serial_port.apply_settings(_BOOTLOADER_PORT_PARAMETERS)
            self.xbee_serial_port.open()
        except SerialException as e:
            _log.exception(e)
            return False
        if not self._is_bootloader_active():
            # This will force the Break mechanism to reboot in bootloader mode in case previous methods failed.
            return self._enter_bootloader_mode_with_break()

        return True

    def _restore_target_connection(self):
        """
        Leaves the firmware update target connection (XBee device or serial port) in its original state.

        Raises:
            SerialException: if there is any error restoring the serial port connection.
            XBeeException: if there is any error restoring the device connection.
        """
        if self.xbee_device is not None:
            if self.xbee_serial_port is not None:
                if self.xbee_serial_port.isOpen():
                    self.xbee_serial_port.close()
                if self.device_port_params is not None:
                    self.xbee_serial_port.apply_settings(self.device_port_params)
            if self.device_was_connected and not self.xbee_device.is_open():
                self.xbee_device.open()
            elif not self.device_was_connected and self.xbee_device.is_open():
                self.xbee_device.close()
        elif self.xbee_serial_port is not None and self.xbee_serial_port.isOpen():
            self.xbee_serial_port.close()

    def _bootloader_update_required(self, device_bootloader_version):
        """
        Checks whether the bootloader needs to be updated or not

        Args:
            device_bootloader_version (Bytearray): the device bootloader version.

        Returns:
            Boolean: ``True`` if the bootloader needs to be updated, ``False`` otherwise
        """
        # If any bootloader version is None (the XML firmware file one or the device one), update is not required.
        if None in (self.xml_bootloader_version, device_bootloader_version):
            return False

        # At this point we can ensure both bootloader versions are not None and 3 bytes long.
        for i in range(len(self.xml_bootloader_version)):
            if self.xml_bootloader_version[i] > device_bootloader_version[i]:
                return True
            if self.xml_bootloader_version[i] < device_bootloader_version[i]:
                return False

        return False

    def _start_firmware_upload_operation(self):
        """
        Starts the firmware upload operation by selecting option '1' of the bootloader.

        Returns:
            Boolean: ``True`` if the upload process started successfully, ``False`` otherwise
        """
        try:
            # Display bootloader menu and consume it.
            self.xbee_serial_port.write(str.encode(_BOOTLOADER_TEST_CHARACTER))
            time.sleep(1)
            self.xbee_serial_port.purge_port()
            # Write '1' to execute bootloader option '1': Upload gbl and consume answer.
            self.xbee_serial_port.write(str.encode(_BOOTLOADER_OPTION_UPLOAD_GBL))
            time.sleep(0.5)
            self.xbee_serial_port.purge_port()
            # Look for the 'C' character during some time, it indicates device is ready to receive firmware pages.
            self.xbee_serial_port.set_read_timeout(0.5)
            deadline = _get_milliseconds() + (_XMODEM_START_TIMEOUT * 1000)
            while _get_milliseconds() < deadline:
                read_bytes = self.xbee_serial_port.read(1)
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
            self.xbee_serial_port.write(str.encode(_BOOTLOADER_TEST_CHARACTER))
            time.sleep(1)
            self.xbee_serial_port.purge_port()
            # Write '2' to execute bootloader option '2': Run.
            self.xbee_serial_port.write(str.encode(_BOOTLOADER_OPTION_RUN_FIRMWARE))

            # Look for the '2' character during some time, it indicates firmware was executed.
            read_bytes = self.xbee_serial_port.read(1)
            while len(read_bytes) > 0 and not read_bytes[0] == ord(_BOOTLOADER_OPTION_RUN_FIRMWARE):
                read_bytes = self.xbee_serial_port.read(1)
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
            self.xbee_serial_port.purge_port()
            self.xbee_serial_port.write(data)
        except SerialException as e:
            _log.exception(e)
            return False

        return True

    def _xmodem_read_cb(self, size, timeout=_READ_DATA_TIMEOUT):
        """
        Callback function used to read data from the serial port when requested from the XModem transfer.

        Args:
            size (Integer): the size of the data to read.
            timeout (Integer, optional): the maximum time to wait to read the requested data (seconds).

        Returns:
            Bytearray: the read data, ``None`` if data could not be read.
        """
        deadline = _get_milliseconds() + (timeout * 1000)
        data = bytearray()
        try:
            while len(data) < size and _get_milliseconds() < deadline:
                read_bytes = self.xbee_serial_port.read(size - len(data))
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
        if self.progress_callback is not None:
            self.progress_callback(self.progress_task, percent)

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
                self.xbee_serial_port.purge_port()
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

        # Start firmware.
        if not self._run_firmware_operation():
            raise FirmwareUpdateException(_ERROR_FIRMWARE_START)

        self._wait_for_reset()

    def _wait_for_reset(self):
        """
        Waits for the device to reset using the xml firmware file specified timeout or the default one.
        """
        if self.xml_update_timeout_ms is not None:
            time.sleep(self.xml_update_timeout_ms / 1000.0)
        else:
            time.sleep(_DEVICE_RESET_TIMEOUT)

    def _exit_with_error(self, message):
        """
        Finishes the process raising a :class`.FirmwareUpdateException` and leaves target in the initial state.

        Args:
            message (String): the error message of the exception to raise.

        Raises:
            FirmwareUpdateException: the exception is always thrown in this method.
        """
        try:
            self._restore_target_connection()
        except (SerialException, XBeeException) as e:
            _log.error("ERROR: %s" % (_ERROR_RESTORE_TARGET_CONNECTION % str(e)))
        _log.error("ERROR: %s" % message)
        raise FirmwareUpdateException(message)

    def update_firmware(self):
        """
        Updates the firmware of the local XBee device.

        Raises:
            FirmwareUpdateException: if there is any error performing the firmware update.
        """
        # Start by parsing the XML firmware file.
        if not self._parse_xml_firmware_file():
            _log.error("ERROR: %s" % _ERROR_XML_PARSE % self.xml_firmware_file)
            raise FirmwareUpdateException(_ERROR_XML_PARSE % self.xml_firmware_file)

        # Verify that the binary firmware file exists.
        if not self._check_firmware_binary_file():
            _log.error(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self.xbee_firmware_file)
            raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND % self.xbee_firmware_file)

        # Depending on the given target, process has a different flow on first steps (serial port or XBee device).
        if self.xbee_device is None:
            # Configure serial port connection with bootloader parameters.
            try:
                _log.debug("Opening port '%s'" % self.port)
                self.xbee_serial_port = XBeeSerialPort(_BOOTLOADER_PORT_PARAMETERS["baudrate"],
                                                       self.port,
                                                       data_bits=_BOOTLOADER_PORT_PARAMETERS["bytesize"],
                                                       stop_bits=_BOOTLOADER_PORT_PARAMETERS["stopbits"],
                                                       parity=_BOOTLOADER_PORT_PARAMETERS["parity"],
                                                       flow_control=FlowControl.NONE,
                                                       timeout=_BOOTLOADER_PORT_PARAMETERS["timeout"])
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
            self.device_was_connected = self.xbee_device.is_open()
            _log.debug("Connecting device '%s'" % self.xbee_device)
            if not self._connect_device_with_retries(_DEVICE_CONNECTION_RETRIES):
                if not self._set_device_in_programming_mode():
                    self._exit_with_error(_ERROR_CONNECT_DEVICE % _DEVICE_CONNECTION_RETRIES)

        # Read device values required for verification steps prior to firmware update.
        _log.debug("Reading device settings:")
        device_bootloader_version = self._get_bootloader_version()
        _log.debug(" - Bootloader version: %s" % device_bootloader_version)
        device_compatibility_number = self._get_compatibility_number()
        _log.debug(" - Compatibility number: %s" % device_compatibility_number)
        device_region_lock = self._get_region_lock()
        _log.debug(" - Region lock: %s" % device_region_lock)
        device_hardware_version = self._get_hardware_version()
        if device_hardware_version is None:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_READ)
        _log.debug(" - Hardware version: %s" % device_hardware_version)

        # Check if the hardware version is compatible with the firmware update process.
        if device_hardware_version not in SUPPORTED_HARDWARE_VERSIONS:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_NOT_SUPPORTED % device_hardware_version)

        # Check if device hardware version is compatible with the firmware.
        if device_hardware_version != self.xml_hardware_version:
            self._exit_with_error(_ERROR_HARDWARE_VERSION_DIFFER % (device_hardware_version, self.xml_hardware_version))

        # Check compatibility number.
        if device_compatibility_number is not None and device_compatibility_number > self.xml_compatibility_number:
            self._exit_with_error(_ERROR_COMPATIBILITY_NUMBER % (device_compatibility_number,
                                                                 self.xml_compatibility_number))

        # Check region lock for compatibility numbers greater than 1.
        if device_compatibility_number is not None and device_compatibility_number > 1 and \
                device_region_lock is not None:
            if device_region_lock != _REGION_ALL and device_region_lock != self.xml_region_lock:
                self._exit_with_error(_ERROR_REGION_LOCK % (device_region_lock, self.xml_region_lock))

        # Check bootloader update file exists if required.
        _log.debug("Bootloader update required? %s" % self._bootloader_update_required(device_bootloader_version))
        if self._bootloader_update_required(device_bootloader_version):
            if not self._check_bootloader_binary_file():
                self._exit_with_error(_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND % self.bootloader_firmware_file)

        # At this point that the firmware update is possible, put the device into programming mode.
        if self.xbee_device is not None and not self._set_device_in_programming_mode():
            self._exit_with_error(_ERROR_DEVICE_PROGRAMMING_MODE)

        # Update the bootloader using XModem protocol if required.
        if self._bootloader_update_required(device_bootloader_version):
            _log.info("Updating bootloader")
            self.progress_task = _PROGRESS_TASK_UPDATE_BOOTLOADER
            try:
                self._transfer_firmware_file_xmodem(self.bootloader_firmware_file)
            except FirmwareUpdateException as e:
                self._exit_with_error(_ERROR_FIRMWARE_UPDATE_BOOTLOADER % str(e))

        # Update the XBee firmware using XModem protocol.
        _log.info("Updating XBee firmware")
        self.progress_task = _PROGRESS_TASK_UPDATE_XBEE
        try:
            self._transfer_firmware_file_xmodem(self.xbee_firmware_file)
        except FirmwareUpdateException as e:
            self._exit_with_error(_ERROR_FIRMWARE_UPDATE_XBEE % str(e))

        # Leave target connection in its original state.
        try:
            self._restore_target_connection()
        except (SerialException, XBeeException) as e:
            raise FirmwareUpdateException(_ERROR_RESTORE_TARGET_CONNECTION % str(e))

        _log.info("Update process finished successfully")


def update_local_firmware(target, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                          progress_callback=None):
    """
    Performs a local firmware update operation in the given target.

    Args:
        target (String or :class:`.XBeeDevice`): target of the firmware upload operation.
            String: serial port identifier.
            :class:`.AbstractXBeeDevice`: the XBee device to upload its firmware.
        xml_firmware_file (String): path of the XML file that describes the firmware to upload.
        xbee_firmware_file (String, optional): location of the XBee binary firmware file.
        bootloader_firmware_file (String, optional): location of the bootloader binary firmware file.
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
        _log.error("ERROR: %s" % _ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_XBEE_FIRMWARE_NOT_FOUND)
    if bootloader_firmware_file is not None and not _file_exists(bootloader_firmware_file):
        _log.error("ERROR: %s" % _ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND)
        raise FirmwareUpdateException(_ERROR_FILE_BOOTLOADER_FIRMWARE_NOT_FOUND)

    # Launch the update process.
    update_process = _LocalFirmwareUpdater(target,
                                           xml_firmware_file,
                                           xbee_firmware_file=xbee_firmware_file,
                                           bootloader_firmware_file=bootloader_firmware_file,
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
