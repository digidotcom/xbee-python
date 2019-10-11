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

import functools
import logging
import os
import re
import string
import time

from digi.xbee.exception import XBeeException, OperationNotSupportedException
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.util import xmodem
from digi.xbee.util.xmodem import XModemException
from enum import Enum, unique
from os import listdir
from os.path import isfile
from serial.serialutil import SerialException

_ANSWER_ATFS = "AT%s" % ATStringCommand.FS.command
_ANSWER_SHA256 = "sha256"

_COMMAND_AT = "AT\r"
_COMMAND_ATFS = "AT%s %s" % (ATStringCommand.FS.command, "%s\r")
_COMMAND_FILE_SYSTEM = "AT%s\r" % ATStringCommand.FS.command
_COMMAND_MODE_ANSWER_OK = "OK"
_COMMAND_MODE_CHAR = "+"
_COMMAND_MODE_EXIT = "AT%s\r" % ATStringCommand.CN.command
_COMMAND_MODE_TIMEOUT = 2

_ERROR_CONNECT_FILESYSTEM = "Error connecting file system manager: %s"
_ERROR_ENTER_CMD_MODE = "Could not enter AT command mode"
_ERROR_EXECUTE_COMMAND = "Error executing command '%s': %s"
_ERROR_FILESYSTEM_NOT_SUPPORTED = "The device does not support file system feature"
_ERROR_FUNCTION_NOT_SUPPORTED = "Function not supported: %s"
_ERROR_TIMEOUT = "Timeout executing command"

_FORMAT_TIMEOUT = 10  # Seconds.

_FUNCTIONS_SEPARATOR = " "

_GUARD_TIME = 2  # In seconds.

_NAK_TIMEOUT = 10  # Seconds.

_PATH_SEPARATOR = "/"
_PATTERN_FILE_SYSTEM_DIRECTORY = "^ +<DIR> (.+)/$"
_PATTERN_FILE_SYSTEM_ERROR = "^(.*\\s)?(E[A-Z0-9]+)( .*)?\\s*$"
_PATTERN_FILE_SYSTEM_FILE = "^ +([0-9]+) (.+)$"
_PATTERN_FILE_SYSTEM_FUNCTIONS = "^.*AT%s %s" % (ATStringCommand.FS.command, "commands: (.*)$")
_PATTERN_FILE_SYSTEM_INFO = "^ *([0-9]*) (.*)$"

_READ_BUFFER = 256
_READ_DATA_TIMEOUT = 3  # Seconds.
_READ_EMPTY_DATA_RETRIES = 10
_READ_EMPTY_DATA_RETRIES_DEFAULT = 1
_READ_PORT_TIMEOUT = 0.05  # Seconds.

_SECURE_ELEMENT_SUFFIX = "#"

_TRANSFER_TIMEOUT = 5  # Seconds.

_log = logging.getLogger(__name__)
_printable_ascii_bytes = string.printable.encode()


class _FilesystemFunction(Enum):
    """
    This class lists the available file system functions for XBee devices.

    | Inherited properties:
    |     **name** (String): The name of this _FilesystemFunction.
    |     **value** (Integer): The ID of this _FilesystemFunction.
    """
    PWD = ("PWD", "pwd")
    CD = ("CD", "cd %s")
    MD = ("MD", "md %s")
    LS = ("LS", "ls")
    LS_DIR = ("LS", "ls %s")
    PUT = ("PUT", "put %s")
    XPUT = ("XPUT", "xput %s")
    GET = ("GET", "get %s")
    MV = ("MV", "mv %s %s")
    RM = ("RM", "rm %s")
    HASH = ("HASH", "hash %s")
    INFO = ("INFO", "info")
    FORMAT = ("FORMAT", "format confirm")

    def __init__(self, name, command):
        self.__name = name
        self.__command = command

    @classmethod
    def get(cls, name):
        """
        Returns the _FilesystemFunction for the given name.

        Args:
            name (String): the name of the _FilesystemFunction to get.

        Returns:
            :class:`._FilesystemFunction`: the _FilesystemFunction with the given name, ``None`` if
                                           there is not a _FilesystemFunction with that name.
        """
        for value in _FilesystemFunction:
            if value.name == name:
                return value

        return None

    @property
    def name(self):
        """
        Returns the name of the _FilesystemFunction element.

        Returns:
            String: the name of the _FilesystemFunction element.
        """
        return self.__name

    @property
    def command(self):
        """
        Returns the command of the _FilesystemFunction element.

        Returns:
            String: the command of the _FilesystemFunction element.
        """
        return self.__command


class FileSystemElement(object):
    """
    Class used to represent XBee file system elements (files and directories).
    """

    def __init__(self, name, path, size=0, is_directory=False):
        """
        Class constructor. Instantiates a new :class:`.FileSystemElement` with the given parameters.

        Args:
            name (String): the name of the file system element.
            path (String): the absolute path of the file system element.
            size (Integer): the size of the file system element, only applicable to files.
            is_directory (Boolean): ``True`` if the file system element is a directory, ``False`` if it is a file.
        """
        self._name = name
        self._path = path
        self._size = size
        self._is_directory = is_directory
        self._is_secure = False
        # Check if element is 'write-only' (secure)
        if self._name.endswith(_SECURE_ELEMENT_SUFFIX):
            self._is_secure = True

    def __str__(self):
        if self._is_directory:
            return "<DIR> %s/" % self._name
        else:
            return "%d %s" % (self._size, self._name)

    @property
    def name(self):
        """
        Returns the file system element name.

        Returns:
            String: the file system element name.
         """
        return self._name

    @property
    def path(self):
        """
        Returns the file system element absolute path.

        Returns:
            String: the file system element absolute path.
         """
        return self._path

    @property
    def size(self):
        """
        Returns the file system element size.

        Returns:
            Integer: the file system element size. If element is a directory, returns '0'.
         """
        return self._size if self._is_directory else 0

    @property
    def is_directory(self):
        """
        Returns whether the file system element is a directory or not.

        Returns:
            Boolean: ``True`` if the file system element is a directory, ``False`` otherwise.
         """
        return self._is_directory

    @property
    def is_secure(self):
        """
        Returns whether the file system element is a secure element or not.

        Returns:
            Boolean: ``True`` if the file system element is secure, ``False`` otherwise.
         """
        return self._is_secure


class FileSystemException(XBeeException):
    """
    This exception will be thrown when any problem related with the XBee device file system occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class FileSystemNotSupportedException(FileSystemException):
    """
    This exception will be thrown when the file system feature is not supported in the device.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class _LocalFileSystemUpdater(object):
    """
    Helper class used to handle the local XBee file system update process.
    """

    def __init__(self, xbee_device, filesystem_path, progress_callback=None):
        """

        Args:
            xbee_device (:class:`.XBeeDevice`): the local XBee device to update its file system.
            filesystem_path (String): local path of the folder containing the filesystem structure to transfer.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            UpdateFileSystemException: if there is any error updating the XBee file system.
        """
        self._xbee_device = xbee_device
        self._serial_port = xbee_device.serial_port
        self._filesystem_path = filesystem_path
        self._progress_callback = progress_callback
        self._supported_functions = []


class LocalXBeeFileSystemManager(object):
    """
    Helper class used to manage the local XBee file system.
    """

    def __init__(self, xbee_device):
        """
        Class constructor. Instantiates a new :class:`.LocalXBeeFileSystemManager` with the given parameters.

        Args:
            xbee_device (:class:`.XBeeDevice`): the local XBee device to manage its file system.
        """
        if not xbee_device.serial_port:
            raise OperationNotSupportedException("Only supported in local XBee connected by serial.")

        self._xbee_device = xbee_device
        self._serial_port = xbee_device.serial_port
        self._supported_functions = []
        self._device_was_connected = False
        self._is_connected = False
        self._old_read_timeout = _READ_PORT_TIMEOUT

    def _read_data(self, timeout=_READ_DATA_TIMEOUT, empty_retries=_READ_EMPTY_DATA_RETRIES_DEFAULT):
        """
        Reads data from the serial port waiting for the provided timeout.

        Args:
            timeout (Integer, optional): the maximum time to wait for data (seconds). Defaults to 1 second.
            empty_retries (Integer, optional): the number of consecutive zero-bytes read before considering no more
                                               data is available.

        Returns:
            String: the read data as string.

        Raises:
            SerialException: if there is any problem reading data from the serial port.
        """
        answer_string = ""
        empty_attempts = 0
        deadline = _get_milliseconds() + (timeout * 1000)
        read_bytes = self._serial_port.read(_READ_BUFFER)
        while (len(answer_string) == 0 or empty_attempts < empty_retries) and _get_milliseconds() < deadline:
            read_string = _filter_non_printable(read_bytes)
            answer_string += read_string
            # Continue reading, maybe there is more data.
            read_bytes = self._serial_port.read(_READ_BUFFER)
            if len(read_string) == 0:
                empty_attempts += 1
            else:
                empty_attempts = 0

        return answer_string

    def _is_in_atcmd_mode(self):
        """
        Returns whether the command mode is active or not.

        Returns:
            Boolean: ``True`` if the AT command mode is active, ``False`` otherwise.
        """
        _log.debug("Checking AT command mode...")
        try:
            self._serial_port.write(str.encode(_COMMAND_AT, encoding='utf-8'))
            answer = self._read_data(timeout=_GUARD_TIME)

            return answer is not None and _COMMAND_MODE_ANSWER_OK in answer
        except SerialException as e:
            _log.exception(e)
            return False

    def _enter_atcmd_mode(self):
        """
        Enters in AT command mode.

        Returns:
             Boolean: ``True`` if entered command mode successfully, ``False`` otherwise.
        """
        _log.debug("Entering AT command mode...")
        try:
            # In some scenarios where the read buffer is constantly being filled with remote data, it is
            # almost impossible to read the 'enter command mode' answer, so purge port before.
            self._serial_port.purge_port()
            for i in range(3):
                self._serial_port.write(str.encode(_COMMAND_MODE_CHAR, encoding='utf-8'))
            answer = self._read_data(timeout=_GUARD_TIME, empty_retries=_READ_EMPTY_DATA_RETRIES)

            return answer is not None and _COMMAND_MODE_ANSWER_OK in answer
        except SerialException as e:
            _log.exception(e)
            return False

    def _exit_atcmd_mode(self):
        """
        Exits from AT command mode.
        """
        _log.debug("Exiting AT command mode...")
        try:
            self._serial_port.write(str.encode(_COMMAND_MODE_EXIT, encoding='utf-8'))
        except SerialException as e:
            _log.exception(e)
        finally:
            time.sleep(_GUARD_TIME)  # It is necessary to wait the guard time before sending data again.

    def _check_atcmd_mode(self):
        """
        Checks whether AT command mode is active and if not tries to enter AT command mode.

        Returns:
             Boolean: ``True`` if AT command mode is active or entered successfully, ``False`` otherwise.
        """
        if not self._is_connected:
            return False

        if not self._is_in_atcmd_mode():
            time.sleep(_GUARD_TIME)
            return self._enter_atcmd_mode()

        return True

    def _supports_filesystem(self):
        """
        Returns whether the device supports file system or not.

        Returns:
             Boolean: ``True`` if the device supports file system, ``False`` otherwise.
        """
        _log.debug("Checking if device supports file system...")
        if not self._check_atcmd_mode():
            return False

        try:
            self._serial_port.write(str.encode(_COMMAND_FILE_SYSTEM, encoding='utf-8'))
            answer = self._read_data()
            if answer and _ANSWER_ATFS in answer:
                self._parse_filesystem_functions(answer.replace("\r", ""))
                return True

            return False
        except SerialException as e:
            _log.exception(e)
            return False

    def _parse_filesystem_functions(self, filesystem_answer):
        """
        Parses the file system command response to obtain a list of supported file system functions.

        Args:
            filesystem_answer (String): the file system command answer to parse.
        """
        result = re.match(_PATTERN_FILE_SYSTEM_FUNCTIONS, filesystem_answer, flags=re.M | re.DOTALL)
        if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
            return

        self._supported_functions = result.groups()[0].split(_FUNCTIONS_SEPARATOR)

    def _is_function_supported(self, function):
        """
        Returns whether the specified file system function is supported or not.

        Args:
            function (:class:`._FilesystemFunction`): the file system function to check.

        Returns:
            Boolean: ``True`` if the specified file system function is supported, ``False`` otherwise.
        """
        if not isinstance(function, _FilesystemFunction):
            return False

        return function.name in self._supported_functions

    @staticmethod
    def _check_function_error(answer, command):
        """
        Checks the given file system command answer and throws an exception if it contains an error.

        Args:
            answer (String): the file system command answer to check for errors.
            command (String): the file system command executed.

        Raises:
            FileSystemException: if any error is found in the answer.
        """
        result = re.match(_PATTERN_FILE_SYSTEM_ERROR, answer, flags=re.M | re.DOTALL)
        if result is not None and len(result.groups()) > 1:
            if len(result.groups()) > 2:
                raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), result.groups()[1] +
                                                                    " >" + result.groups()[2]))
            else:
                raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), result.groups()[1]))

    def _xmodem_write_cb(self, data):
        """
        Callback function used to write data to the serial port when requested from the XModem transfer.

        Args:
            data (Bytearray): the data to write to serial port from the XModem transfer.

        Returns:
            Boolean: ``True`` if the data was successfully written, ``False`` otherwise.
        """
        try:
            self._serial_port.purge_port()
            self._serial_port.write(data)
            self._serial_port.flush()
            return True
        except SerialException as e:
            _log.exception(e)

        return False

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
                read_bytes = self._serial_port.read(size - len(data))
                if len(read_bytes) > 0:
                    data.extend(read_bytes)
            return data
        except SerialException as e:
            _log.exception(e)

        return None

    def _execute_command(self, cmd_type, *args, wait_for_answer=True):
        """
        Executes the given command type with its arguments.

        Args:
            cmd_type (:class:`._FilesystemFunction`): the command type to execute.
            args (): the command arguments
            wait_for_answer (Boolean): ``True`` to wait for command answer, ``False`` otherwise.

        Returns:
            String: the command answer.

        Raises:
            FileSystemException: if there is any error executing the command.
        """
        # Sanity checks.
        if not self._is_function_supported(cmd_type):
            raise FileSystemException(_ERROR_FUNCTION_NOT_SUPPORTED % cmd_type.name)
        if not self._check_atcmd_mode():
            raise FileSystemException(_ERROR_ENTER_CMD_MODE)

        command = _COMMAND_ATFS % (cmd_type.command % args)
        try:
            self._serial_port.write(str.encode(command, encoding='utf-8'))
            answer = None
            if wait_for_answer:
                answer = self._read_data()
                if not answer:
                    raise FileSystemException(_ERROR_TIMEOUT)
                self._check_function_error(answer, command)

            return answer
        except SerialException as e:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), str(e)))

    @property
    def is_connected(self):
        """
        Returns whether the file system manager is connected or not.

        Returns:
            Boolean: ``True`` if the file system manager is connected, ``False`` otherwise.
         """
        return self._is_connected

    def connect(self):
        """
        Connects the file system manager.

        Raises:
            FileSystemException: if there is any error connecting the file system manager.
            FileSystemNotSupportedException: if the device does not support filesystem feature.
        """
        if self._is_connected:
            return

        # The file system manager talks directly with the serial port in raw mode, so disconnect the device.
        # Not disconnecting the device will cause the internal XBee device frame reader to consume the data
        # required by the file system manager from the serial port.
        if self._xbee_device.is_open:
            self._xbee_device.close()
            self._device_was_connected = True

        self._old_read_timeout = self._serial_port.get_read_timeout()
        try:
            self._serial_port.set_read_timeout(_READ_PORT_TIMEOUT)
            self._serial_port.open()
            self._is_connected = True
            if not self._supports_filesystem():
                raise FileSystemNotSupportedException(_ERROR_FILESYSTEM_NOT_SUPPORTED)
        except (SerialException, FileSystemNotSupportedException) as e:
            # Close port if it is open.
            if self._serial_port.isOpen():
                self._serial_port.close()
            self._is_connected = False

            try:
                # Restore serial port timeout.
                self._serial_port.set_read_timeout(self._old_read_timeout)
            except SerialException:
                pass  # Ignore this error as it is not critical and will not provide much info but confusion.
            if isinstance(e, SerialException):
                raise FileSystemException(_ERROR_CONNECT_FILESYSTEM % str(e))
            raise e

    def disconnect(self):
        """
        Disconnects the file system manager and restores the device connection.

        Raises:
            XBeeException: if there is any error restoring the XBee device connection.
        """
        if not self._is_connected:
            return

        # Exit AT command mode.
        self._exit_atcmd_mode()

        # Restore serial port timeout.
        try:
            self._serial_port.set_read_timeout(self._old_read_timeout)
        except SerialException:
            pass
        self._serial_port.close()
        self._is_connected = False
        if self._device_was_connected:
            time.sleep(0.3)
            self._xbee_device.open()

    def get_current_directory(self):
        """
        Returns the current device directory.

        Returns:
             String: the current device directory.

        Raises:
            FileSystemException: if there is any error getting the current directory or the function is not supported.
        """
        _log.info("Retrieving working directory")
        return self._execute_command(_FilesystemFunction.PWD).replace("\r", "")

    def change_directory(self, directory):
        """
        Changes the current device working directory to the given one.

        Args:
            directory (String): the new directory to change to.

        Returns:
             String: the current device working directory after the directory change.

        Raises:
            FileSystemException: if there is any error changing the current directory or the function is not supported.
        """
        # Sanity checks.
        if not directory:
            return

        _log.info("Navigating to directory '%s'" % directory)
        return self._execute_command(_FilesystemFunction.CD, directory).replace("\r", "")

    def make_directory(self, directory):
        """
        Creates the provided directory.

        Args:
            directory (String): the new directory to create.

        Raises:
            FileSystemException: if there is any error creating the directory or the function is not supported.
        """
        # Sanity checks.
        if not directory or directory == "/":
            return

        current_dir = self.get_current_directory()
        try:
            # Create intermediate directories in case it is required.
            temp_path = "/" if directory.startswith("/") else current_dir
            directory_chunks = directory.split("/")
            for chunk in directory_chunks:
                if not chunk:
                    continue
                if not temp_path.endswith("/"):
                    temp_path += "/"
                temp_path += chunk
                # Check if directory exists by navigating to it.
                try:
                    self.change_directory(temp_path)
                except FileSystemException:
                    # Directory does not exist, create it.
                    _log.info("Creating directory '%s'" % temp_path)
                    self._execute_command(_FilesystemFunction.MD, temp_path)
        finally:
            self.change_directory(current_dir)

    def list_directory(self, directory=None):
        """
        Lists the contents of the given directory.

        Args:
            directory (String, optional): the directory to list its contents. Optional. If not provided, the current
                                          directory contents are listed.

        Returns:
            List: list of ``:class:`.FilesystemElement``` objects contained in the given (or current) directory.

        Raises:
            FileSystemException: if there is any error listing the directory contents or the function is not supported.
        """
        if not directory:
            _log.info("Listing directory contents of current dir")
            answer = self._execute_command(_FilesystemFunction.LS)
        else:
            _log.info("Listing directory contents of '%s'" % directory)
            answer = self._execute_command(_FilesystemFunction.LS_DIR, directory)

        path = self.get_current_directory() if directory is None else directory
        if path != _PATH_SEPARATOR:
            path += _PATH_SEPARATOR
        filesystem_elements = []
        lines = answer.split("\r")
        for line in lines:
            # Ignore empty lines.
            if len(str.strip(line)) == 0:
                continue
            result = re.match(_PATTERN_FILE_SYSTEM_DIRECTORY, line)
            if result is not None and len(result.groups()) > 0:
                name = result.groups()[0]
                filesystem_elements.append(FileSystemElement(name, path + name, is_directory=True))
            else:
                result = re.match(_PATTERN_FILE_SYSTEM_FILE, line)
                if result is not None and len(result.groups()) > 1:
                    name = result.groups()[1]
                    size = int(result.groups()[0])
                    filesystem_elements.append(FileSystemElement(name, path + name, size=size))
                else:
                    _log.warning("Unknown filesystem element entry: %s" % line)

        return filesystem_elements

    def remove_element(self, element_path):
        """
        Removes the given file system element path.

        Args:
            element_path (String): path of the file system element to remove.

        Raises:
            FileSystemException: if there is any error removing the element or the function is not supported.
        """
        # Sanity checks.
        if not element_path:
            return

        _log.info("Removing file '%s'" % element_path)
        self._execute_command(_FilesystemFunction.RM, element_path)

    def move_element(self, source_path, dest_path):
        """
        Moves the given source element to the given destination path.

        Args:
            source_path (String): source path of the element to move.
            dest_path (String): destination path of the element to move.

        Raises:
            FileSystemException: if there is any error moving the element or the function is not supported.
        """
        # Sanity checks.
        if not source_path or not dest_path:
            return

        _log.info("Moving file '%s' to '%s'" % (source_path, dest_path))
        self._execute_command(_FilesystemFunction.MV, source_path, dest_path)

    def put_file(self, source_path, dest_path, secure=False, progress_callback=None):
        """
        Transfers the given file in the specified destination path of the XBee device.

        Args:
            source_path (String): the path of the file to transfer.
            dest_path (String): the destination path to put the file in.
            secure (Boolean, optional): ``True`` if the file should be stored securely, ``False`` otherwise. Defaults to
                                        ``False``.
            progress_callback (Function, optional): function to execute to receive progress information.

                Takes the following arguments:

                    * The progress percentage as integer.

        Raises:
            FileSystemException: if there is any error transferring the file or the function is not supported.
        """
        # Sanity checks.
        if secure and not self._is_function_supported(_FilesystemFunction.XPUT):
            raise FileSystemException(_ERROR_FUNCTION_NOT_SUPPORTED % _FilesystemFunction.XPUT.name)
        if not secure and not self._is_function_supported(_FilesystemFunction.PUT):
            raise FileSystemException(_ERROR_FUNCTION_NOT_SUPPORTED % _FilesystemFunction.PUT.name)

        # Create intermediate directories if required.
        dest_parent = os.path.dirname(dest_path)
        if len(dest_parent) == 0:
            dest_parent = self.get_current_directory()
        self.make_directory(dest_parent)

        # Initial XBee3 firmware does not allow to overwrite existing files.
        # If the file to upload already exists, remove it first.
        if not self._is_function_supported(_FilesystemFunction.MV):
            dest_name = os.path.basename(dest_path)
            elements = self.list_directory(dest_parent)
            for element in elements:
                if not element.is_directory and element.name == dest_name:
                    self.remove_element(element.path)
                    break

        _log.info("Uploading file '%s' to '%s'" % (source_path, dest_path))
        command = _COMMAND_ATFS % (_FilesystemFunction.XPUT.command % dest_path) if secure else \
            _COMMAND_ATFS % (_FilesystemFunction.PUT.command % dest_path)
        answer = self._execute_command(_FilesystemFunction.XPUT, dest_path) if secure else \
            self._execute_command(_FilesystemFunction.PUT, dest_path)
        if not answer.endswith(xmodem.XMODEM_CRC):
            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), "Transfer not ready"))
        # Transfer the file.
        try:
            xmodem.send_file_ymodem(source_path, self._xmodem_write_cb, self._xmodem_read_cb,
                                    progress_cb=progress_callback, log=_log)
        except XModemException as e:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), str(e)))
        # Read operation result.
        answer = self._read_data(timeout=_READ_DATA_TIMEOUT, empty_retries=_READ_EMPTY_DATA_RETRIES)
        if not answer:
            raise FileSystemException(_ERROR_TIMEOUT)
        self._check_function_error(answer, command)

    def put_dir(self, source_dir, dest_dir=None, progress_callback=None):
        """
        Uploads the given source directory contents into the given destination directory in the device.

        Args:
            source_dir (String): the local directory to upload its contents.
            dest_dir (String, optional): the remote directory to upload the contents to. Defaults to current directory.
            progress_callback (Function, optional): function to execute to receive progress information.

                Takes the following arguments:

                    * The file being uploaded as string.
                    * The progress percentage as integer.

        Raises:
            FileSystemException: if there is any error uploading the directory or the function is not supported.
        """
        # Sanity checks.
        if not source_dir:
            return

        # First make sure destination directory exists.
        if dest_dir is None:
            dest_dir = self.get_current_directory()
        else:
            self.make_directory(dest_dir)
        # Upload directory contents.
        for file in listdir(source_dir):
            if isfile(os.path.join(source_dir, file)):
                bound_callback = None if progress_callback is None \
                    else functools.partial(progress_callback, *[str(os.path.join(dest_dir, file))])
                self.put_file(str(os.path.join(source_dir, file)), str(os.path.join(dest_dir, file)),
                              progress_callback=bound_callback)
            else:
                self.put_dir(str(os.path.join(source_dir, file)), str(os.path.join(dest_dir, file)),
                             progress_callback=progress_callback)

    def get_file(self, source_path, dest_path, progress_callback=None):
        """
        Downloads the given XBee device file in the specified destination path.

        Args:
            source_path (String): the path of the XBee device file to download.
            dest_path (String): the destination path to store the file in.
            progress_callback (Function, optional): function to execute to receive progress information.

                Takes the following arguments:

                    * The progress percentage as integer.

        Raises:
            FileSystemException: if there is any error downloading the file or the function is not supported.
        """
        command = _COMMAND_ATFS % (_FilesystemFunction.GET.command % source_path)
        _log.info("Downloading file '%s' to '%s'" % (source_path, dest_path))
        self._execute_command(_FilesystemFunction.GET, source_path, wait_for_answer=False)
        try:
            # Consume data until 'NAK' is received.
            deadline = _get_milliseconds() + (_NAK_TIMEOUT * 1000)
            nak_received = False
            while not nak_received and _get_milliseconds() < deadline:
                data = self._xmodem_read_cb(1, timeout=_TRANSFER_TIMEOUT)
                if data and data[0] == xmodem.XMODEM_NAK:
                    nak_received = True
            if not nak_received:
                raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), "Transfer not ready"))
        except SerialException as e:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), str(e)))
        # Receive the file.
        try:
            xmodem.get_file_ymodem(dest_path, self._xmodem_write_cb, self._xmodem_read_cb,
                                   progress_cb=progress_callback, log=_log)
        except XModemException as e:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), str(e)))
        # Read operation result.
        answer = self._read_data()
        if not answer:
            raise FileSystemException(_ERROR_TIMEOUT)
        self._check_function_error(answer, command)

    def format_filesystem(self):
        """
        Formats the device file system.

        Raises:
            FileSystemException: if there is any error formatting the file system.
        """
        command = _COMMAND_ATFS % _FilesystemFunction.FORMAT.command
        _log.info("Formatting file system...")
        self._execute_command(_FilesystemFunction.FORMAT, wait_for_answer=False)
        try:
            deadline = _get_milliseconds() + (_FORMAT_TIMEOUT * 1000)
            ok_received = False
            while not ok_received and _get_milliseconds() < deadline:
                answer = self._read_data()
                self._check_function_error(answer, command)
                if _COMMAND_MODE_ANSWER_OK in answer:
                    ok_received = True
            if not ok_received:
                raise FileSystemException(_ERROR_TIMEOUT)
        except SerialException as e:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (command.replace("\r", ""), str(e)))

    def get_usage_information(self):
        """
        Returns the file system usage information.

        Returns:
            Dictionary: collection of pair values describing the usage information.

        Raises:
            FileSystemException: if there is any error retrieving the file system usage information.
        """
        _log.info("Reading file system usage information...")
        answer = self._execute_command(_FilesystemFunction.INFO)
        info = {}
        parts = str.strip(answer).split("\r")
        for part in parts:
            result = re.match(_PATTERN_FILE_SYSTEM_INFO, part)
            if result is not None and len(result.groups()) > 1:
                info[result.groups()[1]] = result.groups()[0]

        return info

    def get_file_hash(self, file_path):
        """
        Returns the SHA256 hash of the given file path.

        Args:
            file_path (String): path of the file to get its hash.

        Returns:
            String: the SHA256 hash of the given file path.

        Raises:
            FileSystemException: if there is any error retrieving the file hash.
        """
        _log.info("Retrieving SHA256 hash of file '%s'..." % file_path)
        answer = self._execute_command(_FilesystemFunction.HASH, file_path)
        parts = answer.split(_ANSWER_SHA256)
        if len(parts) <= 1:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      ((_COMMAND_ATFS % (_FilesystemFunction.HASH.command %
                                                         file_path)).replace("\r", ""), "Invalid hash received"))

        return str.strip(parts[1])


def _get_milliseconds():
    """
    Returns the current time in milliseconds.

    Returns:
         Integer: the current time in milliseconds.
    """
    return int(time.time() * 1000.0)


def _filter_non_printable(byte_array):
    """
    Filters the non printable characters of the given byte array and returns the resulting string.

    Args:
        byte_array (Bytearray): the byte array to filter.

    Return:
        String: the resulting string after filtering non printable characters of the byte array.
    """
    return bytes(x for x in byte_array if x in _printable_ascii_bytes).decode()
