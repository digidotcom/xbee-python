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

import functools
import logging
import os
import re
import string
import threading
import time
from abc import ABCMeta, abstractmethod
from enum import Enum
from os import listdir
from os.path import isfile
from pathlib import PurePosixPath
from serial.serialutil import SerialException

from digi.xbee.exception import XBeeException, OperationNotSupportedException
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.filesystem import FSCmd, GetPathIdCmdRequest, \
    CreateDirCmdRequest, OpenDirCmdRequest, DeleteCmdRequest, VolStatCmdRequest, \
    VolFormatCmdRequest, HashFileCmdRequest, ReadDirCmdRequest, \
    OpenFileCmdRequest, CloseFileCmdRequest, ReadFileCmdRequest, \
    WriteFileCmdRequest, CloseDirCmdRequest, RenameCmdRequest
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.options import TransmitOptions, DirResponseFlag, FileOpenRequestOption
from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.models.status import TransmitStatus, FSCommandStatus
from digi.xbee.packets.filesystem import RemoteFSRequestPacket, FSRequestPacket
from digi.xbee.util import xmodem, utils
from digi.xbee.util.xmodem import XModemException

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
_ERROR_FUNCTION_NOT_SUPPORTED = "Function not supported: %s"
_ERROR_TIMEOUT = "Timeout executing command"
ERROR_FILESYSTEM_NOT_SUPPORTED = "The device does not support file system feature"

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

REMOTE_SUPPORTED_HW_VERSIONS = (HardwareVersion.XBEE3.code,
                                HardwareVersion.XBEE3_SMT.code,
                                HardwareVersion.XBEE3_TH.code)
LOCAL_SUPPORTED_HW_VERSIONS = REMOTE_SUPPORTED_HW_VERSIONS \
                              + (HardwareVersion.XBEE3_RR.code,
                                 HardwareVersion.XBEE3_RR_TH.code,
                                 HardwareVersion.XBEE_BLU.code,
                                 HardwareVersion.XBEE_BLU_TH.code)

# Update this value when File System API frames are supported
XB3_MIN_FW_VERSION_FS_API_SUPPORT = {
    XBeeProtocol.ZIGBEE: 0x10FF,
    XBeeProtocol.DIGI_MESH: 0x30FF,
    XBeeProtocol.RAW_802_15_4: 0x20FF,
    # XBeeProtocol.BLE, specify so:
    #  * FileSystemManager() is NOT supported until FS API frames are added
    XBeeProtocol.BLE: 0x40FF
}

# Update this values when the File System OTA support is deprecated
XB3_MAX_FW_VERSION_FS_OTA_SUPPORT = {
    XBeeProtocol.ZIGBEE: 0x10FF,
    XBeeProtocol.DIGI_MESH: 0x30FF,
    XBeeProtocol.RAW_802_15_4: 0x20FF
    # XBeeProtocol.BLE, do not specify so:
    #  * LocalXBeeFileSystemManager() is SUPPORTED
    #  * update_remote_filesystem_image() is NOT supported (remotes do not exist)
}

_DEFAULT_BLOCK_SIZE = 64
_DEFAULT_BLOCK_SIZE_CELLULAR = 1490

_TRANSFER_TIMEOUT = 5  # Seconds.

_log = logging.getLogger(__name__)
_printable_ascii_bytes = string.printable.encode(encoding='utf8')


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
        Returns the `_FilesystemFunction` for the given name.

        Args:
            name (String): Name of the `_FilesystemFunction` to get.

        Returns:
            :class:`._FilesystemFunction`: `_FilesystemFunction` with the given
                name, `None` if there is not a `_FilesystemFunction` with the
                provided name.
        """
        for value in _FilesystemFunction:
            if value.cmd_name == name:
                return value

        return None

    @property
    def cmd_name(self):
        """
        Returns the name of the `_FilesystemFunction` element.

        Returns:
            String: Name of the `_FilesystemFunction` element.
        """
        return self.__name

    @property
    def command(self):
        """
        Returns the command of the `_FilesystemFunction` element.

        Returns:
            String: Command of the `_FilesystemFunction` element.
        """
        return self.__command


class FileSystemElement:
    """
    Class used to represent XBee file system elements (files and directories).
    """

    def __init__(self, name, path=None, is_dir=False, size=0, is_secure=False):
        """
        Class constructor. Instantiates a new :class:`.FileSystemElement`
        object with the given parameters.

        Args:
            name (String or bytearray): Name of the file system element.
            path (String or bytearray, optional, default=`None`): Absolute path
                of the element.
            is_dir (Boolean, optional, default=`True`): `True` if the
                element is a directory, `False` for a file.
            size (Integer, optional, default=0): Element size in bytes.
                Only for files.
            is_secure (Boolean, optional, default=`False`): `True` for a secure
                element, `False` otherwise.

        Raises:
            ValueError: If any of the parameters are invalid.
        """
        if not name or not isinstance(name, (str, bytearray, bytes)):
            raise ValueError("Name must be a non-empty string or bytearray")
        if not isinstance(size, int):
            raise ValueError("Size must be a integer")
        if path and not isinstance(path, (str, bytearray, bytes)):
            raise ValueError("Path must be a string or bytearray")

        if isinstance(name, str):
            self._name = name.encode('utf8', errors='ignore')
        else:
            self._name = name
        if isinstance(path, str):
            self._path = path.encode('utf8', errors='ignore')
        else:
            self._path = path if path is not None else bytearray()
        self._is_dir = is_dir
        self._size = size if not is_dir else 0
        self._is_secure = is_secure

    def __str__(self):
        return "{:s} {:10s} {:25s} {:s}".format(
            "d" if self._is_dir else "*" if self._is_secure else "-", self.size_pretty,
            self.name, self.path)

    @property
    def name(self):
        """
        Returns the file system element name.

        Returns:
            String: File system element name.
         """
        return self._name.decode(encoding='utf8', errors='ignore')

    @property
    def path(self):
        """
        Returns the file system element absolute path.

        Returns:
            String: File system element absolute path.
         """
        return self._path.decode(encoding='utf8', errors='ignore')

    @path.setter
    def path(self, element_path):
        """
        Sets the file system element absolute path.

        Args:
            element_path (String): File system element absolute path.
         """
        self._path = element_path

    @property
    def is_dir(self):
        """
        Returns whether the file system element is a directory.

        Returns:
            Boolean: `True` for a directory, `False` otherwise.
         """
        return self._is_dir

    @property
    def size(self):
        """
        Returns the size in bytes of the element.

        Returns:
            Integer: The size in bytes of the file, 0 for a directory.
        """
        return self._size

    @property
    def size_pretty(self):
        """
        Returns a human readable size (e.g., 1K 234M 2G).

        Returns:
            String: Human readable size.
        """
        units = [(1 << 50, 'PB'), (1 << 40, 'TB'), (1 << 30, 'GB'),
                 (1 << 20, 'MB'), (1 << 10, 'KB'), (1, 'B')]

        factor, suffix = units[len(units) - 1]
        for factor, suffix in units:
            if self._size >= factor:
                break
        amount = round(self._size / factor, 2)

        return "%5.2f%s" % (amount, suffix)

    @property
    def is_secure(self):
        """
        Returns whether the element is secure.

        Returns:
            Boolean: `True` for a secure element, `False` otherwise.
        """
        return self._is_secure

    @staticmethod
    def from_data(name, size, flags, path=None):
        """
        Creates a file element from its name and the bytearray with info and
        size.

        Args:
            name (String or bytearray): The name of the element to create.
            size (Bytearray): Byte array containing file size.
            flags (Integer): Integer with file system element information.
            path (String or bytearray, optional, default=`None`): The absolute
                path of the element (without its name).

        Returns:
            :class:`.FileSystemElement`: The new file system element.
        """
        return FileSystemElement(
            name, path=path, is_dir=bool(flags & DirResponseFlag.IS_DIR),
            size=utils.bytes_to_int(size),
            is_secure=bool(flags & DirResponseFlag.IS_SECURE))


class FileSystemException(XBeeException):
    """
    This exception will be thrown when any problem related with the XBee
     file system occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """

    def __init__(self, message, fs_status=None):
        super().__init__(message)
        self.status = fs_status


class FileSystemNotSupportedException(FileSystemException):
    """
    This exception will be thrown when the file system feature is not supported
    in the device.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """


class _FSFrameSender:
    """
    Helper class used to send file system frames and wait for the response.
    """

    def __init__(self, xbee):
        """
        Class constructor. Instantiates a new :class:`._FSFrameSender` with
        the given parameters.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): Destination XBee.
        """
        self.__xbee = xbee
        self.__lock = threading.Event()
        self.__frame = None
        self.__resp_cmd = None
        self.__rec_opts = None

    def __str__(self):
        return "File system sender (dst: %s)" % self.__xbee

    def _fs_frame_cb(self, xbee, frame_id, cmd, receive_opts):
        """
        Callback to execute when a new frame id is received.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): The node that sent the file
                system frame.
            frame_id (Integer): The received frame id.
            cmd (:class:`.FSCmd`): The file system command.
            receive_opts (Integer): Bitfield indicating receive options.
                See :class:`.ReceiveOptions`.
        """
        if (frame_id != self.__frame.frame_id
                or cmd.type != self.__frame.command.type
                or xbee != self.__xbee):
            return

        self.__resp_cmd = cmd
        self.__rec_opts = receive_opts
        self.__lock.set()

    def send(self, frame_to_send, timeout=10):
        """
        Sends the file system frame to the provided XBee and waits for its
        response.

        Args:
            frame_to_send (:class:`XBeeAPIPacket`): The file system frame to
                send.
            timeout (Float): Maximum number of seconds to wait for the response.

        Returns:
            Tuple: Tuple containing route data:
                - rv_status (Integer): Status of the file system command
                  execution. See :class:`.FSCommandStatus`.
                - resp_cmd (:class:`.FSCmd`): The response command.
                - rv_opts (Integer): Bitfield indicating the receive options.
                  See :class:`.ReceiveOptions`.
        """
        local_xb = self.__xbee
        if self.__xbee.is_remote():
            local_xb = self.__xbee.get_local_xbee_device()
        tr_status = None
        self.__lock.clear()
        self.__frame = frame_to_send
        self.__resp_cmd = None
        self.__rec_opts = None

        log_msg_fmt = "%s: %s: %s" % (str(self), self.__frame.command.type.description, "%s")

        local_xb.add_fs_frame_received_callback(self._fs_frame_cb)

        try:
            #start = time.time()

            if self.__xbee.is_remote():
                _log.debug(log_msg_fmt, "Sending remote frame")
                local_xb.send_packet(self.__frame)
                if not self.__lock.wait(timeout):
                    self._throw_fs_exc(self.__frame.command,
                                       "Timeout waiting for remote response")
                tr_status = TransmitStatus.SUCCESS
                # Transmit status frame is never received for Zigbee,
                # DigiMesh is receiving it, 802.15.4
                # https://jira.digi.com/browse/XBHAWK-530
                #st_frame = local_xb.send_packet_sync_and_get_response(
                #    self.__frame, timeout=timeout)
                #tr_status = st_frame.transmit_status if st_frame else None
                #if tr_status in (TransmitStatus.SUCCESS,
                #                 TransmitStatus.SELF_ADDRESSED):
                #    if not self.__lock.wait(timeout - (time.time() - start)):
                #        self._throw_fs_exc(self.__frame.command,
                #                           "Timeout waiting for remote response")
                #else:
                #    self._throw_fs_exc(self.__frame.command,
                #                       "Remote frame not sent (tr status: %s)" % tr_status)
            else:
                _log.debug(log_msg_fmt, "Sending local frame")
                local_xb.send_packet(self.__frame)
                if not self.__lock.wait(timeout):
                    self._throw_fs_exc(self.__frame.command,
                                       "Timeout waiting for local response")
                tr_status = TransmitStatus.SUCCESS
        except FileSystemException:
            pass
        except XBeeException as exc:
            self._throw_fs_exc(self.__frame.command, str(exc))
        finally:
            local_xb.del_fs_frame_received_callback(self._fs_frame_cb)

        if not tr_status or not self.__resp_cmd:
            self._throw_fs_exc(self.__frame.command,
                               "Response not received in timeout")

        status = self.__resp_cmd.status_value
        if status != FSCommandStatus.SUCCESS.code:
            fs_status = FSCommandStatus.get(status)
            msg = str(fs_status) if fs_status else "Unknown file system status (0x%0.2X)" % status
            _log.error("%s: %s: %s", str(self), self.__frame.command.type.description, msg)

        return status, self.__resp_cmd, self.__rec_opts

    def _throw_fs_exc(self, cmd, msg, status=None):
        exc_msg_fmt = "%s error: %s" % (cmd.type.description, "%s")
        log_msg_fmt = "%s: %s: %s" % (str(self), cmd.type.description, "%s")

        _log.error(log_msg_fmt, msg)
        raise FileSystemException(exc_msg_fmt % msg, fs_status=status)


class FileProcess(metaclass=ABCMeta):
    """
    This class represents a file process.
    """

    def __init__(self, f_mng, file, timeout):
        """
        Class constructor. Instantiates a new :class:`._FileProcess` object
        with the provided parameters.

        Args:
            f_mng (class:`.FileSystemManager`): The file system manager.
            file (:class:`.FileSystemElement` or String): File or its absolute path.
            timeout(Float): Timeout in seconds.
        """
        if not isinstance(file, (str, FileSystemElement)):
            raise ValueError("File must be a string or a FileSystemElement")
        if isinstance(file, FileSystemElement):
            if file.is_dir:
                raise ValueError("File cannot be a directory")
            if file.path in ("/", "\\", ".", ".."):
                raise ValueError("Invalid file path")
        if isinstance(file, str) and file in ("/", "\\", ".", ".."):
            raise ValueError("Invalid file path")

        # Sanitize path
        file_path = file
        if isinstance(file, FileSystemElement):
            file_path = file.path
        file_path = os.path.normpath(file_path.replace('\\', '/'))

        self._f_mng = f_mng
        self._f_path = file_path
        self._timeout = timeout

        self._fid = None
        self._fsize = None
        self._cpid = None

        self._running = False
        self._opened = False
        self._status = None
        self._cb = None

    @property
    def running(self):
        """
        Returns if this file command is running.

        Returns:
            Boolean: `True` if it is running, `False` otherwise.
        """
        return self._running

    @property
    def status(self):
        """
        Returns the status code.

        Returns:
             Integer: The status.
        """
        return self._status

    @property
    def block_size(self):
        """
        Returns the size of the block for this file operation.

        Returns:
             Integer: Size of the block for this file operation.
        """
        return self._get_block_size(0)

    def _next(self, last=True):
        """
        Executes the next action.
        """
        error = bool(self._status not in (None, FSCommandStatus.SUCCESS.code))

        if not self._fid and not self._opened and not error:
            self._start_process()
            if self._fid is None or self._cpid is None:
                return

        r_last = False
        if not error:
            r_last = self._exec_specific_cmd()

        if self._opened and (last or r_last or error):
            self._end_process()

    def _start_process(self):
        """
        Starts the file process.
        """
        self._running = True
        self._status = None
        self._cpid = 0

        # Check length of path, if is too big try to change to a parent
        self._cpid, f_path = self._f_mng._cd_to_execute(self._f_path,
                                                        self._cpid, self._timeout)

        self._status, self._fid, self._fsize = self._f_mng.popen_file(
            f_path, options=self._get_open_flags(), path_id=self._cpid,
            timeout=self._timeout)
        # RF file systems return 0xFFFFFFFF file size for new files,
        # while Cellular file systems return 0.
        if self._fsize == 0 and (self._get_open_flags() & FileOpenRequestOption.CREATE) > 0:
            self._fsize = 0xFFFFFFFF

        self._opened = bool(self._status == FSCommandStatus.SUCCESS.code)
        if not self._opened:
            if self._cpid:
                self._f_mng.prelease_path_id(self._cpid, self._timeout)
            self._running = False
            self._notify_process_finished()

    def _end_process(self):
        """
        Closes the file and releases the path id.
        """
        cl_st = None
        # Close file and release directory path id
        if self._fid:
            cl_st = self._f_mng.pclose_file(self._fid, timeout=self._timeout)
        if self._cpid:
            self._f_mng.prelease_path_id(self._cpid, self._timeout)

        self._opened = False
        self._running = False

        self._status = self._status if self._status else cl_st
        if self._status:
            self._notify_process_finished()

    def _get_block_size(self, extra_data_len):
        xbee = self._f_mng.xbee

        n_bytes = self._f_mng.np_value
        if not n_bytes:
            n_bytes = _DEFAULT_BLOCK_SIZE
        else:
            n_bytes = self._f_mng.np_value - extra_data_len
        if xbee.is_remote():
            cfg_max = xbee.get_ota_max_block_size()
            n_bytes = min(cfg_max, n_bytes) if cfg_max else n_bytes

        # If max block is not configured and NP cannot be read, set 64
        if n_bytes < 1:
            n_bytes = _DEFAULT_BLOCK_SIZE

        return n_bytes

    @abstractmethod
    def _get_open_flags(self):
        """
        Bitmask that specifies the options to open the file.

        Returns:
            :class:`.FileOpenRequestOption`: Options to open the file.
        """

    @abstractmethod
    def _exec_specific_cmd(self):
        """
        Executes the specific file process (read or write).

        Returns:
            Boolean: `True` if this was the last command to execute, `False`
                otherwise.
        """

    @abstractmethod
    def _notify_process_finished(self):
        """
        Notifies that the file process has finished its execution.
        """

    def _log_str(self, msg, *args):
        return "%s: %s" % (str(self), msg % args)


class _ReadFileProcess(FileProcess):

    def __init__(self, f_mng, file, offset, timeout, read_callback=None):
        """
        Override.

        Args:
            offset (Integer): File offset to start reading.
            read_callback (Function, optional, default=`None`): Method called
                when new data is read. Receives three arguments:

                * The read chunk of data.
                * The progress percentage as float.
                * The total size of the file.
                * The completion status code (integer). See `.FSCommandStatus`.
        """
        if offset is not None and not isinstance(offset, int) or offset < 0:
            raise ValueError("Offset must be 0 or greater")

        super().__init__(f_mng, file, timeout)
        self.__offset = offset
        self.__l_off = offset
        self._cb = read_callback
        self.__size = 0
        self.__data = bytearray()

        _log.debug(self._log_str("Reading file '%s' (offset: %d)",
                                 self._f_path, offset))

    def __str__(self):
        return "Read file command ('%s')" % self._f_path

    @property
    def block_size(self):
        """
        Returns the size of the block for this file operation.

        Returns:
             Integer: The size of the block for this file operation.
        """
        # cmd_id (1) + f_id (2) + offset (4) + size (2) = 9
        return self._get_block_size(9)

    def next(self, size=-1, last=True):
        """
        Reads from the current offset the provided amount of data. The process
        blocks until all data is read.
        Set `last` to `False` to use subsequents calls to `next` to read more
        data. When no more read is required, close the file setting `last` to
        `True`. If the end of the file is reached it is close independently of
        `last` value.

        Args:
            size (Integer, optional, default=-1): Number of bytes to read.
                -1 for the complete file.
            last (Boolean, optional, default=`True'): `True` if this is the
                last step, `False` otherwise.

        Returns:
            Bytearray: The total read data bytearray.

        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(size, int) or size < -1:
            raise ValueError("Size must be -1 or greater")

        if not size or self._fsize and self.__l_off >= self._fsize:
            return bytearray()

        self.__size = size

        super()._next(last=last)

        if self._status == FSCommandStatus.SUCCESS.code:
            return self.__data

        if not self._cb:
            _raise_exception(self._status,
                             "Error reading file '%s'" % self._f_path)

        return bytearray()

    def _get_open_flags(self):
        """
        Override.

        .. seealso::
           | :meth:`._FileProcess._get_open_flags`
        """
        return FileOpenRequestOption.READ

    def _exec_specific_cmd(self):
        """
        Override.

        .. seealso::
           | :meth:`._FileProcess._exec_specific_cmd`
        """
        self._status = FSCommandStatus.SUCCESS.code
        self.__data = bytearray()

        # Calculate total size to read in file
        total_in_file = self._fsize - self.__offset
        if total_in_file <= 0:
            return True

        # Calculate remaining (not read) size in file
        remain_in_file = self._fsize - self.__l_off
        if not remain_in_file:
            return True

        # Calculate total size to read
        total_to_read = min(self.__size, total_in_file)
        if total_to_read == -1:
            total_to_read = total_in_file

        # Calculate remaining (not read) to read
        remain_to_read = min(self.__size, remain_in_file)
        if remain_to_read == -1:
            remain_to_read = remain_in_file

        # Calculate chunk length
        chunk_len = min(self.block_size, remain_to_read)
        _log.debug(self._log_str("Block size: %d", chunk_len))

        while (chunk_len and len(self.__data) < remain_to_read
               and self.__l_off < self._fsize):
            _log.debug(self._log_str("Reading, offset: %d, size: %d",
                                     self.__l_off, chunk_len))
            self._status, _fid, _offst, chunk = self._f_mng.pread_file(
                self._fid, offset=self.__l_off, size=chunk_len,
                timeout=self._timeout)

            if self._status != FSCommandStatus.SUCCESS.code:
                return True

            self.__data += chunk

            _log.debug(self._log_str("Read %d (%d/%d)", len(chunk),
                                     len(self.__data), remain_to_read))

            if self._cb:
                self._cb(chunk, len(self.__data) * 100 / remain_to_read,
                         self._fsize, self._status)

            # Recalculate offset
            self.__l_off += len(chunk)

            # Recalculate chunk length
            chunk_len = min(chunk_len, remain_to_read - len(self.__data))

        return self.__l_off >= self._fsize

    def _notify_process_finished(self):
        """
        Override.

        .. seealso::
           | :meth:`._FileProcess._notify_process_finished`
        """
        if self._cb:
            self._cb(bytearray(), 0, self._fsize, self._status)


class _WriteFileProcess(FileProcess):

    def __init__(self, f_mng, file, offset, options, timeout, write_callback=None):
        """
        Override.

        Args:
            write_callback (Function, optional, default=`None`): Method called
                when data is written. Receives three arguments:

                * The amount of bytes written in the chunk.
                * The progress percentage as float.
                * The completion status code (integer). See `.FSCommandStatus`.
        """
        if offset is not None and not isinstance(offset, int) or offset < 0:
            raise ValueError("Offset must be 0 or greater")

        super().__init__(f_mng, file, timeout)
        self.__offset = offset
        self.__options = options
        self._cb = write_callback
        self.__n_bytes = 0
        self.__data = bytearray()

        _log.debug(self._log_str("Writing to file '%s' (offset: %d)",
                                 self._f_path, offset))

    def __str__(self):
        return "Write file command ('%s')" % self._f_path

    @property
    def block_size(self):
        """
        Returns the size of the block for this file operation.

        Returns:
             Integer: Size of the block for this file operation.
        """
        # cmd_id (1) + f_id (2) + offset (4) = 7
        return self._get_block_size(7)

    def next(self, data, last=True):
        """
        Writes the provided data in the current file offset. The process blocks
        until all requested data is written.
        Set `last` to `False` to use subsequents calls to `next` to write more
        data. When no more write is required, close the file setting `last` to
        `True`. If the end of the file is reached it is close independently of
        `last` value.

        Args:
            data (Bytearray, bytes, String): Data to write.
            last (Boolean, optional, default=`True'): 'True' if this is the
                last chunk to write, `False` otherwise.

        Returns:
            Integer: The total size written (in bytes).

        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(data, (bytearray, bytes, str)):
            raise ValueError("Data must be a bytearray, bytes or a string")

        self.__data = data
        if isinstance(data, str):
            self.__data = bytearray(data, encoding='utf8')

        super()._next(last=last)

        if self._status == FSCommandStatus.SUCCESS.code:
            return self.__n_bytes

        if not self._cb:
            _raise_exception(self._status,
                             "Error writing file '%s'" % self._f_path)

        return None

    def _get_open_flags(self):
        """
        Override.

        .. seealso::
           | :meth:`._FileProcess._get_open_flags`
        """
        return self.__options

    def _exec_specific_cmd(self):
        """
        Override.

        .. seealso::
           | :meth:`._FileProcess._exec_specific_cmd`
        """
        self._status = FSCommandStatus.SUCCESS.code
        if not self.__data or (self.__offset != WriteFileCmdRequest.USE_CURRENT_OFFSET
                               and self.__offset + 1 >= self._fsize):
            return True

        last_offset = self.__offset
        data_offset = 0

        # Calculate chunk length
        chunk_len = min(self.block_size, len(self.__data))
        _log.debug(self._log_str("Block size: %d", chunk_len))

        while chunk_len and data_offset < len(self.__data):
            _log.debug(self._log_str("Writing, offset: %d, size: %d",
                                     last_offset, chunk_len))
            self._status, _fid, last_offset = self._f_mng.pwrite_file(
                self._fid, data=self.__data[data_offset:data_offset + chunk_len],
                offset=last_offset, timeout=self._timeout)

            if self._status != FSCommandStatus.SUCCESS.code:
                return True

            data_offset += chunk_len
            self.__n_bytes += chunk_len

            if self._cb:
                self._cb(chunk_len, self.__n_bytes * 100 / len(self.__data),
                         self._status)

            # Recalculate chunk length
            chunk_len = min(chunk_len, len(self.__data) - data_offset)

        if self.__offset != WriteFileCmdRequest.USE_CURRENT_OFFSET:
            self.__offset += data_offset
        self.__n_bytes = 0

        return False

    def _notify_process_finished(self):
        """
        Override.

        .. seealso::
           | :meth:`._FileProcess._notify_process_finished`
        """
        if self._cb:
            self._cb(0, self.__n_bytes, self._status)


class FileSystemManager:
    """
    Helper class used to manage local or remote XBee file system.
    """

    DEFAULT_TIMEOUT = 20
    DEFAULT_FORMAT_TIMEOUT = 30

    _LOCAL_READ_CHUNK = 1024

    def __init__(self, xbee):
        """
        Class constructor. Instantiates a new :class:`.FileSystemManager` with
        the given parameters.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): XBee to manage its file system.

        Raises:
            FileSystemNotSupportedException: If the XBee does not support
                filesystem.
        """
        from digi.xbee.devices import AbstractXBeeDevice
        if not isinstance(xbee, AbstractXBeeDevice):
            raise ValueError("XBee must be an XBee class")

        if not check_fs_support(xbee, min_fw_vers=XB3_MIN_FW_VERSION_FS_API_SUPPORT):
            raise FileSystemNotSupportedException(ERROR_FILESYSTEM_NOT_SUPPORTED)

        self.__xbee = xbee
        self.__np_val = None
        self.__root = FileSystemElement(name="/", path="/", is_dir=True,
                                        size=0, is_secure=False)

    def __str__(self):
        return "File system (%s)" % self.__xbee

    @property
    def xbee(self):
        """
        Returns the XBee of this file system manager.

        Returns:
            :class:`.AbstractXBeeDevice`: XBee to manage its file system.
        """
        return self.__xbee

    @property
    def np_value(self):
        """
        The 'NP' parameter value of the local XBee.

        Returns:
             Integer: The 'NP' value.
        """
        return self._get_np()

    def get_root(self):
        """
        Returns the root directory.

        Returns:
             :class:`.FileSystemElement`: The root directory.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
        """
        return self.__root

    def make_directory(self, dir_path, base=None, mk_parents=True, timeout=DEFAULT_TIMEOUT):
        """
        Creates the provided directory.

        Args:
            dir_path (String): Path of the new directory to create. It is
                relative to the directory specify in base.
            base (:class:`.FileSystemElement`, optional, default=`None): Base
                directory. If not specify it refers to '/flash'.
            mk_parents (Boolean, optional, default=`True`): `True` to make
                parent directories as needed, `False` otherwise.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum number
                of seconds to wait for the operation completion. If `mk_parents`
                this is the timeout per directory creation.

        Returns:
            List: List of :class:`.FileSystemElement` created directories.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(dir_path, str):
            raise ValueError("Directory path must be a non empty string")
        if dir_path in ("/", "\\", ".", ".."):
            raise ValueError("Invalid directory path")
        if base and not isinstance(base, FileSystemElement):
            raise ValueError("Base must be a FileSystemElement")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path_id = 0
        path = os.path.normpath(dir_path.replace('\\', '/'))

        base_path = "/flash"
        if base:
            base_path = os.path.normpath(base.path.replace('\\', '/'))

        comp_path = os.path.join(base_path, path)

        _log.debug(self._log_str("Creating directory '%s' (base: %s)",
                                 path, base_path))
        path = PurePosixPath(comp_path)
        dirs = []

        start = time.time()

        try:
            # XBee create directory command does not make intermediate dir, this
            # method generates them recursively:
            # https://jira.digi.com/browse/XBHAWK-523
            if mk_parents and str(path.parent) not in (path.root, '.', '/flash'):
                dirs += self.make_directory(str(path.parent), mk_parents=True,
                                            timeout=timeout)

            # Check length of path, if is too big try to change to a parent
            path_id, to_create = self._cd_to_execute(
                comp_path, path_id, timeout - (time.time() - start))

            # Create the directory
            status = self.pmake_directory(to_create, path_id=path_id,
                                          timeout=(timeout - (time.time() - start)))
        finally:
            if path_id:
                self.prelease_path_id(path_id, timeout)

        if status not in (FSCommandStatus.SUCCESS.code,
                          FSCommandStatus.ALREADY_EXISTS.code):
            _raise_exception(status, "Error making directory '%s'" % comp_path)

        dirs.append(
            FileSystemElement(os.path.basename(comp_path), path=comp_path,
                              is_dir=True, size=0, is_secure=False))

        return dirs

    def list_directory(self, directory=None, timeout=DEFAULT_TIMEOUT):
        """
        Lists the contents of the given directory.

        Args:
            directory (:class:`.FileSystemElement` or String): Directory to
                list or its absolute path.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            List: List of `:class:`.FilesystemElement` objects contained in
                the given directory, empty list if status is not 0.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.
        """
        if directory:
            if not isinstance(directory, (str, FileSystemElement)):
                raise ValueError("Directory must be a string or a FileSystemElement")
            if isinstance(directory, FileSystemElement) and not directory.is_dir:
                raise ValueError("Directory must be a directory")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path_id = 0
        dir_path = directory
        if isinstance(directory, FileSystemElement):
            dir_path = directory.path

        if dir_path in ("", ".", None):
            dir_path = "/flash"
        elif dir_path == "..":
            dir_path = "/"
        dir_path = os.path.normpath(dir_path.replace('\\', '/'))

        _log.debug(self._log_str("Listing directory '%s'", dir_path))

        start = time.time()

        try:
            # Check length of path, if is too big try to change to a parent
            path_id, to_list = self._cd_to_execute(dir_path, path_id, timeout)

            status, files = self.plist_directory(
                to_list, path_id=path_id, timeout=(timeout - (time.time() - start)))

            # This will store the absolute path of the contents
            for entry in files:
                entry.path = os.path.join(dir_path, entry.name)
        finally:
            if path_id:
                self.prelease_path_id(path_id, timeout)

        if status != FSCommandStatus.SUCCESS.code:
            _raise_exception(status, "Error listing directory '%s'" % dir_path)

        return files

    def remove(self, entry, rm_children=True, timeout=DEFAULT_TIMEOUT):
        """
        Removes the given file system entry.

        All files in a directory must be deleted before removing the directory.
        On XBee 3 802.15.4, DigiMesh, and Zigbee, deleted files are marked as
        unusable space unless they are at the "end" of the file system
        (most-recently created). On these products, deleting a file triggers
        recovery of any deleted file space at the end of the file system, and
        can lead to a delayed response.

        Args:
            entry (:class:`.FileSystemElement` or String): File system entry to
                remove or its absolute path.
            rm_children (Boolean, optional, default=`True`): `True` to remove
                directory children if they exist, `False` otherwise.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(entry, (str, FileSystemElement)):
            raise ValueError("Entry must be a string or a FileSystemElement")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path_id = 0
        entry_path = entry
        if isinstance(entry, FileSystemElement):
            entry_path = entry.path

        if entry_path in ("", ".", None):
            entry_path = "/flash"
        elif entry_path == "..":
            entry_path = "/"
        entry_path = os.path.normpath(entry_path.replace('\\', '/'))

        _log.debug(self._log_str("Removing entry '%s'", entry_path))

        start = time.time()

        try:
            # Check length of path, if is too big try to change to a parent
            path_id, to_rm = self._cd_to_execute(entry_path, path_id, timeout)

            status = self.premove(to_rm, path_id=path_id,
                                  timeout=(timeout - (time.time() - start)))

            # To remove a directory, it must be empty beforehand:
            # https://jira.digi.com/browse/XBHAWK-525
            if rm_children and status == FSCommandStatus.DIR_NOT_EMPTY.code:
                # Release the path id
                if path_id:
                    self.prelease_path_id(path_id, timeout)
                    path_id = 0
                # Remove the directory content
                files = self.list_directory(
                    entry_path, timeout=(timeout - (time.time() - start)))
                for file in files:
                    self.remove(file, rm_children=True,
                                timeout=(timeout - (time.time() - start)))
                # Remove the directory
                path_id, to_rm = self._cd_to_execute(entry_path, path_id,
                                                     timeout, refresh=False)
                status = self.premove(to_rm, path_id=path_id,
                                      timeout=(timeout - (time.time() - start)))
        finally:
            if path_id:
                self.prelease_path_id(path_id, timeout)

        if status != FSCommandStatus.SUCCESS.code:
            _raise_exception(status, "Error removing entry '%s'" % entry_path)

    def read_file(self, file, offset=0, progress_cb=None):
        """
        Reads from the provided file starting at the given offset.
        If there is no progress callback the function blocks
        until the required amount of bytes is read.

        Args:
            file (:class:`.FileSystemElement` or String): File to read or its
                absolute path.
            offset (Integer, optional, default=0): File offset to start
                reading.
            progress_cb (Function, optional, default=`None`): Function called
                when new data is read. Receives four arguments:

                    * The chunk of data read as byte array.
                    * The progress percentage as float.
                    * The total size of the file.
                    * The status when process finishes.

        Returns:
            :class:`.FileProcess`: The process to read data from the file.

        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :meth:`.get_file`
        """
        return _ReadFileProcess(self, file, offset, self.DEFAULT_TIMEOUT,
                                read_callback=progress_cb)

    def write_file(self, file, offset=0, secure=False, options=None, progress_cb=None):
        """
        Writes to the provided file the data starting at the given offset. The
        function blocks until the all data is written.

        Args:
            file (:class:`.FileSystemElement` or String): File to write or its
                absolute path.
            offset (Integer, optional, default=0): File offset to start writing.
            secure (Boolean, optional, default=`False`): `True` to store the
                file securely (no read access), `False` otherwise.
            options (Dictionary, optional): Other write options as list:
                `exclusive`, `truncate`, `append`.
            progress_cb (Function, optional, default=`None`): Function call
                when data is written. Receives three arguments:

                    * The amount of bytes written (for each chunk).
                    * The progress percentage as float.
                    * The status when process finishes.

        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :meth:`.put_file`
        """
        if options is None:
            options = []

        wr_options = FileOpenRequestOption.WRITE
        if secure:
            wr_options |= FileOpenRequestOption.SECURE
        if "exclusive" in options:
            wr_options |= FileOpenRequestOption.EXCLUSIVE
        else:
            wr_options |= FileOpenRequestOption.CREATE
        if "truncate" in options:
            wr_options |= FileOpenRequestOption.TRUNCATE
        if "append" in options:
            wr_options |= FileOpenRequestOption.APPEND

        return _WriteFileProcess(self, file, offset, wr_options,
                                 self.DEFAULT_TIMEOUT, write_callback=progress_cb)

    def get_file(self, src, dest, progress_cb=None):
        """
        Downloads the given XBee file in the specified destination path.

        Args:
            src (:class:`.FileSystemElement` or String): File to download or
                its absolute path.
            dest (String): The absolute path of the destination file.
            progress_cb (Function, optional): Function call when data is being
                downloaded. Receives three arguments:

                    * The progress percentage as float.
                    * Destination file path.
                    * Source file path.

        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(dest, str):
            raise ValueError("Destination path must be a non-empty string")

        src_path = src
        if isinstance(src, FileSystemElement):
            src_path = src.path
        src_path = os.path.normpath(src_path.replace('\\', '/'))

        total_read = 0

        def p_cb(chunk, _perc, size, status):
            nonlocal total_read
            if status not in (None, FSCommandStatus.SUCCESS.code):
                _raise_exception(status, "Error getting file '%s'" % src_path)
            total_read += len(chunk)
            if progress_cb:
                progress_cb(total_read * 100.0 / size, dest, src_path)

        with open(dest, "wb+") as dst_file:
            r_proc = self.read_file(src, offset=0, progress_cb=p_cb)
            size = r_proc.block_size
            while True:
                try:
                    data = r_proc.next(size=size, last=False)
                    if not data:
                        break
                    dst_file.write(data)
                except EnvironmentError as exc:
                    r_proc.next(size=0, last=True)
                    raise exc

    def put_file(self, src, dest, secure=False, overwrite=False,
                 mk_parents=True, progress_cb=None):
        """
        Uploads the given file to the specified destination path of the XBee.

        Args:
            src (String): Absolute path of the file to upload.
            dest (:class:`.FileSystemElement` or String): The file in the XBee
                or its absolute path.
            secure (Boolean, optional, default=`False`): `True` if the file
                should be stored securely, `False` otherwise.
            overwrite (Boolean, optional, default=`False`): `True` to overwrite
                the file if it exists, `False` otherwise.
            mk_parents (Boolean, optional, default=`True`): `True` to make
                parent directories as needed, `False` otherwise.
            progress_cb (Function, optional): Function call when data is being
                uploaded. Receives two arguments:

                    * The progress percentage as float.
                    * Destination file path.
                    * Source file path.

        Returns:
            :class:`.FileSystemElement`: The new created file.

        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(src, str):
            raise ValueError("Source path must be a non-empty string")

        dst_path = dest
        if isinstance(dest, FileSystemElement):
            dst_path = dest.path
        dst_path = os.path.normpath(dst_path.replace('\\', '/'))

        f_size = os.stat(src).st_size
        wr_bytes = 0

        def p_cb(n_bytes, _percent, status):
            nonlocal wr_bytes
            if status not in (None, FSCommandStatus.SUCCESS.code):
                _raise_exception(status, "Error putting file '%s'" % src)
            wr_bytes += n_bytes
            if progress_cb:
                progress_cb(wr_bytes * 100.0 / f_size, dst_path, src)

        # Create intermediate directories if required
        dest_parent = os.path.dirname(dst_path)
        if mk_parents and dest_parent != "/flash":
            self.make_directory(dest_parent, mk_parents=True)

        with open(src, "rb+") as src_file:
            wr_opts = []
            if overwrite:
                wr_opts.append("truncate")
            w_proc = self.write_file(dest, offset=WriteFileCmdRequest.USE_CURRENT_OFFSET,
                                     secure=secure, options=wr_opts, progress_cb=p_cb)
            try:
                size = w_proc.block_size
                data = src_file.read(size)
                while data:
                    try:
                        w_proc.next(data, last=False)
                    except FileSystemException as exc:
                        # If write options worked as they are described, we
                        # would not need to remove the file previously
                        # https://jira.digi.com/browse/XBHAWK-531
                        if not overwrite or exc.status != FSCommandStatus.ALREADY_EXISTS.code:
                            raise exc
                        self.remove(dest, rm_children=False)
                        w_proc = self.write_file(dest,
                                                 offset=WriteFileCmdRequest.USE_CURRENT_OFFSET,
                                                 secure=secure, options=wr_opts, progress_cb=p_cb)
                        w_proc.next(data, last=False)
                    data = src_file.read(size)
            finally:
                w_proc.next("", last=True)

        return FileSystemElement(os.path.basename(dst_path), path=dst_path,
                                 is_dir=False, size=os.stat(src).st_size,
                                 is_secure=secure)

    def put_dir(self, src, dest="/flash", verify=True, progress_cb=None):
        """
        Uploads the given source directory contents into the given destination
        directory in the XBee.

        Args:
            src (String): Local directory to upload its contents.
            dest (:class:`.FileSystemElement` or String): The destination dir
                in the XBee or its absolute path. Defaults to '/flash'.
            verify (Boolean, optional, default=`True`): `True` to check the
                hash of the uploaded content.
            progress_cb (Function, optional): Function call when data is being
                uploaded. Receives three argument:

                    * The progress percentage as float.
                    * Destination file path.
                    * The absolute path of the local being uploaded as string.
        Raises:
            FileSystemException: If there is any error performing the operation
                and `progress_cb` is `None`.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(src, str):
            raise ValueError("Source path must be a non-empty string")

        if isinstance(dest, FileSystemElement):
            if not dest.is_dir:
                raise ValueError("Destination must be a directory")
            dest_path = dest.path
        elif isinstance(dest, str):
            dest_path = dest
        elif not dest:
            dest_path = "/flash"
        else:
            raise ValueError("Destination must be string or a FileSystemElement")

        # Create destination directory
        if dest_path != "/flash":
            self.make_directory(dest_path, mk_parents=True)

        # Upload directory contents
        for file in listdir(src):
            src_file_path = os.path.join(src, file)
            dst_file_path = os.path.join(dest_path, file)
            if isfile(src_file_path):
                self.put_file(src_file_path, dst_file_path, overwrite=True,
                              mk_parents=True, progress_cb=progress_cb)
                if not verify:
                    continue
                xb_hash = self.get_file_hash(dst_file_path)
                local_hash = get_local_file_hash(src_file_path)
                if xb_hash == local_hash:
                    continue
                msg = "Error uploading file '%s': Local hash different from " \
                      "remote hash (%s != %s)" % \
                      (src_file_path, utils.hex_to_string(local_hash, pretty=False),
                       utils.hex_to_string(xb_hash, pretty=False))
                _log.error(msg)
                _raise_exception(None, msg)
            else:
                self.put_dir(src_file_path, dst_file_path, progress_cb=progress_cb)

    def get_file_hash(self, file, timeout=DEFAULT_TIMEOUT):
        """
        Returns the SHA256 hash of the given file.

        Args:
            file (:class:`.FileSystemElement` or String): File to get its hash
                or its absolute path.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Bytearray: SHA256 hash of the given file.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(file, (str, FileSystemElement)):
            raise ValueError("File must be a string or a FileSystemElement")
        if isinstance(file, FileSystemElement):
            if not file.is_dir:
                raise ValueError("Cannot hash a directory")
            if file.path in ("/", "\\", ".", ".."):
                raise ValueError("Invalid file path")
        if isinstance(file, str) and file in ("/", "\\", ".", ".."):
            raise ValueError("Invalid file path")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path_id = 0
        file_path = file
        if isinstance(file, FileSystemElement):
            file_path = file.path
        file_path = os.path.normpath(file_path.replace('\\', '/'))

        _log.debug(self._log_str("Retrieving SHA256 hash of '%s'", file_path))

        start = time.time()

        try:
            # Check length of path, if is too big try to change to a parent
            path_id, to_hash = self._cd_to_execute(file_path, path_id, timeout)

            status, hash_val = self.pget_file_hash(
                to_hash, path_id=path_id, timeout=(timeout - (time.time() - start)))
        finally:
            if path_id:
                self.prelease_path_id(path_id, timeout)

        if status != FSCommandStatus.SUCCESS.code:
            _raise_exception(status,
                             "Error getting hash of file '%s'" % file_path)

        return hash_val

    def move(self, source, dest, timeout=DEFAULT_TIMEOUT):
        """
        Moves the given source element to the given destination path.

        Args:
            source (:class:`.FileSystemElement` or String): Source entry to move.
            dest (String): Destination path of the element to move.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum number
                of seconds to wait for the operation completion.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.
        """
        if not isinstance(source, (str, FileSystemElement)):
            raise ValueError("Source must be a string or a FileSystemElement")
        if not isinstance(dest, str) or not dest:
            raise ValueError("Destination must be a non-empty string")
        src_path = source
        if isinstance(source, FileSystemElement):
            src_path = source.path
        if src_path in ("/", "\\", ".", ".."):
            raise ValueError("Invalid source path")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path_id = 0
        src_path = os.path.normpath(src_path.replace('\\', '/'))
        dst_path = os.path.normpath(src_path.replace('\\', '/'))
        common_dir = os.path.normpath(os.path.commonprefix([src_path, dst_path]))

        _log.debug(self._log_str("Moving '%s' to '%s' (path id: %d)", src_path,
                                 dst_path, path_id))

        start = time.time()

        # Change to a common directory
        if common_dir not in ('.', '/'):
            status, path_id, _f_path = self.pget_path_id(
                common_dir, path_id=path_id, timeout=timeout)
            if status != FSCommandStatus.SUCCESS.code:
                _raise_exception(status,
                                 "Error changing to directory '%s'" % common_dir)

            src_path = os.path.relpath(src_path, common_dir)
            dst_path = os.path.relpath(dst_path, common_dir)

        status = self.prename(src_path, dst_path, path_id=path_id,
                              timeout=(timeout - (time.time() - start)))
        if path_id:
            self.prelease_path_id(path_id, timeout)

        if status != FSCommandStatus.SUCCESS.code:
            _raise_exception(
                status, "Error moving file '%s' to '%s'" % (src_path, dst_path))

    def get_volume_info(self, vol="/flash", timeout=DEFAULT_TIMEOUT):
        """
        Returns the file system volume information.
        Currently '/flash' is the only supported value.

        Args:
            vol (:class:`.FileSystemElement`or String, optional, default=`/flash`): Volume name.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Dictionary: Collection of pair values describing volume information.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(vol, (str, FileSystemElement)):
            raise ValueError("Volume must be a string or a FileSystemElement")

        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        name = vol
        if isinstance(vol, FileSystemElement):
            name = vol.path
        name = os.path.normpath(name.replace('\\', '/'))

        _log.info(self._log_str("Reading volume information '%s'", name))

        to_send = FileSystemManager._create_fs_frame(self.__xbee,
                                                     VolStatCmdRequest(name))

        sender = _FSFrameSender(self.__xbee)
        status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        if status != FSCommandStatus.SUCCESS.code:
            _raise_exception(status, "Error getting volume info '%s'" % name)

        _log.info(self._log_str(
            "Volume info '%s': %s (used), %s (free), %s (bad)",
            name, r_cmd.bytes_used, r_cmd.bytes_free, r_cmd.bytes_bad))

        return {"used": r_cmd.bytes_used,
                "free": r_cmd.bytes_free,
                "bad": r_cmd.bytes_bad}

    def format(self, vol="/flash", timeout=DEFAULT_FORMAT_TIMEOUT):
        """
        Formats provided volume.
        Currently '/flash' is the only supported value.
        Formatting the file system takes time, and any other requests will fail
        until it completes and sends a response.

        Args:
            vol (:class:`.FileSystemElement`or String, optional, default=`/flash`): Volume name.
            timeout (Float, optional, default=`DEFAULT_FORMAT_TIMEOUT`):
                Maximum number Of seconds to wait for the operation completion.

        Returns:
            Dictionary: Collection of pair values describing volume information.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(vol, (str, FileSystemElement)):
            raise ValueError("Volume must be a string or a FileSystemElement")

        if not isinstance(timeout, int):
            timeout = self.DEFAULT_FORMAT_TIMEOUT

        # Sanitize path
        name = vol
        if isinstance(vol, FileSystemElement):
            name = vol.path
        name = os.path.normpath(name.replace('\\', '/'))

        _log.info(self._log_str("Formatting volume '%s'", name))

        to_send = FileSystemManager._create_fs_frame(self.__xbee,
                                                     VolFormatCmdRequest(name))

        sender = _FSFrameSender(self.__xbee)
        status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        if status != FSCommandStatus.SUCCESS.code:
            _raise_exception(status, "Error formatting volume '%s'" % name)

        _log.info(self._log_str(
            "After format, volume info '%s': %s (used), %s (free), %s (bad)",
            name, r_cmd.bytes_used, r_cmd.bytes_free, r_cmd.bytes_bad))

        return {"used": r_cmd.bytes_used,
                "free": r_cmd.bytes_free,
                "bad": r_cmd.bytes_bad}

    def pget_path_id(self, dir_path, path_id=0, timeout=DEFAULT_TIMEOUT):
        """
        Returns the directory path id of the given path. Returned directory
        path id expires if not referenced in 2 minutes.

        Args:
            dir_path (String): Path of the directory to get its id. It is
                relative to the directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Tuple (Integer, Integer, String): Status of the file system command
                execution, new directory path id (-1 if status is not 0) and
                its absolute path (empty if status is not 0). The full path
                may be `None` or empty if it is too long and exceeds the
                communication frames length.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(dir_path, str):
            raise ValueError("Directory path must be a non empty string")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        if dir_path not in (".", ".."):
            dir_path = os.path.normpath(dir_path.replace('\\', '/'))

        _log.info(self._log_str("Getting ID of directory '%s' (path id: %d)",
                                dir_path, path_id))

        # Check length of path, if is too big try to change to a parent
        to_cd = self._get_fit_parent_path(dir_path)

        # Change to directory
        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, GetPathIdCmdRequest(path_id, to_cd))
        sender = _FSFrameSender(self.__xbee)
        status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)
        if status != FSCommandStatus.SUCCESS.code:
            return status, -1, ""

        f_id = r_cmd.fs_id
        f_path = r_cmd.full_path

        # If we changed to a parent dir, change now to the final dir
        if len(dir_path) > len(to_cd):
            rel_path = os.path.relpath(dir_path, to_cd)
            status, f_id, f_path = self.pget_path_id(rel_path, path_id=f_id,
                                                     timeout=timeout)
            if status != FSCommandStatus.SUCCESS.code:
                return status, -1, ""

        _log.info(self._log_str("Path id '%d' (%s)", f_id, f_path))

        return status, f_id, f_path

    def pmake_directory(self, dir_path, path_id=0, timeout=DEFAULT_TIMEOUT):
        """
        Creates the provided directory. Parent directories of the one to be
        created must exist. Separate requests must be dane to make intermediate
        directories.

        Args:
            dir_path (String): Path of the new directory to create. It is
                relative to the directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion. If
                `mk_parents` this is the timeout per directory creation.

        Returns:
            Integer: Status of the file system command execution
                (see :class:`.FSCommandStatus`).

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(dir_path, str):
            raise ValueError("Directory path must be a non empty string")
        if dir_path in ("/", "\\", ".", ".."):
            raise ValueError("Invalid directory path")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path = PurePosixPath(os.path.normpath(dir_path.replace('\\', '/')))

        _log.info(self._log_str("Creating directory '%s' (path id: %d)",
                                str(path), path_id))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, CreateDirCmdRequest(path_id, str(path)))

        sender = _FSFrameSender(self.__xbee)
        rv_status, _r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        return rv_status

    def plist_directory(self, dir_path, path_id=0, timeout=DEFAULT_TIMEOUT):
        """
        Lists the contents of the given directory.

        Args:
            dir_path (String): Path of the directory to list. It is relative to
                the directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Tuple (Integer, List): Status of the file system command execution
                and a list of `:class:`.FilesystemElement` objects contained in
                the given directory, empty list if status is not 0.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(dir_path, str):
            raise ValueError("Directory path must be a non empty string")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        if dir_path not in (".", ".."):
            dir_path = os.path.normpath(dir_path.replace('\\', '/'))

        _log.info(self._log_str("Listing directory '%s' (path id: %d)",
                                dir_path, path_id))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, OpenDirCmdRequest(path_id, dir_path))

        sender = _FSFrameSender(self.__xbee)
        start = time.time()
        rv_status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        if rv_status != FSCommandStatus.SUCCESS.code:
            return rv_status, []

        dir_list = r_cmd.fs_entries
        while not r_cmd.is_last:
            to_send = FileSystemManager._create_fs_frame(
                self.__xbee, ReadDirCmdRequest(r_cmd.fs_id))
            rv_status, r_cmd, _rv_opts = sender.send(
                to_send, timeout=(timeout - (time.time() - start)))
            if rv_status != FSCommandStatus.SUCCESS.code:
                # Try to close the directory
                to_send = FileSystemManager._create_fs_frame(
                    self.__xbee, CloseDirCmdRequest(r_cmd.fs_id))
                sender.send(to_send,
                            timeout=(timeout - (time.time() - start)))
                return rv_status, []
            dir_list += r_cmd.fs_entries

        # This will store the path relative to the directory path id
        for entry in dir_list:
            entry.path = os.path.join(dir_path.replace('\\', '/'), entry.name)

        _log.info(self._log_str("List directory '%s' (%d):\n%s", dir_path,
                                path_id, '\n'.join(map(str, dir_list))))

        return rv_status, dir_list

    def premove(self, entry_path, path_id=0, timeout=DEFAULT_TIMEOUT):
        """
        Removes the given file system entry.

        All files in a directory must be deleted before removing the directory.
        On XBee 3 802.15.4, DigiMesh, and Zigbee, deleted files are marked as
        as unusable space unless they are at the "end" of the file system
        (most-recently created). On these products, deleting a file triggers
        recovery of any deleted file space at the end of the file system, and
        can lead to a delayed response.

        Args:
            entry_path (String): Path of the entry to remove. It is relative to
                the directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Integer: Status of the file system command execution
                (see :class:`.FSCommandStatus`).

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(entry_path, str):
            raise ValueError("Entry path must be a non empty string")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        if entry_path not in (".", ".."):
            entry_path = os.path.normpath(entry_path.replace('\\', '/'))

        _log.info(self._log_str("Removing entry '%s' (path id: %d)", entry_path,
                                path_id))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, DeleteCmdRequest(path_id, entry_path))

        sender = _FSFrameSender(self.__xbee)
        rv_status, _r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        return rv_status

    def popen_file(self, file_path, path_id=0,
                   options=FileOpenRequestOption.READ, timeout=DEFAULT_TIMEOUT):
        """
        Open a file for reading and/or writing. Use the
        `FileOpenRequestOption.SECURE` (0x80) bitmask for options to upload a
        write-only file (one that cannot be downloaded or viewed), useful for
        protecting files on the device.
        Returned file id expires if not referenced in 2 minutes.

        Args:
            file_path (String): Path of the file to open. It is relative to the
                directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            options (Integer, optional, default=`FileOpenRequestOption.READ`):
                Bitmask that specifies the options to open the file. It defaults
                to `FileOpenRequestOption.READ` which means open for reading.
                See :class:`.FileOpenRequestOption` for more options.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Tuple (Integer, Integer, Integer): Status of the file system
                command execution (see :class:`.FSCommandStatus`), the file id
                to use in later requests, and the size of the file (in bytes),
                0xFFFFFFFF if unknown.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileOpenRequestOption`
           | :class:`.FSCommandStatus`
           | :meth:`.pclose_file`
        """
        if not isinstance(file_path, str):
            raise ValueError("File path must be a string")
        if file_path in ("/", "\\", ".", ".."):
            raise ValueError("Invalid file path")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not options:
            options = FileOpenRequestOption.READ
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        path = PurePosixPath(os.path.normpath(file_path.replace('\\', '/')))

        _log.info(self._log_str("Opening file '%s' (path id: %d) options: 0x%0.2X",
                                str(path), path_id, options))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, OpenFileCmdRequest(path_id, str(path), options))

        sender = _FSFrameSender(self.__xbee)
        rv_status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        _log.info(self._log_str("File open '%s' (%d) options 0x%0.2X",
                                str(path), path_id, options))

        return rv_status, r_cmd.fs_id, r_cmd.size

    def pclose_file(self, file_id, timeout=DEFAULT_TIMEOUT):
        """
        Closes an open file and releases its file handle.

        Args:
            file_id (Integer): File id returned when opening.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Integer: Status of the file system command execution
                (see :class:`.FSCommandStatus`).

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
           | :meth:`.popen_file`
        """
        if not isinstance(file_id, int):
            raise ValueError("File id must be an integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        _log.info(self._log_str("Closing file '%d'", file_id))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, CloseFileCmdRequest(file_id))

        sender = _FSFrameSender(self.__xbee)
        rv_status, _r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        _log.info(self._log_str("File closed (%d)", file_id))

        return rv_status

    def pread_file(self, file_id, offset=-1, size=-1, timeout=DEFAULT_TIMEOUT):
        """
        Reads from the provided file the given amount of bytes starting at the
        given offset. The file must be opened for reading first.

        Args:
            file_id (Integer): File id returned when opening.
            offset (Integer, optional, default=-1): File offset to start reading.
                -1 to use current position.
            size (Integer, optional, default=-1): Number of bytes to read.
                -1 to read as many as possible.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Tuple (Integer, Integer, Integer, Bytearray): Status of the file
                system command execution (see :class:`.FSCommandStatus`), the
                file id, the offset of the read data, and the read data.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
           | :meth:`.popen_file`
        """
        if not isinstance(file_id, int):
            raise ValueError("File id must be an integer")
        if offset is not None and not isinstance(offset, int) or offset < -1:
            raise ValueError("Offset must be -1 or greater")
        if not isinstance(size, int) or not size or size < -1:
            raise ValueError("Size must be -1 or greater than 0")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        _log.info(self._log_str("Reading file '%d' (offset: %d, size: %d)",
                                file_id, offset, size))

        if offset == -1:
            offset = ReadFileCmdRequest.USE_CURRENT_OFFSET
        if size == -1:
            size = ReadFileCmdRequest.READ_AS_MANY

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, ReadFileCmdRequest(file_id, offset, size))

        sender = _FSFrameSender(self.__xbee)
        rv_status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        _log.info(self._log_str("Read %d bytes from '%d' (offset: %d)",
                                len(r_cmd.data), file_id, r_cmd.offset))

        return rv_status, r_cmd.fs_id, r_cmd.offset, r_cmd.data

    def pwrite_file(self, file_id, data, offset=-1, timeout=DEFAULT_TIMEOUT):
        """
        Writes to the provided file the given data bytes starting at the given
        offset. The file must be opened for writing first.

        Args:
            file_id (Integer): File id returned when opening.
            data (Bytearray, bytes or String): Data to write.
            offset (Integer, optional, default=-1): File offset to start writing.
                -1 to use current position.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Tuple (Integer, Integer, Integer): Status of the file system
                command execution (see :class:`.FSCommandStatus`), the file id,
                and the current offset after writing.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
           | :meth:`.popen_file`
        """
        if not isinstance(file_id, int):
            raise ValueError("File id must be an integer")
        if not isinstance(data, (bytearray, bytes, str)):
            raise ValueError("Data must be a bytearray, bytes or a string")
        if not data:
            raise ValueError("Data cannot be empty")
        if offset is not None and not isinstance(offset, int) or offset < -1:
            raise ValueError("Offset must be -1 or greater")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        if isinstance(data, str):
            data = bytearray(data, encoding='utf8')
        elif isinstance(data, bytes):
            data = bytearray(data)

        _log.info(self._log_str("Writing to file '%d' (offset: %d, size: %d)",
                                file_id, offset, len(data)))

        if offset == -1:
            offset = ReadFileCmdRequest.USE_CURRENT_OFFSET

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, WriteFileCmdRequest(file_id, offset, data=data))

        sender = _FSFrameSender(self.__xbee)
        rv_status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        if rv_status == FSCommandStatus.SUCCESS.code:
            _log.info(self._log_str("Written %d bytes to '%d' (offset: %d)",
                                    len(data), file_id, r_cmd.actual_offset))

        return rv_status, r_cmd.fs_id, r_cmd.actual_offset

    def pget_file_hash(self, file_path, path_id=0, timeout=DEFAULT_TIMEOUT):
        """
        Returns the SHA256 hash of the given file.

        Args:
            file_path (String): Path of the file to get its hash. It is
                relative to the directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Tuple (Integer, Bytearray): Status of the file system command
                execution and SHA256 hash of the given file (empty bytearray if
                status is not 0).

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(file_path, str):
            raise ValueError("File path must be a non empty string")
        if file_path in ("/", "\\", ".", ".."):
            raise ValueError("Invalid file path")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        file_path = os.path.normpath(file_path.replace('\\', '/'))

        _log.info(self._log_str("Retrieving SHA256 hash of '%s' (path id: %d)",
                                file_path, path_id))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, HashFileCmdRequest(path_id, file_path))

        sender = _FSFrameSender(self.__xbee)
        rv_status, r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        if rv_status != FSCommandStatus.SUCCESS.code:
            return rv_status, bytearray()

        _log.info(self._log_str("'%s' hash: %s", file_path,
                                utils.hex_to_string(r_cmd.file_hash, pretty=False)))

        return rv_status, r_cmd.file_hash

    def prename(self, current_path, new_path, path_id=0, timeout=DEFAULT_TIMEOUT):
        """
        Rename provided file.

        Args:
            current_path (String): Current path name. It is relative to the
                directory path id.
            new_path (String): New name. It is relative to the directory path id.
            path_id (Integer, optional, default=0): Directory path id. 0 for
                the root directory.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Integer: Status of the file system command execution
                (see :class:`.FSCommandStatus`).

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(current_path, str):
            raise ValueError("Current path name must be a non empty string")
        if not isinstance(new_path, str):
            raise ValueError("New path name must be a non empty string")
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        # Sanitize path
        if current_path not in (".", ".."):
            current_path = os.path.normpath(current_path.replace('\\', '/'))
        if new_path not in (".", ".."):
            new_path = os.path.normpath(new_path.replace('\\', '/'))

        _log.info(self._log_str("Renaming entry '%s' to '%s' (path id: %d)",
                                current_path, new_path, path_id))

        to_send = FileSystemManager._create_fs_frame(
            self.__xbee, RenameCmdRequest(path_id, current_path, new_path))

        sender = _FSFrameSender(self.__xbee)
        rv_status, _r_cmd, _rv_opts = sender.send(to_send, timeout=timeout)

        return rv_status

    def prelease_path_id(self, path_id, timeout=DEFAULT_TIMEOUT):
        """
        Releases the provided directory path id.

        Args:
            path_id (Integer): Directory path id to release.
            timeout (Float, optional, default=`DEFAULT_TIMEOUT`): Maximum
                number of seconds to wait for the operation completion.

        Returns:
            Integer: Status of the file system command execution.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCommandStatus`
        """
        if not isinstance(path_id, int) or path_id < 0:
            raise ValueError("Directory path id must be a positive integer")
        if not isinstance(timeout, int):
            timeout = self.DEFAULT_TIMEOUT

        status, _, _ = self.pget_path_id("/", path_id=path_id, timeout=timeout)
        if status != FSCommandStatus.SUCCESS.code:
            _log.error(self._log_str("Error releasing path id '%d'", path_id))

        return status

    def _cd_to_execute(self, path, path_id, timeout, refresh=True):
        """
        Changes to another directory in path if its longer than the allowed
        length for the frame transmission.

        Args:
            path (String): The path to check and to use for changing.
            path_id (Integer): Current directory path id.
            timeout (Float): Maximum number of seconds to wait for the
                operation completion.
            refresh (Boolean, optional, default=`True`): `True` to read the
                NP value of the local XBee, `False` to use the cached one.

        Returns:
             Tuple (Integer, String): The new directory path id and the
                relative path of given path to that new directory path id.

        Raises:
            FileSystemException: If there is any error performing the operation
                or the function is not supported.
        """
        max_len = self._get_np(refresh=refresh)
        if not max_len:
            max_len = _DEFAULT_BLOCK_SIZE
        if len(path) <= max_len:
            return path_id, path

        rel_path = path
        start = time.time()
        while len(rel_path) > max_len:
            to_cd = self._get_fit_parent_path(rel_path)
            rel_path = os.path.relpath(rel_path, to_cd)
            status, path_id, _f_path = self.pget_path_id(
                to_cd, path_id=path_id, timeout=(timeout - (time.time() - start)))
            if status != FSCommandStatus.SUCCESS.code:
                _raise_exception(status,
                                 "Error changing to directory '%s'" % to_cd)

        return path_id, rel_path

    def _get_np(self, refresh=False):
        """
        Returns the 'NP' value of the local XBee.

        Args:
            refresh (Boolean, optional, default=`False`): `True` to read the
                NP value of the local XBee, `False` to use the cached one.

        Returns:
             Integer: 'NP' value.
        """
        if self.__np_val and not refresh:
            return self.__np_val
        # Cellular devices do not have NP setting.
        if self.__xbee.get_protocol() == XBeeProtocol.CELLULAR:
            self.__np_val = _DEFAULT_BLOCK_SIZE_CELLULAR
            return self.__np_val

        xbee = self.__xbee
        n_extra_bytes = 0
        if xbee.is_remote():
            xbee = xbee.get_local_xbee_device()
            # 64-bit address (8), send/receive opts (1), and status (1) length
            n_extra_bytes = 10

        cmd = ATStringCommand.NP
        try:
            # Reserve 5 bytes for other frame data
            self.__np_val = utils.bytes_to_int(xbee.get_parameter(cmd, apply=False)) - 5
            # Subtract extra bytes of remote frames
            self.__np_val -= n_extra_bytes
        except XBeeException as exc:
            _log.error(self._log_str(
                "Error getting maximum number of transmission bytes ('%s'): %s",
                cmd, str(exc)))
            self.__np_val = 0

        return self.__np_val

    def _get_fit_parent_path(self, path, refresh=False):
        """
        Returns a parent which length fits the maximum allowed size.

        Args:
            path (String): Path to get a fit parent.
            refresh (Boolean, optional, default=`False`): `True` to read the
                NP value of the local XBee, `False` to use the cached one.

        Returns:
            String: The path that fits the maximum allowed size.
        """
        np_val = self._get_np(refresh=refresh)
        if not np_val:
            np_val = _DEFAULT_BLOCK_SIZE
        if len(path) <= np_val:
            return path

        # Reduce the path until is less than 'NP'
        path = PurePosixPath(path)
        for parent in path.parents:
            if len(str(parent)) <= np_val:
                return str(parent)

        return path

    @staticmethod
    def _create_fs_frame(xbee, cmd, transmit_options=TransmitOptions.NONE.value):
        """
        Creates a local or remote File System Request packet.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): The destination XBee.
            cmd (:class:`.FSCmd` or Bytearray): The command to send.
            transmit_options (Integer, optional, default=`TransmitOptions.NONE.value`):
                Options to transmit the packet if `xbee` is remote.

        Returns:
            :class:`.XBeeAPIPacket`: class:`.FSRequestPacket` or
                class:`.RemoteFSRequestPacket` already formed.

        Raises:
            ValueError: If `xbee` or `cmd` are invalid.
        """
        from digi.xbee.devices import AbstractXBeeDevice
        if not isinstance(xbee, AbstractXBeeDevice):
            raise ValueError("XBee must be a local or remote XBee class")
        if not isinstance(cmd, (bytearray, FSCmd)):
            raise ValueError("Command must be a bytearray or a FSCmd")

        if xbee.is_remote():
            if xbee.get_protocol() in (XBeeProtocol.DIGI_MESH, XBeeProtocol.SX):
                transmit_options |= TransmitOptions.DIGIMESH_MODE.value
            elif xbee.get_protocol() == XBeeProtocol.DIGI_POINT:
                transmit_options |= TransmitOptions.POINT_MULTIPOINT_MODE.value

            return RemoteFSRequestPacket(
                xbee.get_local_xbee_device().get_next_frame_id(),
                xbee.get_64bit_addr(), cmd, transmit_options=transmit_options)

        return FSRequestPacket(xbee.get_next_frame_id(), cmd)

    def _log_str(self, msg, *args):
        return "%s: %s" % (str(self), msg % args)


class LocalXBeeFileSystemManager:
    """
    Helper class used to manage the local XBee file system.
    """

    def __init__(self, xbee_device):
        """
        Class constructor. Instantiates a new
        :class:`.LocalXBeeFileSystemManager` with the given parameters.

        Args:
            xbee_device (:class:`.XBeeDevice`): The local XBee to manage its
                file system.
        """
        if not xbee_device.serial_port:
            raise OperationNotSupportedException(
                message="Only supported in local XBee connected by serial.")

        # Check target compatibility.
        if not check_fs_support(xbee_device,
                                max_fw_vers=XB3_MAX_FW_VERSION_FS_OTA_SUPPORT):
            raise FileSystemNotSupportedException(
                "LocalXBeeFileSystemManager is not supported, use FileSystemManager")

        self._xbee_device = xbee_device
        self._serial_port = xbee_device.serial_port
        self._supported_functions = []
        self._device_was_connected = False
        self._is_connected = False
        self._old_read_timeout = _READ_PORT_TIMEOUT

    def _read_data(self, timeout=_READ_DATA_TIMEOUT,
                   empty_retries=_READ_EMPTY_DATA_RETRIES_DEFAULT):
        """
        Reads data from the serial port waiting for the provided timeout.

        Args:
            timeout (Integer, optional): The maximum time to wait for data
                (seconds). Defaults to 1 second.
            empty_retries (Integer, optional): The number of consecutive
                zero-bytes read before considering no more data is available.

        Returns:
            String: The read data as string.

        Raises:
            SerialException: If there is any problem reading data from the
                serial port.
        """
        answer_string = ""
        empty_attempts = 0
        deadline = _get_milliseconds() + (timeout * 1000)
        read_bytes = self._serial_port.read(_READ_BUFFER)
        while ((len(answer_string) == 0 or empty_attempts < empty_retries)
               and _get_milliseconds() < deadline):
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
            Boolean: `True` if the AT command mode is active, `False` otherwise.
        """
        _log.debug("Checking AT command mode...")
        try:
            self._serial_port.write(str.encode(_COMMAND_AT, encoding='utf8'))
            answer = self._read_data(timeout=_GUARD_TIME)

            return answer is not None and _COMMAND_MODE_ANSWER_OK in answer
        except SerialException as exc:
            _log.exception(exc)
            return False

    def _enter_atcmd_mode(self):
        """
        Enters in AT command mode.

        Returns:
             Boolean: `True` if entered command mode successfully, `False`
                otherwise.
        """
        _log.debug("Entering AT command mode...")
        try:
            # In some scenarios where the read buffer is constantly being
            # filled with remote data, it is almost impossible to read the
            # 'enter command mode' answer, so purge port before.
            self._serial_port.purge_port()
            for _ in range(3):
                self._serial_port.write(str.encode(_COMMAND_MODE_CHAR,
                                                   encoding='utf8'))
            answer = self._read_data(timeout=_GUARD_TIME,
                                     empty_retries=_READ_EMPTY_DATA_RETRIES)

            return answer is not None and _COMMAND_MODE_ANSWER_OK in answer
        except SerialException as exc:
            _log.exception(exc)
            return False

    def _exit_atcmd_mode(self):
        """
        Exits from AT command mode.
        """
        _log.debug("Exiting AT command mode...")
        try:
            self._serial_port.write(str.encode(_COMMAND_MODE_EXIT, encoding='utf8'))
        except SerialException as exc:
            _log.exception(exc)
        finally:
            # It is necessary to wait the guard time before sending data again
            time.sleep(_GUARD_TIME)

    def _check_atcmd_mode(self):
        """
        Checks whether AT command mode is active and if not tries to enter AT
        command mode.

        Returns:
             Boolean: `True` if AT command mode is active or entered
                successfully, `False` otherwise.
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
             Boolean: `True` if the device supports file system, `False` otherwise.
        """
        _log.debug("Checking if device supports file system...")
        if not self._check_atcmd_mode():
            return False

        try:
            self._serial_port.write(str.encode(_COMMAND_FILE_SYSTEM, encoding='utf8'))
            answer = self._read_data()
            if answer and _ANSWER_ATFS in answer.upper():
                self._parse_filesystem_functions(answer.replace("\r", ""))
                return True

            return False
        except SerialException as exc:
            _log.exception(exc)
            return False

    def _parse_filesystem_functions(self, filesystem_answer):
        """
        Parses the file system command response to obtain a list of supported
        file system functions.

        Args:
            filesystem_answer (String): The file system command answer to parse.
        """
        result = re.match(_PATTERN_FILE_SYSTEM_FUNCTIONS, filesystem_answer,
                          flags=re.M | re.DOTALL)
        if result is None or result.string is not result.group(0) or len(result.groups()) < 1:
            return

        self._supported_functions = result.groups()[0].split(_FUNCTIONS_SEPARATOR)

    def _is_function_supported(self, function):
        """
        Returns whether the specified file system function is supported or not.

        Args:
            function (:class:`._FilesystemFunction`): The file system function
                to check.

        Returns:
            Boolean: `True` if the specified file system function is supported,
                `False` otherwise.
        """
        if not isinstance(function, _FilesystemFunction):
            return False

        return function.cmd_name in self._supported_functions

    @staticmethod
    def _check_function_error(answer, command):
        """
        Checks the given file system command answer and throws an exception if
        it contains an error.

        Args:
            answer (String): The file system command answer to check for errors.
            command (String): The file system command executed.

        Raises:
            FileSystemException: If any error is found in the answer.
        """
        result = re.match(_PATTERN_FILE_SYSTEM_ERROR, answer, flags=re.M | re.DOTALL)
        if result is not None and len(result.groups()) > 1:
            if len(result.groups()) > 2:
                raise FileSystemException(
                    _ERROR_EXECUTE_COMMAND % (
                        command.replace("\r", ""),
                        result.groups()[1] + " >" + result.groups()[2]))

            raise FileSystemException(_ERROR_EXECUTE_COMMAND % (
                command.replace("\r", ""), result.groups()[1]))

    def _xmodem_write_cb(self, data):
        """
        Callback function used to write data to the serial port when requested
        from the XModem transfer.

        Args:
            data (Bytearray): The data to write to serial port from the XModem
                transfer.

        Returns:
            Boolean: `True` if the data was successfully written, `False`
                otherwise.
        """
        try:
            self._serial_port.purge_port()
            self._serial_port.write(data)
            self._serial_port.flush()
            return True
        except SerialException as exc:
            _log.exception(exc)

        return False

    def _xmodem_read_cb(self, size, timeout=_READ_DATA_TIMEOUT):
        """
        Callback function used to read data from the serial port when
        requested from the XModem transfer.

        Args:
            size (Integer): Size of the data to read.
            timeout (Integer, optional): Maximum time to wait to read the
                requested data (seconds).

        Returns:
            Bytearray: the read data, `None` if data could not be read.
        """
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

    def _execute_command(self, cmd_type, *args, wait_for_answer=True):
        """
        Executes the given command type with its arguments.

        Args:
            cmd_type (:class:`._FilesystemFunction`): Command type to execute.
            args (): Command arguments
            wait_for_answer (Boolean): `True` to wait for command answer,
                `False` otherwise.

        Returns:
            String: the command answer.

        Raises:
            FileSystemException: If there is any error executing the command.
        """
        # Sanity checks.
        if not self._is_function_supported(cmd_type):
            raise FileSystemException(_ERROR_FUNCTION_NOT_SUPPORTED % cmd_type.cmd_name)
        if not self._check_atcmd_mode():
            raise FileSystemException(_ERROR_ENTER_CMD_MODE)

        command = _COMMAND_ATFS % (cmd_type.command % args)
        try:
            self._serial_port.write(str.encode(command, encoding='utf8', errors='ignore'))
            answer = None
            if wait_for_answer:
                answer = self._read_data()
                if not answer:
                    raise FileSystemException(_ERROR_TIMEOUT)
                self._check_function_error(answer, command)

            return answer
        except SerialException as exc:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      (command.replace("\r", ""), str(exc))) from None

    @property
    def is_connected(self):
        """
        Returns whether the file system manager is connected or not.

        Returns:
            Boolean: `True` if the file system manager is connected, `False`
                otherwise.
         """
        return self._is_connected

    def connect(self):
        """
        Connects the file system manager.

        Raises:
            FileSystemException: If there is any error connecting the file
                system manager.
            FileSystemNotSupportedException: If the device does not support
                filesystem feature.
        """
        if self._is_connected:
            return

        # The file system manager talks directly with the serial port in raw
        # mode, so disconnect the device. Not disconnecting the device will
        # cause the internal XBee device frame reader to consume the data
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
                raise FileSystemNotSupportedException(ERROR_FILESYSTEM_NOT_SUPPORTED)
        except (SerialException, FileSystemNotSupportedException) as exc:
            # Close port if it is open.
            if self._serial_port.isOpen():
                self._serial_port.close()
            self._is_connected = False

            try:
                # Restore serial port timeout.
                self._serial_port.set_read_timeout(self._old_read_timeout)
            except SerialException:
                # Ignore this error as it is not critical and will not provide
                # much info but confusion.
                pass
            if isinstance(exc, SerialException):
                raise FileSystemException(_ERROR_CONNECT_FILESYSTEM % str(exc)) from None
            raise exc

    def disconnect(self):
        """
        Disconnects the file system manager and restores the device connection.

        Raises:
            XBeeException: If there is any error restoring the XBee connection.
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
             String: Current device directory.

        Raises:
            FileSystemException: If there is any error getting the current
                directory or the function is not supported.
        """
        _log.info("Retrieving working directory")
        return self._execute_command(_FilesystemFunction.PWD).replace("\r", "")

    def change_directory(self, directory):
        """
        Changes the current device working directory to the given one.

        Args:
            directory (String): New directory to change to.

        Returns:
             String: Current device working directory after the directory change.

        Raises:
            FileSystemException: If there is any error changing the current
                directory or the function is not supported.
        """
        # Sanity checks.
        if not directory:
            return self.get_current_directory()

        # Sanitize path.
        directory = directory.replace('\\', '/')

        _log.info("Navigating to directory '%s'", directory)
        return self._execute_command(_FilesystemFunction.CD, directory).replace("\r", "")

    def make_directory(self, directory):
        """
        Creates the provided directory.

        Args:
            directory (String): New directory to create.

        Raises:
            FileSystemException: If there is any error creating the directory
                or the function is not supported.
        """
        # Sanity checks.
        if not directory or directory == "/" or directory == "\\":
            return

        # Sanitize path.
        directory = directory.replace('\\', '/')

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
                    _log.info("Creating directory '%s'", temp_path)
                    self._execute_command(_FilesystemFunction.MD, temp_path)
        finally:
            self.change_directory(current_dir)

    def list_directory(self, directory=None):
        """
        Lists the contents of the given directory.

        Args:
            directory (String, optional): the directory to list its contents.
                If not provided, the current directory contents are listed.

        Returns:
            List: list of `:class:`.FilesystemElement` objects contained in
                the given (or current) directory.

        Raises:
            FileSystemException: if there is any error listing the directory
                contents or the function is not supported.
        """
        if not directory:
            _log.info("Listing directory contents of current dir")
            answer = self._execute_command(_FilesystemFunction.LS)
        else:
            # Sanitize path.
            directory = directory.replace('\\', '/')
            _log.info("Listing directory contents of '%s'", directory)
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
                filesystem_elements.append(FileSystemElement(
                    name, path + name, is_dir=True,
                    is_secure=name.endswith(_SECURE_ELEMENT_SUFFIX)))
            else:
                result = re.match(_PATTERN_FILE_SYSTEM_FILE, line)
                if result is not None and len(result.groups()) > 1:
                    name = result.groups()[1]
                    size = int(result.groups()[0])
                    filesystem_elements.append(FileSystemElement(
                        name, path + name, size=size,
                        is_secure=name.endswith(_SECURE_ELEMENT_SUFFIX)))
                else:
                    _log.warning("Unknown filesystem element entry: %s", line)

        return filesystem_elements

    def remove_element(self, element_path):
        """
        Removes the given file system element path.

        Args:
            element_path (String): Path of the file system element to remove.

        Raises:
            FileSystemException: If there is any error removing the element or
                the function is not supported.
        """
        # Sanity checks.
        if not element_path:
            return

        # Sanitize path.
        element_path = element_path.replace('\\', '/')

        _log.info("Removing file '%s'", element_path)
        self._execute_command(_FilesystemFunction.RM, element_path)

    def move_element(self, source_path, dest_path):
        """
        Moves the given source element to the given destination path.

        Args:
            source_path (String): Source path of the element to move.
            dest_path (String): Destination path of the element to move.

        Raises:
            FileSystemException: If there is any error moving the element or
                the function is not supported.
        """
        # Sanity checks.
        if not source_path or not dest_path:
            return

        # Sanitize paths.
        source_path = source_path.replace('\\', '/')
        dest_path = dest_path.replace('\\', '/')

        _log.info("Moving file '%s' to '%s'", source_path, dest_path)
        self._execute_command(_FilesystemFunction.MV, source_path, dest_path)

    def put_file(self, source_path, dest_path, secure=False, progress_callback=None):
        """
        Transfers the given file in the specified destination path of the XBee.

        Args:
            source_path (String): the path of the file to transfer.
            dest_path (String): the destination path to put the file in.
            secure (Boolean, optional, default=`False`): `True` if the file
                should be stored securely, `False` otherwise.
            progress_callback (Function, optional): Function to execute to
                receive progress information. Takes the following arguments:

                    * The progress percentage as integer.

        Raises:
            FileSystemException: If there is any error transferring the file or
                the function is not supported.
        """
        # Sanity checks.
        if secure and not self._is_function_supported(_FilesystemFunction.XPUT):
            raise FileSystemException(_ERROR_FUNCTION_NOT_SUPPORTED
                                      % _FilesystemFunction.XPUT.cmd_name)
        if not secure and not self._is_function_supported(_FilesystemFunction.PUT):
            raise FileSystemException(_ERROR_FUNCTION_NOT_SUPPORTED
                                      % _FilesystemFunction.PUT.cmd_name)

        # Sanitize destination path.
        dest_path = dest_path.replace('\\', '/')

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
                if not element.is_dir and element.name == dest_name:
                    self.remove_element(element.path)
                    break

        _log.info("Uploading file '%s' to '%s'", source_path, dest_path)
        command = _COMMAND_ATFS % (_FilesystemFunction.XPUT.command % dest_path) if secure else \
            _COMMAND_ATFS % (_FilesystemFunction.PUT.command % dest_path)
        answer = self._execute_command(_FilesystemFunction.XPUT, dest_path) if secure else \
            self._execute_command(_FilesystemFunction.PUT, dest_path)
        if not answer.endswith(xmodem.XMODEM_CRC):
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      (command.replace("\r", ""),
                                       "Transfer not ready"))
        # Transfer the file.
        try:
            xmodem.send_file_ymodem(
                source_path, self._xmodem_write_cb, self._xmodem_read_cb,
                progress_cb=progress_callback, log=_log)
        except XModemException as exc:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      (command.replace("\r", ""), str(exc))) from None
        # Read operation result.
        answer = self._read_data(timeout=_READ_DATA_TIMEOUT,
                                 empty_retries=_READ_EMPTY_DATA_RETRIES)
        if not answer:
            raise FileSystemException(_ERROR_TIMEOUT)
        self._check_function_error(answer, command)

    def put_dir(self, source_dir, dest_dir=None, progress_callback=None):
        """
        Uploads the given source directory contents into the given destination
        directory in the device.

        Args:
            source_dir (String): Local directory to upload its contents.
            dest_dir (String, optional): Remote directory to upload the
                contents to. Defaults to current directory.
            progress_callback (Function, optional): Function to execute to
                receive progress information. Takes the following arguments:

                    * The file being uploaded as string.
                    * The progress percentage as integer.

        Raises:
            FileSystemException: If there is any error uploading the directory
                or the function is not supported.
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
                    else functools.partial(progress_callback,
                                           *[str(os.path.join(dest_dir, file))])
                self.put_file(str(os.path.join(source_dir, file)),
                              str(os.path.join(dest_dir, file)),
                              progress_callback=bound_callback)
            else:
                self.put_dir(str(os.path.join(source_dir, file)),
                             str(os.path.join(dest_dir, file)),
                             progress_callback=progress_callback)

    def get_file(self, source_path, dest_path, progress_callback=None):
        """
        Downloads the given XBee device file in the specified destination path.

        Args:
            source_path (String): Path of the XBee device file to download.
            dest_path (String): Destination path to store the file in.
            progress_callback (Function, optional): Function to execute to
                receive progress information. Takes the following arguments:

                    * The progress percentage as integer.

        Raises:
            FileSystemException: If there is any error downloading the file or
                the function is not supported.
        """
        command = _COMMAND_ATFS % (_FilesystemFunction.GET.command % source_path)
        # Sanitize path.
        source_path = source_path.replace('\\', '/')
        _log.info("Downloading file '%s' to '%s'", source_path, dest_path)
        self._execute_command(_FilesystemFunction.GET, source_path,
                              wait_for_answer=False)
        try:
            # Consume data until 'NAK' is received.
            deadline = _get_milliseconds() + (_NAK_TIMEOUT * 1000)
            nak_received = False
            while not nak_received and _get_milliseconds() < deadline:
                data = self._xmodem_read_cb(1, timeout=_TRANSFER_TIMEOUT)
                if data and data[0] == xmodem.XMODEM_NAK:
                    nak_received = True
            if not nak_received:
                raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                          (command.replace("\r", ""),
                                           "Transfer not ready"))
        except SerialException as exc:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      (command.replace("\r", ""), str(exc))) from None
        # Receive the file.
        try:
            xmodem.get_file_ymodem(dest_path, self._xmodem_write_cb, self._xmodem_read_cb,
                                   progress_cb=progress_callback, log=_log)
        except XModemException as exc:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      (command.replace("\r", ""), str(exc))) from None
        # Read operation result.
        answer = self._read_data()
        if not answer:
            raise FileSystemException(_ERROR_TIMEOUT)
        self._check_function_error(answer, command)

    def format_filesystem(self):
        """
        Formats the device file system.

        Raises:
            FileSystemException: If there is any error formatting the file system.
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
        except SerialException as exc:
            raise FileSystemException(_ERROR_EXECUTE_COMMAND %
                                      (command.replace("\r", ""), str(exc))) from None

    def get_usage_information(self):
        """
        Returns the file system usage information.

        Returns:
            Dictionary: Collection of pair values describing the usage information.

        Raises:
            FileSystemException: If there is any error retrieving the file
                system usage information.
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
            file_path (String): Path of the file to get its hash.

        Returns:
            String: SHA256 hash of the given file path.

        Raises:
            FileSystemException: If there is any error retrieving the file hash.
        """
        # Sanitize path.
        file_path = file_path.replace('\\', '/')
        _log.info("Retrieving SHA256 hash of file '%s'...", file_path)
        answer = self._execute_command(_FilesystemFunction.HASH, file_path)
        parts = answer.split(_ANSWER_SHA256)
        if len(parts) <= 1:
            raise FileSystemException(
                _ERROR_EXECUTE_COMMAND % (
                    (_COMMAND_ATFS % (_FilesystemFunction.HASH.command %
                                      file_path)).replace("\r", ""),
                    "Invalid hash received"))

        return str.strip(parts[1])


def update_remote_filesystem_image(remote_device, ota_filesystem_file,
                                   max_block_size=0, timeout=None,
                                   progress_callback=None):
    """
    Performs a remote filesystem update operation in the given target.

    Args:
        remote_device (:class:`.RemoteXBeeDevice`): Remote XBee to update its
            filesystem image.
        ota_filesystem_file (String): Path of the OTA filesystem file to upload.
        max_block_size (Integer, optional): Maximum size of the ota block to send.
        timeout (Integer, optional): Timeout to wait for remote frame requests.
        progress_callback (Function, optional): Function to execute to receive
             progress information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

    Raises:
        FileSystemNotSupportedException: If the target does not support
            filesystem update.
        FileSystemException: If there is any error updating the remote
            filesystem image.
    """
    # Import required firmware update components.
    from digi.xbee.firmware import FirmwareUpdateException, update_remote_filesystem

    # Check target compatibility.
    if not check_fs_support(remote_device, max_fw_vers=XB3_MAX_FW_VERSION_FS_OTA_SUPPORT):
        raise FileSystemNotSupportedException(
            "Filesystem image support update is not supported")

    try:
        update_remote_filesystem(
            remote_device, ota_filesystem_file, max_block_size=max_block_size,
            timeout=timeout, progress_callback=progress_callback)
    except FirmwareUpdateException as exc:
        _log.error("ERROR: %s", str(exc))
        raise FileSystemException(str(exc)) from None


def check_fs_support(xbee, min_fw_vers=None, max_fw_vers=None):
    """
    Checks if filesystem API feature is supported.

    Args:
        xbee (:class:`:AbstractXBeeDevice`): The XBee to check.
        min_fw_vers (Dictionary, optional, default=`None`): A dictionary with
            protocol as key, and minimum firmware version with filesystem
            support as value.
        max_fw_vers (Dictionary, optional, default=`None`): A dictionary with
            protocol as key, and maximum firmware version with filesystem
            support as value.

    Returns:
        Boolean: `True` if filesystem is supported, `False` otherwise.
    """
    hw_version = xbee.get_hardware_version()
    fw_version = xbee.get_firmware_version()
    if not hw_version or (not fw_version and (min_fw_vers or max_fw_vers)):
        try:
            xbee.read_device_info(init=True, fire_event=False)
            hw_version = xbee.get_hardware_version()
            fw_version = xbee.get_firmware_version()
        except XBeeException as exc:
            _log.error(
                "Unable to read XBee hardware/firmware version to check "
                "filesystem support: %s", str(exc))

    # Check compatibility
    supported_hw_versions = LOCAL_SUPPORTED_HW_VERSIONS
    if xbee.is_remote():
        supported_hw_versions = REMOTE_SUPPORTED_HW_VERSIONS
    if hw_version and hw_version.code not in supported_hw_versions:
        return False

    if not fw_version:
        return True

    min_fw_version = min_fw_vers.get(xbee.get_protocol(), None) if min_fw_vers else None
    max_fw_version = max_fw_vers.get(xbee.get_protocol(), None) if max_fw_vers else None

    version = utils.bytes_to_int(fw_version)
    if min_fw_version and version < min_fw_version:
        return False
    if max_fw_version and version > max_fw_version:
        return False

    return True


def get_local_file_hash(local_path):
    """
    Returns the SHA256 hash of the given local file.

    Args:
        local_path (String): Absolute path of the file to get its hash.

    Returns:
        Bytearray: SHA256 hash of the given file.
    """
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(local_path, "rb") as file:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)

        return sha256_hash.digest()


def _raise_exception(status, msg):
    st_msg = ""
    if status is not None:
        fs_st = FSCommandStatus.get(status)
        st_msg = ": %s" % str(fs_st) if fs_st else "Unknown status (0x%0.2X)" % status
    raise FileSystemException("%s%s" % (msg, st_msg), fs_status=status)


def _get_milliseconds():
    """
    Returns the current time in milliseconds.

    Returns:
         Integer: Current time in milliseconds.
    """
    return int(time.time() * 1000.0)


def _filter_non_printable(byte_array):
    """
    Filters the non printable characters of the given byte array and returns
    the resulting string.

    Args:
        byte_array (Bytearray): Byte array to filter.

    Return:
        String: Resulting string after filtering non printable characters of
            the byte array.
    """
    return bytes(x for x in byte_array if x in _printable_ascii_bytes).decode(encoding='utf8')
