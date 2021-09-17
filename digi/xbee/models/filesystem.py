# Copyright 2020, 2021 Digi International Inc.
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
from enum import unique, Enum

from digi.xbee.exception import InvalidPacketException
from digi.xbee.models.options import DirResponseFlag
from digi.xbee.models.status import FSCommandStatus
from digi.xbee.packets.base import DictKeys
from digi.xbee.util import utils


@unique
class FSCmdType(Enum):
    """
    This enumeration lists all the available file system commands.

    | Inherited properties:
    |     **name** (String): Name (id) of this FSCmdType.
    |     **value** (String): Value of this FSCmdType.

    """
    FILE_OPEN = (0x01, "Open/create file")
    FILE_CLOSE = (0x02, "Close file")
    FILE_READ = (0x03, "Read file")
    FILE_WRITE = (0x04, "Write file")
    FILE_HASH = (0x08, "File hash")
    DIR_CREATE = (0x10, "Create directory")
    DIR_OPEN = (0x11, "Open directory")
    DIR_CLOSE = (0x12, "Close directory")
    DIR_READ = (0x13, "Read directory")  # List?
    GET_PATH_ID = (0x1C, "Get directory path ID")
    RENAME = (0x21, "Rename")
    DELETE = (0x2F, "Delete")
    STAT = (0x40, "Stat filesystem")
    FORMAT = (0x4F, "Format filesystem")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the file system command element.

        Returns:
            Integer: Code of the file system command element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the file system command element.

        Returns:
            Integer: Description of the file system command element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Retrieves the file system command associated to the given ID.

        Args:
            code (Integer): The code of the file system command to get.

        Returns:
            :class:`.FSCmdType`: The file system command associated to the
                given code or `None` if not found.
        """
        for frame_type in cls:
            if code == frame_type.code:
                return frame_type
        return None

    def __repr__(self):
        return "%s (%d)" % (self.__desc, self.__code)

    def __str__(self):
        return "%s (%d)" % (self.__desc, self.__code)


FSCmdType.__doc__ += utils.doc_enum(FSCmdType)


class FSCmd:
    """
    This class represents a file system command.
    """

    REQUEST = 0
    RESPONSE = 1

    __HASH_SEED = 23

    def __init__(self, cmd_type, direction=REQUEST, status=None):
        """
        Class constructor. Instantiates a new :class:`.FSCmd` object with
        the provided parameters.

        Args:
            cmd_type (:class:`.FSCmdType` or Integer): The command type.
            direction (Integer, optional, default=0): If this command is a
                request (0) or a response (1).
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution. Only for response commands.

        Raises:
            ValueError: If `cmd_type` is not an integer or a :class:`.FSCmdType`.
            ValueError: If `cmd_type` is invalid.

        .. seealso::
           | :class:`.FSCmdType`
        """
        if not isinstance(cmd_type, (FSCmdType, int)):
            raise ValueError(
                "Command type must be an Integer or a FSCmdType, "
                "not {!r}".format(cmd_type.__class__.__name__))

        if direction not in (self.REQUEST, self.RESPONSE):
            raise ValueError("Direction must be 0 or 1")

        if direction == self.RESPONSE:
            if not isinstance(status, (FSCommandStatus, int)):
                raise TypeError("Response status must be FSCommandStatus or int"
                                " not {!r}".format(status.__class__.__name__))
            if isinstance(status, int) and status not in range(0, 256):
                raise ValueError("Status must be between 0 and 255.")

        self._cmd_type = cmd_type
        if isinstance(cmd_type, int):
            self._cmd_type = FSCmdType.get(cmd_type)

        self._dir = direction

        self._status = status
        if isinstance(status, FSCommandStatus):
            self._status = status.code

    def __len__(self):
        """
        Returns the length value of the command. The length is the number of
        bytes.

        Returns:
            Integer: Number of bytes of the command.
        """
        return len(self._get_spec_data()) + 1

    def __str__(self):
        """
        Returns the command information as dictionary.

        Returns:
            Dictionary: The command information.
        """
        return str(self.to_dict())

    def __eq__(self, other):
        """
        Returns whether the given object is equal to this one.

        Args:
            other: The object to compare.

        Returns:
            Boolean: `True` if the objects are equal, `False` otherwise.
        """
        if not isinstance(other, FSCmd):
            return False

        return other.output() == self.output()

    def __hash__(self):
        """
        Returns a hash code value for the object.

        Returns:
            Integer: Hash code value for the object.
        """
        res = self.__HASH_SEED
        for byte in self.output():
            res = 31 * (res + byte)

        return 31 * (res + self._dir)

    @property
    def type(self):
        """
        Returns the command type.

        Returns:
            :class:`.FSCmdType`: The command type.
        """
        return self._cmd_type

    @property
    def direction(self):
        """
        Returns the command direction.

        Returns:
            Integer: 0 for request, 1 for response.
        """
        return self._dir

    @property
    def status(self):
        """
        Returns the file system command response status.

        Returns:
            :class:`.FSCommandStatus`: File system command response status.

        .. seealso::
           | :class:`.FSCommandStatus`
           | :meth:`.FSCmd.status_value`
        """
        return FSCommandStatus.get(self._status)

    @property
    def status_value(self):
        """
        Returns the file system command response status of the packet.

        Returns:
            Integer: File system command response status.

        .. seealso::
           | :meth:`.FSCmd.status`
        """
        return self._status

    def output(self):
        """
        Returns the raw bytearray of this command.

        Returns:
            Bytearray: Raw bytearray of the command.
        """
        frame = self.__build_command(self._get_spec_data())
        return frame

    def to_dict(self):
        """
        Returns a dictionary with all information of the command fields.

        Returns:
            Dictionary: Dictionary with all info of the command fields.
        """
        ret_dict = {DictKeys.FS_CMD: self._cmd_type}
        if self._dir == self.RESPONSE:
            ret_dict.update({DictKeys.STATUS: self._status})
        ret_dict.update(self._get_spec_data_dict())

        return ret_dict

    @classmethod
    def create_cmd(cls, raw, direction=REQUEST):
        """
        Creates a file system command with the given parameters.
        This method ensures that the FSCmd returned is valid and is well
        built (if not exceptions are raised).

        Args:
            raw (Bytearray): Bytearray to create the command.
            direction (Integer, optional, default=0): If this command is a
                request (0) or a response (1).

        Returns:
            :class:`.FSCmd`: The file system command created.

        Raises:
            InvalidPacketException: If something is wrong with `raw` and the
                command cannot be built.
        """
        if not isinstance(raw, bytearray):
            raise InvalidPacketException(message="Raw must be a bytearray")
        if direction == cls.RESPONSE and len(raw) < 2:
            raise InvalidPacketException(
                message="Command bytearray must have, at least, 2 bytes")
        status = raw[1] if direction == cls.RESPONSE else None
        if len(raw) < cls._get_min_len(status=status):
            raise InvalidPacketException(
                message="Command bytearray must have, at least, %d bytes"
                % cls._get_min_len(status=status))

        return FSCmd(raw[0], direction=direction, status=status)

    @staticmethod
    def _get_min_len(status=None):
        """
        Return the minimum length (in bytes) for the command request.

        Args:
            status (Integer): Status of the file system command execution.
                Only for response commands.

        Returns:
            Integer: Minimum number of bytes.
        """
        if status is None:
            return 1

        return 2

    def _get_spec_data(self):
        """
        Returns the specific data of the command as bytearray. This does not
        include the command type.

        Returns:
            Bytearray: The command specific data as bytearray.
        """
        return bytearray()

    def _get_spec_data_dict(self):
        """
        Similar to :meth:`.FSCmd._get_spec_data` but returns the data a
        dictionary.

        Returns:
            Dictionary: The command data fields as dictionary.
        """
        return {}

    def __build_command(self, data):
        """
        Builds a command from the given data.

        Args:
            data (Bytearray): The command data.

        Returns:
            Bytearray: The complete command as bytearray.
        """
        ret = bytearray([self._cmd_type.code])
        if self._dir == self.RESPONSE:
            ret.append(self._status)
        ret += data

        return ret


class UnknownFSCmd(FSCmd):
    """
    This class represents an unknown file system command.
    """

    def __init__(self, raw, direction=FSCmd.REQUEST):
        """
        Class constructor. Instantiates a new :class:`.UnknownFSCmd` object
        with the provided parameters.

        Args:
            raw (Bytearray): Data of the unknown command.
            direction (Integer, optional, default=0): If this command is a
                request (0) or a response (1).

        Raises:
            ValueError: If `data` is not a bytearray, its length is less
                than 3, or the command type is a known one.

        .. seealso::
           | :class:`.FSCmd`
        """
        if not isinstance(raw, bytearray):
            raise ValueError("Data must be a bytearray")
        if direction == FSCmd.RESPONSE and len(raw) < 2:
            raise InvalidPacketException(
                message="Command bytearray must have, at least, 2 bytes")
        status = raw[1] if direction == FSCmd.RESPONSE else None
        if len(raw) < self._get_min_len(status=status):
            raise ValueError("Command bytearray must have, at least, %d bytes"
                             % self._get_min_len(status=status))

        cmd_type = FSCmdType.get(raw[0])
        if cmd_type is not None:
            raise ValueError("This is a known command: %s" % cmd_type.name)

        super().__init__(raw[0], direction=direction,
                         status=raw[1] if direction == FSCmd.RESPONSE else None)

        self.__data = raw[0]
        if direction == FSCmd.RESPONSE:
            self.__data = raw[0:1] + raw[2:]

    @property
    def type(self):
        """
        Returns the command type.

        Returns:
            Integer: The command type.
        """
        return self.__data[0]

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.

        Returns:
            :class:`.UnknownFSCmd`.

        Raises:
            InvalidPacketException: If `raw` is not a bytearray.
            InvalidPacketException: If `raw` length is less than 3, or the
                command type is a known one.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        try:
            return UnknownFSCmd(raw, direction=direction)
        except (ValueError, TypeError) as exc:
            raise InvalidPacketException(message=str(exc)) from None

    def output(self):
        """
        Returns the raw bytearray of this command.

        Returns:
            Bytearray: Raw bytearray of the command.
        """
        if self._dir == self.REQUEST:
            return self.__data

        ret = self.__data[0:1]
        ret.append(self._status)
        return ret + self.__data[1:]

    def to_dict(self):
        """
        Returns a dictionary with all information of the command fields.

        Returns:
            Dictionary: Dictionary with all info of the command fields.
        """
        ret_dict = {DictKeys.FS_CMD: self.__data[0]}
        if self._dir == self.RESPONSE:
            ret_dict.update({DictKeys.STATUS: self._status})
        ret_dict.update({DictKeys.DATA: self.__data[1:]})

        return ret_dict

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        return self.__data


class FileIdCmd(FSCmd):
    """
    This class represents a file system command request or response that
    includes a file or path id.
    """

    def __init__(self, cmd_type, fid, direction=FSCmd.REQUEST, status=None):
        """
        Class constructor. Instantiates a new :class:`.FileIdCmd` object with
        the provided parameters.

        Args:
            cmd_type (:class:`.FSCmdType` or Integer): The command type.
            fid (Integer): Id of the file/path to operate with. A file id expires
                and becomes invalid if not referenced for over 2 minutes.
                Set to 0x0000 for the root directory (/).
            direction (Integer, optional, default=0): If this command is a
                request (0) or a response (1).
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution. Only for response commands.

        Raises:
            ValueError: If `fid` is invalid.

        .. seealso::
           | :class:`.FSCmd`
           | :class:`.FSCommandStatus`
        """
        if fid is not None:
            if not isinstance(fid, int):
                raise ValueError("File id must be an integer")
            if fid not in range(0, 0x10000):
                raise ValueError("Id must be between 0 and 0xFFFF")

        super().__init__(cmd_type, direction=direction, status=status)

        self._fid = fid

    @property
    def fs_id(self):
        """
        Returns the file/path identifier.

        Returns:
            Integer: The file/path id value.
        """
        return self._fid

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.

        Returns:
            :class:`.FileIdCmd`.

        Raises:
            InvalidPacketException: If the bytearray length is less than the
                minimum required.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        id_idx = 1 if direction == FSCmd.REQUEST else 2
        return FileIdCmd(cmd.type,
                         utils.bytes_to_int(raw[id_idx:id_idx + 2])
                         if len(raw) > cls._get_min_len(status=cmd.status_value) else None,
                         direction=direction, status=cmd.status_value)

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        if status is None:
            # cmd id + file/path id (2 bytes) = 3
            return 3
        if status == FSCommandStatus.SUCCESS.code:
            # cmd id + status + file/path id (2 bytes) = 4
            return 4

        # cmd id + status = 2
        return 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        if self._dir == FSCmd.REQUEST or self._status == FSCommandStatus.SUCCESS.code:
            return utils.int_to_bytes(self._fid, num_bytes=2)

        return bytearray()

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        if self._dir == FSCmd.REQUEST or self._status == FSCommandStatus.SUCCESS.code:
            return {DictKeys.FILE_ID: self._fid}

        return {}


class FileIdNameCmd(FileIdCmd):
    """
    This class represents a file system command request or response that
    includes a file or path id and a name.

    The file/path id is the next byte after the command type in the frame,
    and name are the following bytes until the end of the frame.
    """

    def __init__(self, cmd_type, fid, name, direction=FSCmd.REQUEST, status=None):
        """
        Class constructor. Instantiates a new :class:`.FileIdNameCmd` object
        with the provided parameters.

        Args:
            cmd_type (:class:`.FSCmdType` or Integer): The command type.
            fid (Integer): Id of the file/path to operate with. Set to 0x0000
                for the root directory (/).
            name (String or bytearray): The path name of the file to operate
                with. Its maximum length is 252 characters.
            direction (Integer, optional, default=0): If this command is a
                request (0) or a response (1).
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution. Only for response commands.

        Raises:
            ValueError: If `fid` or `name` are invalid.

        .. seealso::
           | :class:`.FSCmd`
        """
        if name is not None:
            if not isinstance(name, (str, bytearray, bytes)):
                raise ValueError("Name must be a string or bytearray")
            if not name or len(name) > self._get_name_max_len():
                raise ValueError(
                    "Name cannot be empty or exceed %d chars" % self._get_name_max_len())

        super().__init__(cmd_type, fid, direction=direction, status=status)

        if isinstance(name, str):
            self._name = name.encode('utf8', errors='ignore')
        else:
            self._name = name

    @property
    def name(self):
        """
        Returns the path name of the file.

        Returns:
            String: The file path name.
        """
        return self._name.decode(encoding='utf8', errors='ignore')

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.FileIdNameCmd`.

        Raises:
            InvalidPacketException: If the bytearray length is less than the
                minimum required.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)

        id_idx = 1 if direction == FSCmd.REQUEST else 2
        fid = None
        if len(raw) > cls._get_min_len(status=cmd.status_value):
            fid = utils.bytes_to_int(raw[id_idx:id_idx + 2])
        name = None
        if len(raw) > cls._get_min_len(status=cmd.status_value):
            name = raw[id_idx + 2:]

        return FileIdNameCmd(
            cmd.type, fid, name, direction=direction, status=cmd.status_value)

    @staticmethod
    def _get_name_max_len():
        """
        Returns the maximum length of the name field.

        Returns:
            Integer: Name field maximum length (in bytes).
        """
        return 255 - 3  # cmd_id (1) + f_id (2) = 3

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        if status is None:
            # cmd id + path id (2 bytes) + name (at least 1 byte) = 4
            return 4
        if status == FSCommandStatus.SUCCESS.code:
            # cmd id + status + path id (2 bytes) + name (at least 1 byte) = 5
            return 5

        # cmd id + status = 2
        return 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        if self._dir == FSCmd.REQUEST or self._status == FSCommandStatus.SUCCESS.code:
            return ret + self._name

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        if self._dir == FSCmd.REQUEST or self._status == FSCommandStatus.SUCCESS.code:
            dict_ret.update({DictKeys.NAME: self._name})

        return dict_ret


class OpenFileCmdRequest(FileIdNameCmd):
    """
    This class represents a file open/create file system command request.
    Open a file for reading and/or writing. Use `FileOpenRequestOption.SECURE`
    bitmask to upload a write-only file (one that cannot be downloaded or
    viewed), useful for protecting MicroPython source code on the device.

    Command response is received as a :class:`.OpenFileCmdResponse`.
    """

    def __init__(self, path_id, name, flags):
        """
        Class constructor. Instantiates a new :class:`.OpenFileCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): The path name of the file to open/create,
                relative to `path_id`. Its maximum length is 251 chars.
            flags (:class:`.FileOpenRequestOption`): Bitfield of supported flags.
                Use :class:`.FileOpenRequestOption` to compose its value.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
           | :class:`.FileOpenRequestOption`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        if not isinstance(name, (str, bytearray, bytes)):
            raise ValueError("Name must be a string or bytearray")
        if flags not in range(0, 0x100):
            raise ValueError("Flags must be between 0 and 0xFF")

        super().__init__(FSCmdType.FILE_OPEN, path_id, name,
                         direction=self.REQUEST)

        self.__flags = flags

    @property
    def options(self):
        """
        Returns the options to open the file.

        Returns:
            :class:`.FileOpenRequestOption`: The options to open the file.
        """
        return self.__flags

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.OpenFileCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 5.
                (cmd id + path id (2 bytes) + flags (1 byte)
                + name (at least 1 byte) = 5 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_OPEN:
            raise InvalidPacketException(
                message="This command is not an Open File command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return OpenFileCmdRequest(utils.bytes_to_int(raw[1:3]), raw[4:],
                                  utils.bytes_to_int(raw[3:4]))

    @staticmethod
    def _get_name_max_len():
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdNameCmd._get_name_max_len`
        """
        return 255 - 4  # cmd_id (1) + f_id (2) + options (1) = 4

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + path id (2 bytes) + flags (1 byte) + name = 5
        return 5

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        ret = utils.int_to_bytes(self._fid, num_bytes=2)
        ret += utils.int_to_bytes(self.__flags.value, num_bytes=1)

        return ret + self._name

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        dict_ret.update({DictKeys.FLAGS: self.__flags})

        return dict_ret


class OpenFileCmdResponse(FileIdCmd):
    """
    This class represents a file open/create file system command response.

    This is received in response of an :class:`.OpenFileCmdRequest`.
    """

    def __init__(self, status, fid=None, size=None):
        """
        Class constructor. Instantiates a new :class:`.OpenFileCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            fid (Integer, optional, default=`None`): Id of the file that has
                been opened. It expires and becomes invalid if not referenced
                for over 2 minutes.
            size (Integer, optional, default=`None`): Size in bytes of the file.
                0xFFFFFFFF if unknown.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if size is not None and size not in range(0, 0x100000000):
            raise ValueError("Size must be between 0 and 0xFFFFFFFF")

        super().__init__(
            FSCmdType.FILE_OPEN, fid, direction=self.RESPONSE, status=status)

        self.__size = size

    @property
    def size(self):
        """
        Returns the size of the opened file. 0xFFFFFFFF if unknown.

        Returns:
            Integer: Size in bytes of the opened file.
        """
        return self.__size

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.OpenFileCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 8.
                (cmd id + status + file id (2 bytes) + size (4 bytes) = 8).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_OPEN:
            raise InvalidPacketException(
                message="This command is not an Open File command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        return OpenFileCmdResponse(
            cmd.status_value,
            fid=utils.bytes_to_int(raw[2:4]) if ok_status else None,
            size=utils.bytes_to_int(raw[4:8]) if ok_status else None)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + file id (2 bytes) + size (4 bytes) = 8
        return 8 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        if self._status == FSCommandStatus.SUCCESS.code:
            ret += utils.int_to_bytes(self.__size, num_bytes=4)

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        if self._status == FSCommandStatus.SUCCESS.code:
            dict_ret.update({DictKeys.SIZE: self.__size})

        return dict_ret


class CloseFileCmdRequest(FileIdCmd):
    """
    This class represents a file close file system command request.
    Close an open file and release its File Handle.

    Command response is received as a :class:`.CloseFileCmdResponse`.
    """

    def __init__(self, fid):
        """
        Class constructor. Instantiates a new :class:`.CloseFileCmdRequest`
        object with the provided parameters.

        Args:
            fid (Integer): Id of the file to close returned in Open File Response.
                It expires and becomes invalid if not referenced for over 2 minutes.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if not isinstance(fid, int):
            raise ValueError("File id must be an integer")

        super().__init__(FSCmdType.FILE_CLOSE, fid, direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.CloseFileCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 3.
                (cmd id + file_id (2 bytes) = 3 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_CLOSE:
            raise InvalidPacketException(
                message="This command is not a Close File command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return CloseFileCmdRequest(utils.bytes_to_int(raw[1:3]))


class CloseFileCmdResponse(FSCmd):
    """
    This class represents a file close file system command response.

    Command response is received as a :class:`.CloseFileCmdRequest`.
    """

    def __init__(self, status):
        """
        Class constructor. Instantiates a new :class:`.CloseFileCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(FSCmdType.FILE_CLOSE, direction=self.RESPONSE,
                         status=status)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.OpenFileCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 1.
                (cmd id = 1 byte).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_CLOSE:
            raise InvalidPacketException(
                message="This command is not a Close File command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        return CloseFileCmdResponse(cmd.status_value)


class ReadFileCmdRequest(FileIdCmd):
    """
    This class represents a read file system command request.

    Command response is received as a :class:`.ReadFileCmdResponse`.
    """

    USE_CURRENT_OFFSET = 0xFFFFFFFF
    """
    Use current file position to start reading.
    """

    READ_AS_MANY = 0xFFFF
    """
    Read as many bytes as possible (limited by file size or maximum response
    frame size)
    """

    def __init__(self, fid, offset, size):
        """
        Class constructor. Instantiates a new :class:`.ReadFileCmdRequest`
        object with the provided parameters.

        Args:
            fid (Integer): Id of the file to read returned in Open File Response.
                It expires and becomes invalid if not referenced for over 2 minutes.
            offset (Integer): The file offset to start reading. 0xFFFFFFFF to
                use current position (`ReadFileCmdRequest.USE_CURRENT_OFFSET`)
            size (Integer): The number of bytes to read. 0xFFFF
                (`ReadFileCmdRequest.READ_AS_MANY`) to read as many as possible
                (limited by file size or maximum response frame size)

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if not isinstance(fid, int):
            raise ValueError("File id must be an integer")
        if offset not in range(0, 0x100000000):
            raise ValueError("Offset must be between 0 and 0xFFFFFFFF")
        if size not in range(0, 0x10000):
            raise ValueError("Size must be between 0 and 0xFFFF")

        super().__init__(FSCmdType.FILE_READ, fid, direction=self.REQUEST)

        self.__offset = offset
        self.__size = size

    @property
    def offset(self):
        """
        Returns the file offset to start reading. 0xFFFFFFFF to use current
        position (`ReadFileCmdRequest.0xFFFFFFFF`)

        Returns:
            Integer: The file offset.
        """
        return self.__offset

    @property
    def size(self):
        """
        Returns the number of bytes to read. 0xFFFF
        (`ReadFileCmdRequest.READ_AS_MANY`) to read as many as possible
        (limited by file size or maximum response frame size)

        Returns:
            Integer: The number of bytes to read.
        """
        return self.__size

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.ReadFileCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 9.
                (cmd id + file_id (2 bytes) + offset (4 bytes)
                + size (2 bytes) = 9 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_READ:
            raise InvalidPacketException(
                message="This command is not a Read File command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return ReadFileCmdRequest(utils.bytes_to_int(raw[1:3]),
                                  utils.bytes_to_int(raw[3:7]),
                                  utils.bytes_to_int(raw[7:9]))

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + file_id (2 bytes) + offset (4 bytes) + size (2 bytes) = 9
        return 9

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        ret += utils.int_to_bytes(self.__offset, num_bytes=4)

        return ret + utils.int_to_bytes(self.__size, num_bytes=2)

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        dict_ret.update({DictKeys.OFFSET: self.__offset,
                         DictKeys.SIZE:   self.__size})

        return dict_ret


class ReadFileCmdResponse(FileIdCmd):
    """
    This class represents a read file system command response.

    Command response is received as a :class:`.ReadFileCmdRequest`.
    """

    def __init__(self, status, fid=None, offset=None, data=None):
        """
        Class constructor. Instantiates a new :class:`.ReadFileCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            fid (Integer, optional, default=`None`): Id of the read file.
            offset (Integer, optional, default=`None`): The offset of the read
                data.
            data (Bytearray, optional, default=`None`): The file read data.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if offset and offset not in range(0, 0x100000000):
            raise ValueError("Offset must be between 0 and 0xFFFFFFFF")
        if data and not isinstance(data, bytearray):
            raise ValueError("Data must be a bytearray")
        max_len = 255 - 8  # cmd_id (1) + status (1) + f_id (2) + offset (4) = 8
        if len(data) > max_len:
            raise ValueError("Data cannot exceed %d chars" % max_len)

        super().__init__(FSCmdType.FILE_READ, fid, direction=self.RESPONSE,
                         status=status)

        self.__offset = offset
        self.__data = data if data is not None else bytearray()

    @property
    def offset(self):
        """
        Returns the offset of the read data.

        Returns:
            Integer: The data offset.
        """
        return self.__offset

    @property
    def data(self):
        """
        Returns the read data from the file.

        Returns:
            Bytearray: Read data.
        """
        return self.__data

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.ReadFileCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 8.
                (cmd id + status + file_id (2 bytes) + offset (4 bytes) + data = 8)
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_READ:
            raise InvalidPacketException(
                message="This command is not a Read File command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        return ReadFileCmdResponse(
            cmd.status_value,
            fid=utils.bytes_to_int(raw[2:4]) if ok_status else None,
            offset=utils.bytes_to_int(raw[4:8]) if ok_status else None,
            data=raw[8:] if len(raw) > cls._get_min_len(status=cmd.status_value) else None)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + file_id (2 bytes) + offset (4 bytes) = 8
        return 8 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        if self._status == FSCommandStatus.SUCCESS.code:
            ret += utils.int_to_bytes(self.__offset, num_bytes=4)
            return ret + self.__data

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        if self._status == FSCommandStatus.SUCCESS.code:
            dict_ret.update({DictKeys.OFFSET: self.__offset,
                             DictKeys.DATA:   list(self.__data)})

        return dict_ret


class WriteFileCmdRequest(FileIdCmd):
    """
    This class represents a write file system command request.

    Command response is received as a :class:`.WriteFileCmdResponse`.
    """

    USE_CURRENT_OFFSET = 0xFFFFFFFF
    """
    Use current file position to start writing.
    """

    def __init__(self, fid, offset, data=None):
        """
        Class constructor. Instantiates a new :class:`.WriteFileCmdRequest`
        object with the provided parameters.

        Args:
            fid (Integer): Id of the file to write returned in Open File Response.
                It expires and becomes invalid if not referenced for over 2 minutes.
            offset (Integer): The file offset to start writing. 0xFFFFFFFF to
                use current position (`ReadFileCmdRequest.USE_CURRENT_OFFSET`)
            data (Bytearray, optional, default=`None`): The data to write.
                 If empty, frame just refreshes the File Handle timeout to keep
                 the file open.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if not isinstance(fid, int):
            raise ValueError("File id must be an integer")
        if offset not in range(0, 0x100000000):
            raise ValueError("Offset must be between 0 and 0xFFFFFFFF")
        if data and not isinstance(data, bytearray):
            raise ValueError("Data must be a bytearray")
        max_len = 255 - 7  # cmd_id (1) + f_id (2) + offset (4) = 7
        if len(data) > max_len:
            raise ValueError("Data cannot exceed %d chars" % max_len)

        super().__init__(FSCmdType.FILE_WRITE, fid, direction=self.REQUEST)

        self.__offset = offset
        self.__data = data
        if data is None:
            self.__data = bytearray()

    @property
    def offset(self):
        """
        Returns the file offset to start writing.

        Returns:
            Integer: The file offset.
        """
        return self.__offset

    @property
    def data(self):
        """
        Returns the data to write. If empty, frame just refreshes the File
        Handle timeout to keep the file open.

        Returns:
            Bytearray: The data to write.
        """
        return self.__data

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.WriteFileCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 7.
                (cmd id + file_id (2 bytes) + offset (4 bytes) = 7 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_WRITE:
            raise InvalidPacketException(
                message="This command is not a Write File command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return WriteFileCmdRequest(utils.bytes_to_int(raw[1:3]),
                                   utils.bytes_to_int(raw[3:7]),
                                   data=raw[7:] if len(raw) > cls._get_min_len() else None)

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + file_id (2 bytes) + offset (4 bytes) = 7
        return 7

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        ret += utils.int_to_bytes(self.__offset, num_bytes=4)

        return ret + self.__data

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        dict_ret.update({DictKeys.OFFSET: self.__offset,
                         DictKeys.DATA:   list(self.__data)})

        return dict_ret


class WriteFileCmdResponse(FileIdCmd):
    """
    This class represents a write file system command response.

    Command response is received as a :class:`.WriteFileCmdRequest`.
    """

    def __init__(self, status, fid=None, actual_offset=None):
        """
        Class constructor. Instantiates a new :class:`.WriteFileCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            fid (Integer, optional, default=`None`): Id of the written file.
            actual_offset (Integer, optional, default=`None`): The current file
                offset after writing.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if actual_offset and actual_offset not in range(0, 0x100000000):
            raise ValueError("Offset must be between 0 and 0xFFFFFFFF")

        super().__init__(FSCmdType.FILE_WRITE, fid, direction=self.RESPONSE, status=status)

        self.__offset = actual_offset

    @property
    def actual_offset(self):
        """
        Returns the file offset after writing.

        Returns:
            Integer: The file offset.
        """
        return self.__offset

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.WriteFileCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 8.
                (cmd id + status + file_id (2 bytes) + offset (4 bytes) = 8)
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_WRITE:
            raise InvalidPacketException(
                message="This command is not a Write File command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        return WriteFileCmdResponse(
            cmd.status_value,
            fid=utils.bytes_to_int(raw[2:4]) if ok_status else None,
            actual_offset=utils.bytes_to_int(raw[4:8]) if ok_status else None)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + file_id (2 bytes) + offset (4 bytes) = 8
        return 8 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        if self._status == FSCommandStatus.SUCCESS.code:
            return ret + utils.int_to_bytes(self.__offset, num_bytes=4)

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        if self._status == FSCommandStatus.SUCCESS.code:
            dict_ret.update({DictKeys.OFFSET: self.__offset})

        return dict_ret


class HashFileCmdRequest(FileIdNameCmd):
    """
    This class represents a file hash command request.
    Use this command to get a sha256 hash to verify a file's contents without
    downloading the entire file (something not even possible for secure files).
    On XBee Cellular modules, there is a response delay in order to calculate
    the hash of a non-secure file.
    Secure files on XBee Cellular and all files on XBee 3 802.15.4, DigiMesh,
    and Zigbee have a cached hash.

    Command response is received as a :class:`.HashFileCmdResponse`.
    """

    def __init__(self, path_id, name):
        """
        Class constructor. Instantiates a new :class:`.HashFileCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): The path name of the file to hash,
                relative to `path_id`. Its maximum length is 252 chars.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        if not isinstance(name, (str, bytearray, bytes)):
            raise ValueError("Name must be a string or bytearray")
        super().__init__(FSCmdType.FILE_HASH, path_id, name,
                         direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.HashFileCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + path id (2 bytes) + name (at least 1 byte) = 4 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_HASH:
            raise InvalidPacketException(
                message="This command is not a Hash command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return HashFileCmdRequest(utils.bytes_to_int(raw[1:3]), raw[3:])


class HashFileCmdResponse(FSCmd):
    """
    This class represents a file hash command response.

    This is received in response of an :class:`.HashFileCmdRequest`.
    """

    def __init__(self, status, file_hash=None):
        """
        Class constructor. Instantiates a new :class:`.HashFileCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            file_hash (Bytearray, optional, default=`None`): The hash value.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCmd`
        """
        if file_hash is not None:
            if not isinstance(file_hash, bytearray):
                raise TypeError("Hash must be a bytearray")
            if not file_hash or len(file_hash) > 32:
                raise ValueError("Hash must have at least one byte an less than 33")

        super().__init__(FSCmdType.FILE_HASH, direction=self.RESPONSE,
                         status=status)

        self.__hash = file_hash

    @property
    def file_hash(self):
        """
        Returns the hash of the file.

        Returns:
            Bytearray: The hash of the file.
        """
        return self.__hash

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.HashFileCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 34.
                (cmd id + status + hash (32 bytes) = 34).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FILE_HASH:
            raise InvalidPacketException(
                message="This command is not a Hash command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        return HashFileCmdResponse(cmd.status_value,
                                   file_hash=raw[2:34] if ok_status else None)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + hash (32 bytes) = 34
        return 34 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data`
        """
        return self.__hash if self._status == FSCommandStatus.SUCCESS.code else bytearray()

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data_dict`
        """
        return {DictKeys.HASH: self.__hash} \
            if self._status == FSCommandStatus.SUCCESS.code else {}


class CreateDirCmdRequest(FileIdNameCmd):
    """
    This class represents a create directory file system command request.
    Parent directories of the one to be created must exist. Separate request
    must be dane to make intermediate directories.

    Command response is received as a :class:`.CreateDirCmdResponse`.
    """

    def __init__(self, path_id, name):
        """
        Class constructor. Instantiates a new :class:`.CreateDirCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): The path name of the directory to
                create, relative to `path_id`. Its maximum length is 252 chars.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        super().__init__(FSCmdType.DIR_CREATE, path_id, name,
                         direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.CreateDirCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + path id (2 bytes) + name (at least 1 byte) = 4 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_CREATE:
            raise InvalidPacketException(
                message="This command is not a Create Directory command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return CreateDirCmdRequest(utils.bytes_to_int(raw[1:3]), raw[3:])


class CreateDirCmdResponse(FSCmd):
    """
    This class represents a create directory file system command response.

    Command response is received as a :class:`.CreateDirCmdRequest`.
    """

    def __init__(self, status):
        """
        Class constructor. Instantiates a new :class:`.CreateDirCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(FSCmdType.DIR_CREATE, direction=self.RESPONSE,
                         status=status)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.CreateDirCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 2.
                (cmd id + status = 2).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_CREATE:
            raise InvalidPacketException(
                message="This command is not a Create Directory command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        return CreateDirCmdResponse(cmd.status_value)


class OpenDirCmdRequest(FileIdNameCmd):
    """
    This class represents an open directory file system command request.

    Command response is received as a :class:`.OpenDirCmdResponse`.
    """

    def __init__(self, path_id, name):
        """
        Class constructor. Instantiates a new :class:`.OpenDirCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): Path name of the directory to open,
                relative to `path_id`. An empty name is equivalent to '.', both
                refer to the current directory path id. Its maximum length is
                252 chars.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        if name is None or not isinstance(name, str):
            raise ValueError("Path name must be a string")
        super().__init__(FSCmdType.DIR_OPEN, path_id, name,
                         direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.OpenDirCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + path id (2 bytes) + name (at least 1 byte) = 4 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_OPEN:
            raise InvalidPacketException(
                message="This command is not an Open Directory command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return OpenDirCmdRequest(utils.bytes_to_int(raw[1:3]), raw[3:])


class OpenDirCmdResponse(FileIdCmd):
    """
    This class represents an open directory file system command response.
    If the final file system element does not have
    `DirResponseFlag.ENTRY_IS_LAST` set, send a Directory Read Request to get
    additional entries.
    A response ending with an `DirResponseFlag.ENTRY_IS_LAST` flag automatically
    closes the Directory Handle.
    An empty directory returns a single entry with just the
    `DirResponseFlag.ENTRY_IS_LAST` flag set, and a 0-byte name.

    This is received in response of an :class:`.OpenDirCmdRequest`.
    """

    def __init__(self, status, did=None, fs_entries=None):
        """
        Class constructor. Instantiates a new :class:`.OpenFileCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            did (Integer, optional, default=`None`): Id of the directory that
                has been opened. It expires and becomes invalid if not
                referenced for over 2 minutes.
            fs_entries (List, optional, default=`None`): List of bytearrays with
                the info and name of the entries inside the opened directory.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if fs_entries and not isinstance(fs_entries, list):
            raise ValueError("File system entries must be a list")

        super().__init__(FSCmdType.DIR_OPEN, did, direction=self.RESPONSE,
                         status=status)

        self._fs_entries = fs_entries

    @property
    def is_last(self):
        """
        Returns whether there are more elements not included in this response.

        Returns:
            Boolean: `True` if there are no more elements to list, `False`
                otherwise.
        """
        for item in self._fs_entries:
            if not item:
                continue
            if bool(item[0] & DirResponseFlag.IS_LAST):
                return True

        return False

    @property
    def fs_entries(self):
        """
        Returns the list of entries inside the opened directory.

        Returns:
            List: List of :class: .`FileSystemElement` inside the directory.
        """
        if not self._fs_entries:
            return []

        # Empty directory: single entry with just the
        # `DirResponseFlag.ENTRY_IS_LAST` flag set, and a 0-byte name (4 bytes)
        if (self.is_last and len(self._fs_entries) == 1
                and len(self._fs_entries[0]) == 4):
            return []

        f_list = []
        for item in self._fs_entries:
            if not item:
                continue
            from digi.xbee.filesystem import FileSystemElement
            # File size: lower 24 bits (3 bytes) of size_and_flags
            f_list.append(FileSystemElement.from_data(item[4:], item[1:4], item[0]))

        return f_list

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.OpenDirCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 8.
                (cmd id + status + dir id (2 bytes) + filesize_and_flags (4 bytes) = 8).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_OPEN:
            raise InvalidPacketException(
                message="This command is not an Open Directory command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS

        f_list = []
        if ok_status:
            offset = 4  # cmd id + status + dir id (2)
            while offset < len(raw):
                # 4 bytes for the flags_and_size field
                null_index = raw.find(0, offset + 4)
                if null_index == -1:
                    null_index = len(raw)
                f_list.append(raw[offset: null_index])
                offset = null_index + 1

        return OpenDirCmdResponse(cmd.status_value,
                                  did=utils.bytes_to_int(raw[2:4]) if ok_status else None,
                                  fs_entries=f_list)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + dir id (2 bytes) + filesize_and_flags (4 bytes) = 8
        return 8 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        if self._status == FSCommandStatus.SUCCESS.code and self._fs_entries:
            for item in self._fs_entries:
                ret += item + b'\0'
            # Remove the last NULL char
            ret = ret[:-1]

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()

        if self._status == FSCommandStatus.SUCCESS.code:
            dict_ret.update(
                {DictKeys.ENTRY: ', '.join(str(entry) for entry in self.fs_entries)})

        return dict_ret


class CloseDirCmdRequest(FileIdCmd):
    """
    This class represents a directory close file system command request.

    Command response is received as a :class:`.CloseDirCmdResponse`.
    """

    def __init__(self, did):
        """
        Class constructor. Instantiates a new :class:`.CloseDirCmdRequest`
        object with the provided parameters.

        Args:
            did (Integer): Id of the directory to close. It expires and becomes
                invalid if not referenced for over 2 minutes.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if not isinstance(did, int):
            raise ValueError("Directory id must be an integer")
        super().__init__(FSCmdType.DIR_CLOSE, did, direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.CloseDirCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 3.
                (cmd id + dir_id (2 bytes) = 3 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_CLOSE:
            raise InvalidPacketException(
                message="This command is not a Close Directory command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return CloseDirCmdRequest(utils.bytes_to_int(raw[1:3]))


class CloseDirCmdResponse(FSCmd):
    """
    This class represents a directory close file system command response.
    Send this command to indicate that it is done reading the directory and no
    longer needs the Directory Handle. Typical usage scenario is to use a
    Directory Open Request and additional Directory Read Requests until the
    Response includes an entry with the `DirResponseFlag.ENTRY_IS_LAST` flag set.

    Command response is received as a :class:`.CloseDirCmdRequest`.
    """

    def __init__(self, status):
        """
        Class constructor. Instantiates a new :class:`.CloseDirCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(FSCmdType.DIR_CLOSE, direction=self.RESPONSE,
                         status=status)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.CloseDirCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 2.
                (cmd id + status = 2).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_CLOSE:
            raise InvalidPacketException(
                message="This command is not a Close Directory command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        return CloseDirCmdResponse(cmd.status_value)


class ReadDirCmdRequest(FileIdCmd):
    """
    This class represents a directory read file system command request.

    Command response is received as a :class:`.ReadDirCmdResponse`.
    """

    def __init__(self, did):
        """
        Class constructor. Instantiates a new :class:`.ReadDirCmdRequest`
        object with the provided parameters.

        Args:
            did (Integer): Id of the directory to close. It expires and becomes
                invalid if not referenced for over 2 minutes.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if not isinstance(did, int):
            raise ValueError("Directory id must be an integer")
        super().__init__(FSCmdType.DIR_READ, did, direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.ReadDirCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 3.
                (cmd id + dir_id (2 bytes) = 3 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_READ:
            raise InvalidPacketException(
                message="This command is not a Read Directory command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return ReadDirCmdRequest(utils.bytes_to_int(raw[1:3]))


class ReadDirCmdResponse(OpenDirCmdResponse):
    """
    This class represents a read directory file system command response.
    If the final file system element does not have
    `DirResponseFlag.ENTRY_IS_LAST` set, send another Directory Read Request
    to get additional entries.
    A response ending with an `DirResponseFlag.ENTRY_IS_LAST` flag automatically
    closes the Directory Handle.

    This is received in response of an :class:`.ReadDirCmdRequest`.
    """

    def __init__(self, status, did=None, fs_entries=None):
        """
        Class constructor. Instantiates a new :class:`.ReadDirCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            did (Integer, optional, default=`None`): Id of the directory that
                has been read.
            fs_entries (List, optional, default=`None`): List of bytearrays
                with the info and name of the entries inside the directory.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
           | :class:`.DirResponseFlag`
        """
        super().__init__(status, did=did, fs_entries=fs_entries)
        self._cmd_type = FSCmdType.DIR_READ

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.ReadDirCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + status + dir id (2 bytes) = 4).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = FileIdCmd.create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DIR_READ:
            raise InvalidPacketException(
                message="This command is not a Read Directory command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS

        f_list = []
        if ok_status:
            offset = 4  # cmd id + status + dir id (2)
            while offset < len(raw):
                # 4 bytes for the flags_and_size field
                null_index = raw.find(0, offset + 4)
                if null_index == -1:
                    null_index = len(raw)
                f_list.append(raw[offset: null_index])
                offset = null_index + 1

        return ReadDirCmdResponse(cmd.status_value,
                                  did=utils.bytes_to_int(raw[2:4]) if ok_status else None,
                                  fs_entries=f_list)


class GetPathIdCmdRequest(FileIdNameCmd):
    """
    This class represents a get path id file system command request.
    A directory path id (path_id) of 0x0000 in any command, means path names
    are relative to the root directory of the filesystem (/).

        * '/' as path separator
        * '..' to refer to the parent directory
        * '.' to refer to the current path directory

    Use this command to get a shortcut to a subdirectory of the file system to
    allow the use of shorter path names in the frame:

        * If the PATH ID field of this command is 0x0000, the XBee allocates a
          new PATH ID for use in later requests.
        * If the PATH ID field of this command is non-zero, the XBee updates
          the directory path of that ID.

    To release a PATH ID when no longer needed:
        * Send a request with that ID and a single slash ("/") as the pathname.
          Any Change Directory Request that resolves to the root directory
          releases the PATH ID and return a 0x0000 ID.
        * Wait for a timeout (2 minutes)

    Any file system id expires after 2 minutes if not referenced. Refresh this
    timeout by sending a Change Directory request with an empty or a single
    period ('.') as the pathname.

    Command response is received as a :class:`.GetPathIdCmdResponse`.
    """

    def __init__(self, path_id, name):
        """
        Class constructor. Instantiates a new :class:`.GetPathIdCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): The path name of the directory to
                change, relative to `path_id`. An empty name is equivalent to
                '.', both refer to the current directory path id. Its maximum
                length is 252 chars.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        if name is None or not isinstance(name, str):
            raise ValueError("Path name must be a string")
        super().__init__(FSCmdType.GET_PATH_ID, path_id, name,
                         direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.GetPathIdCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + path id (2 bytes) + name (at least 1 byte) = 4 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.GET_PATH_ID:
            raise InvalidPacketException(
                message="This command is not a Directory Change command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return GetPathIdCmdRequest(utils.bytes_to_int(raw[1:3]), raw[3:])


class GetPathIdCmdResponse(FileIdCmd):
    """
    This class represents a get path id file system command response.
    The full path of the new current directory is included if can fit.

    This is received in response of an :class:`.GetPathIdCmdRequest`.
    """

    def __init__(self, status, path_id=None, full_path=None):
        """
        Class constructor. Instantiates a new :class:`.GetPathIdCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            path_id (Integer, optional, default=`None`): New directory path id.
            full_path (String or bytearray, optional, default=`None`): If short
                enough, the full path of the current directory , relative to
                `path_id`. Deep subdirectories may return an empty field
                instead of their full path name. The maximum full path length
                is 255 characters.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdCmd`
        """
        if full_path is not None:
            if not isinstance(full_path, (str, bytearray, bytes)):
                raise ValueError("Full path must be a string or bytearray")
            if not full_path or len(full_path) > 255:
                raise ValueError(
                    "Full path cannot be empty and cannot exceed 255 chars")

        super().__init__(FSCmdType.GET_PATH_ID, path_id,
                         direction=self.RESPONSE, status=status)

        if isinstance(full_path, str):
            self.__path = full_path.encode('utf8', errors='ignore')
        else:
            self.__path = full_path

    @property
    def full_path(self):
        """
        Returns the full path of the current directory.

        Returns:
            String: The directory full path.
        """
        return self.__path.decode(encoding='utf8', errors='ignore')

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.GetPathIdCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + status + path id (2 bytes) = 4).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.GET_PATH_ID:
            raise InvalidPacketException(
                message="This command is not a Change Directory command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        f_path = None
        if len(raw) > cls._get_min_len(status=cmd.status_value):
            f_path = raw[4:]
        return GetPathIdCmdResponse(
            cmd.status_value,
            path_id=utils.bytes_to_int(raw[2:4]) if ok_status else None,
            full_path=f_path)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + path id (2 bytes) = 4
        return 4 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        if self._status == FSCommandStatus.SUCCESS.code and self.__path:
            return ret + self.__path

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        if self._status == FSCommandStatus.SUCCESS.code:
            dict_ret.update({DictKeys.PATH: self.__path})

        return dict_ret


class RenameCmdRequest(FileIdNameCmd):
    """
    This class represents a file/directory rename file system command request.
    Current firmware for XBee 3 802.15.4, DigiMesh, and Zigbee do not support
    renaming files. Contact Digi International to request it as a feature in a
    future release.

    Command response is received as a :class:`.RenameCmdResponse`.
    """

    def __init__(self, path_id, name, new_name):
        """
        Class constructor. Instantiates a new :class:`.RenameCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): The current path name of the
                file/directory to rename relative to `path_id`. Its maximum
                length is 255 chars.
            new_name (String or bytearray): The new name of the file/directory
                relative to `path_id`. Its maximum length is 255 chars.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        if not isinstance(name, (str, bytearray, bytes)):
            raise ValueError("Name must be a string or bytearray")
        if not isinstance(new_name, (str, bytearray, bytes)):
            raise ValueError("New name must be a string or bytearray")
        if (len(name) + len(new_name)) > self._get_name_max_len():
            raise ValueError(
                "Name length plus new name length cannot exceed %d chars" % self._get_name_max_len())

        super().__init__(FSCmdType.RENAME, path_id, name, direction=self.REQUEST)

        if isinstance(name, str):
            self.__new_name = new_name.encode('utf8', errors='ignore')
        else:
            self.__new_name = new_name

    @property
    def new_name(self):
        """
        Returns the new name of the file or directory.

        Returns:
            String: The new name.
        """
        return self.__new_name.decode(encoding='utf8', errors='ignore')

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.RenameCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 6.
                (cmd id + path id (2 bytes) + name (1 byte at least) + ','
                + new name (at least 1 byte) = 6 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.RENAME:
            raise InvalidPacketException(
                message="This command is not a Rename File command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        names = raw[3:].split(b',')
        if len(names) != 2:
            raise InvalidPacketException(
                "Invalid bytearray format, it must contain a ','")

        return RenameCmdRequest(utils.bytes_to_int(raw[1:3]), *names)

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + path id (2 bytes) + name (1 byte at least)
        # + ',' + new name (at least 1 byte) = 6
        return 6

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        ret = super()._get_spec_data()
        ret.extend(b',')

        return ret + self.__new_name

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        dict_ret = super()._get_spec_data_dict()
        dict_ret.update({DictKeys.NEW_NAME: self.__new_name})

        return dict_ret


class RenameCmdResponse(FSCmd):
    """
    This class represents a rename file system command response.

    Command response is received as a :class:`.RenameCmdRequest`.
    """

    def __init__(self, status):
        """
        Class constructor. Instantiates a new :class:`.RenameCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(FSCmdType.RENAME, direction=self.RESPONSE,
                         status=status)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.RenameCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 2.
                (cmd id + status = 2).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.RENAME:
            raise InvalidPacketException(
                message="This command is not a Rename File command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        return RenameCmdResponse(cmd.status_value)


class DeleteCmdRequest(FileIdNameCmd):
    """
    This class represents a delete file system command request.
    All files in a directory must be deleted before removing the directory.
    On XBee 3 802.15.4, DigiMesh, and Zigbee, deleted files are marked as
    as unusable space unless they are at the "end" of the file system
    (most-recently created). On these products, deleting a file triggers
    recovery of any deleted file space at the end of the file system, and can
    lead to a delayed response.

    Command response is received as a :class:`.DeleteCmdResponse`.
    """

    def __init__(self, path_id, name):
        """
        Class constructor. Instantiates a new :class:`.DeleteCmdRequest`
        object with the provided parameters.

        Args:
            path_id (Integer): Directory path id. Set to 0x0000 for the root
                directory (/).
            name (String or bytearray): The name of the file/directory to
                delete relative to `path_id`. Its maximum length is 252 chars.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FileIdNameCmd`
        """
        if not isinstance(path_id, int):
            raise ValueError("Directory path id must be an integer")
        if not isinstance(name, (str, bytearray, bytes)):
            raise ValueError("Name must be a string or bytearray")
        super().__init__(FSCmdType.DELETE, path_id, name, direction=self.REQUEST)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.DeleteCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 4.
                (cmd id + path id (2 bytes) + name (at least 1 byte) = 4 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FileIdNameCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DELETE:
            raise InvalidPacketException(
                message="This command is not a Delete File command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return DeleteCmdRequest(utils.bytes_to_int(raw[1:3]), raw[3:])


class DeleteCmdResponse(FSCmd):
    """
    This class represents a delete file system command response.

    Command response is received as a :class:`.DeleteCmdRequest`.
    """

    def __init__(self, status):
        """
        Class constructor. Instantiates a new :class:`.DeleteCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(FSCmdType.DELETE, direction=self.RESPONSE,
                         status=status)

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.DeleteCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 2.
                (cmd id + status = 2).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.DELETE:
            raise InvalidPacketException(
                message="This command is not a Delete File command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        return DeleteCmdResponse(cmd.status_value)


class VolStatCmdRequest(FSCmd):
    """
    This class represents a volume stat file system command request.
    Formatting the file system takes time, and any other requests fails until
    it completes and sends a response.

    Command response is received as a :class:`.VolStatCmdResponse`.
    """

    def __init__(self, name):
        """
        Class constructor. Instantiates a new :class:`.VolStatCmdRequest`
        object with the provided parameters.

        Args:
            name (String or bytearray): The name of the volume. Its maximum
                length is 254 characters.

        Raises:
            ValueError: If `name` is invalid.

        .. seealso::
           | :class:`.FSCmd`
        """
        if not isinstance(name, (str, bytearray, bytes)):
            raise ValueError("Name must be a string or bytearray")
        max_len = 255 - 1  # cmd_id (1)
        if not name or len(name) > max_len:
            raise ValueError(
                "Name cannot be empty and cannot exceed %d chars" % max_len)

        super().__init__(FSCmdType.STAT, direction=self.REQUEST)

        if isinstance(name, str):
            self._name = name.encode('utf8', errors='ignore')
        else:
            self._name = name

    @property
    def name(self):
        """
        Returns the name of the volume.

        Returns:
            String: The volume name.
        """
        return self._name.decode(encoding='utf8', errors='ignore')

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.VolStatCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 2.
                (cmd id + name (at least 1 byte) = 2 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.STAT:
            raise InvalidPacketException(
                message="This command is not a Volume Stat command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return VolStatCmdRequest(raw[1:])

    @staticmethod
    def _get_min_len(status=None):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + name (at least 1 byte) = 2
        return 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data`
        """
        return self._name

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_spec_data_dict`
        """
        return {DictKeys.NAME: self._name}


class VolStatCmdResponse(FSCmd):
    """
    This class represents a stat file system command response.

    Command response is received as a :class:`.VolStatCmdRequest`.
    """

    def __init__(self, status, bytes_used=None, bytes_free=None, bytes_bad=None):
        """
        Class constructor. Instantiates a new :class:`.VolStatCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            bytes_used (Integer, optional, default=`None`): Number of used bytes.
            bytes_free (Integer, optional, default=`None`): Number of free bytes.
            bytes_bad (Integer, optional, default=`None`): Number of bad bytes.
                For XBee 3 802.15.4, DigiMesh, and Zigbee, this represents
                space used by deleted files.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCmd`
        """
        if bytes_used and bytes_used not in range(0, 0x100000000):
            raise ValueError("Used bytes must be between 0 and 0xFFFFFFFF")
        if bytes_free and bytes_free not in range(0, 0x100000000):
            raise ValueError("Free bytes must be between 0 and 0xFFFFFFFF")
        if bytes_bad and bytes_bad not in range(0, 0x100000000):
            raise ValueError("Bad bytes must be between 0 and 0xFFFFFFFF")

        super().__init__(FSCmdType.STAT, direction=self.RESPONSE,
                         status=status)

        self._bytes_used = bytes_used
        self._bytes_free = bytes_free
        self._bytes_bad = bytes_bad

    @property
    def bytes_used(self):
        """
        Returns the used space on volume.

        Returns:
            Integer: Number of used bytes.
        """
        return self._bytes_used

    @property
    def bytes_free(self):
        """
        Returns the available space on volume.

        Returns:
            Integer: Number of free bytes.
        """
        return self._bytes_free

    @property
    def bytes_bad(self):
        """
        Returns "bad" bytes on volume. For XBee 3 802.15.4, DigiMesh,
        and Zigbee, this represents space used by deleted files.

        Returns:
            Integer: Number of bad bytes.
        """
        return self._bytes_bad

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.VolStatCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 14.
                (cmd id + status + used (4 bytes) + free (4 bytes) + bad (4 bytes) = 14)
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = super().create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.STAT:
            raise InvalidPacketException(
                message="This command is not a Volume Stat command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        return VolStatCmdResponse(
            cmd.status_value,
            bytes_used=utils.bytes_to_int(raw[2:6]) if ok_status else None,
            bytes_free=utils.bytes_to_int(raw[6:10]) if ok_status else None,
            bytes_bad=utils.bytes_to_int(raw[10:14]) if ok_status else None)

    @staticmethod
    def _get_min_len(status=FSCommandStatus.SUCCESS.code):
        """
        Override method.

        .. seealso::
           | :meth:`.FSCmd._get_min_len`
        """
        # cmd id + status + used (4 bytes) + free (4 bytes) + bad (4 bytes) = 14
        return 14 if status == FSCommandStatus.SUCCESS.code else 2

    def _get_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data`
        """
        ret = bytearray()
        if self._status == FSCommandStatus.SUCCESS.code:
            ret = utils.int_to_bytes(self._bytes_used, num_bytes=4)
            ret += utils.int_to_bytes(self._bytes_free, num_bytes=4)
            return ret + utils.int_to_bytes(self._bytes_bad, num_bytes=4)

        return ret

    def _get_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.FileIdCmd._get_spec_data_dict`
        """
        if self._status == FSCommandStatus.SUCCESS.code:
            return {DictKeys.BYTES_USED: self._bytes_used,
                    DictKeys.BYTES_FREE: self._bytes_free,
                    DictKeys.BYTES_BAD: self._bytes_bad}

        return {}


class VolFormatCmdRequest(VolStatCmdRequest):
    """
    This class represents a volume format file system command request.

    Command response is received as a :class:`.VolFormatCmdResponse`.
    """

    def __init__(self, name):
        """
        Class constructor. Instantiates a new :class:`.VolFormatCmdRequest`
        object with the provided parameters.

        Args:
            name (String or bytearray): The name of the volume. Its maximum
                length is 254 chars.

        Raises:
            ValueError: If `name` is invalid.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(name)
        self._cmd_type = FSCmdType.FORMAT

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.REQUEST):
        """
        Override method.
        Direction must be 0.

        Returns:
            :class:`.VolFormatCmdRequest`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 2.
                (cmd id + name (at least 1 byte) = 2 bytes).
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 0.

        .. seealso::
           | :meth:`.FSCmd.create_cmd`
        """
        cmd = FSCmd.create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FORMAT:
            raise InvalidPacketException(
                message="This command is not a Volume Format command")
        if direction != FSCmd.REQUEST:
            raise InvalidPacketException(message="Direction must be 0")

        return VolFormatCmdRequest(raw[1:])


class VolFormatCmdResponse(VolStatCmdResponse):
    """
    This class represents a format file system command response.

    Command response is received as a :class:`.VolStatCmdRequest`.
    """

    def __init__(self, status, bytes_used=None, bytes_free=None, bytes_bad=None):
        """
        Class constructor. Instantiates a new :class:`.VolFormatCmdResponse`
        object with the provided parameters.

        Args:
            status (:class:`.FSCommandStatus` or Integer): Status of the file
                system command execution.
            bytes_used (Integer, optional, default=`None`): Number of used bytes.
            bytes_free (Integer, optional, default=`None`): Number of free bytes.
            bytes_bad (Integer, optional, default=`None`): Number of bad bytes.

        Raises:
            ValueError: If any of the parameters is invalid.

        .. seealso::
           | :class:`.FSCmd`
        """
        super().__init__(status, bytes_used=bytes_used, bytes_free=bytes_free,
                         bytes_bad=bytes_bad)
        self._cmd_type = FSCmdType.FORMAT

    @classmethod
    def create_cmd(cls, raw, direction=FSCmd.RESPONSE):
        """
        Override method.
        Direction must be 1.

        Returns:
            :class:`.VolFormatCmdResponse`.

        Raises:
            InvalidPacketException: If the bytearray length is less than 14.
                (cmd id + status + used (4 bytes) + free (4 bytes) + bad (4 bytes) = 14)
            InvalidPacketException: If the command type is not
                :class:`.FSCmdType` or direction is not 1.

        .. seealso::
           | :meth:`.FileIdCmd.create_cmd`
        """
        cmd = FSCmd.create_cmd(raw, direction=direction)
        if cmd.type != FSCmdType.FORMAT:
            raise InvalidPacketException(
                message="This command is not a Volume Format command")
        if direction != FSCmd.RESPONSE:
            raise InvalidPacketException(message="Direction must be 1")

        ok_status = cmd.status == FSCommandStatus.SUCCESS
        return VolFormatCmdResponse(
            cmd.status_value,
            bytes_used=utils.bytes_to_int(raw[2:6]) if ok_status else None,
            bytes_free=utils.bytes_to_int(raw[6:10]) if ok_status else None,
            bytes_bad=utils.bytes_to_int(raw[10:14]) if ok_status else None)
