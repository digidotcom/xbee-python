# Copyright 2020, 2021, Digi International Inc.
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
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.models.address import XBee64BitAddress
from digi.xbee.models.filesystem import FSCmd, FSCmdType, OpenFileCmdRequest, \
    OpenFileCmdResponse, CloseFileCmdRequest, CloseFileCmdResponse, \
    ReadFileCmdRequest, ReadFileCmdResponse, WriteFileCmdRequest, \
    WriteFileCmdResponse, HashFileCmdRequest, HashFileCmdResponse, \
    CreateDirCmdRequest, CreateDirCmdResponse, OpenDirCmdRequest, \
    OpenDirCmdResponse, CloseDirCmdRequest, CloseDirCmdResponse, \
    ReadDirCmdRequest, ReadDirCmdResponse, GetPathIdCmdRequest, \
    RenameCmdRequest, GetPathIdCmdResponse, RenameCmdResponse, \
    DeleteCmdRequest, DeleteCmdResponse, VolStatCmdRequest,\
    VolStatCmdResponse, VolFormatCmdRequest, VolFormatCmdResponse, UnknownFSCmd
from digi.xbee.models.options import TransmitOptions
from digi.xbee.models.mode import OperatingMode
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys


class FSRequestPacket(XBeeAPIPacket):
    """
    This class represents a File System Request. Packet is built using the
    parameters of the constructor or providing a valid API payload.

    A File System Request allows to access the filesystem and perform
    different operations.

    Command response is received as an :class:`.FSResponsePacket`.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 7

    def __init__(self, frame_id, command, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.FSRequestPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): Frame ID of the packet.
            command (:class:`.FSCmd` or bytearray): File system command to
                execute.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: If `frame_id` is less than 0 or greater than 255.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.

        .. seealso::
           | :class:`.FSCmd`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id not in range(0, 256):
            raise ValueError("Frame id must be between 0 and 255.")

        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, "
                "not {!r}".format(command.__class__.__name__))

        super().__init__(ApiFrameType.FILE_SYSTEM_REQUEST, op_mode=op_mode)

        self._frame_id = frame_id

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command)

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.FSRequestPacket`

        Raises:
            InvalidPacketException: If the bytearray length is less than 7 +
                the minimum length of the command.
                (start delim. + length (2 bytes) + frame type + frame id
                + fs cmd id + checksum + cmd data = 7 bytes + cmd data).
            InvalidPacketException: If the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is different from
                :attr:`.ApiFrameType.FILE_SYSTEM_REQUEST`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=FSRequestPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.FILE_SYSTEM_REQUEST.code:
            raise InvalidPacketException(
                message="This packet is not a File System request packet.")

        return FSRequestPacket(raw[4], raw[5:-1], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        return self.__cmd.output()

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return self.__cmd.to_dict()

    @property
    def command(self):
        """
        Returns the file system command of the packet.

        Returns:
            String: File system command of the packet.
        """
        return self.__cmd

    @command.setter
    def command(self, command):
        """
        Sets the file system command of the packet.

        Args:
            command (:class:`.FSCmd` or Bytearray): New file system command.

        Raises:
            ValueError: If `command` is invalid.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.
        """
        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, not {!r}".format(
                    command.__class__.__name__))

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command)


class FSResponsePacket(XBeeAPIPacket):
    """
    This class represents a File System Response. Packet is built using the
    parameters of the constructor or providing a valid API payload.

    This packet is received in response of an :class:`.FSRequestPacket`.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, command, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.FSResponsePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): The frame ID of the packet.
            command (:class:`.FSCmd` or bytearray): File system command to
                execute.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: If `frame_id` is less than 0 or greater than 255.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.

        .. seealso::
           | :class:`.FSCmd`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id not in range(0, 256):
            raise ValueError("Frame id must be between 0 and 255.")

        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, "
                "not {!r}".format(command.__class__.__name__))

        super().__init__(ApiFrameType.FILE_SYSTEM_RESPONSE, op_mode=op_mode)

        self._frame_id = frame_id

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command, direction=FSCmd.RESPONSE)

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.FSResponsePacket`

        Raises:
            InvalidPacketException: If the bytearray length is less than 8 +
                the minimum length of the command.
                (start delim. + length (2 bytes) + frame type + frame id
                + fs cmd id + status + checksum + cmd data = 8 bytes + cmd data).
            InvalidPacketException: If the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is different from
                :attr:`.ApiFrameType.FILE_SYSTEM_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=FSResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.FILE_SYSTEM_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a File System response packet.")

        return FSResponsePacket(raw[4], raw[5:-1], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        return self.__cmd.output()

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return self.__cmd.to_dict()

    @property
    def command(self):
        """
        Returns the file system command of the packet.

        Returns:
            String: File system command of the packet.
        """
        return self.__cmd

    @command.setter
    def command(self, command):
        """
        Sets the file system command of the packet.

        Args:
            command (:class:`.FSCmd` or Bytearray): New file system command.

        Raises:
            ValueError: If `command` is invalid.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.
        """
        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, not {!r}".format(
                    command.__class__.__name__))

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command, direction=FSCmd.RESPONSE)


class RemoteFSRequestPacket(XBeeAPIPacket):
    """
    This class represents a remote File System Request. Packet is built using
    the parameters of the constructor or providing a valid API payload.

    Used to access the filesystem on a remote device and perform different
    operations.

    Remote command options are set as a bitfield.

    If configured, command response is received as a
    :class:`.RemoteFSResponsePacket`.

    .. seealso::
       | :class:`.RemoteFSResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 16

    def __init__(self, frame_id, x64bit_addr, command,
                 transmit_options=TransmitOptions.NONE.value, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.RemoteFSRequestPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): Frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit destination address.
            command (:class:`.FSCmd` or bytearray): File system command to
                execute.
            transmit_options (Integer, optional, default=`TransmitOptions.NONE.value`): Bitfield of
                supported transmission options.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: If `frame_id` is less than 0 or greater than 255.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.

        .. seealso::
           | :class:`.FSCmd`
           | :class:`.TransmitOptions`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id not in range(0, 256):
            raise ValueError("Frame id must be between 0 and 255.")

        if x64bit_addr is None:
            raise ValueError("64-bit destination address cannot be None.")

        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, "
                "not {!r}".format(command.__class__.__name__))

        super().__init__(ApiFrameType.REMOTE_FILE_SYSTEM_REQUEST, op_mode=op_mode)

        self._frame_id = frame_id

        self.__x64bit_addr = x64bit_addr
        self.__tx_opts = transmit_options

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command)

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RemoteFSRequestPacket`

        Raises:
            InvalidPacketException: If the bytearray length is less than 7 +
                the minimum length of the command.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64bit addr. + transmit options + fs cmd id + checksum
                + cmd data = 16 bytes + cmd data).
            InvalidPacketException: If the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is different from
                :attr:`.ApiFrameType.REMOTE_FILE_SYSTEM_REQUEST`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RemoteFSRequestPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REMOTE_FILE_SYSTEM_REQUEST.code:
            raise InvalidPacketException(
                message="This packet is not a Remote File System request packet.")

        return RemoteFSRequestPacket(raw[4], XBee64BitAddress(raw[5:13]),
                                     raw[14:-1], transmit_options=raw[13], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64bit_addr.address
        ret.append(self.__tx_opts)
        ret += self.__cmd.output()

        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        ret_dict = {DictKeys.X64BIT_ADDR: self.__x64bit_addr.address,
                    DictKeys.TRANSMIT_OPTIONS: self.__tx_opts}
        ret_dict.update(self.__cmd.to_dict())

        return ret_dict

    @property
    def x64bit_dest_addr(self):
        """
        Returns the 64-bit destination address.

        Returns:
            :class:`.XBee64BitAddress`: 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_dest_addr.setter
    def x64bit_dest_addr(self, addr):
        """
        Sets the 64-bit destination address.

        Args:
            addr (:class:`.XBee64BitAddress`): New 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = addr

    @property
    def command(self):
        """
        Returns the file system command of the packet.

        Returns:
            String: File system command of the packet.
        """
        return self.__cmd

    @command.setter
    def command(self, command):
        """
        Sets the file system command of the packet.

        Args:
            command (:class:`.FSCmd` or Bytearray): New file system command.

        Raises:
            ValueError: If `command` is invalid.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.
        """
        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, not {!r}".format(
                    command.__class__.__name__))

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command)

    @property
    def transmit_options(self):
        """
        Returns the transmit options bitfield.

        Returns:
            Integer: Transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, options):
        """
        Sets the transmit options bitfield.

        Args:
            options (Integer): New transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        self.__tx_opts = options


class RemoteFSResponsePacket(XBeeAPIPacket):
    """
    This class represents a Remote File System Response. Packet is built using
    the parameters of the constructor or providing a valid API payload.

    This packet is received in response of an :class:`.RemoteFSRequestPacket`.

    .. seealso::
       | :class:`.RemoteFSRequestPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 17

    def __init__(self, frame_id, x64bit_addr, command, rx_options,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.RemoteFSResponsePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): The frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit source address.
            command (:class:`.FSCmd` or bytearray): File system command to
                execute.
            rx_options (Integer): Bitfield indicating the receive options.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: If `frame_id` is less than 0 or greater than 255.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.

        .. seealso::
           | :class:`.FSCmd`
           | :class:`.ReceiveOptions`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id not in range(0, 256):
            raise ValueError("Frame id must be between 0 and 255.")

        if x64bit_addr is None:
            raise ValueError("64-bit source address cannot be None.")

        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, "
                "not {!r}".format(command.__class__.__name__))

        super().__init__(ApiFrameType.REMOTE_FILE_SYSTEM_RESPONSE, op_mode=op_mode)

        self._frame_id = frame_id

        self.__x64bit_addr = x64bit_addr
        self.__rx_opts = rx_options

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command, direction=FSCmd.RESPONSE)

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RemoteFSResponsePacket`

        Raises:
            InvalidPacketException: If the bytearray length is less than 8 +
                the minimum length of the command.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64bit addr. + receive options + fs cmd id + status
                + checksum + cmd data = 17 bytes + cmd data).
            InvalidPacketException: If the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: If the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: If the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: If the frame type is different from
                :attr:`.ApiFrameType.REMOTE_FILE_SYSTEM_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RemoteFSResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REMOTE_FILE_SYSTEM_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a Remote File System response packet.")

        return RemoteFSResponsePacket(raw[4], XBee64BitAddress(raw[5:13]),
                                      raw[14:-1], raw[13], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return True

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        cmd_array = self.__cmd.output()

        ret = self.__x64bit_addr.address
        ret.append(self.__rx_opts)
        ret.append(cmd_array[0])
        ret += cmd_array[1:]

        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        ret_dict = {DictKeys.X64BIT_ADDR: self.__x64bit_addr.address,
                    DictKeys.RECEIVE_OPTIONS: self.__rx_opts}
        ret_dict.update(self.__cmd.to_dict())

        return ret_dict

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): New 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def command(self):
        """
        Returns the file system command of the packet.

        Returns:
            String: File system command of the packet.
        """
        return self.__cmd

    @command.setter
    def command(self, command):
        """
        Sets the file system command of the packet.

        Args:
            command (:class:`.FSCmd` or Bytearray): New file system command.

        Raises:
            ValueError: If `command` is invalid.
            TypeError: If `command` is not a :class:`.FSCmd` or a bytearray.
        """
        if not isinstance(command, (bytearray, FSCmd)):
            raise TypeError(
                "Command must be a bytearray or a FSCmd, not {!r}".format(
                    command.__class__.__name__))

        self.__cmd = command
        if isinstance(command, bytearray):
            self.__cmd = build_fs_command(command, direction=FSCmd.RESPONSE)

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: Receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, options):
        """
        Sets the receive options bitfield.

        Args:
            options (Integer): New receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = options


def build_fs_command(cmd_bytearray, direction=FSCmd.REQUEST):
    """
    Creates a file system command from raw data.

    Args:
        cmd_bytearray (Bytearray): Raw data of the packet to build.
        direction (Integer, optional, default=0): If this command is a request
            (0) or a response (1).

    Raises:
        InvalidPacketException: If `cmd_bytearray` is not a bytearray or its
            length is less than 1 for requests 2 for responses.

    .. seealso::
       | :class:`.FSCmd`
    """
    if not isinstance(cmd_bytearray, bytearray):
        raise TypeError("Command must be a bytearray")
    if direction not in (FSCmd.REQUEST, FSCmd.RESPONSE):
        raise ValueError("Direction must be 0 or 1")
    min_len = 2 if direction == FSCmd.RESPONSE else 1
    if len(cmd_bytearray) < min_len:
        raise InvalidPacketException(
            message="Command bytearray must have, at least, %d bytes" % min_len)

    cmd_type = FSCmdType.get(cmd_bytearray[0])

    if cmd_type == FSCmdType.FILE_OPEN:
        if direction == FSCmd.REQUEST:
            return OpenFileCmdRequest.create_cmd(cmd_bytearray)

        return OpenFileCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.FILE_CLOSE:
        if direction == FSCmd.REQUEST:
            return CloseFileCmdRequest.create_cmd(cmd_bytearray)

        return CloseFileCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.FILE_READ:
        if direction == FSCmd.REQUEST:
            return ReadFileCmdRequest.create_cmd(cmd_bytearray)

        return ReadFileCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.FILE_WRITE:
        if direction == FSCmd.REQUEST:
            return WriteFileCmdRequest.create_cmd(cmd_bytearray)

        return WriteFileCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.FILE_HASH:
        if direction == FSCmd.REQUEST:
            return HashFileCmdRequest.create_cmd(cmd_bytearray)

        return HashFileCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.DIR_CREATE:
        if direction == FSCmd.REQUEST:
            return CreateDirCmdRequest.create_cmd(cmd_bytearray)

        return CreateDirCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.DIR_OPEN:
        if direction == FSCmd.REQUEST:
            return OpenDirCmdRequest.create_cmd(cmd_bytearray)

        return OpenDirCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.DIR_CLOSE:
        if direction == FSCmd.REQUEST:
            return CloseDirCmdRequest.create_cmd(cmd_bytearray)

        return CloseDirCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.DIR_READ:
        if direction == FSCmd.REQUEST:
            return ReadDirCmdRequest.create_cmd(cmd_bytearray)

        return ReadDirCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.GET_PATH_ID:
        if direction == FSCmd.REQUEST:
            return GetPathIdCmdRequest.create_cmd(cmd_bytearray)

        return GetPathIdCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.RENAME:
        if direction == FSCmd.REQUEST:
            return RenameCmdRequest.create_cmd(cmd_bytearray)

        return RenameCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.DELETE:
        if direction == FSCmd.REQUEST:
            return DeleteCmdRequest.create_cmd(cmd_bytearray)

        return DeleteCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.STAT:
        if direction == FSCmd.REQUEST:
            return VolStatCmdRequest.create_cmd(cmd_bytearray)

        return VolStatCmdResponse.create_cmd(cmd_bytearray)

    if cmd_type == FSCmdType.FORMAT:
        if direction == FSCmd.REQUEST:
            return VolFormatCmdRequest.create_cmd(cmd_bytearray)

        return VolFormatCmdResponse.create_cmd(cmd_bytearray)

    return UnknownFSCmd(cmd_bytearray, direction=direction)
