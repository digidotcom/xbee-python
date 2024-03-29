# Copyright 2017-2022, Digi International Inc.
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

from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.address import XBee16BitAddress, XBee64BitAddress
from digi.xbee.models.status import ATCommandStatus, DiscoveryStatus, TransmitStatus, ModemStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.util import utils
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.io import IOSample, IOLine


class ATCommPacket(XBeeAPIPacket):
    """
    This class represents an AT command packet.

    Used to query or set module parameters on the local device. This API
    command applies changes after executing the command. (Changes made to
    module parameters take effect once changes are applied.).

    Command response is received as an :class:`.ATCommResponsePacket`.

    .. seealso::
       | :class:`.ATCommResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, command, parameter=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.ATCommPacket` object
        with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            command (String or bytearray): AT command of the packet.
            parameter (Bytearray, optional): the AT command parameter.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different from 2.

        .. seealso::
            | :class:`.XBeeAPIPacket`
        """
        if not isinstance(command, (str, bytearray, bytes)):
            raise ValueError("Command must be a string or bytearray")
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.AT_COMMAND, op_mode=op_mode)
        self.__cmd = _encode_at_cmd(command)
        self.__param = parameter
        self._frame_id = frame_id

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ATCommPacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type
                + frame id + command (2 bytes) + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.AT_COMMAND`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=ATCommPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.AT_COMMAND.code:
            raise InvalidPacketException(message="This packet is not an AT command packet.")

        return ATCommPacket(
            raw[4], raw[5:7],
            parameter=raw[7:-1] if len(raw) > ATCommPacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

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
        if self.__param is not None:
            return bytearray(self.__cmd) + self.__param
        return bytearray(self.__cmd)

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.COMMAND: self.__cmd,
                DictKeys.PARAMETER: list(self.__param) if self.__param is not None else None}

    @property
    def command(self):
        """
        Returns the AT command of the packet.

        Returns:
            String: the AT command of the packet.
        """
        return _decode_at_cmd(self.__cmd)

    @command.setter
    def command(self, command):
        """
        Sets the AT command of the packet.

        Args:
            command (String or bytearray): New AT command of the packet.
                Must have length = 2.

        Raises:
            ValueError: if length of `command` is different from 2.
        """
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        self.__cmd = _encode_at_cmd(command)

    @property
    def parameter(self):
        """
        Returns the parameter of the packet.

        Returns:
            Bytearray: the parameter of the packet.
        """
        return self.__param

    @parameter.setter
    def parameter(self, param):
        """
        Sets the parameter of the packet.

        Args:
            param (Bytearray): the new parameter of the packet.
        """
        self.__param = param


class ATCommQueuePacket(XBeeAPIPacket):
    """
    This class represents an AT command Queue packet.

    Used to query or set module parameters on the local device.

    In contrast to the :class:`.ATCommPacket` API packet, new parameter
    values are queued and not applied until either an :class:`.ATCommPacket`
    is sent or the `applyChanges()` method of the :class:`.XBeeDevice`
    class is issued.

    Command response is received as an :class:`.ATCommResponsePacket`.

    .. seealso::
       | :class:`.ATCommResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 8

    def __init__(self, frame_id, command, parameter=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.ATCommQueuePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            command (String or bytearray): the AT command of the packet.
            parameter (Bytearray, optional): the AT command parameter. Optional.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different from 2.

        .. seealso::
            | :class:`.XBeeAPIPacket`
        """
        if not isinstance(command, (str, bytearray, bytes)):
            raise ValueError("Command must be a string or bytearray")
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.AT_COMMAND_QUEUE, op_mode=op_mode)
        self.__cmd = _encode_at_cmd(command)
        self.__param = parameter
        self._frame_id = frame_id

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ATCommQueuePacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 8.
                (start delim. + length (2 bytes) + frame type
                + frame id + command + checksum = 8 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.AT_COMMAND_QUEUE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=ATCommQueuePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.AT_COMMAND_QUEUE.code:
            raise InvalidPacketException(message="This packet is not an AT command Queue packet.")

        return ATCommQueuePacket(
            raw[4], raw[5:7],
            parameter=raw[7:-1] if len(raw) > ATCommQueuePacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

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
        if self.__param is not None:
            return bytearray(self.__cmd) + self.__param
        return bytearray(self.__cmd)

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.COMMAND: self.__cmd,
                DictKeys.PARAMETER: list(self.__param) if self.__param is not None else None}

    @property
    def command(self):
        """
        Returns the AT command of the packet.

        Returns:
            String: the AT command of the packet.
        """
        return _decode_at_cmd(self.__cmd)

    @command.setter
    def command(self, command):
        """
        Sets the AT command of the packet.

        Args:
            command (String or bytearray): New AT command of the packet.
                Must have length = 2.

        Raises:
            ValueError: if length of `command` is different from 2.
        """
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        self.__cmd = _encode_at_cmd(command)

    @property
    def parameter(self):
        """
        Returns the parameter of the packet.

        Returns:
            Bytearray: the parameter of the packet.
        """
        return self.__param

    @parameter.setter
    def parameter(self, param):
        """
        Sets the parameter of the packet.

        Args:
            param (Bytearray): the new parameter of the packet.
        """
        self.__param = param


class ATCommResponsePacket(XBeeAPIPacket):
    """
    This class represents an AT command response packet.

    In response to an AT command message, the module will send an AT command
    response message. Some commands will send back multiple frames (for example,
    the `ND` - Node Discover command).

    This packet is received in response of an :class:`.ATCommPacket`.

    Response also includes an :class:`.ATCommandStatus` object with the status
    of the AT command.

    .. seealso::
       | :class:`.ATCommPacket`
       | :class:`.ATCommandStatus`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 9

    def __init__(self, frame_id, command, response_status=ATCommandStatus.OK,
                 comm_value=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.ATCommResponsePacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet. Must be between 0 and 255.
            command (String or bytearray): the AT command of the packet.
            response_status (:class:`.ATCommandStatus` or Integer): the status of the AT command.
            comm_value (Bytearray, optional): the AT command response value.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different from 2.

        .. seealso::
           | :class:`.ATCommandStatus`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")
        if not isinstance(command, (str, bytearray, bytes)):
            raise ValueError("Command must be a string or bytearray")
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        if response_status is None:
            response_status = ATCommandStatus.OK.code
        elif not isinstance(response_status, (ATCommandStatus, int)):
            raise TypeError("Response status must be ATCommandStatus or int not {!r}".format(
                response_status.__class__.__name__))

        super().__init__(ApiFrameType.AT_COMMAND_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__cmd = _encode_at_cmd(command)
        if isinstance(response_status, ATCommandStatus):
            self.__resp_st = response_status.code
        elif 0 <= response_status <= 255:
            self.__resp_st = response_status
        else:
            raise ValueError("Response status must be between 0 and 255.")
        self.__comm_val = comm_value

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ATCommResponsePacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 9.
                (start delim. + length (2 bytes) + frame type + frame id
                + at command (2 bytes) + command status + checksum = 9 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.AT_COMMAND_RESPONSE`.
            InvalidPacketException: if the command status field is not a valid
                value. See :class:`.ATCommandStatus`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=ATCommResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.AT_COMMAND_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not an AT command response packet.")
        if ATCommandStatus.get(raw[7]) is None:
            raise InvalidPacketException(message="Invalid command status.")

        return ATCommResponsePacket(
            raw[4], raw[5:7], raw[7],
            comm_value=raw[8:-1] if len(raw) > ATCommResponsePacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

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
        ret = bytearray(self.__cmd)
        ret.append(self.__resp_st)
        if self.__comm_val is not None:
            ret += self.__comm_val
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.COMMAND: self.__cmd,
                DictKeys.AT_CMD_STATUS: self.__resp_st,
                DictKeys.RF_DATA: list(self.__comm_val) if self.__comm_val is not None else None}

    @property
    def command(self):
        """
        Returns the AT command of the packet.

        Returns:
            String: the AT command of the packet.
        """
        return _decode_at_cmd(self.__cmd)

    @command.setter
    def command(self, command):
        """
        Sets the AT command of the packet.

        Args:
            command (String or bytearray): New AT command of the packet.
                Must have length = 2.

        Raises:
            ValueError: if length of `command` is different from 2.
        """
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        self.__cmd = _encode_at_cmd(command)

    @property
    def command_value(self):
        """
        Returns the AT command response value.

        Returns:
            Bytearray: the AT command response value.
        """
        return self.__comm_val

    @command_value.setter
    def command_value(self, __comm_value):
        """
        Sets the AT command response value.

        Args:
            __comm_value (Bytearray): the new AT command response value.
        """
        self.__comm_val = __comm_value

    @property
    def status(self):
        """
        Returns the AT command response status of the packet.

        Returns:
            :class:`.ATCommandStatus`: the AT command response status of the packet.

        .. seealso::
           | :class:`.ATCommandStatus`
        """
        return ATCommandStatus.get(self.__resp_st)

    @property
    def real_status(self):
        """
        Returns the AT command response status of the packet.

        Returns:
            Integer: the AT command response status of the packet.
        """
        return self.__resp_st

    @status.setter
    def status(self, response_status):
        """
        Sets the AT command response status of the packet

        Args:
            response_status (:class:`.ATCommandStatus`) : the new AT command
                response status of the packet.

        .. seealso::
           | :class:`.ATCommandStatus`
        """
        if response_status is None:
            raise ValueError("Response status cannot be None")

        if isinstance(response_status, ATCommandStatus):
            self.__resp_st = response_status.code
        elif isinstance(response_status, int):
            if 0 <= response_status <= 255:
                self.__resp_st = response_status
            else:
                raise ValueError("Response status must be between 0 and 255.")
        else:
            raise TypeError(
                "Response status must be ATCommandStatus or int not {!r}".
                format(response_status.__class__.__name__))


class ReceivePacket(XBeeAPIPacket):
    """
    This class represents a receive packet. Packet is built using the parameters
    of the constructor or providing a valid byte array.

    When the module receives an RF packet, it is sent out the UART using this
    message type.

    This packet is received when external devices send transmit request
    packets to this module.

    Among received data, some options can also be received indicating
    transmission parameters.

    .. seealso::
       | :class:`.TransmitPacket`
       | :class:`.ReceiveOptions`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 16

    def __init__(self, x64bit_addr, x16bit_addr, rx_options, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.ReceivePacket` object
        with the provided parameters.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit source address.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit source address.
            rx_options (Integer): bitfield indicating the receive options.
            rf_data (Bytearray, optional): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ReceiveOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.RECEIVE_PACKET, op_mode=op_mode)
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__rx_opts = rx_options
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ATCommResponsePacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 16.
                (start delim. + length (2 bytes) + frame type + 64bit addr.
                + 16bit addr. + Receive options + checksum = 16 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.RECEIVE_PACKET`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=ReceivePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.RECEIVE_PACKET.code:
            raise InvalidPacketException(message="This packet is not a receive packet.")
        return ReceivePacket(
            XBee64BitAddress(raw[4:12]), XBee16BitAddress(raw[12:14]), raw[14],
            rf_data=raw[15:-1] if len(raw) > ReceivePacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return utils.is_bit_enabled(self.__rx_opts, 1)

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64bit_addr.address
        ret += self.__x16bit_addr.address
        ret.append(self.__rx_opts)
        if self.__data is not None:
            return ret + self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR:     self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR:     self.__x16bit_addr.address,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts,
                DictKeys.RF_DATA:         list(self.__data) if self.__data is not None else None}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2 - 8  # Remove 16-bit and 64-bit addresses

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()


class RemoteATCommandPacket(XBeeAPIPacket):
    """
    This class represents a Remote AT command Request packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    Used to query or set module parameters on a remote device. For parameter
    changes on the remote device to take effect, changes must be applied, either
    by setting the apply changes options bit, or by sending an `AC` command
    to the remote node.

    Remote command options are set as a bitfield.

    If configured, command response is received as a :class:`.RemoteATCommandResponsePacket`.

    .. seealso::
       | :class:`.RemoteATCommandResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 19

    def __init__(self, frame_id, x64bit_addr, x16bit_addr, tx_options,
                 command, parameter=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.RemoteATCommandPacket`
        object with the provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit destination address.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit destination address.
            tx_options (Integer): bitfield of supported transmission options.
            command (String or bytearray): AT command to send.
            parameter (Bytearray, optional): AT command parameter.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different from 2.

        .. seealso::
           | :class:`.RemoteATCmdOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")
        if not isinstance(command, (str, bytearray, bytes)):
            raise ValueError("Command must be a string or bytearray")
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))

        super().__init__(ApiFrameType.REMOTE_AT_COMMAND_REQUEST, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__tx_opts = tx_options
        self.__cmd = _encode_at_cmd(command)
        self.__param = parameter

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RemoteATCommandPacket`

        Raises:
            InvalidPacketException: if the Bytearray length is less than 19.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64bit addr. + 16bit addr. + transmit options
                + command (2 bytes) + checksum = 19 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.REMOTE_AT_COMMAND_REQUEST`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=RemoteATCommandPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REMOTE_AT_COMMAND_REQUEST.code:
            raise InvalidPacketException(
                message="This packet is not a remote AT command request packet.")

        return RemoteATCommandPacket(
            raw[4], XBee64BitAddress(raw[5:13]), XBee16BitAddress(raw[13:15]),
            raw[15], raw[16:18],
            parameter=raw[18:-1] if len(raw) > RemoteATCommandPacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

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
        ret += self.__x16bit_addr.address
        ret.append(self.__tx_opts)
        ret += self.__cmd

        return ret if self.__param is None else ret + self.__param

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR: self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR: self.__x16bit_addr.address,
                DictKeys.TRANSMIT_OPTIONS: self.__tx_opts,
                DictKeys.COMMAND: self.__cmd,
                DictKeys.PARAMETER: list(self.__param) if self.__param is not None else None}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2 - 8  # Remove 16-bit and 64-bit addresses

    @property
    def x64bit_dest_addr(self):
        """
        Returns the 64-bit destination address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_dest_addr.setter
    def x64bit_dest_addr(self, x64bit_addr):
        """
        Sets the 64-bit destination address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_dest_addr(self):
        """
        Returns the 16-bit destination address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_dest_addr.setter
    def x16bit_dest_addr(self, x16bit_addr):
        """
        Sets the 16-bit destination address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def transmit_options(self):
        """
        Returns the transmit options bitfield.

        Returns:
            Integer: the transmit options bitfield.

        .. seealso::
           | :class:`.RemoteATCmdOptions`
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, transmit_options):
        """
        Sets the transmit options bitfield.

        Args:
            transmit_options (Integer): the new transmit options bitfield.

        .. seealso::
           | :class:`.RemoteATCmdOptions`
        """
        self.__tx_opts = transmit_options

    @property
    def parameter(self):
        """
        Returns the AT command parameter.

        Returns:
            Bytearray: the AT command parameter.
        """
        return self.__param

    @parameter.setter
    def parameter(self, parameter):
        """
        Sets the AT command parameter.

        Args:
            parameter (Bytearray): the new AT command parameter.
        """
        self.__param = parameter

    @property
    def command(self):
        """
        Returns the AT command.

        Returns:
            String: the AT command.
        """
        return _decode_at_cmd(self.__cmd)

    @command.setter
    def command(self, command):
        """
        Sets the AT command.

        Args:
            command (String or bytearray): New AT command.
        """
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        self.__cmd = _encode_at_cmd(command)


class RemoteATCommandResponsePacket(XBeeAPIPacket):
    """
    This class represents a remote AT command response packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    If a module receives a remote command response RF data frame in response
    to a remote AT command request, the module will send a remote AT command
    response message out the UART. Some commands may send back multiple frames,
    for example, Node Discover (`ND`) command.

    This packet is received in response of a :class:`.RemoteATCommandPacket`.

    Response also includes an object with the status of the AT command.

    .. seealso::
       | :class:`.RemoteATCommandPacket`
       | :class:`.ATCommandStatus`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 19

    def __init__(self, frame_id, x64bit_addr, x16bit_addr, command,
                 resp_status, comm_value=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.RemoteATCommandResponsePacket` object with the provided
        parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit source address
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit source address.
            command (String or bytearray): the AT command of the packet.
            resp_status (:class:`.ATCommandStatus` or Integer): the status of the AT command.
            comm_value (Bytearray, optional): the AT command response value. Optional.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different from 2.

        .. seealso::
           | :class:`.ATCommandStatus`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id > 255 or frame_id < 0:
            raise ValueError("frame_id must be between 0 and 255.")
        if not isinstance(command, (str, bytearray, bytes)):
            raise ValueError("Command must be a string or bytearray")
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        if resp_status is None:
            resp_status = ATCommandStatus.OK.code
        elif not isinstance(resp_status, (ATCommandStatus, int)):
            raise TypeError("Response status must be ATCommandStatus or int not {!r}".format(
                resp_status.__class__.__name__))

        super().__init__(ApiFrameType.REMOTE_AT_COMMAND_RESPONSE, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__cmd = _encode_at_cmd(command)
        if isinstance(resp_status, ATCommandStatus):
            self.__resp_st = resp_status.code
        elif 0 <= resp_status <= 255:
            self.__resp_st = resp_status
        else:
            raise ValueError("Response status must be between 0 and 255.")
        self.__comm_val = comm_value

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RemoteATCommandResponsePacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 19.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64bit addr. + 16bit addr. + receive options
                + command (2 bytes) + checksum = 19 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.REMOTE_AT_COMMAND_RESPONSE`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RemoteATCommandResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REMOTE_AT_COMMAND_RESPONSE.code:
            raise InvalidPacketException(
                message="This packet is not a remote AT command response packet.")

        value = None
        if len(raw) > RemoteATCommandResponsePacket.__MIN_PACKET_LENGTH:
            value = raw[18:-1]

        return RemoteATCommandResponsePacket(
            raw[4], XBee64BitAddress(raw[5:13]), XBee16BitAddress(raw[13:15]),
            raw[15:17], raw[17], comm_value=value, op_mode=operating_mode)

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
        ret += self.__x16bit_addr.address
        ret += self.__cmd
        ret.append(self.__resp_st)
        if self.__comm_val is not None:
            ret += self.__comm_val
        return ret

    def _get_api_packet_spec_data_dict(self):
        return {DictKeys.X64BIT_ADDR:   self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR:   self.__x16bit_addr.address,
                DictKeys.COMMAND:       self.__cmd,
                DictKeys.AT_CMD_STATUS: self.__resp_st,
                DictKeys.RF_DATA:       list(self.__comm_val) if self.__comm_val is not None else None}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2 - 8  # Remove 16-bit and 64-bit addresses

    @property
    def command(self):
        """
        Returns the AT command of the packet.

        Returns:
            String: the AT command of the packet.
        """
        return _decode_at_cmd(self.__cmd)

    @command.setter
    def command(self, command):
        """
        Sets the AT command of the packet.

        Args:
            command (String or bytearray): New AT command of the packet.
                Must have length = 2.

        Raises:
            ValueError: if length of `command` is different from 2.
        """
        if len(command) != 2:
            raise ValueError("Invalid command %s"
                             % str(command, encoding='utf8', errors='ignore'))
        self.__cmd = _encode_at_cmd(command)

    @property
    def command_value(self):
        """
        Returns the AT command response value.

        Returns:
            Bytearray: the AT command response value.
        """
        return self.__comm_val

    @command_value.setter
    def command_value(self, comm_value):
        """
        Sets the AT command response value.

        Args:
            comm_value (Bytearray): the new AT command response value.
        """
        self.__comm_val = comm_value

    @property
    def status(self):
        """
        Returns the AT command response status of the packet.

        Returns:
            :class:`.ATCommandStatus`: the AT command response status of the packet.

        .. seealso::
           | :class:`.ATCommandStatus`
        """
        return ATCommandStatus.get(self.__resp_st)

    @property
    def real_status(self):
        """
        Returns the AT command response status of the packet.

        Returns:
            Integer: the AT command response status of the packet.
        """
        return self.__resp_st

    @status.setter
    def status(self, response_status):
        """
        Sets the AT command response status of the packet

        Args:
            response_status (:class:`.ATCommandStatus`) : the new AT command
                response status of the packet.

        .. seealso::
           | :class:`.ATCommandStatus`
        """
        if response_status is None:
            raise ValueError("Response status cannot be None")

        if isinstance(response_status, ATCommandStatus):
            self.__resp_st = response_status.code
        elif isinstance(response_status, int):
            if 0 <= response_status <= 255:
                self.__resp_st = response_status
            else:
                raise ValueError("Response status must be between 0 and 255.")
        else:
            raise TypeError(
                "Response status must be ATCommandStatus or int not {!r}".
                format(response_status.__class__.__name__))

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit source address

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr


class TransmitPacket(XBeeAPIPacket):
    """
    This class represents a transmit request packet. Packet is built using the
    parameters of the constructor or providing a valid API byte array.

    A transmit request API frame causes the module to send data as an RF
    packet to the specified destination.

    The 64-bit destination address should be set to `0x000000000000FFFF`
    for a broadcast transmission (to all devices).

    The coordinator can be addressed by either setting the 64-bit address to
    `0x0000000000000000` and the 16-bit address to `0xFFFE`, OR by setting the
    64-bit address to the coordinator's 64-bit address and the 16-bit address
    to `0x0000`.

    For all other transmissions, setting the 16-bit address to the correct
    16-bit address can help improve performance when transmitting to multiple
    destinations.

    If a 16-bit address is not known, this field should be set to
    `0xFFFE` (unknown).

    The transmit status frame ( :attr:`.ApiFrameType.TRANSMIT_STATUS`) will
    indicate the discovered 16-bit address, if successful (see :class:`.TransmitStatusPacket`).

    The broadcast radius can be set from `0` up to `NH`. If set to `0`, the
    value of `NH` specifies the broadcast radius (recommended). This parameter
    is only used for broadcast transmissions.

    The maximum number of payload bytes can be read with the `NP` command.

    Several transmit options can be set using the transmit options bitfield.

    .. seealso::
       | :class:`.TransmitOptions`
       | :attr:`.XBee16BitAddress.COORDINATOR_ADDRESS`
       | :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS`
       | :attr:`.XBee64BitAddress.BROADCAST_ADDRESS`
       | :attr:`.XBee64BitAddress.COORDINATOR_ADDRESS`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 18

    def __init__(self, frame_id, x64bit_addr, x16bit_addr, broadcast_radius,
                 tx_options, rf_data=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TransmitPacket` object
        with the provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit destination address.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit destination address.
            broadcast_radius (Integer): maximum number of hops a broadcast transmission can occur.
            tx_options (Integer): bitfield of supported transmission options.
            rf_data (Bytearray, optional): RF data that is sent to the destination device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.TransmitOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
        """
        if frame_id > 255 or frame_id < 0:
            raise ValueError("frame_id must be between 0 and 255.")

        super().__init__(ApiFrameType.TRANSMIT_REQUEST, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__broadcast_radius = broadcast_radius
        self.__tx_opts = tx_options
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TransmitPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 18.
                (start delim. + length (2 bytes) + frame type + frame id
                + 64bit addr. + 16bit addr. + broadcast radius
                + Transmit options + checksum = 18 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.TRANSMIT_REQUEST`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TransmitPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TRANSMIT_REQUEST.code:
            raise InvalidPacketException(message="This packet is not a transmit request packet.")

        return TransmitPacket(
            raw[4], XBee64BitAddress(raw[5:13]), XBee16BitAddress(raw[13:15]),
            raw[15], raw[16],
            rf_data=raw[17:-1] if len(raw) > TransmitPacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

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
        ret += self.__x16bit_addr.address
        ret.append(self.__broadcast_radius)
        ret.append(self.__tx_opts)
        if self.__data is not None:
            return ret + self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR:      self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR:      self.__x16bit_addr.address,
                DictKeys.BROADCAST_RADIUS: self.__broadcast_radius,
                DictKeys.TRANSMIT_OPTIONS: self.__tx_opts,
                DictKeys.RF_DATA:          list(self.__data) if self.__data is not None else None}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2 - 8  # Remove 16-bit and 64-bit addresses

    @property
    def rf_data(self):
        """
        Returns the RF data to send.

        Returns:
            Bytearray: the RF data to send.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the RF data to send.

        Args:
            rf_data (Bytearray): the new RF data to send.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()

    @property
    def transmit_options(self):
        """
        Returns the transmit options bitfield.

        Returns:
            Integer: the transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, transmit_options):
        """
        Sets the transmit options bitfield.

        Args:
            transmit_options (Integer): the new transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        self.__tx_opts = transmit_options

    @property
    def broadcast_radius(self):
        """
        Returns the broadcast radius. Broadcast radius is the maximum number of
        hops a broadcast transmission.

        Returns:
            Integer: the broadcast radius.
        """
        return self.__broadcast_radius

    @broadcast_radius.setter
    def broadcast_radius(self, br_radius):
        """
        Sets the broadcast radius. Broadcast radius is the maximum number of
        hops a broadcast transmission.

        Args:
            br_radius (Integer): the new broadcast radius.
        """
        self.__broadcast_radius = br_radius

    @property
    def x64bit_dest_addr(self):
        """
        Returns the 64-bit destination address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_dest_addr.setter
    def x64bit_dest_addr(self, x64bit_addr):
        """
        Sets the 64-bit destination address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_dest_addr(self):
        """
        Returns the 16-bit destination address.

        Returns:
            :class:`XBee16BitAddress`: the 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_dest_addr.setter
    def x16bit_dest_addr(self, x16bit_addr):
        """
        Sets the 16-bit destination address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr


class TransmitStatusPacket(XBeeAPIPacket):
    """
    This class represents a transmit status packet. Packet is built using the
    parameters of the constructor or providing a valid raw byte array.

    When a Transmit Request is completed, the module sends a transmit status
    message. This message will indicate if the packet was transmitted
    successfully or if there was a failure.

    This packet is the response to standard and explicit transmit requests.

    .. seealso::
       | :class:`.TransmitPacket`
    """

    __MIN_PACKET_LENGTH = 11

    def __init__(self, frame_id, x16bit_addr, tx_retry_count,
                 transmit_status=TransmitStatus.SUCCESS,
                 discovery_status=DiscoveryStatus.NO_DISCOVERY_OVERHEAD,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.TransmitStatusPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            x16bit_addr (:class:`.XBee16BitAddress`): 16-bit network address
                the packet was delivered to.
            tx_retry_count (Integer): the number of application
                transmission retries that took place.
            transmit_status (:class:`.TransmitStatus`, optional): transmit
                status. Default: SUCCESS.
            discovery_status (:class:`DiscoveryStatus`, optional): discovery status.
                Default: NO_DISCOVERY_OVERHEAD.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.

        .. seealso::
           | :class:`.DiscoveryStatus`
           | :class:`.TransmitStatus`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")

        super().__init__(ApiFrameType.TRANSMIT_STATUS, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x16bit_addr = x16bit_addr
        self.__tx_retry_count = tx_retry_count
        self.__tx_status = transmit_status
        self.__discovery_status = discovery_status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.TransmitStatusPacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 11.
                (start delim. + length (2 bytes) + frame type + frame id
                + 16bit addr. + transmit retry count + delivery status
                + discovery status + checksum = 11 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.TRANSMIT_STATUS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=TransmitStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.TRANSMIT_STATUS.code:
            raise InvalidPacketException(message="This packet is not a transmit status packet.")

        return TransmitStatusPacket(raw[4], XBee16BitAddress(raw[5:7]), raw[7],
                                    transmit_status=TransmitStatus.get(raw[8]),
                                    discovery_status=DiscoveryStatus.get(raw[9]),
                                    op_mode=operating_mode)

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
        ret = self.__x16bit_addr.address
        ret.append(self.__tx_retry_count)
        ret.append(self.__tx_status.code)
        ret.append(self.__discovery_status.code)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X16BIT_ADDR: self.__x16bit_addr.address,
                DictKeys.TRANS_R_COUNT: self.__tx_retry_count,
                DictKeys.TS_STATUS: self.__tx_status,
                DictKeys.DS_STATUS: self.__discovery_status}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2  # Remove 16-bit address

    @property
    def x16bit_dest_addr(self):
        """
        Returns the 16-bit destination address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_dest_addr.setter
    def x16bit_dest_addr(self, x16bit_addr):
        """
        Sets the 16-bit destination address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def transmit_status(self):
        """
        Returns the transmit status.

        Returns:
            :class:`.TransmitStatus`: the transmit status.

        .. seealso::
           | :class:`.TransmitStatus`
        """
        return self.__tx_status

    @transmit_status.setter
    def transmit_status(self, transmit_status):
        """
        Sets the transmit status.

        Args:
            transmit_status (:class:`.TransmitStatus`): the new transmit status to set.

        .. seealso::
           | :class:`.TransmitStatus`
        """
        self.__tx_status = transmit_status

    @property
    def transmit_retry_count(self):
        """
        Returns the transmit retry count.

        Returns:
            Integer: the transmit retry count.
        """
        return self.__tx_retry_count

    @transmit_retry_count.setter
    def transmit_retry_count(self, transmit_retry_count):
        """
        Sets the transmit retry count.

        Args:
            transmit_retry_count (Integer): the new transmit retry count.
        """
        self.__tx_retry_count = transmit_retry_count

    @property
    def discovery_status(self):
        """
        Returns the discovery status.

        Returns:
            :class:`.DiscoveryStatus`: the discovery status.

        .. seealso::
           | :class:`.DiscoveryStatus`
        """
        return self.__discovery_status

    @discovery_status.setter
    def discovery_status(self, discovery_status):
        """
        Sets the discovery status.

        Args:
            discovery_status (:class:`.DiscoveryStatus`): the new discovery status to set.

        .. seealso::
           | :class:`.DiscoveryStatus`
        """
        self.__discovery_status = discovery_status


class ModemStatusPacket(XBeeAPIPacket):
    """
    This class represents a modem status packet. Packet is built using the
    parameters of the constructor or providing a valid API raw byte array.

    RF module status messages are sent from the module in response to specific
    conditions and indicates the state of the modem in that moment.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 6

    def __init__(self, modem_status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.ModemStatusPacket`
        object with the provided parameters.

        Args:
            modem_status (:class:`.ModemStatus`): the modem status event.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        .. seealso::
           | :class:`.ModemStatus`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.MODEM_STATUS, op_mode=op_mode)
        self.__modem_status = modem_status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ModemStatusPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 6.
                (start delim. + length (2 bytes) + frame type
                + modem status + checksum = 6 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.MODEM_STATUS`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=ModemStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.MODEM_STATUS.code:
            raise InvalidPacketException(message="This packet is not a modem status packet.")

        return ModemStatusPacket(ModemStatus.get(raw[4]), op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return bytearray([self.__modem_status.code])

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.MODEM_STATUS: self.__modem_status}

    @property
    def modem_status(self):
        """
        Returns the modem status event.

        Returns:
            :class:`.ModemStatus`: The modem status event.

        .. seealso::
           | :class:`.ModemStatus`
        """
        return self.__modem_status

    @modem_status.setter
    def modem_status(self, modem_status):
        """
        Sets the modem status event.

        Args:
            modem_status (:class:`.ModemStatus`): the new modem status event to set.

        .. seealso::
           | :class:`.ModemStatus`
        """
        self.__modem_status = modem_status


class IODataSampleRxIndicatorPacket(XBeeAPIPacket):
    """
    This class represents an IO data sample RX indicator packet. Packet is built
    using the parameters of the constructor or providing a valid API byte array.

    When the module receives an IO sample frame from a remote device, it sends
    the sample out the UART using this frame type (when `AO=0`). Only modules
    running API firmware will send IO samples out the UART.

    Among received data, some options can also be received indicating
    transmission parameters.

    .. seealso::
       | :class:`.XBeeAPIPacket`
       | :class:`.ReceiveOptions`
    """

    __MIN_PACKET_LENGTH = 20

    def __init__(self, x64bit_addr, x16bit_addr, rx_options, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.IODataSampleRxIndicatorPacket` object with the provided parameters.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit source address.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit source address.
            rx_options (Integer): bitfield indicating the receive options.
            rf_data (Bytearray, optional): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `rf_data` is not `None` and it's not valid for
                create an :class:`.IOSample`.

        .. seealso::
           | :class:`.IOSample`
           | :class:`.ReceiveOptions`
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR, op_mode=op_mode)
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__rx_opts = rx_options
        self.__data = rf_data
        self.__io_sample = IOSample(rf_data) if rf_data is not None and len(rf_data) >= 5 else None

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.IODataSampleRxIndicatorPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 20.
                (start delim. + length (2 bytes) + frame type + 64bit addr.
                + 16bit addr. + rf data (5 bytes) + checksum = 20 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=IODataSampleRxIndicatorPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR.code:
            raise InvalidPacketException(
                message="This packet is not an IO data sample RX indicator packet.")

        return IODataSampleRxIndicatorPacket(
            XBee64BitAddress(raw[4:12]), XBee16BitAddress(raw[12:14]),
            raw[14], rf_data=raw[15:-1], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = self.__x64bit_addr.address
        ret += self.__x16bit_addr.address
        ret.append(self.__rx_opts)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        base = {DictKeys.X64BIT_ADDR: self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR: self.__x16bit_addr.address,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts}

        if self.__io_sample is not None:
            base[DictKeys.NUM_SAMPLES] = 1
            base[DictKeys.DIGITAL_MASK] = self.__io_sample.digital_mask
            base[DictKeys.ANALOG_MASK] = self.__io_sample.analog_mask

            # Digital values
            for i in range(16):
                if self.__io_sample.has_digital_value(IOLine.get(i)):
                    base[IOLine.get(i).description + " digital value"] = \
                        self.__io_sample.get_digital_value(IOLine.get(i)).name

            # Analog values
            for i in range(6):
                if self.__io_sample.has_analog_value(IOLine.get(i)):
                    base[IOLine.get(i).description + " analog value"] = \
                        self.__io_sample.get_analog_value(IOLine.get(i))

            # Power supply
            if self.__io_sample.has_power_supply_value():
                base["Power supply value "] = "%02X" % self.__io_sample.power_supply_value

        elif self.__data is not None:
            base[DictKeys.RF_DATA] = utils.hex_to_string(self.__data)

        return base

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return utils.is_bit_enabled(self.__rx_opts, 1)

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 2 - 8  # Remove 16-bit and 64-bit addresses

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit source address

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()

        # Modify the ioSample accordingly
        if rf_data is not None and len(rf_data) >= 5:
            self.__io_sample = IOSample(self.__data)
        else:
            self.__io_sample = None

    @property
    def io_sample(self):
        """
        Returns the IO sample corresponding to the data contained in the packet.

        Returns:
            :class:`.IOSample`: the IO sample of the packet, `None` if the
                packet has not any data or if the sample could not be generated
                correctly.

        .. seealso::
           | :class:`.IOSample`
        """
        return self.__io_sample

    @io_sample.setter
    def io_sample(self, io_sample):
        """
        Sets the IO sample of the packet.

        Args:
            io_sample (:class:`.IOSample`): the new IO sample to set.

        .. seealso::
           | :class:`.IOSample`
        """
        self.__io_sample = io_sample


class ExplicitAddressingPacket(XBeeAPIPacket):
    """
    This class represents an explicit addressing command packet. Packet is
    built using the parameters of the constructor or providing a valid API
    payload.

    Allows application layer fields (endpoint and cluster ID) to be
    specified for a data transmission. Similar to the transmit request, but
    also requires application layer addressing fields to be specified
    (endpoints, cluster ID, profile ID). An explicit addressing request API
    frame causes the module to send data as an RF packet to the specified
    destination, using the specified source and destination endpoints, cluster
    ID, and profile ID.

    The 64-bit destination address should be set to `0x000000000000FFF` for
    a broadcast transmission (to all devices).

    The coordinator can be addressed by either setting the 64-bit address to
    `0x000000000000000` and the 16-bit address to `0xFFFE`, OR by setting the
    64-bit address to the coordinator's 64-bit address and the 16-bit address
    to `0x0000`.

    For all other transmissions, setting the 16-bit address to the right 16-bit
    address can help improve performance when transmitting to multiple destinations.

    If a 16-bit address is not known, this field should be set to
    `0xFFFE` (unknown).

    The transmit status frame (:attr:`.ApiFrameType.TRANSMIT_STATUS`) will
    indicate the discovered 16-bit address, if successful
    (see :class:`.TransmitStatusPacket`)).

    The broadcast radius can be set from `0` up to `NH`. If set to `0`, the
    value of `NH` specifies the broadcast radius (recommended). This parameter
    is only used for broadcast transmissions.

    The maximum number of payload bytes can be read with the `NP` command.
    Note: if source routing is used, the RF payload will be reduced by two
    bytes per intermediate hop in the source route.

    Several transmit options can be set using the transmit options bitfield.

    .. seealso::
       | :class:`.TransmitOptions`
       | :attr:`.XBee16BitAddress.COORDINATOR_ADDRESS`
       | :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS`
       | :attr:`.XBee64BitAddress.BROADCAST_ADDRESS`
       | :attr:`.XBee64BitAddress.COORDINATOR_ADDRESS`
       | :class:`.ExplicitRXIndicatorPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 24

    def __init__(self, frame_id, x64bit_addr, x16bit_addr, src_endpoint,
                 dest_endpoint, cluster_id, profile_id, broadcast_radius=0x00,
                 transmit_options=0x00, rf_data=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. . Instantiates a new :class:`.ExplicitAddressingPacket`
        object with the provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit address.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit address.
            src_endpoint (Integer): source endpoint. 1 byte.
            dest_endpoint (Integer): destination endpoint. 1 byte.
            cluster_id (Integer): cluster id. Must be between 0 and 0xFFFF.
            profile_id (Integer): profile id. Must be between 0 and 0xFFFF.
            broadcast_radius (Integer): maximum number of hops a broadcast transmission can occur.
            transmit_options (Integer): bitfield of supported transmission options.
            rf_data (Bytearray, optional): RF data that is sent to the destination device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id`, `src_endpoint` or `dst_endpoint` are less
                than 0 or greater than 255.
            ValueError: if lengths of `cluster_id` or `profile_id` (respectively)
                are less than 0 or greater than 0xFFFF.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.TransmitOptions`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")
        if src_endpoint < 0 or src_endpoint > 255:
            raise ValueError("Source endpoint must be between 0 and 255.")
        if dest_endpoint < 0 or dest_endpoint > 255:
            raise ValueError("Destination endpoint must be between 0 and 255.")
        if cluster_id < 0 or cluster_id > 0xFFFF:
            raise ValueError("Cluster id must be between 0 and 0xFFFF.")
        if profile_id < 0 or profile_id > 0xFFFF:
            raise ValueError("Profile id must be between 0 and 0xFFFF.")

        super().__init__(ApiFrameType.EXPLICIT_ADDRESSING, op_mode=op_mode)
        self._frame_id = frame_id
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__src_ed = src_endpoint
        self.__dest_ed = dest_endpoint
        self.__cluster_id = cluster_id
        self.__profile_id = profile_id
        self.__broadcast_radius = broadcast_radius
        self.__tx_opts = transmit_options
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ExplicitAddressingPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 24.
                (start delim. + length (2 bytes) + frame type + frame ID
                + 64bit addr. + 16bit addr. + source endpoint + dest. endpoint
                + cluster ID (2 bytes) + profile ID (2 bytes)
                + broadcast radius + transmit options + checksum = 24 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.EXPLICIT_ADDRESSING`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=ExplicitAddressingPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.EXPLICIT_ADDRESSING.code:
            raise InvalidPacketException(message="This packet is not an explicit addressing packet")

        return ExplicitAddressingPacket(
            raw[4], XBee64BitAddress(raw[5:13]), XBee16BitAddress(raw[13:15]), raw[15], raw[16],
            utils.bytes_to_int(raw[17:19]), utils.bytes_to_int(raw[19:21]), raw[21], raw[22],
            rf_data=raw[23:-1] if len(raw) > ExplicitAddressingPacket.__MIN_PACKET_LENGTH else None)

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
        raw = self.__x64bit_addr.address
        raw += self.__x16bit_addr.address
        raw.append(self.__src_ed)
        raw.append(self.__dest_ed)
        raw += utils.int_to_bytes(self.__cluster_id, num_bytes=2)
        raw += utils.int_to_bytes(self.__profile_id, num_bytes=2)
        raw.append(self.__broadcast_radius)
        raw.append(self.__tx_opts)
        if self.__data is not None:
            raw += self.__data
        return raw

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR:      self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR:      self.__x16bit_addr.address,
                DictKeys.SOURCE_ENDPOINT:  self.__src_ed,
                DictKeys.DEST_ENDPOINT:    self.__dest_ed,
                DictKeys.CLUSTER_ID:       self.__cluster_id,
                DictKeys.PROFILE_ID:       self.__profile_id,
                DictKeys.BROADCAST_RADIUS: self.__broadcast_radius,
                DictKeys.TRANSMIT_OPTIONS: self.__tx_opts,
                DictKeys.RF_DATA:          self.__data}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        # Remove 16-bit and 64-bit addresses, the source and destination
        # endpoints, the cluster ID and the profile ID.
        return len(self) - 2 - 8 - 1 - 1 - 2 - 2

    @property
    def source_endpoint(self):
        """
        Returns the source endpoint of the transmission.

        Returns:
            Integer: the source endpoint of the transmission.
        """
        return self.__dest_ed

    @source_endpoint.setter
    def source_endpoint(self, source_endpoint):
        """
        Sets the source endpoint of the transmission.

        Args:
            source_endpoint (Integer): the new source endpoint of the transmission.
        """
        self.__src_ed = source_endpoint

    @property
    def dest_endpoint(self):
        """
        Returns the destination endpoint of the transmission.

        Returns:
            Integer: the destination endpoint of the transmission.
        """
        return self.__dest_ed

    @dest_endpoint.setter
    def dest_endpoint(self, dest_endpoint):
        """
        Sets the destination endpoint of the transmission.

        Args:
            dest_endpoint (Integer): the new destination endpoint of the transmission.
        """
        self.__dest_ed = dest_endpoint

    @property
    def cluster_id(self):
        """
        Returns the cluster ID of the transmission.

        Returns:
            Integer: the cluster ID of the transmission.
        """
        return self.__cluster_id

    @cluster_id.setter
    def cluster_id(self, cluster_id):
        """
        Sets the cluster ID of the transmission.

        Args:
            cluster_id (Integer): the new cluster ID of the transmission.
        """
        self.__cluster_id = cluster_id

    @property
    def profile_id(self):
        """
        Returns the profile ID of the transmission.

        Returns
            Integer: the profile ID of the transmission.
        """
        return self.__profile_id

    @profile_id.setter
    def profile_id(self, profile_id):
        """
        Sets the profile ID of the transmission.

        Args
            profile_id (Integer): the new profile ID of the transmission.
        """
        self.__profile_id = profile_id

    @property
    def rf_data(self):
        """
        Returns the RF data to send.

        Returns:
            Bytearray: the RF data to send.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the RF data to send.

        Args:
            rf_data (Bytearray): the new RF data to send.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()

    @property
    def transmit_options(self):
        """
        Returns the transmit options bitfield.

        Returns:
            Integer: the transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        return self.__tx_opts

    @transmit_options.setter
    def transmit_options(self, transmit_options):
        """
        Sets the transmit options bitfield.

        Args:
            transmit_options (Integer): the new transmit options bitfield.

        .. seealso::
           | :class:`.TransmitOptions`
        """
        self.__tx_opts = transmit_options

    @property
    def broadcast_radius(self):
        """
        Returns the broadcast radius. Broadcast radius is the maximum number
        of hops a broadcast transmission.

        Returns:
            Integer: the broadcast radius.
        """
        return self.__broadcast_radius

    @broadcast_radius.setter
    def broadcast_radius(self, br_radius):
        """
        Sets the broadcast radius. Broadcast radius is the maximum number
        of hops a broadcast transmission.

        Args:
            br_radius (Integer): the new broadcast radius.
        """
        self.__broadcast_radius = br_radius

    @property
    def x64bit_dest_addr(self):
        """
        Returns the 64-bit destination address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_dest_addr.setter
    def x64bit_dest_addr(self, x64bit_addr):
        """
        Sets the 64-bit destination address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit destination address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_dest_addr(self):
        """
        Returns the 16-bit destination address.

        Returns:
            :class:`XBee16BitAddress`: the 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_dest_addr.setter
    def x16bit_dest_addr(self, x16bit_addr):
        """
        Sets the 16-bit destination address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit destination address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr


class ExplicitRXIndicatorPacket(XBeeAPIPacket):
    """
    This class represents an explicit RX indicator packet. Packet is
    built using the parameters of the constructor or providing a valid API
    payload.

    When the modem receives an RF packet it is sent out the UART using this
    message type (when `AO=1`).

    This packet is received when external devices send explicit addressing
    packets to this module.

    Among received data, some options can also be received indicating
    transmission parameters.

    .. seealso::
       | :class:`.ReceiveOptions`
       | :class:`.ExplicitAddressingPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 22

    def __init__(self, x64bit_addr, x16bit_addr, src_endpoint, dest_endpoint,
                 cluster_id, profile_id, rx_options, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.ExplicitRXIndicatorPacket`
        object with the provided parameters.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit source address.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit source address.
            src_endpoint (Integer): source endpoint. 1 byte.
            dest_endpoint (Integer): destination endpoint. 1 byte.
            cluster_id (Integer): cluster ID. Must be between 0 and 0xFFFF.
            profile_id (Integer): profile ID. Must be between 0 and 0xFFFF.
            rx_options (Integer): bitfield indicating the receive options.
            rf_data (Bytearray, optional): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `src_endpoint` or `dst_endpoint` are less than 0 or greater than 255.
            ValueError: if lengths of `cluster_id` or `profile_id` (respectively)
                are different from 2.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBee64BitAddress`
           | :class:`.ReceiveOptions`
           | :class:`.XBeeAPIPacket`
        """
        if src_endpoint < 0 or src_endpoint > 255:
            raise ValueError("Source endpoint must be between 0 and 255.")
        if dest_endpoint < 0 or dest_endpoint > 255:
            raise ValueError("Destination endpoint must be between 0 and 255.")
        if cluster_id < 0 or cluster_id > 0xFFFF:
            raise ValueError("Cluster id must be between 0 and 0xFFFF.")
        if profile_id < 0 or profile_id > 0xFFFF:
            raise ValueError("Profile id must be between 0 and 0xFFFF.")

        super().__init__(ApiFrameType.EXPLICIT_RX_INDICATOR, op_mode=op_mode)
        self.__x64bit_addr = x64bit_addr
        self.__x16bit_addr = x16bit_addr
        self.__src_ed = src_endpoint
        self.__dest_ed = dest_endpoint
        self.__cluster_id = cluster_id
        self.__profile_id = profile_id
        self.__rx_opts = rx_options
        self.__data = rf_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.ExplicitRXIndicatorPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 22.
                (start delim. + length (2 bytes) + frame type + 64bit addr.
                + 16bit addr. + source endpoint + dest. endpoint
                + cluster ID (2 bytes) + profile ID (2 bytes) + receive options
                + checksum = 22 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :attr:`.ApiFrameType.EXPLICIT_RX_INDICATOR`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=ExplicitRXIndicatorPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.EXPLICIT_RX_INDICATOR.code:
            raise InvalidPacketException(
                message="This packet is not an explicit RX indicator packet.")

        return ExplicitRXIndicatorPacket(
            XBee64BitAddress(raw[4:12]), XBee16BitAddress(raw[12:14]), raw[14], raw[15],
            utils.bytes_to_int(raw[16:18]), utils.bytes_to_int(raw[18:20]), raw[20],
            rf_data=raw[21:-1] if len(raw) > ExplicitRXIndicatorPacket.__MIN_PACKET_LENGTH else None,
            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def is_broadcast(self):
        """
        Override method.

        .. seealso::
           | :meth:`XBeeAPIPacket.is_broadcast`
        """
        return utils.is_bit_enabled(self.__rx_opts, 1)

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        raw = self.__x64bit_addr.address
        raw += self.__x16bit_addr.address
        raw.append(self.__src_ed)
        raw.append(self.__dest_ed)
        raw += utils.int_to_bytes(self.__cluster_id, num_bytes=2)
        raw += utils.int_to_bytes(self.__profile_id, num_bytes=2)
        raw.append(self.__rx_opts)
        if self.__data is not None:
            raw += self.__data
        return raw

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.X64BIT_ADDR:     self.__x64bit_addr.address,
                DictKeys.X16BIT_ADDR:     self.__x16bit_addr.address,
                DictKeys.SOURCE_ENDPOINT: self.__src_ed,
                DictKeys.DEST_ENDPOINT:   self.__dest_ed,
                DictKeys.CLUSTER_ID:      self.__cluster_id,
                DictKeys.PROFILE_ID:      self.__profile_id,
                DictKeys.RECEIVE_OPTIONS: self.__rx_opts,
                DictKeys.RF_DATA:         self.__data}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        # Remove 16-bit and 64-bit addresses, the source and destination
        # endpoints, the cluster ID and the profile ID.
        return len(self) - 2 - 8 - 1 - 1 - 2 - 2

    @property
    def x64bit_source_addr(self):
        """
        Returns the 64-bit source address.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self.__x64bit_addr

    @x64bit_source_addr.setter
    def x64bit_source_addr(self, x64bit_addr):
        """
        Sets the 64-bit source address.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`): the new 64-bit source address.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        self.__x64bit_addr = x64bit_addr

    @property
    def x16bit_source_addr(self):
        """
        Returns the 16-bit source address.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__x16bit_addr

    @x16bit_source_addr.setter
    def x16bit_source_addr(self, x16bit_addr):
        """
        Sets the 16-bit source address.

        Args:
            x16bit_addr (:class:`.XBee16BitAddress`): the new 16-bit source address.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        self.__x16bit_addr = x16bit_addr

    @property
    def source_endpoint(self):
        """
        Returns the source endpoint of the transmission.

        Returns:
            Integer: the source endpoint of the transmission.
        """
        return self.__src_ed

    @source_endpoint.setter
    def source_endpoint(self, source_endpoint):
        """
        Sets the source endpoint of the transmission.

        Args:
            source_endpoint (Integer): the new source endpoint of the transmission.
        """
        self.__src_ed = source_endpoint

    @property
    def dest_endpoint(self):
        """
        Returns the destination endpoint of the transmission.

        Returns:
            Integer: the destination endpoint of the transmission.
        """
        return self.__dest_ed

    @dest_endpoint.setter
    def dest_endpoint(self, dest_endpoint):
        """
        Sets the destination endpoint of the transmission.

        Args:
            dest_endpoint (Integer): the new destination endpoint of the transmission.
        """
        self.__dest_ed = dest_endpoint

    @property
    def cluster_id(self):
        """
        Returns the cluster ID of the transmission.

        Returns:
            Integer: the cluster ID of the transmission.
        """
        return self.__cluster_id

    @cluster_id.setter
    def cluster_id(self, cluster_id):
        """
        Sets the cluster ID of the transmission.

        Args:
            cluster_id (Integer): the new cluster ID of the transmission.
        """
        self.__cluster_id = cluster_id

    @property
    def profile_id(self):
        """
        Returns the profile ID of the transmission.

        Returns
            Integer: the profile ID of the transmission.
        """
        return self.__profile_id

    @profile_id.setter
    def profile_id(self, profile_id):
        """
        Sets the profile ID of the transmission.

        Args
            profile_id (Integer): the new profile ID of the transmission.
        """
        self.__profile_id = profile_id

    @property
    def receive_options(self):
        """
        Returns the receive options bitfield.

        Returns:
            Integer: the receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        return self.__rx_opts

    @receive_options.setter
    def receive_options(self, receive_options):
        """
        Sets the receive options bitfield.

        Args:
            receive_options (Integer): the new receive options bitfield.

        .. seealso::
           | :class:`.ReceiveOptions`
        """
        self.__rx_opts = receive_options

    @property
    def rf_data(self):
        """
        Returns the received RF data.

        Returns:
            Bytearray: the received RF data.
        """
        if self.__data is None:
            return None
        return self.__data.copy()

    @rf_data.setter
    def rf_data(self, rf_data):
        """
        Sets the received RF data.

        Args:
            rf_data (Bytearray): the new received RF data.
        """
        if rf_data is None:
            self.__data = None
        else:
            self.__data = rf_data.copy()


def _decode_at_cmd(cmd_bytearray):
    """
    Decodes the given bytearray to an string with 2 characters.

    Args:
        cmd_bytearray (Bytearray): The bytearray to decode.

    Returns:
        String: The decoded AT command string.
    """
    cmd = cmd_bytearray.decode('utf8', errors='backslashreplace')[0:2]
    if len(cmd) != 2:
        # If the command is corrupted it may be an utf-8 valid character
        # which value is bigger than 0xFF, for example '€' 0xc280C. In this
        # situation, add a '?' as the second character not to throw an
        # exception when creating the package that is valid from the
        # conforming bytes point of view
        cmd += '?'

    return cmd


def _encode_at_cmd(cmd):
    """
    Encodes an string AT command to get a bytearray.

    Args:
        cmd (String or bytearray): The string to encode.

    Returns:
        Bytearray: A 2-length bytearray with the command.
    """
    if isinstance(cmd, str):
        cmd = cmd.encode(encoding='utf8', errors='ignore')
        while len(cmd) != 2:
            cmd += b'?'

    return cmd
