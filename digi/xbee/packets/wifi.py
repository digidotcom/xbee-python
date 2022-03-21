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
from ipaddress import IPv4Address

from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.util import utils
from digi.xbee.exception import InvalidOperatingModeException, InvalidPacketException
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.status import ATCommandStatus
from digi.xbee.io import IOSample, IOLine


class IODataSampleRxIndicatorWifiPacket(XBeeAPIPacket):
    """
    This class represents a IO data sample RX indicator (Wi-Fi) packet. Packet
    is built using the parameters of the constructor or providing a valid API
    payload.

    When the module receives an IO sample frame from a remote device, it sends
    the sample out the UART or SPI using this frame type. Only modules running
    API mode will be able to receive IO samples.

    Among received data, some options can also be received indicating
    transmission parameters.

    .. seealso::
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 16

    def __init__(self, src_address, rssi, rx_options, rf_data=None,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.IODataSampleRxIndicatorWifiPacket` object with the
        provided parameters.

        Args:
            src_address (:class:`ipaddress.IPv4Address`): the 64-bit source address.
            rssi (Integer): received signal strength indicator.
            rx_options (Integer): bitfield indicating the receive options.
            rf_data (Bytearray, optional): received RF data.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `rf_data` is not `None` and it's not valid for
                create an :class:`.IOSample`.

        .. seealso::
           | :class:`.IOSample`
           | :class:`ipaddress.IPv4Address`
           | :class:`.ReceiveOptions`
           | :class:`.XBeeAPIPacket`
        """
        super().__init__(ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR_WIFI, op_mode=op_mode)
        self.__src_addr = src_address
        self.__rssi = rssi
        self.__rx_opts = rx_options
        self.__data = rf_data
        self.__io_sample = IOSample(rf_data) if rf_data is not None and len(rf_data) >= 5 else None

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.IODataSampleRxIndicatorWifiPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 16.
                (start delim. + length (2 bytes) + frame type
                + source addr. (4 bytes) + rssi + receive options
                + rf data (5 bytes) + checksum = 16 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR_WIFI`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=IODataSampleRxIndicatorWifiPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR_WIFI.code:
            raise InvalidPacketException(
                message="This packet is not an IO data sample RX indicator Wi-Fi packet.")

        return IODataSampleRxIndicatorWifiPacket(
            IPv4Address(bytes(raw[4:8])), raw[7], raw[8], rf_data=raw[9:-1], op_mode=operating_mode)

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
        ret = bytearray(self.__src_addr.packed)
        ret += utils.int_to_bytes(self.__rssi, num_bytes=1)
        ret += utils.int_to_bytes(self.__rx_opts, num_bytes=1)
        if self.__data is not None:
            ret += self.__data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        base = {DictKeys.SRC_IPV4_ADDR:   "%s (%s)" % (self.__src_addr.packed,
                                                       self.__src_addr.exploded),
                DictKeys.RSSI:            self.__rssi,
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

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 8  # Remove 64-bit address

    @property
    def source_address(self):
        """
        Returns the IPv4 address of the source device.

        Returns:
            :class:`ipaddress.IPv4Address`: the IPv4 address of the source device.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        return self.__src_addr

    @source_address.setter
    def source_address(self, source_address):
        """
        Sets the IPv4 source address.

        Args:
            source_address (:class:`ipaddress.IPv4Address`): The new IPv4 source address.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        if source_address is not None:
            self.__src_addr = source_address

    @property
    def rssi(self):
        """
        Returns the received Signal Strength Indicator (RSSI).

        Returns:
            Integer: the received Signal Strength Indicator (RSSI).
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the received Signal Strength Indicator (RSSI).

        Args:
            rssi (Integer): the new received Signal Strength Indicator (RSSI).
        """
        self.__rssi = rssi

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

        # Modify the IO sample accordingly
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
                packet has not any data or if the sample could not be
                generated correctly.

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


class RemoteATCommandWifiPacket(XBeeAPIPacket):
    """
    This class represents a remote AT command request (Wi-Fi) packet. Packet is
    built using the parameters of the constructor or providing a valid API
    payload.

    Used to query or set module parameters on a remote device. For parameter
    changes on the remote device to take effect, changes must be applied, either
    by setting the apply changes options bit, or by sending an `AC` command
    to the remote node.

    Remote command options are set as a bitfield.

    If configured, command response is received as a :class:`.RemoteATCommandResponseWifiPacket`.

    .. seealso::
       | :class:`.RemoteATCommandResponseWifiPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 17

    def __init__(self, frame_id, dest_address, tx_options, command,
                 parameter=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.RemoteATCommandWifiPacket`
        object with the provided parameters.

        Args:
            frame_id (integer): the frame ID of the packet.
            dest_address (:class:`ipaddress.IPv4Address`): the IPv4 address of
                the destination device.
            tx_options (Integer): bitfield of supported transmission options.
            command (String): AT command to send.
            parameter (Bytearray, optional): AT command parameter.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different than 2.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
           | :class:`.RemoteATCmdOptions`
           | :class:`.XBeeAPIPacket`
        """
        if frame_id < 0 or frame_id > 255:
            raise ValueError("Frame id must be between 0 and 255.")
        if len(command) != 2:
            raise ValueError("Invalid command " + command)

        super().__init__(ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI, op_mode=op_mode)
        self._frame_id = frame_id
        self.__dest_addr = dest_address
        self.__tx_opts = tx_options
        self.__cmd = command
        self.__param = parameter

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RemoteATCommandWifiPacket`

        Raises:
            InvalidPacketException: if the Bytearray length is less than 17.
                (start delim. + length (2 bytes) + frame type + frame id
                + dest. addr. (8 bytes) + transmit options
                + command (2  bytes) + checksum = 17 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RemoteATCommandWifiPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI.code:
            raise InvalidPacketException(
                message="This packet is not a remote AT command request Wi-Fi packet.")

        return RemoteATCommandWifiPacket(
            raw[4], IPv4Address(bytes(raw[9:13])), raw[13], raw[14:16].decode("utf8"),
            parameter=raw[16:-1] if len(raw) > RemoteATCommandWifiPacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray(self.__dest_addr.packed)
        ret += utils.int_to_bytes(self.__tx_opts, num_bytes=1)
        ret += bytearray(self.__cmd, "utf8")
        if self.__param is not None:
            ret += self.__param
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        See:
            :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.DEST_IPV4_ADDR:   "%s (%s)" % (self.__dest_addr.packed, self.__dest_addr.exploded),
                DictKeys.TRANSMIT_OPTIONS: self.__tx_opts,
                DictKeys.COMMAND:          self.__cmd,
                DictKeys.PARAMETER:        list(self.__param) if self.__param is not None else None}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 8  # Destination address

    @property
    def dest_address(self):
        """
        Returns the IPv4 address of the destination device.

        Returns:
            :class:`ipaddress.IPv4Address`: the IPv4 address of the destination device.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        return self.__dest_addr

    @dest_address.setter
    def dest_address(self, dest_address):
        """
        Sets the IPv4 destination address.

        Args:
            dest_address (:class:`ipaddress.IPv4Address`): The new IPv4 destination address.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        if dest_address is not None:
            self.__dest_addr = dest_address

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
    def command(self):
        """
        Returns the AT command.

        Returns:
            String: the AT command.
        """
        return self.__cmd

    @command.setter
    def command(self, command):
        """
        Sets the AT command.

        Args:
            command (String): the new AT command.
        """
        self.__cmd = command

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


class RemoteATCommandResponseWifiPacket(XBeeAPIPacket):
    """
    This class represents a remote AT command response (Wi-Fi) packet. Packet
    is built using the parameters of the constructor or providing a valid API
    payload.

    If a module receives a remote command response RF data frame in response
    to a Remote AT Command Request, the module will send a Remote AT Command
    Response message out the UART. Some commands may send back multiple frames
    for example, Node Discover (`ND`) command.

    This packet is received in response of a :class:`.RemoteATCommandPacket`.

    Response also includes an :class:`.ATCommandStatus` object with the status
    of the AT command.

    .. seealso::
       | :class:`.RemoteATCommandWifiPacket`
       | :class:`.ATCommandStatus`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 17

    def __init__(self, frame_id, src_address, command, resp_status,
                 comm_value=None, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.RemoteATCommandResponseWifiPacket` object with the
        provided parameters.

        Args:
            frame_id (Integer): the frame ID of the packet.
            src_address (:class:`ipaddress.IPv4Address`): the IPv4 address of the source device.
            command (String): the AT command of the packet. Must be a string.
            resp_status (:class:`.ATCommandStatus`): the status of the AT command.
            comm_value (Bytearray, optional): the AT command response value.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.

        Raises:
            ValueError: if `frame_id` is less than 0 or greater than 255.
            ValueError: if length of `command` is different than 2.

        .. seealso::
           | :class:`.ATCommandStatus`
           | :class:`ipaddress.IPv4Address`
        """
        if frame_id > 255 or frame_id < 0:
            raise ValueError("frame_id must be between 0 and 255.")
        if len(command) != 2:
            raise ValueError("Invalid command " + command)

        super().__init__(ApiFrameType.REMOTE_AT_COMMAND_RESPONSE_WIFI, op_mode=op_mode)
        self._frame_id = frame_id
        self.__src_addr = src_address
        self.__cmd = command
        self.__resp_status = resp_status
        self.__comm_val = comm_value

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.RemoteATCommandResponseWifiPacket`.

        Raises:
            InvalidPacketException: if the bytearray length is less than 17.
                (start delim. + length (2 bytes) + frame type + frame id
                + source addr. (8 bytes) +  command (2 bytes) + receive options
                + checksum = 17 bytes).
            InvalidPacketException: if the length field of 'raw' is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of 'raw' is not the
                header byte. See :class:`.SpecialByte`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is not
                :attr:`.ApiFrameType.REMOTE_AT_COMMAND_RESPONSE_WIFI`.
            InvalidOperatingModeException: if `operating_mode` is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
           | :meth:`.XBeeAPIPacket._check_api_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=RemoteATCommandResponseWifiPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.REMOTE_AT_COMMAND_RESPONSE_WIFI.code:
            raise InvalidPacketException(
                message="This packet is not a remote AT command response Wi-Fi packet.")

        return RemoteATCommandResponseWifiPacket(
            raw[4], IPv4Address(bytes(raw[9:13])), raw[13:15].decode("utf8"),
            ATCommandStatus.get(raw[15]),
            comm_value=raw[16:-1] if len(raw) > RemoteATCommandResponseWifiPacket.__MIN_PACKET_LENGTH else None,
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
        ret = bytearray(self.__src_addr.packed)
        ret += bytearray(self.__cmd, "utf8")
        ret += utils.int_to_bytes(self.__resp_status.code, num_bytes=1)
        if self.__comm_val is not None:
            ret += self.__comm_val
        return ret

    def _get_api_packet_spec_data_dict(self):
        return {DictKeys.SRC_IPV4_ADDR: "%s (%s)" % (self.__src_addr.packed, self.__src_addr.exploded),
                DictKeys.COMMAND:       self.__cmd,
                DictKeys.AT_CMD_STATUS: self.__resp_status,
                DictKeys.RF_DATA:       list(self.__comm_val) if self.__comm_val is not None else None}

    @property
    def effective_len(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.effective_len`
        """
        return len(self) - 8  # Remove source address

    @property
    def source_address(self):
        """
        Returns the IPv4 address of the source device.

        Returns:
            :class:`ipaddress.IPv4Address`: the IPv4 address of the source device.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        return self.__src_addr

    @source_address.setter
    def source_address(self, source_address):
        """
        Sets the IPv4 source address.

        Args:
            source_address (:class:`ipaddress.IPv4Address`): The new IPv4 source address.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        if source_address is not None:
            self.__src_addr = source_address

    @property
    def command(self):
        """
        Returns the AT command of the packet.

        Returns:
            String: the AT command of the packet.
        """
        return self.__cmd

    @command.setter
    def command(self, command):
        """
        Sets the AT command of the packet.

        Args:
            command (String): the new AT command of the packet. Must have length = 2.

        Raises:
            ValueError: if length of `command` is different than 2.
        """
        if len(command) != 2:
            raise ValueError("Invalid command " + command)
        self.__cmd = command

    @property
    def status(self):
        """
        Returns the AT command response status of the packet.

        Returns:
            :class:`.ATCommandStatus`: the AT command response status of the packet.

        .. seealso::
           | :class:`.ATCommandStatus`
        """
        return self.__resp_status

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
        self.__resp_status = response_status

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
