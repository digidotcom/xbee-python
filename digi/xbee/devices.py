# Copyright 2017-2019, Digi International Inc.
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

from abc import ABCMeta, abstractmethod
import logging
from enum import Enum, unique
from ipaddress import IPv4Address
import threading
import time

from digi.xbee import serial
from digi.xbee.packets.cellular import TXSMSPacket
from digi.xbee.models.accesspoint import AccessPoint, WiFiEncryptionType
from digi.xbee.models.atcomm import ATCommandResponse, ATCommand, ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import OperatingMode, APIOutputMode, IPAddressingMode
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress, XBeeIMEIAddress
from digi.xbee.models.info import SocketInfo
from digi.xbee.models.message import XBeeMessage, ExplicitXBeeMessage, IPMessage
from digi.xbee.models.options import TransmitOptions, RemoteATCmdOptions, DiscoveryOptions, XBeeLocalInterface, \
    RegisterKeyOptions
from digi.xbee.models.protocol import XBeeProtocol, IPProtocol, Role
from digi.xbee.models.status import ATCommandStatus, TransmitStatus, PowerLevel, \
    ModemStatus, CellularAssociationIndicationStatus, WiFiAssociationIndicationStatus, AssociationIndicationStatus,\
    NetworkDiscoveryStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket
from digi.xbee.packets.common import ATCommPacket, TransmitPacket, RemoteATCommandPacket, ExplicitAddressingPacket, \
    ATCommQueuePacket, ATCommResponsePacket, RemoteATCommandResponsePacket
from digi.xbee.packets.network import TXIPv4Packet
from digi.xbee.packets.raw import TX64Packet, TX16Packet
from digi.xbee.packets.relay import UserDataRelayPacket
from digi.xbee.packets.zigbee import RegisterJoiningDevicePacket, RegisterDeviceStatusPacket
from digi.xbee.util import utils
from digi.xbee.exception import XBeeException, TimeoutException, InvalidOperatingModeException, \
    ATCommandException, OperationNotSupportedException, TransmitException
from digi.xbee.io import IOSample, IOMode
from digi.xbee.reader import PacketListener, PacketReceived, DeviceDiscovered, \
    DiscoveryProcessFinished, NetworkModified
from digi.xbee.serial import FlowControl
from digi.xbee.serial import XBeeSerialPort
from functools import wraps


class AbstractXBeeDevice(object):
    """
    This class provides common functionality for all XBee devices.
    """
    __metaclass__ = ABCMeta

    _DEFAULT_TIMEOUT_SYNC_OPERATIONS = 4
    """
    The default timeout for all synchronous operations, in seconds.
    """

    _BLE_API_USERNAME = "apiservice"
    """
    The Bluetooth Low Energy API username.
    """

    LOG_PATTERN = "{comm_iface:s} - {event:s} - {opmode:s}: {content:s}"
    """
    Pattern used to log packet events.
    """

    _log = logging.getLogger(__name__)
    """
    Logger.
    """

    def __init__(self, local_xbee_device=None, serial_port=None, sync_ops_timeout=_DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.AbstractXBeeDevice` object with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`, optional): only necessary if XBee device is remote. The local
                XBee device that will behave as connection interface to communicate with the remote XBee one.
            serial_port (:class:`.XBeeSerialPort`, optional): only necessary if the XBee device is local. The serial
                port that will be used to communicate with this XBee.
            sync_ops_timeout (Integer, default: :attr:`AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`): the
                timeout (in seconds) that will be applied for all synchronous operations.
            comm_iface (:class:`.XBeeCommunicationInterface`, optional): only necessary if the XBee device is local. The
                hardware interface that will be used to communicate with this XBee.

        .. seealso::
           | :class:`.XBeeDevice`
           | :class:`.XBeeSerialPort`
        """
        if (serial_port, comm_iface).count(None) != 1:
            raise XBeeException("Either ``serial_port`` or ``comm_iface`` must be ``None`` (and only one of them)")

        self.__current_frame_id = 0x00

        self._16bit_addr = None
        self._64bit_addr = None
        self._apply_changes_flag = True

        self._is_open = False
        self._operating_mode = None

        self._local_xbee_device = local_xbee_device
        self._comm_iface = serial_port if serial_port is not None else comm_iface
        self._serial_port = self._comm_iface if isinstance(self._comm_iface, XBeeSerialPort) else None

        self._timeout = sync_ops_timeout

        self.__io_packet_received = False
        self.__io_packet_payload = None

        self._hardware_version = None
        self._firmware_version = None
        self._protocol = None
        self._node_id = None
        self._role = Role.UNKNOWN

        self._packet_listener = None

        self.__generic_lock = threading.Lock()

    def __eq__(self, other):
        """
        Operator '=='. Compares two :class:`.AbstractXBeeDevice` instances.

        Returns:
            If at least one XBee device has 64 bit address (not ``None``), this method returns ``True`` if both
                XBee device's addresses are equal, ``False`` otherwise.

            If at least one XBee device has 16 bit address (not ``None``), this method returns ``True`` if both
                XBee device addresses are equal, ``False`` otherwise.

            If at least one XBee device has node id (not ``None``), this method returns ``True`` if both
                XBee device IDs are equal, ``False`` otherwise.

            Else (all parameters of both devices are ``None``) returns ``True``.
        """
        if other is None:
            return False
        if not isinstance(self, AbstractXBeeDevice) or not isinstance(other, AbstractXBeeDevice):
            return False
        if self.get_64bit_addr() is not None and other.get_64bit_addr() is not None:
            return self.get_64bit_addr() == other.get_64bit_addr()
        return False

    def __hash__(self):
        return hash((23, self.get_64bit_addr()))

    def __str__(self):
        node_id = "" if self.get_node_id() is None else self.get_node_id()
        return "%s - %s" % (self.get_64bit_addr(), node_id)

    def update_device_data_from(self, device):
        """
        Updates the current device reference with the data provided for the given device.

        This is only for internal use.

        Args:
            device (:class:`.AbstractXBeeDevice`): the XBee device to get the data from.

        Return:
            Boolean: ``True`` if the device data has been updated, ``False`` otherwise.
        """
        updated = False

        new_ni = device.get_node_id()
        if new_ni is not None and new_ni != self._node_id:
            self._node_id = new_ni
            updated = True

        new_addr64 = device.get_64bit_addr()
        if (new_addr64 is not None
                and new_addr64 != XBee64BitAddress.UNKNOWN_ADDRESS
                and new_addr64 != self._64bit_addr
                and (self._64bit_addr is None
                     or self._64bit_addr == XBee64BitAddress.UNKNOWN_ADDRESS)):
            self._64bit_addr = new_addr64
            updated = True

        new_addr16 = device.get_16bit_addr()
        if (new_addr16 is not None
                and new_addr16 != XBee16BitAddress.UNKNOWN_ADDRESS
                and new_addr16 != self._16bit_addr):
            self._16bit_addr = new_addr16
            updated = True

        new_role = device.get_role()
        if (new_role is not None
                and new_role != Role.UNKNOWN
                and new_role != self._role):
            self._role = new_role
            updated = True

        return updated

    def get_parameter(self, parameter, parameter_value=None):
        """
        Returns the value of the provided parameter via an AT Command.

        Args:
            parameter (String): parameter to get.
            parameter_value (Bytearray, optional): The value of the parameter to execute (if any).

        Returns:
            Bytearray: the parameter value.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        value = self.__send_parameter(parameter, parameter_value=parameter_value)

        # Check if the response is None, if so throw an exception (maybe it was a write-only parameter).
        if value is None:
            raise OperationNotSupportedException(message="Could not get the %s value." % parameter)

        return value

    def set_parameter(self, parameter, value):
        """
        Sets the value of a parameter via an AT Command.

        If you send parameter to a local XBee device, all changes
        will be applied automatically, except for non-volatile memory,
        in which case you will need to execute the parameter "WR" via
        :meth:`.AbstractXBeeDevice.execute_command` method, or
        :meth:`.AbstractXBeeDevice.apply_changes` method.

        If you are sending parameters to a remote XBee device,
        the changes will be not applied automatically, unless the "apply_changes"
        flag is activated.

        You can set this flag via the method :meth:`.AbstractXBeeDevice.enable_apply_changes`.

        This flag only works for volatile memory, if you want to save
        changed parameters in non-volatile memory, even for remote devices,
        you must execute "WR" command by one of the 2 ways mentioned above.

        Args:
            parameter (String): parameter to set.
            value (Bytearray): value of the parameter.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            ValueError: if ``parameter`` is ``None`` or ``value`` is ``None``.
        """
        if value is None:
            raise ValueError("Value of the parameter cannot be None.")

        self.__send_parameter(parameter, parameter_value=value)

        # Refresh cached parameters if this method modifies some of them.
        self._refresh_if_cached(parameter, value)

    def execute_command(self, parameter):
        """
        Executes the provided command.

        Args:
            parameter (String): The name of the AT command to be executed.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        self.__send_parameter(parameter, parameter_value=None)

    def __send_parameter(self, parameter, parameter_value=None):
        """
        Sends the given AT parameter to this XBee device with an optional
        argument or value and returns the response (likely the value) of that
        parameter in a byte array format.

        Args:
            parameter (String): The name of the AT command to be executed.
            parameter_value (bytearray, optional): The value of the parameter to set (if any).

        Returns:
            Bytearray: A byte array containing the value of the parameter.

        Raises:
            ValueError: if ``parameter`` is ``None`` or if ``len(parameter) != 2``.
        """
        if parameter is None:
            raise ValueError("Parameter cannot be None.")
        if len(parameter) != 2:
            raise ValueError("Parameter must contain exactly 2 characters.")

        at_command = ATCommand(parameter, parameter=parameter_value)

        # Send the AT command.
        response = self._send_at_command(at_command)

        self._check_at_cmd_response_is_valid(response)

        return response.response

    def _check_at_cmd_response_is_valid(self, response):
        """
        Checks if the provided ``ATCommandResponse`` is valid throwing an
        :class:`.ATCommandException` in case it is not.

        Args:
            response: The AT command response to check.

        Raises:
            ATCommandException: if ``response`` is ``None`` or
                                if ``response.response != OK``.
        """
        if response is None or not isinstance(response, ATCommandResponse) or response.status is None:
            raise ATCommandException()
        elif response.status != ATCommandStatus.OK:
            raise ATCommandException(cmd_status=response.status)

    def _send_at_command(self, command):
        """
        Sends the given AT command and waits for answer or until the configured
        receive timeout expires.

        Args:
            command (:class:`.ATCommand`): AT command to be sent.

        Returns:
            :class:`.ATCommandResponse`: object containing the response of the command
                                         or ``None`` if there is no response.

        Raises:
            ValueError: if ``command`` is ``None``.
            InvalidOperatingModeException: if the operating mode is different than ``API`` or ``ESCAPED_API_MODE``.

        """
        if command is None:
            raise ValueError("AT command cannot be None.")

        operating_mode = self._get_operating_mode()
        if operating_mode != OperatingMode.API_MODE and operating_mode != OperatingMode.ESCAPED_API_MODE:
            raise InvalidOperatingModeException(op_mode=operating_mode)

        if self.is_remote():
            remote_at_cmd_opts = RemoteATCmdOptions.NONE.value
            if self.is_apply_changes_enabled():
                remote_at_cmd_opts |= RemoteATCmdOptions.APPLY_CHANGES.value

            remote_16bit_addr = self.get_16bit_addr()
            if remote_16bit_addr is None:
                remote_16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

            packet = RemoteATCommandPacket(self._get_next_frame_id(), self.get_64bit_addr(), remote_16bit_addr,
                                           remote_at_cmd_opts, command.command, parameter=command.parameter)
        else:
            if self.is_apply_changes_enabled():
                packet = ATCommPacket(self._get_next_frame_id(), command.command,
                                      parameter=command.parameter)
            else:
                packet = ATCommQueuePacket(self._get_next_frame_id(), command.command, parameter=command.parameter)

        if self.is_remote():
            answer_packet = self._local_xbee_device.send_packet_sync_and_get_response(packet)
        else:
            answer_packet = self._send_packet_sync_and_get_response(packet)

        response = None

        if isinstance(answer_packet, ATCommResponsePacket) or isinstance(answer_packet, RemoteATCommandResponsePacket):
            response = ATCommandResponse(command, response=answer_packet.command_value,
                                         status=answer_packet.status)

        return response

    def apply_changes(self):
        """
        Applies changes via ``AC`` command.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        self.execute_command(ATStringCommand.AC.command)

    def write_changes(self):
        """
        Writes configurable parameter values to the non-volatile memory of the
        XBee device so that parameter modifications persist through subsequent
        resets.

        Parameters values remain in this device's memory until overwritten by
        subsequent use of this method.

        If changes are made without writing them to non-volatile memory, the
        module reverts back to previously saved parameters the next time the
        module is powered-on.

        Writing the parameter modifications does not mean those values are
        immediately applied, this depends on the status of the 'apply
        configuration changes' option. Use method
        :meth:`is_apply_configuration_changes_enabled` to get its status and
        :meth:`enable_apply_configuration_changes` to enable/disable the
        option. If it is disabled, method :meth:`apply_changes` can be used in
        order to manually apply the changes.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        self.execute_command(ATStringCommand.WR.command)

    @abstractmethod
    def reset(self):
        """
        Performs a software reset on this XBee device and blocks until the process is completed.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        pass

    def read_device_info(self, init=True):
        """
        Updates all instance parameters reading them from the XBee device.

        Args:
            init (Boolean, optional, default=`True`): If ``False`` only not initialized parameters
                are read, all if ``True``.
        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        if self.is_remote():
            if not self._local_xbee_device.comm_iface.is_interface_open:
                raise XBeeException("Local XBee device's serial port closed")
        else:
            if (self._operating_mode != OperatingMode.API_MODE and
               self._operating_mode != OperatingMode.ESCAPED_API_MODE):
                raise InvalidOperatingModeException(op_mode=self._operating_mode)

            if not self._comm_iface.is_interface_open:
                raise XBeeException("XBee device's serial port closed")

        # Hardware version:
        if init or self._hardware_version is None:
            self._hardware_version = HardwareVersion.get(
                self.get_parameter(ATStringCommand.HV.command)[0])
        # Firmware version:
        if init or self._firmware_version is None:
            self._firmware_version = self.get_parameter(ATStringCommand.VR.command)

        # Original value of the protocol:
        orig_protocol = self.get_protocol()
        # Protocol:
        self._protocol = XBeeProtocol.determine_protocol(self._hardware_version.code, self._firmware_version)

        if orig_protocol is not None and orig_protocol != XBeeProtocol.UNKNOWN and orig_protocol != self._protocol:
            raise XBeeException("Error reading device information: "
                                "Your module seems to be %s and NOT %s. " % (self._protocol, orig_protocol) +
                                "Check if you are using the appropriate device class.")

        # 64-bit address:
        if init or self._64bit_addr is None or self._64bit_addr == XBee64BitAddress.UNKNOWN_ADDRESS:
            sh = self.get_parameter(ATStringCommand.SH.command)
            sl = self.get_parameter(ATStringCommand.SL.command)
            self._64bit_addr = XBee64BitAddress(sh + sl)
        # Node ID:
        if init or self._node_id is None:
            self._node_id = self.get_parameter(ATStringCommand.NI.command).decode()
        # 16-bit address:
        if (self._protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.RAW_802_15_4, XBeeProtocol.XTEND,
                               XBeeProtocol.SMART_ENERGY, XBeeProtocol.ZNET]
                and (init or self._16bit_addr is None
                     or self._16bit_addr == XBee16BitAddress.UNKNOWN_ADDRESS)):
            r = self.get_parameter(ATStringCommand.MY.command)
            self._16bit_addr = XBee16BitAddress(r)

        # Role:
        if init or self._role is None or self._role == Role.UNKNOWN:
            self._role = self._determine_role()

    def _determine_role(self):
        """
        Determines the role of the device depending on the device protocol.

        Returns:
            :class:`digi.xbee.models.protocol.Role`: The XBee role.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        if self._protocol in [XBeeProtocol.DIGI_MESH, XBeeProtocol.SX, XBeeProtocol.XTEND_DM]:
            ce = utils.bytes_to_int(self.get_parameter(ATStringCommand.CE.command))
            if ce == 0:
                ss = self.get_parameter(ATStringCommand.SS.command)
                if not ss:
                    return Role.ROUTER

                ss = utils.bytes_to_int(ss)
                if utils.is_bit_enabled(ss, 1):
                    return Role.COORDINATOR
                else:
                    return Role.ROUTER
            elif ce == 1:
                return Role.COORDINATOR
            else:
                return Role.END_DEVICE
        elif self._protocol in [XBeeProtocol.RAW_802_15_4, XBeeProtocol.DIGI_POINT,
                                XBeeProtocol.XLR, XBeeProtocol.XLR_DM]:
            ce = utils.bytes_to_int(self.get_parameter(ATStringCommand.CE.command))
            if self._protocol == XBeeProtocol.RAW_802_15_4:
                if ce == 0:
                    return Role.END_DEVICE
                elif ce == 1:
                    return Role.COORDINATOR
            else:
                if ce == 0:
                    return Role.ROUTER
                elif ce in (1, 3):
                    return Role.COORDINATOR
                elif ce in (2, 4, 6):
                    return Role.END_DEVICE
        elif self._protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.SMART_ENERGY]:
            try:
                ce = utils.bytes_to_int(self.get_parameter(ATStringCommand.CE.command))
                if ce == 1:
                    return Role.COORDINATOR

                sm = utils.bytes_to_int(self.get_parameter(ATStringCommand.SM.command))

                return Role.ROUTER if sm == 0 else Role.END_DEVICE
            except ATCommandException:
                from digi.xbee.models.zdo import NodeDescriptorReader
                nd = NodeDescriptorReader(
                    self, configure_ao=True,
                    timeout=3*self._timeout if self.is_remote() else 2*self._timeout) \
                    .get_node_descriptor()
                if nd:
                    return nd.role

        return Role.UNKNOWN

    def get_node_id(self):
        """
        Returns the Node Identifier (``NI``) value of the XBee device.

        Returns:
            String: the Node Identifier (``NI``) of the XBee device.
        """
        return self._node_id

    def set_node_id(self, node_id):
        """
        Sets the Node Identifier (``NI``) value of the XBee device..

        Args:
            node_id (String): the new Node Identifier (``NI``) of the XBee device.

        Raises:
            ValueError: if ``node_id`` is ``None`` or its length is greater than 20.
            TimeoutException: if the response is not received before the read timeout expires.
        """
        if node_id is None:
            raise ValueError("Node ID cannot be None")
        if len(node_id) > 20:
            raise ValueError("Node ID length must be less than 21")

        self.set_parameter(ATStringCommand.NI.command, bytearray(node_id, 'utf8'))
        self._node_id = node_id

    def get_hardware_version(self):
        """
        Returns the hardware version of the XBee device.

        Returns:
            :class:`.HardwareVersion`: the hardware version of the XBee device.

        .. seealso::
           | :class:`.HardwareVersion`
        """
        return self._hardware_version

    def get_firmware_version(self):
        """
        Returns the firmware version of the XBee device.

        Returns:
            Bytearray: the hardware version of the XBee device.
        """
        return self._firmware_version

    def get_protocol(self):
        """
        Returns the current protocol of the XBee device.

        Returns:
            :class:`.XBeeProtocol`: the current protocol of the XBee device.

        .. seealso::
           | :class:`.XBeeProtocol`
        """
        return self._protocol

    def get_16bit_addr(self):
        """
        Returns the 16-bit address of the XBee device.

        Returns:
            :class:`.XBee16BitAddress`: the 16-bit address of the XBee device.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self._16bit_addr

    def set_16bit_addr(self, value):
        """
        Sets the 16-bit address of the XBee device.

        Args:
            value (:class:`.XBee16BitAddress`): the new 16-bit address of the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if the current protocol is not 802.15.4.
        """
        if self.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise OperationNotSupportedException(message="16-bit address can only be set in 802.15.4 protocol")

        self.set_parameter(ATStringCommand.MY.command, value.address)
        self._16bit_addr = value

    def get_64bit_addr(self):
        """
        Returns the 64-bit address of the XBee device.

        Returns:
            :class:`.XBee64BitAddress`: the 64-bit address of the XBee device.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self._64bit_addr

    def get_role(self):
        """
        Gets the XBee role.

        Returns:
             :class:`digi.xbee.models.protocol.Role`: the role of the XBee.

        .. seealso::
           | :class:`digi.xbee.models.protocol.Role`
        """
        return self._role

    def get_current_frame_id(self):
        """
        Returns the last used frame ID.

        Returns:
            Integer: the last used frame ID.
        """
        return self.__current_frame_id

    def enable_apply_changes(self, value):
        """
        Sets the apply_changes flag.

        Args:
            value (Boolean): ``True`` to enable the apply changes flag, ``False`` to disable it.
        """
        self._apply_changes_flag = value

    def is_apply_changes_enabled(self):
        """
        Returns whether the apply_changes flag is enabled or not.

        Returns:
            Boolean: ``True`` if the apply_changes flag is enabled, ``False`` otherwise.
        """
        return self._apply_changes_flag

    @abstractmethod
    def is_remote(self):
        """
        Determines whether the XBee device is remote or not.

        Returns:
            Boolean: ``True`` if the XBee device is remote, ``False`` otherwise.
        """
        pass

    def set_sync_ops_timeout(self, sync_ops_timeout):
        """
        Sets the serial port read timeout.

        Args:
            sync_ops_timeout (Integer): the read timeout, expressed in seconds.
        """
        self._timeout = sync_ops_timeout
        if self.is_remote():
            self._local_xbee_device.comm_iface.timeout = self._timeout
        else:
            self._comm_iface.timeout = self._timeout

    def get_sync_ops_timeout(self):
        """
        Returns the serial port read timeout.

        Returns:
            Integer: the serial port read timeout in seconds.
        """
        return self._timeout

    def get_dest_address(self):
        """
        Returns the 64-bit address of the XBee device that data will be reported to.

        Returns:
            :class:`.XBee64BitAddress`: the address.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        dh = self.get_parameter(ATStringCommand.DH.command)
        dl = self.get_parameter(ATStringCommand.DL.command)
        return XBee64BitAddress(dh + dl)

    def set_dest_address(self, addr):
        """
        Sets the 64-bit address of the XBee device that data will be reported to.

        Args:
            addr (:class:`.XBee64BitAddress` or :class:`.RemoteXBeeDevice`): the address itself or the remote XBee
                device that you want to set up its address as destination address.

        Raises:
            TimeoutException: If the response is not received before the read timeout expires.
            XBeeException: If the XBee device's serial port is closed.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: If the response is not as expected.
            ValueError: If ``addr`` is ``None``.
        """
        if isinstance(addr, RemoteXBeeDevice):
            addr = addr.get_64bit_addr()

        apply_changes = None
        with self.__generic_lock:
            try:
                apply_changes = self.is_apply_changes_enabled()
                self.enable_apply_changes(False)
                self.set_parameter(ATStringCommand.DH.command, addr.address[:4])
                self.set_parameter(ATStringCommand.DL.command, addr.address[4:])
            except (TimeoutException, XBeeException, InvalidOperatingModeException, ATCommandException) as e:
                # Raise the exception.
                raise e
            finally:
                if apply_changes:
                    self.enable_apply_changes(True)
                    self.apply_changes()

    def get_pan_id(self):
        """
        Returns the operating PAN ID of the XBee device.

        Returns:
            Bytearray: operating PAN ID of the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
        """
        if self.get_protocol() == XBeeProtocol.ZIGBEE:
            return self.get_parameter(ATStringCommand.OP.command)
        return self.get_parameter(ATStringCommand.ID.command)

    def set_pan_id(self, value):
        """
        Sets the operating PAN ID of the XBee device.

        Args:
            value (Bytearray): the new operating PAN ID of the XBee device.. Must have only 1 or 2 bytes.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
        """
        self.set_parameter(ATStringCommand.ID.command, value)

    def get_power_level(self):
        """
        Returns the power level of the XBee device.

        Returns:
            :class:`.PowerLevel`: the power level of the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.

        .. seealso::
           | :class:`.PowerLevel`
        """
        return PowerLevel.get(self.get_parameter(ATStringCommand.PL.command)[0])

    def set_power_level(self, power_level):
        """
        Sets the power level of the XBee device.

        Args:
            power_level (:class:`.PowerLevel`): the new power level of the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.

        .. seealso::
           | :class:`.PowerLevel`
        """
        self.set_parameter(ATStringCommand.PL.command, bytearray([power_level.code]))

    def set_io_configuration(self, io_line, io_mode):
        """
        Sets the configuration of the provided IO line.

        Args:
            io_line (:class:`.IOLine`): the IO line to configure.
            io_mode (:class:`.IOMode`): the IO mode to set to the IO line.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOMode`
        """
        self.set_parameter(io_line.at_command, bytearray([io_mode.value]))

    def get_io_configuration(self, io_line):
        """
        Returns the configuration of the provided IO line.

        Args:
            io_line (:class:`.IOLine`): the io line to configure.

        Returns:
            :class:`.IOMode`: the IO mode of the IO line provided.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if the received data is not an IO mode.
        """
        value = self.get_parameter(io_line.at_command)
        try:
            mode = IOMode(value[0])
        except ValueError:
            raise OperationNotSupportedException(
                "Received configuration IO mode '%s' is invalid." % utils.hex_to_string(value))
        return mode

    def get_io_sampling_rate(self):
        """
        Returns the IO sampling rate of the XBee device.

        Returns:
            Integer: the IO sampling rate of XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        resp = self.get_parameter(ATStringCommand.IR.command)
        return utils.bytes_to_int(resp) / 1000.00

    def set_io_sampling_rate(self, rate):
        """
        Sets the IO sampling rate of the XBee device in seconds. A sample rate of 0 means the IO sampling feature is
        disabled.

        Args:
            rate (Integer): the new IO sampling rate of the XBee device in seconds.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        self.set_parameter(ATStringCommand.IR.command, utils.int_to_bytes(int(rate * 1000)))

    def read_io_sample(self):
        """
        Returns an IO sample from the XBee device containing the value of all enabled digital IO and
        analog input channels.

        Returns:
            :class:`.IOSample`: the IO sample read from the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.

        .. seealso::
           | :class:`.IOSample`
        """
        # The response to the IS command in local 802.15.4 devices is empty,
        # so we have to use callbacks to read the packet.
        if not self.is_remote() and self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            lock = threading.Condition()
            self.__io_packet_received = False
            self.__io_packet_payload = None

            def io_sample_callback(received_packet):
                # Discard non API packets.
                if not isinstance(received_packet, XBeeAPIPacket):
                    return
                # If we already have received an IO packet, ignore this packet.
                if self.__io_packet_received:
                    return
                frame_type = received_packet.get_frame_type()
                # Save the packet value (IO sample payload).
                if (frame_type == ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR
                        or frame_type == ApiFrameType.RX_IO_16
                        or frame_type == ApiFrameType.RX_IO_64):
                    self.__io_packet_payload = received_packet.rf_data
                else:
                    return
                # Set the IO packet received flag.
                self.__io_packet_received = True
                # Continue execution by notifying the lock object.
                lock.acquire()
                lock.notify()
                lock.release()

            self._add_packet_received_callback(io_sample_callback)

            try:
                # Execute command.
                self.execute_command(ATStringCommand.IS.command)

                lock.acquire()
                lock.wait(self.get_sync_ops_timeout())
                lock.release()

                if self.__io_packet_payload is None:
                    raise TimeoutException(message="Timeout waiting for the IO response packet.")
                sample_payload = self.__io_packet_payload
            finally:
                self._del_packet_received_callback(io_sample_callback)
        else:
            sample_payload = self.get_parameter(ATStringCommand.IS.command)

        try:
            return IOSample(sample_payload)
        except Exception as e:
            raise XBeeException("Could not create the IO sample.", e)

    def get_adc_value(self, io_line):
        """
        Returns the analog value of the provided IO line.

        The provided IO line must be previously configured as ADC. To  do so,
        use :meth:`.AbstractXBeeDevice.set_io_configuration` and :attr:`.IOMode.ADC`.

        Args:
            io_line (:class:`.IOLine`): the IO line to get its ADC value.

        Returns:
            Integer: the analog value corresponding to the provided IO line.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if the response does not contain the value for the given IO line.

        .. seealso::
           | :class:`.IOLine`
        """
        io_sample = self.read_io_sample()
        if not io_sample.has_analog_values() or io_line not in io_sample.analog_values.keys():
            raise OperationNotSupportedException(
                "Answer does not contain analog data for %s." % io_line.description)

        return io_sample.analog_values[io_line]

    def set_pwm_duty_cycle(self, io_line, cycle):
        """
        Sets the duty cycle in % of the provided IO line.

        The provided IO line must be PWM-capable, previously configured as PWM output.

        Args:
            io_line (:class:`.IOLine`): the IO Line to be assigned.
            cycle (Integer): duty cycle in % to be assigned. Must be between 0 and 100.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            ValueError: if the given IO line does not have PWM capability or ``cycle`` is not between 0 and 100.

        .. seealso::
           | :class:`.IOLine`
           | :attr:`.IOMode.PWM`
        """
        if not io_line.has_pwm_capability():
            raise ValueError("%s has no PWM capability." % io_line)
        if cycle < 0 or cycle > 100:
            raise ValueError("Cycle must be between 0% and 100%.")

        duty_cycle = int(round(cycle * 1023.00 / 100.00))

        self.set_parameter(io_line.pwm_at_command, bytearray(utils.int_to_bytes(duty_cycle)))

    def get_pwm_duty_cycle(self, io_line):
        """
        Returns the PWM duty cycle in % corresponding to the provided IO line.

        Args:
            io_line (:class:`.IOLine`): the IO line to get its PWM duty cycle.

        Returns:
            Integer: the PWM duty cycle of the given IO line or ``None`` if the response is empty.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            ValueError: if the passed :class:`.IO_LINE` has no PWM capability.

        .. seealso::
           | :class:`.IOLine`
        """
        if not io_line.has_pwm_capability():
            raise ValueError("%s has no PWM capability." % io_line)

        value = utils.bytes_to_int(self.get_parameter(io_line.pwm_at_command))
        return round(((value * 100.0 / 1023.0) * 100.0) / 100.0)

    def get_dio_value(self, io_line):
        """
        Returns the digital value of the provided IO line.

        The provided IO line must be previously configured as digital I/O.
        To do so, use :meth:`.AbstractXBeeDevice.set_io_configuration`.

        Args:
            io_line (:class:`.IOLine`): the DIO line to gets its digital value.

        Returns:
            :class:`.IOValue`: current value of the provided IO line.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if the response does not contain the value for the given IO line.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOValue`
        """
        sample = self.read_io_sample()
        if not sample.has_digital_values() or io_line not in sample.digital_values.keys():
            raise OperationNotSupportedException(
                "Answer does not contain digital data for %s." % io_line.description)
        return sample.digital_values[io_line]

    def set_dio_value(self, io_line, io_value):
        """
        Sets the digital value (high or low) to the provided IO line.
        
        Args:
            io_line (:class:`.IOLine`): the digital IO line to sets its value.
            io_value (:class:`.IOValue`): the IO value to set to the IO line.
            
        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOValue`
        """
        self.set_parameter(io_line.at_command, bytearray([io_value.value]))

    def set_dio_change_detection(self, io_lines_set):
        """
        Sets the digital IO lines to be monitored and sampled whenever their status changes.
        
        A ``None`` set of lines disables this feature.
        
        Args:
            io_lines_set: set of :class:`.IOLine`.
            
        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.

        .. seealso::
           | :class:`.IOLine`
        """
        flags = bytearray(2)
        if io_lines_set is not None:
            for io_line in io_lines_set:
                i = io_line.index
                if i < 8:
                    flags[1] = flags[1] | (1 << i)
                else:
                    flags[0] = flags[0] | ((1 << i) - 8)
        self.set_parameter(ATStringCommand.IC.command, flags)

    @utils.deprecated("1.3", details="Use :meth:`get_api_output_mode_value`")
    def get_api_output_mode(self):
        """
        Returns the API output mode of the XBee device.

        The API output mode determines the format that the received data is
        output through the serial interface of the XBee device.

        Returns:
            :class:`.APIOutputMode`: the API output mode of the XBee device.
            
        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.

        .. seealso::
           | :class:`.APIOutputMode`
        """
        return APIOutputMode.get(self.get_parameter(ATStringCommand.AO.command)[0])

    def get_api_output_mode_value(self):
        """
        Returns the API output mode of the XBee.

        The API output mode determines the format that the received data is
        output through the serial interface of the XBee.

        Returns:
            Bytearray: the parameter value.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or
                ESCAPED API. This method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if it is not supported by the current protocol.

        .. seealso::
           | :class:`digi.xbee.models.mode.APIOutputModeBit`
        """
        if self.get_protocol() not in (XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_MESH,
                                       XBeeProtocol.DIGI_POINT, XBeeProtocol.XLR,
                                       XBeeProtocol.XLR_DM):
            raise OperationNotSupportedException(
                message="Operation not supported for the current protocol (%s)"
                        % self.get_protocol().description)

        return self.get_parameter(ATStringCommand.AO.command)

    @utils.deprecated("1.3", details="Use :meth:`set_api_output_mode_value`")
    def set_api_output_mode(self, api_output_mode):
        """
        Sets the API output mode of the XBee device.
        
        Args:
            api_output_mode (:class:`.APIOutputMode`): the new API output mode of the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if the current protocol is ZigBee

        .. seealso::
           | :class:`.APIOutputMode`
        """
        self.set_parameter(ATStringCommand.AO.command, bytearray([api_output_mode.code]))

    def set_api_output_mode_value(self, api_output_mode):
        """
        Sets the API output mode of the XBee.

        Args:
            api_output_mode (Integer): new API output mode options. Calculate this value using
                the method
                :meth:`digi.xbee.models.mode.APIOutputModeBit.calculate_api_output_mode_value`
                with a set of :class:`digi.xbee.models.mode.APIOutputModeBit`.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            OperationNotSupportedException: if it is not supported by the current protocol.

        .. seealso::
           | :class:`digi.xbee.models.mode.APIOutputModeBit`
        """
        if api_output_mode is None:
            raise ValueError("API output mode cannot be None")

        if self.get_protocol() not in (XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_MESH,
                                       XBeeProtocol.DIGI_POINT, XBeeProtocol.XLR,
                                       XBeeProtocol.XLR_DM):
            raise OperationNotSupportedException(
                message="Operation not supported for the current protocol (%s)"
                        % self.get_protocol().description)

        self.set_parameter(ATStringCommand.AO.command, bytearray([api_output_mode]))

    def enable_bluetooth(self):
        """
        Enables the Bluetooth interface of this XBee device.

        To work with this interface, you must also configure the Bluetooth password if not done previously.
        You can use the :meth:`.AbstractXBeeDevice.update_bluetooth_password` method for that purpose.

        Note that your device must have Bluetooth Low Energy support to use this method.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
        """
        self._enable_bluetooth(True)

    def disable_bluetooth(self):
        """
        Disables the Bluetooth interface of this XBee device.

        Note that your device must have Bluetooth Low Energy support to use this method.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
        """
        self._enable_bluetooth(False)

    def _enable_bluetooth(self, enable):
        """
        Enables or disables the Bluetooth interface of this XBee device.

        Args:
            enable (Boolean): ``True`` to enable the Bluetooth interface, ``False`` to disable it.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
        """
        self.set_parameter(ATStringCommand.BT.command, b'\x01' if enable else b'\x00')
        self.write_changes()
        self.apply_changes()

    def get_bluetooth_mac_addr(self):
        """
        Reads and returns the EUI-48 Bluetooth MAC address of this XBee device in a format such as ``00112233AABB``.

        Note that your device must have Bluetooth Low Energy support to use this method.

        Returns:
            String: The Bluetooth MAC address.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
        """
        return utils.hex_to_string(self.get_parameter(ATStringCommand.BL.command), pretty=False)

    def update_bluetooth_password(self, new_password):
        """
        Changes the password of this Bluetooth device with the new one provided.

        Note that your device must have Bluetooth Low Energy support to use this method.

        Args:
            new_password (String): New Bluetooth password.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
        """
        import srp
        
        # Generate the salt and verifier using the SRP library.
        salt, verifier = srp.create_salted_verification_key(self._BLE_API_USERNAME, new_password,
                                                            hash_alg=srp.SHA256, ng_type=srp.NG_1024, salt_len=4)

        # Ensure the verifier is 128 bytes.
        verifier = (128 - len(verifier)) * b'\x00' + verifier

        # Set the salt.
        self.set_parameter(ATStringCommand.DOLLAR_S.command, salt)

        # Set the verifier (split in 4 settings)
        index = 0
        at_length = int(len(verifier) / 4)

        self.set_parameter(ATStringCommand.DOLLAR_V.command, verifier[index:(index + at_length)])
        index += at_length
        self.set_parameter(ATStringCommand.DOLLAR_W.command, verifier[index:(index + at_length)])
        index += at_length
        self.set_parameter(ATStringCommand.DOLLAR_X.command, verifier[index:(index + at_length)])
        index += at_length
        self.set_parameter(ATStringCommand.DOLLAR_Y.command, verifier[index:(index + at_length)])

        # Write and apply changes.
        self.write_changes()
        self.apply_changes()

    def update_firmware(self, xml_firmware_file, xbee_firmware_file=None, bootloader_firmware_file=None,
                        timeout=None, progress_callback=None):
        """
        Performs a firmware update operation of the device.

        Args:
            xml_firmware_file (String): path of the XML file that describes the firmware to upload.
            xbee_firmware_file (String, optional): location of the XBee binary firmware file.
            bootloader_firmware_file (String, optional): location of the bootloader binary firmware file.
            timeout (Integer, optional): the maximum time to wait for target read operations during the update process.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            XBeeException: if the device is not open.
            InvalidOperatingModeException: if the device operating mode is invalid.
            OperationNotSupportedException: if the firmware update is not supported in the XBee device.
            FirmwareUpdateException: if there is any error performing the firmware update.
        """
        from digi.xbee import firmware

        if not self._comm_iface.is_open:
            raise XBeeException("XBee device's communication interface closed.")
        if self.get_hardware_version() and self.get_hardware_version().code not in firmware.SUPPORTED_HARDWARE_VERSIONS:
            raise OperationNotSupportedException("Firmware update is only supported in XBee3 devices")
        if self.is_remote():
            firmware.update_remote_firmware(self, xml_firmware_file,
                                            ota_firmware_file=xbee_firmware_file,
                                            otb_firmware_file=bootloader_firmware_file,
                                            timeout=timeout,
                                            progress_callback=progress_callback)
        else:
            if self._operating_mode != OperatingMode.API_MODE and \
                    self._operating_mode != OperatingMode.ESCAPED_API_MODE:
                raise InvalidOperatingModeException(op_mode=self._operating_mode)
            if not self._serial_port:
                raise OperationNotSupportedException("Firmware update is only supported in local XBee connected by "
                                                     "serial.")
            firmware.update_local_firmware(self, xml_firmware_file,
                                           xbee_firmware_file=xbee_firmware_file,
                                           bootloader_firmware_file=bootloader_firmware_file,
                                           timeout=timeout,
                                           progress_callback=progress_callback)

    def _autodetect_device(self):
        """
        Performs an autodetection of the device.

        Raises:
            RecoveryException: if there is any error performing the recovery.
            OperationNotSupportedException: if the firmware autodetection is not supported in the XBee device.
        """
        from digi.xbee import recovery

        if self.get_hardware_version() and self.get_hardware_version().code not in recovery.SUPPORTED_HARDWARE_VERSIONS:
            raise OperationNotSupportedException("Autodetection is only supported in XBee3 devices")
        recovery.recover_device(self)

    def apply_profile(self, profile_path, progress_callback=None):
        """
        Applies the given XBee profile to the XBee device.

        Args:
            profile_path (String): path of the XBee profile file to apply.
            progress_callback (Function, optional): function to execute to receive progress information. Receives two
                                                    arguments:

                * The current apply profile task as a String
                * The current apply profile task percentage as an Integer

        Raises:
            XBeeException: if the device is not open.
            InvalidOperatingModeException: if the device operating mode is invalid.
            UpdateProfileException: if there is any error applying the XBee profile.
            OperationNotSupportedException: if XBee profiles are not supported in the XBee device.
        """
        from digi.xbee import profile

        if not self._comm_iface.is_open:
            raise XBeeException("XBee device's communication interface closed.")
        if not self.is_remote() and self._operating_mode != OperatingMode.API_MODE and \
                self._operating_mode != OperatingMode.ESCAPED_API_MODE:
            raise InvalidOperatingModeException(op_mode=self._operating_mode)
        if self.get_hardware_version() and self.get_hardware_version().code not in profile.SUPPORTED_HARDWARE_VERSIONS:
            raise OperationNotSupportedException("XBee profiles are only supported in XBee3 devices")

        profile.apply_xbee_profile(self, profile_path, progress_callback=progress_callback)

    def _get_ai_status(self):
        """
        Returns the current association status of this XBee device.

        It indicates occurrences of errors during the modem initialization
        and connection.

        Returns:
            :class:`.AssociationIndicationStatus`: The association indication status of the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        value = self.get_parameter(ATStringCommand.AI.command)
        return AssociationIndicationStatus.get(utils.bytes_to_int(value))

    def _force_disassociate(self):
        """
        Forces this XBee device to immediately disassociate from the network and
        re-attempt to associate.

        Only valid for End Devices.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        self.execute_command(ATStringCommand.DA.command)

    def _refresh_if_cached(self, parameter, value):
        """
        Refreshes the proper cached parameter depending on ``parameter`` value.
        
        If ``parameter`` is not a cached parameter, this method does nothing.

        Args:
            parameter (String): the parameter to refresh its value.
            value (Bytearray): the new value of the parameter.
        """
        if parameter == ATStringCommand.NI.command:
            self._node_id = value.decode()
        elif parameter == ATStringCommand.MY.command:
            self._16bit_addr = XBee16BitAddress(value)
        elif parameter == ATStringCommand.AP.command:
            self._operating_mode = OperatingMode.get(utils.bytes_to_int(value))

    def _get_next_frame_id(self):
        """
        Returns the next frame ID of the XBee device.
        
        Returns:
            Integer: The next frame ID of the XBee device.
        """
        if self.is_remote():
            fid = self._local_xbee_device._get_next_frame_id()

        else:
            if self.__current_frame_id == 0xFF:
                self.__current_frame_id = 1
            else:
                self.__current_frame_id += 1
            fid = self.__current_frame_id

        return fid

    def _get_operating_mode(self):
        """
        Returns the Operating mode (AT, API or API escaped) of this XBee device
        for a local device, and the operating mode of the local device used as
        communication interface for a remote device.

        Returns:
            :class:`.OperatingMode`: The operating mode of the local XBee device.
        """
        if self.is_remote():
            return self._local_xbee_device.operating_mode
        return self._operating_mode

    @staticmethod
    def _before_send_method(func):
        """
        Decorator. Used to check the operating mode and the COM port's state before a sending operation.
        """
        @wraps(func)
        def dec_function(self, *args, **kwargs):
            if not self._comm_iface.is_interface_open:
                raise XBeeException("XBee device's serial port closed.")
            if (self._operating_mode != OperatingMode.API_MODE and
               self._operating_mode != OperatingMode.ESCAPED_API_MODE):
                raise InvalidOperatingModeException(op_mode=args[0].operating_mode)
            return func(self, *args, **kwargs)
        return dec_function

    @staticmethod
    def _after_send_method(func):
        """
        Decorator. Used to check if the response's transmit status is success after a sending operation.
        """
        @wraps(func)
        def dec_function(*args, **kwargs):
            response = func(*args, **kwargs)
            if (response.transmit_status != TransmitStatus.SUCCESS
                    and response.transmit_status != TransmitStatus.SELF_ADDRESSED):
                raise TransmitException(transmit_status=response.transmit_status)
            return response
        return dec_function

    def _get_packet_by_id(self, frame_id):
        """
        Reads packets until there is one packet found with the provided frame ID.
        
        Args:
            frame_id (Integer): frame ID to use for. Must be between 0 and 255.
            
        Returns:
            :class:XBeePacket: the first XBee packet read whose frame ID matches the provided one.
            
        Raises:
            ValueError: if ``frame_id`` is less than 0 or greater than 255.
            TimeoutException: if there was not any XBee packet matching the provided frame ID that could be read.
        """
        if not (0 <= frame_id <= 255):
            raise ValueError("Frame ID must be between 0 and 255.")

        queue = self._packet_listener.get_queue()

        packet = queue.get_by_id(frame_id, timeout=XBeeDevice.TIMEOUT_READ_PACKET)

        return packet

    @staticmethod
    def __is_api_packet(xbee_packet):
        """
        Determines whether the provided XBee packet is an API packet or not.
        
        Returns:
            Boolean: ``True`` if the provided XBee packet is an API packet (its frame type is inside
                :class:`.ApiFrameType` enum), ``False`` otherwise.
        """
        aft = xbee_packet.get_frame_type()
        try:
            ApiFrameType.get(aft)
        except ValueError:
            return False
        return True

    def _add_packet_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.PacketReceived`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * The received packet as a :class:`digi.xbee.packets.base.XBeeAPIPacket`
        """
        self._packet_listener.add_packet_received_callback(callback)

    def _del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.PacketReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.PacketReceived` event.
        """
        self._packet_listener.del_packet_received_callback(callback)

    def _send_packet_sync_and_get_response(self, packet_to_send, timeout=None):
        """
        Perform all operations needed for a synchronous operation when the packet
        listener is online. This operations are:

            1. Puts "_sync_packet" to ``None``, to discard the last sync. packet read.
            2. Refresh "_sync_packet" to be used by the thread in charge of the synchronous read.
            3. Tells the packet listener that this XBee device is waiting for a packet with a determined frame ID.
            4. Sends the ``packet_to_send``.
            5. Waits the configured timeout for synchronous operations.
            6. Returns all attributes to a consistent state (except _sync_packet)
                | 6.1. _sync_packet to ``None``.
                | 6.2. notify the listener that we are no longer waiting for any packet.
            7. Returns the received packet if it has arrived, ``None`` otherwise.

        This method must be only used when the packet listener is online.

        At the end of this method, the class attribute ``_sync_packet`` will be
        the packet read by this method, or ``None`` if the previous was not possible.
        Note that ``_sync_packet`` will remain being "the last packet read in a
        synchronous operation" until you call this method again.
        Then,  ``_sync_packet`` will be refreshed.

        Args:
            packet_to_send (:class:`.XBeePacket`): the packet to send.
            timeout (Integer, optional): timeout to wait. If no timeout is provided, the default one is used. To wait
                indefinitely, set to ``-1``.

        Returns:
            :class:`.XBeePacket`: the response packet obtained after sending the provided one.

        Raises:
            TimeoutException: if the response is not received in the configured timeout.

        .. seealso::
           | :class:`.XBeePacket`
        """
        lock = threading.Condition()
        response_list = list()

        # Create a packet received callback for the packet to be sent.
        def packet_received_callback(received_packet):
            # Check if it is the packet we are waiting for.
            if received_packet.needs_id() and received_packet.frame_id == packet_to_send.frame_id:
                if not isinstance(packet_to_send, XBeeAPIPacket) or not isinstance(received_packet, XBeeAPIPacket):
                    return
                # If the packet sent is an AT command, verify that the received one is an AT command response and
                # the command matches in both packets.
                if packet_to_send.get_frame_type() == ApiFrameType.AT_COMMAND \
                        and (received_packet.get_frame_type() != ApiFrameType.AT_COMMAND_RESPONSE
                             or packet_to_send.command != received_packet.command):
                    return
                # If the packet sent is a remote AT command, verify that the received one is a remote AT command
                # response and the command matches in both packets.
                if packet_to_send.get_frame_type() == ApiFrameType.REMOTE_AT_COMMAND_REQUEST \
                        and (received_packet.get_frame_type() != ApiFrameType.REMOTE_AT_COMMAND_RESPONSE
                             or packet_to_send.command != received_packet.command
                             or (packet_to_send.x64bit_dest_addr != XBee64BitAddress.BROADCAST_ADDRESS
                                 and packet_to_send.x64bit_dest_addr != XBee64BitAddress.UNKNOWN_ADDRESS
                                 and packet_to_send.x64bit_dest_addr != received_packet.x64bit_source_addr)
                             or (packet_to_send.x16bit_dest_addr != XBee16BitAddress.BROADCAST_ADDRESS
                                 and packet_to_send.x16bit_dest_addr != XBee16BitAddress.UNKNOWN_ADDRESS
                                 and packet_to_send.x16bit_dest_addr != received_packet.x16bit_source_addr)):
                    return
                # If the packet sent is a Socket Create, verify that the received one is a Socket Create Response.
                if packet_to_send.get_frame_type() == ApiFrameType.SOCKET_CREATE \
                        and received_packet.get_frame_type() != ApiFrameType.SOCKET_CREATE_RESPONSE:
                    return
                # If the packet sent is a Socket Option Request, verify that the received one is a Socket Option
                # Response and the socket ID matches in both packets.
                if packet_to_send.get_frame_type() == ApiFrameType.SOCKET_OPTION_REQUEST \
                        and (received_packet.get_frame_type() != ApiFrameType.SOCKET_OPTION_RESPONSE
                             or packet_to_send.socket_id != received_packet.socket_id):
                    return
                # If the packet sent is a Socket Connect, verify that the received one is a Socket Connect Response
                # and the socket ID matches in both packets.
                if packet_to_send.get_frame_type() == ApiFrameType.SOCKET_CONNECT \
                        and (received_packet.get_frame_type() != ApiFrameType.SOCKET_CONNECT_RESPONSE
                             or packet_to_send.socket_id != received_packet.socket_id):
                    return
                # If the packet sent is a Socket Close, verify that the received one is a Socket Close Response
                # and the socket ID matches in both packets.
                if packet_to_send.get_frame_type() == ApiFrameType.SOCKET_CLOSE \
                        and (received_packet.get_frame_type() != ApiFrameType.SOCKET_CLOSE_RESPONSE
                             or packet_to_send.socket_id != received_packet.socket_id):
                    return
                # If the packet sent is a Socket Bind, verify that the received one is a Socket Listen Response
                # and the socket ID matches in both packets.
                if packet_to_send.get_frame_type() == ApiFrameType.SOCKET_BIND \
                        and (received_packet.get_frame_type() != ApiFrameType.SOCKET_LISTEN_RESPONSE
                             or packet_to_send.socket_id != received_packet.socket_id):
                    return
                # Verify that the sent packet is not the received one! This can happen when the echo mode is enabled
                # in the serial port.
                if packet_to_send == received_packet:
                    return

                # Add the received packet to the list and notify the lock.
                response_list.append(received_packet)
                lock.acquire()
                lock.notify()
                lock.release()

        # Add the packet received callback.
        self._add_packet_received_callback(packet_received_callback)

        try:
            # Send the packet.
            self._send_packet(packet_to_send)
            # Wait for response or timeout.
            lock.acquire()
            if timeout == -1:
                lock.wait()
            else:
                lock.wait(self._timeout if timeout is None else timeout)
            lock.release()
            # After the wait check if we received any response, if not throw timeout exception.
            if not response_list:
                raise TimeoutException(message="Response not received in the configured timeout.")
            # Return the received packet.
            return response_list[0]
        finally:
            # Always remove the packet listener from the list.
            self._del_packet_received_callback(packet_received_callback)

    def _send_packet(self, packet, sync=False):
        """
        Sends a packet to the XBee device and waits for the response.
        The packet to send will be escaped or not depending on the current
        operating mode.

        This method can be synchronous or asynchronous.

        If is synchronous, this method  will discard all response
        packets until it finds the one that has the appropriate frame ID,
        that is, the sent packet's frame ID.

        If is asynchronous, this method does not wait for any packet. Returns ``None``.

        Args:
            packet (:class:`.XBeePacket`): The packet to send.
            sync (Boolean): ``True`` to wait for the response of the sent packet and return it, ``False`` otherwise.

        Returns:
            :class:`.XBeePacket`: The response packet if ``sync`` is ``True``, ``None`` otherwise.

        Raises:
            TimeoutException: if ``sync`` is ``True`` and the response packet for the sent one cannot be read.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the packet listener is not running.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBeePacket`
        """
        if not self._packet_listener.is_running():
            raise XBeeException("Packet listener is not running.")

        escape = self._operating_mode == OperatingMode.ESCAPED_API_MODE
        out = packet.output(escaped=escape)
        self._comm_iface.write_frame(out)
        self._log.debug(self.LOG_PATTERN.format(comm_iface=str(self._comm_iface),
                                                event="SENT",
                                                opmode=self._operating_mode,
                                                content=utils.hex_to_string(out)))

        return self._get_packet_by_id(packet.frame_id) if sync else None

    def __get_log(self):
        """
        Returns the XBee device log.

        Returns:
            :class:`.Logger`: the XBee device logger.
        """
        return self._log

    log = property(__get_log)
    """:class:`.Logger`. The XBee device logger."""


class XBeeDevice(AbstractXBeeDevice):
    """
    This class represents a non-remote generic XBee device.
    
    This class has fields that are events. Its recommended to use only the
    append() and remove() method on them, or -= and += operators.
    If you do something more with them, it's for your own risk.
    """

    __DEFAULT_GUARD_TIME = 1.2  # seconds
    """
    Timeout to wait after entering and exiting command mode in seconds.
    
    It is used to determine the operating mode of the module (this 
    library only supports API modes, not AT (transparent) mode).
    """

    __TIMEOUT_ENTER_COMMAND_MODE = 1.5  # seconds
    """
    Timeout to wait after entering in command mode in seconds.
    
    It is used to determine the operating mode of the module (this 
    library only supports API modes, not transparent mode).
    """

    __TIMEOUT_RESET = 5  # seconds
    """
    Timeout to wait when resetting the module.
    """

    TIMEOUT_READ_PACKET = 3  # seconds
    """
    Timeout to read packets.
    """

    __COMMAND_MODE_CHAR = "+"
    """
    Character you have to send to enter AT command mode
    """

    __COMMAND_MODE_OK = "OK\r"
    """
    Response that will be receive if the attempt to enter in at command mode goes well.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.XBeeDevice` with the provided parameters.
        
        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.
        
        Raises:
            All exceptions raised by PySerial's Serial class constructor.
        
        .. seealso::
           | PySerial documentation: http://pyserial.sourceforge.net
        """
        super().__init__(serial_port=XBeeSerialPort(baud_rate=baud_rate,
                                                    port=port,
                                                    data_bits=data_bits,
                                                    stop_bits=stop_bits,
                                                    parity=parity,
                                                    flow_control=flow_control,
                                                    timeout=_sync_ops_timeout) if comm_iface is None else None,
                         sync_ops_timeout=_sync_ops_timeout,
                         comm_iface=comm_iface
                         )
        self._network = self._init_network()

        self.__packet_queue = None
        self.__data_queue = None
        self.__explicit_queue = None

        self.__modem_status_received = False

    @classmethod
    def create_xbee_device(cls, comm_port_data):
        """
        Creates and returns an :class:`.XBeeDevice` from data of the port to which is connected.
        
        Args:
            comm_port_data (Dictionary): dictionary with all comm port data needed.
            The dictionary keys are:
                | "baudRate"    --> Baud rate.
                | "port"        --> Port number.
                | "bitSize"     --> Bit size.
                | "stopBits"    --> Stop bits.
                | "parity"      --> Parity.
                | "flowControl" --> Flow control.
                | "timeout" for --> Timeout for synchronous operations (in seconds).

        Returns:
            :class:`.XBeeDevice`: the XBee device created.

        Raises:
            SerialException: if the port you want to open does not exist or is already opened.

        .. seealso::
           | :class:`.XBeeDevice`
        """
        return XBeeDevice(comm_port_data["port"],
                          comm_port_data["baudRate"],
                          data_bits=comm_port_data["bitSize"],
                          stop_bits=comm_port_data["stopBits"],
                          parity=comm_port_data["parity"],
                          flow_control=comm_port_data["flowControl"],
                          _sync_ops_timeout=comm_port_data["timeout"])

    def open(self, force_settings=False):
        """
        Opens the communication with the XBee device and loads some information about it.
        
        Args:
            force_settings (Boolean, optional): ``True`` to open the device ensuring/forcing that the specified
                serial settings are applied even if the current configuration is different,
                ``False`` to open the device with the current configuration. Default to False.

        Raises:
            TimeoutException: if there is any problem with the communication.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device is already open.
        """
        if self._is_open:
            raise XBeeException("XBee device already open.")

        # Store already registered callbacks
        packet_cbs = self._packet_listener.get_packet_received_callbacks() \
            if self._packet_listener else None
        data_cbs = self._packet_listener.get_data_received_callbacks() \
            if self._packet_listener else None
        modem_status_cbs = self._packet_listener.get_modem_status_received_callbacks() \
            if self._packet_listener else None
        io_cbs = self._packet_listener.get_io_sample_received_callbacks() \
            if self._packet_listener else None
        expl_data_cbs = self._packet_listener.get_explicit_data_received_callbacks() \
            if self._packet_listener else None
        ip_data_cbs = self._packet_listener.get_ip_data_received_callbacks() \
            if self._packet_listener else None
        sms_cbs = self._packet_listener.get_sms_received_callbacks() \
            if self._packet_listener else None
        user_data_relay_cbs = self._packet_listener.get_user_data_relay_received_callbacks() \
            if self._packet_listener else None
        bt_data_cbs = self._packet_listener.get_bluetooth_data_received_callbacks() \
            if self._packet_listener else None
        mp_data_cbs = self._packet_listener.get_micropython_data_received_callbacks() \
            if self._packet_listener else None

        self._comm_iface.open()
        self._log.info("%s port opened" % self._comm_iface)

        # Initialize the packet listener.
        self._packet_listener = None
        self._packet_listener = PacketListener(self._comm_iface, self)
        self.__packet_queue = self._packet_listener.get_queue()
        self.__data_queue = self._packet_listener.get_data_queue()
        self.__explicit_queue = self._packet_listener.get_explicit_queue()

        # Restore callbacks if any
        self._packet_listener.add_packet_received_callback(packet_cbs)
        self._packet_listener.add_data_received_callback(data_cbs)
        self._packet_listener.add_modem_status_received_callback(modem_status_cbs)
        self._packet_listener.add_io_sample_received_callback(io_cbs)
        self._packet_listener.add_explicit_data_received_callback(expl_data_cbs)
        self._packet_listener.add_ip_data_received_callback(ip_data_cbs)
        self._packet_listener.add_sms_received_callback(sms_cbs)
        self._packet_listener.add_user_data_relay_received_callback(user_data_relay_cbs)
        self._packet_listener.add_bluetooth_data_received_callback(bt_data_cbs)
        self._packet_listener.add_micropython_data_received_callback(mp_data_cbs)

        self._packet_listener.start()
        self._packet_listener.wait_until_started()

        if force_settings:
            try:
                self._do_open()
            except XBeeException as e:
                self.log.debug("Could not open the port with default setting, "
                               "forcing settings using recovery: %s" % str(e))
                if self._serial_port is None:
                    raise XBeeException("Can not open the port by forcing the settings, "
                                        "it is only supported for Serial")
                self._autodetect_device()
                self.open(force_settings=False)
        else:
            self._do_open()

    def _do_open(self):
        """
        Opens the communication with the XBee device and loads some information about it.

        Raises:
            TimeoutException: if there is any problem with the communication.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device is already open.
        """
        # Determine the operating mode of the XBee device.
        self._operating_mode = self._determine_operating_mode()
        if self._operating_mode == OperatingMode.UNKNOWN:
            self.close()
            raise InvalidOperatingModeException(message="Could not determine operating mode")
        if self._operating_mode not in [OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE]:
            self.close()
            raise InvalidOperatingModeException(op_mode=self._operating_mode)

        # Read the device info (obtain its parameters and protocol).
        self.read_device_info()

        self._is_open = True

    def close(self):
        """
        Closes the communication with the XBee device.
        
        This method guarantees that all threads running are stopped and
        the serial port is closed.
        """
        if self._network is not None:
            self._network.stop_discovery_process()

        if self._packet_listener is not None:
            self._packet_listener.stop()

        if self._comm_iface is not None and self._comm_iface.is_interface_open:
            self._comm_iface.close()
            self._log.info("%s closed" % self._comm_iface)

        self._is_open = False

    def __get_serial_port(self):
        """
        Returns the serial port associated to the XBee device, if any.

        Returns:
            :class:`.XBeeSerialPort`: the serial port associated to the XBee device. Returns ``None`` if the local XBee
                does not use serial communication.

        .. seealso::
           | :class:`.XBeeSerialPort`
        """
        return self._serial_port

    def __get_comm_iface(self):
        """
        Returns the hardware interface associated to the XBee device.

        Returns:
            :class:`.XBeeCommunicationInterface`: the hardware interface associated to the XBee device.

        .. seealso::
           | :class:`.XBeeSerialPort`
        """
        return self._comm_iface

    @AbstractXBeeDevice._before_send_method
    def get_parameter(self, param, parameter_value=None):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
        """
        return super().get_parameter(param, parameter_value=parameter_value)

    @AbstractXBeeDevice._before_send_method
    def set_parameter(self, param, value):
        """
        Override.

        See:
            :meth:`.AbstractXBeeDevice.set_parameter`
        """
        super().set_parameter(param, value)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_data_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee device corresponding to the given
        64-bit/16-bit address.

        This method will wait for the packet response.

        The default timeout for this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): The 64-bit address of the XBee that will receive the data.
            x16addr (:class:`.XBee16BitAddress`): The 16-bit address of the XBee that will receive the data,
                :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if it is unknown.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket` the response.

        Raises:
            ValueError: if ``x64addr`` is ``None``
            ValueError: if ``x16addr`` is ``None``
            ValueError: if ``data`` is ``None``.
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TransmitException: if the status of the response received is not OK.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TransmitPacket(self.get_next_frame_id(),
                                x64addr,
                                x16addr,
                                0,
                                transmit_options,
                                rf_data=data)
        return self.send_packet_sync_and_get_response(packet)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_data_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee device corresponding to the given
        64-bit address.

        This method will wait for the packet response.

        The default timeout for this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): The 64-bit address of the XBee that will receive the data.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket` the response.

        Raises:
            ValueError: if ``x64addr`` is ``None``
            ValueError: if ``data`` is ``None``.
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TransmitException: if the status of the response received is not OK.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        if self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            packet = TX64Packet(self.get_next_frame_id(),
                                x64addr,
                                transmit_options,
                                rf_data=data)
        else:
            packet = TransmitPacket(self.get_next_frame_id(),
                                    x64addr,
                                    XBee16BitAddress.UNKNOWN_ADDRESS,
                                    0,
                                    transmit_options,
                                    rf_data=data)
        return self.send_packet_sync_and_get_response(packet)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_data_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee device corresponding to the given
        16-bit address.

        This method will wait for the packet response.

        The default timeout for this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x16addr (:class:`.XBee16BitAddress`): The 16-bit address of the XBee that will receive the data.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket` the response.

        Raises:
            ValueError: if ``x16addr`` is ``None``
            ValueError: if ``data`` is ``None``.
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TransmitException: if the status of the response received is not OK.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TX16Packet(self.get_next_frame_id(),
                            x16addr,
                            transmit_options,
                            rf_data=data)
        return self.send_packet_sync_and_get_response(packet)

    def send_data(self, remote_xbee_device, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee device synchronously.
        
        This method will wait for the packet response.
        
        The default timeout for this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to send data to.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.
            
        Returns:
            :class:`.XBeePacket` the response.
            
        Raises:
            ValueError: if ``remote_xbee_device`` is ``None``.
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TransmitException: if the status of the response received is not OK.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
           | :class:`.XBeePacket`
        """
        if remote_xbee_device is None:
            raise ValueError("Remote XBee device cannot be None")

        protocol = self.get_protocol()
        if protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_POINT]:
            if remote_xbee_device.get_64bit_addr() is not None and remote_xbee_device.get_16bit_addr() is not None:
                return self._send_data_64_16(remote_xbee_device.get_64bit_addr(), remote_xbee_device.get_16bit_addr(),
                                             data, transmit_options=transmit_options)
            elif remote_xbee_device.get_64bit_addr() is not None:
                return self._send_data_64(remote_xbee_device.get_64bit_addr(), data,
                                          transmit_options=transmit_options)
            else:
                return self._send_data_64_16(XBee64BitAddress.UNKNOWN_ADDRESS, remote_xbee_device.get_16bit_addr(),
                                             data, transmit_options=transmit_options)
        elif protocol == XBeeProtocol.RAW_802_15_4:
            if remote_xbee_device.get_64bit_addr() is not None:
                return self._send_data_64(remote_xbee_device.get_64bit_addr(), data,
                                          transmit_options=transmit_options)
            else:
                return self._send_data_16(remote_xbee_device.get_16bit_addr(), data,
                                          transmit_options=transmit_options)
        else:
            return self._send_data_64(remote_xbee_device.get_64bit_addr(), data,
                                      transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    def _send_data_async_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee device corresponding to the given
        64-bit/16-bit address.

        This method won't wait for the response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): The 64-bit address of the XBee that will receive the data.
            x16addr (:class:`.XBee16BitAddress`): The 16-bit address of the XBee that will receive the data,
                :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if it is unknown.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket` the response.

        Raises:
            ValueError: if ``x64addr`` is ``None``
            ValueError: if ``x16addr`` is ``None``
            ValueError: if ``data`` is ``None``.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TransmitPacket(self.get_next_frame_id(),
                                x64addr,
                                x16addr,
                                0,
                                transmit_options,
                                rf_data=data)
        self.send_packet(packet)

    @AbstractXBeeDevice._before_send_method
    def _send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee device corresponding to the given
        64-bit address.

        This method won't wait for the response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): The 64-bit address of the XBee that will receive the data.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket` the response.

        Raises:
            ValueError: if ``x64addr`` is ``None``
            ValueError: if ``data`` is ``None``.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        if self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            packet = TX64Packet(self.get_next_frame_id(),
                                x64addr,
                                transmit_options,
                                rf_data=data)
        else:
            packet = TransmitPacket(self.get_next_frame_id(),
                                    x64addr,
                                    XBee16BitAddress.UNKNOWN_ADDRESS,
                                    0,
                                    transmit_options,
                                    rf_data=data)
        self.send_packet(packet)

    @AbstractXBeeDevice._before_send_method
    def _send_data_async_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee device corresponding to the given
        16-bit address.

        This method won't wait for the response.

        Args:
            x16addr (:class:`.XBee16BitAddress`): The 16-bit address of the XBee that will receive the data.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket` the response.

        Raises:
            ValueError: if ``x16addr`` is ``None``
            ValueError: if ``data`` is ``None``.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TX16Packet(self.get_next_frame_id(),
                            x16addr,
                            transmit_options,
                            rf_data=data)
        self.send_packet(packet)

    def send_data_async(self, remote_xbee_device, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee device.
        
        This method won't wait for the response.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to send data to.
            data (String or Bytearray): the raw data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
        """
        if remote_xbee_device is None:
            raise ValueError("Remote XBee device cannot be None")

        protocol = self.get_protocol()
        if protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_POINT]:
            if remote_xbee_device.get_64bit_addr() is not None and remote_xbee_device.get_16bit_addr() is not None:
                self._send_data_async_64_16(remote_xbee_device.get_64bit_addr(), remote_xbee_device.get_16bit_addr(),
                                            data, transmit_options=transmit_options)
            elif remote_xbee_device.get_64bit_addr() is not None:
                self._send_data_async_64(remote_xbee_device.get_64bit_addr(), data,
                                         transmit_options=transmit_options)
            else:
                self._send_data_async_64_16(XBee64BitAddress.UNKNOWN_ADDRESS, remote_xbee_device.get_16bit_addr(),
                                            data, transmit_options=transmit_options)
        elif protocol == XBeeProtocol.RAW_802_15_4:
            if remote_xbee_device.get_64bit_addr() is not None:
                self._send_data_async_64(remote_xbee_device.get_64bit_addr(), data,
                                         transmit_options=transmit_options)
            else:
                self._send_data_async_16(remote_xbee_device.get_16bit_addr(), data,
                                         transmit_options=transmit_options)
        else:
            self._send_data_async_64(remote_xbee_device.get_64bit_addr(), data,
                                     transmit_options=transmit_options)

    def send_data_broadcast(self, data, transmit_options=TransmitOptions.NONE.value):
        """
        Sends the provided data to all the XBee nodes of the network (broadcast).
        
        This method blocks till a success or error transmit status arrives or 
        the configured receive timeout expires.
        
        The received timeout is configured using the :meth:`.AbstractXBeeDevice.set_sync_ops_timeout`
        method and can be consulted with :meth:`.AbstractXBeeDevice.get_sync_ops_timeout` method.
        
        Args:
            data (String or Bytearray): data to send.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.
        
        Raises:
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TransmitException: if the status of the response received is not OK.
            XBeeException: if the XBee device's serial port is closed.
        """
        return self._send_data_64(XBee64BitAddress.BROADCAST_ADDRESS, data,
                                  transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    def send_user_data_relay(self, local_interface, data):
        """
        Sends the given data to the given XBee local interface.

        Args:
            local_interface (:class:`.XBeeLocalInterface`): Destination XBee local interface.
            data (Bytearray): Data to send.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ValueError: if ``local_interface`` is ``None``.
            XBeeException: if there is any problem sending the User Data Relay.

        .. seealso::
           | :class:`.XBeeLocalInterface`
        """
        if local_interface is None:
            raise ValueError("Destination interface cannot be None")

        # Send the packet asynchronously since User Data Relay frames do not receive any transmit status.
        self.send_packet(UserDataRelayPacket(self.get_next_frame_id(), local_interface, data=data))

    def send_bluetooth_data(self, data):
        """
        Sends the given data to the Bluetooth interface using a User Data Relay frame.

        Args:
            data (Bytearray): Data to send.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if there is any problem sending the data.

        .. seealso::
           | :meth:`.XBeeDevice.send_micropython_data`
           | :meth:`.XBeeDevice.send_user_data_relay`
        """
        self.send_user_data_relay(XBeeLocalInterface.BLUETOOTH, data)

    def send_micropython_data(self, data):
        """
        Sends the given data to the MicroPython interface using a User Data Relay frame.

        Args:
            data (Bytearray): Data to send.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if there is any problem sending the data.

        .. seealso::
           | :meth:`.XBeeDevice.send_bluetooth_data`
           | :meth:`.XBeeDevice.send_user_data_relay`
        """
        self.send_user_data_relay(XBeeLocalInterface.MICROPYTHON, data)

    def read_data(self, timeout=None):
        """
        Reads new data received by this XBee device.

        If a ``timeout`` is specified, this method blocks until new data is received or the timeout expires,
        throwing in that case a :class:`.TimeoutException`.
        
        Args:
            timeout (Integer, optional): read timeout in seconds. If it's ``None``, this method is non-blocking
                and will return ``None`` if there is no data available.

        Returns:
            :class:`.XBeeMessage`: the read message or ``None`` if this XBee did not receive new data.

        Raises:
            ValueError: if a timeout is specified and is less than 0.
            TimeoutException: if a timeout is specified and no data was received during that time.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBeeMessage`
        """
        return self.__read_data_packet(None, timeout, False)

    def read_data_from(self, remote_xbee_device, timeout=None):
        """
        Reads new data received from the given remote XBee device.

        If a ``timeout`` is specified, this method blocks until new data is received or the timeout expires,
        throwing in that case a :class:`.TimeoutException`.

        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device that sent the data.
            timeout (Integer, optional): read timeout in seconds. If it's ``None``, this method is non-blocking
                and will return ``None`` if there is no data available.

        Returns:
            :class:`.XBeeMessage`: the read message sent by ``remote_xbee_device`` or ``None`` if this XBee did
                not receive new data.

        Raises:
            ValueError: if a timeout is specified and is less than 0.
            TimeoutException: if a timeout is specified and no data was received during that time.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBeeMessage`
           | :class:`.RemoteXBeeDevice`
        """
        return self.__read_data_packet(remote_xbee_device, timeout, False)

    def has_packets(self):
        """
        Returns whether the XBee device's queue has packets or not.
        This do not include explicit packets.
        
        Return:
            Boolean: ``True`` if this XBee device's queue has packets, ``False`` otherwise.
        
        .. seealso::
           | :meth:`.XBeeDevice.has_explicit_packets`
        """
        return not self.__packet_queue.empty()

    def has_explicit_packets(self):
        """
        Returns whether the XBee device's queue has explicit packets or not.
        This do not include non-explicit packets.
        
        Return:
            Boolean: ``True`` if this XBee device's queue has explicit packets, ``False`` otherwise.
                
        .. seealso::
           | :meth:`.XBeeDevice.has_packets`
        """
        return not self.__explicit_queue.empty()

    def flush_queues(self):
        """
        Flushes the packets queue.
        """
        self.__packet_queue.flush()
        self.__data_queue.flush()
        self.__explicit_queue.flush()

    def reset(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.reset`
        """
        # Send reset command.
        response = self._send_at_command(ATCommand(ATStringCommand.FR.command))

        # Check if AT Command response is valid.
        self._check_at_cmd_response_is_valid(response)

        lock = threading.Condition()
        self.__modem_status_received = False

        def ms_callback(modem_status):
            if modem_status == ModemStatus.HARDWARE_RESET or modem_status == ModemStatus.WATCHDOG_TIMER_RESET:
                self.__modem_status_received = True
                lock.acquire()
                lock.notify()
                lock.release()

        self.add_modem_status_received_callback(ms_callback)
        lock.acquire()
        lock.wait(self.__TIMEOUT_RESET)
        lock.release()
        self.del_modem_status_received_callback(ms_callback)

        if self.__modem_status_received is False:
            raise TimeoutException(message="Timeout waiting for the modem status packet.")

    def add_packet_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.PacketReceived`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * The received packet as a :class:`digi.xbee.packets.base.XBeeAPIPacket`
        """
        super()._add_packet_received_callback(callback)

    def add_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.DataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The data received as an :class:`digi.xbee.models.message.XBeeMessage`
        """
        self._packet_listener.add_data_received_callback(callback)

    def add_modem_status_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.ModemStatusReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The modem status as a :class:`digi.xbee.models.status.ModemStatus`
        """
        self._packet_listener.add_modem_status_received_callback(callback)

    def add_io_sample_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.IOSampleReceived`.

        Args:
            callback (Function): the callback. Receives three arguments.

                * The received IO sample as an :class:`digi.xbee.io.IOSample`
                * The remote XBee device who has sent the packet as a :class:`.RemoteXBeeDevice`
                * The time in which the packet was received as an Integer
        """
        self._packet_listener.add_io_sample_received_callback(callback)

    def add_expl_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.ExplicitDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The explicit data received as a
                  :class:`digi.xbee.models.message.ExplicitXBeeMessage`.
        """
        self._packet_listener.add_explicit_data_received_callback(callback)

    def add_user_data_relay_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.RelayDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The relay data as a :class:`digi.xbee.models.message.UserDataRelayMessage`
        """
        self._packet_listener.add_user_data_relay_received_callback(callback)

    def add_bluetooth_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.BluetoothDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The Bluetooth data as a Bytearray
        """
        self._packet_listener.add_bluetooth_data_received_callback(callback)

    def add_micropython_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.MicroPythonDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The MicroPython data as a Bytearray
        """
        self._packet_listener.add_micropython_data_received_callback(callback)

    def add_socket_state_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.SocketStateReceived`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * The socket ID as an Integer.
                * The state received as a :class:`.SocketState`
        """
        self._packet_listener.add_socket_state_received_callback(callback)

    def add_socket_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.SocketDataReceived`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * The socket ID as an Integer.
                * The data received as Bytearray
        """
        self._packet_listener.add_socket_data_received_callback(callback)

    def add_socket_data_received_from_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.SocketDataReceivedFrom`.

        Args:
            callback (Function): the callback. Receives three arguments.

                * The socket ID as an Integer.
                * A pair (host, port) of the source address where host is a string
                    representing an IPv4 address like '100.50.200.5', and port is an
                    integer.
                * The data received as Bytearray
        """
        self._packet_listener.add_socket_data_received_from_callback(callback)

    def del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.PacketReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.PacketReceived` event.
        """
        super()._del_packet_received_callback(callback)

    def del_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.DataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.DataReceived` event.
        """
        self._packet_listener.del_data_received_callback(callback)

    def del_modem_status_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.ModemStatusReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.ModemStatusReceived` event.
        """
        self._packet_listener.del_modem_status_received_callback(callback)

    def del_io_sample_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.IOSampleReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.IOSampleReceived` event.
        """
        self._packet_listener.del_io_sample_received_callback(callback)

    def del_expl_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.ExplicitDataReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.ExplicitDataReceived` event.
        """
        self._packet_listener.del_explicit_data_received_callback(callback)

    def del_user_data_relay_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.RelayDataReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.RelayDataReceived` event.
        """
        self._packet_listener.del_user_data_relay_received_callback(callback)

    def del_bluetooth_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.BluetoothDataReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.BluetoothDataReceived` event.
        """
        self._packet_listener.del_bluetooth_data_received_callback(callback)

    def del_micropython_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`digi.xbee.reader.MicroPythonDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.MicroPythonDataReceived` event.
        """
        self._packet_listener.del_micropython_data_received_callback(callback)

    def del_socket_state_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`digi.xbee.reader.SocketStateReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.SocketStateReceived` event.
        """
        self._packet_listener.del_socket_state_received_callback(callback)

    def del_socket_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`digi.xbee.reader.SocketDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.SocketDataReceived` event.
        """
        self._packet_listener.del_socket_data_received_callback(callback)

    def del_socket_data_received_from_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`digi.xbee.reader.SocketDataReceivedFrom` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.SocketDataReceivedFrom` event.
        """
        self._packet_listener.del_socket_data_received_from_callback(callback)

    def get_xbee_device_callbacks(self):
        """
        Returns this XBee internal callbacks for process received packets.

        This method is called by the PacketListener associated with this XBee to get its callbacks. These
        callbacks will be executed before user callbacks.

        Returns:
            :class:`.PacketReceived`
        """
        api_callbacks = PacketReceived()

        if not self._network:
            return api_callbacks

        for i in self._network.get_discovery_callbacks():
            api_callbacks.append(i)
        return api_callbacks

    def __get_operating_mode(self):
        """
        Returns this XBee device's operating mode.

        Returns:
            :class:`.OperatingMode`. This XBee device's operating mode.
        """
        return super()._get_operating_mode()

    def is_open(self):
        """
        Returns whether this XBee device is open or not.
        
        Returns:
            Boolean. ``True`` if this XBee device is open, ``False`` otherwise.
        """
        return self._is_open

    def is_remote(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_remote`
        """
        return False

    def get_network(self):
        """
        Returns this XBee device's current network.
        
        Returns:
            :class:`.XBeeDevice.XBeeNetwork`
        """
        if self._network is None:
            self._network = self._init_network()

        return self._network

    def _init_network(self):
        """
        Initializes a new network.

        Returns:
            :class:`.XBeeDevice.XBeeNetwork`
        """
        return XBeeNetwork(self)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_expl_data(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                        cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. Sends the provided data to the given XBee device in
        application layer mode. Application layer mode means that you need to
        specify the application layer fields to be sent with the data.
        
        This method blocks till a success or error response arrives or the
        configured receive timeout expires.
        
        The default timeout for this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to send data to.
            data (String or Bytearray): the raw data to send.
            src_endpoint (Integer): source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission. Must be between 0x0 and 0xFFFF.
            profile_id (Integer): Profile ID of the transmission. Must be between 0x0 and 0xFFFF.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        Returns:
            :class:`.XBeePacket`: the response packet obtained after sending the provided one.

        Raises:
            TimeoutException: if this method can't read a response packet in
                                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TransmitException: if the status of the response received is not OK.
            XBeeException: if the XBee device's serial port is closed.
            ValueError: if ``cluster_id`` is less than 0x0 or greater than 0xFFFF.
            ValueError: if ``profile_id`` is less than 0x0 or greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
           | :class:`.XBeePacket`
        """
        return self.send_packet_sync_and_get_response(self.__build_expldata_packet(remote_xbee_device, data,
                                                                                   src_endpoint, dest_endpoint,
                                                                                   cluster_id, profile_id,
                                                                                   broadcast=False,
                                                                                   transmit_options=transmit_options))

    @AbstractXBeeDevice._before_send_method
    def _send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                              cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. Sends the provided data to the given XBee device in
        application layer mode. Application layer mode means that you need to
        specify the application layer fields to be sent with the data.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to send data to.
            data (String or Bytearray): the raw data to send.
            src_endpoint (Integer): source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission. Must be between 0x0 and 0xFFFF.
            profile_id (Integer): Profile ID of the transmission. Must be between 0x0 and 0xFFFF.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.
        
        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.
            ValueError: if ``cluster_id`` is less than 0x0 or greater than 0xFFFF.
            ValueError: if ``profile_id`` is less than 0x0 or greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
        """
        self.send_packet(self.__build_expldata_packet(remote_xbee_device, data, src_endpoint,
                                                      dest_endpoint, cluster_id,
                                                      profile_id, broadcast=False,
                                                      transmit_options=transmit_options))

    def _send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                  transmit_options=TransmitOptions.NONE.value):
        """
        Sends the provided data to all the XBee nodes of the network (broadcast)
        in application layer mode. Application layer mode means that you need to
        specify the application layer fields to be sent with the data.

        This method blocks till a success or error transmit status arrives or
        the configured receive timeout expires.

        The received timeout is configured using the :meth:`.AbstractXBeeDevice.set_sync_ops_timeout`
        method and can be consulted with :meth:`.AbstractXBeeDevice.get_sync_ops_timeout` method.

        Args:
            data (String or Bytearray): the raw data to send.
            src_endpoint (Integer): source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission. Must be between 0x0 and 0xFFFF.
            profile_id (Integer): Profile ID of the transmission. Must be between 0x0 and 0xFFFF.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.

        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data`
        """
        return self.send_packet_sync_and_get_response(self.__build_expldata_packet(None, data, src_endpoint,
                                                                                   dest_endpoint, cluster_id,
                                                                                   profile_id,
                                                                                   broadcast=True,
                                                                                   transmit_options=transmit_options))

    def _read_expl_data(self, timeout=None):
        """
        Reads new explicit data received by this XBee device.

        If a ``timeout`` is specified, this method blocks until new data is received or the timeout expires,
        throwing in that case a :class:`.TimeoutException`.

        Args:
            timeout (Integer, optional): read timeout in seconds. If it's ``None``, this method is non-blocking
                and will return ``None`` if there is no explicit data available.

        Returns:
            :class:`.ExplicitXBeeMessage`: the read message or ``None`` if this XBee did not receive new data.

        Raises:
            ValueError: if a timeout is specified and is less than 0.
            TimeoutException: if a timeout is specified and no explicit data was received during that time.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
        """
        return self.__read_data_packet(None, timeout, True)

    def _read_expl_data_from(self, remote_xbee_device, timeout=None):
        """
        Reads new explicit data received from the given remote XBee device.

        If a ``timeout`` is specified, this method blocks until new data is received or the timeout expires,
        throwing in that case a :class:`.TimeoutException`.

        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device that sent the explicit data.
            timeout (Integer, optional): read timeout in seconds. If it's ``None``, this method is non-blocking
                and will return ``None`` if there is no data available.

        Returns:
            :class:`.ExplicitXBeeMessage`: the read message sent by ``remote_xbee_device`` or ``None`` if this
                XBee did not receive new data.

        Raises:
            ValueError: if a timeout is specified and is less than 0.
            TimeoutException: if a timeout is specified and no explicit data was received during that time.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
           | :class:`.RemoteXBeeDevice`
        """
        return self.__read_data_packet(remote_xbee_device, timeout, True)

    @AbstractXBeeDevice._before_send_method
    def __read_data_packet(self, remote, timeout, explicit):
        """
        Reads a new data packet received by this XBee device during the provided timeout.

        If a ``timeout`` is specified, this method blocks until new data is received or the timeout expires,
        throwing in that case a :class:`.TimeoutException`.

        Args:
            remote (:class:`.RemoteXBeeDevice`): The remote device to get a data packet from. ``None`` to read a
                data packet sent by any device.
            timeout (Integer): The time to wait for a data packet in seconds.
            explicit (Boolean): ``True`` to read an explicit data packet, ``False`` to read an standard data packet.

        Returns:
            :class:`.XBeeMessage` or :class:`.ExplicitXBeeMessage`: the XBee message received by this device.

        Raises:
            ValueError: if a timeout is specified and is less than 0.
            TimeoutException: if a timeout is specified and no data was received during that time.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.XBeeMessage`
           | :class:`.ExplicitXBeeMessage`
           | :class:`.RemoteXBeeDevice`
        """
        if timeout is not None and timeout < 0:
            raise ValueError("Read timeout must be 0 or greater")

        if not explicit:
            if remote is None:
                packet = self.__data_queue.get(timeout=timeout)
            else:
                packet = self.__data_queue.get_by_remote(remote, timeout=timeout)
        else:
            if remote is None:
                packet = self.__explicit_queue.get(timeout=timeout)
            else:
                packet = self.__explicit_queue.get_by_remote(remote, timeout=timeout)

        if packet is None:
            return None

        frame_type = packet.get_frame_type()
        if frame_type in [ApiFrameType.RECEIVE_PACKET, ApiFrameType.RX_16, ApiFrameType.RX_64]:
            return self.__build_xbee_message(packet, explicit=False)
        elif frame_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
            return self.__build_xbee_message(packet, explicit=True)
        else:
            return None

    def _enter_at_command_mode(self):
        """
        Attempts to put this device in AT Command mode. Only valid if device is
        working in AT mode.
        
        Returns:
            Boolean: ``True`` if the XBee device has entered in AT command mode, ``False`` otherwise.
            
        Raises:
            SerialTimeoutException: if there is any error trying to write within the serial port.
            InvalidOperatingModeException: if the XBee device is in API mode.
        """
        if not self._serial_port:
            raise XBeeException("Command mode is only supported for local XBee devices using a serial connection")
        if self._operating_mode in [OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE]:
            raise InvalidOperatingModeException(
                message="Invalid mode. Command mode can be only accessed while in AT mode")

        self._serial_port.flushInput()

        # It is necessary to wait at least 1 second to enter in command mode after sending any data to the device.
        time.sleep(self.__DEFAULT_GUARD_TIME)
        # Send the command mode sequence.
        b = bytearray(self.__COMMAND_MODE_CHAR, "utf8")
        self._serial_port.write(b)
        self._serial_port.write(b)
        self._serial_port.write(b)
        # Wait some time to let the module generate a response.
        time.sleep(self.__TIMEOUT_ENTER_COMMAND_MODE)
        # Read data from the device (it should answer with 'OK\r').
        data = self._serial_port.read_existing().decode()

        return data and data in self.__COMMAND_MODE_OK

    def _exit_at_command_mode(self):
        """
        Exits AT command mode. The XBee device has to be in command mode.

        Raises:
            SerialTimeoutException: if there is any error trying to write within the serial port.
            InvalidOperatingModeException: if the XBee device is in API mode.
        """
        if not self._serial_port:
            raise XBeeException("Command mode is only supported for local XBee devices using a serial connection")

        if self._operating_mode in [OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE]:
            raise InvalidOperatingModeException(
                message="Invalid mode. Command mode can be only be exited while in AT mode")

        self._serial_port.write("ATCN\r".encode("utf-8"))
        time.sleep(self.__DEFAULT_GUARD_TIME)

    def _determine_operating_mode(self):
        """
        Determines and returns the operating mode of the XBee device.
        
        If the XBee device is not in AT command mode, this method attempts
        to enter on it.
        
        Returns:
            :class:`.OperatingMode`

        .. seealso::
           | :class:`.OperatingMode`
        """
        try:
            self._operating_mode = OperatingMode.API_MODE
            response = self.get_parameter(ATStringCommand.AP.command)
            return OperatingMode.get(response[0])
        except TimeoutException:
            self._operating_mode = OperatingMode.AT_MODE
            listening = self._packet_listener is not None and self._packet_listener.is_running()
            try:
                # Stop listening for packets.
                if listening:
                    self._packet_listener.stop()
                    self._packet_listener.join()
                # If there is timeout exception and is possible to enter
                # in AT command mode, get the actual mode.
                if self._enter_at_command_mode():
                    return self.__get_actual_mode()
            except XBeeException as ste:
                self._log.exception(ste)
            except UnicodeDecodeError:
                # This error is thrown when trying to decode bytes without utf-8 representation, just ignore.
                pass
            finally:
                # Exit AT command mode.
                self._exit_at_command_mode()
                # Restore the packets listening.
                if listening:
                    self._packet_listener = PacketListener(self._comm_iface, self)
                    self._packet_listener.start()
        return OperatingMode.UNKNOWN

    def send_packet_sync_and_get_response(self, packet_to_send, timeout=None):
        """
        Override method.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._send_packet_sync_and_get_response`
        """
        return super()._send_packet_sync_and_get_response(packet_to_send, timeout=timeout)

    def send_packet(self, packet, sync=False):
        """
        Override method.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._send_packet`
        """
        return super()._send_packet(packet, sync=sync)

    def __build_xbee_message(self, packet, explicit=False):
        """
        Builds and returns the XBee message corresponding to the provided ``packet``. The result is an
        :class:`.XBeeMessage` or :class:`.ExplicitXBeeMessage` depending on the packet.

        Args:
            packet (:class:`.XBeePacket`): the packet to get its corresponding XBee message.
            explicit (Boolean): ``True`` if the packet is an explicit packet, ``False`` otherwise.

        Returns:
            :class:`.XBeeMessage` or :class:`.ExplicitXBeeMessage`: the resulting XBee message.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
           | :class:`.XBeeMessage`
           | :class:`.XBeePacket`
        """
        x64addr = None
        x16addr = None
        remote = None

        if hasattr(packet, "x16bit_source_addr"):
            x16addr = packet.x16bit_source_addr
        if hasattr(packet, "x64bit_source_addr"):
            x64addr = packet.x64bit_source_addr
        if x64addr is not None or x16addr is not None:
            remote = RemoteXBeeDevice(self, x64bit_addr=x64addr, x16bit_addr=x16addr)

        if explicit:
            msg = ExplicitXBeeMessage(packet.rf_data, remote, time.time(), packet.source_endpoint,
                                      packet.dest_endpoint, packet.cluster_id,
                                      packet.profile_id, broadcast=packet.is_broadcast())
        else:
            msg = XBeeMessage(packet.rf_data, remote, time.time(), broadcast=packet.is_broadcast())

        return msg

    def __build_expldata_packet(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                                cluster_id, profile_id, broadcast=False, transmit_options=TransmitOptions.NONE.value):
        """
        Builds and returns an explicit data packet with the provided parameters.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to send data to.
            data (String or Bytearray): the raw data to send.
            src_endpoint (Integer): source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission. Must be between 0x0 and 0xFFFF.
            profile_id (Integer): Profile ID of the transmission. Must be between 0x0 and 0xFFFF.
            broadcast (Boolean, optional): ``True`` to send data in broadcast mode (``remote_xbee_device`` is ignored),
                ``False`` to send data to the specified ``remote_xbee_device``.
            transmit_options (Integer, optional): transmit options, bitfield of :class:`.TransmitOptions`. Default to
                ``TransmitOptions.NONE.value``.
        
        Returns:
            :class:`.ExplicitAddressingPacket`: the explicit packet generated with the provided parameters.
        
        Raises:
            All exceptions raised by :meth:`.ExplicitAddressingPacket.__init__`

        .. seealso::
           | :class:`.ExplicitAddressingPacket`
           | :meth:`.ExplicitAddressingPacket.__init__`
           | :class:`.RemoteXBeeDevice`
        """
        if broadcast:
            x64addr = XBee64BitAddress.BROADCAST_ADDRESS
            x16addr = XBee16BitAddress.UNKNOWN_ADDRESS
        else:
            x64addr = remote_xbee_device.get_64bit_addr()
            x16addr = remote_xbee_device.get_16bit_addr()

        # If the device does not have 16-bit address, set it to Unknown.
        if x16addr is None:
            x16addr = XBee16BitAddress.UNKNOWN_ADDRESS

        if isinstance(data, str):
            data = data.encode("utf8")

        return ExplicitAddressingPacket(self._get_next_frame_id(), x64addr,
                                        x16addr, src_endpoint, dest_endpoint,
                                        cluster_id, profile_id, 0, transmit_options, rf_data=data)

    def __get_actual_mode(self):
        """
        Gets and returns the actual operating mode of the XBee device reading the ``AP`` parameter in AT command mode.

        Returns:
             :class:`.OperatingMode`. The actual operating mode of the XBee device or ``OperatingMode.UNKNOWN`` if the
                mode could not be read.

        Raises:
            SerialTimeoutException: if there is any error trying to write within the serial port.
        """
        if not self._serial_port:
            raise XBeeException("Command mode is only supported for local XBee devices using a serial connection")

        # Clear the serial input stream.
        self._serial_port.flushInput()
        # Send the 'AP' command.
        self._serial_port.write("ATAP\r".encode("utf-8"))
        time.sleep(0.1)
        # Read the 'AP' answer.
        ap_answer = self._serial_port.read_existing().decode("utf-8").rstrip()
        if len(ap_answer) == 0:
            return OperatingMode.UNKNOWN
        # Return the corresponding operating mode for the AP answer.
        return OperatingMode.get(int(ap_answer, 16))

    def get_next_frame_id(self):
        """
        Returns the next frame ID of the XBee device.

        Returns:
            Integer: The next frame ID of the XBee device.
        """
        return self._get_next_frame_id()

    comm_iface = property(__get_comm_iface)
    """:class:`.XBeeCommunicationInterface`. The hardware interface associated to the XBee device."""

    serial_port = property(__get_serial_port)
    """:class:`.XBeeSerialPort`. The serial port associated to the XBee device."""

    operating_mode = property(__get_operating_mode)
    """:class:`.OperatingMode`. The operating mode of the XBee device."""


class Raw802Device(XBeeDevice):
    """
    This class represents a local 802.15.4 XBee device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.Raw802Device` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
           _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.
        
        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if not self.is_remote() and self.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise XBeeException("Invalid protocol.")

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        return Raw802Network(self)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.RAW_802_15_4

    def get_ai_status(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._get_ai_status`
        """
        return super()._get_ai_status()

    def send_data_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_64`
        """
        return super()._send_data_64(x64addr, data, transmit_options=transmit_options)

    def send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64`
        """
        super()._send_data_async_64(x64addr, data, transmit_options=transmit_options)

    def send_data_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._send_data_16`
        """
        return super()._send_data_16(x16addr, data, transmit_options=transmit_options)

    def send_data_async_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._send_data_async_16`
        """
        super()._send_data_async_16(x16addr, data, transmit_options=transmit_options)


class DigiMeshDevice(XBeeDevice):
    """
    This class represents a local DigiMesh XBee device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.DigiMeshDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
           _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self.get_protocol() != XBeeProtocol.DIGI_MESH:
            raise XBeeException("Invalid protocol.")

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        return DigiMeshNetwork(self)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.DIGI_MESH

    def send_data_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_64`
        """
        return super()._send_data_64(x64addr, data, transmit_options=transmit_options)

    def send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64`
        """
        super()._send_data_async_64(x64addr, data, transmit_options=transmit_options)

    def read_expl_data(self, timeout=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.read_expl_data`
        """
        return super()._read_expl_data(timeout=timeout)

    def read_expl_data_from(self, remote_xbee_device, timeout=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.read_expl_data_from`
        """
        return super()._read_expl_data_from(remote_xbee_device, timeout=timeout)

    def send_expl_data(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                       cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data`
        """
        return super()._send_expl_data(remote_xbee_device, data, src_endpoint, dest_endpoint, cluster_id,
                                       profile_id, transmit_options=transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                 transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data_broadcast`
        """
        return super()._send_expl_data_broadcast(data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                                 transmit_options=transmit_options)

    def send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data_async`
        """
        super()._send_expl_data_async(remote_xbee_device, data, src_endpoint,
                                      dest_endpoint, cluster_id, profile_id,
                                      transmit_options=transmit_options)


class DigiPointDevice(XBeeDevice):
    """
    This class represents a local DigiPoint XBee device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.DigiPointDevice` with the provided
        parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self.get_protocol() != XBeeProtocol.DIGI_POINT:
            raise XBeeException("Invalid protocol.")

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        return DigiPointNetwork(self)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.DIGI_POINT

    def send_data_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_64_16`
        """
        return super()._send_data_64_16(x64addr, x16addr, data, transmit_options=transmit_options)

    def send_data_async_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64_16`
        """
        super()._send_data_async_64_16(x64addr, x16addr, data, transmit_options=transmit_options)

    def read_expl_data(self, timeout=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.read_expl_data`
        """
        return super()._read_expl_data(timeout=timeout)

    def read_expl_data_from(self, remote_xbee_device, timeout=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.read_expl_data_from`
        """
        return super()._read_expl_data_from(remote_xbee_device, timeout=timeout)

    def send_expl_data(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                       cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data`
        """
        return super()._send_expl_data(remote_xbee_device, data, src_endpoint, dest_endpoint, cluster_id,
                                       profile_id, transmit_options=transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                 transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data_broadcast`
        """
        return super()._send_expl_data_broadcast(data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                                 transmit_options=transmit_options)

    def send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data_async`
        """
        super()._send_expl_data_async(remote_xbee_device, data, src_endpoint,
                                      dest_endpoint, cluster_id, profile_id,
                                      transmit_options=transmit_options)


class ZigBeeDevice(XBeeDevice):
    """
    This class represents a local ZigBee XBee device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.ZigBeeDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
           _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self.get_protocol() != XBeeProtocol.ZIGBEE:
            raise XBeeException("Invalid protocol.")

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        return ZigBeeNetwork(self)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.ZIGBEE

    def get_ai_status(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._get_ai_status`
        """
        return super()._get_ai_status()

    def force_disassociate(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._force_disassociate`
        """
        super()._force_disassociate()

    def send_data_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_64_16`
        """
        return super()._send_data_64_16(x64addr, x16addr, data, transmit_options=transmit_options)

    def send_data_async_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64_16`
        """
        super()._send_data_async_64_16(x64addr, x16addr, data, transmit_options=transmit_options)

    def read_expl_data(self, timeout=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._read_expl_data`
        """
        return super()._read_expl_data(timeout=timeout)

    def read_expl_data_from(self, remote_xbee_device, timeout=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._read_expl_data_from`
        """
        return super()._read_expl_data_from(remote_xbee_device, timeout=timeout)

    def send_expl_data(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                       cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data`
        """
        return super()._send_expl_data(remote_xbee_device, data, src_endpoint, dest_endpoint, cluster_id,
                                       profile_id, transmit_options=transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                 transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data_broadcast`
        """
        return super()._send_expl_data_broadcast(data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                                 transmit_options=transmit_options)

    def send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data_async`
        """
        super()._send_expl_data_async(remote_xbee_device, data, src_endpoint,
                                      dest_endpoint, cluster_id, profile_id,
                                      transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def send_multicast_data(self, group_id, data, src_endpoint, dest_endpoint,
                            cluster_id, profile_id):
        """
        Blocking method. This method sends multicast data to the provided group ID
        synchronously.
        
        This method will wait for the packet response.
        
        The default timeout for this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.
        
        Args:
            group_id (:class:`.XBee16BitAddress`): the 16 bit address of the multicast group.
            data (Bytearray): the raw data to send.
            src_endpoint (Integer): source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission. Must be between 0x0 and 0xFFFF.
            profile_id (Integer): Profile ID of the transmission. Must be between 0x0 and 0xFFFF.
            
        Returns:
            :class:`.XBeePacket`: the response packet.
            
        Raises:
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.

        .. seealso::
           | :class:`XBee16BitAddress`
           | :class:`XBeePacket`
        """
        packet_to_send = ExplicitAddressingPacket(self._get_next_frame_id(),
                                                  XBee64BitAddress.UNKNOWN_ADDRESS,
                                                  group_id, src_endpoint, dest_endpoint,
                                                  cluster_id, profile_id, 0,
                                                  TransmitOptions.ENABLE_MULTICAST.value, rf_data=data)

        return self.send_packet_sync_and_get_response(packet_to_send)

    @AbstractXBeeDevice._before_send_method
    def send_multicast_data_async(self, group_id, data, src_endpoint, dest_endpoint, cluster_id, profile_id):
        """
        Non-blocking method. This method sends multicast data to the provided group ID.
        
        This method won't wait for the response.
        
        Args:
            group_id (:class:`.XBee16BitAddress`): the 16 bit address of the multicast group.
            data (Bytearray): the raw data to send.
            src_endpoint (Integer): source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission. Must be between 0x0 and 0xFFFF.
            profile_id (Integer): Profile ID of the transmission. Must be between 0x0 and 0xFFFF.
        
        Raises:
            TimeoutException: if this method can't read a response packet in
                :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS` seconds.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`XBee16BitAddress`
        """
        packet_to_send = ExplicitAddressingPacket(self._get_next_frame_id(),
                                                  XBee64BitAddress.UNKNOWN_ADDRESS,
                                                  group_id, src_endpoint, dest_endpoint,
                                                  cluster_id, profile_id, 0,
                                                  TransmitOptions.ENABLE_MULTICAST.value, rf_data=data)

        self.send_packet(packet_to_send)

    @AbstractXBeeDevice._before_send_method
    def register_joining_device(self, registrant_address, options, key):
        """
        Securely registers a joining device to a trust center. Registration is the process by which a node is
        authorized to join the network using a preconfigured link key or installation code that is conveyed to
        the trust center out-of-band (using a physical interface and not over-the-air).

        This method is synchronous, it sends the register joining device packet and waits for the answer of the
        operation. Then, returns the corresponding status.

        Args:
            registrant_address (:class:`XBee64BitAddress`): the 64-bit address of the device to register.
            options (RegisterKeyOptions): the register options indicating the key source.
            key (Bytearray): key of the device to register.

        Returns:
            :class:`.ZigbeeRegisterStatus`: the register device operation status or ``None`` if the answer
                received is not a ``RegisterDeviceStatusPacket``.

        Raises:
            TimeoutException: if the answer is not received in the configured timeout.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.
            ValueError: if ``registrant_address`` is ``None`` or if ``options`` is ``None``.

        .. seealso::
           | :class:`RegisterKeyOptions`
           | :class:`XBee64BitAddress`
           | :class:`ZigbeeRegisterStatus`
        """
        if registrant_address is None:
            raise ValueError("Registrant address cannot be ``None``.")
        if options is None:
            raise ValueError("Options cannot be ``None``.")

        packet_to_send = RegisterJoiningDevicePacket(self.get_next_frame_id(),
                                                     registrant_address,
                                                     options,
                                                     key)
        response_packet = self.send_packet_sync_and_get_response(packet_to_send)
        if isinstance(response_packet, RegisterDeviceStatusPacket):
            return response_packet.status
        return None

    @AbstractXBeeDevice._before_send_method
    def register_joining_device_async(self, registrant_address, options, key):
        """
        Securely registers a joining device to a trust center. Registration is the process by which a node is
        authorized to join the network using a preconfigured link key or installation code that is conveyed to
        the trust center out-of-band (using a physical interface and not over-the-air).

        This method is asynchronous, which means that it will not wait for an answer after sending the
        register frame.

        Args:
            registrant_address (:class:`XBee64BitAddress`): the 64-bit address of the device to register.
            options (RegisterKeyOptions): the register options indicating the key source.
            key (Bytearray): key of the device to register.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.
            ValueError: if ``registrant_address`` is ``None`` or if ``options`` is ``None``.

        .. seealso::
           | :class:`RegisterKeyOptions`
           | :class:`XBee64BitAddress`
        """
        if registrant_address is None:
            raise ValueError("Registrant address cannot be ``None``.")
        if options is None:
            raise ValueError("Options cannot be ``None``.")

        packet_to_send = RegisterJoiningDevicePacket(self.get_next_frame_id(),
                                                     registrant_address,
                                                     options,
                                                     key)
        self.send_packet(packet_to_send, sync=True)

    @AbstractXBeeDevice._before_send_method
    def unregister_joining_device(self, unregistrant_address):
        """
        Unregisters a joining device from a trust center.

        This method is synchronous, it sends the unregister joining device packet and waits for the answer of the
        operation. Then, returns the corresponding status.

        Args:
            unregistrant_address (:class:`XBee64BitAddress`): the 64-bit address of the device to unregister.

        Returns:
            :class:`.ZigbeeRegisterStatus`: the unregister device operation status or ``None`` if the answer
                received is not a ``RegisterDeviceStatusPacket``.

        Raises:
            TimeoutException: if the answer is not received in the configured timeout.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.
            ValueError: if ``registrant_address`` is ``None``.

        .. seealso::
           | :class:`XBee64BitAddress`
           | :class:`ZigbeeRegisterStatus`
        """
        return self.register_joining_device(unregistrant_address, RegisterKeyOptions.LINK_KEY, None)

    @AbstractXBeeDevice._before_send_method
    def unregister_joining_device_async(self, unregistrant_address):
        """
        Unregisters a joining device from a trust center.

        This method is asynchronous, which means that it will not wait for an answer after sending the
        uregister frame.

        Args:
            unregistrant_address (:class:`XBee64BitAddress`): the 64-bit address of the device to unregister.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device's serial port is closed.
            ValueError: if ``registrant_address`` is ``None``.

        .. seealso::
           | :class:`XBee64BitAddress`
        """
        self.register_joining_device_async(unregistrant_address, RegisterKeyOptions.LINK_KEY, None)


class IPDevice(XBeeDevice):
    """
    This class provides common functionality for XBee IP devices.
    """

    BROADCAST_IP = "255.255.255.255"

    __DEFAULT_SOURCE_PORT = 9750

    __DEFAULT_PROTOCOL = IPProtocol.TCP

    __OPERATION_EXCEPTION = "Operation not supported in this module."

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.IPDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._ip_addr = None
        self._source_port = self.__DEFAULT_SOURCE_PORT

    def read_device_info(self, init=True):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.read_device_info`
        """
        super().read_device_info(init=init)

        # Read the module's IP address.
        if init or self._ip_addr is None:
            resp = self.get_parameter(ATStringCommand.MY.command)
            self._ip_addr = IPv4Address(utils.bytes_to_int(resp))

        # Read the source port.
        if init or self._source_port is None:
            try:
                resp = self.get_parameter(ATStringCommand.C0.command)
                self._source_port = utils.bytes_to_int(resp)
            except XBeeException:
                # Do not refresh the source port value if there is an error reading
                # it from the module.
                pass

    def get_ip_addr(self):
        """
        Returns the IP address of this IP device.

        To refresh this value use the method :meth:`.IPDevice.read_device_info`.

        Returns:
            :class:`ipaddress.IPv4Address`: The IP address of this IP device.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        return self._ip_addr

    def set_dest_ip_addr(self, address):
        """
        Sets the destination IP address.

        Args:
            address (:class:`ipaddress.IPv4Address`): Destination IP address.

        Raises:
            ValueError: if ``address`` is ``None``.
            TimeoutException: if there is a timeout setting the destination IP address.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        if address is None:
            raise ValueError("Destination IP address cannot be None")

        self.set_parameter(ATStringCommand.DL.command, bytearray(address.exploded, "utf8"))

    def get_dest_ip_addr(self):
        """
        Returns the destination IP address.

        Returns:
            :class:`ipaddress.IPv4Address`: The configured destination IP address.

        Raises:
            TimeoutException: if there is a timeout getting the destination IP address.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        resp = self.get_parameter(ATStringCommand.DL.command)
        return IPv4Address(resp.decode("utf8"))

    def add_ip_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.IPDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The data received as an :class:`digi.xbee.models.message.IPMessage`
        """
        self._packet_listener.add_ip_data_received_callback(callback)

    def del_ip_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.IPDataReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.IPDataReceived` event.
        """
        self._packet_listener.del_ip_data_received_callback(callback)

    def start_listening(self, source_port):
        """
        Starts listening for incoming IP transmissions in the provided port.

        Args:
            source_port (Integer): Port to listen for incoming transmissions.

        Raises:
            ValueError: if ``source_port`` is less than 0 or greater than 65535.
            TimeoutException: if there is a timeout setting the source port.
            XBeeException: if there is any other XBee related exception.
        """
        if not 0 <= source_port <= 65535:
            raise ValueError("Source port must be between 0 and 65535")

        self.set_parameter(ATStringCommand.C0.command, utils.int_to_bytes(source_port))
        self._source_port = source_port

    def stop_listening(self):
        """
        Stops listening for incoming IP transmissions.

        Raises:
            TimeoutException: if there is a timeout processing the operation.
            XBeeException: if there is any other XBee related exception.
        """
        self.set_parameter(ATStringCommand.C0.command, utils.int_to_bytes(0))
        self._source_port = 0

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def send_ip_data(self, ip_addr, dest_port, protocol, data, close_socket=False):
        """
        Sends the provided IP data to the given IP address and port using
        the specified IP protocol. For TCP and TCP SSL protocols, you can
        also indicate if the socket should be closed when data is sent.

        This method blocks till a success or error response arrives or the
        configured receive timeout expires.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to send IP data to.
            dest_port (Integer): The destination port of the transmission.
            protocol (:class:`.IPProtocol`): The IP protocol used for the transmission.
            data (String or Bytearray): The IP data to be sent.
            close_socket (Boolean, optional): ``True`` to close the socket just after the
                transmission. ``False`` to keep it open. Default to ``False``.

        Raises:
            ValueError: if ``ip_addr`` is ``None``.
            ValueError: if ``protocol`` is ``None``.
            ValueError: if ``data`` is ``None``.
            ValueError: if ``dest_port`` is less than 0 or greater than 65535.
            OperationNotSupportedException: if the device is remote.
            TimeoutException: if there is a timeout sending the data.
            XBeeException: if there is any other XBee related exception.
        """
        if ip_addr is None:
            raise ValueError("IP address cannot be None")
        if protocol is None:
            raise ValueError("Protocol cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if not 0 <= dest_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        # Check if device is remote.
        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send IP data from a remote device")

        # The source port value depends on the protocol used in the transmission.
        # For UDP, source port value must be the same as 'C0' one. For TCP it must be 0.
        source_port = self._source_port
        if protocol is not IPProtocol.UDP:
            source_port = 0

        if isinstance(data, str):
            data = data.encode("utf8")

        options = TXIPv4Packet.OPTIONS_CLOSE_SOCKET if close_socket else TXIPv4Packet.OPTIONS_LEAVE_SOCKET_OPEN

        packet = TXIPv4Packet(self.get_next_frame_id(), ip_addr, dest_port, source_port, protocol,
                              options, data=data)

        return self.send_packet_sync_and_get_response(packet)

    @AbstractXBeeDevice._before_send_method
    def send_ip_data_async(self, ip_addr, dest_port, protocol, data, close_socket=False):
        """
        Sends the provided IP data to the given IP address and port
        asynchronously using the specified IP protocol. For TCP and TCP SSL
        protocols, you can also indicate if the socket should be closed when
        data is sent.

        Asynchronous transmissions do not wait for answer from the remote
        device or for transmit status packet.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to send IP data to.
            dest_port (Integer): The destination port of the transmission.
            protocol (:class:`.IPProtocol`): The IP protocol used for the transmission.
            data (String or Bytearray): The IP data to be sent.
            close_socket (Boolean, optional): ``True`` to close the socket just after the
                transmission. ``False`` to keep it open. Default to ``False``.

        Raises:
            ValueError: if ``ip_addr`` is ``None``.
            ValueError: if ``protocol`` is ``None``.
            ValueError: if ``data`` is ``None``.
            ValueError: if ``dest_port`` is less than 0 or greater than 65535.
            OperationNotSupportedException: if the device is remote.
            XBeeException: if there is any other XBee related exception.
        """
        if ip_addr is None:
            raise ValueError("IP address cannot be None")
        if protocol is None:
            raise ValueError("Protocol cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if not 0 <= dest_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        # Check if device is remote.
        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send IP data from a remote device")

        # The source port value depends on the protocol used in the transmission.
        # For UDP, source port value must be the same as 'C0' one. For TCP it must be 0.
        source_port = self._source_port
        if protocol is IPProtocol.UDP:
            source_port = 0

        if isinstance(data, str):
            data = data.encode("utf8")

        options = TXIPv4Packet.OPTIONS_CLOSE_SOCKET if close_socket else TXIPv4Packet.OPTIONS_LEAVE_SOCKET_OPEN

        packet = TXIPv4Packet(self.get_next_frame_id(), ip_addr, dest_port, source_port, protocol,
                              options, data=data)

        self.send_packet(packet)

    def send_ip_data_broadcast(self, dest_port, data):
        """
        Sends the provided IP data to all clients.

        This method blocks till a success or error transmit status arrives or
        the configured receive timeout expires.

        Args:
            dest_port (Integer): The destination port of the transmission.
            data (String or Bytearray): The IP data to be sent.

        Raises:
            ValueError: if ``data`` is ``None``.
            ValueError: if ``dest_port`` is less than 0 or greater than 65535.
            TimeoutException: if there is a timeout sending the data.
            XBeeException: if there is any other XBee related exception.
        """
        return self.send_ip_data(IPv4Address(self.BROADCAST_IP), dest_port, IPProtocol.UDP, data)

    @AbstractXBeeDevice._before_send_method
    def read_ip_data(self, timeout=XBeeDevice.TIMEOUT_READ_PACKET):
        """
        Reads new IP data received by this XBee device during the
        provided timeout.

        This method blocks until new IP data is received or the provided
        timeout expires.

        For non-blocking operations, register a callback and use the method
        :meth:`IPDevice.add_ip_data_received_callback`.

        Before reading IP data you need to start listening for incoming
        IP data at a specific port. Use the method :meth:`IPDevice.start_listening`
        for that purpose. When finished, you can use the method
        :meth:`IPDevice.stop_listening` to stop listening for incoming IP data.

        Args:
            timeout (Integer, optional): The time to wait for new IP data in seconds.

        Returns:
            :class:`.IPMessage`: IP message, ``None`` if this device did not receive new data.

        Raises:
            ValueError: if ``timeout`` is less than 0.
        """
        if timeout < 0:
            raise ValueError("Read timeout must be 0 or greater.")

        return self.__read_ip_data_packet(timeout)

    @AbstractXBeeDevice._before_send_method
    def read_ip_data_from(self, ip_addr, timeout=XBeeDevice.TIMEOUT_READ_PACKET):
        """
        Reads new IP data received from the given IP address during the
        provided timeout.

        This method blocks until new IP data from the provided IP
        address is received or the given timeout expires.

        For non-blocking operations, register a callback and use the method
        :meth:`IPDevice.add_ip_data_received_callback`.

        Before reading IP data you need to start listening for incoming
        IP data at a specific port. Use the method :meth:`IPDevice.start_listening`
        for that purpose. When finished, you can use the method
        :meth:`IPDevice.stop_listening` to stop listening for incoming IP data.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to read data from.
            timeout (Integer, optional): The time to wait for new IP data in seconds.

        Returns:
            :class:`.IPMessage`: IP message, ``None`` if this device did not
                receive new data from the provided IP address.

        Raises:
            ValueError: if ``timeout`` is less than 0.
        """
        if timeout < 0:
            raise ValueError("Read timeout must be 0 or greater.")

        return self.__read_ip_data_packet(timeout, ip_addr=ip_addr)

    def __read_ip_data_packet(self, timeout, ip_addr=None):
        """
        Reads a new IP data packet received by this IP XBee device during
        the provided timeout.

        This method blocks until new IP data is received or the given
        timeout expires.

        If the provided IP address is ``None`` the method returns
        the first IP data packet read from any IP address. If the IP address is
        not ``None`` the method returns the first data package read from
        the provided IP address.

        Args:
            timeout (Integer, optional): The time to wait for new IP data in seconds. Optional.
            ip_addr (:class:`ipaddress.IPv4Address`, optional): The IP address to read data from.
                ``None`` to read an IP data packet from any IP address.

        Returns:
            :class:`.IPMessage`: IP message, ``None`` if this device did not
                receive new data from the provided IP address.
        """
        queue = self._packet_listener.get_ip_queue()

        if ip_addr is None:
            packet = queue.get(timeout=timeout)
        else:
            packet = queue.get_by_ip(ip_addr, timeout=timeout)

        if packet is None:
            return None

        if packet.get_frame_type() == ApiFrameType.RX_IPV4:
            return IPMessage(packet.source_address, packet.source_port,
                             packet.dest_port, packet.ip_protocol,
                             packet.data)

        return None

    def get_network(self):
        """
        Deprecated.

        This protocol does not support the network functionality.
        """
        return None

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        return None

    def get_16bit_addr(self):
        """
        Deprecated.

        This protocol does not have an associated 16-bit address.
        """
        return None

    def get_dest_address(self):
        """
        Deprecated.

        Operation not supported in this protocol. Use :meth:`.IPDevice.get_dest_ip_addr` instead.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_dest_address(self, addr):
        """
        Deprecated.

        Operation not supported in this protocol. Use :meth:`.IPDevice.set_dest_ip_addr` instead.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_pan_id(self):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_pan_id(self, value):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_expl_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_expl_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_data(self, timeout=None, explicit=False):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_data_from(self, remote_xbee_device, timeout=None, explicit=False):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data_broadcast(self, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data(self, remote_xbee_device, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data_async(self, remote_xbee_device, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class CellularDevice(IPDevice):
    """
    This class represents a local Cellular device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.CellularDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._imei_addr = None

    def open(self, force_settings=False):
        """
        Override.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self.get_protocol() not in [XBeeProtocol.CELLULAR, XBeeProtocol.CELLULAR_NBIOT]:
            raise XBeeException("Invalid protocol.")

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.CELLULAR

    def read_device_info(self, init=True):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.read_device _info`
        """
        super().read_device_info(init=init)

        # Generate the IMEI address.
        if init or self._imei_addr is None:
            self._imei_addr = XBeeIMEIAddress(self._64bit_addr.address)

    def is_connected(self):
        """
        Returns whether the device is connected to the Internet or not.

        Returns:
            Boolean: ``True`` if the device is connected to the Internet, ``False`` otherwise.

        Raises:
            TimeoutException: if there is a timeout getting the association indication status.
            XBeeException: if there is any other XBee related exception.
        """
        status = self.get_cellular_ai_status()
        return status == CellularAssociationIndicationStatus.SUCCESSFULLY_CONNECTED

    def get_cellular_ai_status(self):
        """
        Returns the current association status of this Cellular device.

        It indicates occurrences of errors during the modem initialization
        and connection.

        Returns:
            :class:`.CellularAssociationIndicationStatus`: The association indication status of the Cellular device.

        Raises:
            TimeoutException: if there is a timeout getting the association indication status.
            XBeeException: if there is any other XBee related exception.
        """
        value = self.get_parameter(ATStringCommand.AI.command)
        return CellularAssociationIndicationStatus.get(utils.bytes_to_int(value))

    def add_sms_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.SMSReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The data received as an :class:`digi.xbee.models.message.SMSMessage`
        """
        self._packet_listener.add_sms_received_callback(callback)

    def del_sms_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.SMSReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.SMSReceived` event.
        """
        self._packet_listener.del_sms_received_callback(callback)

    def get_imei_addr(self):
        """
        Returns the IMEI address of this Cellular device.

        To refresh this value use the method :meth:`.CellularDevice.read_device_info`.

        Returns:
            :class:`.XBeeIMEIAddress`: The IMEI address of this Cellular device.
        """
        return self._imei_addr

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def send_sms(self, phone_number, data):
        """
        Sends the provided SMS message to the given phone number.

        This method blocks till a success or error response arrives or the
        configured receive timeout expires.

        For non-blocking operations use the method :meth:`.CellularDevice.send_sms_async`.

        Args:
            phone_number (String): The phone number to send the SMS to.
            data (String): Text of the SMS.

        Raises:
            ValueError: if ``phone_number`` is ``None``.
            ValueError: if ``data`` is ``None``.
            OperationNotSupportedException: if the device is remote.
            TimeoutException: if there is a timeout sending the SMS.
            XBeeException: if there is any other XBee related exception.
        """
        if phone_number is None:
            raise ValueError("Phone number cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        # Check if device is remote.
        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send SMS from a remote device")

        xbee_packet = TXSMSPacket(self.get_next_frame_id(), phone_number, data)

        return self.send_packet_sync_and_get_response(xbee_packet)

    @AbstractXBeeDevice._before_send_method
    def send_sms_async(self, phone_number, data):
        """
        Sends asynchronously the provided SMS to the given phone number.

        Asynchronous transmissions do not wait for answer or for transmit
        status packet.

        Args:
            phone_number (String): The phone number to send the SMS to.
            data (String): Text of the SMS.

        Raises:
            ValueError: if ``phone_number`` is ``None``.
            ValueError: if ``data`` is ``None``.
            OperationNotSupportedException: if the device is remote.
            XBeeException: if there is any other XBee related exception.
        """
        if phone_number is None:
            raise ValueError("Phone number cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        # Check if device is remote.
        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send SMS from a remote device")

        xbee_packet = TXSMSPacket(self.get_next_frame_id(), phone_number, data)

        self.send_packet(xbee_packet)

    def get_sockets_list(self):
        """
        Returns a list with the IDs of all active (open) sockets.

        Returns:
            List: list with the IDs of all active (open) sockets, or empty list if there is not any active socket.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
        """
        response = self.get_parameter(ATStringCommand.SI.command)
        return SocketInfo.parse_socket_list(response)

    def get_socket_info(self, socket_id):
        """
        Returns the information of the socket with the given socket ID.

        Args:
            socket_id (Integer): ID of the socket.

        Returns:
            :class:`.SocketInfo`: The socket information, or ``None`` if the socket with that ID does not exist.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.SocketInfo`
        """
        try:
            response = self.get_parameter(ATStringCommand.SI.command,
                                          parameter_value=utils.int_to_bytes(socket_id, 1))
            return SocketInfo.create_socket_info(response)
        except ATCommandException:
            return None

    def get_64bit_addr(self):
        """
        Deprecated.

        Cellular protocol does not have an associated 64-bit address.
        """
        return None

    def add_io_sample_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_io_sample_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_dio_change_detection(self, io_lines_set):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_io_sampling_rate(self):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_io_sampling_rate(self, rate):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_node_id(self):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_node_id(self, node_id):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_power_level(self):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_power_level(self, power_level):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class LPWANDevice(CellularDevice):
    """
    This class provides common functionality for XBee Low-Power Wide-Area Network
    devices.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.LPWANDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.CellularDevice`
           | :meth:`.CellularDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def send_ip_data(self, ip_addr, dest_port, protocol, data, close_socket=False):
        """
        Sends the provided IP data to the given IP address and port using
        the specified IP protocol.

        This method blocks till a success or error response arrives or the
        configured receive timeout expires.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to send IP data to.
            dest_port (Integer): The destination port of the transmission.
            protocol (:class:`.IPProtocol`): The IP protocol used for the transmission.
            data (String or Bytearray): The IP data to be sent.
            close_socket (Boolean, optional): Must be ``False``.

        Raises:
            ValueError: if ``protocol`` is not UDP.
        """
        if protocol != IPProtocol.UDP:
            raise ValueError("This protocol only supports UDP transmissions")

        super().send_ip_data(ip_addr, dest_port, protocol, data, close_socket=close_socket)

    def send_ip_data_async(self, ip_addr, dest_port, protocol, data, close_socket=False):
        """
        Sends the provided IP data to the given IP address and port
        asynchronously using the specified IP protocol.

        Asynchronous transmissions do not wait for answer from the remote
        device or for transmit status packet.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to send IP data to.
            dest_port (Integer): The destination port of the transmission.
            protocol (:class:`.IPProtocol`): The IP protocol used for the transmission.
            data (String or Bytearray): The IP data to be sent.
            close_socket (Boolean, optional): Must be ``False``.

        Raises:
            ValueError: if ``protocol`` is not UDP.
        """
        if protocol != IPProtocol.UDP:
            raise ValueError("This protocol only supports UDP transmissions")

        super().send_ip_data_async(ip_addr, dest_port, protocol, data, close_socket=close_socket)

    def add_sms_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_sms_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_sms(self, phone_number, data):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_sms_async(self, phone_number, data):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method will raise an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class NBIoTDevice(LPWANDevice):
    """
    This class represents a local NB-IoT device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.NBIoTDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.LPWANDevice`
           | :meth:`.LPWANDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._imei_addr = None

    def open(self, force_settings=False):
        """
        Override.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self.get_protocol() != XBeeProtocol.CELLULAR_NBIOT:
            raise XBeeException("Invalid protocol.")

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.CELLULAR_NBIOT


class WiFiDevice(IPDevice):
    """
    This class represents a local Wi-Fi XBee device.
    """

    __DEFAULT_ACCESS_POINT_TIMEOUT = 15  # 15 seconds of timeout to connect, disconnect and scan access points.
    __DISCOVER_TIMEOUT = 30  # 30 seconds of access points discovery timeout.

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.WiFiDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on 'GNU/Linux' or
                'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): comm port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): comm port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): comm port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): comm port flow control.
            _sync_ops_timeout (Integer, default: 3): the read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): the communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.IPDevice`
           | :meth:`.v.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits, parity=parity,
                         flow_control=flow_control, _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self.__ap_timeout = self.__DEFAULT_ACCESS_POINT_TIMEOUT
        self.__scanning_aps = False
        self.__scanning_aps_error = False

    def open(self, force_settings=False):
        """
        Override.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: If the protocol is invalid or if the XBee device is already open.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self.get_protocol() != XBeeProtocol.XBEE_WIFI:
            raise XBeeException("Invalid protocol.")

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.XBEE_WIFI

    def get_wifi_ai_status(self):
        """
        Returns the current association status of the device.

        Returns:
            :class:`.WiFiAssociationIndicationStatus`: the current association status of the device.

        Raises:
            TimeoutException: if there is a timeout getting the association indication status.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :class:`.WiFiAssociationIndicationStatus`
        """
        return WiFiAssociationIndicationStatus.get(utils.bytes_to_int(
            self.get_parameter(ATStringCommand.AI.command)))

    def get_access_point(self, ssid):
        """
        Finds and returns the access point that matches the supplied SSID.

        Args:
            ssid (String): the SSID of the access point to get.

        Returns:
            :class:`.AccessPoint`: the discovered access point with the provided SSID, or ``None``
                if the timeout expires and the access point was not found.

        Raises:
            TimeoutException: if there is a timeout getting the access point.
            XBeeException: if there is an error sending the discovery command.

        .. seealso::
           | :class:`.AccessPoint`
        """
        ap_list = self.scan_access_points()

        for access_point in ap_list:
            if access_point.ssid == ssid:
                return access_point

        return None

    @AbstractXBeeDevice._before_send_method
    def scan_access_points(self):
        """
        Performs a scan to search for access points in the vicinity.

        This method blocks until all the access points are discovered or the
        configured access point timeout expires.

        The access point timeout is configured using the :meth:`.WiFiDevice.set_access_point_timeout`
        method and can be consulted with :meth:`.WiFiDevice.get_access_point_timeout` method.

        Returns:
            List: the list of :class:`.AccessPoint` objects discovered.

        Raises:
            TimeoutException: if there is a timeout scanning the access points.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :class:`.AccessPoint`
        """
        access_points_list = []

        if self.operating_mode not in [OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE]:
            raise InvalidOperatingModeException(message="Only can scan for access points in API mode.")

        def packet_receive_callback(xbee_packet):
            if not self.__scanning_aps:
                return
            if xbee_packet.get_frame_type() != ApiFrameType.AT_COMMAND_RESPONSE:
                return
            if xbee_packet.command != ATStringCommand.AS.command:
                return

            # Check for error.
            if xbee_packet.status == ATCommandStatus.ERROR:
                self.__scanning_aps = False
                self.__scanning_aps_error = True
            # Check for end of discovery.
            elif xbee_packet.command_value is None or len(xbee_packet.command_value) == 0:
                self.__scanning_aps = False
            # Get the access point from the command value.
            else:
                access_point = self.__parse_access_point(xbee_packet.command_value)
                if access_point is not None:
                    access_points_list.append(access_point)

        self.add_packet_received_callback(packet_receive_callback)
        self.__scanning_aps = True

        try:
            self.send_packet(ATCommPacket(self.get_next_frame_id(), ATStringCommand.AS.command),
                             sync=False)

            dead_line = time.time() + self.__DISCOVER_TIMEOUT
            while self.__scanning_aps and time.time() < dead_line:
                time.sleep(0.1)

            # Check if we exited because of a timeout.
            if self.__scanning_aps:
                raise TimeoutException
            # Check if there was an error in the active scan command (device is already connected).
            if self.__scanning_aps_error:
                raise XBeeException("There is an SSID already configured.")
        finally:
            self.__scanning_aps = False
            self.__scanning_aps_error = False
            self.del_packet_received_callback(packet_receive_callback)

        return access_points_list

    def connect_by_ap(self, access_point, password=None):
        """
        Connects to the provided access point.

        This method blocks until the connection with the access point is
        established or the configured access point timeout expires.

        The access point timeout is configured using the
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be consulted with
        :meth:`.WiFiDevice.get_access_point_timeout` method.

        Once the module is connected to the access point, you can issue
        the :meth:`.WiFiDevice.write_changes` method to save the connection settings. This
        way the module will try to connect to the access point every time it
        is powered on.

        Args:
            access_point (:class:`.AccessPoint`): The access point to connect to.
            password (String, optional): The password for the access point, ``None`` if it does not have
                any encryption enabled. Optional.

        Returns:
            Boolean: ``True`` if the module connected to the access point successfully, ``False`` otherwise.

        Raises:
            ValueError:if ``access_point`` is ``None``.
            TimeoutException: if there is a timeout sending the connect commands.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :meth:`.WiFiDevice.connect_by_ssid`
           | :meth:`.WiFiDevice.disconnect`
           | :meth:`.WiFiDevice.get_access_point`
           | :meth:`.WiFiDevice.get_access_point_timeout`
           | :meth:`.WiFiDevice.scan_access_points`
           | :meth:`.WiFiDevice.set_access_point_timeout`
        """
        if access_point is None:
            raise ValueError("The access point to connect to cannot be None.")

        # Set connection parameters.
        self.set_parameter(ATStringCommand.ID.command, bytearray(access_point.ssid, "utf8"))
        self.set_parameter(ATStringCommand.EE.command, utils.int_to_bytes(access_point.encryption_type.code, num_bytes=1))
        if password is not None and access_point.encryption_type != WiFiEncryptionType.NONE:
            self.set_parameter(ATStringCommand.PK.command, bytearray(password, "utf8"))

        # Wait for the module to connect to the access point.
        dead_line = time.time() + self.__ap_timeout
        while time.time() < dead_line:
            time.sleep(0.1)
            # Get the association indication value of the module.
            status = self.get_parameter(ATStringCommand.AI.command)
            if status is None or len(status) < 1:
                continue
            if status[0] == 0:
                return True
        return False

    def connect_by_ssid(self, ssid, password=None):
        """
        Connects to the access point with provided SSID.

        This method blocks until the connection with the access point is
        established or the configured access point timeout expires.

        The access point timeout is configured using the
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be consulted with
        :meth:`.WiFiDevice.get_access_point_timeout` method.

        Once the module is connected to the access point, you can issue
        the :meth:`.WiFiDevice.write_changes` method to save the connection settings. This
        way the module will try to connect to the access point every time it
        is powered on.

        Args:
            ssid (String): the SSID of the access point to connect to.
            password (String, optional): The password for the access point, ``None`` if it does not have
                any encryption enabled. Optional.

        Returns:
            Boolean: ``True`` if the module connected to the access point successfully, ``False`` otherwise.

        Raises:
            ValueError: if ``ssid`` is ``None``.
            TimeoutException: if there is a timeout sending the connect commands.
            XBeeException: if the access point with the provided SSID cannot be found.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :meth:`.WiFiDevice.connect_by_ap`
           | :meth:`.WiFiDevice.disconnect`
           | :meth:`.WiFiDevice.get_access_point`
           | :meth:`.WiFiDevice.get_access_point_timeout`
           | :meth:`.WiFiDevice.scan_access_points`
           | :meth:`.WiFiDevice.set_access_point_timeout`
        """
        if ssid is None:
            raise ValueError("SSID of access point cannot be None.")

        access_point = self.get_access_point(ssid)
        if access_point is None:
            raise XBeeException("Couldn't find any access point with SSID '%s'." % ssid)

        return self.connect_by_ap(access_point, password=password)

    def disconnect(self):
        """
        Disconnects from the access point that the device is connected to.

        This method blocks until the device disconnects totally from the
        access point or the configured access point timeout expires.

        The access point timeout is configured using the
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be consulted with
        :meth:`.WiFiDevice.get_access_point_timeout` method.

        Returns:
            Boolean: ``True`` if the module disconnected from the access point successfully, ``False`` otherwise.

        Raises:
            TimeoutException: if there is a timeout sending the disconnect command.
            XBeeException: if there is any other XBee related exception.

        .. seealso::
           | :meth:`.WiFiDevice.connect_by_ap`
           | :meth:`.WiFiDevice.connect_by_ssid`
           | :meth:`.WiFiDevice.get_access_point_timeout`
           | :meth:`.WiFiDevice.set_access_point_timeout`
        """
        self.execute_command(ATStringCommand.NR.command)
        dead_line = time.time() + self.__ap_timeout
        while time.time() < dead_line:
            time.sleep(0.1)
            # Get the association indication value of the module.
            status = self.get_parameter(ATStringCommand.AI.command)
            if status is None or len(status) < 1:
                continue
            if status[0] == 0x23:
                return True
        return False

    def is_connected(self):
        """
        Returns whether the device is connected to an access point or not.

        Returns:
            Boolean: ``True`` if the device is connected to an access point, ``False`` otherwise.

        Raises:
            TimeoutException: if there is a timeout getting the association indication status.

        .. seealso::
           | :meth:`.WiFiDevice.get_wifi_ai_status`
           | :class:`.WiFiAssociationIndicationStatus`
        """
        status = self.get_wifi_ai_status()

        return status == WiFiAssociationIndicationStatus.SUCCESSFULLY_JOINED

    def __parse_access_point(self, ap_data):
        """
        Parses the given active scan API data and returns an :class:`.AccessPoint`: object.

        Args:
            ap_data (Bytearray): access point data to parse.

        Returns:
            :class:`.AccessPoint`: access point parsed from the provided data. ``None`` if the provided data
                does not correspond to an access point.

        .. seealso::
           | :class:`.AccessPoint`
        """
        index = 0

        if len(ap_data) == 0:
            return None

        # Get the version.
        version = ap_data[index]
        index += 1
        if len(ap_data[index:]) == 0:
            return None
        # Get the channel.
        channel = ap_data[index]
        index += 1
        if len(ap_data[index:]) == 0:
            return None
        # Get the encryption type.
        encryption_type = ap_data[index]
        index += 1
        if len(ap_data[index:]) == 0:
            return None
        # Get the signal strength.
        signal_strength = ap_data[index]
        index += 1
        if len(ap_data[index:]) == 0:
            return None

        signal_quality = self.__get_signal_quality(version, signal_strength)
        ssid = (ap_data[index:]).decode("utf8")

        return AccessPoint(ssid, WiFiEncryptionType.get(encryption_type), channel=channel,
                           signal_quality=signal_quality)

    @staticmethod
    def __get_signal_quality(wifi_version, signal_strength):
        """
        Converts the signal strength value in signal quality (%) based on the
        provided Wi-Fi version.

        Args:
            wifi_version (Integer): Wi-Fi protocol version of the Wi-Fi XBee device.
            signal_strength (Integer): signal strength value to convert to %.

        Returns:
            Integer: the signal quality in %.
        """
        if wifi_version == 1:
            if signal_strength <= -100:
                quality = 0
            elif signal_strength >= -50:
                quality = 100
            else:
                quality = (2 * (signal_strength + 100))
        else:
            quality = 2 * signal_strength

        # Check limits.
        if quality > 100:
            quality = 100
        if quality < 0:
            quality = 0

        return quality

    def get_access_point_timeout(self):
        """
        Returns the configured access point timeout for connecting,
        disconnecting and scanning access points.

        Returns:
            Integer: the current access point timeout in milliseconds.

        .. seealso::
           | :meth:`.WiFiDevice.set_access_point_timeout`
        """
        return self.__ap_timeout

    def set_access_point_timeout(self, ap_timeout):
        """
        Configures the access point timeout in milliseconds for connecting,
        disconnecting and scanning access points.

        Args:
            ap_timeout (Integer): the new access point timeout in milliseconds.

        Raises:
            ValueError: if ``ap_timeout`` is less than 0.

        .. seealso::
           | :meth:`.WiFiDevice.get_access_point_timeout`
        """
        if ap_timeout < 0:
            raise ValueError("Access point timeout cannot be less than 0.")
        self.__ap_timeout = ap_timeout

    def get_ip_addressing_mode(self):
        """
        Returns the IP addressing mode of the device.

        Returns:
            :class:`.IPAddressingMode`: the IP addressing mode.

        Raises:
            TimeoutException: if there is a timeout reading the IP addressing mode.

        .. seealso::
           | :meth:`.WiFiDevice.set_ip_addressing_mode`
           | :class:`.IPAddressingMode`
        """
        return IPAddressingMode.get(utils.bytes_to_int(self.get_parameter(ATStringCommand.MA.command)))

    def set_ip_addressing_mode(self, mode):
        """
        Sets the IP addressing mode of the device.

        Args:
            mode (:class:`.IPAddressingMode`): the new IP addressing mode to set.

        Raises:
            TimeoutException: if there is a timeout setting the IP addressing mode.

        .. seealso::
           | :meth:`.WiFiDevice.get_ip_addressing_mode`
           | :class:`.IPAddressingMode`
        """
        self.set_parameter(ATStringCommand.MA.command, utils.int_to_bytes(mode.code, num_bytes=1))

    def set_ip_address(self, ip_address):
        """
        Sets the IP address of the module.

        This method can only be called if the module is configured
        in :attr:`.IPAddressingMode.STATIC` mode. Otherwise an ``XBeeException``
        will be thrown.

        Args:
            ip_address (:class:`ipaddress.IPv4Address`): the new IP address to set.

        Raises:
            TimeoutException: if there is a timeout setting the IP address.

        .. seealso::
           | :meth:`.WiFiDevice.get_mask_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.MY.command, ip_address.packed)

    def get_mask_address(self):
        """
        Returns the subnet mask IP address.

        Returns:
            :class:`ipaddress.IPv4Address`: the subnet mask IP address.

        Raises:
            TimeoutException: if there is a timeout reading the subnet mask address.

        .. seealso::
           | :meth:`.WiFiDevice.set_mask_address`
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(bytes(self.get_parameter(ATStringCommand.MK.command)))

    def set_mask_address(self, mask_address):
        """
        Sets the subnet mask IP address.

        This method can only be called if the module is configured
        in :attr:`.IPAddressingMode.STATIC` mode. Otherwise an ``XBeeException``
        will be thrown.

        Args:
            mask_address (:class:`ipaddress.IPv4Address`): the new subnet mask address to set.

        Raises:
            TimeoutException: if there is a timeout setting the subnet mask address.

        .. seealso::
           | :meth:`.WiFiDevice.get_mask_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.MK.command, mask_address.packed)

    def get_gateway_address(self):
        """
        Returns the IP address of the gateway.

        Returns:
            :class:`ipaddress.IPv4Address`: the IP address of the gateway.

        Raises:
            TimeoutException: if there is a timeout reading the gateway address.

        .. seealso::
           | :meth:`.WiFiDevice.set_dns_address`
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(bytes(self.get_parameter(ATStringCommand.GW.command)))

    def set_gateway_address(self, gateway_address):
        """
        Sets the IP address of the gateway.

        This method can only be called if the module is configured
        in :attr:`.IPAddressingMode.STATIC` mode. Otherwise an ``XBeeException``
        will be thrown.

        Args:
            gateway_address (:class:`ipaddress.IPv4Address`): the new gateway address to set.

        Raises:
            TimeoutException: if there is a timeout setting the gateway address.

        .. seealso::
           | :meth:`.WiFiDevice.get_gateway_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.GW.command, gateway_address.packed)

    def get_dns_address(self):
        """
        Returns the IP address of Domain Name Server (DNS).

        Returns:
            :class:`ipaddress.IPv4Address`: the DNS address configured.

        Raises:
            TimeoutException: if there is a timeout reading the DNS address.

        .. seealso::
           | :meth:`.WiFiDevice.set_dns_address`
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(bytes(self.get_parameter(ATStringCommand.NS.command)))

    def set_dns_address(self, dns_address):
        """
        Sets the IP address of Domain Name Server (DNS).

        Args:
            dns_address (:class:`ipaddress.IPv4Address`): the new DNS address to set.

        Raises:
            TimeoutException: if there is a timeout setting the DNS address.

        .. seealso::
           | :meth:`.WiFiDevice.get_dns_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.NS.command, dns_address.packed)


class RemoteXBeeDevice(AbstractXBeeDevice):
    """
    This class represents a remote XBee device.
    """

    def __init__(self, local_xbee_device, x64bit_addr=XBee64BitAddress.UNKNOWN_ADDRESS,
                 x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteXBeeDevice` with the provided parameters.
        
        Args:
            local_xbee_device (:class:`.XBeeDevice`): the local XBee device associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit address of the remote XBee device.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit address of the remote XBee device.
            node_id (String, optional): the node identifier of the remote XBee device. Optional.

        .. seealso::
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        super().__init__(local_xbee_device=local_xbee_device,
                         comm_iface=local_xbee_device.comm_iface)

        self._local_xbee_device = local_xbee_device
        self._64bit_addr = x64bit_addr
        if not x64bit_addr:
            self._64bit_addr = XBee64BitAddress.UNKNOWN_ADDRESS
        self._16bit_addr = x16bit_addr
        if not x16bit_addr:
            self._16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS
        self._node_id = node_id

    def get_parameter(self, parameter, parameter_value=None):
        """
        Override.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
        """
        return super().get_parameter(parameter, parameter_value=parameter_value)

    def set_parameter(self, parameter, value):
        """
        Override.
           
        .. seealso::
           | :meth:`.AbstractXBeeDevice.set_parameter`
        """
        super().set_parameter(parameter, value)

    def is_remote(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_remote`
        """
        return True

    def reset(self):
        """
        Override method.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.reset`
        """
        # Send reset command.
        try:
            response = self._send_at_command(ATCommand(ATStringCommand.FR.command))
        except TimeoutException as te:
            # Remote 802.15.4 devices do not respond to the AT command.
            if self._local_xbee_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
                return
            else:
                raise te

        # Check if AT Command response is valid.
        self._check_at_cmd_response_is_valid(response)

    def get_local_xbee_device(self):
        """
        Returns the local XBee device associated to the remote one.
        
        Returns:
            :class:`.XBeeDevice`
        
        """
        return self._local_xbee_device

    def set_local_xbee_device(self, local_xbee_device):
        """
        This methods associates a :class:`.XBeeDevice` to the remote XBee device.

        Args:
            local_xbee_device (:class:`.XBeeDevice`): the new local XBee device associated to the remote one.

        .. seealso::
           | :class:`.XBeeDevice`
        """
        self._local_xbee_device = local_xbee_device

    def get_serial_port(self):
        """
        Returns the serial port of the local XBee device associated to the remote one.

        Returns:
            :class:`XBeeSerialPort`: the serial port of the local XBee device associated to the remote one.

        .. seealso::
           | :class:`XBeeSerialPort`
        """
        return self._local_xbee_device.serial_port

    def get_comm_iface(self):
        """
        Returns the communication interface of the local XBee device associated to the remote one.

        Returns:
            :class:`XBeeCommunicationInterface`: the communication interface of the local XBee device associated to
                the remote one.

        .. seealso::
           | :class:`XBeeCommunicationInterface`
        """
        return self._local_xbee_device.comm_iface


class RemoteRaw802Device(RemoteXBeeDevice):
    """
    This class represents a remote 802.15.4 XBee device.
    """

    def __init__(self, local_xbee_device, x64bit_addr=None, x16bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteXBeeDevice` with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`): the local XBee device associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit address of the remote XBee device.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit address of the remote XBee device.
            node_id (String, optional): the node identifier of the remote XBee device. Optional.

        Raises:
            XBeeException: if the protocol of ``local_xbee_device`` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr=x64bit_addr, x16bit_addr=x16bit_addr,
                         node_id=node_id)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.RemoteXBeeDevice.get_protocol`
        """
        return XBeeProtocol.RAW_802_15_4

    def set_64bit_addr(self, address):
        """
        Sets the 64-bit address of this remote 802.15.4 device.

        Args:
            address (:class:`.XBee64BitAddress`): The 64-bit address to be set to the device.

        Raises:
            ValueError: if ``address`` is ``None``.
        """
        if address is None:
            raise ValueError("64-bit address cannot be None")

        self._64bit_addr = address

    def get_ai_status(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._get_ai_status`
        """
        return super()._get_ai_status()


class RemoteDigiMeshDevice(RemoteXBeeDevice):
    """
    This class represents a remote DigiMesh XBee device.
    """

    def __init__(self, local_xbee_device, x64bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteDigiMeshDevice` with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`): the local XBee device associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit address of the remote XBee device.
            node_id (String, optional): the node identifier of the remote XBee device. Optional.

        Raises:
            XBeeException: if the protocol of ``local_xbee_device`` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.DIGI_MESH:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr=x64bit_addr,
                         x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=node_id)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.RemoteXBeeDevice.get_protocol`
        """
        return XBeeProtocol.DIGI_MESH


class RemoteDigiPointDevice(RemoteXBeeDevice):
    """
    This class represents a remote DigiPoint XBee device.
    """

    def __init__(self, local_xbee_device, x64bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteDigiMeshDevice` with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`): the local XBee device associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit address of the remote XBee device.
            node_id (String, optional): the node identifier of the remote XBee device. Optional.

        Raises:
            XBeeException: if the protocol of ``local_xbee_device`` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.DIGI_POINT:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr=x64bit_addr,
                         x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=node_id)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.RemoteXBeeDevice.get_protocol`
        """
        return XBeeProtocol.DIGI_POINT


class RemoteZigBeeDevice(RemoteXBeeDevice):
    """
    This class represents a remote ZigBee XBee device.
    """

    def __init__(self, local_xbee_device, x64bit_addr=None, x16bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteDigiMeshDevice` with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`): the local XBee device associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): the 64-bit address of the remote XBee device.
            x16bit_addr (:class:`.XBee16BitAddress`): the 16-bit address of the remote XBee device.
            node_id (String, optional): the node identifier of the remote XBee device. Optional.

        Raises:
            XBeeException: if the protocol of ``local_xbee_device`` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.ZIGBEE:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr=x64bit_addr, x16bit_addr=x16bit_addr,
                         node_id=node_id)

    def get_protocol(self):
        """
        Override.
        
        .. seealso::
           | :meth:`.RemoteXBeeDevice.get_protocol`
        """
        return XBeeProtocol.ZIGBEE

    def get_ai_status(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._get_ai_status`
        """
        return super()._get_ai_status()

    def force_disassociate(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._force_disassociate`
        """
        super()._force_disassociate()


class XBeeNetwork(object):
    """
    This class represents an XBee Network.

    The network allows the discovery of remote devices in the same network
    as the local one and stores them.
    """

    ND_PACKET_FINISH = 0x01
    """
    Flag that indicates a "discovery process finish" packet.
    """

    ND_PACKET_REMOTE = 0x02
    """
    Flag that indicates a discovery process packet with info about a remote XBee device.
    """

    # Default timeout for discovering process in case of
    # the real timeout can't be determined.
    __DEFAULT_DISCOVERY_TIMEOUT = 20

    # Correction values for the timeout for determined devices.
    # It has been tested and work 'fine'
    __DIGI_MESH_TIMEOUT_CORRECTION = 3
    __DIGI_MESH_SLEEP_TIMEOUT_CORRECTION = 0.1  # DigiMesh with sleep support.
    __DIGI_POINT_TIMEOUT_CORRECTION = 8

    def __init__(self, xbee_device):
        """
        Class constructor. Instantiates a new ``XBeeNetwork``.

        Args:
            xbee_device (:class:`.XBeeDevice`): the local XBee device to get the network from.

        Raises:
            ValueError: if ``xbee_device`` is ``None``.
        """
        if xbee_device is None:
            raise ValueError("Local XBee device cannot be None")

        self.__xbee_device = xbee_device
        self.__devices_list = []
        self.__last_search_dev_list = []
        self.__lock = threading.Lock()
        self.__discovering = False
        self.__event = threading.Event()
        self.__discover_result = ATCommandStatus.OK
        self.__network_modified = NetworkModified()
        self.__device_discovered = DeviceDiscovered()
        self.__device_discovery_finished = DiscoveryProcessFinished()
        self.__discovery_thread = None
        self.__sought_device_id = None
        self.__discovered_device = None

    def start_discovery_process(self):
        """
        Starts the discovery process. This method is not blocking.
        
        The discovery process will be running until the configured
        timeout expires or, in case of 802.15.4, until the 'end' packet
        is read.
        
        It may be that, after the timeout expires, there are devices
        that continue sending discovery packets to this XBee device. In this
        case, these devices will not be added to the network.

        .. seealso::
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
        """
        with self.__lock:
            if self.__discovering:
                return

        self.__discovery_thread = threading.Thread(target=self.__discover_devices_and_notify_callbacks)
        self.__discovering = True
        self.__discover_result = ATCommandStatus.OK
        self.__discovery_thread.start()

    def stop_discovery_process(self):
        """
        Stops the discovery process if it is running.

        Note that DigiMesh/DigiPoint devices are blocked until the discovery
        time configured (NT parameter) has elapsed, so if you try to get/set
        any parameter during the discovery process you will receive a timeout
        exception.
        """
        self.__event.set()

        if self.__discovery_thread and self.__discovering:
            self.__discovery_thread.join()
            self.__discovery_thread = None

    def discover_device(self, node_id):
        """
        Blocking method. Discovers and reports the first remote XBee device that matches the
        supplied identifier.

        Args:
            node_id (String): the node identifier of the device to be discovered.

        Returns:
            :class:`.RemoteXBeeDevice`: the discovered remote XBee device with the given identifier,
                ``None`` if the timeout expires and the device was not found.
        """
        try:
            with self.__lock:
                self.__sought_device_id = node_id
            self.__discover_devices(node_id=node_id)
        finally:
            with self.__lock:
                self.__sought_device_id = None
                remote = self.__discovered_device
                self.__discovered_device = None
            if remote is not None:
                self.__add_remote(remote, NetworkEventReason.DISCOVERED)
            return remote

    def discover_devices(self, device_id_list):
        """
        Blocking method. Attempts to discover a list of devices and add them to the
        current network.
        
        This method does not guarantee that all devices of ``device_id_list``
        will be found, even if they exist physically. This will depend on the node
        discovery operation (``ND``) and timeout.
        
        Args:
            device_id_list (List): list of device IDs to discover.
            
        Returns:
            List: a list with the discovered devices. It may not contain all devices specified in ``device_id_list``
        """
        self.start_discovery_process()
        while self.is_discovery_running():
            time.sleep(0.1)
        return list(filter(lambda x: x.get_node_id() in device_id_list, self.__last_search_dev_list))

    def is_discovery_running(self):
        """
        Returns whether the discovery process is running or not.
        
        Returns:
            Boolean: ``True`` if the discovery process is running, ``False`` otherwise.
        """
        return self.__discovering

    def get_devices(self):
        """
        Returns a copy of the XBee devices list of the network.
        
        If another XBee device is added to the list before the execution
        of this method, this XBee device will not be added to the list returned
        by this method.
        
        Returns:
            List: a copy of the XBee devices list of the network.
        """
        with self.__lock:
            dl_copy = [len(self.__devices_list)]
            dl_copy[:] = self.__devices_list[:]
            return dl_copy

    def has_devices(self):
        """
        Returns whether there is any device in the network or not.

        Returns:
            Boolean: ``True`` if there is at least one device in the network, ``False`` otherwise.
        """
        return len(self.__devices_list) > 0

    def get_number_devices(self):
        """
        Returns the number of devices in the network.

        Returns:
            Integer: the number of devices in the network.
        """
        return len(self.__devices_list)

    def add_network_modified_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.NetworkModified`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The event type as a :class:`.NetworkEventType`
                * The reason of the event as a :class:`.NetworkEventReason`
                * The node added, updated or removed from the network as a :class:`.XBeeDevice` or
                  :class:`.RemoteXBeeDevice`.

        .. seealso::
           | :meth:`.XBeeNetwork.del_network_modified_callback`
        """
        self.__network_modified += callback

    def add_device_discovered_callback(self, callback):
        """
        Adds a callback for the event :class:`.DeviceDiscovered`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The discovered remote XBee device as a :class:`.RemoteXBeeDevice`

        .. seealso::
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
        """
        self.__device_discovered += callback

    def add_discovery_process_finished_callback(self, callback):
        """
        Adds a callback for the event :class:`.DiscoveryProcessFinished`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The event code as an :class:`.Integer`

        .. seealso::
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
        """
        self.__device_discovery_finished += callback

    def del_network_modified_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.NetworkModified`.

        Args:
            callback (Function): the callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_network_modified_callback`
        """
        self.__network_modified -= callback

    def del_device_discovered_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DeviceDiscovered` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.DeviceDiscovered` event.

        .. seealso::
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
        """
        self.__device_discovered -= callback

    def del_discovery_process_finished_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DiscoveryProcessFinished` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.DiscoveryProcessFinished` event.

        .. seealso::
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
        """
        self.__device_discovery_finished -= callback

    def clear(self):
        """
        Removes all the remote XBee devices from the network.
        """
        with self.__lock:
            self.__devices_list = []
        self.__network_modified(NetworkEventType.CLEAR, NetworkEventReason.MANUAL, None)

    def get_discovery_options(self):
        """
        Returns the network discovery process options.
        
        Returns:
            Bytearray: the parameter value.
        
        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        return self.__xbee_device.get_parameter(ATStringCommand.NO.command)

    def set_discovery_options(self, options):
        """
        Configures the discovery options (``NO`` parameter) with the given value.

        Args:
            options (Set of :class:`.DiscoveryOptions`): new discovery options, empty set to clear the options.

        Raises:
            ValueError: if ``options`` is ``None``.
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.

        .. seealso::
           | :class:`.DiscoveryOptions`
        """
        if options is None:
            raise ValueError("Options cannot be None")

        value = DiscoveryOptions.calculate_discovery_value(self.__xbee_device.get_protocol(), options)
        self.__xbee_device.set_parameter(ATStringCommand.NO.command, utils.int_to_bytes(value))

    def get_discovery_timeout(self):
        """
        Returns the network discovery timeout.
        
        Returns:
            Float: the network discovery timeout.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        tout = self.__xbee_device.get_parameter(ATStringCommand.NT.command)

        return utils.bytes_to_int(tout) / 10.0

    def set_discovery_timeout(self, discovery_timeout):
        """
        Sets the discovery network timeout.
        
        Args:
            discovery_timeout (Float): timeout in seconds.
        
        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
            ValueError: if ``discovery_timeout`` is not between 0x20 and 0xFF
        """
        discovery_timeout *= 10  # seconds to 100ms
        if discovery_timeout < 0x20 or discovery_timeout > 0xFF:
            raise ValueError("Value must be between 3.2 and 25.5")
        timeout = bytearray([int(discovery_timeout)])
        self.__xbee_device.set_parameter(ATStringCommand.NT.command, timeout)

    def get_device_by_64(self, x64bit_addr):
        """
        Returns the XBee in the network whose 64-bit address matches the given one.

        Args:
            x64bit_addr (:class:`XBee64BitAddress`): The 64-bit address of the device to be retrieved.

        Returns:
            :class:`.AbstractXBeeDevice`: the XBee device in the network or ``None`` if it is not found.

        Raises:
            ValueError: if ``x64bit_addr`` is ``None`` or unknown.
        """
        if x64bit_addr is None:
            raise ValueError("64-bit address cannot be None")
        if x64bit_addr == XBee64BitAddress.UNKNOWN_ADDRESS:
            raise ValueError("64-bit address cannot be unknown")

        if self.__xbee_device.get_64bit_addr() == x64bit_addr:
            return self.__xbee_device

        with self.__lock:
            for device in self.__devices_list:
                if device.get_64bit_addr() is not None and device.get_64bit_addr() == x64bit_addr:
                    return device

        return None

    def get_device_by_16(self, x16bit_addr):
        """
        Returns the XBee in the network whose 16-bit address matches the given one.

        Args:
            x16bit_addr (:class:`XBee16BitAddress`): The 16-bit address of the device to be retrieved.

        Returns:
            :class:`.AbstractXBeeDevice`: the XBee device in the network or ``None`` if it is not found.

        Raises:
            ValueError: if ``x16bit_addr`` is ``None`` or unknown.
        """
        if self.__xbee_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            raise ValueError("DigiMesh protocol does not support 16-bit addressing")
        if self.__xbee_device.get_protocol() == XBeeProtocol.DIGI_POINT:
            raise ValueError("Point-to-Multipoint protocol does not support 16-bit addressing")
        if x16bit_addr is None:
            raise ValueError("16-bit address cannot be None")
        if x16bit_addr == XBee16BitAddress.UNKNOWN_ADDRESS:
            raise ValueError("16-bit address cannot be unknown")

        if self.__xbee_device.get_16bit_addr() == x16bit_addr:
            return self.__xbee_device

        with self.__lock:
            for device in self.__devices_list:
                if device.get_16bit_addr() is not None and device.get_16bit_addr() == x16bit_addr:
                    return device

        return None

    def get_device_by_node_id(self, node_id):
        """
        Returns the XBee in the network whose node identifier matches the given one.

        Args:
            node_id (String): The node identifier of the device to be retrieved.

        Returns:
            :class:`.AbstractXBeeDevice`: the XBee device in the network or ``None`` if it is not found.

        Raises:
            ValueError: if ``node_id`` is ``None``.
        """
        if node_id is None:
            raise ValueError("Node ID cannot be None")

        if self.__xbee_device.get_node_id() == node_id:
            return self.__xbee_device

        with self.__lock:
            for device in self.__devices_list:
                if device.get_node_id() is not None and device.get_node_id() == node_id:
                    return device

        return None

    def add_if_not_exist(self, x64bit_addr=None, x16bit_addr=None, node_id=None):
        """
        Adds an XBee device with the provided parameters if it does not exist in the current network.
        
        If the XBee device already exists, its data will be updated with the provided parameters that are not ``None``.
        
        Args:
            x64bit_addr (:class:`XBee64BitAddress`, optional): XBee device's 64bit address. Optional.
            x16bit_addr (:class:`XBee16BitAddress`, optional): XBee device's 16bit address. Optional.
            node_id (String, optional): the node identifier of the XBee device. Optional.
            
        Returns:
            :class:`.AbstractXBeeDevice`: the remote XBee device with the updated parameters. If the XBee device
                was not in the list yet, this method returns the given XBee device without changes.
        """
        if x64bit_addr == self.__xbee_device.get_64bit_addr():
            return self.__xbee_device

        return self.__add_remote_from_attr(NetworkEventReason.MANUAL, x64bit_addr=x64bit_addr,
                                           x16bit_addr=x16bit_addr, node_id=node_id)

    def add_remote(self, remote_xbee_device):
        """
        Adds the provided remote XBee device to the network if it is not contained yet.
        
        If the XBee device is already contained in the network, its data will be updated with the parameters of
        the XBee device that are not ``None``.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to add to the network.
        
        Returns:
            :class:`.RemoteXBeeDevice`: the provided XBee device with the updated parameters. If the XBee device
                was not in the list yet, this method returns it without changes.
        """
        return self.__add_remote(remote_xbee_device, NetworkEventReason.MANUAL)

    def __add_remote(self, remote_xbee, reason):
        """
        Adds the provided remote XBee device to the network if it is not contained yet.

        If the XBee device is already contained in the network, its data will be updated with the
        parameters of the XBee device that are not ``None``.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): the remote XBee device to add to the network.

        Returns:
            :class:`.RemoteXBeeDevice`: the provided XBee device with the updated parameters. If the XBee device
                was not in the list yet, this method returns it without changes.
        """
        if remote_xbee == remote_xbee.get_local_xbee_device():
            return remote_xbee

        with self.__lock:
            for xbee in self.__devices_list:
                if xbee == remote_xbee:
                    if xbee.update_device_data_from(remote_xbee):
                        self.__network_modified(NetworkEventType.UPDATE, reason, node=xbee)
                    return xbee
            self.__devices_list.append(remote_xbee)
            self.__network_modified(NetworkEventType.ADD, reason, node=remote_xbee)

            return remote_xbee

    def __add_remote_from_attr(self, reason, x64bit_addr=None, x16bit_addr=None, node_id=None,
                               role=Role.UNKNOWN):
        """
        Creates a new XBee using the provided data and adds it to the network if it is not
        included yet.

        If the XBee is already in the network, its data will be updated with the parameters of the
        XBee that are not ``None``.

        Args:
            reason (:class:`.NetworkEventReason`): The reason of the addition to the network.
            x64bit_addr (:class:`digi.xbee.models.address.XBee64BitAddress`, optional,
                default=``None``): The 64-bit address of the remote XBee.
            x16bit_addr (:class:`digi.xbee.models.address.XBee16BitAddress`, optional,
                default=``None``): The 16-bit address of the remote XBee.
            node_id (String, optional, default=``None``): The node identifier of the remote XBee.
            role (:class:`digi.xbee.models.protocol.Role`, optional, default=``Role.UNKNOWN``):
                The role of the remote XBee

        Returns:
            :class:`.RemoteXBeeDevice`: the remote XBee device generated from the provided data if
                the data provided is correct and the XBee device's protocol is valid, ``None``
                otherwise.

        .. seealso::
            | :class:`.NetworkEventReason`
            | :class:`digi.xbee.models.address.XBee16BitAddress`
            | :class:`digi.xbee.models.address.XBee64BitAddress`
            | :class:`digi.xbee.models.protocol.Role`

        Returns:
            :class:`.AbstractXBeeDevice`: The created XBee with the updated parameters.
        """
        return self.__add_remote(
            self.__create_remote(x64bit_addr=x64bit_addr, x16bit_addr=x16bit_addr,
                                 node_id=node_id, role=role), reason)

    def add_remotes(self, remote_xbee_devices):
        """
        Adds a list of remote XBee devices to the network.
        
        If any XBee device of the list is already contained in the network, its data will be updated with the
        parameters of the XBee device that are not ``None``.
        
        Args:
            remote_xbee_devices (List): the list of :class:`.RemoteXBeeDevice` to add to the network.
        """
        for rem in remote_xbee_devices:
            self.add_remote(rem)

    def remove_device(self, remote_xbee_device):
        """
        Removes the provided remote XBee device from the network.
        
        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to be removed from the list.
            
        Raises:
            ValueError: if the provided :class:`.RemoteXBeeDevice` is not in the network.
        """
        self.__devices_list.remove(remote_xbee_device)
        self.__network_modified(NetworkEventType.DEL, NetworkEventReason.MANUAL,
                                node=remote_xbee_device)

    def get_discovery_callbacks(self):
        """
        Returns the API callbacks that are used in the device discovery process.
        
        This callbacks notify the user callbacks for each XBee device discovered.

        Returns:
            Tuple (Function, Function): callback for generic devices discovery process,
                callback for discovery specific XBee device ops.
        """
        def discovery_gen_callback(xbee_packet):
            """
            Callback for generic devices discovery process.
            """
            # if the discovering process is not running, stop.
            if not self.__discovering:
                return
            # Check the packet
            nd_id = self.__check_nd_packet(xbee_packet)
            if nd_id == XBeeNetwork.ND_PACKET_FINISH:
                # if it's a ND finish signal, stop wait for packets
                with self.__lock:
                    self.__discovering = xbee_packet.status != ATCommandStatus.OK
                    self.__discover_result = xbee_packet.status
                self.stop_discovery_process()
            elif nd_id == XBeeNetwork.ND_PACKET_REMOTE:
                x16, x64, n_id, role = self.__get_data_for_remote(xbee_packet.command_value)
                remote = self.__create_remote(x64bit_addr=x64, x16bit_addr=x16, node_id=n_id,
                                              role=role)
                # XBee device list, add it and notify callbacks.
                if remote is not None:
                    # if remote was created successfully and it is not in the
                    # XBee device list, add it and notify callbacks.
                    self.__add_remote(remote, NetworkEventReason.DISCOVERED)
                    # always add the XBee device to the last discovered devices list:
                    self.__last_search_dev_list.append(remote)
                    self.__device_discovered(remote)

        def discovery_spec_callback(xbee_packet):
            """
            This callback is used for discovery specific XBee device ops.
            """
            # if __sought_device_id is None, exit (not searching XBee device).
            if self.__sought_device_id is None:
                return
            # Check the packet
            nd_id = self.__check_nd_packet(xbee_packet)
            if nd_id == XBeeNetwork.ND_PACKET_FINISH:
                # if it's a ND finish signal, stop wait for packets
                if xbee_packet.status == ATCommandStatus.OK:
                    with self.__lock:
                        self.__sought_device_id = None
                self.stop_discovery_process()
            elif nd_id == XBeeNetwork.ND_PACKET_REMOTE:
                # if it is not a finish signal, it contains info about a remote XBee device.
                x16, x64, n_id, role = self.__get_data_for_remote(xbee_packet.command_value)
                remote = self.__create_remote(x64bit_addr=x64, x16bit_addr=x16, node_id=n_id,
                                              role=role)
                # if it's the sought XBee device, put it in the proper variable.
                if self.__sought_device_id == remote.get_node_id():
                    with self.__lock:
                        self.__discovered_device = remote
                        self.__sought_device_id = None
                    self.stop_discovery_process()

        return discovery_gen_callback, discovery_spec_callback

    def _get_discovery_thread(self):
        """
        Returns the network discovery thread.
        
        Used to determine whether the discovery thread is alive or not.
        
        Returns:
            :class:`.Thread`: the network discovery thread.
        """
        return self.__discovery_thread

    @staticmethod
    def __check_nd_packet(xbee_packet):
        """
        Checks if the provided XBee packet is an ND response or not. If so, checks if is the 'end' signal
        of the discovery process or if it has information about a remote XBee device.
        
        Returns:
            Integer: the ID that indicates if the packet is a finish discovery signal or if it contains information
                about a remote XBee device, or ``None`` if the ``xbee_packet`` is not a response for an ``ND`` command.

                 * :attr:`.XBeeNetwork.ND_PACKET_FINISH`: if ``xbee_packet`` is an end signal.
                 * :attr:`.XBeeNetwork.ND_PACKET_REMOTE`: if ``xbee_packet`` has info about a remote XBee device.
        """
        if (xbee_packet.get_frame_type() == ApiFrameType.AT_COMMAND_RESPONSE and
           xbee_packet.command == ATStringCommand.ND.command):
            if xbee_packet.command_value is None or len(xbee_packet.command_value) == 0:
                return XBeeNetwork.ND_PACKET_FINISH
            else:
                return XBeeNetwork.ND_PACKET_REMOTE
        else:
            return None

    def __discover_devices_and_notify_callbacks(self):
        """
        Blocking method. Performs a discovery operation, waits
        until it finish (timeout or 'end' packet for 802.15.4),
        and notifies callbacks.
        """
        self.__discover_devices()

        status = NetworkDiscoveryStatus.SUCCESS
        if self.__discover_result != ATCommandStatus.OK:
            status = NetworkDiscoveryStatus.ERROR_NET_DISCOVER

        self.__device_discovery_finished(status)

    def __discover_devices(self, node_id=None):
        """
        Blocking method. Performs a device discovery in the network and waits until it finish (timeout or 'end'
        packet for 802.15.4)

        Args:
            node_id (String, optional): node identifier of the remote XBee device to discover. Optional.
        """
        try:
            self.__event.clear()

            timeout = self.__calculate_timeout()
            # send "ND" async
            self.__xbee_device.send_packet(ATCommPacket(self.__xbee_device.get_next_frame_id(),
                                                        ATStringCommand.ND.command,
                                                        parameter=None if node_id is None else bytearray(node_id, 'utf8')),
                                           sync=False)
            self.__event.wait(timeout)
        except Exception as e:
            self.__xbee_device.log.exception(e)
        finally:
            with self.__lock:
                self.__discovering = False

    def __is_802_compatible(self):
        """
        Checks if the device performing the node discovery is a legacy 
        802.15.4 device or a S1B device working in compatibility mode.
        
        Returns:
            Boolean: ``True`` if the device performing the node discovery is a legacy
                802.15.4 device or S1B in compatibility mode, ``False`` otherwise.
        
        """
        if self.__xbee_device.get_protocol() != XBeeProtocol.RAW_802_15_4:
            return False
        param = None
        try:
            param = self.__xbee_device.get_parameter(ATStringCommand.C8.command)
        except ATCommandException:
            pass
        if param is None or param[0] & 0x2 == 2:
            return True
        return False

    def __calculate_timeout(self):
        """
        Determines the discovery timeout.
        
        Gets timeout information from the device and applies the proper
        corrections to it.
        
        If the timeout cannot be determined getting it from the device, this
        method returns the default timeout for discovery operations.
        
        Returns:
            Float: discovery timeout in seconds.
        """
        # Read the maximum discovery timeout (N?)
        try:
            discovery_timeout = utils.bytes_to_int(self.__xbee_device.get_parameter(ATStringCommand.N_QUESTION.command)) / 1000
        except XBeeException:
            discovery_timeout = None

        # If N? does not exist, read the NT parameter.
        if discovery_timeout is None:
            # Read the XBee device timeout (NT).
            try:
                discovery_timeout = utils.bytes_to_int(self.__xbee_device.get_parameter(ATStringCommand.NT.command)) / 10
            except XBeeException as xe:
                discovery_timeout = XBeeNetwork.__DEFAULT_DISCOVERY_TIMEOUT
                self.__xbee_device.log.exception(xe)
                self.__device_discovery_finished(NetworkDiscoveryStatus.ERROR_READ_TIMEOUT)

            # In DigiMesh/DigiPoint the network discovery timeout is NT + the
            # network propagation time. It means that if the user sends an AT
            # command just after NT ms, s/he will receive a timeout exception.
            if self.__xbee_device.get_protocol() == XBeeProtocol.DIGI_MESH:
                discovery_timeout += XBeeNetwork.__DIGI_MESH_TIMEOUT_CORRECTION
            elif self.__xbee_device.get_protocol() == XBeeProtocol.DIGI_POINT:
                discovery_timeout += XBeeNetwork.__DIGI_POINT_TIMEOUT_CORRECTION

        if self.__xbee_device.get_protocol() == XBeeProtocol.DIGI_MESH:
            # If the module is 'Sleep support', wait another discovery cycle.
            try:
                if utils.bytes_to_int(self.__xbee_device.get_parameter(
                        ATStringCommand.SM.command)) == 7:
                    discovery_timeout += discovery_timeout + \
                                        (discovery_timeout * XBeeNetwork.__DIGI_MESH_SLEEP_TIMEOUT_CORRECTION)
            except XBeeException as xe:
                self.__xbee_device.log.exception(xe)
        elif self.__is_802_compatible():
            discovery_timeout += 2  # Give some time to receive the ND finish packet

        return discovery_timeout

    def __create_remote(self, x64bit_addr=XBee64BitAddress.UNKNOWN_ADDRESS,
                        x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=None, role=Role.UNKNOWN):
        """
        Creates and returns a :class:`.RemoteXBeeDevice` from the provided data,
        if the data contains the required information and in the required
        format.

        Args:
            x64bit_addr (:class:`digi.xbee.models.address.XBee64BitAddress`, optional,
                default=``XBee64BitAddress.UNKNOWN_ADDRESS``): The 64-bit address of the remote XBee.
            x16bit_addr (:class:`digi.xbee.models.address.XBee16BitAddress`, optional,
                default=``XBee16BitAddress.UNKNOWN_ADDRESS``): The 16-bit address of the remote XBee.
            node_id (String, optional, default=``None``): The node identifier of the remote XBee.
            role (:class:`digi.xbee.models.protocol.Role`, optional, default=``Role.UNKNOWN``):
                The role of the remote XBee

        Returns:
            :class:`.RemoteXBeeDevice`: the remote XBee device generated from the provided data if
                the data provided is correct and the XBee device's protocol is valid, ``None``
                otherwise.
        
        .. seealso::
            | :class:`digi.xbee.models.address.XBee16BitAddress`
            | :class:`digi.xbee.models.address.XBee64BitAddress`
            | :class:`digi.xbee.models.protocol.Role`
        """
        if not x64bit_addr and not x16bit_addr:
            return None

        p = self.__xbee_device.get_protocol()

        if p == XBeeProtocol.ZIGBEE:
            xb = RemoteZigBeeDevice(self.__xbee_device, x64bit_addr=x64bit_addr,
                                    x16bit_addr=x16bit_addr, node_id=node_id)
        elif p == XBeeProtocol.DIGI_MESH:
            xb = RemoteDigiMeshDevice(self.__xbee_device, x64bit_addr=x64bit_addr, node_id=node_id)
        elif p == XBeeProtocol.DIGI_POINT:
            xb = RemoteDigiPointDevice(self.__xbee_device, x64bit_addr=x64bit_addr, node_id=node_id)
        elif p == XBeeProtocol.RAW_802_15_4:
            xb = RemoteRaw802Device(self.__xbee_device, x64bit_addr=x64bit_addr,
                                    x16bit_addr=x16bit_addr, node_id=node_id)
        else:
            xb = RemoteXBeeDevice(self.__xbee_device, x64bit_addr=x64bit_addr,
                                  x16bit_addr=x16bit_addr, node_id=node_id)

        xb._role = role
        return xb

    def __get_data_for_remote(self, data):
        """
        Extracts the :class:`.XBee16BitAddress` (bytes 0 and 1), the
        :class:`.XBee64BitAddress` (bytes 2 to 9) and the node identifier
        from the provided data.
        
        Args:
            data (Bytearray): the data to extract information from.
        
        Returns:
            Tuple (:class:`.XBee16BitAddress`, :class:`.XBee64BitAddress`, Bytearray): remote device information
        """
        role = Role.UNKNOWN
        if self.__xbee_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            # node ID starts at 11 if protocol is not 802.15.4:
            #    802.15.4 adds a byte of info between 64bit address and XBee device ID, avoid it:
            i = 11
            # node ID goes from 11 to the next 0x00.
            while data[i] != 0x00:
                i += 1
            node_id = data[11:i]
        else:
            # node ID starts at 10 if protocol is not 802.15.4
            i = 10
            # node id goes from 'i' to the next 0x00.
            while data[i] != 0x00:
                i += 1
            node_id = data[10:i]
            i += 1
            # parent address: next 2 bytes from i
            parent_addr = data[i:i+2]
            i += 2
            # role is the next byte
            role = Role.get(utils.bytes_to_int(data[i:i+1]))
        return XBee16BitAddress(data[0:2]), XBee64BitAddress(data[2:10]), node_id.decode(), role


class ZigBeeNetwork(XBeeNetwork):
    """
    This class represents a ZigBee network.

    The network allows the discovery of remote devices in the same network
    as the local one and stores them.
    """

    def __init__(self, device):
        """
        Class constructor. Instantiates a new ``ZigBeeNetwork``.

        Args:
            device (:class:`.ZigBeeDevice`): the local ZigBee device to get the network from.

        Raises:
            ValueError: if ``device`` is ``None``.
        """
        super().__init__(device)


class Raw802Network(XBeeNetwork):
    """
    This class represents an 802.15.4 network.

    The network allows the discovery of remote devices in the same network
    as the local one and stores them.
    """

    def __init__(self, device):
        """
        Class constructor. Instantiates a new ``Raw802Network``.

        Args:
            device (:class:`.Raw802Device`): the local 802.15.4 device to get the network from.

        Raises:
            ValueError: if ``device`` is ``None``.
        """
        super().__init__(device)


class DigiMeshNetwork(XBeeNetwork):
    """
    This class represents a DigiMesh network.

    The network allows the discovery of remote devices in the same network
    as the local one and stores them.
    """

    def __init__(self, device):
        """
        Class constructor. Instantiates a new ``DigiMeshNetwork``.

        Args:
            device (:class:`.DigiMeshDevice`): the local DigiMesh device to get the network from.

        Raises:
            ValueError: if ``device`` is ``None``.
        """
        super().__init__(device)


class DigiPointNetwork(XBeeNetwork):
    """
    This class represents a DigiPoint network.

    The network allows the discovery of remote devices in the same network
    as the local one and stores them.
    """

    def __init__(self, device):
        """
        Class constructor. Instantiates a new ``DigiPointNetwork``.

        Args:
            device (:class:`.DigiPointDevice`): the local DigiPoint device to get the network from.

        Raises:
            ValueError: if ``device`` is ``None``.
        """
        super().__init__(device)


@unique
class NetworkEventType(Enum):
    """
    Enumerates the different network event types.
    """

    ADD = (0x00, "XBee added to the network")
    DEL = (0x01, "XBee removed from the network")
    UPDATE = (0x02, "XBee in the network updated")
    CLEAR = (0x03, "Network cleared")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    @property
    def code(self):
        """
        Returns the code of the ``NetworkEventType`` element.

        Returns:
            Integer: the code of the ``NetworkEventType`` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the ``NetworkEventType`` element.

        Returns:
            String: the description of the ``NetworkEventType`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the network event for the given code.

        Args:
            code (Integer): the code of the network event to get.

        Returns:
            :class:`.NetworkEventType`: the ``NetworkEventType`` with the given code, ``None`` if
                there is not any event with the provided code.
        """
        for ev_type in cls:
            if ev_type.code == code:
                return ev_type

        return None


NetworkEventType.__doc__ += utils.doc_enum(NetworkEventType)


@unique
class NetworkEventReason(Enum):
    """
    Enumerates the different network event reasons.
    """

    DISCOVERED = (0x00, "Discovered XBee")
    RECEIVED_MSG = (0x01, "Received message from XBee")
    MANUAL = (0x02, "Manual modification")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    @property
    def code(self):
        """
        Returns the code of the ``NetworkEventReason`` element.

        Returns:
            Integer: the code of the ``NetworkEventReason`` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the ``NetworkEventReason`` element.

        Returns:
            String: the description of the ``NetworkEventReason`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the network event reason for the given code.

        Args:
            code (Integer): the code of the network event reason to get.

        Returns:
            :class:`.NetworkEventReason`: the ``NetworkEventReason`` with the given code, ``None``
                if there is not any reason with the provided code.
        """
        for reason in cls:
            if reason.code == code:
                return reason

        return None

NetworkEventReason.__doc__ += utils.doc_enum(NetworkEventReason)
