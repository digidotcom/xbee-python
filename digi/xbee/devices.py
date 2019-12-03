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
from queue import Queue, Empty

from digi.xbee import serial
from digi.xbee.packets.cellular import TXSMSPacket
from digi.xbee.models.accesspoint import AccessPoint, WiFiEncryptionType
from digi.xbee.models.atcomm import ATCommandResponse, ATCommand, ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import OperatingMode, APIOutputMode, IPAddressingMode, NeighborDiscoveryMode, APIOutputModeBit
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
    DiscoveryProcessFinished, NetworkModified, RouteReceived, InitDiscoveryScan, EndDiscoveryScan
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

        self._scan_counter = 0
        self._reachable = True

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
        else:
            # For protocols that do not support a 16 bit address, set it to unknown
            self._16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

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
                try:
                    # Capture the possible exception because DigiMesh S2C does not have
                    # SS command, so the read will throw an ATCommandException
                    ss = self.get_parameter(ATStringCommand.SS.command)
                except ATCommandException:
                    ss = None

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

    def _get_routes(self, route_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the routes of this XBee. If ``route_callback`` is not defined, the process blocks
        until the complete routing table is read.

        Args:
            route_callback (Function, optional, default=``None``): method called when a new route
                is received. Receives two arguments:

                * The XBee that owns this new route.
                * The new route.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that executed the ZDO command.
                * A list with the discovered routes.
                * An error message if something went wrong.

            timeout (Float, optional, default=``RouteTableReader.DEFAULT_TIMEOUT``): The ZDO command
                timeout in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Route` when ``route_callback`` is defined,
                ``None`` otherwise (in this case routes are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Route`
        """
        from digi.xbee.models.zdo import RouteTableReader
        reader = RouteTableReader(self, configure_ao=True,
                                  timeout=timeout if timeout else RouteTableReader.DEFAULT_TIMEOUT)

        return reader.get_route_table(route_callback=route_callback,
                                      process_finished_callback=process_finished_callback)

    def _get_neighbors(self, neighbor_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the neighbors of this XBee. If ``neighbor_callback`` is not defined:
           * In Zigbee and SmartEnergy the process blocks until the complete neighbor table is read.
           * In DigiMesh the process blocks the provided timeout.

        Args:
            neighbor_callback (Function, optional, default=``None``): method called when a new
                neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that is searching for its neighbors.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=``None``): The timeout in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Neighbor` when ``neighbor_callback`` is
                defined, ``None`` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee, Smart Energy
                or DigiMesh.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        if self.get_protocol() in (XBeeProtocol.ZIGBEE, XBeeProtocol.SMART_ENERGY):
            from digi.xbee.models.zdo import NeighborTableReader
            reader = NeighborTableReader(
                self, configure_ao=True,
                timeout=timeout if timeout else NeighborTableReader.DEFAULT_TIMEOUT)

            return reader.get_neighbor_table(neighbor_callback=neighbor_callback,
                                             process_finished_callback=process_finished_callback)
        elif self.get_protocol() in (XBeeProtocol.DIGI_MESH, XBeeProtocol.XLR_DM,
                                     XBeeProtocol.XTEND_DM, XBeeProtocol.SX):
            from digi.xbee.models.zdo import NeighborFinder
            finder = NeighborFinder(
                self, timeout=timeout if timeout else NeighborFinder.DEFAULT_TIMEOUT)

            return finder.get_neighbors(neighbor_callback=neighbor_callback,
                                        process_finished_callback=process_finished_callback)
        else:
            raise OperationNotSupportedException("Get neighbors is not supported in %s"
                                                 % self.get_protocol().description)

    @property
    def reachable(self):
        """
        Returns whether the XBee is reachable.

        Returns:
            Boolean: ``True`` if the device is reachable, ``False`` otherwise.
        """
        return self._reachable

    @property
    def scan_counter(self):
        """
        Returns the scan counter for this node.

        Returns:
             Integer: The scan counter for this node.
        """
        return self._scan_counter

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

        self.__tmp_dm_routes_to = {}
        self.__tmp_dm_to_insert = []
        self.__tmp_dm_routes_lock = threading.Lock()
        self.__route_received = RouteReceived()

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
        socket_st_cbs = self._packet_listener.get_socket_state_received_callbacks() \
            if self._packet_listener else None
        socket_data_cbs = self._packet_listener.get_socket_data_received_callbacks() \
            if self._packet_listener else None
        socket_data_from_cbs = self._packet_listener.get_socket_data_received_from_callbacks() \
            if self._packet_listener else None
        route_record_cbs = self._packet_listener.get_route_record_received_callbacks() \
            if self._packet_listener else None
        route_info_cbs = self._packet_listener.get_route_info_callbacks() \
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
        self._packet_listener.add_socket_state_received_callback(socket_st_cbs)
        self._packet_listener.add_socket_data_received_callback(socket_data_cbs)
        self._packet_listener.add_socket_data_received_from_callback(socket_data_from_cbs)
        self._packet_listener.add_route_record_received_callback(route_record_cbs)
        self._packet_listener.add_route_info_received_callback(route_info_cbs)

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

    def add_route_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.RouteReceived`.
        This works for Zigbee and Digimesh devices.

        Args:
            callback (Function): the callback. Receives three arguments.

                * source (:class:`.XBeeDevice`): The source node.
                * destination (:class:`.RemoteXBeeDevice`): The destination node.
                * hops (List): List of intermediate hops from closest to source
                    to closest to destination (:class:`.RemoteXBeeDevice`).

        .. seealso::
           | :meth:`.XBeeDevice.del_route_received_callback`
        """
        if self._protocol not in [XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                                  XBeeProtocol.SMART_ENERGY,
                                  XBeeProtocol.DIGI_MESH,
                                  XBeeProtocol.DIGI_POINT, XBeeProtocol.SX]:
            raise ValueError("Cannot register callback for %s XBee devices" % self._protocol)

        self.__route_received += callback

        if (self._protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                              XBeeProtocol.SMART_ENERGY]
                and not self.__route_record_callback in self._packet_listener.get_route_record_received_callbacks()):
            self._packet_listener.add_route_record_received_callback(self.__route_record_callback)
        elif not self.__route_info_callback in self._packet_listener.get_route_info_callbacks():
            self._packet_listener.add_route_info_received_callback(self.__route_info_callback)

    def del_route_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.RouteReceived` event.

        Args:
            callback (Function): the callback to delete.

        .. seealso::
           | :meth:`.XBeeDevice.add_route_received_callback`
        """
        self.__route_received -= callback

        if (self._protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                              XBeeProtocol.SMART_ENERGY]
                and self.__route_record_callback in self._packet_listener.get_route_record_received_callbacks()):
            self._packet_listener.del_route_record_received_callback(self.__route_record_callback)
        elif self.__route_info_callback in self._packet_listener.get_route_info_callbacks():
            self._packet_listener.del_route_info_callback(self.__route_info_callback)

    def __route_record_callback(self, src, hops):
        """
        Callback method to receive route record indicator (0xA1) frames.

        Args:
            src (:class:`.RemoteXBeeDevice`): The remote device that sent the
                route record indicator frame.
            hops (List): List of 16-bit addresses (:class:`XBee16BitAddress`)
                of the intermediate hops starting from source node to closest
                to destination.
        """
        node_list = []
        network = self.get_network()

        self._log.debug("Source route for %s (hops %d): %s", src, len(hops),
                        " <<< ".join(map(str, hops)))
        for hop in hops:
            node = network.get_device_by_16(hop)
            # If the intermediate hop is not yet in the network, add it
            if not node:
                node = network._XBeeNetwork__add_remote(
                            RemoteZigBeeDevice(self, x16bit_addr=hop),
                            NetworkEventReason.ROUTE)

            if node not in node_list and hop != src.get_16bit_addr():
                node_list.append(node)

        # Reverse the route: closest to source node the first one
        node_list.reverse()

        self.__route_received(self, src, node_list)

    def __route_info_callback(self, _src_event, _timestamp, _ack_timeout_count,
                              _tx_block_count, dst_addr, src_addr,
                              responder_addr, successor_addr):
        """
        Callback method to receive route information (0x8D) frames.

        Args:
            _src_event (Integer): The source event (0x11: NACK, 0x12: Trace route)
            _timestamp (Integer): The system timer value on the node generating
                this package. The timestamp is in microseconds.
            _ack_timeout_count (Integer): Number of MAC ACK timeouts that occur.
            _tx_block_count (Integer): Number of times the transmissions was
                blocked due to reception in progress.
            dst_addr (:class:`.XBee64BitAddress`): 64-bit address of the final
                destination node.
            src_addr (:class:`.XBee64BitAddress`): 64-bit address of
                the source node.
            responder_addr (:class:`.XBee64BitAddress`): 64-bit address of the
                the node that generates this packet after it sends (or attempts
                to send) the packet to the next hop (successor node)
            successor_addr (:class:`.XBee64BitAddress`): 64-bit address of the
                next node after the responder in the route towards the destination.
        """
        self._log.debug("Trace route for %s: responder %s >>> successor %s",
                        dst_addr, responder_addr, successor_addr)

        def check_dm_route_complete(src, dst, hops_list):
            length = len(hops_list)

            if not length:
                return False

            if hops_list[0][0] != src:
                return False

            if hops_list[length - 1][1] != dst:
                return False

            for i in range(len(hops_list)):
                if length < i + 2:
                    break
                if hops_list[i][1] != hops_list[i + 1][0]:
                    return False

            return True

        with self.__tmp_dm_routes_lock:
            if str(dst_addr) not in self.__tmp_dm_routes_to:
                self.__tmp_dm_routes_to.update({str(dst_addr): []})

            dm_hops_list = self.__tmp_dm_routes_to.get(str(dst_addr))

            # There is no guarantee that Route Information Packet frames
            # arrive in the same order as the route taken by the unicast packet.
            hop = (responder_addr, successor_addr)

            if hop in dm_hops_list:
                return

            if responder_addr == src_addr:
                dm_hops_list.insert(0, hop)
            elif successor_addr == dst_addr or not dm_hops_list:
                dm_hops_list.append(hop)
            else:
                self.__tmp_dm_to_insert.insert(0, hop)

            aux_list = []
            for to_insert in self.__tmp_dm_to_insert:
                for element in dm_hops_list:
                    # Successor in the list is the received responder
                    if element[1] == to_insert[0]:
                        dm_hops_list.insert(dm_hops_list.index(element) + 1, to_insert)
                        break
                    # Responder in the list is the received successor
                    if element[0] == to_insert[1]:
                        dm_hops_list.insert(dm_hops_list.index(element), to_insert)
                        break
                    # Cannot order it, save it for later
                    aux_list.append(to_insert)

            self.__tmp_dm_to_insert = aux_list

            # Check if this is the latest packet of the Trace Route process
            if self.__tmp_dm_to_insert \
                    or not check_dm_route_complete(src_addr, dst_addr, dm_hops_list):
                return

            # Generate the list of ordered hops
            node_list = []
            network = self.get_network()
            for i in range(len(dm_hops_list)):
                address = dm_hops_list[i][0]
                node = network.get_device_by_64(address)
                if not node:
                    # If the intermediate hop is not yet in the network, add it
                    if not node:
                        node = network._XBeeNetwork__add_remote(
                            RemoteDigiMeshDevice(self, x64bit_addr=address),
                            NetworkEventReason.ROUTE)

                if node not in node_list and address != dst_addr:
                    node_list.append(node)

            dest_node = network.get_device_by_64(dst_addr)
            if not dest_node:
                # If the destination is not yet in the network, add it
                if not dest_node:
                    dest_node = network._XBeeNetwork__add_remote(
                            RemoteDigiMeshDevice(self, x64bit_addr=dst_addr),
                            NetworkEventReason.ROUTE)

            self.__tmp_dm_to_insert.clear()
            self.__tmp_dm_routes_to.clear()

        # Remove the source node (first one in list) from the hops
        self.__route_received(self, dest_node, node_list[1:])

    def get_route_to_node(self, remote, timeout=10):
        """
        Gets the route from this XBee to the given remote node.

        Args:
            remote (:class:`.RemoteXBeeDevice`): The remote node.
            timeout (Float, optional, default=10): Maximum number of seconds to
                wait for the route.

        Returns:
            Tuple: Tuple containing route data (`None` if the route was not
                read in the provided timeout):
                - source (:class:`.RemoteXBeeDevice`: The source node of the route.
                - destination (:class:`.RemoteXBeeDevice`): The destination node
                  of the route.
                - hops (List): List of intermediate nodes
                  (:class:`.RemoteXBeeDevice`) ordered from closest to source
                  to closest to destination node (source and destination not
                  included).
        """
        if not remote.is_remote():
            raise ValueError("Remote cannot be a local XBee")
        if self._64bit_addr == remote.get_64bit_addr():
            raise ValueError("Remote cannot be the local XBee")
        if self != remote.get_local_xbee_device():
            raise ValueError("Remote must have '%s' as local XBee" % self)
        if timeout is None or timeout <= 0:
            raise ValueError("Timeout must be greater than 0")

        self._log.debug("Getting route for node %s", remote)

        if self._protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                              XBeeProtocol.SMART_ENERGY, XBeeProtocol.DIGI_MESH,
                              XBeeProtocol.DIGI_POINT, XBeeProtocol.SX]:
            route = self.__get_trace_route(remote, timeout)
        else:
            route = self, remote, [self]

        if route:
            self._log.debug("Route: {{{!s}{!s}{!s} >>> {!s} (hops: {!s})}}".format(
                route[0], " >>> " if route[2] else "", " >>> ".join(map(str, route[2])),
                route[1], len(route[2]) + 1))

        return route

    def __get_trace_route(self, remote, timeout):
        """
        Gets the route from this XBee to the given remote node.

        Args:
            remote (:class:`.RemoteXBeeDevice`): The remote node.
            timeout (Float): Maximum number of seconds to wait for the route.

        Returns:
            Tuple: Tuple containing route data (`None` if the route was not
                read in the provided timeout):
                - source (:class:`.RemoteXBeeDevice`: The source node of the route.
                - destination (:class:`.RemoteXBeeDevice`): The destination node
                  of the route.
                - hops (List): List of intermediate nodes
                  (:class:`.RemoteXBeeDevice`) ordered from closest to source
                  to closest to destination node (source and destination not
                  included).
        """
        lock = threading.Event()
        node_list = []

        def route_cb(src, dest, hops):
            nonlocal node_list
            if dest == remote:
                node_list = [src, *hops]
                lock.set()

        if remote == self:
            return None

        if self._protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                              XBeeProtocol.SMART_ENERGY]:
            if remote.get_role() == Role.END_DEVICE:
                return None

            # Transmit a some information to the remote
            packet = TransmitPacket(
                0x00,                          # Frame ID
                remote.get_64bit_addr(),       # 64-bit address of the remote
                remote.get_16bit_addr(),       # 16-bit address of the remote
                0x00,                          # Broadcast radius (0x00 - Maximum)
                0x00,                          # Transmit options (0x00 - None)
                bytearray([0])                 # Dummy payload
            )

        elif self._protocol in [XBeeProtocol.DIGI_MESH,
                                XBeeProtocol.DIGI_POINT, XBeeProtocol.SX]:
            # Transmit a some information to the remote
            packet = TransmitPacket(
                0x00,                     # Frame ID
                remote.get_64bit_addr(),  # 64-bit address of the remote
                remote.get_16bit_addr(),  # 16-bit address of the remote
                0x00,                     # Broadcast radius (0x00 - Maximum)
                0x08,                     # Transmit options (0x08 - Generate trace route packets)
                bytearray([0])            # Dummy payload
            )

        else:
            return None

        lock.clear()

        self.add_route_received_callback(route_cb)

        try:
            self.send_packet(packet, sync=False)

            timed_out = lock.wait(timeout)
        finally:
            self.del_route_received_callback(route_cb)

        # Check if the list of intermediate nodes is empty
        if timed_out or not node_list:
            return None

        return self, remote, node_list[1:]

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

    def build_aggregate_routes(self):
        """
        Automatically build routes to this node. All nodes in the network will
        build routes to this node. The receiving node establishes a route back
        to this node.

        Raises:
            TimeoutException: If the response is not received before the read
                timeout expires.
            XBeeException: If the XBee device's serial port is closed.
            InvalidOperatingModeException: If the XBee device's operating mode
                is not API or ESCAPED API. This method only checks the cached
                value of the operating mode.
            ATCommandException: If the response is not as expected.
        """
        self.set_parameter(ATStringCommand.AG.command,
                           XBee16BitAddress.UNKNOWN_ADDRESS.address)

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

    def get_neighbors(self, neighbor_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the neighbors of this XBee. If ``neighbor_callback`` is not defined, the process
        blocks during the specified timeout.

        Args:
            neighbor_callback (Function, optional, default=``None``): method called when a new
                neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that is searching for its neighbors.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=``NeighborFinder.DEFAULT_TIMEOUT``): The timeout
                in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Neighbor` when ``neighbor_callback`` is
                defined, ``None`` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not DigiMesh.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborFinder
        return super()._get_neighbors(
            neighbor_callback=neighbor_callback,
            process_finished_callback=process_finished_callback,
            timeout=timeout if timeout else NeighborFinder.DEFAULT_TIMEOUT)


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

    def get_many_to_one_broadcasting_time(self):
        """
        Returns the time between aggregation route broadcast in seconds.

        Returns:
            Integer: The number of seconds between aggregation route broadcasts.
                -1 if it is disabled.

        Raises:
            TimeoutException: If the response is not received before the read
                timeout expires.
            XBeeException: If the XBee device's serial port is closed.
            InvalidOperatingModeException: If the XBee device's operating mode
                is not API or ESCAPED API. This method only checks the cached
                value of the operating mode.
            ATCommandException: If the response is not as expected.
        """
        seconds = utils.bytes_to_int(self.get_parameter(ATStringCommand.AR.command))
        # 0xFF disables aggregation route broadcasting
        if seconds == 0xFF:
            return -1

        return seconds

    def set_many_to_one_broadcasting_time(self, seconds):
        """
        Configures the time between aggregation route broadcast in seconds.

        Args:
            seconds (Integer): The number of seconds between aggregation route
                broadcasts. -1 to disable. 0 to only send one broadcast.

        Raises:
            TimeoutException: If the response is not received before the read
                timeout expires.
            XBeeException: If the XBee device's serial port is closed.
            InvalidOperatingModeException: If the XBee device's operating mode
                is not API or ESCAPED API. This method only checks the cached
                value of the operating mode.
            ATCommandException: If the response is not as expected.
            ValueError: If ``seconds`` is ``None`` or is lower than -1, or
                bigger than 254.
        """
        if seconds is None:
            raise ValueError("The number of seconds cannot be None")
        if seconds < -1 or seconds > 0xFE:
            raise ValueError("The number of seconds must be between -1 and 254")

        if seconds == -1:
            seconds = 0xFF

        self.set_parameter(ATStringCommand.AR.command, bytearray([seconds]))

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

    def get_routes(self, route_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the routes of this XBee. If ``route_callback`` is not defined, the process blocks
        until the complete routing table is read.

        Args:
            route_callback (Function, optional, default=``None``): method called when a new route
                is received. Receives two arguments:

                * The XBee that owns this new route.
                * The new route.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that executed the ZDO command.
                * A list with the discovered routes.
                * An error message if something went wrong.

            timeout (Float, optional, default=``RouteTableReader.DEFAULT_TIMEOUT``): The ZDO command
                timeout in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Route` when ``route_callback`` is defined,
                ``None`` otherwise (in this case routes are received in the callback).

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or
                ESCAPED API. This method only checks the cached value of the operating mode.
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.
            XBeeException: If the XBee device's serial port is closed.

        .. seealso::
           | :class:`com.digi.models.zdo.Route`
        """
        from digi.xbee.models.zdo import RouteTableReader
        return super()._get_routes(route_callback=route_callback,
                                   process_finished_callback=process_finished_callback,
                                   timeout=timeout if timeout else RouteTableReader.DEFAULT_TIMEOUT)

    def get_neighbors(self, neighbor_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the neighbors of this XBee. If ``neighbor_callback`` is not defined, the process
        blocks until the complete neighbor table is read.

        Args:
            neighbor_callback (Function, optional, default=``None``): method called when a new
                neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that executed the ZDO command.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=``NeighborTableReader.DEFAULT_TIMEOUT``): The ZDO
                command timeout in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Neighbor` when ``neighbor_callback`` is
                defined, ``None`` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborTableReader
        return super()._get_neighbors(
            neighbor_callback=neighbor_callback,
            process_finished_callback=process_finished_callback,
            timeout=timeout if timeout else NeighborTableReader.DEFAULT_TIMEOUT)


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

    def get_neighbors(self, neighbor_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the neighbors of this XBee. If ``neighbor_callback`` is not defined, the process
        blocks during the specified timeout.

        Args:
            neighbor_callback (Function, optional, default=``None``): method called when a new
                neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that is searching for its neighbors.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=``NeighborFinder.DEFAULT_TIMEOUT``): The timeout
                in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Neighbor` when ``neighbor_callback`` is
                defined, ``None`` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not DigiMesh.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborFinder
        return super()._get_neighbors(
            neighbor_callback=neighbor_callback,
            process_finished_callback=process_finished_callback,
            timeout=timeout if timeout else NeighborFinder.DEFAULT_TIMEOUT)


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

        # If the remote node is an end device, its parent is stored here.
        self.__parent = None

    @property
    def parent(self):
        """
        Returns the parent of the XBee if it is an end device.

        Returns:
             :class:`.AbstractXBeeDevice`: The parent of the node for end
                devices, ``None`` if unknown or if it is not an end device.
        """
        return self.__parent if self.get_role() == Role.END_DEVICE else None

    @parent.setter
    def parent(self, node):
        """
        Configures the XBee parent if it is an end device. If not it has no
        effect.

        Args:
             node (:class:`.AbstractXBeeDevice`): The parent of the node.
        """
        if self.get_role() == Role.END_DEVICE:
            self.__parent = node

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

    def get_routes(self, route_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the routes of this XBee. If ``route_callback`` is not defined, the process blocks
        until the complete routing table is read.

        Args:
            route_callback (Function, optional, default=``None``): method called when a new route
                is received. Receives two arguments:

                * The XBee that owns this new route.
                * The new route.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that executed the ZDO command.
                * A list with the discovered routes.
                * An error message if something went wrong.

            timeout (Float, optional, default=``RouteTableReader.DEFAULT_TIMEOUT``): The ZDO command
                timeout in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Route` when ``route_callback`` is defined,
                ``None`` otherwise (in this case routes are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Route`
        """
        from digi.xbee.models.zdo import RouteTableReader
        return super()._get_routes(route_callback=route_callback,
                                   process_finished_callback=process_finished_callback,
                                   timeout=timeout if timeout else RouteTableReader.DEFAULT_TIMEOUT)

    def get_neighbors(self, neighbor_callback=None, process_finished_callback=None, timeout=None):
        """
        Returns the neighbors of this XBee. If ``neighbor_callback`` is not defined, the process
        blocks until the complete neighbor table is read.

        Args:
            neighbor_callback (Function, optional, default=``None``): method called when a new
                neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            process_finished_callback (Function, optional, default=``None``): method to execute when
                the process finishes. Receives two arguments:

                * The XBee device that executed the ZDO command.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=``NeighborTableReader.DEFAULT_TIMEOUT``): The ZDO
                command timeout in seconds.
        Returns:
            List: List of :class:`com.digi.models.zdo.Neighbor` when ``neighbor_callback`` is
                defined, ``None`` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborTableReader
        return super()._get_neighbors(
            neighbor_callback=neighbor_callback,
            process_finished_callback=process_finished_callback,
            timeout=timeout if timeout else NeighborTableReader.DEFAULT_TIMEOUT)


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

    __TIME_FOR_NEW_NODES_IN_FIFO = 1  # seconds
    __TIME_WHILE_FINISH_PREVIOUS_PROCESS = 1  # seconds, for 'Cascade' mode

    __DEFAULT_QUEUE_MAX_SIZE = 300
    """
    Default max. size that the queue has.
    """

    __MAX_SCAN_COUNTER = 10000

    DEFAULT_TIME_BETWEEN_SCANS = 10  # seconds
    """
    Default time (in seconds) to wait before starting a new scan.
    """

    MIN_TIME_BETWEEN_SCANS = 0  # seconds
    """
    Low limit for the time (in seconds) to wait before starting a new scan.
    """

    MAX_TIME_BETWEEN_SCANS = 300  # seconds
    """
    High limit for the time (in seconds) to wait before starting a new scan.
    """

    DEFAULT_TIME_BETWEEN_REQUESTS = 5  # seconds
    """
    Default time (in seconds) to wait between node neighbors requests.
    """

    MIN_TIME_BETWEEN_REQUESTS = 0  # seconds
    """
    Low limit for the time (in seconds) to wait between node neighbors requests.
    """

    MAX_TIME_BETWEEN_REQUESTS = 300  # seconds
    """
    High limit for the time (in seconds) to wait between node neighbors requests.
    """

    SCAN_TIL_CANCEL = 0  # 0 for not stopping
    """
    The neighbor discovery process continues until is manually stopped.
    """

    __NT_LIMITS = {
        XBeeProtocol.RAW_802_15_4: (0x1 / 10, 0xFC / 10),  # 0.1, 25.2 seconds
        XBeeProtocol.ZIGBEE: (0x20 / 10, 0xFF / 10),  # 3.2, 25.5 seconds
        XBeeProtocol.DIGI_MESH: (0x20 / 10, 0x2EE0 / 10)  # 3.2, 5788.8 seconds
    }

    _log = logging.getLogger("XBeeNetwork")
    """
    Logger.
    """

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

        self._local_xbee = xbee_device
        self.__devices_list = []
        self.__last_search_dev_list = []
        self.__lock = threading.Lock()
        self.__discovering = False
        self._stop_event = threading.Event()
        self.__discover_result = None
        self.__network_modified = NetworkModified()
        self.__device_discovered = DeviceDiscovered()
        self.__device_discovery_finished = DiscoveryProcessFinished()
        self.__discovery_thread = None
        self.__sought_device_id = None
        self.__discovered_device = None

        # FIFO to store the nodes to ask for their neighbors
        self.__nodes_queue = Queue(self.__class__.__DEFAULT_QUEUE_MAX_SIZE)

        # List with the MAC address (string format) of the still active request processes
        self.__active_processes = []

        # Last date of a sent request. Used to wait certain time between requests:
        #     * In 'Flood' mode to satisfy the minimum time to wait between node requests
        #     * For 'Cascade', the time to wait is applied after finishing the previous request
        #       process
        self.__last_request_date = 0

        self.__scan_counter = 0

        self.__connections = []
        self.__conn_lock = threading.Lock()

        # Dictionary to store the route and node discovery processes per node, so they can be
        # stop when required.
        # The dictionary uses as key the 64-bit address string representation (to be thread-safe)
        self.__nd_processes = {}

        self.__mode = NeighborDiscoveryMode.CASCADE
        self.__stop_scan = 1
        self.__rm_not_discovered_in_last_scan = False
        self.__time_bw_scans = self.__class__.DEFAULT_TIME_BETWEEN_SCANS
        self.__time_bw_nodes = self.__class__.DEFAULT_TIME_BETWEEN_REQUESTS
        self._node_timeout = None

        self.__saved_nt = None

        self.__init_scan_cbs = InitDiscoveryScan()
        self.__end_scan_cbs = EndDiscoveryScan()

    def __increment_scan_counter(self):
        """
        Increments (by one) the scan counter.
        """
        self.__scan_counter += 1
        if self.__scan_counter > self.__class__.__MAX_SCAN_COUNTER:
            self.__scan_counter = 0

    @property
    def scan_counter(self):
        """
        Returns the scan counter.

        Returns:
             Integer: The scan counter.
        """
        return self.__scan_counter

    def start_discovery_process(self, deep=False, n_deep_scans=1):
        """
        Starts the discovery process. This method is not blocking.

        This process can discover node neighbors and connections, or only nodes:

           * Deep discovery: Network nodes and connections between them (including quality)
             are discovered.

             The discovery process will be running the number of scans configured in
             ``n_deep_scans``. A scan is considered the process of discovering the full network.
             If there are more than one number of scans configured, after finishing one another
             is started, until ``n_deep_scans`` is satisfied.

             See :meth:`~.XBeeNetwork.set_deep_discovery_options` to establish the way the
             network discovery process is performed.

           * No deep discovery: Only network nodes are discovered.

             The discovery process will be running until the configured timeout expires or, in
             case of 802.15.4, until the 'end' packet is read.

             It may be that, after the timeout expires, there are devices that continue sending
             discovery packets to this XBee device. In this case, these devices will not be
             added to the network.

        In 802.15.4, both (deep and no deep discovery) are the same and none discover the node
        connections or their quality. The difference is the possibility of running more than
        one scan using a deep discovery.

        Args:
            deep (Boolean, optional, default=``False``): ``True`` for a deep network scan,
                looking for neighbors and their connections, ``False`` otherwise.
            n_deep_scans (Integer, optional, default=1): Number of scans to perform before
                automatically stopping the discovery process.
                :const:`SCAN_TIL_CANCEL` means the process will not be automatically
                stopped. Only applicable if ``deep=True``.

        .. seealso::
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.get_deep_discovery_options`
           | :meth:`.XBeeNetwork.set_deep_discovery_options`
        """
        with self.__lock:
            if self.__discovering:
                return

        if deep:
            self.__stop_scan = n_deep_scans

        self.__discovery_thread = threading.Thread(target=self.__discover_devices_and_notify_callbacks,
                                                   kwargs={'discover_network': deep}, daemon=True)
        self.__discovery_thread.start()

    def stop_discovery_process(self):
        """
        Stops the discovery process if it is running.

        Note that DigiMesh/DigiPoint devices are blocked until the discovery
        time configured (NT parameter) has elapsed, so if you try to get/set
        any parameter during the discovery process you will receive a timeout
        exception.
        """
        self._stop_event.set()

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
        self._stop_event.clear()

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

    def add_init_discovery_scan_callback(self, callback):
        """
        Adds a callback for the event :class:`.InitDiscoveryScan`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * Number of scan to start (starting with 1).
                * Total number of scans.

        .. seealso::
           | :meth:`.XBeeNetwork.del_init_discovery_scan_callback`
        """
        self.__init_scan_cbs += callback

    def add_end_discovery_scan_callback(self, callback):
        """
        Adds a callback for the event :class:`.EndDiscoveryScan`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * Number of scan that has finished (starting with 1).
                * Total number of scans.

        .. seealso::
           | :meth:`.XBeeNetwork.del_end_discovery_scan_callback`
        """
        self.__end_scan_cbs += callback

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

    def del_init_discovery_scan_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.InitDiscoveryScan`.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.InitDiscoveryScan` event.

        .. seealso::
           | :meth:`.XBeeNetwork.add_init_discovery_scan_callback`
        """
        self.__init_scan_cbs -= callback

    def del_end_discovery_scan_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.EndDiscoveryScan`.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.EndDiscoveryScan` event.

        .. seealso::
           | :meth:`.XBeeNetwork.add_end_discovery_scan_callback`
        """
        self.__end_scan_cbs -= callback

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
            self.__devices_list.clear()

        with self.__conn_lock:
            self.__connections.clear()

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
        return self._local_xbee.get_parameter(ATStringCommand.NO.command)

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

        value = DiscoveryOptions.calculate_discovery_value(self._local_xbee.get_protocol(), options)
        self._local_xbee.set_parameter(ATStringCommand.NO.command, utils.int_to_bytes(value))

    def get_deep_discovery_options(self):
        """
        Returns the deep discovery process options.

        Returns:
            Tuple: (:class:`digi.xbee.models.mode.NeighborDiscoveryMode`, Boolean): Tuple containing:
                - mode (:class:`digi.xbee.models.mode.NeighborDiscoveryMode`): Neighbor discovery
                    mode, the way to perform the network discovery process.
                - remove_nodes (Boolean): ``True`` to remove nodes from the network if they were
                    not discovered in the last scan, ``False`` otherwise.

        .. seealso::
           | :class:`digi.xbee.models.mode.NeighborDiscoveryMode`
           | :meth:`.XBeeNetwork.set_deep_discovery_timeouts`
           | :meth:`.XBeeNetwork.start_discovery_process`
        """
        return self.__mode, self.__rm_not_discovered_in_last_scan

    def set_deep_discovery_options(self, deep_mode=NeighborDiscoveryMode.CASCADE,
                                   del_not_discovered_nodes_in_last_scan=False):
        """
        Configures the deep discovery options with the given values.
        These options are only applicable for "deep" discovery
        (see :meth:`~.XBeeNetwork.start_discovery_process`)

        Args:
            deep_mode (:class:`.NeighborDiscoveryMode`, optional, default=`NeighborDiscoveryMode.CASCADE`): Neighbor
                discovery mode, the way to perform the network discovery process.
            del_not_discovered_nodes_in_last_scan (Boolean, optional, default=``False``): ``True`` to
                remove nodes from the network if they were not discovered in the last scan,

        .. seealso::
           | :class:`digi.xbee.models.mode.NeighborDiscoveryMode`
           | :meth:`.XBeeNetwork.get_deep_discovery_timeouts`
           | :meth:`.XBeeNetwork.start_discovery_process`
        """
        if deep_mode is not None and not isinstance(deep_mode, NeighborDiscoveryMode):
            raise TypeError("Deep mode must be NeighborDiscoveryMode not {!r}".format(
                deep_mode.__class__.__name__))

        self.__mode = deep_mode if deep_mode is not None else NeighborDiscoveryMode.CASCADE

        self.__rm_not_discovered_in_last_scan = del_not_discovered_nodes_in_last_scan

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
        tout = self._local_xbee.get_parameter(ATStringCommand.NT.command)

        return utils.bytes_to_int(tout) / 10.0

    def set_discovery_timeout(self, discovery_timeout):
        """
        Sets the discovery network timeout.

        Args:
            discovery_timeout (Float): timeout in seconds.

        Raises:
            TimeoutException: if the response is not received before the read
                timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode
                is not API or ESCAPED API. This method only checks the cached
                value of the operating mode.
            ATCommandException: if the response is not as expected.
            ValueError: if ``discovery_timeout`` is not between the allowed
                minimum and maximum values.
        """
        min_nt, max_nt = self.__get_nt_limits()
        if discovery_timeout < min_nt or discovery_timeout > max_nt:
            raise ValueError("Value must be between %f and %f seconds"
                             % (min_nt, max_nt))

        discovery_timeout *= 10  # seconds to 100ms
        timeout = bytearray([int(discovery_timeout)])
        self._local_xbee.set_parameter(ATStringCommand.NT.command, timeout)

    def get_deep_discovery_timeouts(self):
        """
        Gets deep discovery network timeouts.
        These timeouts are only applicable for "deep" discovery
        (see :meth:`~.XBeeNetwork.start_discovery_process`)

        Returns:
            Tuple (Float, Float, Float): Tuple containing:
                - node_timeout (Float): Maximum duration in seconds of the discovery process per node.
                    This used to find a node neighbors. This timeout is highly dependent on the
                    nature of the network:

                    .. hlist::
                       :columns: 1

                       * It should be greater than the highest NT (Node Discovery Timeout) of your
                         network
                       * and include enough time to let the message propagate depending on the
                         sleep cycle of your devices.

                - time_bw_nodes (Float): Time to wait between node neighbors requests.
                    Use this setting not to saturate your network:

                    .. hlist::
                       :columns: 1

                       * For 'Cascade' the number of seconds to wait after completion of the
                         neighbor discovery process of the previous node.
                       * For 'Flood' the minimum time to wait between each node's neighbor
                         requests.

                - time_bw_scans (Float): Time to wait before starting a new network scan.

        .. seealso::
            | :meth:`.XBeeNetwork.set_deep_discovery_timeouts`
            | :meth:`.XBeeNetwork.start_discovery_process`
        """
        return self._node_timeout, self.__time_bw_nodes, self.__time_bw_scans

    def set_deep_discovery_timeouts(self, node_timeout=None, time_bw_requests=None, time_bw_scans=None):
        """
        Sets deep discovery network timeouts.
        These timeouts are only applicable for "deep" discovery
        (see :meth:`~.XBeeNetwork.start_discovery_process`)

        node_timeout (Float, optional, default=`None`):
            Maximum duration in seconds of the discovery process used to find neighbors of a node.
            If ``None`` already configured timeouts are used.

        time_bw_requests (Float, optional, default=`DEFAULT_TIME_BETWEEN_REQUESTS`): Time to wait
            between node neighbors requests.
            It must be between :const:`MIN_TIME_BETWEEN_REQUESTS` and
            :const:`MAX_TIME_BETWEEN_REQUESTS` seconds inclusive. Use this setting not to saturate
            your network:

                .. hlist::
                   :columns: 1

                   * For 'Cascade' the number of seconds to wait after completion of the
                     neighbor discovery process of the previous node.
                   * For 'Flood' the minimum time to wait between each node's neighbor requests.

        time_bw_scans (Float, optional, default=`DEFAULT_TIME_BETWEEN_SCANS`): Time to wait
            before starting a new network scan.
            It must be between :const:`MIN_TIME_BETWEEN_SCANS` and :const:`MAX_TIME_BETWEEN_SCANS`
            seconds inclusive.

        Raises:
            ValueError: if ``node_timeout``, ``time_bw_requests`` or ``time_bw_scans`` are not
                between their corresponding limits.

        .. seealso::
            | :meth:`.XBeeNetwork.get_deep_discovery_timeouts`
            | :meth:`.XBeeNetwork.start_discovery_process`
        """
        min_nt, max_nt = self.__get_nt_limits()

        if node_timeout and (node_timeout < min_nt or node_timeout > max_nt):
            raise ValueError("Node timeout must be between %f and %f seconds"
                             % (min_nt, max_nt))

        if time_bw_requests \
                and (time_bw_requests < self.__class__.MIN_TIME_BETWEEN_REQUESTS
                     or time_bw_requests > self.__class__.MAX_TIME_BETWEEN_REQUESTS):
            raise ValueError("Time between neighbor requests must be between %d and %d" %
                             (self.__class__.MIN_TIME_BETWEEN_REQUESTS,
                              self.__class__.MAX_TIME_BETWEEN_REQUESTS))

        if time_bw_scans \
                and (time_bw_scans < self.__class__.MIN_TIME_BETWEEN_SCANS
                     or time_bw_scans > self.__class__.MAX_TIME_BETWEEN_SCANS):
            raise ValueError("Time between scans must be between %d and %d" %
                             (self.__class__.MIN_TIME_BETWEEN_SCANS,
                              self.__class__.MAX_TIME_BETWEEN_SCANS))

        self._node_timeout = node_timeout
        self.__time_bw_nodes = time_bw_requests if time_bw_requests is not None \
            else self.__class__.DEFAULT_TIME_BETWEEN_REQUESTS
        self.__time_bw_scans = time_bw_scans if time_bw_scans is not None \
            else self.__class__.DEFAULT_TIME_BETWEEN_SCANS

    def __get_nt_limits(self):
        """
        Returns a tuple with the minimum and maximum values for the 'NT'
        value depending on the protocol.

        Returns:
             Tuple (Float, Float): Minimum value in seconds, maximum value in
                seconds.
        """
        protocol = self._local_xbee.get_protocol()
        if protocol in [XBeeProtocol.RAW_802_15_4, XBeeProtocol.ZIGBEE,
                        XBeeProtocol.DIGI_MESH]:
            return self.__class__.__NT_LIMITS[protocol]

        # Calculate the minimum of the min values and the maximum of max values
        min_nt = self.__class__.__NT_LIMITS[XBeeProtocol.RAW_802_15_4][0]
        max_nt = self.__class__.__NT_LIMITS[XBeeProtocol.RAW_802_15_4][1]
        for protocol in self.__class__.__NT_LIMITS:
            min_nt = min(min_nt, self.__class__.__NT_LIMITS[protocol][0])
            max_nt = max(max_nt, self.__class__.__NT_LIMITS[protocol][1])

        return min_nt, max_nt

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

        if self._local_xbee.get_64bit_addr() == x64bit_addr:
            return self._local_xbee

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
        if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_MESH:
            raise ValueError("DigiMesh protocol does not support 16-bit addressing")
        if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_POINT:
            raise ValueError("Point-to-Multipoint protocol does not support 16-bit addressing")
        if x16bit_addr is None:
            raise ValueError("16-bit address cannot be None")
        if x16bit_addr == XBee16BitAddress.UNKNOWN_ADDRESS:
            raise ValueError("16-bit address cannot be unknown")

        if self._local_xbee.get_16bit_addr() == x16bit_addr:
            return self._local_xbee

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

        if self._local_xbee.get_node_id() == node_id:
            return self._local_xbee

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
        if x64bit_addr == self._local_xbee.get_64bit_addr():
            return self._local_xbee

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
            remote_xbee (:class:`.RemoteXBeeDevice`): The remote XBee device to add to the network.
            reason (:class:`.NetworkEventReason`): The reason of the addition to the network.

        Returns:
            :class:`.AbstractXBeeDevice`: the provided XBee with the updated parameters. If the
                XBee was not in the list yet, this method returns it without changes.
        """
        found = None

        # Check if it is the local device
        if not remote_xbee.is_remote() or remote_xbee == remote_xbee.get_local_xbee_device():
            found = remote_xbee if not remote_xbee.is_remote() else remote_xbee.get_local_xbee_device()
        # Look for the remote in the network list
        else:
            x64 = remote_xbee.get_64bit_addr()
            if not x64 or x64 == XBee64BitAddress.UNKNOWN_ADDRESS:
                # Ask for the 64-bit address
                try:
                    sh = remote_xbee.get_parameter(ATStringCommand.SH.command)
                    sl = remote_xbee.get_parameter(ATStringCommand.SL.command)
                    remote_xbee._64bit_addr = XBee64BitAddress(sh + sl)
                except XBeeException as e:
                    self._log.debug("Error while trying to get 64-bit address of XBee (%s): %s"
                                    % (remote_xbee.get_16bit_addr(), str(e)))

                    # Look for the device by its 16-bit address.
                    x16 = remote_xbee.get_16bit_addr()
                    if x16 and x16 != XBee16BitAddress.UNKNOWN_ADDRESS \
                            and x16 != XBee16BitAddress.BROADCAST_ADDRESS:
                        found = self.get_device_by_16(x16)

            if not found:
                with self.__lock:
                    if remote_xbee in self.__devices_list:
                        found = self.__devices_list[self.__devices_list.index(remote_xbee)]

        if found:
            already_in_scan = False
            if reason in (NetworkEventReason.NEIGHBOR, NetworkEventReason.DISCOVERED):
                already_in_scan = found.scan_counter == self.__scan_counter
                if not already_in_scan:
                    found._scan_counter = self.__scan_counter

            if found.update_device_data_from(remote_xbee):
                self.__network_modified(NetworkEventType.UPDATE, reason, node=found)
                found._reachable = True

            return None if already_in_scan else found

        if reason in (NetworkEventReason.NEIGHBOR, NetworkEventReason.DISCOVERED):
            remote_xbee._scan_counter = self.__scan_counter

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

    def _remove_device(self, remote_xbee_device, reason, force=True):
        """
        Removes the provided remote XBee device from the network.

        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to be removed
                from the list.
            reason (:class:`.NetworkEventReason`): The reason of the removal from the network.
            force (Boolean, optional, default=``True``): ``True`` to force the deletion of the node,
                ``False`` otherwise.
        """
        if not remote_xbee_device:
            return

        with self.__lock:
            if remote_xbee_device not in self.__devices_list:
                return

            i = self.__devices_list.index(remote_xbee_device)
            found_node = self.__devices_list[i]
            if force:
                self.__devices_list.remove(found_node)
                if found_node.reachable:
                    self.__network_modified(NetworkEventType.DEL, reason, node=remote_xbee_device)

        node_b_connections = self.__get_connections_for_node_a_b(found_node, node_a=False)

        # Remove connections with this node as one of its ends
        self.__remove_node_connections(found_node, only_as_node_a=True, force=force)

        if not force:
            # Only for Zigbee, mark non-reachable end devices
            if remote_xbee_device.get_protocol() \
                    in (XBeeProtocol.ZIGBEE, XBeeProtocol.SMART_ENERGY) \
                    and remote_xbee_device.get_role() == Role.END_DEVICE:
                for c in node_b_connections:
                    # End devices do not have connections from them (not asking for their route
                    # and neighbor tables), but if their parent is not reachable they are not either
                    if not c.node_a.reachable:
                        self._set_node_reachable(remote_xbee_device, False)
                        break

    def remove_device(self, remote_xbee_device):
        """
        Removes the provided remote XBee device from the network.

        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to be removed
                from the list.

        Raises:
            ValueError: if the provided :class:`.RemoteXBeeDevice` is not in the network.
        """
        self._remove_device(remote_xbee_device, NetworkEventReason.MANUAL, force=True)

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
                self.__discover_result = xbee_packet.status
                self._stop_event.set()
            elif nd_id == XBeeNetwork.ND_PACKET_REMOTE:
                x16, x64, n_id, role, x64_parent = \
                    self.__get_data_for_remote(xbee_packet.command_value)
                remote = self.__create_remote(x64bit_addr=x64, x16bit_addr=x16,
                                              node_id=n_id, role=role,
                                              parent_addr=x64_parent)
                if remote is not None:
                    # If remote was successfully created and it is not in the XBee list, add it
                    # and notify callbacks.

                    # Do not add a connection to the same node (the local one)
                    if remote == self._local_xbee:
                        return

                    self._log.debug("     o Discovered neighbor of %s: %s"
                                    % (self._local_xbee, remote))

                    node = self.__add_remote(remote, NetworkEventReason.DISCOVERED)
                    if not node:
                        # Node already in network for this scan
                        node = self.get_device_by_64(remote.get_64bit_addr())
                        self._log.debug(
                            "       - NODE already in network in this scan (scan: %d) %s"
                            % (self.__scan_counter, node))
                    else:
                        # Do not add the neighbors to the FIFO, because
                        # only the local device performs an 'ND'
                        self._log.debug("       - Added to network (scan: %d)" % node.scan_counter)

                    # Add connection (there is not RSSI info for a 'ND')
                    from digi.xbee.models.zdo import RouteStatus
                    if self.__add_connection(Connection(
                            self._local_xbee, node, LinkQuality.UNKNOWN, LinkQuality.UNKNOWN,
                            RouteStatus.ACTIVE, RouteStatus.ACTIVE)):
                        self._log.debug("       - Added connection: %s >>> %s"
                                        % (self._local_xbee, node))
                    else:
                        self._log.debug(
                            "       - CONNECTION already in network in this scan (scan: %d) %s >>> %s"
                            % (self.__scan_counter, self._local_xbee, node))

                    # Always add the XBee device to the last discovered devices list:
                    self.__last_search_dev_list.append(node)
                    self.__device_discovered(node)

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
                self.__discover_result = xbee_packet.status
                if xbee_packet.status == ATCommandStatus.OK:
                    with self.__lock:
                        self.__sought_device_id = None
                self.stop_discovery_process()
            elif nd_id == XBeeNetwork.ND_PACKET_REMOTE:
                # if it is not a finish signal, it contains info about a remote XBee device.
                x16, x64, n_id, role, x64_parent = \
                    self.__get_data_for_remote(xbee_packet.command_value)
                remote = self.__create_remote(x64bit_addr=x64, x16bit_addr=x16,
                                              node_id=n_id, role=role,
                                              parent_addr= x64_parent)
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

    def __discover_devices_and_notify_callbacks(self, discover_network=False):
        """
        Blocking method. Performs a discovery operation, waits
        until it finish (timeout or 'end' packet for 802.15.4),
        and notifies callbacks.

        Args:
            discover_network (Boolean, optional, default=``False``): ``True`` to discovery the
                full network with connections between nodes, ``False`` to only discover nodes
                with a single 'ND'.
        """
        self._stop_event.clear()
        self.__discovering = True
        self.__discover_result = None

        if not discover_network:
            status = self.__discover_devices()
            self._discovery_done(self.__active_processes)
        else:
            status = self._discover_full_network()

        self.__device_discovery_finished(status if status else NetworkDiscoveryStatus.SUCCESS)

    def _discover_full_network(self):
        """
        Discovers the network of the local node.

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of
                the discovery process.
        """
        try:
            code = self.__init_discovery(self.__nodes_queue)
            if code != NetworkDiscoveryStatus.SUCCESS:
                return code

            while self.__stop_scan == self.__class__.SCAN_TIL_CANCEL \
                    or self.__scan_counter < self.__stop_scan:

                if self.__scan_counter > 0:
                    self._log.debug("")
                    self._log.debug(" [*] Waiting %f seconds to start next scan"
                                    % self.__time_bw_scans)
                    code = self.__wait_checking(self.__time_bw_scans)
                    if code != NetworkDiscoveryStatus.SUCCESS:
                        return code

                self.__init_scan()

                # Check for cancel
                if self._stop_event.is_set():
                    return NetworkDiscoveryStatus.CANCEL

                code = self.__discover_network(self.__nodes_queue, self.__active_processes,
                                               self._node_timeout)
                if code != NetworkDiscoveryStatus.SUCCESS:
                    return code

                # Purge network
                self.__purge(force=self.__rm_not_discovered_in_last_scan)

                # Notify end scan
                self.__end_scan_cbs(self.__scan_counter, self.__stop_scan)

            return code
        finally:
            self._discovery_done(self.__active_processes)

    def __init_discovery(self, nodes_queue):
        """
        Initializes the discovery process before starting any network scan:
            * Initializes the scan counter
            * Removes all the nodes from the FIFO
            * Prepares the local XBee to start the process

        Args:
             nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of
                the discovery process.
        """
        # Initialize the scan number
        self.__scan_counter = 0

        # Initialize all nodes/connections scan counter
        with self.__lock:
            for xb in self.__devices_list:
                xb._scan_counter = self.__scan_counter

        with self.__conn_lock:
            for c in self.__connections:
                c.scan_counter_a2b = self.__scan_counter
                c.scan_counter_b2a = self.__scan_counter

        # Clear the nodes FIFO
        while not nodes_queue.empty():
            try:
                nodes_queue.get(block=False)
            except Empty:
                continue
            nodes_queue.task_done()

        self.__purge(force=self.__rm_not_discovered_in_last_scan)

        try:
            self._prepare_network_discovery()
        except XBeeException as e:
            self._log.debug(str(e))
            return NetworkDiscoveryStatus.ERROR_GENERAL

        return NetworkDiscoveryStatus.SUCCESS

    def _prepare_network_discovery(self):
        """
        Performs XBee configuration before starting the full network discovery. This saves the
        current NT value and sets it to the ``self._node_timeout``.
        """
        self._log.debug("[*] Preconfiguring %s" % ATStringCommand.NT.command)

        try:

            self.__saved_nt = self.get_discovery_timeout()

            if self._node_timeout is None:
                self._node_timeout = self.__saved_nt

            # Do not configure NT if it is already
            if self.__saved_nt == self._node_timeout:
                self.__saved_nt = None
                return

            self.set_discovery_timeout(self._node_timeout)
        except XBeeException as e:
            raise XBeeException("Could not prepare XBee for network discovery: " + str(e))

    def __init_scan(self):
        """
        Prepares a network to start a new scan.
        """
        self.__increment_scan_counter()
        self._local_xbee._scan_counter = self.__scan_counter

        self.__last_request_date = 0

        # Notify start scan
        self.__init_scan_cbs(self.__scan_counter, self.__stop_scan)

        self._log.debug("\n")
        self._log.debug("================================")
        self._log.debug("  %d network scan" % self.__scan_counter)
        self._log.debug("       Mode: %s (%d)" % (self.__mode.description, self.__mode.code))
        self._log.debug("       Stop after scan: %d" % self.__stop_scan)
        self._log.debug("       Timeout/node: %s" % self._node_timeout
                        if self._node_timeout is not None else "-")
        self._log.debug("================================")

    def __discover_network(self, nodes_queue, active_processes, node_timeout):
        """
        Discovers the network of the local node.

        Args:
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
            active_processes (List): The list of active discovery processes.
            node_timeout (Float): Timeout to discover neighbors for each node (seconds).

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of
                the discovery process.
        """
        code = NetworkDiscoveryStatus.SUCCESS

        # Add local node to the FIFO
        nodes_queue.put(self._local_xbee)

        while True:
            # Wait to have items in the nodes FIFO while some nodes are being discovered,
            # because them can fill the FIFO with new nodes to ask
            while nodes_queue.empty() and active_processes:
                self._log.debug("")
                self._log.debug(
                    " [*] Waiting for more nodes to request or finishing active processes (%d)\n"
                    % (len(active_processes)))
                [self._log.debug("     Waiting for %s" % p) for p in active_processes]

                code = self.__wait_checking(self.__class__.__TIME_FOR_NEW_NODES_IN_FIFO)
                if code == NetworkDiscoveryStatus.CANCEL:
                    return code

            # Check if there are more nodes in the FIFO
            while not nodes_queue.empty():
                # Process the next node
                code = self.__discover_next_node_neighbors(nodes_queue, active_processes,
                                                           node_timeout)
                # Only stop if the process has been cancelled, otherwise continue with the
                # next node
                if code == NetworkDiscoveryStatus.CANCEL:
                    return code

                # For cascade, wait until previous processes finish
                if self.__mode == NeighborDiscoveryMode.CASCADE:
                    while active_processes:
                        code = self.__wait_checking(
                            self.__class__.__TIME_WHILE_FINISH_PREVIOUS_PROCESS)
                        if code == NetworkDiscoveryStatus.CANCEL:
                            return code

            # Check if all processes finish
            if not active_processes:
                self._check_not_discovered_nodes(self.__devices_list, nodes_queue)
                if not nodes_queue.empty():
                    continue
                break

        return code

    def __discover_next_node_neighbors(self, nodes_queue, active_processes, node_timeout):
        """
        Discovers the neighbors of the next node in the given FIFO.

        Args:
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
            active_processes (List): The list of active discovery processes.
            node_timeout (Float): Timeout to discover neighbors for each node (seconds).

        Returns:
             :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of the
                neighbor discovery process.
        """
        code = NetworkDiscoveryStatus.SUCCESS

        # Check for cancel
        if self._stop_event.is_set():
            return NetworkDiscoveryStatus.CANCEL

        requester = nodes_queue.get()

        # Wait between nodes but not for the local one
        if requester != self._local_xbee:
            time_to_wait = self.__time_bw_nodes
            if self.__mode != NeighborDiscoveryMode.CASCADE:
                time_to_wait = self.__time_bw_nodes + (time.time() - self.__last_request_date)
            self._log.debug("")
            self._log.debug(" [*] Waiting %f before sending next request to %s"
                            % (time_to_wait if time_to_wait > 0 else 0.0, requester))
            code = self.__wait_checking(time_to_wait)
            if code != NetworkDiscoveryStatus.SUCCESS:
                return code

        # If the previous request finished, discover node neighbors
        if not requester.get_64bit_addr() in active_processes:
            self._log.debug("")
            self._log.debug(" [*] Discovering neighbors of %s" % requester)
            self.__last_request_date = time.time()
            return self._discover_neighbors(requester, nodes_queue, active_processes, node_timeout)

        self._log.debug("")
        self._log.debug(" [*] Previous request for %s did not finish..." % requester)
        nodes_queue.put(requester)

        return code

    def _check_not_discovered_nodes(self, devices_list, nodes_queue):
        """
        Checks not discovered nodes in the current scan, and add them to the FIFO if necessary.

        Args:
            devices_list (List): List of nodes to check.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
        """
        # Check for nodes in the network not discovered in this scan and ensure
        # they are reachable by directly asking them for its NI
        for n in devices_list:
            if n.scan_counter != self.__scan_counter:
                self._log.debug(" [*] Checking not discovered node %s... (scan %d)"
                                % (n, self.__scan_counter))
                n._scan_counter = self.__scan_counter
                try:
                    n.get_parameter(ATStringCommand.NI.command)
                    n._reachable = True
                    # Update also the connection
                    from digi.xbee.models.zdo import RouteStatus
                    if self.__add_connection(Connection(
                            self._local_xbee, n, LinkQuality.UNKNOWN, LinkQuality.UNKNOWN,
                            RouteStatus.ACTIVE, RouteStatus.ACTIVE)):
                        self._log.debug("     - Added connection: %s >>> %s"
                                        % (self._local_xbee, n))
                except XBeeException:
                    n._reachable = False
                self._log.debug("     - Reachable: %s (scan %d)"
                                % (n._reachable, self.__scan_counter))

    def _discover_neighbors(self, requester, nodes_queue, active_processes, node_timeout):
        """
        Starts the process to discover the neighbors of the given node.

        Args:
            requester(:class:`.AbstractXBeeDevice`): The XBee to discover its neighbors.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
            active_processes (List): The list of active discovery processes.
            node_timeout (Float): Timeout to discover neighbors (seconds).

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of
                the neighbor discovery process.
        """
        code = self.__discover_devices()
        if not code:
            return NetworkDiscoveryStatus.SUCCESS

        # Do not stop scans unless the process is cancel, not because of an error.
        if code is NetworkDiscoveryStatus.ERROR_NET_DISCOVER:
            self._stop_event.clear()
            return NetworkDiscoveryStatus.SUCCESS

        return code

    def __discover_devices(self, node_id=None):
        """
        Blocking method. Performs a device discovery in the network and waits until it finish
        (timeout or 'end' packet for 802.15.4)

        Args:
            node_id (String, optional): node identifier of the remote XBee device to discover.

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: The error code, ``None``
                if finished successfully.
        """
        self.__active_processes.append(str(self._local_xbee.get_64bit_addr()))

        try:
            timeout = self.__calculate_timeout()
            # send "ND" async
            self._local_xbee.send_packet(ATCommPacket(self._local_xbee.get_next_frame_id(),
                                                      ATStringCommand.ND.command,
                                                      parameter=None if node_id is None else bytearray(node_id, 'utf8')),
                                         sync=False)

            self.__nd_processes.update({str(self._local_xbee.get_64bit_addr()): self})

            op_times_out = not self._stop_event.wait(timeout)

            self.__nd_processes.pop(str(self._local_xbee), None)

            if op_times_out or not self.__discover_result or self.__discover_result == ATCommandStatus.OK:
                err_code = None
            elif self.__discover_result and self.__discover_result != ATCommandStatus.OK:
                err_code = NetworkDiscoveryStatus.ERROR_NET_DISCOVER
            else:
                err_code = NetworkDiscoveryStatus.CANCEL

            self._node_discovery_process_finished(self._local_xbee, code=err_code,
                                                  error=err_code.description if err_code else None)

            return err_code
        except Exception as e:
            self._local_xbee.log.exception(e)

    def _node_discovery_process_finished(self, requester, code=None, error=None):
        """
        Notifies the discovery process has finished successfully for ``requester`` node.

        Args:
            requester (:class:`.AbstractXBeeDevice`): The XBee that requests the discovery process.
            code (:class:`digi.xbee.models.status.NetworkDiscoveryStatus`): The error code for the process.
            error (String): The error message if there was one, ``None`` if successfully finished.
        """
        # Purge the connections of the node
        self._log.debug("")
        self._log.debug(" [*] Purging node connections of %s" % requester)
        purged = self.__purge_node_connections(requester, force=self.__rm_not_discovered_in_last_scan)
        if self.__rm_not_discovered_in_last_scan:
            for c in purged:
                self._log.debug("     o Removed connection: %s" % c)

        # Remove the discovery process from the active processes list
        self.__active_processes.remove(str(requester.get_64bit_addr()))

        if code and code not in (NetworkDiscoveryStatus.SUCCESS, NetworkDiscoveryStatus.CANCEL) or error:
            self._log.debug("[***** ERROR] During neighbors scan of %s" % requester)
            if error:
                self._log.debug("        %s" % error)
            else:
                self._log.debug("        %s" % code.description)

            self._handle_special_errors(requester, error)
        else:
            self._log.debug("[!!!] Process finishes for %s  - Remaining: %d"
                            % (requester, len(self.__active_processes)))

    def _handle_special_errors(self, requester, error):
        """
        Process some special errors.

        Args:
            requester (:class:`.AbstractXBeeDevice`): The XBee that requests the discovery process.
            error (String): The error message.
        """
        if not error.endswith(TransmitStatus.NOT_JOINED_NETWORK.description) \
                and not error.endswith(TransmitStatus.ADDRESS_NOT_FOUND.description) \
                and not error.endswith("FN command answer not received"):
            return

        # The node is not found so it is not reachable
        self._log.debug("     o [***] Non-reachable: %s -> ERROR %s" % (requester, error))

        # Do not remove any node here, although the preference is configured to so
        # Do it at the end of the scan...
        no_reachables = [requester]

        requester._scan_counter = self.__scan_counter

        # Get the children nodes to mark them as non-reachable
        conn_list = self.__get_connections_for_node_a_b(requester, node_a=True)
        for c in conn_list:
            child = c.node_b
            # Child node already discovered in this scan
            if not child or child.scan_counter == self.__scan_counter:
                continue
            # Only the connection with the requester node joins the child to the network
            # so it is not reachable
            if len(self.get_node_connections(child)) <= 1:
                no_reachables.append(child)

            # If the node has more than one connection, we cannot be sure if it will
            # be discovered by other devices later since the scan did not end

        # Mark as non-reachable
        [self._set_node_reachable(n, False) for n in no_reachables]

    def _discovery_done(self, active_processes):
        """
        Discovery process has finished either due to cancellation, successful completion, or failure.

        Args:
            active_processes (List): The list of active discovery processes.
        """
        self._restore_network()

        if self.__nd_processes:
            copy = active_processes[:]
            for p in copy:
                nd = self.__nd_processes.get(p)
                if not nd:
                    continue
                nd.stop_discovery_process()
                while p in self.__nd_processes:
                    time.sleep(0.1)

        self.__nd_processes.clear()
        self.__active_processes.clear()

        with self.__lock:
            self.__discovering = False

    def _restore_network(self):
        """
        Performs XBee configuration after the full network discovery.
        This restores the previous NT value.
        """
        if self.__saved_nt is None:
            return

        self._log.debug("[*] Postconfiguring %s" % ATStringCommand.NT.command)
        try:
            self.set_discovery_timeout(self.__saved_nt)
        except XBeeException as e:
            self._error = "Could not restore XBee after network discovery: " + str(e)

        self.__saved_nt = None

    def __is_802_compatible(self):
        """
        Checks if the device performing the node discovery is a legacy 
        802.15.4 device or a S1B device working in compatibility mode.
        
        Returns:
            Boolean: ``True`` if the device performing the node discovery is a legacy
                802.15.4 device or S1B in compatibility mode, ``False`` otherwise.
        
        """
        if self._local_xbee.get_protocol() != XBeeProtocol.RAW_802_15_4:
            return False
        param = None
        try:
            param = self._local_xbee.get_parameter(ATStringCommand.C8.command)
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
            discovery_timeout = utils.bytes_to_int(self._local_xbee.get_parameter(ATStringCommand.N_QUESTION.command)) / 1000
        except XBeeException:
            discovery_timeout = None

        # If N? does not exist, read the NT parameter.
        if discovery_timeout is None:
            # Read the XBee device timeout (NT).
            try:
                discovery_timeout = utils.bytes_to_int(self._local_xbee.get_parameter(ATStringCommand.NT.command)) / 10
            except XBeeException as xe:
                discovery_timeout = XBeeNetwork.__DEFAULT_DISCOVERY_TIMEOUT
                self._local_xbee.log.exception(xe)
                self.__device_discovery_finished(NetworkDiscoveryStatus.ERROR_READ_TIMEOUT)

            # In DigiMesh/DigiPoint the network discovery timeout is NT + the
            # network propagation time. It means that if the user sends an AT
            # command just after NT ms, s/he will receive a timeout exception.
            if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_MESH:
                discovery_timeout += XBeeNetwork.__DIGI_MESH_TIMEOUT_CORRECTION
            elif self._local_xbee.get_protocol() == XBeeProtocol.DIGI_POINT:
                discovery_timeout += XBeeNetwork.__DIGI_POINT_TIMEOUT_CORRECTION

        if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_MESH:
            # If the module is 'Sleep support', wait another discovery cycle.
            try:
                if utils.bytes_to_int(self._local_xbee.get_parameter(
                        ATStringCommand.SM.command)) == 7:
                    discovery_timeout += discovery_timeout + \
                                        (discovery_timeout * XBeeNetwork.__DIGI_MESH_SLEEP_TIMEOUT_CORRECTION)
            except XBeeException as xe:
                self._local_xbee.log.exception(xe)
        elif self.__is_802_compatible():
            discovery_timeout += 2  # Give some time to receive the ND finish packet

        return discovery_timeout

    def __create_remote(self, x64bit_addr=XBee64BitAddress.UNKNOWN_ADDRESS,
                        x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=None,
                        role=Role.UNKNOWN, parent_addr=None):
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
            parent_addr (:class:`.XBee64BitAddress`, optional, default=``None``):
                The 64-bit address of the parent.

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

        p = self._local_xbee.get_protocol()

        if p == XBeeProtocol.ZIGBEE:
            xb = RemoteZigBeeDevice(self._local_xbee, x64bit_addr=x64bit_addr,
                                    x16bit_addr=x16bit_addr, node_id=node_id)
            if not parent_addr or parent_addr in [XBee64BitAddress.BROADCAST_ADDRESS,
                                                  XBee64BitAddress.UNKNOWN_ADDRESS]:
                xb.parent = None
            else:
                xb.parent = self.get_device_by_64(parent_addr)
        elif p == XBeeProtocol.DIGI_MESH:
            xb = RemoteDigiMeshDevice(self._local_xbee, x64bit_addr=x64bit_addr, node_id=node_id)
        elif p == XBeeProtocol.DIGI_POINT:
            xb = RemoteDigiPointDevice(self._local_xbee, x64bit_addr=x64bit_addr, node_id=node_id)
        elif p == XBeeProtocol.RAW_802_15_4:
            xb = RemoteRaw802Device(self._local_xbee, x64bit_addr=x64bit_addr,
                                    x16bit_addr=x16bit_addr, node_id=node_id)
        else:
            xb = RemoteXBeeDevice(self._local_xbee, x64bit_addr=x64bit_addr,
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
            Tuple (:class:`.XBee16BitAddress`, :class:`.XBee64BitAddress`,
                String, :class:.`Role`, :class:`.XBee64BitAddress`):
                Remote device information (16-bit address, 64-bit address,
                node identifier, role, 64-bit address of parent).
        """
        role = Role.UNKNOWN
        parent_addr = None
        if self._local_xbee.get_protocol() == XBeeProtocol.RAW_802_15_4:
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
        return XBee16BitAddress(data[0:2]), XBee64BitAddress(data[2:10]),\
               node_id.decode(), role, parent_addr

    def _set_node_reachable(self, node, reachable):
        """
        Configures a node as reachable or non-reachable. It throws an network event if this
        attribute changes.
        If the value of the attribute was already ``reachable`` value, this method does nothing.

        Args:
            node (:class:`.AbstractXBeeDevice`): The node to configure.
            reachable (Boolean): ``True`` to configure as reachable, ``False`` otherwise.
        """
        if node._reachable != reachable:
            node._reachable = reachable
            self.__network_modified(NetworkEventType.UPDATE, NetworkEventReason.NEIGHBOR, node=node)

    def get_connections(self):
        """
        Returns a copy of the XBee connections.

        If a new connection is added to the list after the execution of this method,
        this connection is not added to the list returned by this method.

        Returns:
            List: A copy of the list of :class:`.Connection` for the network.
        """
        with self.__conn_lock:
            return self.__connections.copy()

    def get_node_connections(self, node):
        """
        Returns the network connections with one of their ends ``node``.

        If a new connection is added to the list after the execution of this method,
        this connection is not added to the list returned by this method.

        Returns:
            List: List of :class:`.Connection` with ``node`` end.
        """
        connections = []
        with self.__conn_lock:
            for c in self.__connections:
                if c.node_a == node or c.node_b == node:
                    connections.append(c)

        return connections

    def __get_connections_for_node_a_b(self, node, node_a=True):
        """
        Returns the network connections with the given node as "node_a" or "node_b".

        Args:
            node (:class:`.AbstractXBeeDevice`): The node to get the connections.
            node_a (Boolean, optional, default=``True``): ``True`` to get connections where
                the given node is "node_a", ``False`` to get those where the node is "node_b".

        Returns:
            List: List of :class:`.Connection` with ``node`` as "node_a" end.
        """
        connections = []
        with self.__conn_lock:
            for c in self.__connections:
                if (node_a and c.node_a == node) \
                        or (not node_a and c.node_b == node):
                    connections.append(c)

        return connections

    def __get_connection(self, node_a, node_b):
        """
        Returns the connection with ends node_a and node_b.

        Args:
            node_a (:class:`.AbstractXBeeDevice`): "node_a" end of the connection.
            node_b (:class:`.AbstractXBeeDevice`): "node_b" end of the connection.

        Returns:
            :class:`.Connection`: The connection with ends ``node_a`` and ``node_b``,
                ``None`` if not found.

        Raises:
            ValueError: If ``node_a`` or ``node_b`` are ``None``
        """
        if not node_a:
            raise ValueError("Node A cannot be None")
        if not node_b:
            raise ValueError("Node B cannot be None")

        c = Connection(node_a, node_b)

        with self.__conn_lock:
            if c not in self.__connections:
                return None

            index = self.__connections.index(c)

            return self.__connections[index]

    def __append_connection(self, connection):
        """
        Adds a new connection to the network.

        Args:
            connection (:class:`.Connection`): The connection to be added.

        Raise:
            ValueError: If ``connection`` is ``None``.
        """
        if not connection:
            raise ValueError("Connection cannot be None")

        with self.__conn_lock:
            self.__connections.append(connection)

    def __del_connection(self, connection):
        """
        Removes a connection from the network.

        Args:
            connection (:class:`.Connection`): The connection to be removed.

        Raise:
            ValueError: If ``connection`` is ``None``.
        """
        if not connection:
            raise ValueError("Connection cannot be None")

        with self.__conn_lock:
            if connection in self.__connections:
                self.__connections.remove(connection)

    def __add_connection(self, connection):
        """
        Adds a new connection to the network. The end nodes of this connection are added
        to the network if they do not exist.

        Args:
            connection (class:`.Connection`): The connection to add.

        Returns:
            Boolean: ``True`` if the connection was successfully added, ``False``
                if the connection was already added.
        """
        if not connection:
            return False

        node_a = self.get_device_by_64(connection.node_a.get_64bit_addr())
        node_b = self.get_device_by_64(connection.node_b.get_64bit_addr())

        # Add the source node
        if not node_a:
            node_a = self.__add_remote(connection.node_a, NetworkEventReason.NEIGHBOR)

        if not node_b:
            node_b = self.__add_remote(connection.node_b, NetworkEventReason.NEIGHBOR)

        if not node_a or not node_b:
            return False

        # Check if the connection already exists a -> b or b -> a
        c_ab = self.__get_connection(node_a, node_b)
        c_ba = self.__get_connection(node_b, node_a)

        # If none of them exist, add it
        if not c_ab and not c_ba:
            connection.scan_counter_a2b = self.__scan_counter
            self.__append_connection(connection)
            return True

        # If the connection exists, update its data
        if c_ab:
            if c_ab.scan_counter_a2b != self.__scan_counter:
                c_ab.lq_a2b = connection.lq_a2b
                c_ab.status_a2b = connection.status_a2b
                c_ab.scan_counter_a2b = self.__scan_counter
                return True

        elif c_ba:
            if c_ba.scan_counter_b2a != self.__scan_counter:
                c_ba.lq_b2a = connection.lq_a2b
                c_ba.status_b2a = connection.status_a2b
                c_ba.scan_counter_b2a = self.__scan_counter
                return True

        return False

    def __remove_node_connections(self, node, only_as_node_a=False, force=False):
        """
        Remove the connections that has node as one of its ends.

        Args:
            node (:class:`.AbstractXBeeDevice`): The node whose connections are being removed.
            only_as_node_a (Boolean, optional, default=``False``): Only remove those connections
                with the provided node as "node_a".
            force (Boolean, optional, default=``True``): ``True`` to force the
                deletion of the connections, ``False`` otherwise.

        Returns:
            List: List of removed connections.
        """
        if only_as_node_a:
            node_conn = self.__get_connections_for_node_a_b(node, node_a=True)
        else:
            node_conn = self.get_node_connections(node)

        with self.__conn_lock:
            c_removed = [len(node_conn)]
            c_removed[:] = node_conn[:]
            for c in node_conn:
                if force:
                    self.__del_connection(c)
                else:
                    c.lq_a2b = LinkQuality.UNKNOWN

        return c_removed

    def __purge(self, force=False):
        """
        Removes the nodes and connections that has not been discovered during the last scan.

        Args:
            force (Boolean, optional, default=``False``): ``True`` to force the deletion of nodes
                and connections, ``False`` otherwise.
        """
        # Purge nodes and connections from network
        removed_nodes = self.__purge_network_nodes(force=force)
        removed_connections = self.__purge_network_connections(force=force)

        self._log.debug("")
        self._log.debug(" [*] Purging network...")
        [self._log.debug("     o Removed node: %s" % n) for n in removed_nodes]
        [self._log.debug("     o Removed connections: %s" % n) for n in removed_connections]

    def __purge_network_nodes(self, force=False):
        """
        Removes the nodes and connections that has not been discovered during the last scan.

        Args:
            force (Boolean, optional, default=``False``): ``True`` to force the deletion of nodes,
                ``False`` otherwise.

        Returns:
            List: The list of purged nodes.
        """
        nodes_to_remove = []
        with self.__lock:
            for n in self.__devices_list:
                if not n.scan_counter or n.scan_counter != self.__scan_counter or not n.reachable:
                    nodes_to_remove.append(n)

        [self._remove_device(n, NetworkEventReason.NEIGHBOR, force=force) for n in nodes_to_remove]

        return nodes_to_remove

    def __purge_network_connections(self, force=False):
        """
        Removes the connections that has not been discovered during the last scan.

         Args:
            force (Boolean, optional, default=``False``): ``True`` to force the deletion of
                connections, ``False`` otherwise.

        Returns:
            List: The list of purged connections.
        """
        connections_to_remove = []
        with self.__conn_lock:
            for c in self.__connections:
                if c.scan_counter_a2b != self.__scan_counter \
                        and c.scan_counter_b2a != self.__scan_counter:
                    c.lq_a2b = LinkQuality.UNKNOWN
                    c.lq_b2a = LinkQuality.UNKNOWN
                    connections_to_remove.append(c)
                elif c.scan_counter_a2b != self.__scan_counter:
                    c.lq_a2b = LinkQuality.UNKNOWN
                elif c.scan_counter_b2a != self.__scan_counter:
                    c.lq_b2a = LinkQuality.UNKNOWN
                elif c.lq_a2b == LinkQuality.UNKNOWN \
                        and c.lq_b2a == LinkQuality.UNKNOWN:
                    connections_to_remove.append(c)

        if force:
            [self.__del_connection(c) for c in connections_to_remove]

        return connections_to_remove

    def __purge_node_connections(self, node_a, force=False):
        """
        Purges given node connections. Removes the connections that has not been discovered during
        the last scan.

        Args:
            node_a (:class:`.AbstractXBeeDevice`): The node_a of the connections to purge.
            force (Boolean, optional, default=``False``): ``True`` to force the deletion of the
                connections, ``False`` otherwise.

        Returns:
            List: List of purged connections.
        """
        c_purged = []

        # Get node connections, but only those whose "node_a" is "node" (we are only purging
        # connections that are discovered with "node", and they are those with "node" as "node_a")
        node_conn = self.__get_connections_for_node_a_b(node_a, node_a=True)

        with self.__conn_lock:
            for c in node_conn:
                if c.scan_counter_a2b != self.__scan_counter:
                    c.lq_a2b = LinkQuality.UNKNOWN
                    if c.scan_counter_b2a == self.__scan_counter \
                            and c.lq_b2a == LinkQuality.UNKNOWN:
                        c_purged.append(c)

        if force:
            [self.__del_connection(c) for c in c_purged]

        return c_purged

    def __wait_checking(self, seconds):
        """
        Waits some time, verifying if the process has been canceled.

        Args:
            seconds (Float): The amount of seconds to wait.

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status
                of the discovery process.
        """
        if seconds <= 0:
            return NetworkDiscoveryStatus.SUCCESS

        def current_ms_time():
            return int(round(time.time() * 1000))

        dead_line = current_ms_time() + seconds*1000
        while current_ms_time() < dead_line:
            time.sleep(0.25)
            # Check for cancel
            if self._stop_event.is_set():
                return NetworkDiscoveryStatus.CANCEL

        return NetworkDiscoveryStatus.SUCCESS


class ZigBeeNetwork(XBeeNetwork):
    """
    This class represents a ZigBee network.

    The network allows the discovery of remote devices in the same network
    as the local one and stores them.
    """
    __ROUTE_TABLE_TYPE = "route_table"
    __NEIGHBOR_TABLE_TYPE = "neighbor_table"

    def __init__(self, device):
        """
        Class constructor. Instantiates a new ``ZigBeeNetwork``.

        Args:
            device (:class:`.ZigBeeDevice`): the local ZigBee device to get the network from.

        Raises:
            ValueError: if ``device`` is ``None``.
        """
        super().__init__(device)

        self.__saved_ao = None

        # Dictionary to store the route and neighbor discovery processes per node, so they can be
        # stop when required.
        # The dictionary uses as key the 64-bit address string representation (to be thread-safe)
        self.__zdo_processes = {}

        # Dictionary to store discovered routes for each Zigbee device
        # The dictionary uses as key the 64-bit address string representation (to be thread-safe)
        self.__discovered_routes = {}

    def _prepare_network_discovery(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._prepare_network_discovery`
        """
        self._log.debug("[*] Preconfiguring %s" % ATStringCommand.AO.command)
        try:
            self.__saved_ao = self._local_xbee.get_api_output_mode_value()

            # Do not configure AO if it is already
            if utils.is_bit_enabled(self.__saved_ao[0], 0):
                self.__saved_ao = None

                return

            value = APIOutputModeBit.calculate_api_output_mode_value(
                self._local_xbee.get_protocol(), {APIOutputModeBit.EXPLICIT})

            self._local_xbee.set_api_output_mode_value(value)

        except XBeeException as e:
            raise XBeeException("Could not prepare XBee for network discovery: " + str(e))

    def _discover_neighbors(self, requester, nodes_queue, active_processes, node_timeout):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discover_neighbors`
        """
        active_processes.append(str(requester.get_64bit_addr()))

        if node_timeout is None:
            node_timeout = 30

        code = self.__get_route_table(requester, nodes_queue, node_timeout)

        return code

    def _check_not_discovered_nodes(self, devices_list, nodes_queue):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._check_not_discovered_nodes`
        """
        for n in devices_list:
            if not n.scan_counter or n.scan_counter != self.scan_counter:
                self._log.debug(" [*] Adding to FIFO not discovered node %s... (scan %d)"
                                % (n, self.scan_counter))
                nodes_queue.put(n)

    def _discovery_done(self, active_processes):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discovery_done`
        """
        copy = active_processes[:]
        for p in copy:
            zdos = self.__zdo_processes.get(p)
            if not zdos:
                continue

            self.__stop_zdo_command(zdos, self.__class__.__ROUTE_TABLE_TYPE)
            self.__stop_zdo_command(zdos, self.__class__.__NEIGHBOR_TABLE_TYPE)

            zdos.clear()

        self.__zdo_processes.clear()
        self.__discovered_routes.clear()

        super()._discovery_done(active_processes)

    def _restore_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._restore_network`
        """
        if self.__saved_ao is None:
            return

        self._log.debug("[*] Postconfiguring %s" % ATStringCommand.AO.command)
        try:
            self._local_xbee.set_api_output_mode_value(self.__saved_ao[0])
        except XBeeException as e:
            self._error = "Could not restore XBee after network discovery: " + str(e)

        self.__saved_ao = None

    def _handle_special_errors(self, requester, error):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._handle_special_errors`
        """
        super()._handle_special_errors(requester, error)

        if error == "ZDO command answer not received":
            # 'AO' value is misconfigured, restore it
            self._log.debug("     [***] Local XBee misconfigured: restoring 'AO' value")
            value = APIOutputModeBit.calculate_api_output_mode_value(
                self._local_xbee.get_protocol(), {APIOutputModeBit.EXPLICIT})

            self._local_xbee.set_api_output_mode_value(value)

            # Add the node to the FIFO to try again
            self._XBeeNetwork__nodes_queue.put(requester)

    def __get_route_table(self, requester, nodes_queue, node_timeout):
        """
        Launch the process to get the route table of the XBee.

        Args:
            requester (:class:`.AbstractXBeeDevice`): The XBee to discover its route table.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
            node_timeout (Float): Timeout to get the route table (seconds).

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of
                the route table process.
        """
        def __new_route_callback(xbee, route):
            self._log.debug("     o Discovered route of %s: %s - %s -> %s"
                            % (xbee, route.destination, route.next_hop, route.status))

            # Requester node is clearly reachable
            self._set_node_reachable(xbee, True)

            # Get the discovered routes of the node
            routes_list = self.__discovered_routes.get(str(xbee.get_64bit_addr()))
            if not routes_list:
                routes_list = {}
                self.__discovered_routes.update({str(xbee.get_64bit_addr()): routes_list})

            # Add the new route
            if str(route.next_hop) not in routes_list:
                routes_list.update({str(route.next_hop): route})

            # Check for cancel
            if self._stop_event.is_set():
                cmd = self.__get_zdo_command(xbee, self.__class__.__ROUTE_TABLE_TYPE)
                if cmd:
                    cmd.stop()

        def __route_discover_finished_callback(xbee, routes, error):
            zdo_processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
            if zdo_processes:
                zdo_processes.pop(self.__class__.__ROUTE_TABLE_TYPE)

            if error:
                self.__zdo_processes.pop(str(requester.get_64bit_addr()), None)
                # Remove the discovered routes
                self.__discovered_routes.pop(str(xbee.get_64bit_addr()), None)
                # Process the error and do not continue
                self._node_discovery_process_finished(
                    xbee, code=NetworkDiscoveryStatus.ERROR_GENERAL, error=error)
            else:
                # Check for cancel
                if self._stop_event.is_set():
                    # Remove the discovered routes
                    self.__discovered_routes.pop(str(xbee.get_64bit_addr()), None)
                    self._node_discovery_process_finished(xbee, code=NetworkDiscoveryStatus.CANCEL)
                    # return

                # Get neighbor table
                code = self.__get_neighbor_table(xbee, nodes_queue, node_timeout)
                if code != NetworkDiscoveryStatus.SUCCESS:
                    self._node_discovery_process_finished(
                        xbee, code=NetworkDiscoveryStatus.ERROR_GENERAL, error=error)

        self._log.debug("   [o] Getting ROUTE TABLE of node %s" % requester)

        from digi.xbee.models.zdo import RouteTableReader
        reader = RouteTableReader(requester, configure_ao=False, timeout=node_timeout)
        reader.get_route_table(route_callback=__new_route_callback,
                               process_finished_callback=__route_discover_finished_callback)

        processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
        if not processes:
            processes = {}
            self.__zdo_processes.update({str(requester.get_64bit_addr()): processes})
        processes.update({self.__class__.__ROUTE_TABLE_TYPE: reader})

        return NetworkDiscoveryStatus.SUCCESS

    def __get_neighbor_table(self, requester, nodes_queue, node_timeout):
        """
        Launch the process to get the neighbor table of the XBee.

        Args:
            requester (:class:`.AbstractXBeeDevice`): The XBee to discover its neighbor table.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
            node_timeout (Float): Timeout to get the route neighbor (seconds).

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting status of the
                neighbor table process.
        """
        def __new_neighbor_callback(xbee, neighbor):
            # Do not add a connection to the same node
            if neighbor == xbee:
                return

            # Get the discovered routes of the node
            routes_list = self.__discovered_routes.get(str(xbee.get_64bit_addr()))

            # Add the new neighbor
            self.__process_discovered_neighbor_data(xbee, routes_list, neighbor, nodes_queue)

            # Check for cancel
            if self._stop_event.is_set():
                cmd = self.__get_zdo_command(xbee, self.__class__.__NEIGHBOR_TABLE_TYPE)
                if cmd:
                    cmd.stop()

        def __neighbor_discover_finished_callback(xbee, _, error):
            zdo_processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
            if zdo_processes:
                zdo_processes.pop(self.__class__.__NEIGHBOR_TABLE_TYPE, None)
            self.__zdo_processes.pop(str(requester.get_64bit_addr()), None)

            # Remove the discovered routes
            self.__discovered_routes.pop(str(xbee.get_64bit_addr()), None)

            # Process the error if exists
            code = NetworkDiscoveryStatus.SUCCESS if not error \
                else NetworkDiscoveryStatus.ERROR_GENERAL
            self._node_discovery_process_finished(xbee, code=code, error=error)

        self._log.debug("   [o] Getting NEIGHBOR TABLE of node %s" % requester)

        from digi.xbee.models.zdo import NeighborTableReader
        reader = NeighborTableReader(requester, configure_ao=False, timeout=node_timeout)
        reader.get_neighbor_table(neighbor_callback=__new_neighbor_callback,
                                  process_finished_callback=__neighbor_discover_finished_callback)

        processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
        if not processes:
            processes = {}
            self.__zdo_processes.update({str(requester.get_64bit_addr()): processes})
        processes.update({self.__class__.__NEIGHBOR_TABLE_TYPE: reader})

        return NetworkDiscoveryStatus.SUCCESS

    def __process_discovered_neighbor_data(self, requester, routes, neighbor, nodes_queue):
        """
        Notifies a neighbor has been discovered.

        Args:
            requester (:class:`.AbstractXBeeDevice`): The Zigbee Device whose neighbor table was requested.
            routes (Dictionary): A dictionary with the next hop 16-bit address string as key, and
                the route (``digi.xbee.models.zdo.Route``) as value.
            neighbor (:class:`digi.xbee.models.zdo.Neighbor`): The discovered neighbor.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
        """
        self._log.debug("     o Discovered neighbor of %s: %s (%s)"
                        % (requester, neighbor.node, neighbor.relationship.name))

        # Requester node is clearly reachable
        self._set_node_reachable(requester, True)

        # Add the neighbor node to the network
        node = self._XBeeNetwork__add_remote(neighbor.node, NetworkEventReason.NEIGHBOR)
        if not node:
            # Node already in network for this scan
            node = self.get_device_by_64(neighbor.node.get_64bit_addr())
            self._log.debug("       - NODE already in network in this scan (scan: %d) %s"
                            % (node.scan_counter, node))
        else:
            if neighbor.node.get_role() != Role.END_DEVICE:
                # Add to the FIFO to ask for its neighbors
                nodes_queue.put(node)
                self._log.debug("       - Added to network (scan: %d)" % node.scan_counter)
            else:
                # Not asking to End Devices when found, consider them as reachable
                self._set_node_reachable(node, True)
                # Save its parent
                node.parent = requester
            self._XBeeNetwork__device_discovered(node)

        # Add connections
        route = None
        if routes:
            route = routes.get(str(neighbor.node.get_16bit_addr()))

        if not route and not neighbor.relationship:
            return

        from digi.xbee.models.zdo import RouteStatus, NeighborRelationship
        connection = None

        if route:
            connection = Connection(requester, node, lq_a2b=neighbor.lq,
                                    lq_b2a=LinkQuality.UNKNOWN, status_a2b=route.status,
                                    status_b2a=RouteStatus.UNKNOWN)
            self._log.debug("       - Using route for the connection: %d" % route.status.id)
        elif neighbor.node.get_role() != Role.UNKNOWN \
                and neighbor.relationship != NeighborRelationship.PREVIOUS_CHILD \
                and neighbor.relationship != NeighborRelationship.SIBLING:
            self._log.debug(
                "       - No route for this node, using relationship for the connection: %s"
                % neighbor.relationship.name)
            if neighbor.relationship == NeighborRelationship.PARENT:
                connection = Connection(node, requester, lq_a2b=neighbor.lq,
                                        lq_b2a=LinkQuality.UNKNOWN, status_a2b=RouteStatus.ACTIVE,
                                        status_b2a=RouteStatus.UNKNOWN)
            elif neighbor.relationship == NeighborRelationship.CHILD \
                    or neighbor.relationship == NeighborRelationship.UNDETERMINED:
                connection = Connection(requester, node, lq_a2b=neighbor.lq,
                                        lq_b2a=LinkQuality.UNKNOWN, status_a2b=RouteStatus.ACTIVE,
                                        status_b2a=RouteStatus.UNKNOWN)
        if not connection:
            self._log.debug("       - Connection NULL for this neighbor")
            return

        if self._XBeeNetwork__add_connection(connection):
            self._log.debug("       - Added connection (LQI: %d) %s >>> %s"
                            % (neighbor.lq, requester, node))
        else:
            self._log.debug(
                "       - CONNECTION (LQI: %d) already in network in this"
                " scan (scan: %d) %s >>> %s"
                % (neighbor.lq, node.scan_counter, requester, node))

    def __get_zdo_command(self, xbee, cmd_type):
        """
        Returns the ZDO command in process (route/neighbor table) for the provided device.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): The device to get a ZDO command in process.
            cmd_type (String): The ZDO command type (route/neighbor table)
        """
        cmds = self.__zdo_processes.get(str(xbee.get_64bit_addr()))
        if cmds:
            return cmds.get(cmd_type)

        return None

    def __stop_zdo_command(self, commands, cmd_type):
        """
        Stops the execution of the ZDO command contained in the given dictionary.
        This method blocks until the ZDO command is completely stopped.

        Args:
            commands (Dictionary): The dictionary with the ZDO command to stop.
            cmd_type (String): The ZDO command type (route/neighbor table)
        """
        if not commands or not cmd_type:
            return

        cmd = commands.get(cmd_type)
        if not cmd or not cmd.running:
            return

        cmd.stop()


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

        self.__saved_no = None

        # Dictionary to store the neighbor find processes per node, so they can be
        # stop when required.
        # The dictionary uses as key the 64-bit address string representation (to be thread-safe)
        self.__neighbor_finders = {}

    def _prepare_network_discovery(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._prepare_network_discovery`
        """
        super()._prepare_network_discovery()

        self._log.debug("[*] Preconfiguring %s" % ATStringCommand.NO.command)
        try:
            self.__saved_no = self.get_discovery_options()

            # Do not configure NO if it is already
            if utils.is_bit_enabled(self.__saved_no[0], 2):
                self.__saved_no = None

                return

            self.set_discovery_options({DiscoveryOptions.APPEND_RSSI})

        except XBeeException as e:
            raise XBeeException("Could not prepare XBee for network discovery: " + str(e))

    def _discover_neighbors(self, requester, nodes_queue, active_processes, node_timeout):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discover_neighbors`
        """
        def __new_neighbor_callback(xbee, neighbor):
            # Do not add a connection to the same node
            if neighbor == xbee:
                return

            # Add the new neighbor
            self.__process_discovered_neighbor_data(xbee, neighbor, nodes_queue)

        def __neighbor_discover_finished_callback(xbee, _, error):
            self.__neighbor_finders.pop(str(requester.get_64bit_addr()), None)

            # Process the error if exists
            code = NetworkDiscoveryStatus.SUCCESS if not error \
                else NetworkDiscoveryStatus.ERROR_GENERAL
            self._node_discovery_process_finished(xbee, code=code, error=error)

        self._log.debug("   [o] Calling NEIGHBOR FINDER for node %s" % requester)

        from digi.xbee.models.zdo import NeighborFinder
        finder = NeighborFinder(requester, timeout=node_timeout)
        finder.get_neighbors(neighbor_callback=__new_neighbor_callback,
                             process_finished_callback=__neighbor_discover_finished_callback)

        active_processes.append(str(requester.get_64bit_addr()))
        self.__neighbor_finders.update({str(requester.get_64bit_addr()): finder})

        return NetworkDiscoveryStatus.SUCCESS

    def _check_not_discovered_nodes(self, devices_list, nodes_queue):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._check_not_discovered_nodes`
        """
        for n in devices_list:
            if not n.scan_counter or n.scan_counter != self.scan_counter:
                self._log.debug(" [*] Adding to FIFO not discovered node %s... (scan %d)"
                                % (n, self.scan_counter))
                nodes_queue.put(n)

    def _discovery_done(self, active_processes):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discovery_done`
        """
        copy = active_processes[:]
        for p in copy:
            finder = self.__neighbor_finders.get(p)
            if not finder:
                continue

            finder.stop()

        self.__neighbor_finders.clear()

        super()._discovery_done(active_processes)

    def _restore_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._restore_network`
        """
        super()._restore_network()

        if self.__saved_no is None:
            return

        self._log.debug("[*] Postconfiguring %s" % ATStringCommand.NO.command)
        try:
            self._local_xbee.set_parameter(ATStringCommand.NO.command, self.__saved_no)
        except XBeeException as e:
            self._error = "Could not restore XBee after network discovery: " + str(e)

        self.__saved_no = None

    def __process_discovered_neighbor_data(self, requester, neighbor, nodes_queue):
        """
        Notifies a neighbor has been discovered.

        Args:
            requester (:class:`.AbstractXBeeDevice`): The DigiMesh device whose neighbors was
                requested.
            neighbor (:class:`digi.xbee.models.zdo.Neighbor`): The discovered neighbor.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to discover their
                neighbors are stored.
        """
        self._log.debug("     o Discovered neighbor of %s: %s (%s)"
                        % (requester, neighbor.node, neighbor.relationship.name))

        # Requester node is clearly reachable
        self._set_node_reachable(requester, True)

        # Add the neighbor node to the network
        node = self._XBeeNetwork__add_remote(neighbor.node, NetworkEventReason.NEIGHBOR)
        if not node:
            # Node already in network for this scan
            node = self.get_device_by_64(neighbor.node.get_64bit_addr())
            self._log.debug("       - NODE already in network in this scan (scan: %d) %s"
                            % (node.scan_counter, node))
            # Do not add the connection if the discovered device is itself
            if node.get_64bit_addr() == requester.get_64bit_addr():
                return
        else:
            # Add to the FIFO to ask for its neighbors
            nodes_queue.put(node)
            self._log.debug("       - Added to network (scan: %d)" % node.scan_counter)

            self._XBeeNetwork__device_discovered(node)

        # Add connections
        from digi.xbee.models.zdo import RouteStatus
        connection = Connection(requester, node, lq_a2b=neighbor.lq, lq_b2a=LinkQuality.UNKNOWN,
                                status_a2b=RouteStatus.ACTIVE, status_b2a=RouteStatus.ACTIVE)

        if self._XBeeNetwork__add_connection(connection):
            self._log.debug("       - Added connection (RSSI: %s) %s >>> %s"
                            % (connection.lq_a2b, requester, node))
        else:
            self._log.debug(
                "       - CONNECTION (RSSI: %d) already in network in this "
                "scan (scan: %d) %s >>> %s"
                % (connection.lq_a2b, node.scan_counter, requester, node))

        # Found node is clearly reachable, it answered to a FN
        self._set_node_reachable(node, True)


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
    NEIGHBOR = (0x01, "Discovered as XBee neighbor")
    RECEIVED_MSG = (0x02, "Received message from XBee")
    MANUAL = (0x03, "Manual modification")
    ROUTE = (0x04, "Hop of a network route")

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


class LinkQuality(object):
    """
    This class represents the link qualitity of a connection.
    It can be a LQI (Link Quality Index) for ZigBee devices, or RSSI
    (Received Signal Strength Indicator) for the rest.
    """

    UNKNOWN = None
    """
    Unknown link quality.
    """

    UNKNOWN_VALUE = -9999
    """
    Unknown link quality value.
    """

    __UNKNOWN_STR = '?'

    def __init__(self, lq=UNKNOWN, is_rssi=False):
        """
        Class constructor. Instanciates a new ``LinkQuality``.

        Args:
            lq (Integer, optional, default=``L_UNKNOWN``): The link quality or ``None`` if unknown.
            is_rssi (Boolean, optional, default=``False``): ``True`` to specify the value is a RSSI,
                ``False`` otherwise.
        """
        self.__lq = lq
        self.__is_rssi = is_rssi

    def __str__(self):
        if self.__lq == 0:
            return str(self.__lq)

        if self.__lq == self.__class__.UNKNOWN_VALUE:
            return self.__class__.__UNKNOWN_STR

        if self.__is_rssi:
            return "-" + str(self.__lq)

        return str(self.__lq)

    @property
    def lq(self):
        """
        Returns the link quality value.

        Returns:
             Integer: The link quality value.
        """
        return self.__lq

    @property
    def is_rssi(self):
        """
        Returns whether this is a RSSI value.

        Returns:
             Boolean: ``True`` if this is an RSSI value, ``False`` for LQI.
        """
        return self.__lq


LinkQuality.UNKNOWN = LinkQuality(lq=LinkQuality.UNKNOWN_VALUE)


class Connection(object):
    """
    This class represents a generic connection between two nodes in a XBee network.
    It contains the source and destination nodes, the LQI value for the connection between them and
    its status.
    """

    def __init__(self, node_a, node_b, lq_a2b=None, lq_b2a=None, status_a2b=None, status_b2a=None):
        """
        Class constructor. Instantiates a new ``Connection``.

        Args:
            node_a (:class:`.AbstractXBeeDevice`): One of the connection ends.
            node_b (:class:`.AbstractXBeeDevice`): The other connection end.
            lq_a2b (:class:`.LinkQuality` or Integer, optional, default=``None``): The link
                quality for the connection node_a -> node_b. If not specified
                ``LinkQuality.UNKNOWN`` is used.
            lq_b2a (:class:`.LinkQuality` or Integer, optional, default=``None``): The link
                quality for the connection node_b -> node_a. If not specified
                ``LinkQuality.UNKNOWN`` is used.
            status_a2b (:class:`digi.xbee.models.zdo.RouteStatus`, optional, default=``None``): The
                status for the connection node_a -> node_b. If not specified
                ``RouteStatus.UNKNOWN`` is used.
            status_b2a (:class:`digi.xbee.models.zdo.RouteStatus`, optional, default=``None``): The
                status for the connection node_b -> node_a. If not specified
                ``RouteStatus.UNKNOWN`` is used.

        Raises:
            ValueError: if ``node_a`` or ``node_b`` is ``None``.

        .. seealso::
           | :class:`.AbstractXBeeDevice`
           | :class:`.LinkQuality`
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        if not node_a:
            raise ValueError("Node A must be defined")
        if not node_b:
            raise ValueError("Node B must be defined")

        self.__node_a = node_a
        self.__node_b = node_b

        self.__lq_a2b = Connection.__get_lq(lq_a2b, node_a)
        self.__lq_b2a = Connection.__get_lq(lq_b2a, node_a)

        from digi.xbee.models.zdo import RouteStatus
        self.__st_a2b = status_a2b if status_a2b else RouteStatus.UNKNOWN
        self.__st_b2a = status_b2a if status_b2a else RouteStatus.UNKNOWN

        self.__scan_counter_a2b = 0
        self.__scan_counter_b2a = 0

    def __str__(self):
        return "{{{!s} >>> {!s} [{!s} / {!s}]: {!s} / {!s}}}".format(
            self.__node_a, self.__node_b, self.__st_a2b, self.__st_b2a, self.__lq_a2b,
            self.__lq_b2a)

    def __eq__(self, other):
        if not isinstance(other, Connection):
            return False

        return self.__node_a.get_64bit_addr() == other.node_a.get_64bit_addr() \
            and self.__node_b.get_64bit_addr() == other.node_b.get_64bit_addr()

    def __hash__(self):
        return hash((self.__node_a.get_64bit_addr(), self.__node_b.get_64bit_addr()))

    @property
    def node_a(self):
        """
        Returns the node A of this connection.

        Returns:
             :class:`.AbstractXBeeDevice`: The node A.

        .. seealso::
           | :class:`.AbstractXBeeDevice`
        """
        return self.__node_a

    @property
    def node_b(self):
        """
        Returns the node B of this connection.

        Returns:
             :class:`.AbstractXBeeDevice`: The node .

        .. seealso::
           | :class:`.AbstractXBeeDevice`
        """
        return self.__node_b

    @property
    def lq_a2b(self):
        """
        Returns the link quality of the connection from node A to node B.

        Returns:
             :class:`.LinkQuality`: The link quality for the connection A -> B.

        .. seealso::
           | :class:`.LinkQuality`
        """
        return self.__lq_a2b

    @lq_a2b.setter
    def lq_a2b(self, new_lq_a2b):
        """
        Sets the link quality of the connection from node A to node B.

        Args:
            new_lq_a2b (:class:`.LinkQuality`): The new A -> B link quality value.

        .. seealso::
           | :class:`.LinkQuality`
        """
        self.__lq_a2b = new_lq_a2b

    @property
    def lq_b2a(self):
        """
        Returns the link quality of the connection from node B to node A.

        Returns:
             :class:`.LinkQuality`: The link quality for the connection B -> A.

        .. seealso::
           | :class:`.LinkQuality`
        """
        return self.__lq_b2a

    @lq_b2a.setter
    def lq_b2a(self, new_lq_b2a):
        """
        Sets the link quality of the connection from node B to node A.

        Args:
            new_lq_b2a (:class:`.LinkQuality`): The new B -> A link quality value.

        .. seealso::
           | :class:`.LinkQuality`
        """
        self.__lq_b2a = new_lq_b2a

    @property
    def status_a2b(self):
        """
        Returns the status of this connection from node A to node B.

        Returns:
             :class:`digi.xbee.models.zdo.RouteStatus`: The status for A -> B connection.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        return self.__st_a2b

    @status_a2b.setter
    def status_a2b(self, new_status_a2b):
        """
        Sets the status of this connection from node A to node B.

        Args:
            new_status_a2b (:class:`digi.xbee.models.zdo.RouteStatus`): The new
                A -> B connection status.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        self.__st_a2b = new_status_a2b

    @property
    def status_b2a(self):
        """
        Returns the status of this connection from node B to node A.

        Returns:
             :class:`digi.xbee.models.zdo.RouteStatus`: The status for B -> A connection.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        return self.__st_b2a

    @status_b2a.setter
    def status_b2a(self, new_status_b2a):
        """
        Sets the status of this connection from node B to node A.

        Args:
            new_status_b2a (:class:`digi.xbee.models.zdo.RouteStatus`): The new
                B -> A connection status.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        self.__st_b2a = new_status_b2a

    @staticmethod
    def __get_lq(lq, src):
        """
        Retrieves the `LinkQuality` object that corresponds to the integer provided.

        Args:
            lq (Integer): The link quality value.
            src (:class:`.AbstractXBeeDevice`): The node from where the connection starts.

        Returns:
             :class:`.LinkQuality`: The corresponding `LinkQuality`.

        .. seealso::
           | :class:`.AbstractXBeeDevice`
           | :class:`.LinkQuality`
        """
        if isinstance(lq, LinkQuality):
            return lq
        elif isinstance(lq, int):
            return LinkQuality(lq=lq,
                               is_rssi=src.get_protocol() in [XBeeProtocol.DIGI_MESH,
                                                              XBeeProtocol.XTEND_DM,
                                                              XBeeProtocol.XLR_DM, XBeeProtocol.SX])
        else:
            return LinkQuality.UNKNOWN

    @property
    def scan_counter_a2b(self):
        """
        Returns the scan counter for this connection, discovered by its A node.

        Returns:
             Integer: The scan counter for this connection, discovered by its A node.
        """
        return self.__scan_counter_a2b

    @scan_counter_a2b.setter
    def scan_counter_a2b(self, new_scan_counter_a2b):
        """
        Configures the scan counter for this connection, discovered by its A node.

        Args:
             new_scan_counter_a2b (Integer): The scan counter for this connection, discovered by its
                A node.
        """
        self.__scan_counter_a2b = new_scan_counter_a2b

    @property
    def scan_counter_b2a(self):
        """
        Returns the scan counter for this connection, discovered by its B node.

        Returns:
             Integer: The scan counter for this connection, discovered by its B node.
        """
        return self.__scan_counter_b2a

    @scan_counter_b2a.setter
    def scan_counter_b2a(self, new_scan_counter_b2a):
        """
        Configures the scan counter for this connection, discovered by its B node.

        Args:
             new_scan_counter_b2a (Integer): The scan counter for this connection, discovered by its
                B node.
        """
        self.__scan_counter_b2a = new_scan_counter_b2a
