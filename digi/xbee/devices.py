# Copyright 2017-2024, Digi International Inc.
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
import threading
import time

from abc import ABCMeta, abstractmethod
from enum import Enum, unique
from functools import wraps
from ipaddress import IPv4Address
from queue import Queue, Empty

from digi.xbee import serial
from digi.xbee.filesystem import FileSystemManager
from digi.xbee.models.statistics import Statistics
from digi.xbee.packets.cellular import TXSMSPacket
from digi.xbee.models.accesspoint import AccessPoint, WiFiEncryptionType
from digi.xbee.models.atcomm import ATCommandResponse, ATCommand, ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import OperatingMode, APIOutputMode, \
    IPAddressingMode, NeighborDiscoveryMode, APIOutputModeBit
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress, \
    XBeeIMEIAddress
from digi.xbee.models.info import SocketInfo
from digi.xbee.models.message import XBeeMessage, ExplicitXBeeMessage, IPMessage
from digi.xbee.models.options import TransmitOptions, RemoteATCmdOptions, \
    DiscoveryOptions, XBeeLocalInterface, RegisterKeyOptions
from digi.xbee.models.protocol import XBeeProtocol, IPProtocol, Role
from digi.xbee.models.status import ATCommandStatus, TransmitStatus, \
    PowerLevel, ModemStatus, CellularAssociationIndicationStatus, \
    WiFiAssociationIndicationStatus, AssociationIndicationStatus, NetworkDiscoveryStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import XBeeAPIPacket
from digi.xbee.packets.common import ATCommPacket, TransmitPacket, \
    RemoteATCommandPacket, ExplicitAddressingPacket, ATCommQueuePacket, \
    ATCommResponsePacket, RemoteATCommandResponsePacket
from digi.xbee.packets.network import TXIPv4Packet
from digi.xbee.packets.raw import TX64Packet, TX16Packet
from digi.xbee.packets.relay import UserDataRelayPacket
from digi.xbee.packets.zigbee import RegisterJoiningDevicePacket, \
    RegisterDeviceStatusPacket, CreateSourceRoutePacket

from digi.xbee.sender import PacketSender, SyncRequestSender
from digi.xbee.util import utils
from digi.xbee.exception import XBeeException, TimeoutException, \
    InvalidOperatingModeException, ATCommandException, \
    OperationNotSupportedException, TransmitException
from digi.xbee.io import IOSample, IOMode
from digi.xbee.reader import PacketListener, PacketReceived, DeviceDiscovered, \
    DiscoveryProcessFinished, NetworkModified, RouteReceived, InitDiscoveryScan, \
    EndDiscoveryScan, XBeeEvent, NetworkUpdateProgress
from digi.xbee.serial import FlowControl
from digi.xbee.serial import XBeeSerialPort
from digi.xbee.ble import BLEManager

_ERROR_INCOMPATIBLE_PROTOCOL = \
    "Error reading device information: Your module seems to be %s and NOT %s. " \
    "Check if you are using the appropriate device class."


class AbstractXBeeDevice:
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
    Bluetooth Low Energy API username.
    """

    _log = logging.getLogger(__name__)
    """
    Logger.
    """

    def __init__(self, local_xbee_device=None, serial_port=None,
                 sync_ops_timeout=_DEFAULT_TIMEOUT_SYNC_OPERATIONS, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.AbstractXBeeDevice`
        object with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`, optional, default=`None`): Only
                necessary if XBee is remote. The local XBee to be the connection
                interface to communicate with the remote XBee one.
            serial_port (:class:`.XBeeSerialPort`, optional, default=`None`): Only
                necessary if the XBee device is local. The serial port to
                communicate with this XBee.
            sync_ops_timeout (Integer, optional, default: :attr:`AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`):
                Timeout (in seconds) for all synchronous operations.
            comm_iface (:class:`.XBeeCommunicationInterface`, optional, default=`None`):
                Only necessary if the XBee is local. The hardware interface to
                communicate with this XBee.

        .. seealso::
           | :class:`.XBeeDevice`
           | :class:`.XBeeSerialPort`
        """
        if (serial_port, comm_iface).count(None) != 1:
            raise XBeeException("Either 'serial_port' or 'comm_iface' must be "
                                "'None' (and only one of them)")

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
        self._br = None

        self._packet_listener = None
        self._packet_sender = None

        self._scan_counter = 0
        self._reachable = True

        self._initializing = False
        self._active_update_type = None

        self.__generic_lock = threading.Lock()

        self._ota_max_block_size = 0
        self._file_manager = None

    def __eq__(self, other):
        """
        Operator '=='. Compares two :class:`.AbstractXBeeDevice` instances.

        Returns:
            If at least one XBee has 64-bit address (not `None`), this method
                returns `True` if both XBee addresses are equal, `False` otherwise.

            If at least one XBee has 16-bit address (not `None`), this method
                returns `True` if both XBee addresses are equal, `False` otherwise.

            If at least one XBee has node id (not `None`), this method returns
                `True` if both XBee IDs are equal, `False` otherwise.

            Else (all parameters of both devices are `None`) returns `True`.
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
        Updates the current node information with provided data. This is only
        for internal use.

        Args:
            device (:class:`.AbstractXBeeDevice`): XBee to get the data from.

        Return:
            Boolean: `True` if the node data has been updated, `False` otherwise.
        """
        updated = False

        if not device.is_remote() or device.get_local_xbee_device() == self:
            # Use the internal attribute because the 'operating_mode' property
            # is only available for 'XBeeDevice' objects and not for
            # 'RemoteXBeeDevice' objects, and 'device' parameter is always a
            # remote object even to update a local XBee object
            new_op_mode = device._operating_mode
            if new_op_mode and new_op_mode != self._operating_mode:
                self._operating_mode = new_op_mode
                updated = True

        new_ni = device.get_node_id()
        if new_ni is not None and new_ni != self._node_id:
            self._node_id = new_ni
            updated = True

        new_addr64 = device.get_64bit_addr()
        if (XBee64BitAddress.is_known_node_addr(new_addr64)
                and new_addr64 != self._64bit_addr
                and not XBee64BitAddress.is_known_node_addr(self._64bit_addr)):
            self._64bit_addr = new_addr64
            updated = True

        new_addr16 = device.get_16bit_addr()
        if new_addr16 != self._16bit_addr:
            if (device.get_protocol() in (XBeeProtocol.DIGI_MESH,
                                          XBeeProtocol.DIGI_POINT,
                                          XBeeProtocol.RAW_802_15_4)
                    or XBee16BitAddress.is_known_node_addr(new_addr16)):
                self._16bit_addr = new_addr16
                updated = True

        new_role = device.get_role()
        if (new_role is not None
                and new_role != Role.UNKNOWN
                and new_role != self._role):
            self._role = new_role
            updated = True

        new_fw = device.get_firmware_version()
        if new_fw:
            self._firmware_version = new_fw

        new_hw = device.get_hardware_version()
        if new_hw:
            self._hardware_version = new_hw

        new_br = device.br
        if new_br != self._br:
            self._br = new_br
            # It is not necessary to set the 'updated' flag to 'True' because,
            # if the 'BR' change occurs between 0 and X or X and 0, it means
            # the device protocol has changed. When this happens in a remote
            # device, the device is removed from the network and if it happens
            # in a local device, the object is re-instantiated. In both cases,
            # this code is never reached. If the 'BR' change occurs between 1
            # and 2 or 2 and 1, the device protocol (Digi-Mesh) does not
            # change, thus it is not necessary to notify any relevant change.

        if (isinstance(self, (ZigBeeDevice, RemoteZigBeeDevice))
                and isinstance(device, (ZigBeeDevice, RemoteZigBeeDevice))):
            new_parent = device.parent
            if new_parent:
                self.parent = new_parent
                updated = True

        return updated

    def get_parameter(self, parameter, parameter_value=None, apply=None):
        """
        Returns the value of the provided parameter via an AT Command.

        Args:
            parameter (String or :class: `.ATStringCommand`): Parameter to get.
            parameter_value (Bytearray, optional, default=`None`): Value of the
                parameter to execute (if any).
            apply (Boolean, optional, default=`None`): `True` to apply changes
                in XBee configuration, `False` not to apply them, `None` to use
                `is_apply_changes_enabled()` returned value.

        Returns:
            Bytearray: Parameter value.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.set_parameter`
           | :meth:`.AbstractXBeeDevice.execute_command`
           | :meth:`.AbstractXBeeDevice.apply_changes`
           | :meth:`.AbstractXBeeDevice.write_changes`
        """
        # Use 'None' as 'apply' default value to keep the behaviour the method
        # had in previous versions
        value = self.__send_parameter(
            parameter, parameter_value=parameter_value, apply=apply)

        # Check if response is None, if so throw an exception (maybe a write-only parameter)
        if value is None:
            if isinstance(parameter, ATStringCommand):
                parameter = parameter.command
            raise OperationNotSupportedException(
                message="Could not get the %s value." % parameter)

        return value

    def set_parameter(self, parameter, value, apply=None):
        """
        Sets the value of a parameter via an AT Command.

        Any parameter changes are applied automatically, if `apply` is `True` or
        if it is `None` and apply flag is enabled (`is_apply_changes_enabled()`)

        You can set this flag via the method
        :meth:`.AbstractXBeeDevice.enable_apply_changes`.

        This only applies modified values in the XBee configuration, to save
        changed parameters permanently (between resets), use
        :meth:`.AbstractXBeeDevice.write_changes`.

        Args:
            parameter (String or :class: `.ATStringCommand`): Parameter to set.
            value (Bytearray): Value of the parameter.
            apply (Boolean, optional, default=`None`): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            ValueError: If `parameter` is `None` or `value` is `None`.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
           | :meth:`.AbstractXBeeDevice.execute_command`
           | :meth:`.AbstractXBeeDevice.apply_changes`
           | :meth:`.AbstractXBeeDevice.write_changes`
           | :meth:`.AbstractXBeeDevice.is_apply_changes_enabled`
           | :meth:`.AbstractXBeeDevice.enable_apply_changes`
        """
        if value is None:
            raise ValueError("Value of the parameter cannot be None.")

        # Use 'None' as 'apply' default value to keep the behaviour the method
        # had in previous versions
        self.__send_parameter(parameter, parameter_value=value, apply=apply)

    def execute_command(self, parameter, value=None, apply=None):
        """
        Executes the provided command.

        Args:
            parameter (String or :class: `.ATStringCommand`): AT command to execute.
            value (bytearray, optional, default=`None`): Command value (if any).
            apply (Boolean, optional, default=`None`): `True` to apply changes
                in XBee configuration, `False` not to apply them, `None` to use
                `is_apply_changes_enabled()` returned value.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
           | :meth:`.AbstractXBeeDevice.set_parameter`
           | :meth:`.AbstractXBeeDevice.apply_changes`
           | :meth:`.AbstractXBeeDevice.write_changes`
           | :meth:`.AbstractXBeeDevice.is_apply_changes_enabled`
           | :meth:`.AbstractXBeeDevice.enable_apply_changes`
        """
        # Use 'None' as 'apply' default value to keep the behaviour the method
        # had in previous versions
        self.__send_parameter(parameter, parameter_value=value, apply=apply)

    def __send_parameter(self, parameter, parameter_value=None, apply=None):
        """
        Sends the given AT parameter to this XBee with an optional argument
        or value and returns the response (likely the value) of that parameter
        in a byte array format.

        Args:
            parameter (String or :class: `.ATStringCommand`): AT command/parameter to execute.
            parameter_value (bytearray, optional, default=`None`): Value of the
                AT command/parameter (if any).
            apply (Boolean, optional, default=`None`): `True` to enable the
                apply changes flag, `False` to disable it, `None` to use
                `is_apply_changes_enabled()` returned value.

        Returns:
            Bytearray: A byte array containing the value of the parameter.

        Raises:
            ValueError: if `parameter` is `None` or if `len(parameter) != 2`.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        if parameter is None:
            raise ValueError("Parameter cannot be None.")
        if isinstance(parameter, ATStringCommand):
            parameter = parameter.command
        if len(parameter) != 2:
            raise ValueError("Parameter must contain exactly 2 characters.")

        at_command = ATCommand(parameter, parameter=parameter_value)

        # Send the AT command.
        response = self._send_at_command(at_command, apply=apply)

        self._check_at_cmd_response_is_valid(response)

        return response.response

    @staticmethod
    def _check_at_cmd_response_is_valid(response):
        """
        Checks if the provided `ATCommandResponse` is valid throwing an
        :class:`.ATCommandException` in case it is not.

        Args:
            response: The AT command response to check.

        Raises:
            ATCommandException: If `response` is `None` or `response.status != OK`.
        """
        if (response is None or not isinstance(response, ATCommandResponse)
                or response.status is None):
            raise ATCommandException()
        if response.status != ATCommandStatus.OK:
            raise ATCommandException(message=response.status.description,
                                     cmd_status=response.status)

    def _send_at_command(self, command, apply=None):
        """
        Sends the given AT command and waits for answer or until the configured
        receive timeout expires.

        Args:
            command (:class:`.ATCommand`): AT command to send.
            apply (Boolean, optional, default=`None`): `True` to enable the
                apply changes flag, `False` to disable it, `None` to use
                `is_apply_changes_enabled()` returned value.

        Returns:
            :class:`.ATCommandResponse`: Response of the command or `None`
                if there is no response.

        Raises:
            ValueError: If `command` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
        """
        if command is None:
            raise ValueError("AT command cannot be None.")

        if (not self.is_remote() and command.parameter
                and command.command.upper() == ATStringCommand.AP.command
                and not self._packet_sender.is_op_mode_valid(command.parameter)):
            op_mode_val = utils.bytes_to_int(command.parameter)
            op_mode = OperatingMode.get(op_mode_val)
            raise ATCommandException(
                message="Operating mode '%d' (%s) not set not to loose XBee connection"
                % (op_mode_val, op_mode.description if op_mode else "Unknown"))

        operating_mode = self._get_operating_mode()
        if operating_mode not in (OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        apply = apply if apply is not None else self.is_apply_changes_enabled()

        if self.is_remote():
            remote_at_cmd_opts = RemoteATCmdOptions.NONE.value
            if apply:
                remote_at_cmd_opts |= RemoteATCmdOptions.APPLY_CHANGES.value

            remote_16bit_addr = self.get_16bit_addr()
            if remote_16bit_addr is None:
                remote_16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

            packet = RemoteATCommandPacket(
                self._get_next_frame_id(), self.get_64bit_addr(), remote_16bit_addr,
                remote_at_cmd_opts, command.command, parameter=command.parameter)
        else:
            if apply:
                packet = ATCommPacket(self._get_next_frame_id(), command.command,
                                      parameter=command.parameter)
            else:
                packet = ATCommQueuePacket(self._get_next_frame_id(),
                                           command.command, parameter=command.parameter)

        if self.is_remote():
            answer_packet = self._local_xbee_device.send_packet_sync_and_get_response(
                packet, timeout=self._timeout)
        else:
            answer_packet = self._send_packet_sync_and_get_response(packet)

        response = None

        if isinstance(answer_packet, (ATCommResponsePacket, RemoteATCommandResponsePacket)):
            response = ATCommandResponse(command, response=answer_packet.command_value,
                                         status=answer_packet.status)

        return response

    def apply_changes(self):
        """
        Applies changes via 'AC' command.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self.execute_command(ATStringCommand.AC, apply=False)

    def write_changes(self):
        """
        Writes configurable parameter values to the non-volatile memory of the
        XBee so that parameter modifications persist through subsequent resets.

        Parameters values remain in the device's memory until overwritten by
        subsequent use of this method.

        If changes are made without writing them, the XBee reverts back to
        previously saved parameters the next time the module is powered-on.

        Writing the parameter modifications does not mean those values are
        immediately applied, this depends on the status of the 'apply
        configuration changes' option. Use method
        :meth:`is_apply_changes_enabled` to get its status and
        :meth:`enable_apply_changes` to enable/disable the option. Method
        :meth:`apply_changes` can be used in order to manually apply the changes.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self.execute_command(ATStringCommand.WR, apply=False)

    @abstractmethod
    def reset(self):
        """
        Performs a software reset on this XBee and blocks until the process is
        completed.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """

    def _read_device_info(self, reason, init=True, fire_event=True):
        """
        Updates all instance parameters reading them from the XBee.

        Args:
            reason (:class:`.NetworkEventReason`): If an event is thrown, this
                parameter specifies the reason.
            init (Boolean, optional, default=`True`): If `False` only not
                initialized parameters are read, all if `True`.
            fire_event (Boolean, optional, default=`True`): `True` to throw
                and update event if any parameter changed, `False` otherwise.
        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_device_info_complete`
        """
        if self.is_remote():
            if not self._local_xbee_device.comm_iface.is_interface_open:
                raise XBeeException("Local XBee device's communication interface closed")
        else:
            if (self._operating_mode not in (OperatingMode.API_MODE,
                                             OperatingMode.ESCAPED_API_MODE)):
                raise InvalidOperatingModeException(op_mode=self._operating_mode)

            if not self._comm_iface.is_interface_open:
                raise XBeeException("XBee device's communication interface closed")

        if self._initializing:
            return

        self._initializing = True

        if self.is_remote() and init:
            # Clear the 16-bit address, it might be obsolete: a problem for Zigbee
            self._16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

        updated = False

        try:
            # Hardware version:
            if init or self._hardware_version is None:
                hw_version = HardwareVersion.get(
                    self.get_parameter(ATStringCommand.HV, apply=False)[0])
                if self._hardware_version != hw_version:
                    updated = True
                    self._hardware_version = hw_version
            # Firmware version:
            if init or self._firmware_version is None:
                fw_version = self.get_parameter(ATStringCommand.VR, apply=False)
                if self._firmware_version != fw_version:
                    updated = True
                    self._firmware_version = fw_version

            # Protocol:
            self._protocol = self.determine_protocol(
                self._hardware_version.code, self._firmware_version)

            # 64-bit address:
            if init or not XBee64BitAddress.is_known_node_addr(self._64bit_addr):
                sh_val = self.get_parameter(ATStringCommand.SH, apply=False)
                sl_val = self.get_parameter(ATStringCommand.SL, apply=False)
                x64bit_addr = XBee64BitAddress(sh_val + sl_val)
                if self._64bit_addr != x64bit_addr:
                    self._64bit_addr = x64bit_addr
                    updated = True
            # Node ID:
            if init or not self._node_id:
                node_id = str(self.get_parameter(ATStringCommand.NI, apply=False),
                              encoding='utf8', errors='ignore')
                if self._node_id != node_id:
                    self._node_id = node_id
                    updated = True
            # 16-bit address:
            if self._protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.RAW_802_15_4,
                                  XBeeProtocol.XTEND, XBeeProtocol.SMART_ENERGY,
                                  XBeeProtocol.ZNET):
                if init or not XBee16BitAddress.is_known_node_addr(self._16bit_addr):
                    x16bit_addr = XBee16BitAddress(
                        self.get_parameter(ATStringCommand.MY, apply=False))
                    if self._16bit_addr != x16bit_addr:
                        self._16bit_addr = x16bit_addr
                        updated = True
            else:
                # For protocols that do not support a 16-bit address, set it to unknown
                self._16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

            # Role:
            if init or self._role is None or self._role == Role.UNKNOWN:
                role = self._determine_role()
                if self._role != role:
                    self._role = role
                    updated = True
        except XBeeException:
            raise
        else:
            if fire_event and updated:
                network = self.get_local_xbee_device().get_network() if self.is_remote() \
                    else self.get_network()
                if (network
                        and (not self.is_remote()
                             or network.get_device_by_64(self._64bit_addr)
                             or network.get_device_by_16(self._16bit_addr))):
                    network._network_modified(
                        NetworkEventType.UPDATE, reason, node=self)
        finally:
            self._initializing = False

    def read_device_info(self, init=True, fire_event=True):
        """
        Updates all instance parameters reading them from the XBee.

        Args:
            init (Boolean, optional, default=`True`): If `False` only not
                initialized parameters are read, all if `True`.
            fire_event (Boolean, optional, default=`True`): `True` to throw
                and update event if any parameter changed, `False` otherwise.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_device_info_complete`
        """
        self._read_device_info(NetworkEventReason.READ_INFO, init=init, fire_event=fire_event)

    def determine_protocol(self, hardware_version, firmware_version):
        """
        Determines the XBee protocol based on the given hardware and firmware
        versions.

        Args:
            hardware_version (Integer): Hardware version to get its protocol.
            firmware_version (Bytearray): Firmware version to get its protocol.

        Returns:
            :class:`.XBeeProtocol`: XBee protocol corresponding to the given
                hardware and firmware versions.
        """
        if hardware_version in (HardwareVersion.SX.code,
                                HardwareVersion.SX_PRO.code,
                                HardwareVersion.XB8X.code):
            self._br = self.get_parameter(ATStringCommand.BR, apply=False)[0]

        return XBeeProtocol.determine_protocol(
            hardware_version, firmware_version, br_value=self._br)

    def is_device_info_complete(self):
        """
        Returns whether XBee node information is complete.

        Returns:
            Boolean: `True` if node information is complete, `False` otherwise.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.read_device_info`
        """
        is_16bit_init = True
        if self._protocol in (XBeeProtocol.RAW_802_15_4, XBeeProtocol.ZIGBEE,
                              XBeeProtocol.XTEND, XBeeProtocol.SMART_ENERGY,
                              XBeeProtocol.ZNET):
            is_16bit_init = XBee16BitAddress.is_known_node_addr(self._16bit_addr)

        return (self._hardware_version is not None
                and self._firmware_version is not None
                and XBee64BitAddress.is_known_node_addr(self._64bit_addr)
                and self._node_id is not None
                and is_16bit_init
                and self._role is not None and self._role != Role.UNKNOWN)

    def _determine_role(self):
        """
        Determines the role of the XBee depending on its protocol.

        Returns:
            :class:`.Role`: XBee role.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        if self._protocol in (XBeeProtocol.DIGI_MESH, XBeeProtocol.SX, XBeeProtocol.XTEND_DM):
            ce_val = utils.bytes_to_int(
                self.get_parameter(ATStringCommand.CE, apply=False))
            if ce_val == 0:
                try:
                    # Capture the possible exception because DigiMesh S2C does not have
                    # SS command, so the read will throw an ATCommandException
                    ss_val = self.get_parameter(ATStringCommand.SS, apply=False)
                except ATCommandException:
                    ss_val = None

                if not ss_val:
                    return Role.ROUTER

                ss_val = utils.bytes_to_int(ss_val)
                if utils.is_bit_enabled(ss_val, 1):
                    return Role.COORDINATOR
                return Role.ROUTER
            if ce_val == 1:
                return Role.COORDINATOR
            return Role.END_DEVICE
        if self._protocol in (XBeeProtocol.RAW_802_15_4, XBeeProtocol.DIGI_POINT,
                              XBeeProtocol.XLR, XBeeProtocol.XLR_DM):
            ce_val = utils.bytes_to_int(
                self.get_parameter(ATStringCommand.CE, apply=False))
            if self._protocol == XBeeProtocol.RAW_802_15_4:
                if ce_val == 0:
                    return Role.END_DEVICE
                if ce_val == 1:
                    return Role.COORDINATOR
            else:
                if ce_val == 0:
                    return Role.ROUTER
                if ce_val in (1, 3):
                    return Role.COORDINATOR
                if ce_val in (2, 4, 6):
                    return Role.END_DEVICE
        elif self._protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.SMART_ENERGY):
            try:
                ce_val = utils.bytes_to_int(
                    self.get_parameter(ATStringCommand.CE, apply=False))
                if ce_val == 1:
                    return Role.COORDINATOR

                sm_val = utils.bytes_to_int(
                    self.get_parameter(ATStringCommand.SM, apply=False))

                return Role.ROUTER if sm_val == 0 else Role.END_DEVICE
            except ATCommandException:
                from digi.xbee.models.zdo import NodeDescriptorReader
                n_desc = NodeDescriptorReader(
                    self, configure_ao=True,
                    timeout=3*self._timeout if self.is_remote() else 2*self._timeout) \
                    .get_node_descriptor()
                if n_desc:
                    return n_desc.role

        return Role.UNKNOWN

    def get_node_id(self):
        """
        Returns the node identifier ('NI') value of the XBee.

        Returns:
            String: Node identifier ('NI') of the XBee.
        """
        return self._node_id

    def set_node_id(self, node_id):
        """
        Sets the node identifier ('NI`) value of the XBee.

        Args:
            node_id (String): New node identifier ('NI') of the XBee.

        Raises:
            ValueError: If `node_id` is `None` or its length is greater than 20.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        if node_id is None:
            raise ValueError("Node ID cannot be None")
        if len(node_id) > 20:
            raise ValueError("Node ID length must be less than 21")

        self.set_parameter(ATStringCommand.NI, bytearray(node_id, 'utf8'),
                           apply=self.is_apply_changes_enabled())
        self._node_id = node_id

    def get_hardware_version(self):
        """
        Returns the hardware version of the XBee.

        Returns:
            :class:`.HardwareVersion`: Hardware version of the XBee.

        .. seealso::
           | :class:`.HardwareVersion`
        """
        return self._hardware_version

    def get_firmware_version(self):
        """
        Returns the firmware version of the XBee.

        Returns:
            Bytearray: Firmware version of the XBee.
        """
        return self._firmware_version

    def get_protocol(self):
        """
        Returns the current protocol of the XBee.

        Returns:
            :class:`.XBeeProtocol`: Current protocol of the XBee.

        .. seealso::
           | :class:`.XBeeProtocol`
        """
        return self._protocol

    def get_16bit_addr(self):
        """
        Returns the 16-bit address of the XBee.

        Returns:
            :class:`.XBee16BitAddress`: 16-bit address of the XBee.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self._16bit_addr

    def set_16bit_addr(self, value):
        """
        Sets the 16-bit address of the XBee.

        Args:
            value (:class:`.XBee16BitAddress`): New 16-bit address of the XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            OperationNotSupportedException: If the protocol is not 802.15.4.
        """
        if self.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise OperationNotSupportedException(
                message="16-bit address can only be set in 802.15.4 protocol")

        self.set_parameter(ATStringCommand.MY, value.address,
                           apply=self.is_apply_changes_enabled())
        self._16bit_addr = value

    def get_64bit_addr(self):
        """
        Returns the 64-bit address of the XBee.

        Returns:
            :class:`.XBee64BitAddress`: 64-bit address of the XBee.

        .. seealso::
           | :class:`.XBee64BitAddress`
        """
        return self._64bit_addr

    def get_role(self):
        """
        Gets the XBee role.

        Returns:
             :class:`.Role`: the role of the XBee.

        .. seealso::
           | :class:`.Role`
        """
        return self._role

    def get_current_frame_id(self):
        """
        Returns the last used frame ID.

        Returns:
            Integer: Last used frame ID.
        """
        return self.__current_frame_id

    def enable_apply_changes(self, value):
        """
        Sets apply changes flag.

        Args:
            value (Boolean): `True` to enable apply changes flag, `False` to
                disable it.
        """
        self._apply_changes_flag = value

    def is_apply_changes_enabled(self):
        """
        Returns whether apply changes flag is enabled.

        Returns:
            Boolean: `True` if apply changes flag is enabled, `False` otherwise.
        """
        return self._apply_changes_flag

    @abstractmethod
    def is_remote(self):
        """
        Determines whether XBee is remote.

        Returns:
            Boolean: `True` if the XBee is remote, `False` otherwise.
        """

    def set_sync_ops_timeout(self, sync_ops_timeout):
        """
        Sets the serial port read timeout.

        Args:
            sync_ops_timeout (Integer): Read timeout in seconds.
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
            Integer: Serial port read timeout in seconds.
        """
        return self._timeout

    def get_dest_address(self):
        """
        Returns the 64-bit address of the XBee that is data destination.

        Returns:
            :class:`.XBee64BitAddress`: 64-bit address of destination XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :meth:`.set_dest_address`
        """
        dh_val = self.get_parameter(ATStringCommand.DH, apply=False)
        dl_val = self.get_parameter(ATStringCommand.DL, apply=False)
        return XBee64BitAddress(dh_val + dl_val)

    def set_dest_address(self, addr):
        """
        Sets the 64-bit address of the XBee that is data destination.

        Args:
            addr (:class:`.XBee64BitAddress` or :class:`.RemoteXBeeDevice`):
                Address itself or remote XBee to be data destination.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            ValueError: If `addr` is `None`.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :meth:`.get_dest_address`
        """
        if isinstance(addr, RemoteXBeeDevice):
            addr = addr.get_64bit_addr()

        apply = self.is_apply_changes_enabled()
        with self.__generic_lock:
            try:
                self.set_parameter(
                    ATStringCommand.DH, addr.address[:4], apply=False)
                self.set_parameter(
                    ATStringCommand.DL, addr.address[4:], apply=apply)
            except (TimeoutException, XBeeException,
                    InvalidOperatingModeException, ATCommandException) as exc:
                # Raise the exception.
                raise exc

    def get_pan_id(self):
        """
        Returns the operating PAN ID of the XBee.

        Returns:
            Bytearray: Operating PAN ID of the XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.set_pan_id`
        """
        if self.get_protocol() == XBeeProtocol.ZIGBEE:
            return self.get_parameter(ATStringCommand.OP, apply=False)
        return self.get_parameter(ATStringCommand.ID, apply=False)

    def set_pan_id(self, value):
        """
        Sets the operating PAN ID of the XBee.

        Args:
            value (Bytearray): New operating PAN ID of the XBee. Must have only
                1 or 2 bytes.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.get_pan_id`
        """
        self.set_parameter(ATStringCommand.ID, value,
                           apply=self.is_apply_changes_enabled())

    def get_power_level(self):
        """
        Returns the power level of the XBee.

        Returns:
            :class:`.PowerLevel`: Power level of the XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.PowerLevel`
           | :meth:`.set_power_level`
        """
        return PowerLevel.get(self.get_parameter(ATStringCommand.PL, apply=False)[0])

    def set_power_level(self, power_level):
        """
        Sets the power level of the XBee.

        Args:
            power_level (:class:`.PowerLevel`): New power level of the XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.PowerLevel`
           | :meth:`.get_power_level`
        """
        self.set_parameter(ATStringCommand.PL, bytearray([power_level.code]),
                           apply=self.is_apply_changes_enabled())

    def set_io_configuration(self, io_line, io_mode):
        """
        Sets the configuration of the provided IO line.

        Args:
            io_line (:class:`.IOLine`): IO line to configure.
            io_mode (:class:`.IOMode`): IO mode to set to the IO line.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOMode`
           | :meth:`.get_io_configuration`
        """
        self.set_parameter(io_line.at_command, bytearray([io_mode.value]),
                           apply=self.is_apply_changes_enabled())

    def get_io_configuration(self, io_line):
        """
        Returns the configuration of the provided IO line.

        Args:
            io_line (:class:`.IOLine`): IO line to get its configuration.

        Returns:
            :class:`.IOMode`: IO mode of the IO line provided.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOMode`
           | :meth:`.set_io_configuration`
        """
        value = self.get_parameter(io_line.at_command, apply=False)
        try:
            mode = IOMode(value[0])
        except ValueError:
            raise OperationNotSupportedException(
                "Received configuration IO mode '%s' is invalid." % utils.hex_to_string(value)) from None
        return mode

    def get_io_sampling_rate(self):
        """
        Returns the IO sampling rate of the XBee.

        Returns:
            Integer: IO sampling rate of XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.set_io_sampling_rate`
        """
        resp = self.get_parameter(ATStringCommand.IR, apply=False)
        return utils.bytes_to_int(resp) / 1000.00

    def set_io_sampling_rate(self, rate):
        """
        Sets the IO sampling rate of the XBee in seconds. A sample rate of 0
        means the IO sampling feature is disabled.

        Args:
            rate (Integer): New IO sampling rate of the XBee in seconds.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :meth:`.get_io_sampling_rate`
        """
        self.set_parameter(ATStringCommand.IR,
                           utils.int_to_bytes(int(rate * 1000)),
                           apply=self.is_apply_changes_enabled())

    def read_io_sample(self):
        """
        Returns an IO sample from the XBee containing the value of all enabled
        digital IO and analog input channels.

        Returns:
            :class:`.IOSample`: IO sample read from the XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

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
                if frame_type in (ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR,
                                  ApiFrameType.RX_IO_16, ApiFrameType.RX_IO_64):
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
                self.execute_command(ATStringCommand.IS, apply=False)

                lock.acquire()
                lock.wait(self.get_sync_ops_timeout())
                lock.release()

                if self.__io_packet_payload is None:
                    raise TimeoutException(message="Timeout waiting for the IO response packet.")
                sample_payload = self.__io_packet_payload
            finally:
                self._del_packet_received_callback(io_sample_callback)
        else:
            sample_payload = self.get_parameter(ATStringCommand.IS, apply=False)

        try:
            return IOSample(sample_payload)
        except Exception as exc:
            raise XBeeException("Could not create the IO sample.", exc) from None

    def get_adc_value(self, io_line):
        """
        Returns the analog value of the provided IO line.

        The provided IO line must be previously configured as ADC. To do so,
        use :meth:`.AbstractXBeeDevice.set_io_configuration` and :attr:`.IOMode.ADC`.

        Args:
            io_line (:class:`.IOLine`): IO line to get its ADC value.

        Returns:
            Integer: Analog value corresponding to the provided IO line.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            OperationNotSupportedException: If response does not contain the
                value for the given IO line.

        .. seealso::
           | :class:`.IOLine`
           | :meth:`.set_io_configuration`
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
            io_line (:class:`.IOLine`): IO Line to be assigned.
            cycle (Integer): Duty cycle in % to be assigned. Must be between 0 and 100.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            ValueError: If the given IO line does not have PWM capability or
                `cycle` is not between 0 and 100.

        .. seealso::
           | :class:`.IOLine`
           | :attr:`.IOMode.PWM`
        """
        if not io_line.has_pwm_capability():
            raise ValueError("%s has no PWM capability." % io_line)
        if cycle < 0 or cycle > 100:
            raise ValueError("Cycle must be between 0% and 100%.")

        duty_cycle = int(round(cycle * 1023.00 / 100.00))

        self.set_parameter(io_line.pwm_at_command,
                           bytearray(utils.int_to_bytes(duty_cycle)),
                           apply=self.is_apply_changes_enabled())

    def get_pwm_duty_cycle(self, io_line):
        """
        Returns the PWM duty cycle in % corresponding to the provided IO line.

        Args:
            io_line (:class:`.IOLine`): IO line to get its PWM duty cycle.

        Returns:
            Integer: PWM duty cycle of the given IO line.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            ValueError: If `io_line` has no PWM capability.

        .. seealso::
           | :class:`.IOLine`
        """
        if not io_line.has_pwm_capability():
            raise ValueError("%s has no PWM capability." % io_line)

        value = utils.bytes_to_int(
            self.get_parameter(io_line.pwm_at_command, apply=False))
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
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            OperationNotSupportedException: If response does not contain the
                value for the given IO line.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOValue`
           | :meth:`.set_io_configuration`
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
            io_line (:class:`.IOLine`): Digital IO line to sets its value.
            io_value (:class:`.IOValue`): IO value to set to the IO line.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOValue`
        """
        self.set_parameter(io_line.at_command, bytearray([io_value.value]),
                           apply=self.is_apply_changes_enabled())

    def set_dio_change_detection(self, io_lines_set):
        """
        Sets the digital IO lines to be monitored and sampled whenever their
        status changes. A `None` set of lines disables this feature.

        Args:
            io_lines_set: Set of :class:`.IOLine`.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

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
                    flags[0] = flags[0] | (1 << (i - 8))
        self.set_parameter(ATStringCommand.IC, flags,
                           apply=self.is_apply_changes_enabled())

    @utils.deprecated("1.3", details="Use :meth:`get_api_output_mode_value`")
    def get_api_output_mode(self):
        """
        Returns the API output mode of the XBee.

        The API output mode determines the format of the data through the
        serial interface of the XBee.

        Returns:
            :class:`.APIOutputMode`: API output mode of the XBee.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.APIOutputMode`
        """
        return APIOutputMode.get(
            self.get_parameter(ATStringCommand.AO, apply=False)[0])

    def get_api_output_mode_value(self):
        """
        Returns the API output mode of the XBee.

        The API output mode determines the format that the received data is
        output through the serial interface of the XBee.

        Returns:
            Bytearray: the parameter value.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            OperationNotSupportedException: If it is not supported by the
                current protocol.

        .. seealso::
           | :class:`digi.xbee.models.mode.APIOutputModeBit`
        """
        if self.get_protocol() not in (XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_MESH,
                                       XBeeProtocol.DIGI_POINT, XBeeProtocol.XLR,
                                       XBeeProtocol.XLR_DM):
            raise OperationNotSupportedException(
                message="Operation not supported for the current protocol (%s)"
                % self.get_protocol().description)

        return self.get_parameter(ATStringCommand.AO, apply=False)

    @utils.deprecated("1.3", details="Use :meth:`set_api_output_mode_value`")
    def set_api_output_mode(self, api_output_mode):
        """
        Sets the API output mode of the XBee.

        Args:
            api_output_mode (:class:`.APIOutputMode`): New API output mode.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            OperationNotSupportedException: If it is not supported by the
                current protocol.

        .. seealso::
           | :class:`.APIOutputMode`
        """
        self.set_parameter(ATStringCommand.AO,
                           bytearray([api_output_mode.code]),
                           apply=self.is_apply_changes_enabled())

    def set_api_output_mode_value(self, api_output_mode):
        """
        Sets the API output mode of the XBee.

        Args:
            api_output_mode (Integer): New API output mode options.
                Calculate this value using the method
                :meth:`.APIOutputModeBit.calculate_api_output_mode_value`
                with a set of :class:`.APIOutputModeBit`.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            OperationNotSupportedException: If it is not supported by the
                current protocol.

        .. seealso::
           | :class:`.APIOutputModeBit`
        """
        if api_output_mode is None:
            raise ValueError("API output mode cannot be None")

        if self.get_protocol() not in (XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_MESH,
                                       XBeeProtocol.RAW_802_15_4,
                                       XBeeProtocol.DIGI_POINT, XBeeProtocol.XLR,
                                       XBeeProtocol.XLR_DM):
            raise OperationNotSupportedException(
                message="Operation not supported for the current protocol (%s)"
                % self.get_protocol().description)

        self.set_parameter(ATStringCommand.AO, bytearray([api_output_mode]),
                           apply=self.is_apply_changes_enabled())

    def enable_bluetooth(self):
        """
        Enables the Bluetooth interface of this XBee.

        To work with this interface, you must also configure the Bluetooth
        password if not done previously. Use method
        :meth:`.AbstractXBeeDevice.update_bluetooth_password`.

        Note that your XBee must include Bluetooth Low Energy support.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self._enable_bluetooth(True)

    def disable_bluetooth(self):
        """
        Disables the Bluetooth interface of this XBee.

        Note that your device must include Bluetooth Low Energy support.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self._enable_bluetooth(False)

    def _enable_bluetooth(self, enable):
        """
        Enables or disables the Bluetooth interface of this XBee.

        Args:
            enable (Boolean): `True` to enable the Bluetooth interface, `False`
                to disable it.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self.set_parameter(ATStringCommand.BT, b'\x01' if enable else b'\x00',
                           apply=False)
        self.write_changes()
        self.apply_changes()

    def get_bluetooth_mac_addr(self):
        """
        Reads and returns the EUI-48 Bluetooth MAC address of this XBee
        following the format `00112233AABB`.

        Note that your device must include Bluetooth Low Energy support.

        Returns:
            String: The Bluetooth MAC address.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        return utils.hex_to_string(
            self.get_parameter(ATStringCommand.BL, apply=False), pretty=False)

    def update_bluetooth_password(self, new_password, apply=True, save=True):
        """
        Changes the Bluetooth password of this XBee with the new one provided.

        Note that your device must include Bluetooth Low Energy support.

        Args:
            new_password (String): New Bluetooth password.
            apply (Boolean, optional, default=`True`): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.
            save (Boolean, optional, default=`True`): `True` to save changes,
                `False` otherwise.

        Raises:
            ValueError: If `new_password` is invalid.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        if not isinstance(new_password, (str, bytes, bytearray)):
            raise ValueError("Password must be a string, bytes, or bytearray")

        import digi.xbee.util.srp
        salt, verifier = digi.xbee.util.srp.create_salted_verification_key(
            self._BLE_API_USERNAME, new_password, hash_alg=digi.xbee.util.srp.HAType.SHA256,
            ng_type=digi.xbee.util.srp.NgGroupParams.NG_1024, salt_len=4)

        self.update_bluetooth_salt_verifier(salt, verifier, apply=apply, save=save)

    def update_bluetooth_salt_verifier(self, salt, verifier, apply=True, save=True):
        """
        Changes the Bluetooth password of this XBee with the new one provided.

        Note that your device must include Bluetooth Low Energy support.

        Args:
            salt (bytes): New Bluetooth password.
            verifier (bytes): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.
            apply (Boolean, optional, default=`True`): `True` to apply changes,
                `False` otherwise, `None` to use `is_apply_changes_enabled()`
                returned value.
            save (Boolean, optional, default=`True`): `True` to save changes,
                `False` otherwise.

        Raises:
            ValueError: If `salt` or `verifier` are invalid.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        if not isinstance(salt, (bytes, bytearray)):
            raise ValueError("Salt must be a bytes or bytearray")
        if not isinstance(verifier, (bytes, bytearray)):
            raise ValueError("Verifier must be a bytes or bytearray")

        apply_changes = apply if apply is not None else self.is_apply_changes_enabled()

        # Ensure the verifier is 128 bytes.
        verifier = (128 - len(verifier)) * b'\x00' + verifier

        # Set the salt.
        self.set_parameter(ATStringCommand.DOLLAR_S, salt, apply=False)

        # Set the verifier (split in 4 settings)
        index = 0
        at_length = int(len(verifier) / 4)

        self.set_parameter(ATStringCommand.DOLLAR_V,
                           verifier[index:(index + at_length)], apply=False)
        index += at_length
        self.set_parameter(ATStringCommand.DOLLAR_W,
                           verifier[index:(index + at_length)], apply=False)
        index += at_length
        self.set_parameter(ATStringCommand.DOLLAR_X,
                           verifier[index:(index + at_length)], apply=False)
        index += at_length
        self.set_parameter(ATStringCommand.DOLLAR_Y,
                           verifier[index:(index + at_length)], apply=apply_changes and not save)

        # Write and apply changes.
        if save:
            self.execute_command(ATStringCommand.WR, apply=apply_changes)

    def update_firmware(self, xml_firmware_file, xbee_firmware_file=None,
                        bootloader_firmware_file=None, timeout=None, progress_callback=None):
        """
        Performs a firmware update operation of the XBee.

        Args:
            xml_firmware_file (String): Path of the XML file that describes the
                firmware to upload.
            xbee_firmware_file (String, optional, default=`None`): Location of
                the XBee binary firmware file.
            bootloader_firmware_file (String, optional, default=`None`): Location
                of the bootloader binary firmware file.
            timeout (Integer, optional, default=`None`): Maximum time to wait
                for target read operations during the update process (seconds).
            progress_callback (Function, optional, default=`None`): Function to
                to receive progress information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            OperationNotSupportedException: If XBee does not support firmware update.
            FirmwareUpdateException: If there is any error during the firmware update.
        """
        from digi.xbee import firmware

        if not self._comm_iface.is_interface_open:
            raise XBeeException("XBee device's communication interface closed.")

        if self.is_remote():
            firmware.update_remote_firmware(self, xml_firmware_file,
                                            firmware_file=xbee_firmware_file,
                                            bootloader_file=bootloader_firmware_file,
                                            timeout=timeout,
                                            max_block_size=self._ota_max_block_size,
                                            progress_callback=progress_callback)
        else:
            if self._operating_mode not in (OperatingMode.API_MODE,
                                            OperatingMode.ESCAPED_API_MODE):
                raise InvalidOperatingModeException(op_mode=self._operating_mode)
            if not self._serial_port:
                raise OperationNotSupportedException(
                    "Firmware update is only supported in local XBee connected by serial")
            firmware.update_local_firmware(self, xml_firmware_file,
                                           xbee_firmware_file=xbee_firmware_file,
                                           bootloader_firmware_file=bootloader_firmware_file,
                                           timeout=timeout,
                                           progress_callback=progress_callback)

    def _autodetect_device(self):
        """
        Performs an autodetection of the local XBee.

        Raises:
            RecoveryException: If there is any error performing the recovery.
            OperationNotSupportedException: If the firmware autodetection is
                not supported in the XBee.
        """
        from digi.xbee import recovery

        if (self.get_hardware_version()
                and self.get_hardware_version().code not in recovery.SUPPORTED_HARDWARE_VERSIONS):
            raise OperationNotSupportedException(
                "Autodetection is only supported in XBee 3 devices")
        recovery.recover_device(self)

    def apply_profile(self, profile_path, timeout=None, progress_callback=None):
        """
        Applies the given XBee profile to the XBee.

        Args:
            profile_path (String): Path of the XBee profile file to apply.
            timeout (Integer, optional, default=`None`): Maximum time to wait
                for target read operations during the apply profile (seconds).
            progress_callback (Function, optional, default=`None`): Function to
                receive progress information. Receives two arguments:

                * The current apply profile task as a String
                * The current apply profile task percentage as an Integer

        Raises:
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            UpdateProfileException: If there is any error applying the XBee profile.
        """
        from digi.xbee import profile

        if not self._comm_iface.is_interface_open:
            raise XBeeException("XBee device's communication interface closed.")
        if (not self.is_remote()
                and self._operating_mode not in (OperatingMode.API_MODE,
                                                 OperatingMode.ESCAPED_API_MODE)):
            raise InvalidOperatingModeException(op_mode=self._operating_mode)

        profile.apply_xbee_profile(self, profile_path, timeout=timeout,
                                   progress_callback=progress_callback)

    def get_file_manager(self):
        """
        Returns the file system manager for the XBee.

        Returns:
             :class:`.FileSystemManager`: The file system manager.

        Raises:
            FileSystemNotSupportedException: If the XBee does not support
                filesystem.
        """
        if not self._file_manager:
            self._file_manager = FileSystemManager(self)

        return self._file_manager

    def _get_ai_status(self):
        """
        Returns the current association status of this XBee. It indicates
        occurrences of errors during the modem initialization and connection.

        Returns:
            :class:`.AssociationIndicationStatus`: The XBee association
                indication status.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        value = self.get_parameter(ATStringCommand.AI, apply=False)
        return AssociationIndicationStatus.get(utils.bytes_to_int(value))

    def _force_disassociate(self):
        """
        Forces this XBee  to immediately disassociate from the network and
        re-attempt to associate.

        Only valid for End Devices.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self.execute_command(ATStringCommand.DA, apply=False)

    def _get_next_frame_id(self):
        """
        Returns the next frame ID of the XBee.

        Returns:
            Integer: The next frame ID of the XBee.
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
        Returns the Operating mode (AT, API or API escaped) of this XBee if it
        is local, and the operating mode of the local XBee for a remote node.

        Returns:
            :class:`.OperatingMode`: The operating mode of the local XBee.
        """
        if self.is_remote():
            return self._local_xbee_device.operating_mode
        return self._operating_mode

    @staticmethod
    def _before_send_method(func):
        """
        Decorator. Used to check the operating mode and the COM port's state
        before a sending operation.
        """
        @wraps(func)
        def dec_function(self, *args, **kwargs):
            if not self._comm_iface.is_interface_open:
                raise XBeeException("XBee device's communication interface closed.")
            if self._operating_mode not in (OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE):
                raise InvalidOperatingModeException(op_mode=self._operating_mode)
            return func(self, *args, **kwargs)
        return dec_function

    @staticmethod
    def _after_send_method(func):
        """
        Decorator. Used to check if the response's transmit status is success
        after a sending operation.
        """
        @wraps(func)
        def dec_function(*args, **kwargs):
            response = func(*args, **kwargs)
            if response.transmit_status not in (TransmitStatus.SUCCESS,
                                                TransmitStatus.SELF_ADDRESSED):
                raise TransmitException(transmit_status=response.transmit_status)
            return response
        return dec_function

    def _get_packet_by_id(self, frame_id):
        """
        Reads packets until there is one packet found with the provided frame ID.

        Args:
            frame_id (Integer): Frame ID to use for. Must be between 0 and 255.

        Returns:
            :class:XBeePacket: First XBee packet read whose frame ID matches
                the provided one.

        Raises:
            ValueError: If `frame_id` is less than 0 or greater than 255.
            TimeoutException: If there was not any XBee packet matching the
                provided frame ID that could be read.
        """
        if not 0 <= frame_id <= 255:
            raise ValueError("Frame ID must be between 0 and 255.")

        queue = self._packet_listener.get_queue()

        packet = queue.get_by_id(frame_id, timeout=XBeeDevice.TIMEOUT_READ_PACKET)

        return packet

    def _add_packet_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.PacketReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The received packet as a :class:`.XBeeAPIPacket`
        """
        self._packet_listener.add_packet_received_callback(callback)

    def _del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.PacketReceived` event.

        Args:
            callback (Function): The callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.PacketReceived` event.
        """
        if callback in self._packet_listener.get_packet_received_callbacks():
            self._packet_listener.del_packet_received_callback(callback)

    def _send_packet_sync_and_get_response(self, packet_to_send, timeout=None):
        """
        Sends the packet and waits for its corresponding response.

        Args:
            packet_to_send (:class:`.XBeePacket`): The packet to transmit.
            timeout (Integer, optional, default=`None`): Number of seconds to
                wait. -1 to wait indefinitely.

        Returns:
            :class:`.XBeePacket`: Received response packet.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TimeoutException: If response is not received in the configured
                timeout.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBeePacket`
        """
        if not self._packet_listener.is_running():
            raise XBeeException("Packet listener is not running.")

        sender = SyncRequestSender(self, packet_to_send,
                                   self._timeout if timeout is None else timeout)
        return sender.send()

    def _send_packet(self, packet, sync=False):
        """
        Sends the packet and waits for the response. The packet to send is
        escaped depending on the current operating mode.

        This method can be synchronous or asynchronous.

        If synchronous, this method discards all response packets until it finds
        the one that has the appropriate frame ID, that is, the sent packet's
        frame ID.

        If asynchronous, this method does not wait for any response and returns
        `None`.

        Args:
            packet (:class:`.XBeePacket`): The packet to send.
            sync (Boolean): `True` to wait for the response of the sent packet
                and return it, `False` otherwise.

        Returns:
            :class:`.XBeePacket`: Response packet if `sync` is `True`, `None`
                otherwise.

        Raises:
            TimeoutException: If `sync` is `True` and the response packet for
                the sent one cannot be read.
            InvalidOperatingModeException: If the XBee operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the packet listener is not running or the XBee's
                communication interface is closed.

        .. seealso::
           | :class:`.XBeePacket`
        """
        if not self._packet_listener.is_running():
            raise XBeeException("Packet listener is not running.")

        self._packet_sender.send_packet(packet)

        return self._get_packet_by_id(packet.frame_id) if sync else None

    def _get_routes(self, route_cb=None, finished_cb=None, timeout=None):
        """
        Returns the routes of this XBee. If `route_cb` is not defined, the
        process blocks until the complete routing table is read.

        Args:
            route_cb (Function, optional, default=`None`): Method called when
                a new route is received. Receives two arguments:

                * The XBee that owns this new route.
                * The new route.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that executed the ZDO command.
                * A list with the discovered routes.
                * An error message if something went wrong.

            timeout (Float, optional, default=`RouteTableReader.DEFAULT_TIMEOUT`): The
                ZDO command timeout in seconds.
        Returns:
            List: List of :class:`.Route` when `route_cb` is not defined,
                `None` otherwise (in this case routes are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Route`
        """
        from digi.xbee.models.zdo import RouteTableReader
        reader = RouteTableReader(self, configure_ao=True,
                                  timeout=timeout if timeout else RouteTableReader.DEFAULT_TIMEOUT)

        return reader.get_route_table(route_cb=route_cb, finished_cb=finished_cb)

    def _get_neighbors(self, neighbor_cb=None, finished_cb=None, timeout=None):
        """
        Returns the neighbors of this XBee. If `neighbor_cb` is not defined:
           * In Zigbee and SmartEnergy the process blocks until the complete
             neighbor table is read.
           * In DigiMesh the process blocks the provided timeout.

        Args:
            neighbor_cb (Function, optional, default=`None`): Function called
                when a new neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            finished_cb (Function, optional, default=`None`): Function to
                execute when the process finishes. Receives three arguments:

                * The XBee device that is searching for its neighbors.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=`None`): The timeout in seconds.
        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee,
                Smart Energy or DigiMesh.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        if self.get_protocol() in (XBeeProtocol.ZIGBEE, XBeeProtocol.SMART_ENERGY):
            from digi.xbee.models.zdo import NeighborTableReader
            reader = NeighborTableReader(
                self, configure_ao=True,
                timeout=timeout if timeout else NeighborTableReader.DEFAULT_TIMEOUT)

            neighbors = reader.get_neighbor_table(neighbor_cb=neighbor_cb,
                                                  finished_cb=finished_cb)
        elif self.get_protocol() in (XBeeProtocol.DIGI_MESH, XBeeProtocol.XLR_DM,
                                     XBeeProtocol.XTEND_DM, XBeeProtocol.SX):
            from digi.xbee.models.zdo import NeighborFinder
            finder = NeighborFinder(
                self, timeout=timeout if timeout else NeighborFinder.DEFAULT_TIMEOUT)

            neighbors = finder.get_neighbors(neighbor_cb=neighbor_cb,
                                             finished_cb=finished_cb)
        else:
            raise OperationNotSupportedException("Get neighbors is not supported in %s"
                                                 % self.get_protocol().description)

        if not neighbors:
            return neighbors

        network = self.get_local_xbee_device().get_network() if self.is_remote() \
            else self.get_network()
        for neighbor in neighbors:
            n_node = neighbor.node
            is_local = bool(
                n_node.get_64bit_addr() == (self.get_local_xbee_device().get_64bit_addr() if self.is_remote() else self.get_64bit_addr()))
            node = network._add_remote_from_attr(
                NetworkEventReason.NEIGHBOR,
                x64bit_addr="local" if is_local else n_node.get_64bit_addr(),
                x16bit_addr=n_node.get_16bit_addr(), node_id=n_node.get_node_id())
            node_from_network = network.get_device_by_64(n_node.get_64bit_addr())
            if not node_from_network:
                node_from_network = network.add_remote(node)

            neighbor._node = node_from_network

        return neighbors

    @property
    def reachable(self):
        """
        Returns whether the XBee is reachable.

        Returns:
            Boolean: `True` if the device is reachable, `False` otherwise.
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

    @property
    def log(self):
        """
        Returns the XBee logger.

        Returns:
            :class:`.Logger`: The XBee device logger.
        """
        return self._log

    @property
    def br(self):
        """
        Returns the BR value of the device.

        Returns:
            Integer: The BR value of the device.
        """
        return self._br


class XBeeDevice(AbstractXBeeDevice):
    """
    This class represents a non-remote generic XBee.

    This class has fields that are events. Its recommended to use only the
    append() and remove() method on them, or -= and += operators.
    If you do something more with them, it's for your own risk.
    """

    __DEFAULT_GUARD_TIME = 1.2  # seconds
    """
    Timeout to wait after entering and exiting command mode in seconds.

    It is used to determine the operating mode of the module (this library only
    supports API modes, not AT (transparent) mode).
    """

    __TIMEOUT_RESET = 5  # seconds
    """
    Timeout to wait when resetting the module.
    """

    TIMEOUT_READ_PACKET = 3  # seconds
    """
    Timeout to read packets.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 exclusive=True, comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.XBeeDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer, optional, default=`None`): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 4): Read timeout (in seconds).
            exclusive (Boolean, optional, default=`True`): Set serial port
                exclusive access mode (POSIX only).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by PySerial's Serial class constructor.

        .. seealso::
           | PySerial documentation: http://pyserial.sourceforge.net
        """
        super().__init__(
            serial_port=XBeeSerialPort(baud_rate=baud_rate, port=port,
                                       data_bits=data_bits, stop_bits=stop_bits,
                                       parity=parity, flow_control=flow_control,
                                       timeout=_sync_ops_timeout,
                                       exclusive=exclusive) if comm_iface is None else None,
            sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        # If there is no XBeeNetwork object provided by comm_iface,
        # initialize a default XBeeNetwork
        if not comm_iface or comm_iface.get_network(self) is None:
            self._network = self._init_network()
        else:
            self._network = None

        self.__packet_queue = None
        self.__data_queue = None
        self.__explicit_queue = None

        self.__modem_status_received = False

        self.__tmp_dm_routes_to = {}
        self.__tmp_dm_to_insert = []
        self.__tmp_dm_routes_lock = threading.Lock()
        self.__route_received = RouteReceived()
        self.__stats = Statistics()

    @classmethod
    def create_xbee_device(cls, comm_port_data):
        """
        Creates and returns an :class:`.XBeeDevice` from data of the port to
        which is connected.

        Args:
            comm_port_data (Dictionary): Dictionary with all comm port data needed.
            The dictionary keys are:
                | "baudRate"    --> Baud rate.
                | "port"        --> Port number.
                | "bitSize"     --> Bit size.
                | "stopBits"    --> Stop bits.
                | "parity"      --> Parity.
                | "flowControl" --> Flow control.
                | "timeout" for --> Timeout for synchronous operations (in seconds).

        Returns:
            :class:`.XBeeDevice`: XBee object created.

        Raises:
            SerialException: If the port to open does not exist or is already opened.

        .. seealso::
           | :class:`.XBeeDevice`
        """
        return XBeeDevice(comm_port_data["port"], comm_port_data["baudRate"],
                          data_bits=comm_port_data["bitSize"],
                          stop_bits=comm_port_data["stopBits"],
                          parity=comm_port_data["parity"],
                          flow_control=comm_port_data["flowControl"],
                          _sync_ops_timeout=comm_port_data["timeout"])

    def open(self, force_settings=False):
        """
        Opens the communication with the XBee and loads information about it.

        Args:
            force_settings (Boolean, optional, default=`False`): `True` to open
                the device ensuring/forcing that the specified serial settings
                are applied even if the current configuration is different,
                `False` to open the device with the current configuration.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee is already opened.
        """
        if self._is_open:
            raise XBeeException("XBee device already open.")

        self._comm_iface.open()
        self._log.info("%s port opened", self._comm_iface)
        xbee_info = self._comm_iface.get_local_xbee_info()
        if xbee_info:
            self._operating_mode = OperatingMode.get(xbee_info[0])
        elif self._operating_mode not in (OperatingMode.API_MODE,
                                          OperatingMode.ESCAPED_API_MODE):
            self._operating_mode = OperatingMode.API_MODE
        if not self._packet_sender:
            self._packet_sender = PacketSender(self)
        self._restart_packet_listener()

        try:
            self._do_open()
        except XBeeException as exc:
            if not force_settings:
                raise exc
            self.log.debug("Could not open the port with default setting, "
                           "forcing settings using recovery: %s", str(exc))
            if self._serial_port is None:
                raise XBeeException("Can not open the port by forcing the settings, "
                                    "it is only supported for Serial") from None
            self._autodetect_device()
            self.open(force_settings=False)

    def _do_open(self):
        """
        Opens the communication with the XBee and loads information about it.

        Raises:
            TimeoutException: If there is any problem with the communication.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee is already opened.
        """
        xbee_info = self._comm_iface.get_local_xbee_info() if self._comm_iface else ()
        if xbee_info:
            self._operating_mode = OperatingMode.get(xbee_info[0])
            self._hardware_version = HardwareVersion.get(xbee_info[1])
            self._firmware_version = utils.int_to_bytes(xbee_info[2])
            self._br = xbee_info[7]
            self._protocol = XBeeProtocol.determine_protocol(
                self._hardware_version.code, self._firmware_version,
                br_value=self._br)
            self._64bit_addr = XBee64BitAddress.from_hex_string(xbee_info[3])
            self._16bit_addr = XBee16BitAddress.from_hex_string(xbee_info[4])
            self._node_id = xbee_info[5]
            self._role = Role.get(xbee_info[6])

        else:
            # Determine the operating mode of the XBee device.
            self._operating_mode = self._determine_operating_mode()
            if self._operating_mode == OperatingMode.UNKNOWN:
                self.close()
                raise InvalidOperatingModeException(message="Could not determine operating mode")
            if self._operating_mode not in (OperatingMode.API_MODE,
                                            OperatingMode.ESCAPED_API_MODE):
                self.close()
                raise InvalidOperatingModeException(op_mode=self._operating_mode)

            # Read the device info (obtain its parameters and protocol).
            self.read_device_info()

        self._is_open = True

    def close(self):
        """
        Closes the communication with the XBee.

        This method guarantees that all threads running are stopped and the
        serial port is closed.
        """
        if self._network is not None:
            self._network.stop_discovery_process()

        if self._packet_listener is not None:
            self._packet_listener.stop()

        if self._comm_iface is not None and self._comm_iface.is_interface_open:
            self._comm_iface.close()
            self._log.info("%s closed", self._comm_iface)

        self._is_open = False

    @property
    def serial_port(self):
        """
        Returns the serial port associated to the XBee, if any.

        Returns:
            :class:`.XBeeSerialPort`: Serial port of the XBee. `None` if the
                local XBee does not use serial communication.

        .. seealso::
           | :class:`.XBeeSerialPort`
        """
        return self._serial_port

    @property
    def comm_iface(self):
        """
        Returns the hardware interface associated to the XBee.

        Returns:
            :class:`.XBeeCommunicationInterface`: Hardware interface of the XBee.

        .. seealso::
           | :class:`.XBeeCommunicationInterface`
        """
        return self._comm_iface

    @property
    def operating_mode(self):
        """
        Returns the operating mode of this XBee.

        Returns:
            :class:`.OperatingMode`. This XBee operating mode.
        """
        return super()._get_operating_mode()

    @property
    def stats(self):
        """
        Gets the statistics for this XBee.

        Returns:
            :class:`.Statistics`. XBee statistics.
        """
        return self._comm_iface.get_stats() if self._comm_iface.get_stats() else self.__stats

    @AbstractXBeeDevice._before_send_method
    def get_parameter(self, parameter, parameter_value=None, apply=None):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
        """
        return super().get_parameter(
            parameter, parameter_value=parameter_value, apply=apply)

    @AbstractXBeeDevice._before_send_method
    def set_parameter(self, parameter, value, apply=None):
        """
        Override.

        See:
            :meth:`.AbstractXBeeDevice.set_parameter`
        """
        super().set_parameter(parameter, value, apply=apply)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_data_64_16(self, x64addr, x16addr, data,
                         transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to the remote XBee with the
        given 64-bit/16-bit address.

        This method waits for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee, :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if unknown.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x64addr`, `x16addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        packet = TransmitPacket(self.get_next_frame_id(), x64addr, x16addr,
                                0, transmit_options, rf_data=data)
        return self.send_packet_sync_and_get_response(packet)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_data_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee with the given
        64-bit address.

        This method waits for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x64addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        if self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            packet = TX64Packet(self.get_next_frame_id(), x64addr,
                                transmit_options, rf_data=data)
        else:
            packet = TransmitPacket(self.get_next_frame_id(), x64addr,
                                    XBee16BitAddress.UNKNOWN_ADDRESS, 0,
                                    transmit_options, rf_data=data)
        return self.send_packet_sync_and_get_response(packet)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_data_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee with the given
        16-bit address.

        This method will wait for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x16addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        packet = TX16Packet(self.get_next_frame_id(), x16addr,
                            transmit_options, rf_data=data)
        return self.send_packet_sync_and_get_response(packet)

    def send_data(self, remote_xbee, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee synchronously.

        This method will wait for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `remote_xbee` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
           | :class:`.XBeePacket`
        """
        if remote_xbee is None:
            raise ValueError("Remote XBee device cannot be None")

        protocol = self.get_protocol()
        if protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_POINT):
            if (remote_xbee.get_64bit_addr() is not None
                    and remote_xbee.get_16bit_addr() is not None):
                return self._send_data_64_16(remote_xbee.get_64bit_addr(),
                                             remote_xbee.get_16bit_addr(),
                                             data, transmit_options=transmit_options)
            if remote_xbee.get_64bit_addr() is not None:
                return self._send_data_64(remote_xbee.get_64bit_addr(), data,
                                          transmit_options=transmit_options)
            return self._send_data_64_16(XBee64BitAddress.UNKNOWN_ADDRESS,
                                         remote_xbee.get_16bit_addr(),
                                         data, transmit_options=transmit_options)
        if protocol == XBeeProtocol.RAW_802_15_4:
            if remote_xbee.get_64bit_addr() is not None:
                return self._send_data_64(remote_xbee.get_64bit_addr(), data,
                                          transmit_options=transmit_options)
            return self._send_data_16(remote_xbee.get_16bit_addr(), data,
                                      transmit_options=transmit_options)

        return self._send_data_64(remote_xbee.get_64bit_addr(), data,
                                  transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    def _send_data_async_64_16(self, x64addr, x16addr, data,
                               transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 64-bit/16-bit address.

        This method does not wait for a response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee, :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if unknown.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x64addr`, `x16addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        packet = TransmitPacket(self.get_next_frame_id(), x64addr, x16addr, 0,
                                transmit_options, rf_data=data)
        self.send_packet(packet)

    @AbstractXBeeDevice._before_send_method
    def _send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 64-bit address.

        This method does not wait for a response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x64addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        if self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            packet = TX64Packet(self.get_next_frame_id(), x64addr,
                                transmit_options, rf_data=data)
        else:
            packet = TransmitPacket(self.get_next_frame_id(), x64addr,
                                    XBee16BitAddress.UNKNOWN_ADDRESS, 0,
                                    transmit_options, rf_data=data)
        self.send_packet(packet)

    @AbstractXBeeDevice._before_send_method
    def _send_data_async_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 16-bit address.

        This method does not wait for a response.

        Args:
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x16addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        packet = TX16Packet(self.get_next_frame_id(),
                            x16addr,
                            transmit_options,
                            rf_data=data)
        self.send_packet(packet)

    def send_data_async(self, remote_xbee, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee.

        This method does not wait for a response.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): the remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `remote_xbee` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
        """
        if remote_xbee is None:
            raise ValueError("Remote XBee device cannot be None")

        protocol = self.get_protocol()
        if protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.DIGI_POINT):
            if (remote_xbee.get_64bit_addr() is not None
                    and remote_xbee.get_16bit_addr() is not None):
                self._send_data_async_64_16(remote_xbee.get_64bit_addr(),
                                            remote_xbee.get_16bit_addr(),
                                            data, transmit_options=transmit_options)
            elif remote_xbee.get_64bit_addr() is not None:
                self._send_data_async_64(remote_xbee.get_64bit_addr(), data,
                                         transmit_options=transmit_options)
            else:
                self._send_data_async_64_16(XBee64BitAddress.UNKNOWN_ADDRESS,
                                            remote_xbee.get_16bit_addr(),
                                            data, transmit_options=transmit_options)
        elif protocol == XBeeProtocol.RAW_802_15_4:
            if remote_xbee.get_64bit_addr() is not None:
                self._send_data_async_64(remote_xbee.get_64bit_addr(), data,
                                         transmit_options=transmit_options)
            else:
                self._send_data_async_16(remote_xbee.get_16bit_addr(), data,
                                         transmit_options=transmit_options)
        else:
            self._send_data_async_64(remote_xbee.get_64bit_addr(), data,
                                     transmit_options=transmit_options)

    def send_data_broadcast(self, data, transmit_options=TransmitOptions.NONE.value):
        """
        Sends the provided data to all the XBee nodes of the network (broadcast).

        This method blocks until a success or error transmit status arrives or
        the configured receive timeout expires.

        The received timeout is configured using method
        :meth:`.AbstractXBeeDevice.set_sync_ops_timeout` and can be consulted
        with :meth:`.AbstractXBeeDevice.get_sync_ops_timeout` method.

        Args:
            data (String or Bytearray): Data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.
        """
        return self._send_data_64(XBee64BitAddress.BROADCAST_ADDRESS, data,
                                  transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    def send_user_data_relay(self, local_interface, data):
        """
        Sends the given data to the given XBee local interface.

        Args:
            local_interface (:class:`.XBeeLocalInterface`): Destination XBee
                local interface.
            data (Bytearray): Data to send.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ValueError: If `local_interface` is `None`.
            XBeeException: If there is any problem sending the User Data Relay.

        .. seealso::
           | :class:`.XBeeLocalInterface`
        """
        if local_interface is None:
            raise ValueError("Destination interface cannot be None")

        # Send the packet asynchronously since User Data Relay frames only
        # receive a transmit status if an error occurs
        self.send_packet(UserDataRelayPacket(self.get_next_frame_id(),
                                             local_interface, data=data))

    def send_bluetooth_data(self, data):
        """
        Sends the given data to the Bluetooth interface using a User Data Relay frame.

        Args:
            data (Bytearray): Data to send.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If there is any problem sending the data.

        .. seealso::
           | :meth:`.XBeeDevice.send_micropython_data`
           | :meth:`.XBeeDevice.send_user_data_relay`
        """
        self.send_user_data_relay(XBeeLocalInterface.BLUETOOTH, data)

    def send_micropython_data(self, data):
        """
        Sends the given data to the MicroPython interface using a User Data
        Relay frame.

        Args:
            data (Bytearray): Data to send.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If there is any problem sending the data.

        .. seealso::
           | :meth:`.XBeeDevice.send_bluetooth_data`
           | :meth:`.XBeeDevice.send_user_data_relay`
        """
        self.send_user_data_relay(XBeeLocalInterface.MICROPYTHON, data)

    def read_data(self, timeout=None):
        """
        Reads new data received by this XBee.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            timeout (Integer, optional): Read timeout in seconds. If `None`,
                this method is non-blocking and returns `None` if no data is available.

        Returns:
            :class:`.XBeeMessage`: Read message or `None` if this XBee did not
                receive new data.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no data was
                received during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBeeMessage`
        """
        return self.__read_data_packet(None, timeout, False)

    def read_data_from(self, remote_xbee, timeout=None):
        """
        Reads new data received from the given remote XBee.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee that sent the data.
            timeout (Integer, optional): Read timeout in seconds. If `None`,
                this method is non-blocking and returns `None` if no data is available.

        Returns:
            :class:`.XBeeMessage`: Read message sent by `remote_xbee` or `None`
                if this XBee did not receive new data.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no data was received
                during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBeeMessage`
           | :class:`.RemoteXBeeDevice`
        """
        return self.__read_data_packet(remote_xbee, timeout, False)

    def has_packets(self):
        """
        Returns if there are pending packets to read. This does not include
        explicit packets.

        Return:
            Boolean: `True` if there are pending packets, `False` otherwise.

        .. seealso::
           | :meth:`.XBeeDevice.has_explicit_packets`
        """
        return not self.__packet_queue.empty()

    def has_explicit_packets(self):
        """
        Returns if there are pending explicit packets to read. This does not
        include non-explicit packets.

        Return:
            Boolean: `True` if there are pending packets, `False` otherwise.

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
            if modem_status in (ModemStatus.HARDWARE_RESET,
                                ModemStatus.WATCHDOG_TIMER_RESET):
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
        Adds a callback for the event :class:`.PacketReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The received packet as a :class:`.XBeeAPIPacket`.
        """
        super()._add_packet_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.DataReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The data received as an :class:`.XBeeMessage`.
        """
        self._packet_listener.add_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_modem_status_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.ModemStatusReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The modem status as a :class:`.ModemStatus`.
        """
        self._packet_listener.add_modem_status_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_io_sample_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.IOSampleReceived`.

        Args:
            callback (Function): The callback. Receives three arguments.

                * The received IO sample as an :class:`.IOSample`.
                * The remote XBee which sent the packet as a :class:`.RemoteXBeeDevice`.
                * The time in which the packet was received as an Integer.
        """
        self._packet_listener.add_io_sample_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_expl_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.ExplicitDataReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The explicit data received as a :class:`.ExplicitXBeeMessage`.
        """
        self._packet_listener.add_explicit_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_user_data_relay_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.RelayDataReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The relay data as a :class:`.UserDataRelayMessage`.
        """
        self._packet_listener.add_user_data_relay_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_bluetooth_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.BluetoothDataReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The Bluetooth data as a Bytearray.
        """
        self._packet_listener.add_bluetooth_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_micropython_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.MicroPythonDataReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The MicroPython data as a Bytearray.
        """
        self._packet_listener.add_micropython_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_socket_state_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.SocketStateReceived`.

        Args:
            callback (Function): The callback. Receives two arguments.

                * The socket ID as an Integer.
                * The state received as a :class:`.SocketState`.
        """
        self._packet_listener.add_socket_state_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_socket_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.SocketDataReceived`.

        Args:
            callback (Function): The callback. Receives two arguments.

                * The socket ID as an Integer.
                * The data received as Bytearray.
        """
        self._packet_listener.add_socket_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_socket_data_received_from_callback(self, callback):
        """
        Adds a callback for the event :class:`.SocketDataReceivedFrom`.

        Args:
            callback (Function): The callback. Receives three arguments.

                * The socket ID as an Integer.
                * Source address pair (host, port) where host is a string
                    representing an IPv4 address like '100.50.200.5', and port
                    is an integer.
                * The data received as Bytearray.
        """
        self._packet_listener.add_socket_data_received_from_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def add_fs_frame_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.FileSystemFrameReceived`.

        Args:
            callback (Function): The callback. Receives four arguments.

                * Source (:class:`.AbstractXBeeDevice`): The node that sent the
                  file system frame.
                * Frame id (Integer): The received frame id.
                * Command (:class:`.FSCmd`): The file system command.
                * Receive options (Integer): Bitfield indicating receive options.

        .. seealso::
           | :class:`.AbstractXBeeDevice`
           | :class:`.FSCmd`
           | :class:`.ReceiveOptions`
        """
        self._packet_listener.add_fs_frame_received_callback(callback)

    def del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.PacketReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        super()._del_packet_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DataReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_data_received_callbacks():
            self._packet_listener.del_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_modem_status_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.ModemStatusReceived`
        event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_modem_status_received_callbacks():
            self._packet_listener.del_modem_status_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_io_sample_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.IOSampleReceived`
        event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_io_sample_received_callbacks():
            self._packet_listener.del_io_sample_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_expl_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.ExplicitDataReceived`
        event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_explicit_data_received_callbacks():
            self._packet_listener.del_explicit_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_user_data_relay_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.RelayDataReceived`
        event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_user_data_relay_received_callbacks():
            self._packet_listener.del_user_data_relay_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_bluetooth_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.BluetoothDataReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_bluetooth_data_received_callbacks():
            self._packet_listener.del_bluetooth_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_micropython_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.MicroPythonDataReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_micropython_data_received_callbacks():
            self._packet_listener.del_micropython_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_socket_state_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.SocketStateReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_socket_state_received_callbacks():
            self._packet_listener.del_socket_state_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_socket_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.SocketDataReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_socket_data_received_callbacks():
            self._packet_listener.del_socket_data_received_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_socket_data_received_from_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.SocketDataReceivedFrom` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_socket_data_received_from_callbacks():
            self._packet_listener.del_socket_data_received_from_callback(callback)

    @AbstractXBeeDevice._before_send_method
    def del_fs_frame_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.FileSystemFrameReceived` event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_fs_frame_received_callbacks():
            self._packet_listener.del_fs_frame_received_callback(callback)

    def get_xbee_device_callbacks(self):
        """
        Returns this XBee internal callbacks for process received packets.

        This method is called by the PacketListener associated with this XBee
        to get its callbacks. These callbacks are executed before user callbacks.

        Returns:
            :class:`.PacketReceived`
        """
        api_callbacks = PacketReceived()

        if self.serial_port:
            api_callbacks.append(self._packet_sender.at_response_received_cb)
            api_callbacks.append(self._update_rx_stats_cb)

        if not self._network:
            return api_callbacks

        for i in self._network.get_discovery_callbacks():
            api_callbacks.append(i)

        return api_callbacks

    def is_open(self):
        """
        Returns whether this XBee is open.

        Returns:
            Boolean. `True` if this XBee is open, `False` otherwise.
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
        Returns the network of this XBee.

        Returns:
            :class:`.XBeeNetwork`: The XBee network.
        """
        comm_network = self._comm_iface.get_network(self) if self._comm_iface else None
        if comm_network:
            return comm_network

        if self._network is None:
            self._network = self._init_network()

        return self._network

    def _restart_packet_listener(self):
        """
        Restarts the XBee packet listener.
        """
        # Store already registered callbacks
        packet_cbs = self._packet_listener.get_packet_received_callbacks() \
            if self._packet_listener else None
        packet_from_cbs = self._packet_listener.get_packet_received_from_callbacks() \
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
        fs_frame_cbs = self._packet_listener.get_fs_frame_received_callbacks() \
            if self._packet_listener else None
        ble_gap_scan_cbs = self._packet_listener.get_ble_gap_scan_received_callbacks() \
            if self._packet_listener else None
        ble_gap_scan_status_cbs = self._packet_listener.get_ble_gap_scan_status_received_callbacks() \
            if self._packet_listener else None

        # Initialize the packet listener
        self._packet_listener = None
        self._packet_listener = PacketListener(self._comm_iface, self)
        self.__packet_queue = self._packet_listener.get_queue()
        self.__data_queue = self._packet_listener.get_data_queue()
        self.__explicit_queue = self._packet_listener.get_explicit_queue()

        # Restore callbacks if any
        self._packet_listener.add_packet_received_callback(packet_cbs)
        self._packet_listener.add_packet_received_from_callback(packet_from_cbs)
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
        self._packet_listener.add_fs_frame_received_callback(fs_frame_cbs)
        self._packet_listener.add_ble_gap_advertisement_received_callback(ble_gap_scan_cbs)
        self._packet_listener.add_ble_gap_scan_status_received_callback(ble_gap_scan_status_cbs)

        self._packet_listener.start()
        self._packet_listener.wait_until_started()

    def _init_network(self):
        """
        Initializes a new network.

        Returns:
            :class:`.XBeeDevice.XBeeNetwork`: Initialized network.
        """
        return XBeeNetwork(self)

    def read_expl_data(self, timeout=None):
        """
        Reads new explicit data received by this XBee.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            timeout (Integer, optional): Read timeout in seconds. If `None`,
                this method is non-blocking and returns `None` if there is no
                explicit data available.

        Returns:
            :class:`.ExplicitXBeeMessage`: Read message or `None` if this XBee
                did not receive new explicit data.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no explicit data was
                received during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
        """
        return self._read_expl_data(timeout=timeout)

    def read_expl_data_from(self, remote_xbee, timeout=None):
        """
        Reads new explicit data received from the given remote XBee.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee that sent the explicit data.
            timeout (Integer, optional): Read timeout in seconds. If `None`,
                this method is non-blocking and returns `None` if there is no
                data available.

        Returns:
            :class:`.ExplicitXBeeMessage`: Read message sent by `remote_xbee`
                or `None` if this XBee did not receive new data from that node.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no explicit data was
                received during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
           | :class:`.RemoteXBeeDevice`
        """
        return self._read_expl_data_from(remote_xbee, timeout=timeout)

    def send_expl_data(self, remote_xbee, data, src_endpoint, dest_endpoint,
                       cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. Sends the provided explicit data to the given XBee,
        source and destination end points, cluster and profile ids.

        This method blocks until a success or error response arrives or the
        configured receive timeout expires. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: Response packet obtained after sending data.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `cluster_id` or `profile_id` is less than 0x0 or
                greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
           | :class:`.XBeePacket`
        """
        return self._send_expl_data(
            remote_xbee, data, src_endpoint, dest_endpoint, cluster_id,
            profile_id, transmit_options=transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id,
                                 profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Sends the provided explicit data to all the XBee nodes of the network
        (broadcast) using provided source and destination end points, cluster
        and profile ids.

        This method blocks until a success or error transmit status arrives or
        the configured receive timeout expires. The received timeout is
        configured using the :meth:`.AbstractXBeeDevice.set_sync_ops_timeout`
        method and can be consulted with method
        :meth:`.AbstractXBeeDevice.get_sync_ops_timeout`.

        Args:
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `cluster_id` or `profile_id` is less than 0x0 or
                greater than 0xFFFF.

        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data`
        """
        return self._send_expl_data_broadcast(
            data, src_endpoint, dest_endpoint, cluster_id, profile_id,
            transmit_options=transmit_options)

    def send_expl_data_async(self, remote_xbee, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. Sends the provided explicit data to the given XBee,
        source and destination end points, cluster and profile ids.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `cluster_id` or `profile_id` is less than 0x0 or
                greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
        """
        self._send_expl_data_async(remote_xbee, data, src_endpoint,
                                   dest_endpoint, cluster_id, profile_id,
                                   transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def _send_expl_data(self, remote_xbee, data, src_endpoint, dest_endpoint,
                        cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. Sends the provided explicit data to the given XBee,
        source and destination end points, cluster and profile ids.

        This method blocks until a success or error response arrives or the
        configured receive timeout expires. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: Response packet obtained after sending data.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `cluster_id` or `profile_id` is less than 0x0 or
                greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
           | :class:`.XBeePacket`
        """
        return self.send_packet_sync_and_get_response(
            self.__build_expldata_packet(remote_xbee, data, src_endpoint,
                                         dest_endpoint, cluster_id, profile_id,
                                         broadcast=False,
                                         transmit_options=transmit_options))

    @AbstractXBeeDevice._before_send_method
    def _send_expl_data_async(self, remote_xbee, data, src_endpoint, dest_endpoint,
                              cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. Sends the provided explicit data to the given XBee,
        source and destination end points, cluster and profile ids.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `cluster_id` or `profile_id` is less than 0x0 or
                greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
        """
        self.send_packet(
            self.__build_expldata_packet(remote_xbee, data, src_endpoint,
                                         dest_endpoint, cluster_id, profile_id,
                                         broadcast=False, transmit_options=transmit_options))

    def _send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                  transmit_options=TransmitOptions.NONE.value):
        """
        Sends the provided explicit data to all the XBee nodes of the network
        (broadcast) using provided source and destination end points, cluster
        and profile ids.

        This method blocks until a success or error transmit status arrives or
        the configured receive timeout expires. The received timeout is
        configured using the :meth:`.AbstractXBeeDevice.set_sync_ops_timeout`
        method and can be consulted with method
        :meth:`.AbstractXBeeDevice.get_sync_ops_timeout`.

        Args:
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `cluster_id` or `profile_id` is less than 0x0 or
                greater than 0xFFFF.

        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data`
        """
        return self.send_packet_sync_and_get_response(
            self.__build_expldata_packet(None, data, src_endpoint, dest_endpoint,
                                         cluster_id, profile_id, broadcast=True,
                                         transmit_options=transmit_options))

    def _read_expl_data(self, timeout=None):
        """
        Reads new explicit data received by this XBee.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            timeout (Integer, optional): Read timeout in seconds. If `None`,
                this method is non-blocking and returns `None` if there is no
                explicit data available.

        Returns:
            :class:`.ExplicitXBeeMessage`: Read message or `None` if this XBee
                did not receive new explicit data.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no explicit data was
                received during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
        """
        return self.__read_data_packet(None, timeout, True)

    def _read_expl_data_from(self, remote_xbee, timeout=None):
        """
        Reads new explicit data received from the given remote XBee.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee that sent the explicit data.
            timeout (Integer, optional): Read timeout in seconds. If `None`,
                this method is non-blocking and returns `None` if there is no
                data available.

        Returns:
            :class:`.ExplicitXBeeMessage`: Read message sent by `remote_xbee`
                or `None` if this XBee did not receive new data from that node.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no explicit data was
                received during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.ExplicitXBeeMessage`
           | :class:`.RemoteXBeeDevice`
        """
        return self.__read_data_packet(remote_xbee, timeout, True)

    @AbstractXBeeDevice._before_send_method
    def __read_data_packet(self, remote, timeout, explicit):
        """
        Reads a new data packet received by this XBee during the provided timeout.

        If `timeout` is specified, this method blocks until new data is received
        or the timeout expires, throwing a :class:`.TimeoutException` in this case.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to get a data
                packet from. `None` to read a data packet sent by any device.
            timeout (Integer): The time to wait for a data packet in seconds.
            explicit (Boolean): `True` to read an explicit data packet, `False`
                to read an standard data packet.

        Returns:
            :class:`.XBeeMessage` or :class:`.ExplicitXBeeMessage`: XBee
                message received by this device.

        Raises:
            ValueError: If a timeout is specified and is less than 0.
            TimeoutException: If a timeout is specified and no explicit data was
                received during that time.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

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
        if frame_type in (ApiFrameType.RECEIVE_PACKET,
                          ApiFrameType.RX_16, ApiFrameType.RX_64):
            return self.__build_xbee_message(packet, explicit=False)
        if frame_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
            return self.__build_xbee_message(packet, explicit=True)

        return None

    def _enter_at_command_mode(self):
        """
        Attempts to put this device in AT Command mode. Only valid if device is
        working in AT mode.

        Returns:
            Boolean: `True` if the XBee has entered in AT command mode, `False`
                otherwise.

        Raises:
            SerialTimeoutException: If there is any error trying to write to
                the serial port.
        """
        if not self._serial_port:
            raise XBeeException(
                "Command mode is only supported for local XBee devices using a serial connection")

        from digi.xbee.recovery import enter_at_command_mode
        return enter_at_command_mode(self._serial_port)

    def _exit_at_command_mode(self):
        """
        Exits AT command mode. The XBee has to be in command mode.

        Raises:
            SerialTimeoutException: If there is any error trying to write to
                the serial port.
        """
        if not self._serial_port:
            raise XBeeException(
                "Command mode is only supported for local XBee devices using a serial connection")

        self._serial_port.write("ATCN\r".encode("utf8"))
        time.sleep(self.__DEFAULT_GUARD_TIME)

    def _determine_operating_mode(self):
        """
        Determines and returns the operating mode of the XBee dice.

        If the XBee is not in AT command mode, this method attempts to enter on it.

        Returns:
            :class:`.OperatingMode`: This XBee operating mode.

        .. seealso::
           | :class:`.OperatingMode`
        """
        try:
            response = self.get_parameter(ATStringCommand.AP, apply=False)
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
                # This error is thrown when trying to decode bytes without
                # utf-8 representation, just ignore.
                pass
            finally:
                # Exit AT command mode.
                self._exit_at_command_mode()
                # Restore the packets listening.
                if listening:
                    self._restart_packet_listener()
        return OperatingMode.UNKNOWN

    def send_packet_sync_and_get_response(self, packet_to_send, timeout=None):
        """
        Sends the packet and waits for its corresponding response.

        Args:
            packet_to_send (:class:`.XBeePacket`): The packet to transmit.
            timeout (Integer, optional, default=`None`): Number of seconds to
                wait. -1 to wait indefinitely.

        Returns:
            :class:`.XBeePacket`: Received response packet.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TimeoutException: If response is not received in the configured
                timeout.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBeePacket`
        """
        return self._send_packet_sync_and_get_response(packet_to_send, timeout=timeout)

    def send_packet(self, packet, sync=False):
        """
        Sends the packet and waits for the response. The packet to send is
        escaped depending on the current operating mode.

        This method can be synchronous or asynchronous.

        If synchronous, this method discards all response packets until it finds
        the one that has the appropriate frame ID, that is, the sent packet's
        frame ID.

        If asynchronous, this method does not wait for any response and returns
        `None`.

        Args:
            packet (:class:`.XBeePacket`): The packet to send.
            sync (Boolean): `True` to wait for the response of the sent packet
                and return it, `False` otherwise.

        Returns:
            :class:`.XBeePacket`: Response packet if `sync` is `True`, `None`
                otherwise.

        Raises:
            TimeoutException: If `sync` is `True` and the response packet for
                the sent one cannot be read.
            InvalidOperatingModeException: If the XBee operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the packet listener is not running or the XBee's
                communication interface is closed.

        .. seealso::
           | :class:`.XBeePacket`
        """
        return self._send_packet(packet, sync=sync)

    def __build_xbee_message(self, packet, explicit=False):
        """
        Builds and returns the XBee message corresponding to the provided
        packet`. The result is an :class:`.XBeeMessage` or
        :class:`.ExplicitXBeeMessage` depending on the provided parameters.

        Args:
            packet (:class:`.XBeePacket`): Packet to get its corresponding XBee
                message.
            explicit (Boolean): `True` if the packet is an explicit packet,
                `False` otherwise.

        Returns:
            :class:`.XBeeMessage` or :class:`.ExplicitXBeeMessage`: Resulting XBee message.

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

    def __build_expldata_packet(self, remote_xbee, data, src_endpoint, dest_endpoint,
                                cluster_id, profile_id, broadcast=False,
                                transmit_options=TransmitOptions.NONE.value):
        """
        Builds and returns an explicit data packet with the provided parameters.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to send data to.
            data (String or Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)
            broadcast (Boolean, optional): `True` to send data in broadcast
                mode (`remote_xbee` is ignored), `False` to send data to the
                specified `remote_xbee`.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.ExplicitAddressingPacket`: Explicit packet generated with
                the provided parameters.

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
            x64addr = remote_xbee.get_64bit_addr()
            x16addr = remote_xbee.get_16bit_addr()

        # If the device does not have 16-bit address, set it to Unknown.
        if x16addr is None:
            x16addr = XBee16BitAddress.UNKNOWN_ADDRESS

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors='ignore')

        return ExplicitAddressingPacket(self._get_next_frame_id(), x64addr,
                                        x16addr, src_endpoint, dest_endpoint,
                                        cluster_id, profile_id, 0, transmit_options, rf_data=data)

    def __get_actual_mode(self):
        """
        Gets and returns the actual operating mode of the XBee reading 'AP'
        parameter in AT command mode.

        Returns:
             :class:`.OperatingMode`: The actual operating mode of the XBee or
                `OperatingMode.UNKNOWN` if could not be read.

        Raises:
            SerialTimeoutException: If there is any error trying to write to
                the serial port.
        """
        if not self._serial_port:
            raise XBeeException(
                "Command mode is only supported for local XBee devices using a serial connection")

        # Clear the serial input stream.
        self._serial_port.flushInput()
        # Send the 'AP' command.
        self._serial_port.write("ATAP\r".encode(encoding="utf8"))
        time.sleep(0.1)
        # Read the 'AP' answer.
        ap_answer = self._serial_port.read_existing() \
            .decode(encoding="utf8", errors='ignore').rstrip()
        if len(ap_answer) == 0:
            return OperatingMode.UNKNOWN
        # Return the corresponding operating mode for the AP answer.
        try:
            return OperatingMode.get(int(ap_answer, 16))
        except ValueError:
            return OperatingMode.UNKNOWN

    def get_next_frame_id(self):
        """
        Returns the next frame ID of the XBee.

        Returns:
            Integer: The next frame ID of the XBee.
        """
        return self._get_next_frame_id()

    def add_route_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.RouteReceived`.
        This works for Zigbee and Digimesh devices.

        Args:
            callback (Function): The callback. Receives three arguments.

                * source (:class:`.XBeeDevice`): The source node.
                * destination (:class:`.RemoteXBeeDevice`): The destination node.
                * hops (List): List of intermediate hops from closest to source
                    to closest to destination (:class:`.RemoteXBeeDevice`).

        .. seealso::
           | :meth:`.XBeeDevice.del_route_received_callback`
        """
        if self._protocol not in (XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                                  XBeeProtocol.SMART_ENERGY,
                                  XBeeProtocol.DIGI_MESH,
                                  XBeeProtocol.DIGI_POINT, XBeeProtocol.SX):
            raise ValueError(
                "Cannot register route received callback for %s XBee devices"
                % self._protocol.description)

        self.__route_received += callback

        if (self._protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                               XBeeProtocol.SMART_ENERGY)
                and self.__route_record_callback not in self._packet_listener.get_route_record_received_callbacks()):
            self._packet_listener.add_route_record_received_callback(self.__route_record_callback)
        elif self.__route_info_callback not in self._packet_listener.get_route_info_callbacks():
            self._packet_listener.add_route_info_received_callback(self.__route_info_callback)

    def del_route_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.RouteReceived` event.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeDevice.add_route_received_callback`
        """
        if callback in self.__route_received:
            self.__route_received -= callback

        if (self._protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                               XBeeProtocol.SMART_ENERGY)
                and self.__route_record_callback in self._packet_listener.get_route_record_received_callbacks()):
            self._packet_listener.del_route_record_received_callback(self.__route_record_callback)
        elif self.__route_info_callback in self._packet_listener.get_route_info_callbacks():
            self._packet_listener.del_route_info_callback(self.__route_info_callback)

    def __route_record_callback(self, src, hops):
        """
        Callback method to receive route record indicator (0xA1) frames.

        Args:
            src (:class:`.RemoteXBeeDevice`): The remote node that sent the
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
                node = network._add_remote(
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

            for idx in range(len(hops_list)):
                if length < idx + 2:
                    break
                if hops_list[idx][1] != hops_list[idx + 1][0]:
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
            if (self.__tmp_dm_to_insert
                    or not check_dm_route_complete(src_addr, dst_addr, dm_hops_list)):
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
                        node = network._add_remote(
                            RemoteDigiMeshDevice(self, x64bit_addr=address),
                            NetworkEventReason.ROUTE)

                if node not in node_list and address != dst_addr:
                    node_list.append(node)

            dest_node = network.get_device_by_64(dst_addr)
            if not dest_node:
                # If the destination is not yet in the network, add it
                if not dest_node:
                    dest_node = network._add_remote(
                        RemoteDigiMeshDevice(self, x64bit_addr=dst_addr),
                        NetworkEventReason.ROUTE)

            self.__tmp_dm_to_insert.clear()
            self.__tmp_dm_routes_to.clear()

        # Remove the source node (first one in list) from the hops
        self.__route_received(self, dest_node, node_list[1:])

    def get_route_to_node(self, remote, timeout=10, force=True):
        """
        Gets the route from this XBee to the given remote node.

        For Zigbee:
            * 'AR' parameter of the local node must be configured with a value
              different from 'FF'.
            * Set `force` to `True` to force the Zigbee remote node to return
              its route independently of the local node configuration as high
              or low RAM concentrator ('DO' of the local value)

        Args:
            remote (:class:`.RemoteXBeeDevice`): The remote node.
            timeout (Float, optional, default=10): Maximum number of seconds to
                wait for the route.
            force (Boolean): `True` to force asking for the route, `False`
                otherwise. Only for Zigbee.

        Returns:
            Tuple: Tuple containing route data:
                - status (:class:`.TransmitStatus`): The transmit status.
                - Tuple with route data (`None` if the route was not read in the
                  provided timeout):

                      - source (:class:`.RemoteXBeeDevice`): The source node of the
                        route.
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

        if self._protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                              XBeeProtocol.SMART_ENERGY, XBeeProtocol.DIGI_MESH,
                              XBeeProtocol.SX):
            status, route = self.__get_trace_route(remote, timeout, force=force)
        else:
            route = self, remote, []
            status = TransmitStatus.SUCCESS

        if route:
            self._log.debug("Route: {{{!s}{!s}{!s} >>> {!s} (hops: {!s})}}".format(
                route[0], " >>> " if route[2] else "", " >>> ".join(map(str, route[2])),
                route[1], len(route[2]) + 1))

        return status, route

    def __get_trace_route(self, remote, timeout, force=True):
        """
        Gets the route from this XBee to the given remote node.

        Args:
            remote (:class:`.RemoteXBeeDevice`): The remote node.
            timeout (Float): Maximum number of seconds to wait for the route.
            force (Boolean): `True` to force asking for the route, `False`
                otherwise. Only for Zigbee.

        Returns:
            Tuple: Tuple containing route data:
                - status (:class:`.TransmitStatus`): The transmit status.
                - Tuple with route data (`None` if the route was not read in the
                  provided timeout):
                    - source (:class:`.RemoteXBeeDevice`): The source node of the
                      route.
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
            return None, None

        if self._protocol in (XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET,
                              XBeeProtocol.SMART_ENERGY):
            if remote.get_role() == Role.END_DEVICE:
                return None, None

            # Transmit a some information to the remote
            packet = TransmitPacket(
                0x01,                          # Frame ID
                remote.get_64bit_addr(),       # 64-bit address of the remote
                remote.get_16bit_addr(),       # 16-bit address of the remote
                0x00,                          # Broadcast radius (0x00 - Maximum)
                0x00,                          # Transmit options (0x00 - None)
                bytearray([0])                 # Dummy payload
            )

            # To force getting the route we have to send again the AR value
            # configured in the local node (only if it is different from FF)
            if force:
                ar_value = None
                try:
                    ar_value = self.get_parameter(ATStringCommand.AR, apply=False)
                    if ar_value and utils.bytes_to_int(ar_value) != 0xFF:
                        self.set_parameter(ATStringCommand.AR, ar_value, apply=False)
                except XBeeException as exc:
                    self._log.debug(
                        "Error getting route to node: unable to %s '%s' value: %s",
                        "get" if not ar_value else "set",
                        ATStringCommand.AR.command, str(exc))

        elif self._protocol in (XBeeProtocol.DIGI_MESH, XBeeProtocol.SX):
            # Transmit a some information to the remote
            packet = TransmitPacket(
                0x01,                     # Frame ID
                remote.get_64bit_addr(),  # 64-bit address of the remote
                remote.get_16bit_addr(),  # 16-bit address of the remote
                0x00,                     # Broadcast radius (0x00 - Maximum)
                # Transmit options (0x08 - Generate trace route packets)
                TransmitOptions.DIGIMESH_MODE.value | TransmitOptions.ENABLE_TRACE_ROUTE.value,
                bytearray([0])            # Dummy payload
            )

        else:
            return None, None

        lock.clear()

        status = None
        timed_out = False

        self.add_route_received_callback(route_cb)

        try:
            start = time.time()

            st_frame = self.send_packet_sync_and_get_response(packet, timeout=timeout)
            status = st_frame.transmit_status if st_frame else None
            if status in (TransmitStatus.SUCCESS, TransmitStatus.SELF_ADDRESSED):
                timed_out = not lock.wait(timeout - (time.time() - start))
        except TimeoutException:
            timed_out = True
        finally:
            self.del_route_received_callback(route_cb)

        # Check if the list of intermediate nodes is empty
        if timed_out or not node_list:
            return status, None

        return status, (self, remote, node_list[1:])

    def _update_rx_stats_cb(self, rx_packet):
        """
        Callback to increase the XBee statistics related with received packets.

        Args:
            rx_packet (:class: `.XBeeAPIPacket`): The received API packet.
        """
        self.__stats._update_rx_stats(rx_packet)

    def _update_tx_stats(self, tx_packet):
        """
        Increments the XBee statistics related with transmitted packets.

        Args:
            tx_packet (:class: `.XBeeAPIPacket`): The sent API packet.
        """
        self.__stats._update_tx_stats(tx_packet)


class Raw802Device(XBeeDevice):
    """
    This class represents a local 802.15.4 XBee.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.Raw802Device` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
           _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol != XBeeProtocol.RAW_802_15_4:
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.RAW_802_15_4))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.RAW_802_15_4

        return self._protocol

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._init_network`
        """
        return Raw802Network(self)

    def get_ai_status(self):
        """
        Returns the current association status of this XBee. It indicates
        occurrences of errors during the modem initialization and connection.

        Returns:
            :class:`.AssociationIndicationStatus`: The XBee association
                indication status.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        return self._get_ai_status()

    def send_data_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee with the given
        64-bit address.

        This method waits for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x64addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        return self._send_data_64(x64addr, data, transmit_options=transmit_options)

    def send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 64-bit address.

        This method does not wait for a response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x64addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        self._send_data_async_64(x64addr, data, transmit_options=transmit_options)

    def send_data_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee with the given
        16-bit address.

        This method will wait for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x16addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        return self._send_data_16(x16addr, data, transmit_options=transmit_options)

    def send_data_async_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 16-bit address.

        This method does not wait for a response.

        Args:
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x16addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        self._send_data_async_16(x16addr, data, transmit_options=transmit_options)


class DigiMeshDevice(XBeeDevice):
    """
    This class represents a local DigiMesh XBee.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.DigiMeshDevice` with the
        provided parameters.

        Args:
            port (String): serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): port flow control.
           _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol != XBeeProtocol.DIGI_MESH:
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.DIGI_MESH))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.DIGI_MESH

        return self._protocol

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._init_network`
        """
        return DigiMeshNetwork(self)

    def build_aggregate_routes(self):
        """
        Forces all nodes in the network to automatically build routes to this
        node. The receiving node establishes a route back to this node.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self.set_parameter(ATStringCommand.AG,
                           XBee16BitAddress.UNKNOWN_ADDRESS.address,
                           apply=False)

    def send_data_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to a remote XBee with the given
        64-bit address.

        This method waits for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x64addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        return self._send_data_64(x64addr, data, transmit_options=transmit_options)

    def send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 64-bit address.

        This method does not wait for a response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x64addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        self._send_data_async_64(x64addr, data, transmit_options=transmit_options)

    def get_neighbors(self, neighbor_cb=None, finished_cb=None, timeout=None):
        """
        Returns the neighbors of this XBee. If `neighbor_cb` is not
        defined, the process blocks during the specified timeout.

        Args:
            neighbor_cb (Function, optional, default=`None`): Method called
                when a new neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives two arguments:

                * The XBee that is searching for its neighbors.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=`NeighborFinder.DEFAULT_TIMEOUT`): The timeout
                in seconds.
        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not DigiMesh.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborFinder
        return super()._get_neighbors(
            neighbor_cb=neighbor_cb, finished_cb=finished_cb,
            timeout=timeout if timeout else NeighborFinder.DEFAULT_TIMEOUT)


class DigiPointDevice(XBeeDevice):
    """
    This class represents a local DigiPoint XBee.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.DigiPointDevice` with
        the provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol != XBeeProtocol.DIGI_POINT:
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.DIGI_POINT))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.DIGI_POINT

        return self._protocol

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._init_network`
        """
        return DigiPointNetwork(self)

    def send_data_64_16(self, x64addr, x16addr, data,
                        transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to the remote XBee with the
        given 64-bit/16-bit address.

        This method waits for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee, :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if unknown.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x64addr`, `x16addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        return self._send_data_64_16(x64addr, x16addr, data,
                                     transmit_options=transmit_options)

    def send_data_async_64_16(self, x64addr, x16addr, data,
                              transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 64-bit/16-bit address.

        This method does not wait for a response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee, :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if unknown.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x64addr`, `x16addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        self._send_data_async_64_16(x64addr, x16addr, data,
                                    transmit_options=transmit_options)


class ZigBeeDevice(XBeeDevice):
    """
    This class represents a local Zigbee XBee.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.ZigBeeDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
           _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol != XBeeProtocol.ZIGBEE:
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.ZIGBEE))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.ZIGBEE

        return self._protocol

    def _init_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._init_network`
        """
        return ZigBeeNetwork(self)

    def get_ai_status(self):
        """
        Returns the current association status of this XBee. It indicates
        occurrences of errors during the modem initialization and connection.

        Returns:
            :class:`.AssociationIndicationStatus`: The XBee association
                indication status.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        return self._get_ai_status()

    def force_disassociate(self):
        """
        Forces this XBee  to immediately disassociate from the network and
        re-attempt to associate.

        Only valid for End Devices.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self._force_disassociate()

    def get_many_to_one_broadcasting_time(self):
        """
        Returns the time between aggregation route broadcast in tenths of a
        second.

        Returns:
            Integer: The number of tenths of a second between aggregation route
                broadcasts. -1 if it is disabled.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        seconds = utils.bytes_to_int(
            self.get_parameter(ATStringCommand.AR, apply=False))
        # 0xFF disables aggregation route broadcasting
        if seconds == 0xFF:
            return -1

        return seconds

    def set_many_to_one_broadcasting_time(self, tenths_second):
        """
        Configures the time between aggregation route broadcast in tenths of a
        second.

        Args:
            tenths_second (Integer): The number of tenths of a second between
                aggregation route broadcasts. -1 to disable. 0 to only send one
                broadcast.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
            ValueError: If `tenths_second` is `None` or is lower than -1, or
                bigger than 254.
        """
        if tenths_second is None:
            raise ValueError("The number of seconds cannot be None")
        if tenths_second < -1 or tenths_second > 0xFE:
            raise ValueError("The number of seconds must be between -1 and 254")

        if tenths_second == -1:
            tenths_second = 0xFF

        self.set_parameter(ATStringCommand.AR, bytearray([tenths_second]),
                           apply=self.is_apply_changes_enabled())

    def send_data_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Blocking method. This method sends data to the remote XBee with the
        given 64-bit/16-bit address.

        This method waits for the packet response. The default timeout is
        :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee, :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if unknown.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Returns:
            :class:`.XBeePacket`: The response.

        Raises:
            ValueError: If `x64addr`, `x16addr` or `data` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TransmitException: If the status of the response received is not OK.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        return self._send_data_64_16(x64addr, x16addr, data,
                                     transmit_options=transmit_options)

    def send_data_async_64_16(self, x64addr, x16addr, data,
                              transmit_options=TransmitOptions.NONE.value):
        """
        Non-blocking method. This method sends data to a remote XBee with the
        given 64-bit/16-bit address.

        This method does not wait for a response.

        Args:
            x64addr (:class:`.XBee64BitAddress`): 64-bit address of the
                destination XBee.
            x16addr (:class:`.XBee16BitAddress`): 16-bit address of the
                destination XBee, :attr:`.XBee16BitAddress.UNKNOWN_ADDRESS` if unknown.
            data (String or Bytearray): Raw data to send.
            transmit_options (Integer, optional): Transmit options, bitfield of
                :class:`.TransmitOptions`. Default to `TransmitOptions.NONE.value`.

        Raises:
            ValueError: If `x64addr`, `x16addr` or `data` is `None`.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        self._send_data_async_64_16(x64addr, x16addr, data, transmit_options=transmit_options)

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def send_multicast_data(self, group_id, data, src_endpoint, dest_endpoint,
                            cluster_id, profile_id):
        """
        Blocking method. This method sends multicast data to the provided group
        ID synchronously.

        This method will wait for the packet response. The default timeout for
        this method is :attr:`.XBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`.

        Args:
            group_id (:class:`.XBee16BitAddress`): 16-bit address of the
                multicast group.
            data (Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)

        Returns:
            :class:`.XBeePacket`: the response packet.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`XBee16BitAddress`
           | :class:`XBeePacket`
        """
        packet_to_send = ExplicitAddressingPacket(
            self._get_next_frame_id(), XBee64BitAddress.UNKNOWN_ADDRESS,
            group_id, src_endpoint, dest_endpoint, cluster_id, profile_id, 0,
            TransmitOptions.ENABLE_MULTICAST.value, rf_data=data)

        return self.send_packet_sync_and_get_response(packet_to_send)

    @AbstractXBeeDevice._before_send_method
    def send_multicast_data_async(self, group_id, data, src_endpoint,
                                  dest_endpoint, cluster_id, profile_id):
        """
        Non-blocking method. This method sends multicast data to the provided
        group ID.

        This method does not wait for a response.

        Args:
            group_id (:class:`.XBee16BitAddress`): 16-bit address of the
                multicast group.
            data (Bytearray): Raw data to send.
            src_endpoint (Integer): Source endpoint of the transmission. 1 byte.
            dest_endpoint (Integer): Destination endpoint of the transmission. 1 byte.
            cluster_id (Integer): Cluster ID of the transmission (between 0x0 and 0xFFFF)
            profile_id (Integer): Profile ID of the transmission (between 0x0 and 0xFFFF)

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`XBee16BitAddress`
        """
        packet_to_send = ExplicitAddressingPacket(
            self._get_next_frame_id(), XBee64BitAddress.UNKNOWN_ADDRESS,
            group_id, src_endpoint, dest_endpoint, cluster_id, profile_id, 0,
            TransmitOptions.ENABLE_MULTICAST.value, rf_data=data)

        self.send_packet(packet_to_send)

    @AbstractXBeeDevice._before_send_method
    def register_joining_device(self, registrant_address, options, key):
        """
        Securely registers a joining device to a trust center. Registration is
        the process by which a node is authorized to join the network using a
        preconfigured link key or installation code that is conveyed to the
        trust center out-of-band (using a physical interface and not over-the-air).

        This method is synchronous, it sends the register joining device request
        and waits for the answer of the operation. Then, returns the
        corresponding status.

        Args:
            registrant_address (:class:`XBee64BitAddress`): 64-bit address of
                the device to register.
            options (RegisterKeyOptions): Register options indicating the key source.
            key (Bytearray): Key of the device to register.

        Returns:
            :class:`.ZigbeeRegisterStatus`: Register device operation status or
                `None` if the answer is not a `RegisterDeviceStatusPacket`.

        Raises:
            TimeoutException: If the answer is not received in the configured timeout.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: If `registrant_address` or `options` is `None`.

        .. seealso::
           | :class:`RegisterKeyOptions`
           | :class:`XBee64BitAddress`
           | :class:`ZigbeeRegisterStatus`
        """
        if registrant_address is None:
            raise ValueError("Registrant address cannot be 'None'")
        if options is None:
            raise ValueError("Options cannot be 'None'")

        packet_to_send = RegisterJoiningDevicePacket(
            self.get_next_frame_id(), registrant_address, options, key)
        response_packet = self.send_packet_sync_and_get_response(packet_to_send)
        if isinstance(response_packet, RegisterDeviceStatusPacket):
            return response_packet.status
        return None

    @AbstractXBeeDevice._before_send_method
    def register_joining_device_async(self, registrant_address, options, key):
        """
        Securely registers a joining device to a trust center. Registration is
        the process by which a node is authorized to join the network using a
        preconfigured link key or installation code that is conveyed to the
        trust center out-of-band (using a physical interface and not over-the-air).

        This method is asynchronous, which means that it does not wait for an
        answer after sending the request.

        Args:
            registrant_address (:class:`XBee64BitAddress`): 64-bit address of
                the device to register.
            options (RegisterKeyOptions): Register options indicating the key source.
            key (Bytearray): Key of the device to register.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: if `registrant_address` or `options` is `None`.

        .. seealso::
           | :class:`RegisterKeyOptions`
           | :class:`XBee64BitAddress`
        """
        if registrant_address is None:
            raise ValueError("Registrant address cannot be 'None'.")
        if options is None:
            raise ValueError("Options cannot be 'None'.")

        packet_to_send = RegisterJoiningDevicePacket(
            self.get_next_frame_id(), registrant_address, options, key)
        self.send_packet(packet_to_send, sync=True)

    @AbstractXBeeDevice._before_send_method
    def unregister_joining_device(self, unregistrant_address):
        """
        Unregisters a joining device from a trust center.

        This method is synchronous, it sends the unregister joining device
        request and waits for the answer of the operation. Then, returns the
        corresponding status.

        Args:
            unregistrant_address (:class:`XBee64BitAddress`): 64-bit address of
                the device to unregister.

        Returns:
            :class:`.ZigbeeRegisterStatus`: Unregister device operation status
                or `None` if the answer is not a `RegisterDeviceStatusPacket`.

        Raises:
            TimeoutException: If the answer is not received in the configured timeout.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: If `registrant_address` is `None`.

        .. seealso::
           | :class:`XBee64BitAddress`
           | :class:`ZigbeeRegisterStatus`
        """
        return self.register_joining_device(unregistrant_address,
                                            RegisterKeyOptions.LINK_KEY, None)

    @AbstractXBeeDevice._before_send_method
    def unregister_joining_device_async(self, unregistrant_address):
        """
        Unregisters a joining device from a trust center.

        This method is asynchronous, which means that it will not wait for an
        answer after sending the unregister request.

        Args:
            unregistrant_address (:class:`XBee64BitAddress`): 64-bit address of
                the device to unregister.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the XBee's communication interface is closed.
            ValueError: If `registrant_address` is `None`.

        .. seealso::
           | :class:`XBee64BitAddress`
        """
        self.register_joining_device_async(unregistrant_address,
                                           RegisterKeyOptions.LINK_KEY, None)

    def get_routes(self, route_cb=None, finished_cb=None, timeout=None):
        """
        Returns the routes of this XBee. If `route_cb` is not defined,
        the process blocks until the complete routing table is read.

        Args:
            route_cb (Function, optional, default=`None`): Method called
                when a new route is received. Receives two arguments:

                * The XBee that owns this new route.
                * The new route.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that executed the ZDO command.
                * A list with the discovered routes.
                * An error message if something went wrong.

            timeout (Float, optional, default=`RouteTableReader.DEFAULT_TIMEOUT`): The
                ZDO command timeout in seconds.
        Returns:
            List: List of :class:`.Route` when `route_cb` is not defined,
                `None` otherwise (in this case routes are received in the callback).

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            OperationNotSupportedException: If XBee is not Zigbee or Smart Energy.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`com.digi.models.zdo.Route`
        """
        from digi.xbee.models.zdo import RouteTableReader
        return super()._get_routes(route_cb=route_cb, finished_cb=finished_cb,
                                   timeout=timeout if timeout else RouteTableReader.DEFAULT_TIMEOUT)

    def get_neighbors(self, neighbor_cb=None, finished_cb=None, timeout=None):
        """
        Returns the neighbors of this XBee. If `neighbor_cb` is not
        defined, the process blocks until the complete neighbor table is read.

        Args:
            neighbor_cb (Function, optional, default=`None`): Method called
                when a new neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that executed the ZDO command.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=`NeighborTableReader.DEFAULT_TIMEOUT`): The ZDO
                command timeout in seconds.
        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborTableReader
        return super()._get_neighbors(
            neighbor_cb=neighbor_cb, finished_cb=finished_cb,
            timeout=timeout if timeout else NeighborTableReader.DEFAULT_TIMEOUT)

    def create_source_route(self, dest_node, hops):
        """
        Creates a source route for the provided destination node. A source route
        specifies the complete route a packet traverses to get from source to
        destination.

        For best results, use source routing with many-to-one routing.

        Args:
             dest_node (:class:`.RemoteXBeeDevice`): The destination node.
             hops (List): List of intermediate nodes (:class:`.RemoteXBeeDevice`)
                ordered from closest to source to closest to destination node
                (source and destination excluded).

        Raises:
            ValueError: If `dest_node` is `None`, or if it is a local node, or
                if its protocol is not Zigbee based, or if its 64-bit address or
                16-bit address is `None`, unknown, or invalid.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            XBeeException: If the packet listener is not running or the XBee's
                communication interface is closed.
        """
        if not dest_node:
            raise ValueError("Destination node cannot be None")
        if not dest_node.is_remote():
            raise ValueError("Destination node cannot be a local node")

        if dest_node.get_protocol() not in (XBeeProtocol.ZIGBEE,
                                            XBeeProtocol.ZNET,
                                            XBeeProtocol.SMART_ENERGY):
            raise ValueError("Invalid protocol of destination node")

        x64 = dest_node.get_64bit_addr()
        if x64 == XBee64BitAddress.BROADCAST_ADDRESS:
            raise ValueError("Invalid 64-bit address of destination node: %s" % x64)

        x16 = dest_node.get_16bit_addr()
        if x16 == XBee16BitAddress.BROADCAST_ADDRESS:
            raise ValueError("Invalid 16-bit address of destination node: %s" % x16)

        if (not XBee64BitAddress.is_known_node_addr(x64)
                and not XBee16BitAddress.is_known_node_addr(x16)):
            raise ValueError("64-bit and 16-bit addresses of destination node cannot be unknown")

        if hops is None:
            hops = []

        addresses = []
        for hop in hops:
            hop16 = hop.get_16bit_addr()
            if not XBee16BitAddress.is_known_node_addr(hop16):
                raise ValueError("Invalid 16-bit address of hop node: %s" % hop16)
            addresses.append(hop16)

        self._log.debug("Create source route for %s: {%s%s%s >>> %s (hops: %s)}",
                        dest_node, dest_node.get_local_xbee_device(),
                        " >>> " if hops else "", " >>> ".join(map(str, hops)),
                        dest_node, len(hops) + 1)
        # Reverse addresses to create the packet:
        # from closest to destination to closest to source
        addresses.reverse()
        self.send_packet(
            CreateSourceRoutePacket(0x00, x64, x16, route_options=0, hops=addresses), sync=False)


class BluDevice(XBeeDevice):
    """
    This class represents a local Blu device.
    """

    __OPERATION_EXCEPTION = "Operation not supported in this module."

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.BluDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._ble_manager = BLEManager(self)

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol not in (XBeeProtocol.BLE,):
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.BLE))
        self._ble_manager.open()

    def close(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.close`
        """
        self._ble_manager.close()
        super().close()

    def get_ble_manager(self):
        """
        Returns the BLE manager for the XBee.

        Returns:
             :class:`.BLEManager`: The BLE manager.
        """
        if not self._ble_manager:
            self._ble_manager = BLEManager(self)

        return self._ble_manager

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.BLE

        return self._protocol

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
           | :meth:`.XBeeDevice._init_network`
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

        Operation not supported in this protocol.
        This method raises an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_dest_address(self, addr):
        """
        Deprecated.

        Operation not supported in this protocol.
        This method raises an :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_pan_id(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_pan_id(self, value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_expl_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_expl_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_data(self, timeout=None):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_data_from(self, remote_xbee, timeout=None):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data_broadcast(self, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data(self, remote_xbee, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data_async(self, remote_xbee, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_expl_data(self, timeout=None):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_expl_data_from(self, remote_xbee, timeout=None):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_expl_data(self, remote_xbee, data, src_endpoint, dest_endpoint,
                       cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id,
                                 profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_expl_data_async(self, remote_xbee, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_io_sample_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_io_sample_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_dio_change_detection(self, io_lines_set):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_io_sampling_rate(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_io_sampling_rate(self, rate):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_power_level(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_power_level(self, power_level):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class IPDevice(XBeeDevice):
    """
    This class provides common functionality for XBee IP devices.
    """

    BROADCAST_IP = "255.255.255.255"

    __DEFAULT_SOURCE_PORT = 9750

    __OPERATION_EXCEPTION = "Operation not supported in this module."

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.IPDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._ip_addr = None
        self._source_port = self.__DEFAULT_SOURCE_PORT

    def _read_device_info(self, reason, init=True, fire_event=True):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._read_device_info`
        """
        updated = False

        # Read the module's IP address.
        if init or self._ip_addr is None:
            resp = self.get_parameter(ATStringCommand.MY, apply=False)
            ip_addr = IPv4Address(utils.bytes_to_int(resp))
            if self._ip_addr != ip_addr:
                updated = True
                self._ip_addr = ip_addr

        # Read the source port.
        if init or self._source_port is None:
            try:
                resp = self.get_parameter(ATStringCommand.C0, apply=False)
                src_port = utils.bytes_to_int(resp)
                if self._source_port != src_port:
                    updated = True
                    self._source_port = src_port
            except XBeeException:
                # Do not refresh the source port value if there is an error reading
                # it from the module.
                pass

        super()._read_device_info(reason, init=init,
                                  fire_event=updated and fire_event)

    def is_device_info_complete(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_device_info_complete`
        """
        return (super().is_device_info_complete()
                and self._ip_addr is not None and self._source_port is not None)

    def get_ip_addr(self):
        """
        Returns the IP address of this IP XBee.

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
            ValueError: If `address` is `None`.
            TimeoutException: If there is a timeout setting the destination IP address.
            XBeeException: If there is any other XBee related exception.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        if address is None:
            raise ValueError("Destination IP address cannot be None")

        self.set_parameter(ATStringCommand.DL,
                           bytearray(address.exploded, "utf8"),
                           apply=self.is_apply_changes_enabled())

    def get_dest_ip_addr(self):
        """
        Returns the destination IP address.

        Returns:
            :class:`ipaddress.IPv4Address`: Configured destination IP address.

        Raises:
            TimeoutException: If there is a timeout getting the destination IP address.
            XBeeException: If there is any other XBee related exception.

        .. seealso::
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(
            str(self.get_parameter(ATStringCommand.DL, apply=False), encoding="utf8"))

    def add_ip_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.IPDataReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The data received as an :class:`.IPMessage`
        """
        self._packet_listener.add_ip_data_received_callback(callback)

    def del_ip_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.IPDataReceived`
        event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_ip_data_received_callbacks():
            self._packet_listener.del_ip_data_received_callback(callback)

    def start_listening(self, src_port):
        """
        Starts listening for incoming IP transmissions in the provided port.

        Args:
            src_port (Integer): Port to listen for incoming transmissions.

        Raises:
            ValueError: If `source_port` is less than 0 or greater than 65535.
            TimeoutException: If there is a timeout setting the source port.
            XBeeException: If there is any other XBee related exception.
        """
        if not 0 <= src_port <= 65535:
            raise ValueError("Source port must be between 0 and 65535")

        self.set_parameter(ATStringCommand.C0, utils.int_to_bytes(src_port),
                           apply=self.is_apply_changes_enabled())
        self._source_port = src_port

    def stop_listening(self):
        """
        Stops listening for incoming IP transmissions.

        Raises:
            TimeoutException: If there is a timeout processing the operation.
            XBeeException: If there is any other XBee related exception.
        """
        self.set_parameter(ATStringCommand.C0, utils.int_to_bytes(0),
                           apply=self.is_apply_changes_enabled())
        self._source_port = 0

    @AbstractXBeeDevice._before_send_method
    @AbstractXBeeDevice._after_send_method
    def send_ip_data(self, ip_addr, dest_port, protocol, data, close_socket=False):
        """
        Sends the provided IP data to the given IP address and port using the
        specified IP protocol. For TCP and TCP SSL protocols, you can also
        indicate if the socket should be closed when data is sent.

        This method blocks until a success or error response arrives or the
        configured receive timeout expires.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to send IP data to.
            dest_port (Integer): The destination port of the transmission.
            protocol (:class:`.IPProtocol`): The IP protocol used for the transmission.
            data (String or Bytearray): The IP data to be sent.
            close_socket (Boolean, optional, default=`False`): `True` to close
                the socket just after the transmission. `False` to keep it open.

        Raises:
            ValueError: If `ip_addr` or `protocol` or `data` is `None` or
                `dest_port` is less than 0 or greater than 65535.
            OperationNotSupportedException: If the XBee is remote.
            TimeoutException: If there is a timeout sending the data.
            XBeeException: If there is any other XBee related exception.
        """
        if ip_addr is None:
            raise ValueError("IP address cannot be None")
        if protocol is None:
            raise ValueError("Protocol cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if not 0 <= dest_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        # Check if device is remote.
        if self.is_remote():
            raise OperationNotSupportedException(message="Cannot send IP data from a remote device")

        # The source port value depends on the protocol used in the transmission.
        # For UDP, source port value must be the same as 'C0' one. For TCP it must be 0.
        src_port = self._source_port
        if protocol is not IPProtocol.UDP:
            src_port = 0

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        opts = TXIPv4Packet.OPTIONS_CLOSE_SOCKET if close_socket else TXIPv4Packet.OPTIONS_LEAVE_SOCKET_OPEN

        packet = TXIPv4Packet(self.get_next_frame_id(), ip_addr, dest_port,
                              src_port, protocol, opts, data=data)

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
            close_socket (Boolean, optional, default=`False`): `True` to close
                the socket just after the transmission. `False` to keep it open.

        Raises:
            ValueError: If `ip_addr` or `protocol` or `data` is `None` or
                `dest_port` is less than 0 or greater than 65535.
            OperationNotSupportedException: If the XBee is remote.
            XBeeException: If there is any other XBee related exception.
        """
        if ip_addr is None:
            raise ValueError("IP address cannot be None")
        if protocol is None:
            raise ValueError("Protocol cannot be None")
        if not isinstance(data, (str, bytearray, bytes)):
            raise ValueError("Data must be a string or bytearray")

        if not 0 <= dest_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        # Check if device is remote.
        if self.is_remote():
            raise OperationNotSupportedException(
                message="Cannot send IP data from a remote device")

        # The source port value depends on the protocol used in the transmission.
        # For UDP, source port value must be the same as 'C0' one. For TCP it must be 0.
        src_port = self._source_port
        if protocol is IPProtocol.UDP:
            src_port = 0

        if isinstance(data, str):
            data = data.encode(encoding="utf8", errors="ignore")

        opts = TXIPv4Packet.OPTIONS_CLOSE_SOCKET if close_socket else TXIPv4Packet.OPTIONS_LEAVE_SOCKET_OPEN

        packet = TXIPv4Packet(self.get_next_frame_id(), ip_addr, dest_port,
                              src_port, protocol, opts, data=data)

        self.send_packet(packet)

    def send_ip_data_broadcast(self, dest_port, data):
        """
        Sends the provided IP data to all clients.

        This method blocks until a success or error transmit status arrives or
        the configured receive timeout expires.

        Args:
            dest_port (Integer): The destination port of the transmission.
            data (String or Bytearray): The IP data to be sent.

        Raises:
            ValueError: If `data` is `None` or `dest_port` is less than 0 or
                greater than 65535.
            TimeoutException: If there is a timeout sending the data.
            XBeeException: If there is any other XBee related exception.
        """
        return self.send_ip_data(IPv4Address(self.BROADCAST_IP), dest_port, IPProtocol.UDP, data)

    @AbstractXBeeDevice._before_send_method
    def read_ip_data(self, timeout=XBeeDevice.TIMEOUT_READ_PACKET):
        """
        Reads new IP data received by this XBee during the provided timeout.

        This method blocks until new IP data is received or the provided
        timeout expires.

        For non-blocking operations, register a callback and use the method
        :meth:`IPDevice.add_ip_data_received_callback`.

        Before reading IP data you need to start listening for incoming IP data
        at a specific port. Use the method :meth:`IPDevice.start_listening` for
        that purpose. When finished, you can use the method
        :meth:`IPDevice.stop_listening` to stop listening for incoming IP data.

        Args:
            timeout (Integer, optional): The time to wait for new IP data in seconds.

        Returns:
            :class:`.IPMessage`: IP message, `None` if this device did not receive new data.

        Raises:
            ValueError: If `timeout` is less than 0.
        """
        if timeout < 0:
            raise ValueError("Read timeout must be 0 or greater.")

        return self.__read_ip_data_packet(timeout)

    @AbstractXBeeDevice._before_send_method
    def read_ip_data_from(self, ip_addr, timeout=XBeeDevice.TIMEOUT_READ_PACKET):
        """
        Reads new IP data received from the given IP address during the
        provided timeout.

        This method blocks until new IP data from the provided IP address is
        received or the given timeout expires.

        For non-blocking operations, register a callback and use the method
        :meth:`IPDevice.add_ip_data_received_callback`.

        Before reading IP data you need to start listening for incoming IP data
        at a specific port. Use the method :meth:`IPDevice.start_listening` for
        that purpose. When finished, you can use the method
        :meth:`IPDevice.stop_listening` to stop listening for incoming IP data.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to read data from.
            timeout (Integer, optional): The time to wait for new IP data in seconds.

        Returns:
            :class:`.IPMessage`: IP message, `None` if this device did not
                receive new data from the provided IP address.

        Raises:
            ValueError: If `timeout` is less than 0.
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

        If the provided IP address is `None` the method returns the first IP
        data packet read from any IP address. If the IP address is not `None`
        the method returns the first data package read from the given IP address.

        Args:
            timeout (Integer, optional): The time to wait for new IP data in seconds.
            ip_addr (:class:`ipaddress.IPv4Address`, optional): The IP address
                to read data from. `None` to read an IP data packet from any IP address.

        Returns:
            :class:`.IPMessage`: IP message, `None` if this device did not
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
                             packet.dest_port, packet.ip_protocol, packet.data)

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
           | :meth:`.XBeeDevice._init_network`
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

        Operation not supported in this protocol. Use
        :meth:`.IPDevice.get_dest_ip_addr` instead. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_dest_address(self, addr):
        """
        Deprecated.

        Operation not supported in this protocol. Use
        :meth:`.IPDevice.set_dest_ip_addr` instead. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_pan_id(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_pan_id(self, value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def add_expl_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_expl_data_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_data(self, timeout=None):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_data_from(self, remote_xbee, timeout=None):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data_broadcast(self, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data(self, remote_xbee, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_data_async(self, remote_xbee, data, transmit_options=TransmitOptions.NONE.value):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_expl_data(self, timeout=None):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def read_expl_data_from(self, remote_xbee, timeout=None):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_expl_data(self, remote_xbee, data, src_endpoint, dest_endpoint,
                       cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id,
                                 profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_expl_data_async(self, remote_xbee, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class CellularDevice(IPDevice):
    """
    This class represents a local Cellular device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.CellularDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._imei_addr = None

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol not in (XBeeProtocol.CELLULAR, XBeeProtocol.CELLULAR_NBIOT):
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.CELLULAR))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.CELLULAR

        return self._protocol

    def _read_device_info(self, reason, init=True, fire_event=True):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._read_device_info`
        """
        updated = False

        # Generate the IMEI address.
        if init or self._imei_addr is None:
            imei_val = str(self.get_parameter(ATStringCommand.IM, apply=False),
                           encoding='utf8', errors='ignore')
            imei_addr = XBeeIMEIAddress.from_string(imei_val)
            if self._imei_addr != imei_addr:
                updated = True
                self._imei_addr = imei_addr

        super()._read_device_info(reason, init=init,
                                  fire_event=updated and fire_event)

    def is_device_info_complete(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_device_info_complete`
        """
        return super().is_device_info_complete() and self._imei_addr is not None

    def is_connected(self):
        """
        Returns whether the device is connected to the Internet.

        Returns:
            Boolean: `True` if connected to the Internet, `False` otherwise.

        Raises:
            TimeoutException: If there is a timeout getting the association
                indication status.
            XBeeException: If there is any other XBee related exception.
        """
        status = self.get_cellular_ai_status()
        return status == CellularAssociationIndicationStatus.SUCCESSFULLY_CONNECTED

    def get_cellular_ai_status(self):
        """
        Returns the current association status of this Cellular device.

        It indicates occurrences of errors during the modem initialization
        and connection.

        Returns:
            :class:`.CellularAssociationIndicationStatus`: The association
                indication status of the Cellular device.

        Raises:
            TimeoutException: If there is a timeout getting the association
                indication status.
            XBeeException: If there is any other XBee related exception.
        """
        value = self.get_parameter(ATStringCommand.AI, apply=False)
        return CellularAssociationIndicationStatus.get(utils.bytes_to_int(value))

    def add_sms_callback(self, callback):
        """
        Adds a callback for the event :class:`.SMSReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The data received as an :class:`.SMSMessage`
        """
        self._packet_listener.add_sms_received_callback(callback)

    def del_sms_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SMSReceived`
        event.

        Args:
            callback (Function): The callback to delete.
        """
        if callback in self._packet_listener.get_sms_received_callbacks():
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

        This method blocks until a success or error response arrives or the
        configured receive timeout expires.

        For non-blocking operations use the method :meth:`.CellularDevice.send_sms_async`.

        Args:
            phone_number (String): The phone number to send the SMS to.
            data (String): Text of the SMS.

        Raises:
            ValueError: If `phone_number` or `data` is `None`.
            OperationNotSupportedException: If the device is remote.
            TimeoutException: If there is a timeout sending the SMS.
            XBeeException: If there is any other XBee related exception.
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
            ValueError: If `phone_number` or `data` is `None`.
            OperationNotSupportedException: If the device is remote.
            XBeeException: If there is any other XBee related exception.
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
            List: list with the IDs of all active (open) sockets, or empty list
                if there is not any active socket.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TimeoutException: If the response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
        """
        response = self.get_parameter(ATStringCommand.SI, apply=False)
        return SocketInfo.parse_socket_list(response)

    def get_socket_info(self, socket_id):
        """
        Returns the information of the socket with the given socket ID.

        Args:
            socket_id (Integer): ID of the socket.

        Returns:
            :class:`.SocketInfo`: The socket information, or `None` if the
                socket with that ID does not exist.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TimeoutException: If the response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :class:`.SocketInfo`
        """
        try:
            response = self.get_parameter(ATStringCommand.SI,
                                          parameter_value=utils.int_to_bytes(socket_id, 1),
                                          apply=False)
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

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_io_sample_received_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_dio_change_detection(self, io_lines_set):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_io_sampling_rate(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_io_sampling_rate(self, rate):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_node_id(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_node_id(self, node_id):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def get_power_level(self):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def set_power_level(self, power_level):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class LPWANDevice(CellularDevice):
    """
    This class provides common functionality for XBee Low-Power Wide-Area Network
    devices.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.LPWANDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.CellularDevice`
           | :meth:`.CellularDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)

    def send_ip_data(self, ip_addr, dest_port, protocol, data, close_socket=False):
        """
        Sends the provided IP data to the given IP address and port using
        the specified IP protocol.

        This method blocks until a success or error response arrives or the
        configured receive timeout expires.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to send IP data to.
            dest_port (Integer): The destination port of the transmission.
            protocol (:class:`.IPProtocol`): The IP protocol used for the transmission.
            data (String or Bytearray): The IP data to be sent.
            close_socket (Boolean, optional): Must be `False`.

        Raises:
            ValueError: If `protocol` is not UDP.
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
            close_socket (Boolean, optional): Must be `False`.

        Raises:
            ValueError: If `protocol` is not UDP.
        """
        if protocol != IPProtocol.UDP:
            raise ValueError("This protocol only supports UDP transmissions")

        super().send_ip_data_async(ip_addr, dest_port, protocol, data, close_socket=close_socket)

    def add_sms_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def del_sms_callback(self, callback):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_sms(self, phone_number, data):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)

    def send_sms_async(self, phone_number, data):
        """
        Deprecated.

        Operation not supported in this protocol. This method raises an
        :class:`.AttributeError`.
        """
        raise AttributeError(self.__OPERATION_EXCEPTION)


class NBIoTDevice(LPWANDevice):
    """
    This class represents a local NB-IoT device.
    """

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.NBIoTDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.LPWANDevice`
           | :meth:`.LPWANDevice.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self._imei_addr = None

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol != XBeeProtocol.CELLULAR_NBIOT:
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.CELLULAR_NBIOT))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.CELLULAR_NBIOT

        return self._protocol


class WiFiDevice(IPDevice):
    """
    This class represents a local Wi-Fi XBee.
    """

    # Timeout to connect, disconnect, and scan access points
    __DEFAULT_ACCESS_POINT_TIMEOUT = 15
    # Access points discovery timeout
    __DISCOVER_TIMEOUT = 30

    def __init__(self, port=None, baud_rate=None, data_bits=serial.EIGHTBITS,
                 stop_bits=serial.STOPBITS_ONE, parity=serial.PARITY_NONE,
                 flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS,
                 comm_iface=None):
        """
        Class constructor. Instantiates a new :class:`.WiFiDevice` with the
        provided parameters.

        Args:
            port (String): Serial port identifier. Depends on operating system.
                e.g. '/dev/ttyUSB0' on 'GNU/Linux' or 'COM3' on Windows.
            baud_rate (Integer): Serial port baud rate.
            data_bits (Integer, default: :attr:`.serial.EIGHTBITS`): Port bitsize.
            stop_bits (Integer, default: :attr:`.serial.STOPBITS_ONE`): Port stop bits.
            parity (Character, default: :attr:`.serial.PARITY_NONE`): Port parity.
            flow_control (Integer, default: :attr:`.FlowControl.NONE`): Port flow control.
            _sync_ops_timeout (Integer, default: 3): Read timeout (in seconds).
            comm_iface (:class:`.XBeeCommunicationInterface`): Communication interface.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.IPDevice`
           | :meth:`.v.__init__`
        """
        super().__init__(port, baud_rate, data_bits=data_bits, stop_bits=stop_bits,
                         parity=parity, flow_control=flow_control,
                         _sync_ops_timeout=_sync_ops_timeout, comm_iface=comm_iface)
        self.__ap_timeout = self.__DEFAULT_ACCESS_POINT_TIMEOUT
        self.__scanning_aps = False
        self.__scanning_aps_error = False

    def open(self, force_settings=False):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open(force_settings=force_settings)
        if self._protocol != XBeeProtocol.XBEE_WIFI:
            self.close()
            raise XBeeException(_ERROR_INCOMPATIBLE_PROTOCOL
                                % (self.get_protocol(), XBeeProtocol.XBEE_WIFI))

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        if not self._protocol or self._protocol == XBeeProtocol.UNKNOWN:
            return XBeeProtocol.XBEE_WIFI

        return self._protocol

    def get_wifi_ai_status(self):
        """
        Returns the current association status of the device.

        Returns:
            :class:`.WiFiAssociationIndicationStatus`: Current association
                status of the device.

        Raises:
            TimeoutException: If there is a timeout getting the association
                indication status.
            XBeeException: If there is any other XBee related exception.

        .. seealso::
           | :class:`.WiFiAssociationIndicationStatus`
        """
        return WiFiAssociationIndicationStatus.get(utils.bytes_to_int(
            self.get_parameter(ATStringCommand.AI, apply=False)))

    def get_access_point(self, ssid):
        """
        Finds and returns the access point that matches the supplied SSID.

        Args:
            ssid (String): SSID of the access point to get.

        Returns:
            :class:`.AccessPoint`: Discovered access point with the provided
                SID, or `None` if the timeout expires and the access point was
                not found.

        Raises:
            TimeoutException: If there is a timeout getting the access point.
            XBeeException: If there is an error sending the discovery command.

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

        The access point timeout is configured using the
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be
        consulted with :meth:`.WiFiDevice.get_access_point_timeout` method.

        Returns:
            List: List of :class:`.AccessPoint` objects discovered.

        Raises:
            TimeoutException: If there is a timeout scanning the access points.
            XBeeException: If there is any other XBee related exception.

        .. seealso::
           | :class:`.AccessPoint`
        """
        access_points_list = []

        if self.operating_mode not in (OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE):
            raise InvalidOperatingModeException(
                message="Only can scan for access points in API mode.")

        def packet_receive_callback(xbee_packet):
            if not self.__scanning_aps:
                return
            if xbee_packet.get_frame_type() != ApiFrameType.AT_COMMAND_RESPONSE:
                return
            if xbee_packet.command.upper() != ATStringCommand.AS.command:
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
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be
        consulted with :meth:`.WiFiDevice.get_access_point_timeout` method.

        Once the module is connected to the access point, you can issue the
        :meth:`.WiFiDevice.write_changes` method to save the connection
        settings. This way the module will try to connect to the access point
        every time it is powered on.

        Args:
            access_point (:class:`.AccessPoint`): The access point to connect to.
            password (String, optional): The password for the access point,
                `None` if it does not have any encryption enabled.

        Returns:
            Boolean: `True` if the module connected to the access point
                successfully, `False` otherwise.

        Raises:
            ValueError: If `access_point` is `None`.
            TimeoutException: If there is a timeout sending the connect commands.
            XBeeException: If there is any other XBee related exception.

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

        set_pw = password is not None and access_point.encryption_type != WiFiEncryptionType.NONE
        # Set connection parameters.
        self.set_parameter(ATStringCommand.ID,
                           bytearray(access_point.ssid, "utf8"), apply=False)
        self.set_parameter(ATStringCommand.EE,
                           utils.int_to_bytes(access_point.encryption_type.code, num_bytes=1),
                           apply=bool(not set_pw and self.is_apply_changes_enabled()))
        if set_pw:
            self.set_parameter(ATStringCommand.PK, bytearray(password, "utf8"),
                               apply=self.is_apply_changes_enabled())

        # Wait for the module to connect to the access point.
        dead_line = time.time() + self.__ap_timeout
        while time.time() < dead_line:
            time.sleep(0.1)
            # Get the association indication value of the module.
            status = self.get_parameter(ATStringCommand.AI, apply=False)
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
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be
        consulted with :meth:`.WiFiDevice.get_access_point_timeout` method.

        Once the module is connected to the access point, you can issue the
        :meth:`.WiFiDevice.write_changes` method to save the connection
        settings. This way the module will try to connect to the access point
        every time it is powered on.

        Args:
            ssid (String): SSID of the access point to connect to.
            password (String, optional): The password for the access point,
                `None` if it does not have any encryption enabled.

        Returns:
            Boolean: `True` if the module connected to the access point
                successfully, `False` otherwise.

        Raises:
            ValueError: If `ssid` is `None`.
            TimeoutException: If there is a timeout sending the connect commands.
            XBeeException: If the access point with the provided SSID cannot be found.
            XBeeException: If there is any other XBee related exception.

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
        :meth:`.WiFiDevice.set_access_point_timeout` method and can be
        consulted with :meth:`.WiFiDevice.get_access_point_timeout` method.

        Returns:
            Boolean: `True` if the module disconnected from the access point
                successfully, `False` otherwise.

        Raises:
            TimeoutException: If there is a timeout sending the disconnect command.
            XBeeException: If there is any other XBee related exception.

        .. seealso::
           | :meth:`.WiFiDevice.connect_by_ap`
           | :meth:`.WiFiDevice.connect_by_ssid`
           | :meth:`.WiFiDevice.get_access_point_timeout`
           | :meth:`.WiFiDevice.set_access_point_timeout`
        """
        self.execute_command(ATStringCommand.NR, apply=False)
        dead_line = time.time() + self.__ap_timeout
        while time.time() < dead_line:
            time.sleep(0.1)
            # Get the association indication value of the module.
            status = self.get_parameter(ATStringCommand.AI, apply=False)
            if status is None or len(status) < 1:
                continue
            if status[0] == 0x23:
                return True
        return False

    def is_connected(self):
        """
        Returns whether the device is connected to an access point or not.

        Returns:
            Boolean: `True` if the device is connected to an access point,
                `False` otherwise.

        Raises:
            TimeoutException: If there is a timeout getting the association
                indication status.

        .. seealso::
           | :meth:`.WiFiDevice.get_wifi_ai_status`
           | :class:`.WiFiAssociationIndicationStatus`
        """
        status = self.get_wifi_ai_status()

        return status == WiFiAssociationIndicationStatus.SUCCESSFULLY_JOINED

    def __parse_access_point(self, ap_data):
        """
        Parses the given active scan API data and returns an
        :class:`.AccessPoint`: object.

        Args:
            ap_data (Bytearray): Access point data to parse.

        Returns:
            :class:`.AccessPoint`: Access point parsed from the provided data.
                `None` if the provided data does not correspond to an access point.

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

        return AccessPoint(str(ap_data[index:], encoding="utf8"),
                           WiFiEncryptionType.get(encryption_type),
                           channel=channel, signal_quality=signal_quality)

    @staticmethod
    def __get_signal_quality(wifi_version, signal_strength):
        """
        Converts the signal strength value in signal quality (%) based on the
        provided Wi-Fi version.

        Args:
            wifi_version (Integer): Wi-Fi protocol version of the Wi-Fi XBee.
            signal_strength (Integer): Signal strength value to convert to %.

        Returns:
            Integer: The signal quality in %.
        """
        if wifi_version == 1:
            if signal_strength <= -100:
                quality = 0
            elif signal_strength >= -50:
                quality = 100
            else:
                quality = 2 * (signal_strength + 100)
        else:
            quality = 2 * signal_strength

        # Check limits.
        return max(min(quality, 100), 0)

    def get_access_point_timeout(self):
        """
        Returns the configured access point timeout for connecting,
        disconnecting and scanning access points.

        Returns:
            Integer: The current access point timeout in milliseconds.

        .. seealso::
           | :meth:`.WiFiDevice.set_access_point_timeout`
        """
        return self.__ap_timeout

    def set_access_point_timeout(self, ap_timeout):
        """
        Configures the access point timeout in milliseconds for connecting,
        disconnecting and scanning access points.

        Args:
            ap_timeout (Integer): The new access point timeout in milliseconds.

        Raises:
            ValueError: If `ap_timeout` is less than 0.

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
            :class:`.IPAddressingMode`: The IP addressing mode.

        Raises:
            TimeoutException: If there is a timeout reading the IP addressing mode.

        .. seealso::
           | :meth:`.WiFiDevice.set_ip_addressing_mode`
           | :class:`.IPAddressingMode`
        """
        return IPAddressingMode.get(utils.bytes_to_int(
            self.get_parameter(ATStringCommand.MA, apply=False)))

    def set_ip_addressing_mode(self, mode):
        """
        Sets the IP addressing mode of the device.

        Args:
            mode (:class:`.IPAddressingMode`): The new IP addressing mode to set.

        Raises:
            TimeoutException: If there is a timeout setting the IP addressing mode.

        .. seealso::
           | :meth:`.WiFiDevice.get_ip_addressing_mode`
           | :class:`.IPAddressingMode`
        """
        self.set_parameter(ATStringCommand.MA,
                           utils.int_to_bytes(mode.code, num_bytes=1),
                           apply=self.is_apply_changes_enabled())

    def set_ip_address(self, ip_address):
        """
        Sets the IP address of the module.

        This method can only be called if the module is configured
        in :attr:`.IPAddressingMode.STATIC` mode. Otherwise an `XBeeException`
        will be thrown.

        Args:
            ip_address (:class:`ipaddress.IPv4Address`): New IP address to set.

        Raises:
            TimeoutException: If there is a timeout setting the IP address.

        .. seealso::
           | :meth:`.WiFiDevice.get_mask_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.MY, ip_address.packed,
                           apply=self.is_apply_changes_enabled())

    def get_mask_address(self):
        """
        Returns the subnet mask IP address.

        Returns:
            :class:`ipaddress.IPv4Address`: The subnet mask IP address.

        Raises:
            TimeoutException: If there is a timeout reading the subnet mask address.

        .. seealso::
           | :meth:`.WiFiDevice.set_mask_address`
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(
            bytes(self.get_parameter(ATStringCommand.MK, apply=False)))

    def set_mask_address(self, mask_address):
        """
        Sets the subnet mask IP address.

        This method can only be called if the module is configured
        in :attr:`.IPAddressingMode.STATIC` mode. Otherwise an `XBeeException`
        will be thrown.

        Args:
            mask_address (:class:`ipaddress.IPv4Address`): New subnet mask address to set.

        Raises:
            TimeoutException: If there is a timeout setting the subnet mask address.

        .. seealso::
           | :meth:`.WiFiDevice.get_mask_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.MK, mask_address.packed,
                           apply=self.is_apply_changes_enabled())

    def get_gateway_address(self):
        """
        Returns the IP address of the gateway.

        Returns:
            :class:`ipaddress.IPv4Address`: The IP address of the gateway.

        Raises:
            TimeoutException: If there is a timeout reading the gateway address.

        .. seealso::
           | :meth:`.WiFiDevice.set_dns_address`
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(
            bytes(self.get_parameter(ATStringCommand.GW, apply=False)))

    def set_gateway_address(self, gateway_address):
        """
        Sets the IP address of the gateway.

        This method can only be called if the module is configured
        in :attr:`.IPAddressingMode.STATIC` mode. Otherwise an `XBeeException`
        will be thrown.

        Args:
            gateway_address (:class:`ipaddress.IPv4Address`): The new gateway address to set.

        Raises:
            TimeoutException: If there is a timeout setting the gateway address.

        .. seealso::
           | :meth:`.WiFiDevice.get_gateway_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.GW, gateway_address.packed,
                           apply=self.is_apply_changes_enabled())

    def get_dns_address(self):
        """
        Returns the IP address of Domain Name Server (DNS).

        Returns:
            :class:`ipaddress.IPv4Address`: The DNS address configured.

        Raises:
            TimeoutException: If there is a timeout reading the DNS address.

        .. seealso::
           | :meth:`.WiFiDevice.set_dns_address`
           | :class:`ipaddress.IPv4Address`
        """
        return IPv4Address(
            bytes(self.get_parameter(ATStringCommand.NS, apply=False)))

    def set_dns_address(self, dns_address):
        """
        Sets the IP address of Domain Name Server (DNS).

        Args:
            dns_address (:class:`ipaddress.IPv4Address`): The new DNS address to set.

        Raises:
            TimeoutException: If there is a timeout setting the DNS address.

        .. seealso::
           | :meth:`.WiFiDevice.get_dns_address`
           | :class:`ipaddress.IPv4Address`
        """
        self.set_parameter(ATStringCommand.NS, dns_address.packed,
                           apply=self.is_apply_changes_enabled())


class RemoteXBeeDevice(AbstractXBeeDevice):
    """
    This class represents a remote XBee.
    """

    def __init__(self, local_xbee, x64bit_addr=XBee64BitAddress.UNKNOWN_ADDRESS,
                 x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteXBeeDevice` with
        the provided parameters.

        Args:
            local_xbee (:class:`.XBeeDevice`): Local XBee associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit address of the remote XBee.
            x16bit_addr (:class:`.XBee16BitAddress`): 16-bit address of the remote XBee.
            node_id (String, optional): Node identifier of the remote XBee.

        .. seealso::
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        super().__init__(local_xbee_device=local_xbee,
                         comm_iface=local_xbee.comm_iface)

        self._local_xbee_device = local_xbee
        self._64bit_addr = x64bit_addr
        if not x64bit_addr:
            self._64bit_addr = XBee64BitAddress.UNKNOWN_ADDRESS
        self._protocol = local_xbee.get_protocol()
        self._16bit_addr = x16bit_addr
        if not x16bit_addr or self._protocol in (XBeeProtocol.DIGI_MESH,
                                                 XBeeProtocol.DIGI_POINT):
            self._16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS
        self._node_id = node_id

    def get_parameter(self, parameter, parameter_value=None, apply=None):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
        """
        return super().get_parameter(
            parameter, parameter_value=parameter_value, apply=apply)

    def set_parameter(self, parameter, value, apply=None):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.set_parameter`
        """
        super().set_parameter(parameter, value, apply=apply)

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
        except TimeoutException as exc:
            # Remote 802.15.4 devices do not respond to the AT command.
            if self._local_xbee_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
                return
            raise exc

        # Check if AT Command response is valid.
        self._check_at_cmd_response_is_valid(response)

    def get_local_xbee_device(self):
        """
        Returns the local XBee associated to the remote one.

        Returns:
            :class:`.XBeeDevice`: Local XBee.
        """
        return self._local_xbee_device

    def set_local_xbee_device(self, local_xbee_device):
        """
        This methods associates a :class:`.XBeeDevice` to the remote XBee.

        Args:
            local_xbee_device (:class:`.XBeeDevice`): New local XBee associated
                to the remote one.

        .. seealso::
           | :class:`.XBeeDevice`
        """
        self._local_xbee_device = local_xbee_device

    def get_serial_port(self):
        """
        Returns the serial port of the local XBee associated to the remote one.

        Returns:
            :class:`XBeeSerialPort`: Serial port of the local XBee associated
                to the remote one.

        .. seealso::
           | :class:`XBeeSerialPort`
        """
        return self._local_xbee_device.serial_port

    def get_comm_iface(self):
        """
        Returns the communication interface of the local XBee associated to
        the remote one.

        Returns:
            :class:`XBeeCommunicationInterface`: Communication interface of the
                local XBee associated to the remote one.

        .. seealso::
           | :class:`XBeeCommunicationInterface`
        """
        return self._local_xbee_device.comm_iface

    def get_ota_max_block_size(self):
        """
        Returns the maximum number of bytes to send for ota updates.

        Returns:
             Integer: Maximum ota block size to send.
        """
        return self._ota_max_block_size

    def set_ota_max_block_size(self, size):
        """
        Sets the maximum number of bytes to send for ota updates.

        Args:
            size (Integer): Maximum ota block size to send.

        Raises:
            ValueError: If size is not between 0 and 255.
        """
        if not isinstance(size, int):
            raise ValueError("Maximum block size must be an integer")
        if size < 0 or size > 255:
            raise ValueError("Maximum block size must be between 0 and 255")

        self._ota_max_block_size = size

    def update_filesystem_image(self, ota_filesystem_file, timeout=None,
                                progress_callback=None):
        """
        Performs a filesystem image update operation of the device.

        Args:
            ota_filesystem_file (String): Location of the OTA filesystem image file.
            timeout (Integer, optional): Maximum time to wait for target read
                operations during the update process.
            progress_callback (Function, optional): Function to receive
                progress information. Receives two arguments:

                * The current update task as a String.
                * The current update task percentage as an Integer.

        Raises:
            XBeeException: If the device is not open.
            InvalidOperatingModeException: If the device operating mode is invalid.
            FileSystemNotSupportedException: If the filesystem update is not
                supported in the XBee.
            FileSystemException: If there is any error performing the filesystem update.
        """
        from digi.xbee.filesystem import update_remote_filesystem_image

        if not self._comm_iface.is_interface_open:
            raise XBeeException("XBee device's communication interface closed.")

        update_remote_filesystem_image(self, ota_filesystem_file, timeout=timeout,
                                       max_block_size=self._ota_max_block_size,
                                       progress_callback=progress_callback)


class RemoteRaw802Device(RemoteXBeeDevice):
    """
    This class represents a remote 802.15.4 XBee.
    """

    def __init__(self, local_xbee, x64bit_addr=None, x16bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteXBeeDevice` with
        the provided parameters.

        Args:
            local_xbee (:class:`.XBeeDevice`): Local XBee associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit address of the remote XBee.
            x16bit_addr (:class:`.XBee16BitAddress`): 16-bit address of the remote XBee.
            node_id (String, optional): Node identifier of the remote XBee.

        Raises:
            XBeeException: If the protocol of `local_xbee` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee, x64bit_addr=x64bit_addr,
                         x16bit_addr=x16bit_addr, node_id=node_id)

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
            address (:class:`.XBee64BitAddress`): The 64-bit address to set.

        Raises:
            ValueError: If `address` is `None`.
        """
        if address is None:
            raise ValueError("64-bit address cannot be None")

        self._64bit_addr = address

    def get_ai_status(self):
        """
        Returns the current association status of this XBee. It indicates
        occurrences of errors during the modem initialization and connection.

        Returns:
            :class:`.AssociationIndicationStatus`: The XBee association
                indication status.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        return self._get_ai_status()


class RemoteDigiMeshDevice(RemoteXBeeDevice):
    """
    This class represents a remote DigiMesh XBee device.
    """

    def __init__(self, local_xbee, x64bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteDigiMeshDevice`
        with the provided parameters.

        Args:
            local_xbee (:class:`.XBeeDevice`): Local XBee associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit address of the remote XBee.
            node_id (String, optional): Node identifier of the remote XBee.

        Raises:
            XBeeException: If the protocol of `local_xbee` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee.get_protocol() != XBeeProtocol.DIGI_MESH:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee, x64bit_addr=x64bit_addr,
                         x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=node_id)

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.RemoteXBeeDevice.get_protocol`
        """
        return XBeeProtocol.DIGI_MESH

    def get_neighbors(self, neighbor_cb=None, finished_cb=None, timeout=None):
        """
        Returns the neighbors of this XBee. If `neighbor_cb` is not
        defined, the process blocks during the specified timeout.

        Args:
            neighbor_cb (Function, optional, default=`None`): Method called
                when a new neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that is searching for its neighbors.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=`NeighborFinder.DEFAULT_TIMEOUT`): The timeout
                in seconds.
        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not DigiMesh.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborFinder
        return super()._get_neighbors(
            neighbor_cb=neighbor_cb, finished_cb=finished_cb,
            timeout=timeout if timeout else NeighborFinder.DEFAULT_TIMEOUT)


class RemoteDigiPointDevice(RemoteXBeeDevice):
    """
    This class represents a remote DigiPoint XBee.
    """

    def __init__(self, local_xbee, x64bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteDigiMeshDevice`
        with the provided parameters.

        Args:
            local_xbee (:class:`.XBeeDevice`): Local XBee associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit address of the remote XBee.
            node_id (String, optional): Node identifier of the remote XBee.

        Raises:
            XBeeException: If the protocol of `local_xbee` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee.get_protocol() != XBeeProtocol.DIGI_POINT:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee, x64bit_addr=x64bit_addr,
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
    This class represents a remote Zigbee XBee.
    """

    def __init__(self, local_xbee, x64bit_addr=None, x16bit_addr=None, node_id=None):
        """
        Class constructor. Instantiates a new :class:`.RemoteDigiMeshDevice`
        with the provided parameters.

        Args:
            local_xbee (:class:`.XBeeDevice`): Local XBee associated with the remote one.
            x64bit_addr (:class:`.XBee64BitAddress`): 64-bit address of the remote XBee.
            x16bit_addr (:class:`.XBee16BitAddress`): 16-bit address of the remote XBee.
            node_id (String, optional): Node identifier of the remote XBee.

        Raises:
            XBeeException: If the protocol of `local_xbee` is invalid.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee.get_protocol() != XBeeProtocol.ZIGBEE:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee, x64bit_addr=x64bit_addr,
                         x16bit_addr=x16bit_addr, node_id=node_id)

        # If the remote node is an end device, its parent is stored here.
        self.__parent = None

    @property
    def parent(self):
        """
        Returns the parent of the XBee if it is an end device.

        Returns:
             :class:`.AbstractXBeeDevice`: The parent of the node for end
                devices, `None` if unknown or if it is not an end device.
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

    def _read_device_info(self, reason, init=True, fire_event=True):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice._read_device_info`
        """
        updated = False
        if init or self.__parent is None:
            # Check the role, to get the parent only for end devices
            if self._role in (Role.UNKNOWN, None):
                super()._read_device_info(reason, init=init, fire_event=fire_event)

            if self._role != Role.END_DEVICE:
                super()._read_device_info(reason, init=init, fire_event=fire_event)
                return

            # Read the module's parent address for end devices.
            resp = self.get_parameter(ATStringCommand.MP, apply=False)
            if not XBee16BitAddress.is_known_node_addr(resp):
                super()._read_device_info(reason, init=init, fire_event=fire_event)
                return

            parent_addr = XBee16BitAddress(resp)
            network = self._local_xbee_device.get_network()
            parent = network.get_device_by_16(parent_addr)
            # If the parent node is not yet in the network, add it
            if not parent:
                parent = network._add_remote(
                    RemoteZigBeeDevice(self._local_xbee_device,
                                       x16bit_addr=parent_addr),
                    NetworkEventReason.NEIGHBOR)
            self.__parent = parent
            updated = True

        super()._read_device_info(reason, init=init, fire_event=updated and fire_event)

    def is_device_info_complete(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.is_device_info_complete`
        """
        complete = super().is_device_info_complete()
        if self._role == Role.END_DEVICE:
            return complete and self.__parent is not None

        return complete

    def get_ai_status(self):
        """
        Returns the current association status of this XBee. It indicates
        occurrences of errors during the modem initialization and connection.

        Returns:
            :class:`.AssociationIndicationStatus`: The XBee association
                indication status.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        return self._get_ai_status()

    def force_disassociate(self):
        """
        Forces this XBee  to immediately disassociate from the network and
        re-attempt to associate.

        Only valid for End Devices.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        self._force_disassociate()

    def get_routes(self, route_cb=None, finished_cb=None, timeout=None):
        """
        Returns the routes of this XBee. If `route_cb` is not defined, the
        process blocks until the complete routing table is read.

        Args:
            route_cb (Function, optional, default=`None`): Method called when a
                new route is received. Receives two arguments:

                * The XBee that owns this new route.
                * The new route.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that executed the ZDO command.
                * A list with the discovered routes.
                * An error message if something went wrong.

            timeout (Float, optional, default=`RouteTableReader.DEFAULT_TIMEOUT`): The ZDO command
                timeout in seconds.
        Returns:
            List: List of :class:`.Route` when `route_cb` is not defined,
                `None` otherwise (in this case routes are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Route`
        """
        from digi.xbee.models.zdo import RouteTableReader
        return super()._get_routes(route_cb=route_cb, finished_cb=finished_cb,
                                   timeout=timeout if timeout else RouteTableReader.DEFAULT_TIMEOUT)

    def get_neighbors(self, neighbor_cb=None, finished_cb=None, timeout=None):
        """
        Returns the neighbors of this XBee. If `neighbor_cb` is not
        defined, the process blocks until the complete neighbor table is read.

        Args:
            neighbor_cb (Function, optional, default=`None`): Method called
                when a new neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that executed the ZDO command.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

            timeout (Float, optional, default=`NeighborTableReader.DEFAULT_TIMEOUT`): The ZDO
                command timeout in seconds.
        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback).

        Raises:
            OperationNotSupportedException: If XBee protocol is not Zigbee or Smart Energy.

        .. seealso::
           | :class:`com.digi.models.zdo.Neighbor`
        """
        from digi.xbee.models.zdo import NeighborTableReader
        return super()._get_neighbors(
            neighbor_cb=neighbor_cb, finished_cb=finished_cb,
            timeout=timeout if timeout else NeighborTableReader.DEFAULT_TIMEOUT)


class XBeeNetwork:
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
    Flag that indicates a discovery process packet with info about a remote XBee.
    """

    # Default timeout for discovering process in case of
    # the real timeout can't be determined.
    _DEFAULT_DISCOVERY_TIMEOUT = 20

    # Correction values for the timeout for determined devices.
    # It has been tested and work 'fine'
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

    MAX_TIME_BETWEEN_SCANS = 3 * 24 * 60 * 60  # seconds
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

    MAX_TIME_BETWEEN_REQUESTS = 10 * 60  # seconds
    """
    High limit for the time (in seconds) to wait between node neighbors requests.
    """

    SCAN_TIL_CANCEL = 0  # 0 for not stopping
    """
    The neighbor discovery process continues until is manually stopped.
    """

    NT_LIMITS = {
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
        Class constructor. Instantiates a new `XBeeNetwork`.

        Args:
            xbee_device (:class:`.XBeeDevice`): Local XBee to get the network from.

        Raises:
            ValueError: If `xbee_device` is `None`.
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
        self._network_modified = NetworkModified()
        self._device_discovered = DeviceDiscovered()
        self.__device_discovery_finished = DiscoveryProcessFinished()
        self.__network_update_progress = NetworkUpdateProgress()
        self.__discovery_thread = None
        self.__sought_device_id = None
        self.__discovered_device = None

        # FIFO to store the nodes to ask for their neighbors
        self._nodes_queue = Queue(self.__DEFAULT_QUEUE_MAX_SIZE)

        # List with the MAC address (string format) of the still active request processes
        self.__active_processes = []

        # Last date of a sent request. Used to wait certain time between requests:
        #  * In 'Flood' mode to satisfy the minimum time to wait between node requests
        #  * For 'Cascade', the time to wait is applied after finishing the previous request
        #    process
        self.__last_request_date = 0

        self.__scan_counter = 0

        self.__connections = []
        self.__conn_lock = threading.Lock()

        # Dictionary to store the route and node discovery processes per node,
        # so they can be stop when required.
        # The dictionary uses as key the 64-bit address string representation
        # (to be thread-safe)
        self.__nd_processes = {}

        self.__mode = NeighborDiscoveryMode.CASCADE
        self.__stop_scan = 1
        self.__rm_not_discovered_in_last_scan = False
        self.__time_bw_scans = self.DEFAULT_TIME_BETWEEN_SCANS
        self.__time_bw_nodes = self.DEFAULT_TIME_BETWEEN_REQUESTS
        self._node_timeout = None

        self.__saved_nt = None

        self.__init_scan_cbs = InitDiscoveryScan()
        self.__end_scan_cbs = EndDiscoveryScan()

        # Dictionary to store registered callbacks per node.
        self.__packet_received_from = {}

    def __increment_scan_counter(self):
        """
        Increments (by one) the scan counter.
        """
        self.__scan_counter += 1
        if self.__scan_counter > self.__MAX_SCAN_COUNTER:
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

           * Deep discovery: Network nodes and connections between them
             (including quality) are discovered.

             The discovery process will be running the number of scans
             configured in `n_deep_scans`. A scan is considered the process of
             discovering the full network. If there are more than one number of
             scans configured, after finishing one another is started, until
             `n_deep_scans` is satisfied.

             See :meth:`~.XBeeNetwork.set_deep_discovery_options` to establish
             the way the network discovery process is performed.

           * No deep discovery: Only network nodes are discovered.

             The discovery process will be running until the configured timeout
             expires or, in case of 802.15.4, until the 'end' packet is read.

             It may occur that, after timeout expiration, there are nodes that
             continue sending discovery responses to the local XBee. In this
             case, these nodes will not be added to the network.

        In 802.15.4, both (deep and no deep discovery) are the same and none
        discover the node connections or their quality. The difference is the
        possibility of running more than one scan using a deep discovery.

        Args:
            deep (Boolean, optional, default=`False`): `True` for a deep
                network scan, looking for neighbors and their connections,
                `False` otherwise.
            n_deep_scans (Integer, optional, default=1): Number of scans to
                perform before automatically stopping the discovery process.
                :const:`SCAN_TIL_CANCEL` means the process will not be
                automatically stopped. Only applicable if `deep=True`.

        .. seealso::
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.get_deep_discovery_options`
           | :meth:`.XBeeNetwork.set_deep_discovery_options`
           | :meth:`.XBeeNetwork.get_deep_discovery_timeouts`
           | :meth:`.XBeeNetwork.set_deep_discovery_timeouts`
           | :meth:`.XBeeNetwork.get_discovery_options`
           | :meth:`.XBeeNetwork.set_discovery_options`
           | :meth:`.XBeeNetwork.get_discovery_timeout`
           | :meth:`.XBeeNetwork.set_discovery_timeout`
        """
        with self.__lock:
            if self.__discovering:
                return

        self._log.info("Start network discovery for '%s'%s", self._local_xbee,
                       (" (%d scans)" % n_deep_scans) if deep else "")

        if deep:
            self.__stop_scan = n_deep_scans

        self.__discovery_thread = threading.Thread(
            target=self.__discover_devices_and_notify_callbacks,
            kwargs={'discover_network': deep}, daemon=True)
        self.__discovery_thread.start()

    def stop_discovery_process(self):
        """
        Stops the discovery process if it is running.

        Note that some DigiMesh/DigiPoint devices are blocked until the discovery
        time configured ('NT' parameter) has elapsed, so, when trying to get/set
        any parameter during the discovery process, a TimeoutException is raised.
        """
        self._stop_event.set()

        if self.__discovery_thread and self.__discovering:
            self.__discovery_thread.join()
            self.__discovery_thread = None

    def discover_device(self, node_id):
        """
        Blocking method. Discovers and reports the first remote XBee that
        matches the supplied identifier.

        Args:
            node_id (String): Node identifier of the node to discover.

        Returns:
            :class:`.RemoteXBeeDevice`: Discovered remote XBee, `None` if the
                timeout expires and the node was not found.

        .. seealso::
           | :meth:`.XBeeNetwork.get_discovery_options`
           | :meth:`.XBeeNetwork.set_discovery_options`
           | :meth:`.XBeeNetwork.get_discovery_timeout`
           | :meth:`.XBeeNetwork.set_discovery_timeout`
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
                self._add_remote(remote, NetworkEventReason.DISCOVERED)

        return remote

    def discover_devices(self, device_id_list):
        """
        Blocking method. Attempts to discover a list of nodes and add them to
        the current network.

        This method does not guarantee that all nodes of `device_id_list` will
        be found, even if they exist physically. This depends on the node
        discovery operation and timeout.

        Args:
            device_id_list (List): List of device IDs to discover.

        Returns:
            List: List with the discovered nodes. It may not contain all nodes
                specified in `device_id_list`.

        .. seealso::
           | :meth:`.XBeeNetwork.get_discovery_options`
           | :meth:`.XBeeNetwork.set_discovery_options`
           | :meth:`.XBeeNetwork.get_discovery_timeout`
           | :meth:`.XBeeNetwork.set_discovery_timeout`
        """
        self.start_discovery_process()
        while self.is_discovery_running():
            time.sleep(0.1)
        discovered_devices = list(filter(lambda x: x.get_node_id() in device_id_list, self.__last_search_dev_list))
        self.__last_search_dev_list.clear()
        return discovered_devices

    def is_discovery_running(self):
        """
        Returns whether the discovery process is running.

        Returns:
            Boolean: `True` if the discovery process is running, `False` otherwise.
        """
        return self.__discovering

    def get_devices(self):
        """
        Returns a copy of the XBee devices list of the network.

        If a new XBee node is added to the list after the execution of this
        method, this new XBee is not added to the list returned by this method.

        Returns:
            List: A copy of the XBee devices list of the network.
        """
        with self.__lock:
            dl_copy = [len(self.__devices_list)]
            dl_copy[:] = self.__devices_list[:]
            return dl_copy

    def has_devices(self):
        """
        Returns whether there is any device in the network.

        Returns:
            Boolean: `True` if there is at least one node in the network,
                `False` otherwise.
        """
        return len(self.__devices_list) > 0

    def get_number_devices(self):
        """
        Returns the number of nodes in the network.

        Returns:
            Integer: Number of nodes in the network.
        """
        return len(self.__devices_list)

    def export(self, dir_path=None, name=None, desc=None):
        """
        Exports this network to the given file path.

        If the provided path already exists the file is removed.

        Args:
            dir_path (String, optional, default=`None`): Absolute path of the
                directory to export the network. It should not include the file
                name. If not defined home directory is used.
            name (String, optional, default=`None`): Network human readable name.
            desc (String, optional, default=`None`): Network description.

        Returns:
            Tuple (Integer, String): Tuple with result (0: success, 1: failure)
                and string (exported file path if success, error string otherwise).
        """
        import datetime
        from pathlib import Path

        date_now = datetime.datetime.now()
        if not dir_path:
            dir_path = str(Path.home())
        if not name:
            name = "%s network" % str(self._local_xbee)
        file_name = "%s_%s.xnet" % (name.strip().replace(" ", "_"),
                                    date_now.strftime("%m%d%y_%H%M%S"))
        file = Path(dir_path, file_name)
        try:
            if file.exists():
                file.unlink()
            file.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return 1, "%s (%d): %s" % (exc.strerror, exc.errno, exc.filename)

        from digi.xbee.util.exportutils import generate_network_xml
        tree = generate_network_xml(self._local_xbee, date_now=date_now,
                                    name=name, desc=desc)

        from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
        try:
            with ZipFile(str(file), 'w') as xnet_zip:
                info = ZipInfo(filename='network.xml',
                               date_time=time.localtime(date_now.timestamp()))
                info.compress_type = ZIP_DEFLATED
                with xnet_zip.open(info, 'w') as xnet_file:
                    tree.write(xnet_file, encoding='utf8', xml_declaration=False)
        except (OSError, IOError) as exc:
            return 1, "%s (%d): %s" % (exc.strerror, exc.errno, exc.filename)

        return 0, str(file)

    def update_nodes(self, task_list):
        """
        Performs the provided update tasks. It blocks until all tasks finish.

        Args:
            task_list (List or tuple): List of update tasks
                (:class:`.FwUpdateTask` or :class:`.ProfileUpdateTask`)

        Returns:
            Dictionary: Uses the 64-bit address of the XBee as key and, as
                value, a Tuple with the XBee (:class:`.AbstractXBeeDevice`) and
                an :class:`.XBeeException` if the process failed for that node
                (`None` if it successes)
        """
        from digi.xbee.firmware import FwUpdateTask
        from digi.xbee.profile import ProfileUpdateTask

        if not task_list:
            return {}

        result = {}
        for task in task_list:
            try:
                if isinstance(task, FwUpdateTask):
                    task.xbee.update_firmware(task.xml_path,
                                              xbee_firmware_file=task.fw_path,
                                              bootloader_firmware_file=task.bl_path,
                                              timeout=task.timeout,
                                              progress_callback=task.callback)
                elif isinstance(task, ProfileUpdateTask):
                    task.xbee.apply_profile(task.profile_path, timeout=task.timeout,
                                            progress_callback=task.callback)
                result.update({str(task.xbee.get_64bit_addr()): (task.xbee, None)})
            except XBeeException as exc:
                result.update({str(task.xbee.get_64bit_addr()): (task.xbee, exc)})

        return result

    def add_network_modified_callback(self, callback):
        """
        Adds a callback for the event :class:`.NetworkModified`.

        Args:
            callback (Function): The callback. Receives three arguments.

                * The event type as a :class:`.NetworkEventType`.
                * The reason of the event as a :class:`.NetworkEventReason`.
                * The node added, updated or removed from the network as a
                  :class:`.XBeeDevice` or :class:`.RemoteXBeeDevice`.

        .. seealso::
           | :meth:`.XBeeNetwork.del_network_modified_callback`
        """
        self._network_modified += callback

    def add_device_discovered_callback(self, callback):
        """
        Adds a callback for the event :class:`.DeviceDiscovered`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The discovered remote XBee as a :class:`.RemoteXBeeDevice`.

        .. seealso::
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
        """
        self._device_discovered += callback

    def add_init_discovery_scan_callback(self, callback):
        """
        Adds a callback for the event :class:`.InitDiscoveryScan`.

        Args:
            callback (Function): The callback. Receives two arguments.

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
            callback (Function): The callback. Receives two arguments.

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
            callback (Function): The callback. Receives two arguments.

                * The event code as an :class:`.NetworkDiscoveryStatus`.
                * (Optional) A description of the discovery process as a string.

        .. seealso::
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
        """
        self.__device_discovery_finished += callback

    def add_packet_received_from_callback(self, node, callback):
        """
        Adds a callback to listen to any received packet from the provided node.

        Args:
            node (:class:`.RemoteXBeeDevice`): The node to listen for frames.
            callback (Function): The callback. Receives two arguments.

                * The received packet as a :class:`.XBeeAPIPacket`.
                * The remote XBee who sent the packet as a
                  :class:`.RemoteXBeeDevice`.

        .. seealso::
           | :meth:`.XBeeNetwork.del_packet_received_from_callback`
        """
        if not self.__packet_received_from:
            self._local_xbee._packet_listener.add_packet_received_from_callback(
                self.__received_packet_from_cb)

        cbs = self.__packet_received_from.get(str(node.get_64bit_addr()))
        if not cbs:
            cbs = XBeeEvent()
            self.__packet_received_from.update({str(node.get_64bit_addr()): cbs})

        cbs += callback

    def __received_packet_from_cb(self, packet, remote):
        """
        Callback method to handle received packets from a remote.

        Args:
            packet (:class:.`XBeeAPIPacket`): The received packet.
            remote (:class:`.RemoteXBeeDevice`): The node receiving the packet.
        """
        cbs = self.__packet_received_from.get(str(remote.get_64bit_addr()))
        if not cbs:
            return

        cbs(packet, remote)

    def add_update_progress_callback(self, callback):
        """
        Adds a callback for the event :class:`.NetworkUpdateProgress`.

        Args:
            callback (Function): The callback. Receives three arguments.
                * The XBee being updated.
                * An :class:`.UpdateProgressStatus` with the current status.

        .. seealso::
           | :meth:`.XBeeNetwork.del_update_progress_callback`
        """
        self.__network_update_progress += callback

    def del_network_modified_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.NetworkModified`.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_network_modified_callback`
        """
        if callback in self._network_modified:
            self._network_modified -= callback

    def del_device_discovered_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DeviceDiscovered` event.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.del_discovery_process_finished_callback`
        """
        if callback in self._device_discovered:
            self._device_discovered -= callback

    def del_init_discovery_scan_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.InitDiscoveryScan`.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_init_discovery_scan_callback`
        """
        if callback in self.__init_scan_cbs:
            self.__init_scan_cbs -= callback

    def del_end_discovery_scan_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.EndDiscoveryScan`.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_end_discovery_scan_callback`
        """
        if callback in self.__end_scan_cbs:
            self.__end_scan_cbs -= callback

    def del_discovery_process_finished_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.DiscoveryProcessFinished` event.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_discovery_process_finished_callback`
           | :meth:`.XBeeNetwork.add_device_discovered_callback`
           | :meth:`.XBeeNetwork.del_device_discovered_callback`
        """
        if callback in self.__device_discovery_finished:
            self.__device_discovery_finished -= callback

    def del_packet_received_from_callback(self, node, callb=None):
        """
        Deletes a received packet callback from the provided node.

        Args:
            node (:class:`.RemoteXBeeDevice`): The node to listen for frames.
            callb (Function, optional, default=`None`): The callback to delete,
                `None` to delete all.

        .. seealso::
           | :meth:`.XBeeNetwork.add_packet_received_from_callback`
        """
        cbs = self.__packet_received_from.get(str(node.get_64bit_addr()), None)
        if not cbs:
            return

        if not callb:
            cbs.clear()
        elif callb in cbs:
            cbs -= callb

        if not cbs:
            self.__packet_received_from.pop(str(node.get_64bit_addr()), None)

        if (not self.__packet_received_from
                and self.__received_packet_from_cb in
                self._local_xbee._packet_listener.get_packet_received_from_callbacks()):
            self._local_xbee._packet_listener.del_packet_received_from_callback(
                self.__received_packet_from_cb)

    def del_update_progress_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.NetworkUpdateProgress`.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.XBeeNetwork.add_update_progress_callback`
        """
        if callback in self.__network_update_progress:
            self.__network_update_progress -= callback

    def get_update_progress_callbacks(self):
        """
        Returns the list of registered callbacks for update progress.
        This is only for internal use.

        Returns:
            List: List of :class:`.NetworkUpdateProgress` events.
        """
        return self.__network_update_progress

    def clear(self):
        """
        Removes all remote XBee nodes from the network.
        """
        return self._clear(NetworkEventReason.MANUAL)

    def _clear(self, reason):
        """
        Removes all the remote XBee nodes from the network.

        Args:
            reason (:class:`.NetworkEventReason`): Reason of the clear event.
        """
        with self.__lock:
            for node in self.__devices_list:
                self.del_packet_received_from_callback(node, callb=None)

        with self.__lock:
            self.__devices_list.clear()

        with self.__conn_lock:
            self.__connections.clear()

        self._network_modified(NetworkEventType.CLEAR, reason, node=None)

    def get_discovery_options(self):
        """
        Returns the network discovery process options.

        Returns:
            Bytearray: Discovery options value.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        return self._local_xbee.get_parameter(ATStringCommand.NO, apply=False)

    def set_discovery_options(self, options):
        """
        Configures the discovery options (`NO` parameter) with the given value.

        Args:
            options (Set of :class:`.DiscoveryOptions`): New discovery options,
                empty set to clear the options.

        Raises:
            ValueError: If `options` is `None`.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.

        .. seealso::
           | :class:`.DiscoveryOptions`
        """
        if options is None:
            raise ValueError("Options cannot be None")

        value = DiscoveryOptions.calculate_discovery_value(self._local_xbee.get_protocol(), options)
        self._local_xbee.set_parameter(ATStringCommand.NO,
                                       utils.int_to_bytes(value), apply=True)

    def get_deep_discovery_options(self):
        """
        Returns the deep discovery process options.

        Returns:
            Tuple: (:class:`.NeighborDiscoveryMode`, Boolean): Tuple containing:
                - mode (:class:`.NeighborDiscoveryMode`): Neighbor discovery
                    mode, the way to perform the network discovery process.
                - remove_nodes (Boolean): `True` to remove nodes from the
                    network if they were not discovered in the last scan,
                    `False` otherwise.

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
            del_not_discovered_nodes_in_last_scan (Boolean, optional, default=`False`): `True` to
                remove nodes from the network if they were not discovered in the last scan.

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
            Float: Network discovery timeout.

        Raises:
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        tout = self._local_xbee.get_parameter(ATStringCommand.NT, apply=False)

        return utils.bytes_to_int(tout) / 10.0

    def set_discovery_timeout(self, discovery_timeout):
        """
        Sets the discovery network timeout.

        Args:
            discovery_timeout (Float): Timeout in seconds.

        Raises:
            ValueError: If `discovery_timeout` is not between the allowed
                minimum and maximum values.
            TimeoutException: If response is not received before the read
                timeout expires.
            XBeeException: If the XBee's communication interface is closed.
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            ATCommandException: If response is not as expected.
        """
        min_nt, max_nt = self.get_nt_limits(self._local_xbee.get_protocol())
        if discovery_timeout < min_nt or discovery_timeout > max_nt:
            raise ValueError("Value must be between %f and %f seconds"
                             % (min_nt, max_nt))

        discovery_timeout *= 10  # seconds to 100ms
        timeout = bytearray([int(discovery_timeout)])
        self._local_xbee.set_parameter(ATStringCommand.NT, timeout,
                                       apply=True)

    def get_deep_discovery_timeouts(self):
        """
        Gets deep discovery network timeouts.
        These timeouts are only applicable for "deep" discovery
        (see :meth:`~.XBeeNetwork.start_discovery_process`)

        Returns:
            Tuple (Float, Float, Float): Tuple containing:
                - node_timeout (Float): Maximum duration in seconds of the
                    discovery process per node. This is used to find neighbors
                    of a node. This timeout is highly dependent on the nature of
                    the network:

                    .. hlist::
                       :columns: 1

                       * It should be greater than the highest 'NT' (Node
                         Discovery Timeout) of your network.
                       * And include enough time to let the message propagate
                         depending on the sleep cycle of your network nodes.

                - time_bw_nodes (Float): Time to wait between node neighbors
                    requests. Use this setting not to saturate your network:

                    .. hlist::
                       :columns: 1

                       * For 'Cascade', the number of seconds to wait after
                         completion of the neighbor discovery process of the
                         previous node.
                       * For 'Flood', the minimum time to wait between each
                         node's neighbor requests.

                - time_bw_scans (Float): Time to wait before starting a new
                    network scan.

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
            Maximum duration in seconds of the discovery process used to find
            neighbors of a node. If `None` already configured timeouts are used.

        time_bw_requests (Float, optional, default=`DEFAULT_TIME_BETWEEN_REQUESTS`): Time to wait
            between node neighbors requests.
            It must be between :const:`MIN_TIME_BETWEEN_REQUESTS` and
            :const:`MAX_TIME_BETWEEN_REQUESTS` seconds inclusive. Use this
            setting not to saturate your network:

                .. hlist::
                   :columns: 1

                   * For 'Cascade', the number of seconds to wait after
                     completion of the neighbor discovery process of the
                     previous node.
                   * For 'Flood', the minimum time to wait between each node's
                     neighbor requests.

        time_bw_scans (Float, optional, default=`DEFAULT_TIME_BETWEEN_SCANS`): Time to wait
            before starting a new network scan.
            It must be between :const:`MIN_TIME_BETWEEN_SCANS` and
            :const:`MAX_TIME_BETWEEN_SCANS` seconds inclusive.

        Raises:
            ValueError: if `node_timeout`, `time_bw_requests` or
                `time_bw_scans` are not between their corresponding limits.

        .. seealso::
            | :meth:`.XBeeNetwork.get_deep_discovery_timeouts`
            | :meth:`.XBeeNetwork.start_discovery_process`
        """
        min_nt, max_nt = self.get_nt_limits(self._local_xbee.get_protocol())

        if node_timeout and (node_timeout < min_nt or node_timeout > max_nt):
            raise ValueError("Node timeout must be between %f and %f seconds"
                             % (min_nt, max_nt))

        if (time_bw_requests
                and (time_bw_requests < self.MIN_TIME_BETWEEN_REQUESTS
                     or time_bw_requests > self.MAX_TIME_BETWEEN_REQUESTS)):
            raise ValueError("Time between neighbor requests must be between %d and %d" %
                             (self.MIN_TIME_BETWEEN_REQUESTS,
                              self.MAX_TIME_BETWEEN_REQUESTS))

        if (time_bw_scans
                and (time_bw_scans < self.MIN_TIME_BETWEEN_SCANS
                     or time_bw_scans > self.MAX_TIME_BETWEEN_SCANS)):
            raise ValueError("Time between scans must be between %d and %d" %
                             (self.MIN_TIME_BETWEEN_SCANS,
                              self.MAX_TIME_BETWEEN_SCANS))

        self._node_timeout = node_timeout
        self.__time_bw_nodes = time_bw_requests if time_bw_requests is not None \
            else self.DEFAULT_TIME_BETWEEN_REQUESTS
        self.__time_bw_scans = time_bw_scans if time_bw_scans is not None \
            else self.DEFAULT_TIME_BETWEEN_SCANS

    @classmethod
    def get_nt_limits(cls, protocol):
        """
        Returns a tuple with the minimum and maximum values for the 'NT'
        value depending on the protocol.

        Returns:
             Tuple (Float, Float): Minimum value in seconds, maximum value in
                seconds.
        """
        if protocol in (XBeeProtocol.RAW_802_15_4, XBeeProtocol.ZIGBEE,
                        XBeeProtocol.DIGI_MESH):
            return cls.NT_LIMITS[protocol]

        # Calculate the minimum of the min values and the maximum of max values
        min_nt = min(map(lambda p: p[0], cls.NT_LIMITS.values()))
        max_nt = max(map(lambda p: p[1], cls.NT_LIMITS.values()))

        return min_nt, max_nt

    def is_node_in_network(self, node):
        """
        Checks if the provided node is in the network or if it is the local XBee.

        Args:
            node (:class:`.AbstractXBeeDevice`): The node to check.

        Returns:
            Boolean: `True` if the node is in the network, `False` otherwise.

        Raises:
            ValueError: If `node` is `None`.
        """
        if not node:
            raise ValueError("Node cannot be None")

        x64 = node.get_64bit_addr()
        if XBee64BitAddress.is_known_node_addr(x64):
            return self.get_device_by_64(x64) is not None

        x16 = node.get_16bit_addr()
        if XBee16BitAddress.is_known_node_addr(x16):
            return self.get_device_by_16(x16) is not None

        node_id = node.get_node_id()
        if node_id:
            return self.get_device_by_node_id(node_id) is not None

        return False

    def get_device_by_64(self, x64bit_addr):
        """
        Returns the XBee in the network whose 64-bit address matches the given one.

        Args:
            x64bit_addr (:class:`XBee64BitAddress`):  64-bit address of the
                node to retrieve.

        Returns:
            :class:`.AbstractXBeeDevice`: XBee in the network or `None` if not found.

        Raises:
            ValueError: If `x64bit_addr` is `None` or unknown.
        """
        if x64bit_addr is None:
            raise ValueError("64-bit address cannot be None")
        if not XBee64BitAddress.is_known_node_addr(x64bit_addr):
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
            x16bit_addr (:class:`XBee16BitAddress`): 16-bit address of the node
                to retrieve.

        Returns:
            :class:`.AbstractXBeeDevice`: XBee in the network or `Non` if not found.

        Raises:
            ValueError: If `x16bit_addr` is `None` or unknown.
        """
        if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_MESH:
            raise ValueError("DigiMesh protocol does not support 16-bit addressing")
        if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_POINT:
            raise ValueError("Point-to-Multipoint protocol does not support 16-bit addressing")
        if x16bit_addr is None:
            raise ValueError("16-bit address cannot be None")
        if not XBee16BitAddress.is_known_node_addr(x16bit_addr):
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
            node_id (String): Node identifier of the node to retrieve.

        Returns:
            :class:`.AbstractXBeeDevice`: XBee in the network or `None` if not found.

        Raises:
            ValueError: If `node_id` is `None`.
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
        Adds an XBee with the provided information if it does not exist in the
        current network.

        If the XBee already exists, its data is updated with the provided
        information.

        If no valid address is provided (`x64bit_addr`, `x16bit_addr`), `None`
        is returned.

        Args:
            x64bit_addr (:class:`XBee64BitAddress`, optional, default=`None`):
                64-bit address.
            x16bit_addr (:class:`XBee16BitAddress`, optional, default=`None`):
                16-bit address.
            node_id (String, optional, default=`None`): Node identifier.

        Returns:
            :class:`.AbstractXBeeDevice`: the remote XBee with the updated
                information. If the XBee was not in the list yet, this method
                returns the given XBee without changes.
        """
        if not (XBee64BitAddress.is_known_node_addr(x64bit_addr)
                or XBee16BitAddress.is_known_node_addr(x16bit_addr)):
            return None

        if x64bit_addr == self._local_xbee.get_64bit_addr():
            return self._local_xbee

        return self._add_remote_from_attr(NetworkEventReason.MANUAL, x64bit_addr=x64bit_addr,
                                          x16bit_addr=x16bit_addr, node_id=node_id)

    def add_remote(self, remote_xbee):
        """
        Adds the provided remote XBee to the network if it is not in yet.

        If the XBee is already in the network, its data is updated with the
        information of the provided XBee that are not `None`.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to add.

        Returns:
            :class:`.RemoteXBeeDevice`: Provided XBee with updated data. If
                the XBee was not in the list, it returns it without changes.
        """
        return self._add_remote(remote_xbee, NetworkEventReason.MANUAL)

    def _add_remote(self, remote_xbee, reason):
        """
        Adds the provided remote XBee to the network if it is not in yet.

        If the XBee is already in the network, its data is updated with the
        information of the provided XBee that are not `None`.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to add.
            reason (:class:`.NetworkEventReason`): Reason of the addition.

        Returns:
            :class:`.AbstractXBeeDevice`: Provided XBee with updated data. If
                the XBee was not in the list, it returns it without changes.
        """
        if not remote_xbee:
            return remote_xbee

        found = None

        # Check if it is the local device
        if (not remote_xbee.is_remote()
                or remote_xbee == remote_xbee.get_local_xbee_device()):
            found = remote_xbee if not remote_xbee.is_remote() \
                else remote_xbee.get_local_xbee_device()
        # Look for the remote in the network list
        else:
            x64 = remote_xbee.get_64bit_addr()
            x16 = remote_xbee.get_16bit_addr()
            is_x64_known_addr = XBee64BitAddress.is_known_node_addr(x64)
            is_x16_known_addr = XBee16BitAddress.is_known_node_addr(x16)

            if not is_x64_known_addr and not is_x16_known_addr:
                return None

            # If node does not have a valid 64-bit address, ask for it only if
            # its 16-bit is valid
            if not is_x64_known_addr and is_x16_known_addr:
                # It may happen the node is in the network cache and can be
                # found by its 16-bit address. In this case, this would not be
                # necessary. But, by always asking, we are trying to keep the
                # 64-bit address as the main key for nodes and reducing the
                # possibilities of considering the same node what actually are
                # different physical but maybe with the same 16-bit address
                # (bad configured in case of 802.15.4) or with a not updated
                # 16-bit address (in a Zigbee network)
                remote_xbee._initializing = True
                # Ask for the 64-bit address
                try:
                    sh_val = remote_xbee.get_parameter(ATStringCommand.SH, apply=False)
                    sl_val = remote_xbee.get_parameter(ATStringCommand.SL, apply=False)
                    x64 = XBee64BitAddress(sh_val + sl_val)
                    is_x64_known_addr = XBee64BitAddress.is_known_node_addr(x64)
                    remote_xbee._64bit_addr = x64
                except XBeeException as exc:
                    self._log.debug(
                        "Error while trying to get 64-bit address of XBee (%s - %s): %s",
                        remote_xbee, x16, str(exc))
                remote_xbee._initializing = False

            # Look for the node in the cache by its 64-bit address
            if is_x64_known_addr:
                with self.__lock:
                    if remote_xbee in self.__devices_list:
                        found = self.__devices_list[self.__devices_list.index(remote_xbee)]

            # If not found, look for the node in the cache by its 16-bit address
            if not found:
                found_16 = None
                if is_x16_known_addr:
                    found_16 = self.get_device_by_16(x16)

                # For an invalid 64-bit address of the node to add, use the
                # node found by its 16-bit address in the cache
                if not is_x64_known_addr:
                    found = found_16
                # For a valid 64-bit address of the node to add, check if the
                # node with the same 16-bit address in the cache has a valid
                # 64-bit address. If not, consider this addition an update of
                # the existing entry (found by the 16-bit address)
                elif (found_16
                      and not XBee64BitAddress.is_known_node_addr(
                          found_16.get_64bit_addr())):
                    found = found_16

        if found:
            already_in_scan = False
            if reason in (NetworkEventReason.NEIGHBOR, NetworkEventReason.DISCOVERED):
                already_in_scan = found.scan_counter == self.__scan_counter
                if not already_in_scan:
                    found._scan_counter = self.__scan_counter

            is_init = found._initializing and reason == NetworkEventReason.RECEIVED_MSG
            if not is_init and found.update_device_data_from(remote_xbee):
                self._network_modified(NetworkEventType.UPDATE, reason, node=found)
                found._reachable = True

            return None if already_in_scan else found

        if reason in (NetworkEventReason.NEIGHBOR, NetworkEventReason.DISCOVERED):
            remote_xbee._scan_counter = self.__scan_counter

        self.__devices_list.append(remote_xbee)
        self._network_modified(NetworkEventType.ADD, reason, node=remote_xbee)

        return remote_xbee

    def _add_remote_from_attr(self, reason, x64bit_addr=None, x16bit_addr=None, node_id=None,
                              role=Role.UNKNOWN, hw_version=None, fw_version=None, op_mode=None):
        """
        Creates a new XBee using the provided data and adds it to the network
        if it is not included yet.

        If the XBee is already in the network, its data is updated with the
        provided information.

        Args:
            reason (:class:`.NetworkEventReason`): The reason of the addition.
            x64bit_addr (:class:`.XBee64BitAddress`, optional,
                default=`None`): The 64-bit address of the remote XBee.
            x16bit_addr (:class:`.XBee16BitAddress`, optional,
                default=`None`): The 16-bit address of the remote XBee.
            node_id (String, optional, default=`None`): The node identifier of the remote XBee.
            role (:class:`.Role`, optional, default=`Role.UNKNOWN`): The role
                of the remote XBee.
            hw_version (:class:`.HardwareVersion`, optional, default=`None`): The hardware version.
            fw_version (bytearray, optional, default=`None`): The firmware version.
            op_mode (:class:`.OperatingMode`, optional, default=`None`): The
                operating mode, useful to update the local XBee.

        Returns:
            :class:`.RemoteXBeeDevice`: Remote XBee generated from the provided
                data if the data provided is correct and the XBee protocol is
                valid, `None` otherwise.

        .. seealso::
            | :class:`.NetworkEventReason`
            | :class:`digi.xbee.models.address.XBee16BitAddress`
            | :class:`digi.xbee.models.address.XBee64BitAddress`
            | :class:`digi.xbee.models.hw.HardwareVersion`
            | :class:`digi.xbee.models.protocol.Role`
            | :class:`digi.xbee.models.mode.OperatingMode`
        """
        return self._add_remote(
            self.__create_remote(x64bit_addr=x64bit_addr, x16bit_addr=x16bit_addr,
                                 node_id=node_id, role=role, hw_version=hw_version,
                                 fw_version=fw_version, op_mode=op_mode), reason)

    def add_remotes(self, remote_xbees):
        """
        Adds a list of remote XBee nodes to the network.

        If any node in the list is already in the network, its data is updated
        with the information of the corresponding XBee in the list.

        Args:
            remote_xbees (List): List of :class:`.RemoteXBeeDevice` to add.
        """
        for rem in remote_xbees:
            self.add_remote(rem)

    def _remove_device(self, remote_xbee, reason, force=True):
        """
        Removes the provided remote XBee from the network.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to remove.
            reason (:class:`.NetworkEventReason`): Reason of the removal.
            force (Boolean, optional, default=`True`): `True` to force the
                deletion of the node, `False` otherwise.

        Raises:
            ValueError: If the provided `remote_xbee` is not in the network.
        """
        if not remote_xbee:
            return

        with self.__lock:
            if remote_xbee not in self.__devices_list:
                return

            i = self.__devices_list.index(remote_xbee)
            found_node = self.__devices_list[i]
            if force:
                self.__devices_list.remove(found_node)
                if found_node.reachable:
                    self._network_modified(NetworkEventType.DEL, reason, node=remote_xbee)

        node_b_connections = self.__get_connections_for_node_a_b(found_node, node_a=False)

        # Remove connections with this node as one of its ends
        self.__remove_node_connections(found_node, only_as_node_a=True, force=force)

        if force:
            self.del_packet_received_from_callback(found_node, callb=None)
        else:
            # Only for Zigbee, mark non-reachable end devices
            if (remote_xbee.get_protocol() in (XBeeProtocol.ZIGBEE,
                                               XBeeProtocol.SMART_ENERGY)
                    and remote_xbee.get_role() == Role.END_DEVICE):
                for conn in node_b_connections:
                    # End devices do not have connections from them (not asking
                    # for their routing and neighbor tables), but if their
                    # parent is not reachable, they are not either
                    if not conn.node_a.reachable:
                        self._set_node_reachable(remote_xbee, False)
                        break

    def remove_device(self, remote_xbee):
        """
        Removes the provided remote XBee from the network.

        Args:
            remote_xbee (:class:`.RemoteXBeeDevice`): Remote XBee to remove.

        Raises:
            ValueError: If the provided `remote_xbee` is not in the network.
        """
        self._remove_device(remote_xbee, NetworkEventReason.MANUAL, force=True)

    def get_discovery_callbacks(self):
        """
        Returns the API callbacks that are used in the device discovery process.

        This callbacks notify the user callbacks for each XBee discovered.

        Returns:
            Tuple (Function, Function): Callback for generic devices discovery
                process, callback for discovery specific XBee ops.
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
                    # If remote was successfully created and it is not in the
                    # XBee list, add it and notify callbacks.
                    self._log.debug("     o Discovered neighbor of %s: %s",
                                    self._local_xbee, remote)

                    node = self._add_remote(remote, NetworkEventReason.DISCOVERED)
                    if not node:
                        # Node already in network for this scan
                        node = self.get_device_by_64(remote.get_64bit_addr())
                        self._log.debug(
                            "       - NODE already in network in this scan (scan: %d) %s",
                            self.__scan_counter, node)
                    else:
                        # Do not add the neighbors to the FIFO, because
                        # only the local device performs an 'ND'
                        self._log.debug("       - Added to network (scan: %d)", node.scan_counter)

                    # Do not add a connection to the same node (the local one)
                    if node != self._local_xbee:
                        # Add connection (there is not RSSI info for a 'ND')
                        from digi.xbee.models.zdo import RouteStatus
                        if self._add_connection(Connection(
                                self._local_xbee, node, LinkQuality.UNKNOWN, LinkQuality.UNKNOWN,
                                RouteStatus.ACTIVE, RouteStatus.ACTIVE)):
                            self._log.debug("       - Added connection: %s >>> %s",
                                            self._local_xbee, node)
                        else:
                            self._log.debug(
                                "       - CONNECTION already in network in this scan (scan: %d) %s >>> %s",
                                self.__scan_counter, self._local_xbee, node)

                    # Always add the XBee device to the last discovered devices list:
                    self.__last_search_dev_list.append(node)
                    self._device_discovered(node)

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
                # if it is not a finish signal, it contains info about a remote XBee.
                x16, x64, n_id, role, x64_parent = \
                    self.__get_data_for_remote(xbee_packet.command_value)
                remote = self.__create_remote(x64bit_addr=x64, x16bit_addr=x16,
                                              node_id=n_id, role=role,
                                              parent_addr=x64_parent)
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
            :class:`.Thread`: Network discovery thread.
        """
        return self.__discovery_thread

    @staticmethod
    def __check_nd_packet(xbee_packet):
        """
        Checks if the provided XBee packet is a 'ND' response. If so, checks if
        is the 'end' signal of the discovery process or if it has information
        about a remote XBee.

        Returns:
            Integer: ID that indicates if the packet is a finish discovery
                signal or if it contains information about a remote XBee, or
                `None` if `xbee_packet` is not a response for an 'ND' command.

                 * :attr:`.XBeeNetwork.ND_PACKET_FINISH`: if `xbee_packet` is
                    an end signal.
                 * :attr:`.XBeeNetwork.ND_PACKET_REMOTE`: if `xbee_packet` has
                    info about a remote XBee.
        """
        if (xbee_packet.get_frame_type() == ApiFrameType.AT_COMMAND_RESPONSE
                and xbee_packet.command.upper() == ATStringCommand.ND.command):
            if xbee_packet.command_value is None or len(xbee_packet.command_value) == 0:
                return XBeeNetwork.ND_PACKET_FINISH
            return XBeeNetwork.ND_PACKET_REMOTE

        return None

    def __discover_devices_and_notify_callbacks(self, discover_network=False):
        """
        Blocking method. Performs a discovery operation, waits until it finishes
        (timeout or 'end' packet for 802.15.4), and notifies callbacks.

        Args:
            discover_network (Boolean, optional, default=`False`): `True` to
                discovery the full network with connections between nodes,
                `False` to only discover nodes with a single 'ND'.
        """
        self._stop_event.clear()
        self.__last_search_dev_list.clear()
        self.__discovering = True
        self.__discover_result = None

        if not discover_network:
            status = self.__discover_devices()
            self._discovery_done(self.__active_processes)
        else:
            status = self._discover_full_network()

        self._log.info("End network discovery for '%s'", self._local_xbee)
        self.__device_discovery_finished(status if status else NetworkDiscoveryStatus.SUCCESS)

    def _discover_full_network(self):
        """
        Discovers the network of the local node.

        Returns:
            :class:`digi.xbee.models.status.NetworkDiscoveryStatus`: Resulting
                status of the discovery process.
        """
        try:
            code = self.__init_discovery(self._nodes_queue)
            if code != NetworkDiscoveryStatus.SUCCESS:
                return code

            while (self.__stop_scan == self.SCAN_TIL_CANCEL
                   or self.__scan_counter < self.__stop_scan):

                if self.__scan_counter > 0:
                    self._log.debug("")
                    self._log.debug(" [*] Waiting %f seconds to start next scan",
                                    self.__time_bw_scans)
                    code = self.__wait_checking(self.__time_bw_scans)
                    if code != NetworkDiscoveryStatus.SUCCESS:
                        return code

                self.__init_scan()

                # Check for cancel
                if self._stop_event.is_set():
                    return NetworkDiscoveryStatus.CANCEL

                code = self.__discover_network(self._nodes_queue, self.__active_processes,
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
             nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.

        Returns:
            :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
        """
        # Initialize the scan number
        self.__scan_counter = 0

        # Initialize all nodes/connections scan counter
        with self.__lock:
            for xb_item in self.__devices_list:
                xb_item._scan_counter = self.__scan_counter

        with self.__conn_lock:
            for conn_item in self.__connections:
                conn_item.scan_counter_a2b = self.__scan_counter
                conn_item.scan_counter_b2a = self.__scan_counter

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
        except XBeeException as exc:
            self._log.warning(str(exc))

        return NetworkDiscoveryStatus.SUCCESS

    def _prepare_network_discovery(self):
        """
        Performs XBee configuration before starting the full network discovery.
        This saves the current 'NT' value and sets it to `self._node_timeout`.
        """
        self._log.debug("[*] Preconfiguring %s", ATStringCommand.NT.command)

        try:
            self.__saved_nt = self.get_discovery_timeout()

            if self._node_timeout is None:
                self._node_timeout = self.__saved_nt

            # Do not configure NT if it is already
            if self.__saved_nt == self._node_timeout:
                self.__saved_nt = None
                return

            self.set_discovery_timeout(self._node_timeout)
        except XBeeException as exc:
            raise XBeeException(
                "Could not prepare XBee for network discovery: %s" % str(exc)) from exc

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
        self._log.debug("  %d network scan", self.__scan_counter)
        self._log.debug("       Mode: %s (%d)", self.__mode.description, self.__mode.code)
        self._log.debug("       Stop after scan: %d", self.__stop_scan)
        self._log.debug("       Timeout/node: %s", self._node_timeout
                        if self._node_timeout is not None else "-")
        self._log.debug("================================")

    def __discover_network(self, nodes_queue, active_processes, node_timeout):
        """
        Discovers the network of the local node.

        Args:
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
            active_processes (List): List of active discovery processes.
            node_timeout (Float): Maximum number of seconds to discover
                neighbors for each node.

        Returns:
            :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
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
                    " [*] Waiting for more nodes to request or finishing active processes (%d)\n",
                    len(active_processes))
                for act_proc in active_processes:
                    self._log.debug("     Waiting for %s", act_proc)

                code = self.__wait_checking(self.__TIME_FOR_NEW_NODES_IN_FIFO)
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
                            self.__TIME_WHILE_FINISH_PREVIOUS_PROCESS)
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
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
            active_processes (List): List of active discovery processes.
            node_timeout (Float): Maximum number of seconds to discover
                neighbors for each node.

        Returns:
             :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
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
            self._log.debug(" [*] Waiting %f before sending next request to %s",
                            time_to_wait if time_to_wait > 0 else 0.0, requester)
            code = self.__wait_checking(time_to_wait)
            if code != NetworkDiscoveryStatus.SUCCESS:
                return code

        # If the previous request finished, discover node neighbors
        if not requester.get_64bit_addr() in active_processes:
            self._log.debug("")
            self._log.debug(" [*] Discovering neighbors of %s", requester)
            self.__last_request_date = time.time()
            return self._discover_neighbors(requester, nodes_queue, active_processes, node_timeout)

        self._log.debug("")
        self._log.debug(" [*] Previous request for %s did not finish...", requester)
        nodes_queue.put(requester)

        return code

    def _check_not_discovered_nodes(self, devices_list, _nodes_queue):
        """
        Checks not discovered nodes in the current scan, and add them to the
        FIFO if necessary.

        Args:
            devices_list (List): List of nodes to check.
            _nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
        """
        # Check for nodes in the network not discovered in this scan and ensure
        # they are reachable by directly asking them for its NI
        for n_item in devices_list:
            if n_item.scan_counter != self.__scan_counter:
                self._log.debug(" [*] Checking not discovered node %s... (scan %d)",
                                n_item, self.__scan_counter)
                n_item._scan_counter = self.__scan_counter
                try:
                    n_item.get_parameter(ATStringCommand.NI, apply=False)
                    n_item._reachable = True
                    # Update also the connection
                    from digi.xbee.models.zdo import RouteStatus
                    if self._add_connection(Connection(
                            self._local_xbee, n_item, LinkQuality.UNKNOWN,
                            LinkQuality.UNKNOWN, RouteStatus.ACTIVE, RouteStatus.ACTIVE)):
                        self._log.debug("     - Added connection: %s >>> %s",
                                        self._local_xbee, n_item)
                except XBeeException:
                    n_item._reachable = False
                self._log.debug("     - Reachable: %s (scan %d)",
                                n_item._reachable, self.__scan_counter)

    def _discover_neighbors(self, _requester, _nodes_queue, _active_processes, _node_timeout):
        """
        Starts the process to discover the neighbors of the given node.

        Args:
            _requester(:class:`.AbstractXBeeDevice`): XBee to discover its neighbors.
            _nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
            _active_processes (List): List of active discovery processes.
            _node_timeout (Float): Timeout to discover neighbors (seconds).

        Returns:
            :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
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
        Blocking method. Performs a device discovery in the network and waits
        until it finishes (timeout or 'end' packet for 802.15.4)

        Args:
            node_id (String, optional, default=`None`): Node identifier of the
                remote XBee to discover.

        Returns:
            :class:`.NetworkDiscoveryStatus`: The error code, `None` if
                finished successfully.
        """
        self.__active_processes.append(str(self._local_xbee.get_64bit_addr()))

        try:
            timeout = self._calculate_timeout(
                default_timeout=XBeeNetwork._DEFAULT_DISCOVERY_TIMEOUT)
            # send "ND" async
            self._local_xbee.send_packet(
                ATCommPacket(self._local_xbee.get_next_frame_id(),
                             ATStringCommand.ND.command,
                             parameter=None if node_id is None
                             else bytearray(node_id, encoding='utf8', errors='ignore')),
                sync=False)

            self.__nd_processes.update({str(self._local_xbee.get_64bit_addr()): self})

            op_times_out = not self._stop_event.wait(timeout)

            self.__nd_processes.pop(str(self._local_xbee), None)

            if (op_times_out or not self.__discover_result
                    or self.__discover_result == ATCommandStatus.OK):
                err_code = None
            elif self.__discover_result and self.__discover_result != ATCommandStatus.OK:
                err_code = NetworkDiscoveryStatus.ERROR_NET_DISCOVER
            else:
                err_code = NetworkDiscoveryStatus.CANCEL

            self._node_discovery_process_finished(self._local_xbee, code=err_code,
                                                  error=err_code.description if err_code else None)

            return err_code
        except Exception as exc:
            self._local_xbee.log.exception(exc)
            return NetworkDiscoveryStatus.ERROR_GENERAL

    def _node_discovery_process_finished(self, requester, code=None, error=None):
        """
        Notifies the discovery process has finished successfully for `requester` node.

        Args:
            requester (:class:`.AbstractXBeeDevice`): XBee that requests the discovery process.
            code (:class:`.NetworkDiscoveryStatus`): Error code for the process.
            error (String): Error message, `None` if successfully finished.
        """
        # Purge the connections of the node
        self._log.debug("")
        self._log.debug(" [*] Purging node connections of %s", requester)
        purged = self.__purge_node_connections(requester,
                                               force=self.__rm_not_discovered_in_last_scan)
        if self.__rm_not_discovered_in_last_scan:
            for conn in purged:
                self._log.debug("     o Removed connection: %s", conn)

        # Remove the discovery process from the active processes list
        if str(requester.get_64bit_addr()) in self.__active_processes:
            self.__active_processes.remove(str(requester.get_64bit_addr()))

        if code and code not in (NetworkDiscoveryStatus.SUCCESS,
                                 NetworkDiscoveryStatus.CANCEL) or error:
            self._log.debug("[***** ERROR] During neighbors scan of %s", requester)
            if error:
                self._log.debug("        %s", error)
            else:
                self._log.debug("        %s", code.description)

            self._handle_special_errors(requester, error)
        else:
            self._log.debug("[!!!] Process finishes for %s  - Remaining: %d",
                            requester, len(self.__active_processes))

    def _handle_special_errors(self, requester, error):
        """
        Process some special errors.

        Args:
            requester (:class:`.AbstractXBeeDevice`): XBee that requests the discovery process.
            error (String): Error message.
        """
        if not (error.endswith(TransmitStatus.NOT_JOINED_NETWORK.description)
                or error.endswith(TransmitStatus.ADDRESS_NOT_FOUND.description)
                or error.endswith(TransmitStatus.NETWORK_ACK_FAILURE.description)
                or error.endswith("ZDO command not sent")
                or error.endswith("ZDO command answer not received")
                or error.endswith("%s command answer not received" % ATStringCommand.FN.command)
                or error.endswith("Error executing %s command (status: %s (%d))"
                                  % (ATStringCommand.FN.command,
                                     ATCommandStatus.TX_FAILURE.description,
                                     ATCommandStatus.TX_FAILURE.code))):
            return

        # The node is not found so it is not reachable
        self._log.debug("     o [***] Non-reachable: %s -> ERROR %s", requester, error)

        # Do not remove any node here, although the preference is configured
        # to do so. Do it at the end of the scan...
        no_reachables = [requester]

        requester._scan_counter = self.__scan_counter

        # Get the children nodes to mark them as non-reachable
        conn_list = self.__get_connections_for_node_a_b(requester, node_a=True)
        for conn in conn_list:
            child = conn.node_b
            # Child node already discovered in this scan
            if not child or child.scan_counter == self.__scan_counter:
                continue
            # Only the connection with the requester node joins the child to
            # the network so it is not reachable
            if len(self.get_node_connections(child)) <= 1:
                no_reachables.append(child)

            # If the node has more than one connection, we cannot be sure if it
            # will be discovered by other devices later since the scan did not end

        # Mark as non-reachable
        for node in no_reachables:
            self._set_node_reachable(node, False)

    def _discovery_done(self, active_processes):
        """
        Discovery process has finished either due to cancellation, successful
        completion, or failure.

        Args:
            active_processes (List): List of active discovery processes.
        """
        self._restore_network()

        if self.__nd_processes:
            copy = active_processes[:]
            for act_proc in copy:
                nd_proc = self.__nd_processes.get(act_proc)
                if not nd_proc:
                    continue
                nd_proc.stop_discovery_process()
                while act_proc in self.__nd_processes:
                    time.sleep(0.1)

        self.__nd_processes.clear()
        active_processes.clear()

        with self.__lock:
            self.__discovering = False

    def _restore_network(self):
        """
        Performs XBee configuration after the full network discovery.
        This restores the previous 'NT' value.
        """
        if self.__saved_nt is None:
            return

        self._log.debug("[*] Postconfiguring %s", ATStringCommand.NT.command)
        try:
            self.set_discovery_timeout(self.__saved_nt)
        except XBeeException as exc:
            self._error = "Could not restore XBee after network discovery: %s" % str(exc)

        self.__saved_nt = None

    def _is_802_compatible(self):
        """
        Checks if the device performing the node discovery is a legacy 802.15.4
        device or a S1B device working in compatibility mode.

        Returns:
            Boolean: `True` if the device performing the node discovery is a
                legacy 802.15.4 or S1B in compatibility mode, `False` otherwise.
        """
        if self._local_xbee.get_protocol() != XBeeProtocol.RAW_802_15_4:
            return False
        param = None
        try:
            param = self._local_xbee.get_parameter(ATStringCommand.C8, apply=False)
        except ATCommandException:
            pass
        if param is None or param[0] & 0x2 == 2:
            return True
        return False

    def _calculate_timeout(self, default_timeout=_DEFAULT_DISCOVERY_TIMEOUT):
        """
        Determines the discovery timeout.

        Gets timeout information from the device and applies the proper
        corrections to it.

        If the timeout cannot be determined getting it from the device, this
        method returns the default timeout for discovery operations.

        Args:
            default_timeout (Float): Default value to use in case of error.

        Returns:
            Float: discovery timeout in seconds.
        """
        self._log.debug("[*] Calculating network discovery timeout...")

        if not default_timeout or default_timeout < 0:
            default_timeout = XBeeNetwork._DEFAULT_DISCOVERY_TIMEOUT

        # Read the maximum discovery timeout (N?)
        try:
            discovery_timeout = utils.bytes_to_int(
                self._local_xbee.get_parameter(
                    ATStringCommand.N_QUESTION, apply=False)) / 1000
        except XBeeException:
            # If N? does not exist, read the NT parameter.
            self._log.debug("Could not calculate network discovery timeout: "
                            "'%s' does not exist, trying with '%s'",
                            ATStringCommand.N_QUESTION.command,
                            ATStringCommand.NT.command)
            # Read the network timeout (NT)
            try:
                discovery_timeout = self.get_discovery_timeout()
            except XBeeException as exc:
                discovery_timeout = default_timeout
                self._log.warning("Could not calculate network discovery timeout: "
                                  "Error reading '%s'", ATStringCommand.NT.command)
                self._local_xbee.log.exception(exc)

            # In DigiPoint the network discovery timeout is NT + the
            # network propagation time. It means that if the user sends an AT
            # command just after NT ms, s/he will receive a timeout exception.
            if self._local_xbee.get_protocol() == XBeeProtocol.DIGI_POINT:
                discovery_timeout += XBeeNetwork.__DIGI_POINT_TIMEOUT_CORRECTION

        self._log.debug("     Network discovery timeout: %f s", discovery_timeout)

        return discovery_timeout

    def __create_remote(self, x64bit_addr=XBee64BitAddress.UNKNOWN_ADDRESS,
                        x16bit_addr=XBee16BitAddress.UNKNOWN_ADDRESS, node_id=None,
                        role=Role.UNKNOWN, parent_addr=None, hw_version=None,
                        fw_version=None, op_mode=None):
        """
        Creates and returns a :class:`.RemoteXBeeDevice` from the provided data,
        if the data contains the required information and in the required
        format.

        Args:
            x64bit_addr (:class:`.XBee64BitAddress`, optional,
                default=`XBee64BitAddress.UNKNOWN_ADDRESS`): 64-bit address.
            x16bit_addr (:class:`.XBee16BitAddress`, optional,
                default=`XBee16BitAddress.UNKNOWN_ADDRESS`): 16-bit address.
            node_id (String, optional, default=`None`): Node identifier.
            role (:class:`.Role`, optional, default=`Role.UNKNOWN`): XBee role.
            parent_addr (:class:`.XBee64BitAddress`, optional, default=`None`):
                64-bit address of the parent.
            hw_version (:class:`.HardwareVersion`, optional, default=`None`): Hardware version.
            fw_version (bytearray, optional, default=`None`): Firmware version.
            op_mode (:class:`.OperatingMode`, optional, default=`None`): The
                operating mode, useful to update the local XBee.

        Returns:
            :class:`.RemoteXBeeDevice`: Remote XBee generated from the provided
                data if the data provided is correct and the XBee protocol is
                valid, `None` otherwise.

        .. seealso::
            | :class:`digi.xbee.models.address.XBee16BitAddress`
            | :class:`digi.xbee.models.address.XBee64BitAddress`
            | :class:`digi.xbee.models.hw.HardwareVersion`
            | :class:`digi.xbee.models.protocol.Role`
            | :class:`digi.xbee.models.mode.OperatingMode`
        """
        if x64bit_addr == "local":
            x64bit_addr = self._local_xbee.get_64bit_addr()

        if not (XBee64BitAddress.is_known_node_addr(x64bit_addr)
                or XBee16BitAddress.is_known_node_addr(x16bit_addr)):
            return None

        protocol = self._local_xbee.get_protocol()

        if protocol == XBeeProtocol.ZIGBEE:
            xbee = RemoteZigBeeDevice(self._local_xbee, x64bit_addr=x64bit_addr,
                                      x16bit_addr=x16bit_addr, node_id=node_id)
            if not XBee64BitAddress.is_known_node_addr(parent_addr):
                xbee.parent = None
            else:
                xbee.parent = self.get_device_by_64(parent_addr)
        elif protocol == XBeeProtocol.DIGI_MESH:
            xbee = RemoteDigiMeshDevice(self._local_xbee, x64bit_addr=x64bit_addr, node_id=node_id)
        elif protocol == XBeeProtocol.DIGI_POINT:
            xbee = RemoteDigiPointDevice(self._local_xbee, x64bit_addr=x64bit_addr, node_id=node_id)
        elif protocol == XBeeProtocol.RAW_802_15_4:
            xbee = RemoteRaw802Device(self._local_xbee, x64bit_addr=x64bit_addr,
                                      x16bit_addr=x16bit_addr, node_id=node_id)
        else:
            xbee = RemoteXBeeDevice(self._local_xbee, x64bit_addr=x64bit_addr,
                                    x16bit_addr=x16bit_addr, node_id=node_id)

        xbee._role = role
        xbee._hardware_version = hw_version
        xbee._firmware_version = fw_version
        xbee._operating_mode = op_mode

        return xbee

    def __get_data_for_remote(self, data):
        """
        Extracts the :class:`.XBee16BitAddress` (bytes 0 and 1), the
        :class:`.XBee64BitAddress` (bytes 2 to 9) and the node identifier
        from the provided data.

        Args:
            data (Bytearray): Data to extract information from.

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
            #    802.15.4 adds an info byte between 64bit address and XBee device ID, avoid it:
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
            parent_addr = XBee64BitAddress(data[i:i+2])
            i += 2
            # role is the next byte
            role = Role.get(utils.bytes_to_int(data[i:i+1]))
        return XBee16BitAddress(data[0:2]), XBee64BitAddress(data[2:10]), \
            node_id.decode('utf8', errors='ignore'), role, parent_addr

    def _set_node_reachable(self, node, reachable):
        """
        Configures a node as reachable or non-reachable. It throws an network
        event if this attribute changes.
        If the value of the attribute was already `reachable` value, this
        method does nothing.

        Args:
            node (:class:`.AbstractXBeeDevice`): The node to configure.
            reachable (Boolean): `True` to configure as reachable, `False` otherwise.
        """
        if node._reachable != reachable:
            node._reachable = reachable
            self._network_modified(NetworkEventType.UPDATE, NetworkEventReason.NEIGHBOR, node=node)

    def get_connections(self):
        """
        Returns a copy of the XBee network connections.

        A deep discover must be performed to get the connections between
        network nodes.

        If a new connection is added to the list after the execution of this
        method, this new connection is not added to the list returned by this
        method.

        Returns:
            List: A copy of the list of :class:`.Connection` for the network.

        .. seealso::
           | :meth:`.XBeeNetwork.get_node_connections`
           | :meth:`.XBeeNetwork.start_discovery_process`
        """
        with self.__conn_lock:
            return self.__connections.copy()

    def get_node_connections(self, node):
        """
        Returns the network connections with one of their ends `node`.

        A deep discover must be performed to get the connections between
        network nodes.

        If a new connection is added to the list after the execution of this
        method, this new connection is not added to the list returned by this
        method.

        Args:
            node (:class:`.AbstractXBeeDevice`): The node to get its connections.

        Returns:
            List: List of :class:`.Connection` with `node` end.

        .. seealso::
           | :meth:`.XBeeNetwork.get_connections`
           | :meth:`.XBeeNetwork.start_discovery_process`
        """
        connections = []
        with self.__conn_lock:
            for conn in self.__connections:
                if node in (conn.node_a, conn.node_b):
                    connections.append(conn)

        return connections

    def __get_connections_for_node_a_b(self, node, node_a=True):
        """
        Returns the network connections with the given node as `node_a` or
        `node_b`.

        Args:
            node (:class:`.AbstractXBeeDevice`): The node to get its connections.
            node_a (Boolean, optional, default=`True`): `True` to get
                connections where the given node is `node_a`, `False` to get
                those where the node is `node_b`.

        Returns:
            List: List of :class:`.Connection` with `node` as `node_a` end.
        """
        connections = []
        with self.__conn_lock:
            for conn in self.__connections:
                if ((node_a and conn.node_a == node)
                        or (not node_a and conn.node_b == node)):
                    connections.append(conn)

        return connections

    def __get_connection(self, node_a, node_b):
        """
        Returns the connection with ends `node_a` and `node_b`.

        Args:
            node_a (:class:`.AbstractXBeeDevice`): "node_a" end of the connection.
            node_b (:class:`.AbstractXBeeDevice`): "node_b" end of the connection.

        Returns:
            :class:`.Connection`: The connection with ends `node_a` and `node_b`,
                `None` if not found.

        Raises:
            ValueError: If `node_a` or `node_b` are `None`.
        """
        if not node_a:
            raise ValueError("Node A cannot be None")
        if not node_b:
            raise ValueError("Node B cannot be None")

        conn = Connection(node_a, node_b)

        with self.__conn_lock:
            if conn not in self.__connections:
                return None

            index = self.__connections.index(conn)

            return self.__connections[index]

    def __append_connection(self, connection):
        """
        Adds a new connection to the network.

        Args:
            connection (:class:`.Connection`): The connection to be added.

        Raise:
            ValueError: If `connection` is `None`.
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
            ValueError: If `connection` is `None`.
        """
        if not connection:
            raise ValueError("Connection cannot be None")

        with self.__conn_lock:
            if connection in self.__connections:
                self.__connections.remove(connection)

    def _add_connection(self, connection):
        """
        Adds a new connection to the network. The end nodes of this connection
        are added to the network if they do not exist.

        Args:
            connection (class:`.Connection`): The connection to add.

        Returns:
            Boolean: `True` if the connection was successfully added, `False`
                if the connection was already added.
        """
        if not connection:
            return False

        node_a = self.get_device_by_64(connection.node_a.get_64bit_addr())
        node_b = self.get_device_by_64(connection.node_b.get_64bit_addr())

        # Add the source node
        if not node_a:
            node_a = self._add_remote(connection.node_a, NetworkEventReason.NEIGHBOR)

        if not node_b:
            node_b = self._add_remote(connection.node_b, NetworkEventReason.NEIGHBOR)

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
            node (:class:`.AbstractXBeeDevice`): Node whose connections are
                being removed.
            only_as_node_a (Boolean, optional, default=`False`): Only remove
                those connections with the provided node as `node_a`.
            force (Boolean, optional, default=`True`): `True` to force the
                deletion of the connections, `False` otherwise.

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
            for conn in node_conn:
                if force:
                    self.__connections.remove(conn)
                else:
                    conn.lq_a2b = LinkQuality.UNKNOWN

        return c_removed

    def __purge(self, force=False):
        """
        Removes the nodes and connections that has not been discovered during
        the last scan.

        Args:
            force (Boolean, optional, default=`False`): `True` to force the
                deletion of nodes and connections, `False` otherwise.
        """
        # Purge nodes and connections from network
        removed_nodes = self.__purge_network_nodes(force=force)
        removed_connections = self.__purge_network_connections(force=force)

        self._log.debug("")
        self._log.debug(" [*] Purging network...")
        for node in removed_nodes:
            self._log.debug("     o Removed node: %s", node)
        for conn in removed_connections:
            self._log.debug("     o Removed connections: %s", conn)

    def __purge_network_nodes(self, force=False):
        """
        Removes the nodes and connections that has not been discovered during
        the last scan.

        Args:
            force (Boolean, optional, default=`False`): `True` to force the
                deletion of nodes, `False` otherwise.

        Returns:
            List: The list of purged nodes.
        """
        nodes_to_remove = []
        with self.__lock:
            for node in self.__devices_list:
                if (not node.scan_counter
                        or node.scan_counter != self.__scan_counter
                        or not node.reachable):
                    nodes_to_remove.append(node)

        for node in nodes_to_remove:
            self._remove_device(node, NetworkEventReason.NEIGHBOR, force=force)

        return nodes_to_remove

    def __purge_network_connections(self, force=False):
        """
        Removes the connections that has not been discovered during the last scan.

         Args:
            force (Boolean, optional, default=`False`): `True` to force the
                deletion of connections, `False` otherwise.

        Returns:
            List: The list of purged connections.
        """
        connections_to_remove = []
        with self.__conn_lock:
            for conn in self.__connections:
                if self.__scan_counter not in (conn.scan_counter_a2b,
                                               conn.scan_counter_b2a):
                    conn.lq_a2b = LinkQuality.UNKNOWN
                    conn.lq_b2a = LinkQuality.UNKNOWN
                    connections_to_remove.append(conn)
                elif conn.scan_counter_a2b != self.__scan_counter:
                    conn.lq_a2b = LinkQuality.UNKNOWN
                elif conn.scan_counter_b2a != self.__scan_counter:
                    conn.lq_b2a = LinkQuality.UNKNOWN
                elif (conn.lq_a2b == LinkQuality.UNKNOWN
                      and conn.lq_b2a == LinkQuality.UNKNOWN):
                    connections_to_remove.append(conn)

        if force:
            for conn in connections_to_remove:
                self.__del_connection(conn)

        return connections_to_remove

    def __purge_node_connections(self, node_a, force=False):
        """
        Purges given node connections. Removes the connections that has not
        been discovered during the last scan.

        Args:
            node_a (:class:`.AbstractXBeeDevice`): The "node_a" of the
                connections to purge.
            force (Boolean, optional, default=`False`): `True` to force the
                deletion of the connections, `False` otherwise.

        Returns:
            List: List of purged connections.
        """
        c_purged = []

        # Get node connections, but only those whose "node_a" is "node" (we are only purging
        # connections that are discovered with "node", and they are those with "node" as "node_a")
        node_conn = self.__get_connections_for_node_a_b(node_a, node_a=True)

        with self.__conn_lock:
            for conn in node_conn:
                if conn.scan_counter_a2b != self.__scan_counter:
                    conn.lq_a2b = LinkQuality.UNKNOWN
                    if (conn.scan_counter_b2a == self.__scan_counter
                            and conn.lq_b2a == LinkQuality.UNKNOWN):
                        c_purged.append(conn)

        if force:
            for conn in c_purged:
                self.__del_connection(conn)

        return c_purged

    def __wait_checking(self, seconds):
        """
        Waits some time, verifying if the process has been canceled.

        Args:
            seconds (Float): The amount of seconds to wait.

        Returns:
            :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
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
    This class represents a Zigbee network.

    The network allows the discovery of remote nodes in the same network as the
    local one and stores them.
    """
    __ROUTE_TABLE_TYPE = "route_table"
    __NEIGHBOR_TABLE_TYPE = "neighbor_table"

    def __init__(self, device):
        """
        Class constructor. Instantiates a new `ZigBeeNetwork`.

        Args:
            device (:class:`.ZigBeeDevice`): Local Zigbee node to get the
                network from.

        Raises:
            ValueError: If `device` is `None`.
        """
        super().__init__(device)

        self.__saved_ao = None

        # Dictionary to store the route and neighbor discovery processes per
        # node, so they can be stop when required.
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
        self._log.debug("[*] Preconfiguring %s", ATStringCommand.AO.command)
        try:
            self.__enable_explicit_mode()
        except XBeeException as exc:
            raise XBeeException(
                "Could not prepare XBee for network discovery: %s" % str(exc)) from exc

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

    def _node_discovery_process_finished(self, requester, code=None, error=None):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._node_discovery_process_finished`
        """
        super()._node_discovery_process_finished(requester, code=code, error=error)

        # An "address not found" error may occur when the 16-bit address
        # in the cache is not the right one. Try to read the new value and,
        # if it is different from the old one, add the node to the FIFO again
        if error and TransmitStatus.ADDRESS_NOT_FOUND.description in error:
            self._log.debug("[***** ERROR] '%s' for %s: refresh 16-bit address",
                            requester, error)
            x16_orig = requester.get_16bit_addr()
            try:
                x16 = XBee16BitAddress(
                    requester.get_parameter(ATStringCommand.MY, apply=False))
                if x16_orig != x16:
                    self._nodes_queue.put(requester)
            except XBeeException:
                pass

    def _check_not_discovered_nodes(self, devices_list, nodes_queue):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._check_not_discovered_nodes`
        """
        for node in devices_list:
            if not node.scan_counter or node.scan_counter != self.scan_counter:
                self._log.debug(" [*] Adding to FIFO not discovered node %s... (scan %d)",
                                node, self.scan_counter)
                nodes_queue.put(node)

    def _discovery_done(self, active_processes):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discovery_done`
        """
        copy = active_processes[:]
        for act_proc in copy:
            zdos = self.__zdo_processes.get(act_proc)
            if not zdos:
                continue

            self.__stop_zdo_command(zdos, self.__ROUTE_TABLE_TYPE)
            self.__stop_zdo_command(zdos, self.__NEIGHBOR_TABLE_TYPE)

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

        self._log.debug("[*] Postconfiguring %s", ATStringCommand.AO.command)
        try:
            self._local_xbee.set_parameter(ATStringCommand.AO,
                                           self.__saved_ao, apply=True)
        except XBeeException as exc:
            self._error = "Could not restore XBee after network discovery: %s" % str(exc)

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
            try:
                self.__enable_explicit_mode()
            except XBeeException as exc:
                self._log.warning("Unable to restore 'AO0 value: %s", str(exc))

            # Add the node to the FIFO to try again
            self._nodes_queue.put(requester)

    def __enable_explicit_mode(self):
        """
        Enables explicit mode by modifying the value of 'AO' parameter if it
        is needed.
        """
        self.__saved_ao = self._local_xbee.get_api_output_mode_value()

        # Do not configure AO if it is already:
        #   * Bit 0: Native/Explicit API output (1)
        #   * Bit 5: Prevent ZDO msgs from going out the serial port (0)
        value = bytearray([self.__saved_ao[0]]) if self.__saved_ao \
            else bytearray([APIOutputModeBit.EXPLICIT.code])
        if (value[0] & APIOutputModeBit.EXPLICIT.code
                and not value[0] & APIOutputModeBit.SUPPRESS_ALL_ZDO_MSG.code):
            self.__saved_ao = None

            return

        value[0] = value[0] | APIOutputModeBit.EXPLICIT.code
        value[0] = value[0] & ~APIOutputModeBit.SUPPRESS_ALL_ZDO_MSG.code

        self._local_xbee.set_parameter(ATStringCommand.AO, value, apply=True)

    def __get_route_table(self, requester, nodes_queue, node_timeout):
        """
        Launch the process to get the route table of the XBee.

        Args:
            requester (:class:`.AbstractXBeeDevice`): XBee to discover its
                routing table.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
            node_timeout (Float): Timeout to get the routing table (seconds).

        Returns:
            :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
        """
        def __new_route_cb(xbee, route):
            self._log.debug("     o Discovered route of %s: %s - %s -> %s",
                            xbee, route.destination, route.next_hop, route.status)

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
            else:
                r_in_list = routes_list.get(str(route.next_hop))
                self._log.debug("       - ROUTE already found %s - %s -> %s",
                                r_in_list.destination, r_in_list.next_hop, r_in_list.status)
                from digi.xbee.models.zdo import RouteStatus
                if r_in_list.status != RouteStatus.ACTIVE and route.status == RouteStatus.ACTIVE:
                    self._log.debug("       - Updating route %s - %s -> %s",
                                    route.destination, route.next_hop, route.status)
                    routes_list.update({str(route.next_hop): route})

            # Check for cancel
            if self._stop_event.is_set():
                cmd = self.__get_zdo_command(xbee, self.__ROUTE_TABLE_TYPE)
                if cmd:
                    cmd.stop()

        def __route_discover_finished_cb(xbee, _routes, error):
            zdo_processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
            if zdo_processes:
                zdo_processes.pop(self.__ROUTE_TABLE_TYPE)

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

                # Get neighbor table
                code = self.__get_neighbor_table(xbee, nodes_queue, node_timeout)
                if code != NetworkDiscoveryStatus.SUCCESS:
                    self._node_discovery_process_finished(
                        xbee, code=NetworkDiscoveryStatus.ERROR_GENERAL, error=error)

        self._log.debug("   [o] Getting ROUTE TABLE of node %s", requester)

        from digi.xbee.models.zdo import RouteTableReader
        reader = RouteTableReader(requester, configure_ao=False, timeout=node_timeout)
        reader.get_route_table(route_cb=__new_route_cb,
                               finished_cb=__route_discover_finished_cb)

        processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
        if not processes:
            processes = {}
            self.__zdo_processes.update({str(requester.get_64bit_addr()): processes})
        processes.update({self.__ROUTE_TABLE_TYPE: reader})

        return NetworkDiscoveryStatus.SUCCESS

    def __get_neighbor_table(self, requester, nodes_queue, node_timeout):
        """
        Launch the process to get the neighbor table of the XBee.

        Args:
            requester (:class:`.AbstractXBeeDevice`): XBee to discover its
                neighbor table.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
            node_timeout (Float): Timeout to get the neighbor table (seconds).

        Returns:
            :class:`.NetworkDiscoveryStatus`: Resulting status of the process.
        """
        def __new_neighbor_cb(xbee, neighbor):
            # Do not add a connection to the same node
            if neighbor == xbee:
                return

            # Get the discovered routes of the node
            routes_list = self.__discovered_routes.get(str(xbee.get_64bit_addr()))

            # Add the new neighbor
            self.__process_discovered_neighbor_data(xbee, routes_list, neighbor, nodes_queue)

            # Check for cancel
            if self._stop_event.is_set():
                cmd = self.__get_zdo_command(xbee, self.__NEIGHBOR_TABLE_TYPE)
                if cmd:
                    cmd.stop()

        def __neighbor_discover_finished_cb(xbee, _, error):
            zdo_processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
            if zdo_processes:
                zdo_processes.pop(self.__NEIGHBOR_TABLE_TYPE, None)
            self.__zdo_processes.pop(str(requester.get_64bit_addr()), None)

            # Remove the discovered routes
            self.__discovered_routes.pop(str(xbee.get_64bit_addr()), None)

            # Process the error if exists
            code = NetworkDiscoveryStatus.SUCCESS if not error \
                else NetworkDiscoveryStatus.ERROR_GENERAL
            self._node_discovery_process_finished(xbee, code=code, error=error)

        self._log.debug("   [o] Getting NEIGHBOR TABLE of node %s", requester)

        from digi.xbee.models.zdo import NeighborTableReader
        reader = NeighborTableReader(requester, configure_ao=False, timeout=node_timeout)
        reader.get_neighbor_table(neighbor_cb=__new_neighbor_cb,
                                  finished_cb=__neighbor_discover_finished_cb)

        processes = self.__zdo_processes.get(str(requester.get_64bit_addr()))
        if not processes:
            processes = {}
            self.__zdo_processes.update({str(requester.get_64bit_addr()): processes})
        processes.update({self.__NEIGHBOR_TABLE_TYPE: reader})

        return NetworkDiscoveryStatus.SUCCESS

    def __process_discovered_neighbor_data(self, requester, routes, neighbor, nodes_queue):
        """
        Notifies a neighbor has been discovered.

        Args:
            requester (:class:`.AbstractXBeeDevice`): Zigbee node whose neighbor
                table was requested.
            routes (Dictionary): A dictionary with the next hop 16-bit address
                string as key, and the route (:class:`.Route`) as value.
            neighbor (:class:`.Neighbor`): The discovered neighbor.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
        """
        self._log.debug("     o Discovered neighbor of %s: %s (%s)",
                        requester, neighbor.node, neighbor.relationship.name)

        # Requester node is clearly reachable
        self._set_node_reachable(requester, True)

        # Add the neighbor node to the network
        node = self._add_remote(neighbor.node, NetworkEventReason.NEIGHBOR)
        if not node:
            # Node already in network for this scan
            node = self.get_device_by_64(neighbor.node.get_64bit_addr())
            self._log.debug("       - NODE already in network in this scan (scan: %d) %s",
                            node.scan_counter, node)
        else:
            if neighbor.node.get_role() != Role.END_DEVICE:
                # Add to the FIFO to ask for its neighbors
                nodes_queue.put(node)
                self._log.debug("       - Added to network (scan: %d)", node.scan_counter)
            else:
                # Not asking to End Devices when found, consider them as reachable
                self._set_node_reachable(node, True)
                # Save its parent
                node.parent = requester
            self._device_discovered(node)

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
            self._log.debug("       - Using route for the connection: %d", route.status.id)
        elif (neighbor.node.get_role() != Role.UNKNOWN
              and neighbor.relationship != NeighborRelationship.PREVIOUS_CHILD
              and neighbor.relationship != NeighborRelationship.SIBLING):
            self._log.debug(
                "       - No route for this node, using relationship for the connection: %s",
                neighbor.relationship.name)
            if neighbor.relationship == NeighborRelationship.PARENT:
                connection = Connection(node, requester, lq_a2b=neighbor.lq,
                                        lq_b2a=LinkQuality.UNKNOWN, status_a2b=RouteStatus.ACTIVE,
                                        status_b2a=RouteStatus.UNKNOWN)
            elif neighbor.relationship in (NeighborRelationship.CHILD,
                                           NeighborRelationship.UNDETERMINED):
                connection = Connection(requester, node, lq_a2b=neighbor.lq,
                                        lq_b2a=LinkQuality.UNKNOWN, status_a2b=RouteStatus.ACTIVE,
                                        status_b2a=RouteStatus.UNKNOWN)
        if not connection:
            self._log.debug("       - Connection NULL for this neighbor")
            return

        if self._add_connection(connection):
            self._log.debug("       - Added connection (LQI: %d) %s >>> %s",
                            neighbor.lq, requester, node)
        else:
            self._log.debug(
                "       - CONNECTION (LQI: %d) already in network in this"
                " scan (scan: %d) %s >>> %s",
                neighbor.lq, node.scan_counter, requester, node)

    def __get_zdo_command(self, xbee, cmd_type):
        """
        Returns the ZDO command in process (route/neighbor table) for the
        provided node.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): Node to get a ZDO command in process.
            cmd_type (String): The ZDO command type (route/neighbor table)
        """
        cmds = self.__zdo_processes.get(str(xbee.get_64bit_addr()))
        if cmds:
            return cmds.get(cmd_type)

        return None

    @staticmethod
    def __stop_zdo_command(commands, cmd_type):
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

    The network allows the discovery of remote nodes in the same network as the
    local one and stores them.
    """

    def _calculate_timeout(self, default_timeout=XBeeNetwork._DEFAULT_DISCOVERY_TIMEOUT):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._calculate_timeout`
        """
        discovery_timeout = super()._calculate_timeout(default_timeout=default_timeout)

        if self._is_802_compatible():
            discovery_timeout += 2  # Give some time to receive the ND finish packet

        self._log.debug("     802.15.4 network discovery timeout: %f s", discovery_timeout)

        return discovery_timeout


class DigiMeshNetwork(XBeeNetwork):
    """
    This class represents a DigiMesh network.

    The network allows the discovery of remote nodes in the same network as the
    local one and stores them.
    """

    def __init__(self, device):
        """
        Class constructor. Instantiates a new `DigiMeshNetwork`.

        Args:
            device (:class:`.DigiMeshDevice`): Local DigiMesh node to get the
                network from.

        Raises:
            ValueError: If `device` is `None`.
        """
        super().__init__(device)

        self.__saved_no = None
        self.__saved_so = None

        self.__sync_sleep_enabled = False

        # Calculated timeout based on the 'N?' value of the local XBee and the
        # sleep configuration of the network.
        self.__real_node_timeout = None

        # Dictionary to store the neighbor find processes per node, so they
        # can be stop when required.
        # The dictionary uses as key the 64-bit address string representation (to be thread-safe)
        self.__neighbor_finders = {}

    def _calculate_timeout(self, default_timeout=XBeeNetwork._DEFAULT_DISCOVERY_TIMEOUT):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._calculate_timeout`
        """
        discovery_timeout = super()._calculate_timeout(default_timeout=default_timeout)

        # If the module is 'Synchronous Cyclic Sleep Support' (SM=7) or
        # 'Synchronous Cyclic Sleep' (SM=8), we need to calculate the total
        # number of inactivity seconds.
        try:
            sm_value = utils.bytes_to_int(
                self._local_xbee.get_parameter(ATStringCommand.SM.command, apply=False))
            self.__sync_sleep_enabled = sm_value in (7, 8)
            if self.__sync_sleep_enabled:
                os_val = utils.bytes_to_int(  # Operating sleep time
                    self._local_xbee.get_parameter(ATStringCommand.OS.command, apply=False)) / 100
                ow_val = utils.bytes_to_int(  # Operating wake time
                    self._local_xbee.get_parameter(ATStringCommand.OW.command, apply=False)) / 1000
                discovery_timeout = \
                    discovery_timeout * (os_val + ow_val) / ow_val
        except XBeeException:
            self._log.warning("Could not calculate network discovery timeout: "
                              "unable to read sleep parameters ('%s', '%s')",
                              ATStringCommand.OS.command, ATStringCommand.OW.command)

        self._log.debug("     DigiMesh network discovery timeout: %f s", discovery_timeout)

        return discovery_timeout

    def _prepare_network_discovery(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._prepare_network_discovery`
        """
        super()._prepare_network_discovery()

        self._log.debug("[*] Preconfiguring %s", ATStringCommand.NO.command)
        try:
            # Configured discovery options "APPEND_DD" and "APPEND_RSSI" in the
            # local XBee affects also to the FN requests of the remotes.
            # For example, if "APPEND_RSSI" is enabled in the local XBee, no
            # matter what is configured in any remote, when 'FN' is sent as a
            # remote command to a remote node, the RSSI is included in every
            # received response. The same is applicable to "APPEND_DD".
            self.__saved_no = self.get_discovery_options()

            # Do not configure NO if it is already
            if utils.is_bit_enabled(self.__saved_no[0], 2):
                self.__saved_no = None
            else:
                self.set_discovery_options({DiscoveryOptions.APPEND_RSSI})

            self._log.debug("[*] Preconfiguring %s", ATStringCommand.SO.command)
            self.__saved_so = self._local_xbee.get_parameter(
                ATStringCommand.SO, apply=False)

            # Enable bit 2 of SO: Enable API sleep status messages
            # Useful for synchronous sleep networks to know when the network is sleeping or awake
            if utils.is_bit_enabled(self.__saved_so[1], 2):
                self.__saved_so = None
            else:
                value = utils.int_to_bytes(utils.bytes_to_int(self.__saved_so), 2)
                value[1] = value[1] | 0x04 if not (value[1] & 0x04 == 4) else value[1]

                self._local_xbee.set_parameter(ATStringCommand.SO, value, apply=True)

        except XBeeException as exc:
            raise XBeeException(
                "Could not prepare XBee for network discovery: %s" % str(exc)) from exc

        # Calculate the real timeout to wait for responses, based on 'N?' and
        # the cyclic sleep times, if the node is configured for that.
        # This is calculated for the local node and applied also for remote
        # nodes (that is, it is considering 'NT', 'NN', 'NH' of all nodes are
        # configured with the same values in each module)
        self.__real_node_timeout = self._calculate_timeout(default_timeout=self._node_timeout)

    def _discover_neighbors(self, requester, nodes_queue, active_processes, node_timeout):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discover_neighbors`
        """
        def __new_neighbor_cb(xbee, neighbor):
            # Do not add a connection to the same node
            if neighbor == xbee:
                return

            # Add the new neighbor
            self.__process_discovered_neighbor_data(xbee, neighbor, nodes_queue)

        def __neighbor_discover_finished_cb(xbee, _, error):
            self.__neighbor_finders.pop(str(requester.get_64bit_addr()), None)

            # Process the error if exists
            code = NetworkDiscoveryStatus.SUCCESS if not error \
                else NetworkDiscoveryStatus.ERROR_GENERAL
            self._node_discovery_process_finished(xbee, code=code, error=error)

        self._log.debug("   [o] Calling NEIGHBOR FINDER for node %s", requester)

        if requester.is_remote() and self.__sync_sleep_enabled:
            self._log.debug("     - Ensure network is awaken ...")
            awake = threading.Event()

            # Register a callback to check if the local XBee is configured to
            # 'Enable API sleep status messages' (bit 2 of 'SO')
            def modem_st_cb(modem_status):
                if modem_status == ModemStatus.NETWORK_WOKE_UP:
                    self._local_xbee.del_modem_status_received_callback(modem_st_cb)
                    awake.set()

            self._local_xbee.add_modem_status_received_callback(modem_st_cb)
            while not awake.wait(timeout=node_timeout):
                pass

        from digi.xbee.models.zdo import NeighborFinder
        finder = NeighborFinder(requester, timeout=self.__real_node_timeout)
        finder.get_neighbors(neighbor_cb=__new_neighbor_cb,
                             finished_cb=__neighbor_discover_finished_cb)

        active_processes.append(str(requester.get_64bit_addr()))
        self.__neighbor_finders.update({str(requester.get_64bit_addr()): finder})

        return NetworkDiscoveryStatus.SUCCESS

    def _check_not_discovered_nodes(self, devices_list, nodes_queue):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._check_not_discovered_nodes`
        """
        for node in devices_list:
            if not node.scan_counter or node.scan_counter != self.scan_counter:
                self._log.debug(" [*] Adding to FIFO not discovered node %s... (scan %d)",
                                node, self.scan_counter)
                nodes_queue.put(node)

    def _discovery_done(self, active_processes):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeNetwork._discovery_done`
        """
        copy = active_processes[:]
        for act_proc in copy:
            finder = self.__neighbor_finders.get(act_proc)
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
        error = ""

        if self.__saved_no is not None:
            self._log.debug("[*] Postconfiguring %s", ATStringCommand.NO.command)
            try:
                self._local_xbee.set_parameter(ATStringCommand.NO,
                                               self.__saved_no,
                                               apply=bool(not self.__saved_so))
            except XBeeException as exc:
                error = str(exc)

            self.__saved_no = None

        if self.__saved_so is not None:
            self._log.debug("[*] Postconfiguring %s", ATStringCommand.SO.command)
            try:
                self._local_xbee.set_parameter(ATStringCommand.SO,
                                               self.__saved_so, apply=True)
            except XBeeException as exc:
                if error:
                    error += ". "
                error += str(exc)

            self.__saved_so = None

        if error:
            self._error = "Could not restore XBee after network discovery: %s" % error

    def __process_discovered_neighbor_data(self, requester, neighbor, nodes_queue):
        """
        Notifies a neighbor has been discovered.

        Args:
            requester (:class:`.AbstractXBeeDevice`): DigiMesh node whose
                neighbors was requested.
            neighbor (:class:`.Neighbor`): The discovered neighbor.
            nodes_queue (:class:`queue.Queue`): FIFO where the nodes to
                discover their neighbors are stored.
        """
        self._log.debug("     o Discovered neighbor of %s: %s (%s)",
                        requester, neighbor.node, neighbor.relationship.name)

        # Requester node is clearly reachable
        self._set_node_reachable(requester, True)

        # Add the neighbor node to the network
        node = self._add_remote(neighbor.node, NetworkEventReason.NEIGHBOR)
        if not node:
            # Node already in network for this scan
            node = self.get_device_by_64(neighbor.node.get_64bit_addr())
            self._log.debug("       - NODE already in network in this scan (scan: %d) %s",
                            node.scan_counter, node)
            # Do not add the connection if the discovered device is itself
            if node.get_64bit_addr() == requester.get_64bit_addr():
                return
        else:
            # Add to the FIFO to ask for its neighbors
            nodes_queue.put(node)
            self._log.debug("       - Added to network (scan: %d)", node.scan_counter)

            self._device_discovered(node)

        # Add connections
        from digi.xbee.models.zdo import RouteStatus
        connection = Connection(requester, node, lq_a2b=neighbor.lq, lq_b2a=LinkQuality.UNKNOWN,
                                status_a2b=RouteStatus.ACTIVE, status_b2a=RouteStatus.ACTIVE)

        if self._add_connection(connection):
            self._log.debug("       - Added connection (RSSI: %s) %s >>> %s",
                            connection.lq_a2b, requester, node)
        else:
            self._log.debug(
                "       - CONNECTION (RSSI: %s) already in network in this "
                "scan (scan: %d) %s >>> %s",
                connection.lq_a2b, node.scan_counter, requester, node)

        # Found node is clearly reachable, it answered to a FN
        self._set_node_reachable(node, True)


class DigiPointNetwork(XBeeNetwork):
    """
    This class represents a DigiPoint network.

    The network allows the discovery of remote nodes in the same network as the
    local one and stores them.
    """


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

    def __str__(self):
        return "%s (%d)" % (self.__description, self.__code)

    @property
    def code(self):
        """
        Returns the code of the `NetworkEventType` element.

        Returns
            Integer: Code of the `NetworkEventType` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `NetworkEventType` element.

        Returns:
            String: Description of the `NetworkEventType` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the network event for the given code.

        Args:
            code (Integer): Code of the network event to get.

        Returns:
            :class:`.NetworkEventType`: the `NetworkEventType` with the given
                code, `None` if there is not any event with the provided code.
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
    READ_INFO = (0x05, "Read XBee information")
    FIRMWARE_UPDATE = (0x06, "The firmware of the device was updated")
    PROFILE_UPDATE = (0x07, "New profile applied to the device")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __str__(self):
        return "%s (%d)" % (self.__description, self.__code)

    @property
    def code(self):
        """
        Returns the code of the `NetworkEventReason` element.

        Returns:
            Integer: Code of the `NetworkEventReason` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `NetworkEventReason` element.

        Returns:
            String: Description of the `NetworkEventReason` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the network event reason for the given code.

        Args:
            code (Integer): Code of the network event reason to get.

        Returns:
            :class:`.NetworkEventReason`: the `NetworkEventReason` with the
                given code, `None` if there is not any reason with the provided code.
        """
        for reason in cls:
            if reason.code == code:
                return reason

        return None


NetworkEventReason.__doc__ += utils.doc_enum(NetworkEventReason)


class LinkQuality:
    """
    This class represents the link quality of a connection.
    It can be a LQI (Link Quality Index) for Zigbee devices, or RSSI
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
        Class constructor. Instantiates a new `LinkQuality`.

        Args:
            lq (Integer, optional, default=`UNKNOWN`): Link quality.
            is_rssi (Boolean, optional, default=`False`): `True` to specify the
                value is a RSSI, `False` for LQI.
        """
        self.__lq = lq
        self.__is_rssi = is_rssi

    def __str__(self):
        if self.__lq == 0:
            return str(self.__lq)

        if self.__lq == self.UNKNOWN_VALUE:
            return self.__UNKNOWN_STR

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
             Boolean: `True` if this is an RSSI value, `False` for LQI.
        """
        return self.__is_rssi


LinkQuality.UNKNOWN = LinkQuality(lq=LinkQuality.UNKNOWN_VALUE)


class Connection:
    """
    This class represents a generic connection between two nodes in a XBee
    network. It contains the source and destination nodes, the link quality of
    the connection between them and its status.
    """

    def __init__(self, node_a, node_b, lq_a2b=None, lq_b2a=None, status_a2b=None, status_b2a=None):
        """
        Class constructor. Instantiates a new `Connection`.

        Args:
            node_a (:class:`.AbstractXBeeDevice`): One of the connection ends.
            node_b (:class:`.AbstractXBeeDevice`): The other connection end.
            lq_a2b (:class:`.LinkQuality` or Integer, optional, default=`None`): Link
                quality for the connection node_a -> node_b. If not specified
                `LinkQuality.UNKNOWN` is used.
            lq_b2a (:class:`.LinkQuality` or Integer, optional, default=`None`): Link
                quality for the connection node_b -> node_a. If not specified
                `LinkQuality.UNKNOWN` is used.
            status_a2b (:class:`digi.xbee.models.zdo.RouteStatus`, optional, default=`None`): The
                status for the connection node_a -> node_b. If not specified
                `RouteStatus.UNKNOWN` is used.
            status_b2a (:class:`digi.xbee.models.zdo.RouteStatus`, optional, default=`None`): The
                status for the connection node_b -> node_a. If not specified
                `RouteStatus.UNKNOWN` is used.

        Raises:
            ValueError: If `node_a` or `node_b` is `None`.

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
            self.__node_a, self.__node_b, self.__st_a2b, self.__st_b2a,
            self.__lq_a2b, self.__lq_b2a)

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
             :class:`.AbstractXBeeDevice`: The node B.

        .. seealso::
           | :class:`.AbstractXBeeDevice`
        """
        return self.__node_b

    @property
    def lq_a2b(self):
        """
        Returns the link quality of the connection from node A to node B.

        Returns:
             :class:`.LinkQuality`: Link quality for the connection A -> B.

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
             :class:`.LinkQuality`: Link quality for the connection B -> A.

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
             :class:`.RouteStatus`: The status for A -> B connection.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        return self.__st_a2b

    @status_a2b.setter
    def status_a2b(self, new_status_a2b):
        """
        Sets the status of this connection from node A to node B.

        Args:
            new_status_a2b (:class:`.RouteStatus`): The new A -> B connection status.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        self.__st_a2b = new_status_a2b

    @property
    def status_b2a(self):
        """
        Returns the status of this connection from node B to node A.

        Returns:
             :class:`.RouteStatus`: The status for B -> A connection.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        return self.__st_b2a

    @status_b2a.setter
    def status_b2a(self, new_status_b2a):
        """
        Sets the status of this connection from node B to node A.

        Args:
            new_status_b2a (:class:`o.RouteStatus`): The new B -> A connection status.

        .. seealso::
           | :class:`digi.xbee.models.zdo.RouteStatus`
        """
        self.__st_b2a = new_status_b2a

    @staticmethod
    def __get_lq(lq_val, src):
        """
        Retrieves the `LinkQuality` object that corresponds to the integer provided.

        Args:
            lq_val (Integer): The link quality value.
            src (:class:`.AbstractXBeeDevice`): The node from where the connection starts.

        Returns:
             :class:`.LinkQuality`: The corresponding `LinkQuality`.

        .. seealso::
           | :class:`.AbstractXBeeDevice`
           | :class:`.LinkQuality`
        """
        if isinstance(lq_val, LinkQuality):
            return lq_val
        if isinstance(lq_val, int):
            return LinkQuality(lq=lq_val,
                               is_rssi=src.get_protocol() in (XBeeProtocol.DIGI_MESH,
                                                              XBeeProtocol.XTEND_DM,
                                                              XBeeProtocol.XLR_DM,
                                                              XBeeProtocol.SX))
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
             new_scan_counter_a2b (Integer): The scan counter for this
                connection, discovered by its A node.
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
             new_scan_counter_b2a (Integer): The scan counter for this
                connection, discovered by its B node.
        """
        self.__scan_counter_b2a = new_scan_counter_b2a
