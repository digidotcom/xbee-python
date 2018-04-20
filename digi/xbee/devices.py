# Copyright 2017, 2018, Digi International Inc.
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
from ipaddress import IPv4Address
from threading import Event
import threading
import time

import serial
from serial.serialutil import SerialTimeoutException

from digi.xbee.packets.cellular import TXSMSPacket
from digi.xbee.models.accesspoint import AccessPoint, WiFiEncryptionType
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import OperatingMode, APIOutputMode, IPAddressingMode
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress, XBeeIMEIAddress
from digi.xbee.models.message import XBeeMessage, ExplicitXBeeMessage, IPMessage
from digi.xbee.models.options import TransmitOptions, RemoteATCmdOptions, DiscoveryOptions
from digi.xbee.models.protocol import XBeeProtocol, IPProtocol
from digi.xbee.models.status import ATCommandStatus, TransmitStatus, PowerLevel, \
    ModemStatus, CellularAssociationIndicationStatus, WiFiAssociationIndicationStatus, AssociationIndicationStatus,\
    NetworkDiscoveryStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ATCommPacket, TransmitPacket, RemoteATCommandPacket, ExplicitAddressingPacket
from digi.xbee.packets.network import TXIPv4Packet
from digi.xbee.packets.raw import TX64Packet, TX16Packet
from digi.xbee.util import utils
from digi.xbee.exception import XBeeException, TimeoutException, InvalidOperatingModeException, \
    ATCommandException, OperationNotSupportedException
from digi.xbee.io import IOSample, IOMode
from digi.xbee.reader import PacketListener, PacketReceived, DeviceDiscovered, DiscoveryProcessFinished
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

    LOG_PATTERN = "{port:<6s}{event:<12s}{opmode:<20s}{content:<50s}"
    """
    Pattern used to log packet events.
    """

    _log = logging.getLogger(__name__)
    """
    Logger.
    """

    def __init__(self, local_xbee_device=None, serial_port=None, sync_ops_timeout=_DEFAULT_TIMEOUT_SYNC_OPERATIONS):
        """
        Class constructor. Instantiates a new :class:`.AbstractXBeeDevice` object with the provided parameters.

        Args:
            local_xbee_device (:class:`.XBeeDevice`, optional): only necessary if XBee device is remote. The local
                XBee device that will behave as connection interface to communicate with the remote XBee one.
            serial_port (:class:`.XBeeSerialPort`, optional): only necessary if the XBee device is local. The serial
                port that will be used to communicate with this XBee.
            sync_ops_timeout (Integer, default: :attr:`AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS`): the
                timeout (in seconds) that will be applied for all synchronous operations.

        .. seealso::
           | :class:`.XBeeDevice`
           | :class:`.XBeeSerialPort`
        """
        self.__current_frame_id = 0x00

        self._16bit_addr = None
        self._64bit_addr = None
        self._apply_changes_flag = True

        self._is_open = False
        self._operating_mode = None

        self._local_xbee_device = local_xbee_device
        self._serial_port = serial_port
        self._timeout = sync_ops_timeout

        self._io_sample_event = Event()  # event: used to wait to the next IO sample.
        self._wait_for_next_io_sample = False  # flag: waiting for next IO sample or not.
        self._last_io_sample_received = None  # reference io sample received in the current read.

        self._hardware_version = None
        self._firmware_version = None
        self._protocol = None
        self._node_id = None

        self._packet_listener = None

        self._log.addHandler(logging.StreamHandler())

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

    def update_device_data_from(self, device):
        """
        Updates the current device reference with the data provided for the given device.

        This is only for internal use.

        Args:
            device (:class:`.AbstractXBeeDevice`): the XBee device to get the data from.
        """
        if device.get_node_id() is not None:
            self._node_id = device.get_node_id()

        addr64 = device.get_64bit_addr()
        if (addr64 is not None and
            addr64 != XBee64BitAddress.UNKNOWN_ADDRESS and
            addr64 != self._64bit_addr and
                (self._64bit_addr is None or self._64bit_addr == XBee64BitAddress.UNKNOWN_ADDRESS)):
            self._64bit_addr = addr64

        addr16 = device.get_16bit_addr()
        if addr16 is not None and addr16 != self._16bit_addr:
            self._16bit_addr = addr16

    @abstractmethod
    def get_parameter(self, parameter):
        """
        Returns the value of the provided parameter via an AT Command.

        Args:
            parameter (String): parameter to get.

        Returns:
            Bytearray: the parameter value.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        pass

    @abstractmethod
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

        This flags only works for volatile memory, if you want to save
        changed parameters in non-volatile memory, even for remote devices,
        you must execute "WR" command by some of the 2 ways mentioned above.

        Args:
            parameter (String): parameter to set.
            value (Bytearray): value of the parameter.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        pass

    def execute_command(self, parameter):
        """
        Executes the provided command.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        self.set_parameter(parameter, None)

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
        self.execute_command("AC")

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
        self.execute_command("WR")

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

    def read_device_info(self):
        """
        Updates all instance parameters reading them from the XBee device.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            ATCommandException: if the response is not as expected.
        """
        if self.is_remote():
            if not self._local_xbee_device.serial_port.is_open:
                raise XBeeException("Local XBee device's serial port closed")
        else:
            if (self._operating_mode != OperatingMode.API_MODE and
               self._operating_mode != OperatingMode.ESCAPED_API_MODE):
                raise InvalidOperatingModeException("Not supported operating mode: " + str(self._operating_mode))

            if not self._serial_port.is_open:
                raise XBeeException("XBee device's serial port closed")

        # Hardware version:
        self._hardware_version = HardwareVersion.get(self.get_parameter("HV")[0])
        # Firmware version:
        self._firmware_version = self.get_parameter("VR")
        # Original value of the protocol:
        orig_protocol = self.get_protocol()
        # Protocol:
        self._protocol = XBeeProtocol.determine_protocol(self._hardware_version.code, self._firmware_version)
        
        if orig_protocol is not None and orig_protocol != XBeeProtocol.UNKNOWN and orig_protocol != self._protocol:
            raise XBeeException("Error reading device information: "
                                "Your module seems to be %s and NOT %s. " % (self._protocol, orig_protocol) +
                                "Check if you are using the appropriate device class.")
        
        # 64-bit address:
        sh = self.get_parameter("SH")
        sl = self.get_parameter("SL")
        self._64bit_addr = XBee64BitAddress(sh + sl)
        # Node ID:
        self._node_id = self.get_parameter("NI").decode()
        # 16-bit address:
        if self._protocol in [XBeeProtocol.ZIGBEE,
                              XBeeProtocol.RAW_802_15_4,
                              XBeeProtocol.XTEND,
                              XBeeProtocol.SMART_ENERGY,
                              XBeeProtocol.ZNET]:
            r = self.get_parameter("MY")
            self._16bit_addr = XBee16BitAddress(r)

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

        self.set_parameter("NI", bytearray(node_id, 'utf8'))
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
            raise OperationNotSupportedException("16-bit address can only be set in 802.15.4 protocol")

        self.set_parameter("MY", value.address)
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
            self._local_xbee_device.serial_port.timeout = self._timeout
        else:
            self._serial_port.timeout = self._timeout

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
        dh = self.get_parameter("DH")
        dl = self.get_parameter("DL")
        return XBee64BitAddress(dh + dl)

    def set_dest_address(self, addr):
        """
        Sets the 64-bit address of the XBee device that data will be reported to.

        Args:
            addr(:class:`.XBee64BitAddress` or :class:`.RemoteXBeeDevice`): the address itself or the remote XBee device
                that you want to set up its address as destination address.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
            All exceptions raised by :meth:`.XBeeDevice.set_parameter`.
        """
        if isinstance(addr, RemoteXBeeDevice):
            addr = addr.get_64bit_addr()

        apply_changes = None
        with self.__generic_lock:
            try:
                apply_changes = self.is_apply_changes_enabled()
                self.enable_apply_changes(False)
                self.set_parameter("DH", addr.address[:4])
                self.set_parameter("DL", addr.address[4:])
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
            return self.get_parameter("OP")
        return self.get_parameter("ID")

    def set_pan_id(self, value):
        """
        Sets the operating PAN ID of the XBee device.

        Args:
            value (Bytearray): the new operating PAN ID of the XBee device.. Must have only 1 or 2 bytes.

        Raises:
            TimeoutException: if the response is not received before the read timeout expires.
        """
        self.set_parameter("ID", value)

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
        return PowerLevel.get(self.get_parameter("PL")[0])

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
        self.set_parameter("PL", bytearray([power_level.code]))

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
        try:
            mode = IOMode.get(self.get_parameter(io_line.at_command)[0])
        except ValueError:
            raise OperationNotSupportedException("The received value is not an IO mode.")
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
        resp = self.get_parameter("IR")
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
        self.set_parameter("IR", utils.int_to_bytes(int(rate * 1000)))

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
        # so we have to use callbacks to read the packet:
        if not self.is_remote() and self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            try:
                # clear the event
                self._io_sample_event.clear()

                # notify the thread that we are waiting for the next IO sample.
                self._wait_for_next_io_sample = True

                # execute command
                self.execute_command("IS")

                # wait...
                if not self._io_sample_event.wait(self.get_sync_ops_timeout()):
                    raise TimeoutException("Error trying to read IO sample")
                # if there is no timeout exception, all goes well
                # notify the thread that we are no longer waiting for io samples.
                self._wait_for_next_io_sample = False

                # get the packet.
                io_packet = self._last_io_sample_received
                # reset the packet reference.
                self._last_io_sample_received = None

                # return the IO Sample.
                return io_packet.io_sample
            except Exception as e:
                # if there is an exception, reset all variables to
                # a consistent state:
                self._wait_for_next_io_sample = False
                self._last_io_sample_received = None
                self._io_sample_event.set()
                # raise the exception:
                raise e
        else:
            return IOSample(self.get_parameter("IS"))

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
            raise OperationNotSupportedException("Answer does not contain analog values for the given IO line.")
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
            raise OperationNotSupportedException("Answer does not contain digital values for the given IO_LINE")
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
        self.set_parameter("IC", flags)

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
        return APIOutputMode.get(self.get_parameter("AO")[0])

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
        self.set_parameter("AO", bytearray([api_output_mode.code]))

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
        value = self.get_parameter("AI")
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
        self.execute_command("DA")

    def _refresh_if_cached(self, parameter, value):
        """
        Refreshes the proper cached parameter depending on ``parameter`` value.
        
        If ``parameter`` is not a cached parameter, this method does nothing.

        Args:
            parameter (String): the parameter to refresh its value.
            value (Bytearray): the new value of the parameter.
        """
        if parameter == "NI":
            self._node_id = value.decode()
        elif parameter == "MY":
            self._16bit_addr = XBee16BitAddress(value)
        elif parameter == "AP":
            self._operating_mode = OperatingMode.get(utils.bytes_to_int(value))

    def _get_next_frame_id(self):
        """
        Returns the next frame ID of the XBee device.
        
        Returns:
            Integer: The next frame ID of the XBee device.
        """
        if self.__current_frame_id == 0xFF:
            self.__current_frame_id = 1
        else:
            self.__current_frame_id += 1
        return self.__current_frame_id

    @staticmethod
    def _before_send_method(func):
        """
        Decorator. Used to check the operating mode and the COM port's state before a sending operation.
        """
        @wraps(func)
        def dec_function(self, *args, **kwargs):
            if not self._serial_port.is_open:
                raise XBeeException("XBee device's serial port closed.")
            if (self._operating_mode != OperatingMode.API_MODE and
               self._operating_mode != OperatingMode.ESCAPED_API_MODE):
                raise InvalidOperatingModeException("Not supported operating mode: " + 
                                                    str(args[0].operating_mode.description))
            return func(self, *args, **kwargs)
        return dec_function

    @staticmethod
    def _after_send_method(func):
        """
        Decorator. Used to check the if response's transmit status is success after a sending operation.
        """
        @wraps(func)
        def dec_function(*args, **kwargs):
            response = func(*args, **kwargs)
            if response.transmit_status != TransmitStatus.SUCCESS:
                raise XBeeException("Transmit status: %s" % response.transmit_status.description)
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

        packet = queue.get_by_id(frame_id, XBeeDevice.TIMEOUT_READ_PACKET)

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

    __TIMEOUT_BEFORE_COMMAND_MODE = 1.2  # seconds
    """
    Timeout to wait after entering in command mode in seconds.
    
    It is used to determine the operating mode of the module (this 
    library only supports API modes, not transparent mode).
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

    def __init__(self, port, baud_rate, data_bits=serial.EIGHTBITS, stop_bits=serial.STOPBITS_ONE,
                 parity=serial.PARITY_NONE, flow_control=FlowControl.NONE,
                 _sync_ops_timeout=AbstractXBeeDevice._DEFAULT_TIMEOUT_SYNC_OPERATIONS):
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
            _sync_ops_timeout (Integer, default: 3): comm port read timeout.
        
        Raises:
            All exceptions raised by PySerial's Serial class constructor.
        
        .. seealso::
           | PySerial documentation: http://pyserial.sourceforge.net
        """
        super().__init__(serial_port=XBeeSerialPort(baud_rate=baud_rate,
                                                    port=None,  # to keep port closed until init().
                                                    data_bits=data_bits,
                                                    stop_bits=stop_bits,
                                                    parity=parity,
                                                    flow_control=flow_control,
                                                    timeout=_sync_ops_timeout),
                         sync_ops_timeout=_sync_ops_timeout
                         )
        self.__port = port
        self.__baud_rate = baud_rate
        self.__data_bits = data_bits
        self.__stop_bits = stop_bits
        self.__parity = parity
        self.__flow_control = flow_control

        self._network = XBeeNetwork(self)

        self.__packet_queue = None
        self.__data_queue = None
        self.__explicit_queue = None

        self._wait_for_id_event = Event()  # event for common packets (synchronous ops.).
        self._sync_packet_id = None
        self._sync_packet = None

        self._modem_status_event = Event()  # event for modem status packets.
        self._capture_next_modem_status = False  # flag for modem status packets.
        self._last_modem_status_captured = None  # the last modem status packet captured.

        self.__cv = threading.Condition()
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
                          comm_port_data["bitSize"],
                          comm_port_data["stopBits"],
                          comm_port_data["parity"],
                          comm_port_data["flowControl"],
                          comm_port_data["timeout"])

    def open(self):
        """
        Opens the communication with the XBee device and loads some information about it.
        
        Raises:
            TimeoutException: if there is any problem with the communication.
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            XBeeException: if the XBee device is already open.
        """

        if self._is_open:
            raise XBeeException("XBee device already open.")

        self._serial_port.port = self.__port
        self._serial_port.open()
        self._log.info("%s port opened" % self.__port)

        # Initialize the packet listener.
        self._packet_listener = PacketListener(self._serial_port, self)
        self.__packet_queue = self._packet_listener.get_queue()
        self.__data_queue = self._packet_listener.get_data_queue()
        self.__explicit_queue = self._packet_listener.get_explicit_queue()
        self._packet_listener.start()

        # Determine the operating mode of the XBee device.
        self._operating_mode = self._determine_operating_mode()
        if self._operating_mode == OperatingMode.UNKNOWN:
            self.close()
            raise InvalidOperatingModeException("Could not determine operating mode")
        if self._operating_mode == OperatingMode.AT_MODE:
            self.close()
            raise InvalidOperatingModeException.from_operating_mode(self._operating_mode)

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

        if self._serial_port is not None and self._serial_port.isOpen():
            self._serial_port.close()
            self._log.info("%s port closed" % self.__port)

        self._is_open = False

    def __get_serial_port(self):
        """
        Returns the serial port associated to the XBee device.

        Returns:
            :class:`.XBeeSerialPort`: the serial port associated to the XBee device.

        .. seealso::
           | :class:`.XBeeSerialPort`
        """
        return self._serial_port

    @AbstractXBeeDevice._before_send_method
    def get_parameter(self, param):
        """
        Override.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
        """
        packet_to_send = ATCommPacket(self._get_next_frame_id(), param)
        response = self.send_packet_sync_and_get_response(packet_to_send)  # raises TimeoutException

        if response.status != ATCommandStatus.OK:
            raise ATCommandException("Error sending parameter, command status: " + str(response.status))
        return response.command_value

    @AbstractXBeeDevice._before_send_method
    def set_parameter(self, param, value):
        """
        Override.
        
        See:
            :meth:`.AbstractXBeeDevice.set_parameter`
        """
        response = self.send_packet_sync_and_get_response(ATCommPacket(self._get_next_frame_id(), param, value))

        if response.status != ATCommandStatus.OK:
            raise ATCommandException("Error sending parameter, command status: " + str(response.status))
        # refresh cached parameters if this methods modifies some of them:
        self._refresh_if_cached(param, value)

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
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.

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
            raise OperationNotSupportedException("Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TransmitPacket(self.get_next_frame_id(),
                                x64addr,
                                x16addr,
                                0,
                                transmit_options,
                                data)
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
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.

        .. seealso::
           | :class:`.XBee64BitAddress`
           | :class:`.XBeePacket`
        """
        if x64addr is None:
            raise ValueError("64-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException("Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        if self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            packet = TX64Packet(self.get_next_frame_id(),
                                x64addr,
                                transmit_options,
                                data)
        else:
            packet = TransmitPacket(self.get_next_frame_id(),
                                    x64addr,
                                    XBee16BitAddress.UNKNOWN_ADDRESS,
                                    0,
                                    transmit_options,
                                    data)
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
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.

        .. seealso::
           | :class:`.XBee16BitAddress`
           | :class:`.XBeePacket`
        """
        if x16addr is None:
            raise ValueError("16-bit address cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if self.is_remote():
            raise OperationNotSupportedException("Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TX16Packet(self.get_next_frame_id(),
                            x16addr,
                            transmit_options,
                            data)
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
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.

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
                                             data, transmit_options)
            elif remote_xbee_device.get_64bit_addr() is not None:
                return self._send_data_64(remote_xbee_device.get_64bit_addr(), data, transmit_options)
            else:
                return self._send_data_64_16(XBee64BitAddress.UNKNOWN_ADDRESS, remote_xbee_device.get_16bit_addr(),
                                             data, transmit_options)
        elif protocol == XBeeProtocol.RAW_802_15_4:
            if remote_xbee_device.get_64bit_addr() is not None:
                return self._send_data_64(remote_xbee_device.get_64bit_addr(), data, transmit_options)
            else:
                return self._send_data_16(remote_xbee_device.get_16bit_addr(), data, transmit_options)
        else:
            return self._send_data_64(remote_xbee_device.get_64bit_addr(), data, transmit_options)

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
            raise OperationNotSupportedException("Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TransmitPacket(self.get_next_frame_id(),
                                x64addr,
                                x16addr,
                                0,
                                transmit_options,
                                data)
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
            raise OperationNotSupportedException("Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        if self.get_protocol() == XBeeProtocol.RAW_802_15_4:
            packet = TX64Packet(self.get_next_frame_id(),
                                x64addr,
                                transmit_options,
                                data)
        else:
            packet = TransmitPacket(self.get_next_frame_id(),
                                    x64addr,
                                    XBee16BitAddress.UNKNOWN_ADDRESS,
                                    0,
                                    transmit_options,
                                    data)
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
            raise OperationNotSupportedException("Cannot send data to a remote device from a remote device")

        if isinstance(data, str):
            data = data.encode("utf8")

        packet = TX16Packet(self.get_next_frame_id(),
                            x16addr,
                            transmit_options,
                            data)
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
                                            data, transmit_options)
            elif remote_xbee_device.get_64bit_addr() is not None:
                self._send_data_async_64(remote_xbee_device.get_64bit_addr(), data, transmit_options)
            else:
                self._send_data_async_64_16(XBee64BitAddress.UNKNOWN_ADDRESS, remote_xbee_device.get_16bit_addr(),
                                            data, transmit_options)
        elif protocol == XBeeProtocol.RAW_802_15_4:
            if remote_xbee_device.get_64bit_addr() is not None:
                self._send_data_async_64(remote_xbee_device.get_64bit_addr(), data, transmit_options)
            else:
                self._send_data_async_16(remote_xbee_device.get_16bit_addr(), data, transmit_options)
        else:
            self._send_data_async_64(remote_xbee_device.get_64bit_addr(), data, transmit_options)

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
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.
        """
        return self._send_data_64(XBee64BitAddress.BROADCAST_ADDRESS, data, transmit_options)

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
        # send command:
        self.execute_command("FR")
        self.__cv.acquire()

        def ms_callback(modem_status):
            if modem_status == ModemStatus.HARDWARE_RESET or modem_status == ModemStatus.WATCHDOG_TIMER_RESET:
                self.__modem_status_received = True
                self.__cv.acquire()
                self.__cv.notify()
                self.__cv.release()

        self.add_modem_status_received_callback(ms_callback)
        self.__cv.wait(self.__TIMEOUT_RESET)
        self.__cv.release()
        self.del_modem_status_received_callback(ms_callback)

        if self.__modem_status_received is False:
            raise XBeeException("Invalid modem status.")

    def add_packet_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.PacketReceived`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * The received packet as a :class:`.XBeeAPIPacket`
                * The sender as a :class:`.RemoteXBeeDevice`
        """
        self._packet_listener.add_packet_received_callback(callback)

    def add_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.DataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The data received as an :class:`.XBeeMessage`
        """
        self._packet_listener.add_data_received_callback(callback)

    def add_modem_status_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.ModemStatusReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The modem status as a :class:`.ModemStatus`
        """
        self._packet_listener.add_modem_status_received_callback(callback)

    def add_io_sample_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.IOSampleReceived`.

        Args:
            callback (Function): the callback. Receives three arguments.

                * The received IO sample as an :class:`.IOSample`
                * The remote XBee device who has sent the packet as a :class:`.RemoteXBeeDevice`
                * The time in which the packet was received as an Integer
        """
        self._packet_listener.add_io_sample_received_callback(callback)

    def add_expl_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.ExplicitDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The explicit data received as an :class:`.ExplicitXBeeMessage`
        """
        self._packet_listener.add_explicit_data_received_callback(callback)

    def del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.PacketReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.PacketReceived` event.
        """
        self._packet_listener.del_packet_received_callback(callback)

    def del_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.DataReceived` event.
        """
        self._packet_listener.del_data_received_callback(callback)

    def del_modem_status_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.ModemStatusReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.ModemStatusReceived` event.
        """
        self._packet_listener.del_modem_status_received_callback(callback)

    def del_io_sample_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.IOSampleReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.IOSampleReceived` event.
        """
        self._packet_listener.del_io_sample_received_callback(callback)

    def del_expl_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.ExplicitDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.ExplicitDataReceived` event.
        """
        self._packet_listener.del_explicit_data_received_callback(callback)

    def get_xbee_device_callbacks(self):
        """
        Returns this XBee internal callbacks for process received packets.
        
        This method is called by the PacketListener associated with this XBee to get its callbacks. These
        callbacks will be executed before user callbacks.
        
        Returns:
            :class:`.PacketReceived`
        """
        api_callbacks = PacketReceived()

        def sync_send_callback(received_packet):
            """
            This callback is used for the synchronous call to send_data()
            """
            # if we are waiting for any packet...
            if self._sync_packet_id is not None:
                # if this packet has id and is the waited:
                if received_packet.needs_id() and received_packet.frame_id == self._sync_packet_id:
                    # put it in the proper variable
                    self._sync_packet = received_packet
                    # notify event waiters:
                    self._wait_for_id_event.set()

        def modem_status_callback(received_packet):
            """
            This callback is used for capturing modem status.
            """
            if (self._capture_next_modem_status and
                    received_packet.get_frame_type() == ApiFrameType.MODEM_STATUS):
                self._last_modem_status_captured = received_packet
                self._modem_status_event.set()

        def io_sample_callback(received_packet):
            """
            Used for 802.15.4 IO sample reception.
            """
            if self._wait_for_next_io_sample:
                frame_type = received_packet.get_frame_type()
                if (frame_type == ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR or
                        frame_type == ApiFrameType.RX_IO_16 or
                        frame_type == ApiFrameType.RX_IO_64):
                    self._last_io_sample_received = received_packet
                    self._io_sample_event.set()

        api_callbacks += sync_send_callback
        api_callbacks += modem_status_callback
        api_callbacks += io_sample_callback
        for i in self._network.get_discovery_callbacks():
            api_callbacks.append(i)
        return api_callbacks

    def __get_operating_mode(self):
        """
        Returns this XBee device's operating mode.
        
        Returns:
            :class:`.OperatingMode`. This XBee device's operating mode.
        """
        return self._operating_mode

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
        return self._network

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
            XBeeException: if the XBee device's serial port is closed.
            XBeeException: if the status of the response received is not OK.
            ValueError: if ``cluster_id`` is less than 0x0 or greater than 0xFFFF.
            ValueError: if ``profile_id`` is less than 0x0 or greater than 0xFFFF.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
           | :class:`.XBeePacket`
        """
        return self.send_packet_sync_and_get_response(self.__build_expldata_packet(remote_xbee_device, data,
                                                                                   src_endpoint, dest_endpoint,
                                                                                   cluster_id, profile_id,
                                                                                   False, transmit_options))

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
                                                      profile_id, False, transmit_options))

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
                                                                                   profile_id, True, transmit_options))

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
                packet = self.__data_queue.get_by_remote(remote, timeout)
        else:
            if remote is None:
                packet = self.__explicit_queue.get(timeout=timeout)
            else:
                packet = self.__explicit_queue.get_by_remote(remote, timeout)

        if packet is None:
            return None

        frame_type = packet.get_frame_type()
        if frame_type in [ApiFrameType.RECEIVE_PACKET, ApiFrameType.RX_16, ApiFrameType.RX_64]:
            return self.__build_xbee_message(packet, False)
        elif frame_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
            return self.__build_xbee_message(packet, True)
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
        """
        if self._operating_mode != OperatingMode.AT_MODE:
            raise InvalidOperatingModeException("Invalid mode. Command mode can be only accessed while in AT mode")
        listening = self._packet_listener is not None and self._packet_listener.is_running()
        if listening:
            self._packet_listener.stop()
            self._packet_listener.join()

        self._serial_port.flushInput()

        # It is necessary to wait at least 1 second to enter in command mode after sending any data to the device.
        time.sleep(self.__TIMEOUT_BEFORE_COMMAND_MODE)
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
            response = self.get_parameter("AP")
            return OperatingMode.get(response[0])
        except TimeoutException:
            self._operating_mode = OperatingMode.AT_MODE
            try:
                # If there is timeout exception and is possible to enter
                # in AT command mode, the current operating mode is AT.
                if self._enter_at_command_mode():
                    return OperatingMode.AT_MODE
            except SerialTimeoutException as ste:
                self._log.exception(ste)
        return OperatingMode.UNKNOWN

    def send_packet_sync_and_get_response(self, packet_to_send):
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

        Returns:
            :class:`.XBeePacket`: the response packet obtained after sending the provided one.

        Raises:
            TimeoutException: if the response is not received in the configured timeout.

        .. seealso::
           | :class:`.XBeePacket`
        """
        # clear the event for wait:
        self._wait_for_id_event.clear()

        # sets the sync_packet_id which is used to notify that we are
        # waiting for a packet to the callback in charge of synchronous reads.
        # It's used to identify the found packet too.
        self._sync_packet_id = packet_to_send.frame_id

        # Send the packet.
        self.send_packet(packet_to_send)

        # Wait until the callback notify us, or until
        # the timeout expires.
        if not self._wait_for_id_event.wait(self._timeout):
            self._sync_packet = None

        # Notify to our callback that we are no longer waiting.
        self._sync_packet_id = None

        if self._sync_packet is None:
            # if packet is None, timeout has expired:
            raise TimeoutException("Response not received in the configured timeout.")
        else:
            # Get a reference for the new packet, clear sync packet
            # variable, and return the read packet.
            received_packet = self._sync_packet
            self._sync_packet = None
            return received_packet

    def send_packet(self, packet, sync=False):
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
        out = packet.output(escape)
        self._serial_port.write(out)
        self._log.debug(self.LOG_PATTERN.format(port=self.__port,
                                                event="SENT",
                                                opmode=self._operating_mode,
                                                content=utils.hex_to_string(out)))

        return self._get_packet_by_id(packet.frame_id) if sync else None

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
            remote = RemoteXBeeDevice(self, x64addr, x16addr)

        if explicit:
            msg = ExplicitXBeeMessage(packet.rf_data, remote, time.time(), packet.source_endpoint,
                                      packet.dest_endpoint, packet.cluster_id,
                                      packet.profile_id, packet.is_broadcast())
        else:
            msg = XBeeMessage(packet.rf_data, remote, time.time(), packet.is_broadcast())

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
                                        cluster_id, profile_id, 0, transmit_options, data)

    def get_next_frame_id(self):
        """
        Returns the next frame ID of the XBee device.

        Returns:
            Integer: The next frame ID of the XBee device.
        """
        return self._get_next_frame_id()

    serial_port = property(__get_serial_port)
    """:class:`.XBeeSerialPort`. The serial port associated to the XBee device."""

    operating_mode = property(__get_operating_mode)
    """:class:`.OperatingMode`. The operating mode of the XBee device."""


class Raw802Device(XBeeDevice):
    """
    This class represents a local 802.15.4 XBee device.
    """

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`Raw802Device` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.
        
        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

    def open(self):
        """
        Override.
        
        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
        if not self.is_remote() and self.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise XBeeException("Invalid protocol.")

    def get_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        if self._network is None:
            self._network = Raw802Network(self)
        return self._network

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
        return super()._send_data_64(x64addr, data, transmit_options)

    def send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64`
        """
        super()._send_data_async_64(x64addr, data, transmit_options)

    def send_data_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._send_data_16`
        """
        return super()._send_data_16(x16addr, data, transmit_options)

    def send_data_async_16(self, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice._send_data_async_16`
        """
        super()._send_data_async_16(x16addr, data, transmit_options)


class DigiMeshDevice(XBeeDevice):
    """
    This class represents a local DigiMesh XBee device.
    """

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`DigiMeshDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :meth:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

    def open(self):
        """
        Override.

        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
        if self.get_protocol() != XBeeProtocol.DIGI_MESH:
            raise XBeeException("Invalid protocol.")

    def get_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        if self._network is None:
            self._network = DigiMeshNetwork(self)
        return self._network

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
        return super()._send_data_64(x64addr, data, transmit_options)

    def send_data_async_64(self, x64addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64`
        """
        super()._send_data_async_64(x64addr, data, transmit_options)

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
                                       profile_id, transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                 transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data_broadcast`
        """
        return super()._send_expl_data_broadcast(data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                                 transmit_options)

    def send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data_async`
        """
        super()._send_expl_data_async(remote_xbee_device, data, src_endpoint,
                                      dest_endpoint, cluster_id, profile_id, transmit_options)


class DigiPointDevice(XBeeDevice):
    """
    This class represents a local DigiPoint XBee device.
    """

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`DigiPointDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :meth:`XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`.XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

    def open(self):
        """
        Override.

        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
        if self.get_protocol() != XBeeProtocol.DIGI_POINT:
            raise XBeeException("Invalid protocol.")

    def get_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        if self._network is None:
            self._network = DigiPointNetwork(self)
        return self._network

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
        return super()._send_data_64_16(x64addr, x16addr, data, transmit_options)

    def send_data_async_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64_16`
        """
        super()._send_data_async_64_16(x64addr, x16addr, data, transmit_options)

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
                                       profile_id, transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                 transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data_broadcast`
        """
        return super()._send_expl_data_broadcast(data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                                 transmit_options)

    def send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data_async`
        """
        super()._send_expl_data_async(remote_xbee_device, data, src_endpoint,
                                      dest_endpoint, cluster_id, profile_id, transmit_options)


class ZigBeeDevice(XBeeDevice):
    """
    This class represents a local ZigBee XBee device.
    """

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`ZigBeeDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :func:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

    def open(self):
        """
        Override.

        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
        if self.get_protocol() != XBeeProtocol.ZIGBEE:
            raise XBeeException("Invalid protocol.")

    def get_network(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_network`
        """
        if self._network is None:
            self._network = ZigBeeNetwork(self)
        return self._network

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
        return super()._send_data_64_16(x64addr, x16addr, data, transmit_options)

    def send_data_async_64_16(self, x64addr, x16addr, data, transmit_options=TransmitOptions.NONE.value):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.send_data_async_64_16`
        """
        super()._send_data_async_64_16(x64addr, x16addr, data, transmit_options)

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
                                       profile_id, transmit_options)

    def send_expl_data_broadcast(self, data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                 transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice._send_expl_data_broadcast`
        """
        return super()._send_expl_data_broadcast(data, src_endpoint, dest_endpoint, cluster_id, profile_id,
                                                 transmit_options)

    def send_expl_data_async(self, remote_xbee_device, data, src_endpoint, dest_endpoint,
                             cluster_id, profile_id, transmit_options=TransmitOptions.NONE.value):
        """
        Override.
        
        .. seealso::
           | :meth:`.XBeeDevice.send_expl_data_async`
        """
        super()._send_expl_data_async(remote_xbee_device, data, src_endpoint,
                                      dest_endpoint, cluster_id, profile_id, transmit_options)

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
                                                  TransmitOptions.ENABLE_MULTICAST.value, data)
        
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
                                                  TransmitOptions.ENABLE_MULTICAST.value, data)
        
        self.send_packet(packet_to_send)


class IPDevice(XBeeDevice):
    """
    This class provides common functionality for XBee IP devices.
    """

    BROADCAST_IP = "255.255.255.255"

    __DEFAULT_SOURCE_PORT = 9750

    __DEFAULT_PROTOCOL = IPProtocol.TCP

    __OPERATION_EXCEPTION = "Operation not supported in this module."

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`.IPDevice` with the
        provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :func:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

        self._ip_addr = None
        self._source_port = self.__DEFAULT_SOURCE_PORT

    def read_device_info(self):
        """
        Override.

        .. seealso::
           | :meth:`.AbstractXBeeDevice.read_device_info`
        """
        super().read_device_info()

        # Read the module's IP address.
        resp = self.get_parameter("MY")
        self._ip_addr = IPv4Address(utils.bytes_to_int(resp))

        # Read the source port.
        try:
            resp = self.get_parameter("C0")
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

        self.set_parameter("DL", bytearray(address.exploded, "utf8"))

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
        resp = self.get_parameter("DL")
        return IPv4Address(resp.decode("utf8"))

    def add_ip_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.IPDataReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The data received as an :class:`.IPMessage`
        """
        self._packet_listener.add_ip_data_received_callback(callback)

    def del_ip_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.IPDataReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.IPDataReceived` event.
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

        self.set_parameter("C0", utils.int_to_bytes(source_port))
        self._source_port = source_port

    def stop_listening(self):
        """
        Stops listening for incoming IP transmissions.

        Raises:
            TimeoutException: if there is a timeout processing the operation.
            XBeeException: if there is any other XBee related exception.
        """
        self.set_parameter("C0", utils.int_to_bytes(0))
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
            raise OperationNotSupportedException("Cannot send IP data from a remote device")

        # The source port value depends on the protocol used in the transmission.
        # For UDP, source port value must be the same as 'C0' one. For TCP it must be 0.
        source_port = self._source_port
        if protocol is not IPProtocol.UDP:
            source_port = 0

        if isinstance(data, str):
            data = data.encode("utf8")

        options = TXIPv4Packet.OPTIONS_CLOSE_SOCKET if close_socket else TXIPv4Packet.OPTIONS_LEAVE_SOCKET_OPEN

        packet = TXIPv4Packet(self.get_next_frame_id(), ip_addr, dest_port, source_port, protocol,
                              options, data)

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
            raise OperationNotSupportedException("Cannot send IP data from a remote device")

        # The source port value depends on the protocol used in the transmission.
        # For UDP, source port value must be the same as 'C0' one. For TCP it must be 0.
        source_port = self._source_port
        if protocol is IPProtocol.UDP:
            source_port = 0

        if isinstance(data, str):
            data = data.encode("utf8")

        options = TXIPv4Packet.OPTIONS_CLOSE_SOCKET if close_socket else TXIPv4Packet.OPTIONS_LEAVE_SOCKET_OPEN

        packet = TXIPv4Packet(self.get_next_frame_id(), ip_addr, dest_port, source_port, protocol,
                              options, data)

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

        return self.__read_ip_data_packet(timeout, ip_addr)

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
            packet = queue.get_by_ip(ip_addr, timeout)

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

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`.CellularDevice` with the
        provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :func:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

        self._imei_addr = None

    def open(self):
        """
        Override.

        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
        if self.get_protocol() not in [XBeeProtocol.CELLULAR, XBeeProtocol.CELLULAR_NBIOT]:
            raise XBeeException("Invalid protocol.")

    def get_protocol(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.get_protocol`
        """
        return XBeeProtocol.CELLULAR

    def read_device_info(self):
        """
        Override.

        .. seealso::
           | :meth:`.XBeeDevice.read_device _info`
        """
        super().read_device_info()

        # Generate the IMEI address.
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
        value = self.get_parameter("AI")
        return CellularAssociationIndicationStatus.get(utils.bytes_to_int(value))

    def add_sms_callback(self, callback):
        """
        Adds a callback for the event :class:`.SMSReceived`.

        Args:
            callback (Function): the callback. Receives one argument.

                * The data received as an :class:`.SMSMessage`
        """
        self._packet_listener.add_sms_received_callback(callback)

    def del_sms_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SMSReceived`
        event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.SMSReceived` event.
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
            raise OperationNotSupportedException("Cannot send SMS from a remote device")

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
            raise OperationNotSupportedException("Cannot send SMS from a remote device")

        xbee_packet = TXSMSPacket(self.get_next_frame_id(), phone_number, data)

        self.send_packet(xbee_packet)

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

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`.LPWANDevice` with the
        provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :func:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

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

        super().send_ip_data(ip_addr, dest_port, protocol, data)

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

        super().send_ip_data_async(ip_addr, dest_port, protocol, data)

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

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`.CellularDevice` with the
        provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :func:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)

        self._imei_addr = None

    def open(self):
        """
        Override.

        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
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

    def __init__(self, port, baud_rate):
        """
        Class constructor. Instantiates a new :class:`WiFiDevice` with the provided parameters.

        Args:
            port (Integer or String): serial port identifier.
                Integer: number of XBee device, numbering starts at zero.
                Device name: depending on operating system. e.g. '/dev/ttyUSB0' on GNU/Linux or 'COM3' on Windows.
            baud_rate (Integer): the serial port baud rate.

        Raises:
            All exceptions raised by :func:`.XBeeDevice.__init__` constructor.

        .. seealso::
           | :class:`.XBeeDevice`
           | :meth:`XBeeDevice.__init__`
        """
        super().__init__(port, baud_rate)
        self.__ap_timeout = self.__DEFAULT_ACCESS_POINT_TIMEOUT
        self.__scanning_aps = False
        self.__scanning_aps_error = False

    def open(self):
        """
        Override.

        Raises:
            XBeeException: if the protocol is invalid.
            All exceptions raised by :meth:`.XBeeDevice.open`.

        .. seealso::
           | :meth:`.XBeeDevice.open`
        """
        super().open()
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
        return WiFiAssociationIndicationStatus.get(utils.bytes_to_int(self.get_parameter("AI")))

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

        if self.operating_mode == OperatingMode.AT_MODE or self.operating_mode == OperatingMode.UNKNOWN:
            raise InvalidOperatingModeException("Cannot scan for access points in AT mode.")

        def packet_receive_callback(xbee_packet):
            if not self.__scanning_aps:
                return
            if xbee_packet.get_frame_type() != ApiFrameType.AT_COMMAND_RESPONSE:
                return
            if xbee_packet.command != "AS":
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
            self.send_packet(ATCommPacket(self.get_next_frame_id(), "AS"), False)

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
        self.set_parameter("ID", bytearray(access_point.ssid, "utf8"))
        self.set_parameter("EE", utils.int_to_bytes(access_point.encryption_type.code, num_bytes=1))
        if password is not None and access_point.encryption_type != WiFiEncryptionType.NONE:
            self.set_parameter("PK", bytearray(password, "utf8"))

        # Wait for the module to connect to the access point.
        dead_line = time.time() + self.__ap_timeout
        while time.time() < dead_line:
            time.sleep(0.1)
            # Get the association indication value of the module.
            status = self.get_parameter("AI")
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

        return self.connect_by_ap(access_point, password)

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
        self.execute_command("NR")
        dead_line = time.time() + self.__ap_timeout
        while time.time() < dead_line:
            time.sleep(0.1)
            # Get the association indication value of the module.
            status = self.get_parameter("AI")
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

        return AccessPoint(ssid, WiFiEncryptionType.get(encryption_type), channel, signal_quality)

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
        return IPAddressingMode.get(utils.bytes_to_int(self.get_parameter("MA")))

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
        self.set_parameter("MA", utils.int_to_bytes(mode.code, num_bytes=1))

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
        self.set_parameter("MY", ip_address.packed)

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
        return IPv4Address(bytes(self.get_parameter("MK")))

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
        self.set_parameter("MK", mask_address.packed)

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
        return IPv4Address(bytes(self.get_parameter("GW")))

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
        self.set_parameter("GW", gateway_address.packed)

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
        return IPv4Address(bytes(self.get_parameter("NS")))

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
        self.set_parameter("NS", dns_address.packed)


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
                         serial_port=local_xbee_device.serial_port)

        self._local_xbee_device = local_xbee_device
        self._64bit_addr = x64bit_addr
        self._16bit_addr = x16bit_addr
        self._node_id = node_id

    def get_parameter(self, parameter):
        """
        Override.
        
        .. seealso::
           | :meth:`.AbstractXBeeDevice.get_parameter`
        """
        if not self._local_xbee_device.serial_port.is_open:
            raise XBeeException("Local XBee device's serial port is closed.")

        x16bit_addr = self.get_16bit_addr()
        if x16bit_addr is None:
            x16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

        packet_to_send = RemoteATCommandPacket(self._get_next_frame_id(),
                                               self.get_64bit_addr(),
                                               x16bit_addr,
                                               RemoteATCmdOptions.NONE.value,
                                               parameter)
        response = self._local_xbee_device.send_packet_sync_and_get_response(packet_to_send)  # raises TimeoutException
        
        if response.status != ATCommandStatus.OK:
            raise ATCommandException("Error getting parameter, command status: " + response.status.description)
        return response.command_value

    def set_parameter(self, parameter, value):
        """
        Override.
           
        .. seealso::
           | :meth:`.AbstractXBeeDevice.set_parameter`
        """
        if not self._local_xbee_device.serial_port.is_open:
            raise XBeeException("Local XBee device's serial port is closed.")

        if self.is_apply_changes_enabled():
            options = RemoteATCmdOptions.APPLY_CHANGES
        else:
            options = RemoteATCmdOptions.NONE

        x16bit_addr = self.get_16bit_addr()
        if x16bit_addr is None:
            x16bit_addr = XBee16BitAddress.UNKNOWN_ADDRESS

        packet_to_send = RemoteATCommandPacket(self._get_next_frame_id(),
                                               self.get_64bit_addr(),
                                               x16bit_addr,
                                               options.value, parameter, value)
        response = self._local_xbee_device.send_packet_sync_and_get_response(packet_to_send)

        if response.status != ATCommandStatus.OK:
            raise ATCommandException("Error setting parameter, command status: " + response.status.description)
        # refresh cached parameters if this methods modifies some of them:
        self._refresh_if_cached(parameter, value)

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
        try:
            self.execute_command("FR")
        except TimeoutException as te:
            if self._local_xbee_device.get_protocol() != XBeeProtocol.RAW_802_15_4:
                raise te

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

    def __str__(self):
        node_id = "" if self.get_node_id() is None else self.get_node_id()
        return "%s - %s" % (self.get_64bit_addr(), node_id)


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
            All exceptions raised by :class:`.RemoteXBeeDevice` constructor.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.RAW_802_15_4:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr, x16bit_addr, node_id=node_id)

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
            All exceptions raised by :class:`.RemoteXBeeDevice` constructor.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.DIGI_MESH:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr, None, node_id)

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
            All exceptions raised by :class:`.RemoteXBeeDevice` constructor.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.DIGI_POINT:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr, None, node_id)

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
            All exceptions raised by :class:`.RemoteXBeeDevice` constructor.

        .. seealso::
           | :class:`RemoteXBeeDevice`
           | :class:`XBee16BitAddress`
           | :class:`XBee64BitAddress`
           | :class:`XBeeDevice`
        """
        if local_xbee_device.get_protocol() != XBeeProtocol.ZIGBEE:
            raise XBeeException("Invalid protocol.")

        super().__init__(local_xbee_device, x64bit_addr, x16bit_addr, node_id)

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

    __NODE_DISCOVERY_COMMAND = "ND"

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
        self.__discovery_thread.start()

    def stop_discovery_process(self):
        """
        Stops the discovery process if it is running.

        Note that DigiMesh/DigiPoint devices are blocked until the discovery
        time configured (NT parameter) has elapsed, so if you try to get/set
        any parameter during the discovery process you will receive a timeout
        exception.
        """
        if self.__discovering:
            with self.__lock:
                self.__discovering = False

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
            self.__discover_devices(node_id)
        finally:
            with self.__lock:
                self.__sought_device_id = None
                remote = self.__discovered_device
                self.__discovered_device = None
            if remote is not None:
                self.add_remote(remote)
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
        return self.__xbee_device.get_parameter("NO")

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
        self.__xbee_device.set_parameter("NO", utils.int_to_bytes(value))

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
        tout = self.__xbee_device.get_parameter("NT")

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
        self.__xbee_device.set_parameter("NT", timeout)

    def get_device_by_64(self, x64bit_addr):
        """
        Returns the remote device already contained in the network whose 64-bit
        address matches the given one.

        Args:
            x64bit_addr (:class:`XBee64BitAddress`): The 64-bit address of the device to be retrieved.

        Returns:
            :class:`.RemoteXBeeDevice`: the remote XBee device in the network or ``None`` if it is not found.

        Raises:
            ValueError: if ``x64bit_addr`` is ``None`` or unknown.
        """
        if x64bit_addr is None:
            raise ValueError("64-bit address cannot be None")
        if x64bit_addr == XBee64BitAddress.UNKNOWN_ADDRESS:
            raise ValueError("64-bit address cannot be unknown")

        with self.__lock:
            for device in self.__devices_list:
                if device.get_64bit_addr() is not None and device.get_64bit_addr() == x64bit_addr:
                    return device

        return None

    def get_device_by_16(self, x16bit_addr):
        """
        Returns the remote device already contained in the network whose 16-bit
        address matches the given one.

        Args:
            x16bit_addr (:class:`XBee16BitAddress`): The 16-bit address of the device to be retrieved.

        Returns:
            :class:`.RemoteXBeeDevice`: the remote XBee device in the network or ``None`` if it is not found.

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

        with self.__lock:
            for device in self.__devices_list:
                if device.get_16bit_addr() is not None and device.get_16bit_addr() == x16bit_addr:
                    return device

        return None

    def get_device_by_node_id(self, node_id):
        """
        Returns the remote device already contained in the network whose node identifier
        matches the given one.

        Args:
            node_id (String): The node identifier of the device to be retrieved.

        Returns:
            :class:`.RemoteXBeeDevice`: the remote XBee device in the network or ``None`` if it is not found.

        Raises:
            ValueError: if ``node_id`` is ``None``.
        """
        if node_id is None:
            raise ValueError("Node ID cannot be None")

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
            :class:`.RemoteXBeeDevice`: the remote XBee device with the updated parameters. If the XBee device
                was not in the list yet, this method returns the given XBee device without changes.
        """
        remote = RemoteXBeeDevice(self.__xbee_device, x64bit_addr, x16bit_addr, node_id)
        return self.add_remote(remote)

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
        with self.__lock:
            for local_xbee in self.__devices_list:
                if local_xbee == remote_xbee_device:
                    local_xbee.update_device_data_from(remote_xbee_device)
                    return local_xbee
            self.__devices_list.append(remote_xbee_device)
            return remote_xbee_device

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
            elif nd_id == XBeeNetwork.ND_PACKET_REMOTE:
                remote = self.__create_remote(xbee_packet.command_value)
                # if remote was created successfully and it is not int the
                # XBee device list, add it and notify callbacks.
                if remote is not None:
                    # if remote was created successfully and it is not int the
                    # XBee device list, add it and notify callbacks.
                    if remote not in self.__devices_list:
                        with self.__lock:
                            self.__devices_list.append(remote)
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
            elif nd_id == XBeeNetwork.ND_PACKET_REMOTE:
                # if it is not a finish signal, it contains info about a remote XBee device.
                remote = self.__create_remote(xbee_packet.command_value)
                # if it's the sought XBee device, put it in the proper variable.
                if self.__sought_device_id == remote.get_node_id():
                    with self.__lock:
                        self.__discovered_device = remote
                        self.__sought_device_id = None

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
           xbee_packet.command == XBeeNetwork.__NODE_DISCOVERY_COMMAND):
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
        self.__device_discovery_finished(NetworkDiscoveryStatus.SUCCESS)

    def __discover_devices(self, node_id=None):
        """
        Blocking method. Performs a device discovery in the network and waits until it finish (timeout or 'end'
        packet for 802.15.4)

        Args:
            node_id (String, optional): node identifier of the remote XBee device to discover. Optional.
        """
        try:
            init_time = time.time()

            # In 802.15.4 devices, the discovery finishes when the 'end' command 
            # is received, so it's not necessary to calculate the timeout.
            # This also applies to S1B devices working in compatibility mode.
            is_802_compatible = self.__is_802_compatible()
            timeout = 0
            if not is_802_compatible:
                timeout = self.__calculate_timeout()
            # send "ND" async
            self.__xbee_device.send_packet(ATCommPacket(self.__xbee_device.get_next_frame_id(),
                                                        "ND",
                                                        None if node_id is None else bytearray(node_id, 'utf8')),
                                           False)

            if not is_802_compatible:
                # If XBee device is not 802.15.4, wait until timeout expires.
                while self.__discovering or self.__sought_device_id is not None:
                    if (time.time() - init_time) > timeout:
                        with self.__lock:
                            self.__discovering = False
                        break
                    time.sleep(0.1)

            else:
                # If XBee device is 802.15.4, wait until the 'end' xbee_message arrive.
                # "__discovering" will be assigned as False by the callback
                # when this receive that 'end' xbee_message. If this xbee_message never arrives,
                # stop when timeout expires.
                while self.__discovering or self.__sought_device_id is not None:
                    time.sleep(0.1)
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
            param = self.__xbee_device.get_parameter("C8")
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
            discovery_timeout = utils.bytes_to_int(self.__xbee_device.get_parameter("N?")) / 1000
        except XBeeException:
            discovery_timeout = None

        # If N? does not exist, read the NT parameter.
        if discovery_timeout is None:
            # Read the XBee device timeout (NT).
            try:
                discovery_timeout = utils.bytes_to_int(self.__xbee_device.get_parameter("NT")) / 10
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
                if utils.bytes_to_int(self.__xbee_device.get_parameter("SM")) == 7:
                    discovery_timeout += discovery_timeout + \
                                        (discovery_timeout * XBeeNetwork.__DIGI_MESH_SLEEP_TIMEOUT_CORRECTION)
            except XBeeException as xe:
                self.__xbee_device.log.exception(xe)

        return discovery_timeout

    def __create_remote(self, discovery_data):
        """
        Creates and returns a :class:`.RemoteXBeeDevice` from the provided data,
        if the data contains the required information and in the required
        format.
        
        Returns:
            :class:`.RemoteXBeeDevice`: the remote XBee device generated from the provided data if the data
                provided is correct and the XBee device's protocol is valid, ``None`` otherwise.
        
        .. seealso::
           | :meth:`.XBeeNetwork.__get_data_for_remote`
        """
        if discovery_data is None:
            return None
        p = self.__xbee_device.get_protocol()
        x16bit_addr, x64bit_addr, node_id = self.__get_data_for_remote(discovery_data)

        if p == XBeeProtocol.ZIGBEE:
            return RemoteZigBeeDevice(self.__xbee_device, x64bit_addr, x16bit_addr, node_id)
        elif p == XBeeProtocol.DIGI_MESH:
            return RemoteDigiMeshDevice(self.__xbee_device, x64bit_addr, node_id)
        elif p == XBeeProtocol.DIGI_POINT:
            return RemoteDigiPointDevice(self.__xbee_device, x64bit_addr, node_id)
        elif p == XBeeProtocol.RAW_802_15_4:
            return RemoteRaw802Device(self.__xbee_device, x64bit_addr, x16bit_addr, node_id)
        else:
            return RemoteXBeeDevice(self.__xbee_device, x64bit_addr, x16bit_addr, node_id)

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
        return XBee16BitAddress(data[0:2]), XBee64BitAddress(data[2:10]), node_id.decode()


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
