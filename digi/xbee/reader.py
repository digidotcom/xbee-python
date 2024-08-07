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

from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from threading import Event
import logging
import threading
import time

from serial import SerialException

import digi.xbee.devices
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.message import (
    XBeeMessage, ExplicitXBeeMessage, IPMessage, SMSMessage,
    UserDataRelayMessage, BLEGAPScanLegacyAdvertisementMessage,
    BLEGAPScanExtendedAdvertisementMessage, BLEGAPScanStatusMessage
)
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import XBeeLocalInterface
from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.models.status import ATCommandStatus
from digi.xbee.packets import factory
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ReceivePacket, IODataSampleRxIndicatorPacket
from digi.xbee.packets.raw import RX64Packet, RX16Packet
from digi.xbee.util import utils
from digi.xbee.exception import TimeoutException, InvalidPacketException
from digi.xbee.io import IOSample

# Maximum number of parallel callbacks.
MAX_PARALLEL_CALLBACKS = 50

EXECUTOR = ThreadPoolExecutor(max_workers=MAX_PARALLEL_CALLBACKS)


class XBeeEvent(list):
    """
    This class represents a generic XBee event.

    New event callbacks can be added here following this prototype:

    ::

        def callback_prototype(*args, **kwargs):
            #do something...

    All of them will be executed when the event is fired.

    .. seealso::
       | list (Python standard class)
    """

    def __call__(self, *args, **kwargs):
        for func in self:
            future = EXECUTOR.submit(func, *args, **kwargs)
            future.add_done_callback(self.__execution_finished)

    def __repr__(self):
        return "Event(%s)" % list.__repr__(self)

    def __iadd__(self, other):
        self.append(other)
        return self

    def __isub__(self, other):
        self.remove(other)
        return self

    def __execution_finished(self, future):
        """
        Called when the execution of the callable has finished.

        Args:
            future (:class:`.Future`): Future associated to the execution of
                the callable.

        Raises:
            Exception: If the execution of the callable raised any exception.
        """
        if future.exception():
            raise future.exception()


class PacketReceived(XBeeEvent):
    """
    This event is fired when an XBee receives any packet, independent of
    its frame type.

    The callbacks for handle this events will receive the following arguments:
        1. received_packet (:class:`.XBeeAPIPacket`): Received packet.

    .. seealso::
       | :class:`.XBeeAPIPacket`
       | :class:`.XBeeEvent`
    """


class PacketReceivedFrom(XBeeEvent):
    """
    This event is fired when an XBee receives any packet, independent of
    its frame type.

    The callbacks for handle this events will receive the following arguments:
        1. received_packet (:class:`.XBeeAPIPacket`): Received packet.
        2. sender (:class:`.RemoteXBeeDevice`): Remote XBee who sent the packet.

    .. seealso::
       | :class:`.RemoteXBeeDevice`
       | :class:`.XBeeAPIPacket`
       | :class:`.XBeeEvent`
    """


class DataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.XBeeMessage`): Message containing the data
           received, the sender and the time.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.XBeeMessage`
    """


class ModemStatusReceived(XBeeEvent):
    """
    This event is fired when a XBee receives a modem status packet.

    The callbacks for handle this events will receive the following arguments:
        1. modem_status (:class:`.ModemStatus`): Modem status received.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.ModemStatus`
    """


class IOSampleReceived(XBeeEvent):
    """
    This event is fired when a XBee receives an IO packet.

    This includes:

    1. IO data sample RX indicator packet.
    2. RX IO 16 packet.
    3. RX IO 64 packet.

    The callbacks that handle this event will receive the following arguments:
        1. io_sample (:class:`.IOSample`): Received IO sample.
        2. sender (:class:`.RemoteXBeeDevice`): Remote XBee who sent the packet.
        3. time (Integer): the time in which the packet was received.

    .. seealso::
       | :class:`.IOSample`
       | :class:`.RemoteXBeeDevice`
       | :class:`.XBeeEvent`
    """


class NetworkModified(XBeeEvent):
    """
    This event is fired when the network is being modified by the addition of a
    new node, an existing node information is updated, a node removal, or when
    the network items are cleared.

    The callbacks that handle this event will receive the following arguments:
        1. event_type (:class:`digi.xbee.devices.NetworkEventType`): Network
           event type.
        2. reason (:class:`digi.xbee.devices.NetworkEventReason`): Reason of
           the event.
        3. node (:class:`digi.xbee.devices.XBeeDevice` or
           :class:`digi.xbee.devices.RemoteXBeeDevice`): Node added, updated
           or removed from the network.

    .. seealso::
       | :class:`digi.xbee.devices.NetworkEventReason`
       | :class:`digi.xbee.devices.NetworkEventType`
       | :class:`digi.xbee.devices.RemoteXBeeDevice`
       | :class:`digi.xbee.devices.XBeeDevice`
       | :class:`.XBeeEvent`
    """


class DeviceDiscovered(XBeeEvent):
    """
    This event is fired when an XBee discovers another remote XBee
    during a discovering operation.

    The callbacks that handle this event will receive the following arguments:
        1. discovered_device (:class:`.RemoteXBeeDevice`): Discovered remote XBee.

    .. seealso::
       | :class:`.RemoteXBeeDevice`
       | :class:`.XBeeEvent`
    """


class DiscoveryProcessFinished(XBeeEvent):
    """
    This event is fired when the discovery process finishes, either
    successfully or due to an error.

    The callbacks that handle this event will receive the following arguments:
        1. status (:class:`.NetworkDiscoveryStatus`): Network discovery status.
        2. description (String, optional): Description of the discovery status.

    .. seealso::
       | :class:`.NetworkDiscoveryStatus`
       | :class:`.XBeeEvent`
    """


class ExplicitDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives an explicit data packet.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.ExplicitXBeeMessage`): Message containing the
           received data, the sender, the time, and explicit data message
           parameters.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.XBeeMessage`
    """


class IPDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives IP data.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.IPMessage`): Message containing containing the IP
           address the message belongs to, source and destination ports, IP
           protocol, and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.IPMessage`
    """


class SMSReceived(XBeeEvent):
    """
    This event is fired when an XBee receives an SMS.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.SMSMessage`): Message containing the phone number
           that sent the message and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.SMSMessage`
    """


class RelayDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives a user data relay output packet.

    The callbacks to handle these events will receive the following arguments:
        1. message (:class:`.UserDataRelayMessage`): Message containing the
           source interface and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.UserDataRelayMessage`
    """


class BluetoothDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data from the Bluetooth interface.

    The callbacks to handle these events will receive the following arguments:
        1. data (Bytearray): Received Bluetooth data.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class MicroPythonDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data from the MicroPython interface.

    The callbacks to handle these events will receive the following arguments:
        1. data (Bytearray): Received MicroPython data.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class SocketStateReceived(XBeeEvent):
    """
    This event is fired when an XBee receives a socket state packet.

    The callbacks to handle these events will receive the following arguments:
        1. socket_id (Integer): Socket ID for state reported.
        2. state (:class:`.SocketState`): Received state.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class SocketDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives a socket receive data packet.

    The callbacks to handle these events will receive the following arguments:
        1. socket_id (Integer): ID of the socket that received the data.
        2. payload (Bytearray): Received data.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class SocketDataReceivedFrom(XBeeEvent):
    """
    This event is fired when an XBee receives a socket receive from data packet.

    The callbacks to handle these events will receive the following arguments:
        1. socket_id (Integer): ID of the socket that received the data.
        2. address (Tuple): Pair (host, port) of the source address where
            host is a string representing an IPv4 address like '100.50.200.5',
            and port is an integer.
        3. payload (Bytearray): Received data.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class RouteRecordIndicatorReceived(XBeeEvent):
    """
    This event is fired when a route record packet is received.

    The callbacks to handle these events will receive the following arguments:
        1. Source (:class:`.RemoteXBeeDevice`): Remote node that sent the
            route record.
        2. Hops (List): List of intermediate hops 16-bit addresses from closest
            to source (who sent the route record) to closest to destination
            (:class:`.XBee16BitAddress`).

    .. seealso::
       | :class:`.XBeeEvent`
    """


class RouteInformationReceived(XBeeEvent):
    """
    This event is fired when a route information packet is received.

    The callbacks to handle these events will receive the following arguments:
        1. Source event (Integer): Source event (0x11: NACK, 0x12: Trace route)
        2. Timestamp (Integer): System timer value on the node generating
            this package. The timestamp is in microseconds.
        3. ACK timeout count (Integer): Number of MAC ACK timeouts that occur.
        4. TX blocked count (Integer): Number of times the transmissions was
            blocked due to reception in progress.
        5. Destination address (:class:`.XBee64BitAddress`): 64-bit address of
            the final destination node.
        6. Source address (:class:`.XBee64BitAddress`): 64-bit address of
            the source node.
        7. Responder address (:class:`.XBee64BitAddress`): 64-bit address of
            of the node that generates this packet after it sends (or attempts
            to send) the packet to the next hop (successor node)
        8. Successor address (:class:`.XBee64BitAddress`): 64-bit address of
            of the next node after the responder in the route towards the
            destination.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class RouteReceived(XBeeEvent):
    """
    This event is fired when a route is received.

    The callbacks to handle these events will receive the following arguments:
        1. source (:class:`.XBeeDevice`): Local node.
        2. destination (:class:`.RemoteXBeeDevice`): Remote node.
        3. hops (List): List of intermediate hops from source node to
            closest to destination (:class:`.RemoteXBeeDevice`).

    .. seealso::
       | :class:`.XBeeEvent`
    """


class InitDiscoveryScan(XBeeEvent):
    """
    This event is fired when a new network discovery scan is about to start.

    The callbacks to handle these events will receive the following arguments:
        1. Number of scan to start (starting with 1).
        2. Total number of scans.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class EndDiscoveryScan(XBeeEvent):
    """
    This event is fired when a network discovery scan has just finished.

    The callbacks to handle these events will receive the following arguments:
        1. Number of scan that has finished (starting with 1).
        2. Total number of scans.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class FileSystemFrameReceived(XBeeEvent):
    """
    This event is fired when a file system packet is received.

    The callbacks to handle these events will receive the following arguments:
        1. Source (:class:`.AbstractXBeeDevice`): Node that sent the file
           system frame.
        2. Frame id (Integer): Received frame id.
        3. Command (:class:`.FSCmd`): File system command.
        4. Status (:class: `.FSCommandStatus`): Status code.
        5. Receive options (Integer): Bitfield indicating receive options.
           See :class:`.ReceiveOptions`.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class BLEGAPScanReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data from the BLE scan interface.

    The callbacks to handle these events will receive the following arguments:
        1. data (Bytearray): Received Bluetooth data.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class BLEGAPScanStatusReceived(XBeeEvent):
    """
    This event is fired when an XBee receives status from the BLE
    scan interface.

    The callbacks for handle this events will receive the following arguments:
        1. Status (:class:`.BLEGAPScanStatus`): Gap scan Status code.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class NetworkUpdateProgress(XBeeEvent):
    """
    This event is fired when the progress of a running firmware update changes.

    The callbacks to handle these events will receive the following arguments:
        1. The XBee being updated.
        2. The current update task as a String.
        3. The current update task percentage as an Integer.

    .. seealso::
       | :class:`.XBeeEvent`
    """


class PacketListener(threading.Thread):
    """
    This class represents a packet listener, which is a thread that's always
    listening for incoming packets to the XBee.

    When it receives a packet, this class throws an event depending on which
    packet it is. You can add your own callbacks for this events via certain
    class methods. This callbacks must have a certain header, see each event
    documentation.

    This class has fields that are events. Its recommended to use only the
    append() and remove() method on them, or -= and += operators.
    If you do something more with them, it's for your own risk.

    Here are the parameters which will be received by the event callbacks,
    depending on which event it is in each case:

    The following parameters are passed via \\*\\*kwargs to event callbacks of:

    1. PacketReceived:
        1.1 received_packet (:class:`.XBeeAPIPacket`): Received packet.
    2. DataReceived
        2.1 message (:class:`.XBeeMessage`): Message containing the data
            received, the sender and the time.
    3. ModemStatusReceived
        3.1 modem_status (:class:`.ModemStatus`): Modem status received.
    """

    __DEFAULT_QUEUE_MAX_SIZE = 40
    """
    Default max. size that the queue has.
    """

    _LOG_PATTERN = "{comm_iface:s} - {event:s} - {fr_type:s}: {sender:s} - {more_data:s}"
    """
    Generic pattern for display received messages (high-level) with logger.
    """

    _LOG_PACKET_PATTERN = "{comm_iface:s} - {event:s} - {opmode:s}: {content:s}"
    """
    Pattern used to log packet events.
    """

    _log = logging.getLogger(__name__)
    """
    Logger.
    """

    def __init__(self, comm_iface, xbee_device, queue_max_size=None):
        """
        Class constructor. Instantiates a new :class:`.PacketListener` object
        with the provided parameters.

        Args:
            comm_iface (:class:`.XBeeCommunicationInterface`): Hardware
                interface to listen to.
            xbee_device (:class:`.XBeeDevice`): XBee that is the listener owner.
            queue_max_size (Integer): Maximum size of the XBee queue.
        """
        threading.Thread.__init__(self)

        self.daemon = True

        # User callbacks:
        self.__packet_received = PacketReceived()
        self.__packet_received_from = PacketReceivedFrom()
        self.__data_received = DataReceived()
        self.__modem_status_received = ModemStatusReceived()
        self.__io_sample_received = IOSampleReceived()
        self.__explicit_packet_received = ExplicitDataReceived()
        self.__ip_data_received = IPDataReceived()
        self.__sms_received = SMSReceived()
        self.__relay_data_received = RelayDataReceived()
        self.__bluetooth_data_received = BluetoothDataReceived()
        self.__micropython_data_received = MicroPythonDataReceived()
        self.__socket_state_received = SocketStateReceived()
        self.__socket_data_received = SocketDataReceived()
        self.__socket_data_received_from = SocketDataReceivedFrom()
        self.__route_record_indicator_received_from = RouteRecordIndicatorReceived()
        self.__dm_route_information_received_from = RouteInformationReceived()
        self.__fs_frame_received = FileSystemFrameReceived()
        self.__ble_gap_scan_received = BLEGAPScanReceived()
        self.__ble_gap_scan_status_received = BLEGAPScanStatusReceived()

        # API internal callbacks:
        self.__packet_received_api = xbee_device.get_xbee_device_callbacks()

        self.__xbee = xbee_device
        self.__comm_iface = comm_iface
        self.__stop = True
        self.__started = Event()

        self.__queue_max_size = (queue_max_size if queue_max_size is not None
                                 else self.__DEFAULT_QUEUE_MAX_SIZE)
        self.__xbee_queue = XBeeQueue(self.__queue_max_size)
        self.__data_xbee_queue = XBeeQueue(self.__queue_max_size)
        self.__explicit_xbee_queue = XBeeQueue(self.__queue_max_size)
        self.__ip_xbee_queue = XBeeQueue(self.__queue_max_size)

    def wait_until_started(self, timeout=None):
        """
        Blocks until the thread has fully started. If already started, returns
        immediately.

        Args:
            timeout (Float): Timeout for the operation in seconds.
        """

        self.__started.wait(timeout)

    def run(self):
        """
        This is the method that will be executing for listening packets.

        For each packet, it will execute the proper callbacks.
        """
        try:
            self.__stop = False
            self.__started.set()
            while not self.__stop:
                try:
                    # Try to read a packet. Read packet is unescaped.
                    raw_packet = self.__comm_iface.wait_for_frame(
                        self.__xbee.operating_mode)
                except SerialException as exc:
                    # SerialException: device reports readiness to read but
                    # returned no data (device disconnected or multiple access on port?)
                    if "device reports readiness to read but returned no data" in str(exc):
                        self._log.warning("Serial exception while reading: %s", exc)
                        continue
                    raise exc

                if raw_packet is not None:
                    # If the current protocol is 802.15.4, the packet may have
                    # to be discarded.
                    if (self.__xbee.get_protocol() == XBeeProtocol.RAW_802_15_4
                            and not self.__check_packet_802_15_4(raw_packet)):
                        continue

                    # Build the packet.
                    try:
                        read_packet = factory.build_frame(
                            raw_packet, self.__xbee.operating_mode)
                    except InvalidPacketException as exc:
                        if self.__xbee.is_open():
                            self._log.error("Error processing packet '%s': %s",
                                            utils.hex_to_string(raw_packet), str(exc))
                        continue

                    self._log.debug(self._LOG_PACKET_PATTERN.format(
                        comm_iface=str(self.__xbee.comm_iface),
                        event="RECEIVED", opmode=self.__xbee.operating_mode,
                        content=utils.hex_to_string(raw_packet)))

                    # Add the packet to the queue.
                    self.__add_packet_queue(read_packet)

                    # If the packet has information about a remote device,
                    # extract it and add/update this remote device to/in this
                    # XBee's network.
                    remote = self.__try_add_remote_device(read_packet)

                    # Execute API internal callbacks.
                    self.__packet_received_api(read_packet)

                    # Execute all user callbacks.
                    self.__execute_user_callbacks(read_packet, remote)
        except Exception as exc:
            if not self.__stop:
                self._log.exception(exc)
        finally:
            if not self.__stop:
                self.__stop = True
                if self.__comm_iface.is_interface_open:
                    self.__comm_iface.close()

    def stop(self):
        """
        Stops listening.
        """
        self.__stop = True
        self.__comm_iface.quit_reading()
        # Wait until thread fully stops.
        self.join()

    def is_running(self):
        """
        Returns whether this instance is running or not.

        Returns:
            Boolean: `True` if this instance is running, `False` otherwise.
        """
        return not self.__stop

    def get_queue(self):
        """
        Returns the packets queue.

        Returns:
            :class:`.XBeeQueue`: Packets queue.
        """
        return self.__xbee_queue

    def get_data_queue(self):
        """
        Returns the data packets queue.

        Returns:
            :class:`.XBeeQueue`: Data packets queue.
        """
        return self.__data_xbee_queue

    def get_explicit_queue(self):
        """
        Returns the explicit packets queue.

        Returns:
            :class:`.XBeeQueue`: Explicit packets queue.
        """
        return self.__explicit_xbee_queue

    def get_ip_queue(self):
        """
        Returns the IP packets queue.

        Returns:
            :class:`.XBeeQueue`: IP packets queue.
        """
        return self.__ip_xbee_queue

    def add_packet_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.PacketReceived`.

        Args:
            callback (Function or List of functions): Callback.
                Receives one argument.

                * The received packet as a :class:`.XBeeAPIPacket`
        """
        if isinstance(callback, list):
            self.__packet_received.extend(callback)
        elif callback:
            self.__packet_received += callback

    def add_packet_received_from_callback(self, callback):
        """
        Adds a callback for the event :class:`.PacketReceivedFrom`.

        Args:
            callback (Function or List of functions): Callback. Receives
                two arguments.

                * The received packet as a :class:`.XBeeAPIPacket`
                * The remote XBee device who has sent the packet as a
                  :class:`.RemoteXBeeDevice`
        """
        if isinstance(callback, list):
            self.__packet_received_from.extend(callback)
        elif callback:
            self.__packet_received_from += callback

    def add_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.DataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as an :class:`.XBeeMessage`
        """
        if isinstance(callback, list):
            self.__data_received.extend(callback)
        elif callback:
            self.__data_received += callback

    def add_modem_status_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.ModemStatusReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The modem status as a :class:`.ModemStatus`
        """
        if isinstance(callback, list):
            self.__modem_status_received.extend(callback)
        elif callback:
            self.__modem_status_received += callback

    def add_io_sample_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.IOSampleReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives three
                arguments.

                * The received IO sample as an :class:`.IOSample`
                * The remote XBee device who has sent the packet as a
                  :class:`.RemoteXBeeDevice`
                * The time in which the packet was received as an Integer
        """
        if isinstance(callback, list):
            self.__io_sample_received.extend(callback)
        elif callback:
            self.__io_sample_received += callback

    def add_explicit_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.ExplicitDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The explicit data received as an :class:`.ExplicitXBeeMessage`
        """
        if isinstance(callback, list):
            self.__explicit_packet_received.extend(callback)
        elif callback:
            self.__explicit_packet_received += callback

    def add_ip_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.IPDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as an :class:`.IPMessage`
        """
        if isinstance(callback, list):
            self.__ip_data_received.extend(callback)
        elif callback:
            self.__ip_data_received += callback

    def add_sms_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.SMSReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as an :class:`.SMSMessage`
        """
        if isinstance(callback, list):
            self.__sms_received.extend(callback)
        elif callback:
            self.__sms_received += callback

    def add_user_data_relay_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.RelayDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as a :class:`.UserDataRelayMessage`
        """
        if isinstance(callback, list):
            self.__relay_data_received.extend(callback)
        elif callback:
            self.__relay_data_received += callback

    def add_bluetooth_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.BluetoothDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as a Bytearray
        """
        if isinstance(callback, list):
            self.__bluetooth_data_received.extend(callback)
        elif callback:
            self.__bluetooth_data_received += callback

    def add_micropython_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.MicroPythonDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as a Bytearray
        """
        if isinstance(callback, list):
            self.__micropython_data_received.extend(callback)
        elif callback:
            self.__micropython_data_received += callback

    def add_socket_state_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.SocketStateReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives two
                arguments.

                * The socket ID as an Integer.
                * The state received as a :class:`.SocketState`
        """
        if isinstance(callback, list):
            self.__socket_state_received.extend(callback)
        elif callback:
            self.__socket_state_received += callback

    def add_socket_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.SocketDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives two
                arguments.

                * The socket ID as an Integer.
                * The status received as a :class:`.SocketStatus`
        """
        if isinstance(callback, list):
            self.__socket_data_received.extend(callback)
        elif callback:
            self.__socket_data_received += callback

    def add_socket_data_received_from_callback(self, callback):
        """
        Adds a callback for the event :class:`.SocketDataReceivedFrom`.

        Args:
            callback (Function or List of functions): Callback. Receives three
                arguments.

                * The socket ID as an Integer.
                * A pair (host, port) of the source address where host is a
                  string representing an IPv4 address like '100.50.200.5',
                  and port is an integer.
                * The status received as a :class:`.SocketStatus`
        """
        if isinstance(callback, list):
            self.__socket_data_received_from.extend(callback)
        elif callback:
            self.__socket_data_received_from += callback

    def add_route_record_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.RouteRecordIndicatorReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives two
                arguments.

                * Source (:class:`.RemoteXBeeDevice`): Remote node that sent
                    the route record.
                * Hops (List): List of intermediate hops 16-bit addresses from
                    closest to source (who sent the route record) to closest to
                    destination.
        """
        if isinstance(callback, list):
            self.__route_record_indicator_received_from.extend(callback)
        elif callback:
            self.__route_record_indicator_received_from += callback

    def add_route_info_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.RouteInformationReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives eight
                arguments.

                * Source event (Integer): Source event (0x11: NACK,
                  0x12: Trace route)
                * Timestamp (Integer): System timer value on the node
                  generating this package. The timestamp is in microseconds.
                * ACK timeout count (Integer): Number of MAC ACK timeouts that occur.
                * TX blocked count (Integer): Number of times the transmissions
                  was blocked due to reception in progress.
                * Destination address (:class:`.XBee64BitAddress`): 64-bit
                  address of the final destination node.
                * Source address (:class:`.XBee64BitAddress`): 64-bit address
                  of the source node.
                * Responder address (:class:`.XBee64BitAddress`): 64-bit
                  address of the node that generated this packet after it sent
                  (or attempted to send) the packet to the next hop
                  (successor node)
                * Successor address (:class:`.XBee64BitAddress`): 64-bit
                  address of the next node after the responder in the route
                  towards the destination.
        """
        if isinstance(callback, list):
            self.__dm_route_information_received_from.extend(callback)
        elif callback:
            self.__dm_route_information_received_from += callback

    def add_fs_frame_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.FileSystemFrameReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives four
                arguments.

                * Source (:class:`.AbstractXBeeDevice`): Node that sent the
                   file system frame.
                * Frame id (Integer): Received frame id.
                * Command (:class:`.FSCmd`): File system command.
                * Receive options (Integer): Bitfield indicating receive
                  options. See :class:`.ReceiveOptions`.
        """
        if isinstance(callback, list):
            self.__fs_frame_received.extend(callback)
        elif callback:
            self.__fs_frame_received += callback

    def add_ble_gap_advertisement_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.BluetoothDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as a Bytearray
        """
        if isinstance(callback, list):
            self.__ble_gap_scan_received.extend(callback)
        elif callback:
            self.__ble_gap_scan_received += callback

    def add_ble_gap_scan_status_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.BluetoothDataReceived`.

        Args:
            callback (Function or List of functions): Callback. Receives one
                argument.

                * The data received as a Bytearray
        """
        if isinstance(callback, list):
            self.__ble_gap_scan_status_received.extend(callback)
        elif callback:
            self.__ble_gap_scan_status_received += callback

    def del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.PacketReceived`
        event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.PacketReceived` event.
        """
        self.__packet_received -= callback

    def del_packet_received_from_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.PacketReceivedFrom` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.PacketReceivedFrom` event.
        """
        self.__packet_received_from -= callback

    def del_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DataReceived`
        event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.DataReceived` event.
        """
        self.__data_received -= callback

    def del_modem_status_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.ModemStatusReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.ModemStatusReceived` event.
        """
        self.__modem_status_received -= callback

    def del_io_sample_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.IOSampleReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.IOSampleReceived` event.
        """
        self.__io_sample_received -= callback

    def del_explicit_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.ExplicitDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.ExplicitDataReceived` event.
        """
        self.__explicit_packet_received -= callback

    def del_ip_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.IPDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.IPDataReceived` event.
        """
        self.__ip_data_received -= callback

    def del_sms_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SMSReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.SMSReceived` event.
        """
        self.__sms_received -= callback

    def del_user_data_relay_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.RelayDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.RelayDataReceived` event.
        """
        self.__relay_data_received -= callback

    def del_bluetooth_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.BluetoothDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.BluetoothDataReceived` event.
        """
        self.__bluetooth_data_received -= callback

    def del_micropython_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.MicroPythonDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.MicroPythonDataReceived` event.
        """
        self.__micropython_data_received -= callback

    def del_socket_state_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.SocketStateReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.SocketStateReceived` event.
        """
        self.__socket_state_received -= callback

    def del_socket_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.SocketDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.SocketDataReceived` event.
        """
        self.__socket_data_received -= callback

    def del_socket_data_received_from_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.SocketDataReceivedFrom` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.SocketDataReceivedFrom` event.
        """
        self.__socket_data_received_from -= callback

    def del_route_record_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.RouteRecordIndicatorReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.RouteRecordIndicatorReceived` event.
        """
        self.__route_record_indicator_received_from -= callback

    def del_route_info_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.RouteInformationReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.RouteInformationReceived` event.
        """
        self.__dm_route_information_received_from -= callback

    def del_fs_frame_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.FileSystemFrameReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.FileSystemFrameReceived` event.
        """
        self.__fs_frame_received -= callback

    def del_ble_gap_advertisement_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.BluetoothDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.BluetoothDataReceived` event.
        """
        self.__ble_gap_scan_received -= callback

    def del_ble_gap_scan_status_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.BluetoothDataReceived` event.

        Args:
            callback (Function): Callback to delete.

        Raises:
            ValueError: If `callback` is not in the callback list of
                :class:`.BluetoothDataReceived` event.
        """
        self.__ble_gap_scan_status_received -= callback

    def get_packet_received_callbacks(self):
        """
        Returns the list of registered callbacks for received packets.

        Returns:
            List: List of :class:`.PacketReceived` events.
        """
        return self.__packet_received

    def get_packet_received_from_callbacks(self):
        """
        Returns the list of registered callbacks for received packets.

        Returns:
            List: List of :class:`.PacketReceivedFrom` events.
        """
        return self.__packet_received_from

    def get_data_received_callbacks(self):
        """
        Returns the list of registered callbacks for received data.

        Returns:
            List: List of :class:`.DataReceived` events.
        """
        return self.__data_received

    def get_modem_status_received_callbacks(self):
        """
        Returns the list of registered callbacks for received modem status.

        Returns:
            List: List of :class:`.ModemStatusReceived` events.
        """
        return self.__modem_status_received

    def get_io_sample_received_callbacks(self):
        """
        Returns the list of registered callbacks for received IO samples.

        Returns:
            List: List of :class:`.IOSampleReceived` events.
        """
        return self.__io_sample_received

    def get_explicit_data_received_callbacks(self):
        """
        Returns the list of registered callbacks for received explicit data.

        Returns:
            List: List of :class:`.ExplicitDataReceived` events.
        """
        return self.__explicit_packet_received

    def get_ip_data_received_callbacks(self):
        """
        Returns the list of registered callbacks for received IP data.

        Returns:
            List: List of :class:`.IPDataReceived` events.
        """
        return self.__ip_data_received

    def get_sms_received_callbacks(self):
        """
        Returns the list of registered callbacks for received SMS.

        Returns:
            List: List of :class:`.SMSReceived` events.
        """
        return self.__sms_received

    def get_user_data_relay_received_callbacks(self):
        """
        Returns the list of registered callbacks for received user data relay.

        Returns:
            List: List of :class:`.RelayDataReceived` events.
        """
        return self.__relay_data_received

    def get_bluetooth_data_received_callbacks(self):
        """
        Returns the list of registered callbacks for received Bluetooth data.

        Returns:
            List: List of :class:`.BluetoothDataReceived` events.
        """
        return self.__bluetooth_data_received

    def get_micropython_data_received_callbacks(self):
        """
        Returns the list of registered callbacks for received MicroPython data.

        Returns:
            List: List of :class:`.MicroPythonDataReceived` events.
        """
        return self.__micropython_data_received

    def get_socket_state_received_callbacks(self):
        """
        Returns the list of registered callbacks for received socket state.

        Returns:
            List: List of :class:`.SocketStateReceived` events.
        """
        return self.__socket_state_received

    def get_socket_data_received_callbacks(self):
        """
        Returns the list of registered callbacks for received socket data.

        Returns:
            List: List of :class:`.SocketDataReceived` events.
        """
        return self.__socket_data_received

    def get_socket_data_received_from_callbacks(self):
        """
        Returns the list of registered callbacks for received socket data from.

        Returns:
            List: List of :class:`.SocketDataReceivedFrom` events.
        """
        return self.__socket_data_received_from

    def get_route_record_received_callbacks(self):
        """
        Returns the list of registered callbacks for received route records.

        Returns:
            List: List of :class:`.RouteRecordIndicatorReceived` events.
        """
        return self.__route_record_indicator_received_from

    def get_route_info_callbacks(self):
        """
        Returns the list of registered callbacks for received route information
        packets.

        Returns:
            List: List of :class:`.RouteInformationReceived` events.
        """
        return self.__dm_route_information_received_from

    def get_fs_frame_received_callbacks(self):
        """
        Returns the list of registered callbacks for received file system
        packets.

        Returns:
            List: List of :class:`.FileSystemFrameReceived` events.
        """
        return self.__fs_frame_received

    def get_ble_gap_scan_received_callbacks(self):
        """
        Returns the list of registered callbacks for received Bluetooth data.

        Returns:
            List: List of :class:`.BluetoothDataReceived` events.
        """
        return self.__ble_gap_scan_received

    def get_ble_gap_scan_status_received_callbacks(self):
        """
        Returns the list of registered callbacks for received Bluetooth data.

        Returns:
            List: List of :class:`.BluetoothDataReceived` events.
        """
        return self.__ble_gap_scan_status_received

    def __execute_user_callbacks(self, packet, remote=None):
        """
        Executes callbacks corresponding to the received packet.

        Args:
            packet (:class:`.XBeeAPIPacket`): Received packet.
            remote (:class:`.RemoteXBeeDevice`): XBee that sent the packet.
        """
        # All packets callback.
        self.__packet_received(packet)
        if remote:
            self.__packet_received_from(packet, remote)

        # Data reception callbacks
        f_type = packet.get_frame_type()
        if f_type in (ApiFrameType.RX_64, ApiFrameType.RX_16,
                      ApiFrameType.RECEIVE_PACKET):
            data = packet.rf_data
            is_broadcast = packet.is_broadcast()
            self.__data_received(
                XBeeMessage(data, remote, time.time(), broadcast=is_broadcast))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface),
                event="RECEIVED", fr_type="DATA",
                sender=str(remote.get_64bit_addr()) if remote is not None else "None",
                more_data=utils.hex_to_string(data)))

        # Modem status callbacks
        elif f_type == ApiFrameType.MODEM_STATUS:
            self.__modem_status_received(packet.modem_status)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface),
                event="RECEIVED", fr_type="MODEM STATUS",
                sender=str(remote.get_64bit_addr()) if remote is not None else "None",
                more_data=packet.modem_status))

        # IO_sample callbacks
        elif f_type in (ApiFrameType.RX_IO_16, ApiFrameType.RX_IO_64,
                        ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR):
            self.__io_sample_received(packet.io_sample, remote, time.time())
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface),
                event="RECEIVED", fr_type="IOSAMPLE",
                sender=str(remote.get_64bit_addr()) if remote is not None else "None",
                more_data=str(packet.io_sample)))

        # Explicit packet callbacks
        elif f_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
            data = packet.rf_data
            is_broadcast = packet.is_broadcast()
            # If it's 'special' packet, notify the data_received callbacks too:
            if self.__is_explicit_data_packet(packet):
                self.__data_received(XBeeMessage(data, remote, time.time(),
                                                 broadcast=is_broadcast))
            elif self.__is_explicit_io_packet(packet):
                self.__io_sample_received(IOSample(data), remote, time.time())
            self.__explicit_packet_received(PacketListener.__expl_to_message(
                remote, is_broadcast, packet))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface),
                event="RECEIVED", fr_type="EXPLICIT DATA",
                sender=str(remote.get_64bit_addr()) if remote is not None else "None",
                more_data=utils.hex_to_string(data)))

        # IP data
        elif f_type == ApiFrameType.RX_IPV4:
            self.__ip_data_received(
                IPMessage(packet.source_address, packet.source_port,
                          packet.dest_port, packet.ip_protocol, packet.data))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="IP DATA", sender=str(packet.source_address),
                more_data=utils.hex_to_string(packet.data)))

        # SMS
        elif f_type == ApiFrameType.RX_SMS:
            self.__sms_received(SMSMessage(packet.phone_number, packet.data))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="SMS", sender=str(packet.phone_number),
                more_data=packet.data))

        # Relay
        elif f_type == ApiFrameType.USER_DATA_RELAY_OUTPUT:
            # Notify generic callbacks.
            self.__relay_data_received(
                UserDataRelayMessage(packet.src_interface, packet.data))
            # Notify specific callbacks.
            if packet.src_interface == XBeeLocalInterface.BLUETOOTH:
                self.__bluetooth_data_received(packet.data)
            elif packet.src_interface == XBeeLocalInterface.MICROPYTHON:
                self.__micropython_data_received(packet.data)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="RELAY DATA", sender=packet.src_interface.description,
                more_data=utils.hex_to_string(packet.data)))

        # Socket state
        elif f_type == ApiFrameType.SOCKET_STATE:
            self.__socket_state_received(packet.socket_id, packet.state)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="SOCKET STATE", sender=str(packet.socket_id),
                more_data=packet.state))

        # Socket receive data
        elif f_type == ApiFrameType.SOCKET_RECEIVE:
            self.__socket_data_received(packet.socket_id, packet.payload)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="SOCKET DATA", sender=str(packet.socket_id),
                more_data=utils.hex_to_string(packet.payload)))

        # Socket receive data from
        elif f_type == ApiFrameType.SOCKET_RECEIVE_FROM:
            address = (str(packet.source_address), packet.source_port)
            self.__socket_data_received_from(packet.socket_id, address, packet.payload)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="SOCKET DATA", sender=str(packet.socket_id),
                more_data="%s - %s" % (address, utils.hex_to_string(packet.payload))))

        # Route record indicator
        elif f_type == ApiFrameType.ROUTE_RECORD_INDICATOR:
            self.__route_record_indicator_received_from(remote,
                                                        packet.hops)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="ROUTE RECORD INDICATOR",
                sender=str(remote.get_64bit_addr()) if remote else "None",
                more_data="Hops: %s" % ' - '.join(map(str, packet.hops))))

        # Route information
        elif f_type == ApiFrameType.DIGIMESH_ROUTE_INFORMATION:
            self.__dm_route_information_received_from(
                packet.src_event, packet.timestamp,
                packet.ack_timeout_count, packet.tx_block_count,
                packet.dst_addr, packet.src_addr,
                packet.responder_addr, packet.successor_addr)
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="ROUTE INFORMATION", sender=str(packet.responder_addr),
                more_data="src: %s - dst: %s - responder: %s - successor: %s - "
                          "src event: %d - timestamp: %d - ack timeouts: %d - "
                          "tx blocked: %d" % (packet.src_addr,
                                              packet.dst_addr,
                                              packet.responder_addr,
                                              packet.successor_addr,
                                              packet.src_event,
                                              packet.timestamp,
                                              packet.ack_timeout_count,
                                              packet.tx_block_count)))
        # File system frame
        elif f_type in (ApiFrameType.FILE_SYSTEM_RESPONSE,
                        ApiFrameType.REMOTE_FILE_SYSTEM_RESPONSE):
            node = self.__xbee
            rcv_opts = None
            if f_type == ApiFrameType.REMOTE_FILE_SYSTEM_RESPONSE:
                node = remote
                rcv_opts = packet.receive_options
            self.__fs_frame_received(node, packet.frame_id, packet.command, rcv_opts)

            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface),
                event="RECEIVED", fr_type="FILE SYSTEM RESPONSE",
                sender=str(remote.get_64bit_addr()) if remote else "Local",
                more_data="frame id: %d - command: %s, status: %d (%s), "
                          "receive options: %s" % (packet.frame_id,
                                                   packet.command,
                                                   packet.command.status_value,
                                                   packet.command.status,
                                                   rcv_opts)))

        # Bluetooth BLE GAP Scan Legacy Advertisement Response
        elif f_type == ApiFrameType.BLUETOOTH_GAP_SCAN_LEGACY_ADVERTISEMENT_RESPONSE:
            self.__ble_gap_scan_received(BLEGAPScanLegacyAdvertisementMessage(
                packet.address,
                packet.address_type,
                packet.advertisement_flags,
                packet.rssi,
                packet.payload))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="BLE GAP SCAN LEGACY", sender=str(packet.address),
                more_data=packet.payload.decode(encoding='utf8', errors='ignore')))

        # Bluetooth BLE GAP Scan Extended Advertisement Response
        elif f_type == ApiFrameType.BLUETOOTH_GAP_SCAN_EXTENDED_ADVERTISEMENT_RESPONSE:
            self.__ble_gap_scan_received(BLEGAPScanExtendedAdvertisementMessage(
                packet.address,
                packet.address_type,
                packet.advertisement_flags,
                packet.rssi,
                packet.advertisement_set_id,
                packet.primary_phy,
                packet.secondary_phy,
                packet.tx_power,
                packet.periodic_interval,
                packet.data_completeness,
                packet.payload))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="BLE GAP SCAN EXTENDED", sender=str(packet.address),
                more_data=packet.payload.decode(encoding='utf8', errors='ignore')))

        # Bluetooth BLE GAP Scan Status Response
        elif f_type == ApiFrameType.BLUETOOTH_GAP_SCAN_STATUS:
            self.__ble_gap_scan_status_received(BLEGAPScanStatusMessage(
                packet.scan_status))
            self._log.debug(self._LOG_PATTERN.format(
                comm_iface=str(self.__xbee.comm_iface), event="RECEIVED",
                fr_type="BLE GAP SCAN STATUS", sender="None",
                more_data=str(packet.scan_status)))

    @staticmethod
    def __get_remote_device_data_from_packet(packet, uses_16bit_addr):
        """
        Extracts the 64 bit-address, the 16 bit-address, node identifier,
        hardware version, and firmware version from `packet` if is possible.
        """
        # Do not get information from a Remote AT Command response with a
        # TX failure: it is not possible to know if the remote does not exists
        # or is sleeping
        f_type = packet.get_frame_type()
        if (f_type == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE
                and packet.status == ATCommandStatus.TX_FAILURE):
            return None, None, None, None, None, None

        x64bit_addr = None
        x16bit_addr = None
        node_id = None
        hw_version = None
        fw_version = None
        op_mode = None

        if hasattr(packet, "x64bit_source_addr"):
            x64bit_addr = packet.x64bit_source_addr
        if hasattr(packet, "x16bit_source_addr"):
            x16bit_addr = packet.x16bit_source_addr

        # Check if NI, HV, VR, MY values are included in the response
        if (f_type in (ApiFrameType.AT_COMMAND_RESPONSE,
                       ApiFrameType.REMOTE_AT_COMMAND_RESPONSE)
                and packet.status == ATCommandStatus.OK
                and packet.command_value):
            cmd = packet.command.upper()
            val = packet.command_value

            # Mark data is coming from the local XBee
            if f_type == ApiFrameType.AT_COMMAND_RESPONSE:
                x64bit_addr = "local"

            if cmd == ATStringCommand.NI.command:
                node_id = val.decode(encoding='utf8', errors='ignore')
            elif cmd == ATStringCommand.HV.command:
                hw_version = HardwareVersion.get(val[0])
            elif cmd == ATStringCommand.VR.command:
                fw_version = val
            elif cmd == ATStringCommand.MY.command:
                if not x16bit_addr:
                    x16bit_addr = None
                    if uses_16bit_addr and XBee16BitAddress.is_valid(val):
                        x16bit_addr = XBee16BitAddress(val)
            elif (cmd == ATStringCommand.AP.command
                  and f_type == ApiFrameType.AT_COMMAND_RESPONSE):
                op_mode = OperatingMode.get(val[0])

        return x64bit_addr, x16bit_addr, node_id, hw_version, fw_version, op_mode

    @staticmethod
    def __check_packet_802_15_4(raw_data):
        """
        If the current XBee's protocol is 802.15.4 and the user sends many 'ND'
        commands, the device could return an RX 64 IO packet with an invalid
        payload (length < 5).

        In this case the packet must be discarded, or an exception must be raised.

        This method checks a received raw_data and returns `False` if the
        the packet should not be processed.

        Args:
            raw_data (Bytearray): Received data.

        Returns:
            Boolean: `True` if the packet must be processed, `False` otherwise.
        """
        if (raw_data[3] == ApiFrameType.RX_IO_64
                and len(raw_data[14:-1]) < IOSample.min_io_sample_payload()):
            return False
        return True

    def __try_add_remote_device(self, packet):
        """
        If the packet has information about a remote device, this method
        extracts that information from the packet, creates a remote device, and
        adds it (if not exist yet) to the network.

        Args:
            packet (:class:`.XBeeAPIPacket`): Packet to check.

        Returns:
            :class:`.RemoteXBeeDevice`: Remote XBee extracted from the packet,
                `None` if the packet has not information about a remote device.
        """
        remote = None
        x64, x16, n_id, hw_ver, fw_ver, op_mode = \
            self.__get_remote_device_data_from_packet(
                packet, not XBeeProtocol.is_ip_protocol(self.__xbee.get_protocol()))
        if (x64 == "local" or XBee64BitAddress.is_known_node_addr(x64)
                or XBee16BitAddress.is_known_node_addr(x16)):
            network = self.__xbee.get_network()

            # Not all XBee supports network functionality
            if not network:
                if x64 == "local" or x64 == self.__xbee.get_64bit_addr():
                    return self.__xbee

                return None

            remote = network._add_remote_from_attr(
                digi.xbee.devices.NetworkEventReason.RECEIVED_MSG,
                x64bit_addr=x64, x16bit_addr=x16, node_id=n_id,
                hw_version=hw_ver, fw_version=fw_ver, op_mode=op_mode)

        return remote

    @staticmethod
    def __is_explicit_data_packet(packet):
        """
        Checks if the provided explicit data packet is directed to the data cluster.

        This means that this XBee has its API Output Mode distinct than Native
        (it's expecting explicit data packets), but some device has sent it a
        non-explicit data packet (TransmitRequest f.e.).
        In this case, this XBee receives a explicit data packet with the
        following values:

            1. Source endpoint = 0xE8
            2. Destination endpoint = 0xE8
            3. Cluster ID = 0x0011
            4. Profile ID = 0xC105

        Args:
            packet (:class:`.XBeeAPIPacket`): Packet to check.

        Returns:
            Boolean: `True` if the packet is a explicit data packet, `False`
                otherwise.
        """
        return (packet.source_endpoint == 0xE8 and packet.dest_endpoint == 0xE8
                and packet.cluster_id == 0x0011 and packet.profile_id == 0xC105)

    @staticmethod
    def __is_explicit_io_packet(packet):
        """
        Checks if the provided explicit data packet is directed to the IO cluster.

        This means that this XBee has its API Output Mode distinct than Native
        (it's expecting explicit data packets), but some device has sent an IO
        sample packet (IODataSampleRxIndicatorPacket f.e.).
        In this case, this XBee receives a explicit data packet with the
        following values:

            1. Source endpoint = 0xE8
            2. Destination endpoint = 0xE8
            3. Cluster ID = 0x0092
            4. Profile ID = 0xC105

        Args:
            packet (:class:`.XBeeAPIPacket`): Packet to check.

        Returns:
            Boolean: `True` if the packet is a explicit IO packet, `False`
                otherwise.
        """
        return (packet.source_endpoint == 0xE8 and packet.dest_endpoint == 0xE8
                and packet.cluster_id == 0x0092 and packet.profile_id == 0xC105)

    def __expl_to_no_expl(self, packet):
        """
        Creates a non-explicit data packet from the given explicit packet
        depending on this listener's XBee device protocol.

        Args:
            packet (:class:`.XBeeAPIPacket`): Packet to convert.

        Returns:
            :class:`.XBeeAPIPacket`: Proper receive packet depending on the
                current protocol and the available information (inside the
                packet).
        """
        x64 = packet.x64bit_source_addr
        x16 = packet.x16bit_source_addr
        if self.__xbee.get_protocol() != XBeeProtocol.RAW_802_15_4:
            return ReceivePacket(x64, x16, packet.receive_options,
                                 rf_data=packet.rf_data)

        if x64 != XBee64BitAddress.UNKNOWN_ADDRESS:
            return RX64Packet(x64, 0, packet.receive_options,
                              rf_data=packet.rf_data)
        if x16 != XBee16BitAddress.UNKNOWN_ADDRESS:
            return RX16Packet(x16, 0, packet.receive_options,
                              rf_data=packet.rf_data)

        # both address UNKNOWN
        return RX64Packet(x64, 0, packet.receive_options, rf_data=packet.rf_data)

    def __expl_to_io(self, packet):
        """
        Creates a IO packet from the given explicit packet depending on this
        listener's XBee protocol.

        Args:
            packet (:class:`.XBeeAPIPacket`): Packet to convert.

        Returns:
            :class:`.XBeeAPIPacket`: Proper receive packet depending on the
                current protocol and the available information (inside the packet).
        """
        return IODataSampleRxIndicatorPacket(
            packet.x64bit_source_addr, packet.x16bit_source_addr,
            packet.receive_options, rf_data=packet.rf_data)

    def __add_packet_queue(self, packet):
        """
        Adds a packet to the queue. If the queue is full, the first packet of
        the queue is removed and the given packet is added.

        Args:
            packet (:class:`.XBeeAPIPacket`): Packet to be added.
        """
        # Data packets.
        f_type = packet.get_frame_type()
        if f_type in (ApiFrameType.RECEIVE_PACKET, ApiFrameType.RX_64,
                      ApiFrameType.RX_16):
            if self.__data_xbee_queue.full():
                self.__data_xbee_queue.get()
            self.__data_xbee_queue.put_nowait(packet)
        # Explicit packets.
        elif f_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
            if self.__explicit_xbee_queue.full():
                self.__explicit_xbee_queue.get()
            self.__explicit_xbee_queue.put_nowait(packet)
            # Check if the explicit packet is 'special'.
            if self.__is_explicit_data_packet(packet):
                # Create the non-explicit version of this packet and add it to
                # the queue.
                self.__add_packet_queue(self.__expl_to_no_expl(packet))
            elif self.__is_explicit_io_packet(packet):
                # Create the IO packet corresponding to this packet and add it
                # to the queue.
                self.__add_packet_queue(self.__expl_to_io(packet))
        # IP packets.
        elif f_type == ApiFrameType.RX_IPV4:
            if self.__ip_xbee_queue.full():
                self.__ip_xbee_queue.get()
            self.__ip_xbee_queue.put_nowait(packet)
        # Rest of packets.
        else:
            if self.__xbee_queue.full():
                self.__xbee_queue.get()
            self.__xbee_queue.put_nowait(packet)

    @staticmethod
    def __expl_to_message(remote, broadcast, packet):
        """
        Converts an explicit packet in an explicit message.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee that sent the packet.
            broadcast (Boolean, optional, default=`False`): Flag indicating
                whether the message is broadcast (`True`) or not (`False`).
            packet (:class:`.XBeeAPIPacket`): Packet to be converted.

        Returns:
            :class:`.ExplicitXBeeMessage`: Explicit message generated from the
                provided parameters.
        """
        return ExplicitXBeeMessage(packet.rf_data, remote, time.time(),
                                   packet.source_endpoint, packet.dest_endpoint,
                                   packet.cluster_id, packet.profile_id,
                                   broadcast=broadcast)


class XBeeQueue(Queue):
    """
    This class represents an XBee queue.
    """

    def __init__(self, maxsize=10):
        """
        Class constructor. Instantiates a new :class:`.XBeeQueue` with the
        provided parameters.

        Args:
            maxsize (Integer, optional, default=10): Maximum size of the queue.
        """
        Queue.__init__(self, maxsize)

    def get(self, block=True, timeout=None):
        """
        Returns the first element of the queue if there is some element ready
        before timeout expires, in case of the timeout is not `None`.

        If timeout is `None`, this method is non-blocking. In this case, if
        there is not any element available, it returns `None`, otherwise it
        returns an :class:`.XBeeAPIPacket`.

        Args:
            block (Boolean): `True` to block during `timeout` waiting for a
                packet, `False` to not block.
            timeout (Integer, optional): timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: Packet if there is any packet available
                before `timeout` expires. If `timeout` is `None`, the returned
                value may be `None`.

        Raises:
            TimeoutException: If `timeout` is not `None` and there is not any
                packet available before the timeout expires.
        """
        if timeout is None:
            try:
                return Queue.get(self, block=False)
            except (Empty, ValueError):
                return None

        try:
            return Queue.get(self, True, timeout)
        except Empty:
            raise TimeoutException() from None

    def get_by_remote(self, remote, timeout=None):
        """
        Returns the first element of the queue that had been sent by
        `remote`, if there is some in the specified timeout.

        If timeout is `None`, this method is non-blocking. In this case, if
        there is not any packet sent by `remote` in the queue, it returns
        `None`, otherwise it returns an :class:`.XBeeAPIPacket`.

        Args:
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to get its first
                element from queue.
            timeout (Integer, optional, default=`None`): Timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: If there is any packet available before
                the timeout expires. If timeout is `None`, the returned value
                may be `None`.

        Raises:
            TimeoutException: If timeout is not `None` and there is not any
                packet available that was sent by `remote` before the timeout
                expires.
        """
        if timeout is None:
            with self.mutex:
                for packet in self.queue:
                    if self.__remote_device_match(packet, remote):
                        self.queue.remove(packet)
                        return packet
            return None

        packet = self.get_by_remote(remote)
        dead_line = time.time() + timeout
        while packet is None and dead_line > time.time():
            time.sleep(0.1)
            packet = self.get_by_remote(remote)
        if packet is None:
            raise TimeoutException()

        return packet

    def get_by_ip(self, ip_addr, timeout=None):
        """
        Returns the first IP data packet from the queue whose IP address
        matches the provided address.

        If timeout is `None`, this method is non-blocking. In this case, if
        there is not any packet sent by `ip_addr` in the queue, it returns
        `None`, otherwise it returns an :class:`.XBeeAPIPacket`.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): IP address to look for in
                the list of packets.
            timeout (Integer, optional, default=`None`): Timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: If there is any packet available before the
                timeout expires. If timeout is `None`, the returned value may
                be `None`.

        Raises:
            TimeoutException: If timeout is not `None` and there is not any
                packet available that was sent by `ip_addr` before the timeout
                expires.
        """
        if timeout is None:
            with self.mutex:
                for packet in self.queue:
                    if self.__ip_addr_match(packet, ip_addr):
                        self.queue.remove(packet)
                        return packet
            return None

        packet = self.get_by_ip(ip_addr)
        dead_line = time.time() + timeout
        while packet is None and dead_line > time.time():
            time.sleep(0.1)
            packet = self.get_by_ip(ip_addr)
        if packet is None:
            raise TimeoutException()

        return packet

    def get_by_id(self, frame_id, timeout=None):
        """
        Returns the first packet from the queue whose frame ID matches the
        provided one.

        If timeout is `None`, this method is non-blocking. In this case, if
        there is not any received packet with the provided frame ID in the
        queue, it returns `None`, otherwise it returns an
        :class:`.XBeeAPIPacket`.

        Args:
            frame_id (Integer): Frame ID to look for in the list of packets.
            timeout (Integer, optional, default=`None`): Timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: If there is any packet available before
                the timeout expires. If timeout is `None`, the returned value
                may be `None`.

        Raises:
            TimeoutException: If timeout is not `None` and there is not any
                packet available that matches the provided frame ID before the
                timeout expires.
        """
        if timeout is None:
            with self.mutex:
                for packet in self.queue:
                    if packet.needs_id() and packet.frame_id == frame_id:
                        self.queue.remove(packet)
                        return packet
            return None

        packet = self.get_by_id(frame_id)
        dead_line = time.time() + timeout
        while packet is None and dead_line > time.time():
            time.sleep(0.1)
            packet = self.get_by_id(frame_id)
        if packet is None:
            raise TimeoutException()

        return packet

    def flush(self):
        """
        Clears the queue.
        """
        with self.mutex:
            self.queue.clear()

    @staticmethod
    def __remote_device_match(packet, remote):
        """
        Returns whether or not the source address of the provided XBee packet
        matches the address of the given remote XBee device.

        Args:
            packet (:class:`.XBeePacket`): XBee packet to get the address to compare.
            remote (:class:`.RemoteXBeeDevice`): Remote XBee to get the address
                to compare.

        Returns:
            Boolean: `True` if the remote device matches, `False` otherwise.
        """
        f_type = packet.get_frame_type()
        if f_type == ApiFrameType.RECEIVE_PACKET:
            if packet.x64bit_source_addr == remote.get_64bit_addr():
                return True
            return (remote.get_16bit_addr() != XBee16BitAddress.UNKNOWN_ADDRESS
                    and packet.x16bit_source_addr == remote.get_16bit_addr())

        if f_type == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE:
            if packet.x64bit_source_addr == remote.get_64bit_addr():
                return True
            return (remote.get_16bit_addr() != XBee16BitAddress.UNKNOWN_ADDRESS
                    and packet.x16bit_source_addr == remote.get_16bit_addr())

        if f_type == ApiFrameType.RX_16:
            return packet.x16bit_source_addr == remote.get_16bit_addr()

        if f_type == ApiFrameType.RX_64:
            return packet.x64bit_source_addr == remote.get_64bit_addr()

        if f_type == ApiFrameType.RX_IO_16:
            return packet.x16bit_source_addr == remote.get_16bit_addr()

        if f_type == ApiFrameType.RX_IO_64:
            return packet.x64bit_source_addr == remote.get_64bit_addr()

        if f_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
            return packet.x64bit_source_addr == remote.get_64bit_addr()

        return False

    @staticmethod
    def __ip_addr_match(packet, ip_addr):
        """
        Returns whether or not the IP address of the XBee packet matches the
        provided one.

        Args:
            packet (:class:`.XBeePacket`): XBee packet to get the address to compare.
            ip_addr (:class:`ipaddress.IPv4Address`): IP address to be compared
                with the XBee packet's one.

        Returns:
            Boolean: `True` if the IP address matches, `False` otherwise.
        """
        return (packet.get_frame_type() == ApiFrameType.RX_IPV4
                and packet.source_address == ip_addr)
