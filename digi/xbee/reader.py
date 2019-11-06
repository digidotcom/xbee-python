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

from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from threading import Event
import logging
import threading
import time

import digi.xbee.devices
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress
from digi.xbee.models.message import XBeeMessage, ExplicitXBeeMessage, IPMessage, \
    SMSMessage, UserDataRelayMessage
from digi.xbee.models.options import XBeeLocalInterface
from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.packets import factory
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ReceivePacket, IODataSampleRxIndicatorPacket
from digi.xbee.packets.raw import RX64Packet, RX16Packet
from digi.xbee.util import utils
from digi.xbee.exception import TimeoutException, InvalidPacketException
from digi.xbee.io import IOSample


# Maximum number of parallel callbacks.
MAX_PARALLEL_CALLBACKS = 50

executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_CALLBACKS)


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
        for f in self:
            future = executor.submit(f, *args, **kwargs)
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
            future (:class:`.Future`): Future associated to the execution of the callable.

        Raises:
            Exception: if the execution of the callable raised any exception.
        """
        if future.exception():
            raise future.exception()


class PacketReceived(XBeeEvent):
    """
    This event is fired when an XBee receives any packet, independent of
    its frame type.

    The callbacks for handle this events will receive the following arguments:
        1. received_packet (:class:`.XBeeAPIPacket`): the received packet.

    .. seealso::
       | :class:`.XBeeAPIPacket`
       | :class:`.XBeeEvent`
    """
    pass


class DataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.XBeeMessage`): message containing the data received, the sender and the time.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.XBeeMessage`
    """
    pass


class ModemStatusReceived(XBeeEvent):
    """
    This event is fired when a XBee receives a modem status packet.

    The callbacks for handle this events will receive the following arguments:
        1. modem_status (:class:`.ModemStatus`): the modem status received.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.ModemStatus`
    """
    pass


class IOSampleReceived(XBeeEvent):
    """
    This event is fired when a XBee receives an IO packet.

    This includes:

    1. IO data sample RX indicator packet.
    2. RX IO 16 packet.
    3. RX IO 64 packet.

    The callbacks that handle this event will receive the following arguments:
        1. io_sample (:class:`.IOSample`): the received IO sample.
        2. sender (:class:`.RemoteXBeeDevice`): the remote XBee device who has sent the packet.
        3. time (Integer): the time in which the packet was received.

    .. seealso::
       | :class:`.IOSample`
       | :class:`.RemoteXBeeDevice`
       | :class:`.XBeeEvent`
    """
    pass


class NetworkModified(XBeeEvent):
    """
    This event is fired when the network is being modified by the addition of a new node, an
    existing node information is updated, a node removal, or when the network items are cleared.

    The callbacks that handle this event will receive the following arguments:
        1. event_type (:class:`digi.xbee.devices.NetworkEventType`): the network event type.
        2. reason (:class:`digi.xbee.devices.NetworkEventReason`): The reason of the event.
        3. node (:class:`digi.xbee.devices.XBeeDevice` or
           :class:`digi.xbee.devices.RemoteXBeeDevice`): The node added, updated or removed from
           the network.

    .. seealso::
       | :class:`digi.xbee.devices.NetworkEventReason`
       | :class:`digi.xbee.devices.NetworkEventType`
       | :class:`digi.xbee.devices.RemoteXBeeDevice`
       | :class:`digi.xbee.devices.XBeeDevice`
       | :class:`.XBeeEvent`
    """
    pass


class DeviceDiscovered(XBeeEvent):
    """
    This event is fired when an XBee discovers another remote XBee
    during a discovering operation.

    The callbacks that handle this event will receive the following arguments:
        1. discovered_device (:class:`.RemoteXBeeDevice`): the discovered remote XBee device.

    .. seealso::
       | :class:`.RemoteXBeeDevice`
       | :class:`.XBeeEvent`
    """
    pass


class DiscoveryProcessFinished(XBeeEvent):
    """
    This event is fired when the discovery process finishes, either
    successfully or due to an error.

    The callbacks that handle this event will receive the following arguments:
        1. status (:class:`.NetworkDiscoveryStatus`): the network discovery status.

    .. seealso::
       | :class:`.NetworkDiscoveryStatus`
       | :class:`.XBeeEvent`
    """
    pass


class ExplicitDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives an explicit data packet.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.ExplicitXBeeMessage`): message containing the data received, the sender, the time
            and explicit data message parameters.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.XBeeMessage`
    """
    pass


class IPDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives IP data.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.IPMessage`): message containing containing the IP address the message
            belongs to, the source and destination ports, the IP protocol, and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.IPMessage`
    """
    pass


class SMSReceived(XBeeEvent):
    """
    This event is fired when an XBee receives an SMS.

    The callbacks for handle this events will receive the following arguments:
        1. message (:class:`.SMSMessage`): message containing the phone number that sent
            the message and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.SMSMessage`
    """
    pass


class RelayDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives a user data relay output packet.

    The callbacks to handle these events will receive the following arguments:
        1. message (:class:`.UserDataRelayMessage`): message containing the source interface
            and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeEvent`
       | :class:`.UserDataRelayMessage`
    """
    pass


class BluetoothDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data from the Bluetooth interface.

    The callbacks to handle these events will receive the following arguments:
        1. data (Bytearray): received Bluetooth data.

    .. seealso::
       | :class:`.XBeeEvent`
    """
    pass


class MicroPythonDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives data from the MicroPython interface.

    The callbacks to handle these events will receive the following arguments:
        1. data (Bytearray): received MicroPython data.

    .. seealso::
       | :class:`.XBeeEvent`
    """
    pass


class SocketStateReceived(XBeeEvent):
    """
    This event is fired when an XBee receives a socket state packet.

    The callbacks to handle these events will receive the following arguments:
        1. socket_id (Integer): socket ID for state reported.
        2. state (:class:`.SocketState`): received state.

    .. seealso::
       | :class:`.XBeeEvent`
    """
    pass


class SocketDataReceived(XBeeEvent):
    """
    This event is fired when an XBee receives a socket receive data packet.

    The callbacks to handle these events will receive the following arguments:
        1. socket_id (Integer): ID of the socket that received the data.
        2. payload (Bytearray): received data.

    .. seealso::
       | :class:`.XBeeEvent`
    """
    pass


class SocketDataReceivedFrom(XBeeEvent):
    """
    This event is fired when an XBee receives a socket receive from data packet.

    The callbacks to handle these events will receive the following arguments:
        1. socket_id (Integer): ID of the socket that received the data.
        2. address (Tuple): a pair (host, port) of the source address where
            host is a string representing an IPv4 address like '100.50.200.5',
            and port is an integer.
        3. payload (Bytearray): received data.

    .. seealso::
       | :class:`.XBeeEvent`
    """
    pass


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

    The following parameters are passed via \*\*kwargs to event callbacks of:

    1. PacketReceived:
        1.1 received_packet (:class:`.XBeeAPIPacket`): the received packet.
    2. DataReceived
        2.1 message (:class:`.XBeeMessage`): message containing the data received, the sender and the time.
    3. ModemStatusReceived
        3.1 modem_status (:class:`.ModemStatus`): the modem status received.
    """

    __DEFAULT_QUEUE_MAX_SIZE = 40
    """
    Default max. size that the queue has.
    """

    _LOG_PATTERN = "{comm_iface:<6s}{event:<12s}{fr_type:<10s}{sender:<18s}{more_data:<50s}"
    """
    Generic pattern for display received messages (high-level) with logger.
    """

    _log = logging.getLogger(__name__)
    """
    Logger.
    """

    def __init__(self, comm_iface, xbee_device, queue_max_size=None):
        """
        Class constructor. Instantiates a new :class:`.PacketListener` object with the provided parameters.

        Args:
            comm_iface (:class:`.XBeeCommunicationInterface`): the hardware interface to listen to.
            xbee_device (:class:`.XBeeDevice`): the XBee that is the listener owner.
            queue_max_size (Integer): the maximum size of the XBee queue.
        """
        threading.Thread.__init__(self)

        self.daemon = True

        # User callbacks:
        self.__packet_received = PacketReceived()
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

        # API internal callbacks:
        self.__packet_received_API = xbee_device.get_xbee_device_callbacks()

        self.__xbee_device = xbee_device
        self.__comm_iface = comm_iface
        self.__stop = True
        self.__started = Event()

        self.__queue_max_size = queue_max_size if queue_max_size is not None else self.__DEFAULT_QUEUE_MAX_SIZE
        self.__xbee_queue = XBeeQueue(self.__queue_max_size)
        self.__data_xbee_queue = XBeeQueue(self.__queue_max_size)
        self.__explicit_xbee_queue = XBeeQueue(self.__queue_max_size)
        self.__ip_xbee_queue = XBeeQueue(self.__queue_max_size)

    def wait_until_started(self, timeout=None):
        """
        Blocks until the thread has fully started. If already started, returns
        immediately.

        Args:
            timeout (Float): timeout for the operation in seconds.
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
                # Try to read a packet. Read packet is unescaped.
                raw_packet = self.__comm_iface.wait_for_frame(self.__xbee_device.operating_mode)

                if raw_packet is not None:
                    # If the current protocol is 802.15.4, the packet may have to be discarded.
                    if (self.__xbee_device.get_protocol() == XBeeProtocol.RAW_802_15_4 and
                       not self.__check_packet_802_15_4(raw_packet)):
                        continue

                    # Build the packet.
                    try:
                        read_packet = factory.build_frame(raw_packet, self.__xbee_device.operating_mode)
                    except InvalidPacketException as e:
                        self._log.error("Error processing packet '%s': %s" % (utils.hex_to_string(raw_packet), str(e)))
                        continue

                    self._log.debug(self.__xbee_device.LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                                          event="RECEIVED",
                                                                          opmode=self.__xbee_device.operating_mode,
                                                                          content=utils.hex_to_string(raw_packet)))

                    # Add the packet to the queue.
                    self.__add_packet_queue(read_packet)

                    # If the packet has information about a remote device, extract it
                    # and add/update this remote device to/in this XBee's network.
                    remote = self.__try_add_remote_device(read_packet)

                    # Execute API internal callbacks.
                    self.__packet_received_API(read_packet)

                    # Execute all user callbacks.
                    self.__execute_user_callbacks(read_packet, remote)
        except Exception as e:
            if not self.__stop:
                self._log.exception(e)
        finally:
            if not self.__stop:
                self.__stop = True
                if self.__comm_iface.is_interface_open:
                    self.__comm_iface.close()

    def stop(self):
        """
        Stops listening.
        """
        self.__comm_iface.quit_reading()
        self.__stop = True
        # Wait until thread fully stops.
        self.join()

    def is_running(self):
        """
        Returns whether this instance is running or not.

        Returns:
            Boolean: ``True`` if this instance is running, ``False`` otherwise.
        """
        return not self.__stop

    def get_queue(self):
        """
        Returns the packets queue.

        Returns:
            :class:`.XBeeQueue`: the packets queue.
        """
        return self.__xbee_queue

    def get_data_queue(self):
        """
        Returns the data packets queue.

        Returns:
            :class:`.XBeeQueue`: the data packets queue.
        """
        return self.__data_xbee_queue

    def get_explicit_queue(self):
        """
        Returns the explicit packets queue.

        Returns:
            :class:`.XBeeQueue`: the explicit packets queue.
        """
        return self.__explicit_xbee_queue

    def get_ip_queue(self):
        """
        Returns the IP packets queue.

        Returns:
            :class:`.XBeeQueue`: the IP packets queue.
        """
        return self.__ip_xbee_queue

    def add_packet_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.PacketReceived`.

        Args:
            callback (Function or List of functions): the callback. Receives two arguments.

                * The received packet as a :class:`.XBeeAPIPacket`
        """
        if isinstance(callback, list):
            self.__packet_received.extend(callback)
        elif callback:
            self.__packet_received += callback

    def add_data_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.DataReceived`.

        Args:
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives three arguments.

                * The received IO sample as an :class:`.IOSample`
                * The remote XBee device who has sent the packet as a :class:`.RemoteXBeeDevice`
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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives one argument.

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
            callback (Function or List of functions): the callback. Receives two arguments.

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
            callback (Function or List of functions): the callback. Receives two arguments.

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
            callback (Function or List of functions): the callback. Receives three arguments.

                * The socket ID as an Integer.
                * A pair (host, port) of the source address where host is a string representing an IPv4 address
                    like '100.50.200.5', and port is an integer.
                * The status received as a :class:`.SocketStatus`
        """
        if isinstance(callback, list):
            self.__socket_data_received_from.extend(callback)
        elif callback:
            self.__socket_data_received_from += callback

    def del_packet_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.PacketReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.PacketReceived` event.
        """
        self.__packet_received -= callback

    def del_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.DataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.DataReceived` event.
        """
        self.__data_received -= callback

    def del_modem_status_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.ModemStatusReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.ModemStatusReceived` event.
        """
        self.__modem_status_received -= callback

    def del_io_sample_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.IOSampleReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.IOSampleReceived` event.
        """
        self.__io_sample_received -= callback

    def del_explicit_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.ExplicitDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.ExplicitDataReceived` event.
        """
        self.__explicit_packet_received -= callback

    def del_ip_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.IPDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.IPDataReceived`
                event.
        """
        self.__ip_data_received -= callback

    def del_sms_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SMSReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of :class:`.SMSReceived` event.
        """
        self.__sms_received -= callback

    def del_user_data_relay_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.RelayDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.RelayDataReceived` event.
        """
        self.__relay_data_received -= callback

    def del_bluetooth_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.BluetoothDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.BluetoothDataReceived` event.
        """
        self.__bluetooth_data_received -= callback

    def del_micropython_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.MicroPythonDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.MicroPythonDataReceived` event.
        """
        self.__micropython_data_received -= callback

    def del_socket_state_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SocketStateReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.SocketStateReceived` event.
        """
        self.__socket_state_received -= callback

    def del_socket_data_received_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SocketDataReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.SocketDataReceived` event.
        """
        self.__socket_data_received -= callback

    def del_socket_data_received_from_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`.SocketDataReceivedFrom` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`.SocketDataReceivedFrom` event.
        """
        self.__socket_data_received_from -= callback

    def get_packet_received_callbacks(self):
        """
        Returns the list of registered callbacks for received packets.

        Returns:
            List: List of :class:`.PacketReceived` events.
        """
        return self.__packet_received

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
        Returns the list of registered callbacks for received micropython data.

        Returns:
            List: List of :class:`.MicroPythonDataReceived` events.
        """
        return self.__micropython_data_received

    def __execute_user_callbacks(self, xbee_packet, remote=None):
        """
        Executes callbacks corresponding to the received packet.

        Args:
            xbee_packet (:class:`.XBeeAPIPacket`): the received packet.
            remote (:class:`.RemoteXBeeDevice`): the XBee device that sent the packet.
        """
        # All packets callback.
        self.__packet_received(xbee_packet)

        # Data reception callbacks
        if (xbee_packet.get_frame_type() == ApiFrameType.RX_64 or
                xbee_packet.get_frame_type() == ApiFrameType.RX_16 or
                xbee_packet.get_frame_type() == ApiFrameType.RECEIVE_PACKET):
            data = xbee_packet.rf_data
            is_broadcast = xbee_packet.is_broadcast()
            self.__data_received(XBeeMessage(data, remote, time.time(), broadcast=is_broadcast))
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="DATA",
                                                    sender=str(remote.get_64bit_addr()) if remote is not None
                                                    else "None",
                                                    more_data=utils.hex_to_string(data)))

        # Modem status callbacks
        elif xbee_packet.get_frame_type() == ApiFrameType.MODEM_STATUS:
            self.__modem_status_received(xbee_packet.modem_status)
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="MODEM STATUS",
                                                    sender=str(remote.get_64bit_addr()) if remote is not None
                                                    else "None",
                                                    more_data=xbee_packet.modem_status))

        # IO_sample callbacks
        elif (xbee_packet.get_frame_type() == ApiFrameType.RX_IO_16 or
              xbee_packet.get_frame_type() == ApiFrameType.RX_IO_64 or
              xbee_packet.get_frame_type() == ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR):
            self.__io_sample_received(xbee_packet.io_sample, remote, time.time())
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="IOSAMPLE",
                                                    sender=str(remote.get_64bit_addr()) if remote is not None
                                                    else "None",
                                                    more_data=str(xbee_packet.io_sample)))

        # Explicit packet callbacks
        elif xbee_packet.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR:
            data = xbee_packet.rf_data
            is_broadcast = xbee_packet.is_broadcast()
            # If it's 'special' packet, notify the data_received callbacks too:
            if self.__is_explicit_data_packet(xbee_packet):
                self.__data_received(XBeeMessage(data, remote, time.time(), broadcast=is_broadcast))
            elif self.__is_explicit_io_packet(xbee_packet):
                self.__io_sample_received(IOSample(data), remote, time.time())
            self.__explicit_packet_received(PacketListener.__expl_to_message(remote, is_broadcast, xbee_packet))
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="EXPLICIT DATA",
                                                    sender=str(remote.get_64bit_addr()) if remote is not None
                                                    else "None",
                                                    more_data=utils.hex_to_string(data)))

        # IP data
        elif xbee_packet.get_frame_type() == ApiFrameType.RX_IPV4:
            self.__ip_data_received(
                IPMessage(xbee_packet.source_address, xbee_packet.source_port,
                          xbee_packet.dest_port, xbee_packet.ip_protocol, xbee_packet.data))
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="IP DATA",
                                                    sender=str(xbee_packet.source_address),
                                                    more_data=utils.hex_to_string(xbee_packet.data)))

        # SMS
        elif xbee_packet.get_frame_type() == ApiFrameType.RX_SMS:
            self.__sms_received(SMSMessage(xbee_packet.phone_number, xbee_packet.data))
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="SMS",
                                                    sender=str(xbee_packet.phone_number),
                                                    more_data=xbee_packet.data))

        # Relay
        elif xbee_packet.get_frame_type() == ApiFrameType.USER_DATA_RELAY_OUTPUT:
            # Notify generic callbacks.
            self.__relay_data_received(UserDataRelayMessage(xbee_packet.src_interface, xbee_packet.data))
            # Notify specific callbacks.
            if xbee_packet.src_interface == XBeeLocalInterface.BLUETOOTH:
                self.__bluetooth_data_received(xbee_packet.data)
            elif xbee_packet.src_interface == XBeeLocalInterface.MICROPYTHON:
                self.__micropython_data_received(xbee_packet.data)
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="RELAY DATA",
                                                    sender=xbee_packet.src_interface.description,
                                                    more_data=utils.hex_to_string(xbee_packet.data)))

        # Socket state
        elif xbee_packet.get_frame_type() == ApiFrameType.SOCKET_STATE:
            self.__socket_state_received(xbee_packet.socket_id, xbee_packet.state)
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="SOCKET STATE",
                                                    sender=str(xbee_packet.socket_id),
                                                    more_data=xbee_packet.state))

        # Socket receive data
        elif xbee_packet.get_frame_type() == ApiFrameType.SOCKET_RECEIVE:
            self.__socket_data_received(xbee_packet.socket_id, xbee_packet.payload)
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="SOCKET DATA",
                                                    sender=str(xbee_packet.socket_id),
                                                    more_data=utils.hex_to_string(xbee_packet.payload)))

        # Socket receive data from
        elif xbee_packet.get_frame_type() == ApiFrameType.SOCKET_RECEIVE_FROM:
            address = (str(xbee_packet.source_address), xbee_packet.source_port)
            self.__socket_data_received_from(xbee_packet.socket_id, address, xbee_packet.payload)
            self._log.info(self._LOG_PATTERN.format(comm_iface=str(self.__xbee_device.comm_iface),
                                                    event="RECEIVED",
                                                    fr_type="SOCKET DATA",
                                                    sender=str(xbee_packet.socket_id),
                                                    more_data="%s - %s" % (address,
                                                                           utils.hex_to_string(xbee_packet.payload))))

    def __create_remote_device_from_packet(self, xbee_packet):
        """
        Creates a :class:`.RemoteXBeeDevice` that represents the device that
        has sent the ``xbee_packet``.

        Returns:
            :class:`.RemoteXBeeDevice`
        """
        x64bit_addr, x16bit_addr = self.__get_remote_device_data_from_packet(xbee_packet)
        return digi.xbee.devices.RemoteXBeeDevice(self.__xbee_device, x64bit_addr=x64bit_addr,
                                                  x16bit_addr=x16bit_addr)

    @staticmethod
    def __get_remote_device_data_from_packet(xbee_packet):
        """
        Extracts the 64 bit-address and the 16 bit-address from ``xbee_packet`` if is
        possible.
        """
        x64bit_addr = None
        x16bit_addr = None
        if hasattr(xbee_packet, "x64bit_source_addr"):
            x64bit_addr = xbee_packet.x64bit_source_addr
        if hasattr(xbee_packet, "x16bit_source_addr"):
            x16bit_addr = xbee_packet.x16bit_source_addr
        return x64bit_addr, x16bit_addr

    @staticmethod
    def __check_packet_802_15_4(raw_data):
        """
        If the current XBee's protocol is 802.15.4 and
        the user sends many 'ND' commands, the device could return
        an RX 64 IO packet with an invalid payload (length < 5).

        In this case the packet must be discarded, or an exception
        must be raised.

        This method checks a received raw_data and returns False if
        the packet mustn't be processed.

        Args:
            raw_data (Bytearray): received data.

        Returns:
            Boolean: ``True`` if the packet must be processed, ``False`` otherwise.
        """
        if raw_data[3] == ApiFrameType.RX_IO_64 and len(raw_data[14:-1]) < IOSample.min_io_sample_payload():
            return False
        return True

    def __try_add_remote_device(self, xbee_packet):
        """
        If the packet has information about a remote device, this method
        extracts that information from the packet, creates a remote device, and
        adds it (if not exist yet) to the network.

        Returns:
            :class:`.RemoteXBeeDevice`: the remote device extracted from the packet, `None`` if the packet has
                not information about a remote device.
        """
        remote = None
        x64, x16 = self.__get_remote_device_data_from_packet(xbee_packet)
        if x64 is not None or x16 is not None:
            remote = self.__xbee_device.get_network()._XBeeNetwork__add_remote_from_attr(
                digi.xbee.devices.NetworkEventReason.RECEIVED_MSG, x64bit_addr=x64, x16bit_addr=x16)
        return remote

    @staticmethod
    def __is_explicit_data_packet(xbee_packet):
        """
        Checks if the provided explicit data packet is directed to the data cluster.

        This means that this XBee has its API Output Mode distinct than Native (it's expecting
        explicit data packets), but some device has sent it a non-explicit data packet
        (TransmitRequest f.e.).
        In this case, this XBee will receive a explicit data packet with the following values:

            1. Source endpoint = 0xE8
            2. Destination endpoint = 0xE8
            3. Cluster ID = 0x0011
            4. Profile ID = 0xC105
        """
        return (xbee_packet.source_endpoint == 0xE8 and xbee_packet.dest_endpoint == 0xE8
                and xbee_packet.cluster_id == 0x0011 and xbee_packet.profile_id == 0xC105)

    @staticmethod
    def __is_explicit_io_packet(xbee_packet):
        """
        Checks if the provided explicit data packet is directed to the IO cluster.

        This means that this XBee has its API Output Mode distinct than Native (it's expecting
        explicit data packets), but some device has sent an IO sample packet
        (IODataSampleRxIndicatorPacket f.e.).
        In this case, this XBee will receive a explicit data packet with the following values:

            1. Source endpoint = 0xE8
            2. Destination endpoint = 0xE8
            3. Cluster ID = 0x0092
            4. Profile ID = 0xC105
        """
        return (xbee_packet.source_endpoint == 0xE8 and xbee_packet.dest_endpoint == 0xE8
                and xbee_packet.cluster_id == 0x0092 and xbee_packet.profile_id == 0xC105)

    def __expl_to_no_expl(self, xbee_packet):
        """
        Creates a non-explicit data packet from the given explicit packet depending on
        this listener's XBee device protocol.

        Returns:
            :class:`.XBeeAPIPacket`: the proper receive packet depending on the current protocol and
                the available information (inside the packet).
        """
        x64addr = xbee_packet.x64bit_source_addr
        x16addr = xbee_packet.x16bit_source_addr
        if self.__xbee_device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            if x64addr != XBee64BitAddress.UNKNOWN_ADDRESS:
                new_pkt = RX64Packet(x64addr, 0, xbee_packet.receive_options, rf_data=xbee_packet.rf_data)
            elif x16addr != XBee16BitAddress.UNKNOWN_ADDRESS:
                new_pkt = RX16Packet(x16addr, 0, xbee_packet.receive_options, rf_data=xbee_packet.rf_data)
            else:  # both address UNKNOWN
                new_pkt = RX64Packet(x64addr, 0, xbee_packet.receive_options, rf_data=xbee_packet.rf_data)
        else:
            new_pkt = ReceivePacket(x64addr, x16addr, xbee_packet.receive_options,
                                    rf_data=xbee_packet.rf_data)
        return new_pkt

    def __expl_to_io(self, xbee_packet):
        """
        Creates a IO packet from the given explicit packet depending on this listener's XBee device
        protocol.

        Returns:
            :class:`.XBeeAPIPacket`: the proper receive packet depending on the current protocol and
                the available information (inside the packet).
        """
        return IODataSampleRxIndicatorPacket(xbee_packet.x64bit_source_addr,
                                             xbee_packet.x16bit_source_addr,
                                             xbee_packet.receive_options, rf_data=xbee_packet.rf_data)

    def __add_packet_queue(self, xbee_packet):
        """
        Adds a packet to the queue. If the queue is full,
        the first packet of the queue is removed and the given
        packet is added.

        Args:
            xbee_packet (:class:`.XBeeAPIPacket`): the packet to be added.
        """
        # Data packets.
        if xbee_packet.get_frame_type() in [ApiFrameType.RECEIVE_PACKET, ApiFrameType.RX_64, ApiFrameType.RX_16]:
            if self.__data_xbee_queue.full():
                self.__data_xbee_queue.get()
            self.__data_xbee_queue.put_nowait(xbee_packet)
        # Explicit packets.
        if xbee_packet.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR:
            if self.__explicit_xbee_queue.full():
                self.__explicit_xbee_queue.get()
            self.__explicit_xbee_queue.put_nowait(xbee_packet)
            # Check if the explicit packet is 'special'.
            if self.__is_explicit_data_packet(xbee_packet):
                # Create the non-explicit version of this packet and add it to the queue.
                self.__add_packet_queue(self.__expl_to_no_expl(xbee_packet))
            elif self.__is_explicit_io_packet(xbee_packet):
                # Create the IO packet corresponding to this packet and add it to the queue.
                self.__add_packet_queue(self.__expl_to_io(xbee_packet))
        # IP packets.
        elif xbee_packet.get_frame_type() == ApiFrameType.RX_IPV4:
            if self.__ip_xbee_queue.full():
                self.__ip_xbee_queue.get()
            self.__ip_xbee_queue.put_nowait(xbee_packet)
        # Rest of packets.
        else:
            if self.__xbee_queue.full():
                self.__xbee_queue.get()
            self.__xbee_queue.put_nowait(xbee_packet)

    @staticmethod
    def __expl_to_message(remote, broadcast, xbee_packet):
        """
        Converts an explicit packet in an explicit message.

        Args:
            remote (:class:`.RemoteXBeeDevice`): the remote XBee device that sent the packet.
            broadcast (Boolean, optional, default=``False``): flag indicating whether the message is
                broadcast (``True``) or not (``False``). Optional.
            xbee_packet (:class:`.XBeeAPIPacket`): the packet to be converted.

        Returns:
            :class:`.ExplicitXBeeMessage`: the explicit message generated from the provided parameters.
        """
        return ExplicitXBeeMessage(xbee_packet.rf_data, remote, time.time(), xbee_packet.source_endpoint,
                                   xbee_packet.dest_endpoint, xbee_packet.cluster_id,
                                   xbee_packet.profile_id, broadcast=broadcast)


class XBeeQueue(Queue):
    """
    This class represents an XBee queue.
    """

    def __init__(self, maxsize=10):
        """
        Class constructor. Instantiates a new :class:`.XBeeQueue` with the provided parameters.

        Args:
            maxsize (Integer, default: 10) the maximum size of the queue.
        """
        Queue.__init__(self, maxsize)

    def get(self, block=True, timeout=None):
        """
        Returns the first element of the queue if there is some
        element ready before timeout expires, in case of the timeout is not
        ``None``.

        If timeout is ``None``, this method is non-blocking. In this case, if there
        isn't any element available, it returns ``None``, otherwise it returns
        an :class:`.XBeeAPIPacket`.

        Args:
            block (Boolean): ``True`` to block during ``timeout`` waiting for a packet, ``False`` to not block.
            timeout (Integer, optional): timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: a packet if there is any packet available before ``timeout`` expires.
                If ``timeout`` is ``None``, the returned value may be ``None``.

        Raises:
            TimeoutException: if ``timeout`` is not ``None`` and there isn't any packet available
                before the timeout expires.
        """
        if timeout is None:
            try:
                xbee_packet = Queue.get(self, block=False)
            except (Empty, ValueError):
                xbee_packet = None
            return xbee_packet
        else:
            try:
                return Queue.get(self, True, timeout)
            except Empty:
                raise TimeoutException()

    def get_by_remote(self, remote_xbee_device, timeout=None):
        """
        Returns the first element of the queue that had been sent
        by ``remote_xbee_device``, if there is some in the specified timeout.

        If timeout is ``None``, this method is non-blocking. In this case, if there isn't
        any packet sent by ``remote_xbee_device`` in the queue, it returns ``None``,
        otherwise it returns an :class:`.XBeeAPIPacket`.

        Args:
            remote_xbee_device (:class:`.RemoteXBeeDevice`): the remote XBee device to get its firs element from queue.
            timeout (Integer, optional): timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: if there is any packet available before the timeout expires. If timeout is
                ``None``, the returned value may be ``None``.

        Raises:
            TimeoutException: if timeout is not ``None`` and there isn't any packet available that has
                been sent by ``remote_xbee_device`` before the timeout expires.
        """
        if timeout is None:
            with self.mutex:
                for xbee_packet in self.queue:
                    if self.__remote_device_match(xbee_packet, remote_xbee_device):
                        self.queue.remove(xbee_packet)
                        return xbee_packet
            return None
        else:
            xbee_packet = self.get_by_remote(remote_xbee_device)
            dead_line = time.time() + timeout
            while xbee_packet is None and dead_line > time.time():
                time.sleep(0.1)
                xbee_packet = self.get_by_remote(remote_xbee_device)
            if xbee_packet is None:
                raise TimeoutException()
            return xbee_packet

    def get_by_ip(self, ip_addr, timeout=None):
        """
        Returns the first IP data packet from the queue whose IP address
        matches the provided address.

        If timeout is ``None``, this method is non-blocking. In this case, if there isn't
        any packet sent by ``remote_xbee_device`` in the queue, it returns ``None``,
        otherwise it returns an :class:`.XBeeAPIPacket`.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to look for in the list of packets.
            timeout (Integer, optional): Timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: if there is any packet available before the timeout expires. If timeout is
                ``None``, the returned value may be ``None``.

        Raises:
            TimeoutException: if timeout is not ``None`` and there isn't any packet available that has
                been sent by ``remote_xbee_device`` before the timeout expires.
        """
        if timeout is None:
            with self.mutex:
                for xbee_packet in self.queue:
                    if self.__ip_addr_match(xbee_packet, ip_addr):
                        self.queue.remove(xbee_packet)
                        return xbee_packet
            return None
        else:
            xbee_packet = self.get_by_ip(ip_addr)
            dead_line = time.time() + timeout
            while xbee_packet is None and dead_line > time.time():
                time.sleep(0.1)
                xbee_packet = self.get_by_ip(ip_addr)
            if xbee_packet is None:
                raise TimeoutException()
            return xbee_packet

    def get_by_id(self, frame_id, timeout=None):
        """
        Returns the first packet from the queue whose frame ID
        matches the provided one.

        If timeout is ``None``, this method is non-blocking. In this case, if there isn't
        any received packet with the provided frame ID in the queue, it returns ``None``,
        otherwise it returns an :class:`.XBeeAPIPacket`.

        Args:
            frame_id (Integer): The frame ID to look for in the list of packets.
            timeout (Integer, optional): Timeout in seconds.

        Returns:
            :class:`.XBeeAPIPacket`: if there is any packet available before the timeout expires. If timeout is
                ``None``, the returned value may be ``None``.

        Raises:
            TimeoutException: if timeout is not ``None`` and there isn't any packet available that matches
            the provided frame ID before the timeout expires.
        """
        if timeout is None:
            with self.mutex:
                for xbee_packet in self.queue:
                    if xbee_packet.needs_id() and xbee_packet.frame_id == frame_id:
                        self.queue.remove(xbee_packet)
                        return xbee_packet
            return None
        else:
            xbee_packet = self.get_by_id(frame_id)
            dead_line = time.time() + timeout
            while xbee_packet is None and dead_line > time.time():
                time.sleep(0.1)
                xbee_packet = self.get_by_id(frame_id)
            if xbee_packet is None:
                raise TimeoutException()
            return xbee_packet

    def flush(self):
        """
        Clears the queue.
        """
        with self.mutex:
            self.queue.clear()

    @staticmethod
    def __remote_device_match(xbee_packet, remote_xbee_device):
        """
        Returns whether or not the source address of the provided XBee packet
        matches the address of the given remote XBee device.

        Args:
            xbee_packet (:class:`.XBeePacket`): The XBee packet to get the address to compare.
            remote_xbee_device (:class:`.RemoteXBeeDevice`): The remote XBee device to get the address to compare.

        Returns:
            Boolean: ``True`` if the remote device matches, ``False`` otherwise.
        """
        if xbee_packet.get_frame_type() == ApiFrameType.RECEIVE_PACKET:
            if xbee_packet.x64bit_source_addr == remote_xbee_device.get_64bit_addr():
                return True
            return xbee_packet.x16bit_source_addr == remote_xbee_device.get_16bit_addr()

        elif xbee_packet.get_frame_type() == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE:
            if xbee_packet.x64bit_source_addr == remote_xbee_device.get_64bit_addr():
                return True
            return xbee_packet.x16bit_source_addr == remote_xbee_device.get_16bit_addr()

        elif xbee_packet.get_frame_type() == ApiFrameType.RX_16:
            return xbee_packet.x16bit_source_addr == remote_xbee_device.get_16bit_addr()

        elif xbee_packet.get_frame_type() == ApiFrameType.RX_64:
            return xbee_packet.x64bit_source_addr == remote_xbee_device.get_64bit_addr()

        elif xbee_packet.get_frame_type() == ApiFrameType.RX_IO_16:
            return xbee_packet.x16bit_source_addr == remote_xbee_device.get_16bit_addr()

        elif xbee_packet.get_frame_type() == ApiFrameType.RX_IO_64:
            return xbee_packet.x64bit_source_addr == remote_xbee_device.get_64bit_addr()

        elif xbee_packet.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR:
            return xbee_packet.x64bit_source_addr == remote_xbee_device.get_64bit_addr()

        else:
            return False

    @staticmethod
    def __ip_addr_match(xbee_packet, ip_addr):
        """
        Returns whether or not the IP address of the XBee packet matches the
        provided one.

        Args:
            xbee_packet (:class:`.XBeePacket`): The XBee packet to get the address to compare.
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address to be compared with the XBee packet's one.

        Returns:
            Boolean: ``True`` if the IP address matches, ``False`` otherwise.
        """
        return xbee_packet.get_frame_type() == ApiFrameType.RX_IPV4 and xbee_packet.source_address == ip_addr
