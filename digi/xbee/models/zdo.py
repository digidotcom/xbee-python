# Copyright 2019-2021, Digi International Inc.
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
import threading
from abc import abstractmethod, ABCMeta
import logging
from enum import Enum

from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice, RemoteZigBeeDevice, RemoteDigiMeshDevice
from digi.xbee.exception import XBeeException, OperationNotSupportedException
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.mode import APIOutputModeBit
from digi.xbee.models.options import TransmitOptions
from digi.xbee.models.protocol import Role, XBeeProtocol
from digi.xbee.models.status import TransmitStatus, ATCommandStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ExplicitAddressingPacket, RemoteATCommandPacket, ATCommPacket
from digi.xbee.util import utils


class _ZDOCommand(metaclass=ABCMeta):
    """
    This class represents a ZDO command.
    """

    SOURCE_ENDPOINT = 0x00
    DEST_ENDPOINT = 0x00
    PROFILE_ID = 0x0000

    STATUS_SUCCESS = 0x00

    _global_transaction_id = 1

    _logger = logging.getLogger(__name__)

    def __init__(self, xbee, cluster_id, rx_cluster_id, configure_ao, timeout):
        """
        Class constructor. Instantiates a new :class:`._ZDOCommand` object
        with the provided parameters.

        Args:
            xbee (class:`.XBeeDevice` or class:`.RemoteXBeeDevice`): XBee to
                send the ZDO command.
            cluster_id (Integer): The ZDO command cluster ID.
            rx_cluster_id (Integer): The ZDO command receive cluster ID.
            configure_ao (Boolean): `True` to configure AO value before and
                after executing this ZDO command, `False` otherwise.
            timeout(Float): The ZDO command timeout in seconds.

        Raises:
            OperationNotSupportedException: If ZDO commands are not supported
                in the XBee protocol.
            TypeError: If the `xbee` is not a `.XBeeDevice` or a
                `.RemoteXBeeDevice`.
            ValueError: If `xbee` is `None`.
            ValueError: If `cluster_id`, `receive_cluster_id`, or `timeout` are
                less than 0.
        """
        if not xbee:
            raise ValueError("XBee cannot be None")
        if isinstance(xbee, (XBeeDevice, RemoteXBeeDevice)):
            self._xbee = xbee
        else:
            raise TypeError("The xbee must be an XBeeDevice or a RemoteXBeeDevice"
                            "not {!r}".format(xbee.__class__.__name__))
        if xbee.get_protocol() not in [XBeeProtocol.ZIGBEE, XBeeProtocol.SMART_ENERGY]:
            raise OperationNotSupportedException(
                message="ZDO commands are not supported in %s"
                % xbee.get_protocol().description)
        if cluster_id < 0:
            raise ValueError("Cluster id cannot be negative")
        if rx_cluster_id < 0:
            raise ValueError("Receive cluster id cannot be negative")
        if timeout < 0:
            raise ValueError("Timeout cannot be negative")

        self.__cluster_id = cluster_id
        self.__rx_cluster_id = rx_cluster_id
        self.__configure_ao = configure_ao
        self.__timeout = timeout

        self.__saved_ao = None
        self._running = False
        self._error = None
        self.__zdo_thread = None
        self._lock = threading.Event()
        self._received_status = False
        self._received_answer = False
        self._data_parsed = False

        self._current_transaction_id = self.__class__._global_transaction_id
        self.__class__._global_transaction_id = self.__class__._global_transaction_id + 1
        if self.__class__._global_transaction_id == 0xFF:
            self.__class__._global_transaction_id = 1

    @property
    def running(self):
        """
        Returns if this ZDO command is running.

        Returns:
            Boolean: `True` if it is running, `False` otherwise.
        """
        return self._running

    @property
    def error(self):
        """
        Returns the error string if any.

        Returns:
             String: The error string.
        """
        return self._error

    def stop(self):
        """
        Stops the ZDO command process if it is running.
        """
        if not self._lock.is_set():
            self._lock.set()

        if self.__zdo_thread and self._running:
            self.__zdo_thread.join()
            self.__zdo_thread = None

    def _start_process(self, sync=True, zdo_cb=None):
        """
        Starts the ZDO command process. It can be a blocking method depending
        on `sync`.

        Args:
            sync (Boolean): `True` for a blocking method, `False` to run
                asynchronously in a separate thread.
            zdo_cb (Function, optional): Method to execute when ZDO process
                finishes. Receives two arguments:
                * The XBee that executed the ZDO command.
                * An error message if something went wrong.
        """
        if not sync:
            self.__zdo_thread = threading.Thread(target=self._send_zdo,
                                                 kwargs={'zdo_cb': zdo_cb}, daemon=True)
            self.__zdo_thread.start()
        else:
            self._send_zdo(zdo_cb=zdo_cb)

    def _send_zdo(self, zdo_cb=None):
        """
        Sends the ZDO command.

        Args:
            zdo_cb (Function, optional): method to execute when ZDO process
                finishes. Receives two arguments:
                * The XBee that executed the ZDO command.
                * An error message if something went wrong.
        """
        self._running = True
        self._error = None
        self._received_status = False
        self._received_answer = False
        self._data_parsed = False
        self._lock.clear()

        if not self._xbee.is_remote():
            node = self._xbee
        else:
            node = self._xbee.get_local_xbee_device()

        node.add_packet_received_callback(self._zdo_packet_cb)

        self._init_variables()

        try:
            self.__prepare_device()

            node.send_packet(self._generate_zdo_packet())

            self._lock.wait(self.__timeout)

            if not self._received_status:
                if not self._error:
                    self._error = "ZDO command not sent"
                return

            if not self._received_answer:
                if not self._error:
                    self._error = "ZDO command answer not received"
                return

            self._perform_finish_actions()
        except XBeeException as exc:
            self._error = "Error sending ZDO command: " + str(exc)
        finally:
            node.del_packet_received_callback(self._zdo_packet_cb)
            self.__restore_device()
            self._notify_process_finished(zdo_cb)
            self._running = False

    @abstractmethod
    def _init_variables(self):
        """
        Initializes the ZDO command process variables.
        """

    @abstractmethod
    def _is_broadcast(self):
        """
        Retrieves whether the ZDO is broadcast.

        Returns:
            Boolean: `True` for broadcasting this ZDO, `False` otherwise.
        """

    @abstractmethod
    def _get_zdo_command_data(self):
        """
        Retrieves the ZDO packet data to be sent.

        Returns:
            Bytearray: The packet data.
        """

    @abstractmethod
    def _parse_data(self, data):
        """
        Handles what to do with the received data of the explicit frame. The
        status byte is already consumed.

        Args:
            data (bytearray): Byte array containing the frame data.

        Returns:
            Boolean: `True` if the process finishes, `False` otherwise.
        """

    @abstractmethod
    def _perform_finish_actions(self):
        """
        Performs final actions when the ZDO process has finished successfully.
        """

    def _notify_process_finished(self, zdo_cb):
        """
        Notifies that the ZDO process has finished its execution.

        Args:
            zdo_cb (Function, optional): Method to execute when ZDO process
                finishes. Receives two arguments:
                * The XBee that executed the ZDO command.
                * An error message if something went wrong.
        """
        if zdo_cb:
            zdo_cb(self._xbee, self._error)

    def __prepare_device(self):
        """
        Performs the local XBee configuration before sending the ZDO command.
        This saves the current AO value and sets it to 1.
        """
        if not self.__configure_ao:
            return

        if not self._xbee.is_remote():
            node = self._xbee
        else:
            node = self._xbee.get_local_xbee_device()

        try:
            self.__saved_ao = node.get_api_output_mode_value()

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

            node.set_parameter(ATStringCommand.AO, value, apply=True)

        except XBeeException as exc:
            raise XBeeException("Could not prepare XBee for ZDO: " + str(exc)) from exc

    def __restore_device(self):
        """
        Performs XBee configuration after sending the ZDO command.
        This restores the previous AO value.
        """
        if not self.__configure_ao or self.__saved_ao is None:
            return

        if not self._xbee.is_remote():
            node = self._xbee
        else:
            node = self._xbee.get_local_xbee_device()

        try:
            node.set_parameter(ATStringCommand.AO, self.__saved_ao, apply=True)
        except XBeeException as exc:
            self._error = "Could not restore XBee after ZDO: " + str(exc)

    def _generate_zdo_packet(self):
        """
        Generates the ZDO packet.

        Returns:
             :class:`.ExplicitAddressingPacket`: The packet to send.
        """
        if self._is_broadcast():
            addr64 = XBee64BitAddress.BROADCAST_ADDRESS
            addr16 = XBee16BitAddress.BROADCAST_ADDRESS
        else:
            addr64 = self._xbee.get_64bit_addr()
            addr16 = self._xbee.get_16bit_addr()

        return ExplicitAddressingPacket(
            self._current_transaction_id, addr64, addr16, self.SOURCE_ENDPOINT,
            self.DEST_ENDPOINT, self.__cluster_id, self.PROFILE_ID,
            broadcast_radius=0, transmit_options=TransmitOptions.NONE.value,
            rf_data=self._get_zdo_command_data())

    def _zdo_packet_cb(self, frame):
        """
        Callback notified when a new frame is received.

        Args:
            frame (:class:`.XBeeAPIPacket`): The received packet.
        """
        if not self._running:
            return

        if frame.get_frame_type() == ApiFrameType.EXPLICIT_RX_INDICATOR:
            # Check address
            x64 = self._xbee.get_64bit_addr()
            x16 = self._xbee.get_16bit_addr()
            if (not self._is_broadcast()
                    and x64 != XBee64BitAddress.UNKNOWN_ADDRESS
                    and x64 != frame.x64bit_source_addr
                    and x16 != XBee16BitAddress.UNKNOWN_ADDRESS
                    and x16 != frame.x16bit_source_addr):
                return
            # Check:
            #    * Profile, Cluster ID and endpoints.
            #    * If transaction ID matches, if not discard: not the frame we
            #      are waiting for.
            if (frame.profile_id != self.PROFILE_ID
                    or frame.cluster_id != self.__rx_cluster_id
                    or frame.source_endpoint != self.SOURCE_ENDPOINT
                    or frame.dest_endpoint != self.DEST_ENDPOINT
                    or frame.rf_data[0] != self._current_transaction_id):
                return
            self._received_answer = True
            # Status byte
            if frame.rf_data[1] != self.STATUS_SUCCESS:
                self._error = "Error executing ZDO command (status: %d)" % int(frame.rf_data[1])
                self.stop()
                return

            self._data_parsed = self._parse_data(frame.rf_data[2:])

            if self._data_parsed and self._received_status:
                self.stop()
        elif frame.get_frame_type() == ApiFrameType.TRANSMIT_STATUS:
            self._logger.debug("Received 'ZDO' status frame: %s",
                               frame.transmit_status.description)
            # If transaction ID does not match, discard: not the frame we are waiting for.
            if frame.frame_id != self._current_transaction_id:
                return

            self._received_status = True
            if frame.transmit_status not in (TransmitStatus.SUCCESS,
                                             TransmitStatus.SELF_ADDRESSED):
                self._error = "Error sending ZDO command: %s" % frame.transmit_status.description
                self.stop()

            if self._data_parsed:
                self.stop()


class NodeDescriptorReader(_ZDOCommand):
    """
    This class performs a node descriptor read of the given XBee using a ZDO command.

    The node descriptor read works only with Zigbee devices in API mode.
    """

    CLUSTER_ID = 0x0002
    RECEIVE_CLUSTER_ID = 0x8002

    __DEFAULT_TIMEOUT = 20  # seconds

    def __init__(self, xbee, configure_ao=True, timeout=__DEFAULT_TIMEOUT):
        """
        Class constructor. Instantiates a new :class:`.NodeDescriptorReader`
        object with the provided parameters.

        Args:
            xbee (class:`.XBeeDevice` or class:`.RemoteXBeeDevice`): XBee to
                send the command.
            configure_ao (Boolean, optional, default=`True`): `True` to set
                AO value before and after executing, `False` otherwise.
            timeout (Float, optional, default=`.__DEFAULT_TIMEOUT`): The ZDO
                command timeout in seconds.

        Raises:
            ValueError: If `xbee` is `None`.
            ValueError: If `cluster_id`, `receive_cluster_id`, or `timeout`
                are less than 0.
            TypeError: If the `xbee` is not a `.XBeeDevice` or a
                `RemoteXBeeDevice`.
        """
        super().__init__(
            xbee, self.CLUSTER_ID,
            self.RECEIVE_CLUSTER_ID, configure_ao, timeout)

        self.__node_descriptor = None
        self.__role = Role.UNKNOWN

    def get_node_descriptor(self):
        """
        Returns the descriptor of the node.

        Returns:
            :class:`.NodeDescriptor`: The node descriptor.
        """
        self._start_process(sync=True)

        return self.__node_descriptor

    def _init_variables(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._init_variables`
        """
        self.__role = Role.UNKNOWN

    def _is_broadcast(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._is_broadcast`
        """
        return False

    def _get_zdo_command_data(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._get_zdo_command_data`
        """
        return bytearray([
            self._current_transaction_id, self._xbee.get_16bit_addr().get_lsb(),
            self._xbee.get_16bit_addr().get_hsb()])

    def _parse_data(self, data):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._parse_data`
        """
        # Ensure the 16-bit address received matches the address of the device
        x16 = XBee16BitAddress.from_bytes(data[1], data[0])
        if x16 != self._xbee.get_16bit_addr():
            return False

        # Role field: 3 bits (0, 1, 2) of the next byte
        role = Role.get(utils.get_int_from_byte(data[2], 0, 3))
        # Complex descriptor available: next bit (3) of the same byte
        complex_desc_available = utils.is_bit_enabled(data[2], 3)
        # User descriptor available: next bit (4) of the same byte
        user_desc_available = utils.is_bit_enabled(data[2], 4)

        # Frequency band: 5 bits of the next byte
        freq_band = NodeDescriptorReader.__to_bits(data[3])[-5:]

        # MAC capabilities: next byte
        mac_capabilities = NodeDescriptorReader.__to_bits(data[4])

        # Manufacturer code: next 2 bytes
        manufacturer_code = utils.bytes_to_int([data[6], data[5]])

        # Maximum buffer size: next byte
        max_buffer_size = int(data[7])

        # Maximum incoming transfer size: next 2 bytes
        max_in_transfer_size = utils.bytes_to_int([data[9], data[8]])

        # Maximum outgoing transfer size: next 2 bytes
        max_out_transfer_size = utils.bytes_to_int([data[13], data[12]])

        # Maximum outgoing transfer size: next byte
        desc_capabilities = NodeDescriptorReader.__to_bits(data[14])

        self.__node_descriptor = NodeDescriptor(
            role, complex_desc_available, user_desc_available, freq_band,
            mac_capabilities, manufacturer_code, max_buffer_size,
            max_in_transfer_size, max_out_transfer_size, desc_capabilities)

        return True

    @staticmethod
    def __to_bits(data_byte):
        """
        Convert the byte to an array of bits.

        Args:
            data_byte (Integer): The byte to convert.

        Returns:
            List: An array of bits.
        """
        return [(int(data_byte) >> i) & 1 for i in range(0, 8)]

    def _perform_finish_actions(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._perform_finish_actions`
        """


class NodeDescriptor:
    """
    This class represents a node descriptor of an XBee.
    """

    def __init__(self, role, complex_desc_supported, user_desc_supported, freq_band,
                 mac_capabilities, manufacturer_code, max_buffer_size, max_in_transfer_size,
                 max_out_transfer_size, desc_capabilities):
        """
        Class constructor. Instantiates a new :class:`.NodeDescriptor` object
        with the provided parameters.

        Args:
            role (:class:`.Role`): The device role.
            complex_desc_supported (Boolean): `True` if the complex descriptor
                is supported.
            user_desc_supported (Boolean): `True` if the user descriptor is
                supported.
            freq_band (List): Byte array with the frequency bands.
            mac_capabilities (List): Byte array with MAC capabilities.
            manufacturer_code (Integer): The manufacturer's code assigned by
                the Zigbee Alliance.
            max_buffer_size  (Integer): Maximum size in bytes of a data
                transmission.
            max_in_transfer_size (Integer): Maximum number of bytes that can be
                received by the node.
            max_out_transfer_size (Integer): Maximum number of bytes that can
                 be transmitted by the node.
            desc_capabilities (List): Byte array with descriptor capabilities.
        """
        self.__role = role
        self.__complex_desc_available = complex_desc_supported
        self.__user_desc_available = user_desc_supported
        self.__freq_band = freq_band
        self.__mac_capabilities = mac_capabilities
        self.__manufacturer_code = manufacturer_code
        self.__max_buffer_size = max_buffer_size
        self.__max_in_tx_size = max_in_transfer_size
        self.__max_out_tx_size = max_out_transfer_size
        self.__desc_capabilities = desc_capabilities

    @property
    def role(self):
        """
        Gets the role in this node descriptor.

        Returns:
             :class:`.Role`: The role of the node descriptor.

        .. seealso::
           | :class:`.Role`
        """
        return self.__role

    @property
    def complex_desc_supported(self):
        """
        Gets if the complex descriptor is supported.

        Returns:
             Boolean: `True` if supported, `False` otherwise.
        """
        return self.__complex_desc_available

    @property
    def user_desc_supported(self):
        """
        Gets if the user descriptor is supported.

        Returns:
             Boolean: `True` if supported, `False` otherwise.
        """
        return self.__user_desc_available

    @property
    def freq_band(self):
        """
        Gets the frequency bands (LSB - bit0- index 0, MSB - bit4 - index 4):
        * Bit0: 868 MHz
        * Bit1: Reserved
        * Bit2: 900 MHz
        * Bit3: 2.4 GHz
        * Bit4: Reserved

        Returns:
             List: List of integers with the frequency bands bits.
        """
        return self.__freq_band

    @property
    def mac_capabilities(self):
        """
        Gets the MAC capabilities (LSB - bit0- index 0, MSB - bit7 - index 7):
        * Bit0: Alternate PAN coordinator
        * Bit1: Device Type
        * Bit2: Power source
        * Bit3: Receiver on when idle
        * Bit4-5: Reserved
        * Bit6: Security capability
        * Bit7: Allocate address

        Returns:
             List: List of integers with MAC capabilities bits.
        """
        return self.__mac_capabilities

    @property
    def manufacturer_code(self):
        """
        Gets the manufacturer's code assigned by the Zigbee Alliance.

        Returns:
             Integer: The manufacturer's code.
        """
        return self.__manufacturer_code

    @property
    def max_buffer_size(self):
        """
        Gets the maximum size in bytes of a data transmission (including APS bytes).

        Returns:
             Integer: Maximum size in bytes.
        """
        return self.__max_buffer_size

    @property
    def max_in_transfer_size(self):
        """
        Gets the maximum number of bytes that can be received by the node.

        Returns:
             Integer: Maximum number of bytes that can be received by the node.
        """
        return self.__max_in_tx_size

    @property
    def max_out_transfer_size(self):
        """
        Gets the maximum number of bytes that can be transmitted by the node,
        including fragmentation.

        Returns:
             Integer: Maximum number of bytes that can be transmitted by the node.
        """
        return self.__max_out_tx_size

    @property
    def desc_capabilities(self):
        """
        Gets the descriptor capabilities (LSB - bit0- index 0, MSB - bit1 - index 1):
        * Bit0: Extended active endpoint list available
        * Bit1: Extended simple descriptor list available

        Returns:
             List: List of integers with descriptor capabilities bits.
        """
        return self.__desc_capabilities


class RouteTableReader(_ZDOCommand):
    """
    This class performs a route table read of the given XBee using a ZDO command.

    The node descriptor read works only with Zigbee devices in API mode.
    """

    DEFAULT_TIMEOUT = 20  # seconds

    CLUSTER_ID = 0x0032
    RECEIVE_CLUSTER_ID = 0x8032

    ROUTE_BYTES_LEN = 5

    ST_FIELD_OFFSET = 0
    ST_FIELD_LEN = 3
    MEM_FIELD_OFFSET = 3
    M2O_FIELD_OFFSET = 4
    RR_FIELD_OFFSET = 5

    def __init__(self, xbee, configure_ao=True, timeout=DEFAULT_TIMEOUT):
        """
        Class constructor. Instantiates a new :class:`.RouteTableReader` object
        with the provided parameters.

        Args:
            xbee (class:`.XBeeDevice` or class:`.RemoteXBeeDevice`): XBee to
                send the command.
            configure_ao (Boolean, optional, default=`True`): `True` to set
                AO value before and after executing, `False` otherwise.
            timeout (Float, optional, default=`.DEFAULT_TIMEOUT`): The ZDO
                command timeout in seconds.

        Raises:
            ValueError: If `xbee` is `None`.
            ValueError: If `cluster_id`, `receive_cluster_id`, or `timeout` are
                less than 0.
            TypeError: If the `xbee` is not a `.XBeeDevice` or a
                `.RemoteXBeeDevice`.
        """
        super().__init__(xbee, self.CLUSTER_ID, self.RECEIVE_CLUSTER_ID,
                         configure_ao, timeout)

        self.__routes = None
        self.__total_routes = 0
        self.__index = 0

        self.__cb = None

    def get_route_table(self, route_cb=None, finished_cb=None):
        """
        Returns the routes of the XBee. If `route_cb` is not defined, the
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

        Returns:
            List: List of :class:`.Route` when `route_cb` is not defined,
                `None` otherwise (in this case routes are received in the
                callback).

        .. seealso::
           | :class:`.Route`
        """
        self.__cb = route_cb
        self._start_process(sync=bool(not self.__cb), zdo_cb=finished_cb)

        return self.__routes

    def _init_variables(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._init_variables`
        """
        self.__routes = []
        self.__total_routes = 0
        self.__index = 0

    def _is_broadcast(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._is_broadcast`
        """
        return False

    def _get_zdo_command_data(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._get_zdo_command_data`
        """
        return bytearray([self._current_transaction_id, self.__index])

    def _parse_data(self, data):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._parse_data`
        """
        # Byte 0: Total number of routing table entries
        # Byte 1: Starting point in the routing table
        # Byte 2: Number of routing table entries in the response
        # Byte 3 - end: List of routing table entries (as many as indicated in byte 2)

        self.__total_routes = int(data[0])
        # Ignore start index and get the number of entries in this response.
        n_items = int(data[2])
        if not n_items:
            # No entries in this response, try again?
            self.__get_next_routes()
            return True

        # Parse routes
        routes_starting_index = 3
        byte_index = routes_starting_index
        # Subtract the 3 first bytes: total number of entries, start index, and
        # the number of entries in this response
        n_route_data_bytes = len(data) - 3

        while byte_index + 1 < n_route_data_bytes:
            if byte_index + self.ROUTE_BYTES_LEN \
                    > n_route_data_bytes + routes_starting_index:
                break

            route = self.__parse_route(
                data[byte_index:byte_index + self.ROUTE_BYTES_LEN])
            if route:
                self._logger.debug("Route of %s: %s - %s -> %s", self._xbee,
                                   route.destination, route.next_hop, route.status)
                self.__routes.append(route)
                if self.__cb:
                    self.__cb(self._xbee, route)

            byte_index += self.ROUTE_BYTES_LEN
            self.__index += 1

        # Check if we already have all the routes
        if self.__index < self.__total_routes:
            self.__get_next_routes()

            return False

        return True

    def _perform_finish_actions(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._perform_finish_actions`
        """

    def _notify_process_finished(self, zdo_cb):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._notify_process_finished`
        """
        if zdo_cb:
            zdo_cb(self._xbee, self.__routes, self._error)

    def __parse_route(self, data):
        """
        Parses the given bytearray and returns a route.

        Args:
            data (bytearray): Bytearray with data to parse.

        Returns:
             :class:`.Route`: The route or `None` if not found.
        """
        # Bytes 0 - 1: 16-bit destination address (little endian)
        # Byte 2: Setting byte:
        #          * Bits 0 - 2: Route status
        #          * Bit 3: Low-memory concentrator flag
        #          * Bit 4: Destination is a concentrator flag
        #          * Bit 5: Route record message should be sent prior to next transmission flag
        # Bytes 3 - 4: 16 bit next hop address (little endian)
        return Route(XBee16BitAddress.from_bytes(data[1], data[0]),
                     XBee16BitAddress.from_bytes(data[4], data[3]),
                     RouteStatus.get(utils.get_int_from_byte(
                         data[2], self.ST_FIELD_OFFSET, self.ST_FIELD_LEN)),
                     utils.is_bit_enabled(data[2], self.MEM_FIELD_OFFSET),
                     utils.is_bit_enabled(data[2], self.M2O_FIELD_OFFSET),
                     utils.is_bit_enabled(data[2], self.RR_FIELD_OFFSET))

    def __get_next_routes(self):
        """
        Sends a new ZDO request to get more route table entries.
        """
        if not self._xbee.is_remote():
            node = self._xbee
        else:
            node = self._xbee.get_local_xbee_device()

        try:
            node.send_packet(self._generate_zdo_packet())
        except XBeeException as exc:
            self._error = "Error sending ZDO command: " + str(exc)


class RouteStatus(Enum):
    """
    Enumerates the available route status.
    """

    ACTIVE = (0, "Active")
    DISCOVERY_UNDERWAY = (1, "Discovery Underway")
    DISCOVERY_FAILED = (2, "Discovery Failed")
    INACTIVE = (3, "Inactive")
    VALIDATION_UNDERWAY = (4, "Validation Underway")
    UNKNOWN = (-1, "Unknown")

    def __init__(self, identifier, name):
        self.__id = identifier
        self.__name = name

    def __str__(self):
        return self.__name

    @property
    def id(self):
        """
        Returns the identifier of the RouteStatus.

        Returns:
            Integer: RouteStatus identifier.
        """
        return self.__id

    @property
    def name(self):
        """
        Returns the name of the RouteStatus.

        Returns:
            String: RouteStatus name.
        """
        return self.__name

    @classmethod
    def get(cls, identifier):
        """
        Returns the RouteStatus for the given identifier.

        Args:
            identifier (Integer): Id corresponding to the route status to get.

        Returns:
            :class:`.RouteStatus`: RouteStatus with the given id. `None` if
                it does not exist.
        """
        for item in cls:
            if identifier == item.id:
                return item

        return None


class Route:
    """
    This class represents a Zigbee route read from the route table of an XBee.
    """

    def __init__(self, destination, next_hop, status, is_low_memory,
                 is_many_to_one, is_route_record_required):
        """
        Class constructor. Instantiates a new :class:`.Route` object with the
        provided parameters.

        Args:
            destination (:class:`.XBee16BitAddress`): 16-bit destination
                address of the route.
            next_hop (:class:`.XBee16BitAddress`): 16-bit address of the
                next hop.
            status (:class:`.RouteStatus`): Status of the route.
            is_low_memory (Boolean): `True` to indicate if the device is a
                low-memory concentrator.
            is_many_to_one (Boolean): `True` to indicate the destination is a
                concentrator.
            is_route_record_required (Boolean): `True` to indicate a route
                record message should be sent prior to the next data
                transmission.

        .. seealso::
           | :class:`.RouteStatus`
           | :class:`.XBee16BitAddress`
        """
        self.__dest = destination
        self.__next = next_hop
        self.__status = status
        self.__is_low_memory = is_low_memory
        self.__is_mto = is_many_to_one
        self.__is_rr_required = is_route_record_required

    def __str__(self):
        return ("Destination: {!s} - Next: {!s} (status: {!s}, low-memory: {!r}"
                ", many-to-one: {!r}, route record required: {!r})".format(
                    self.__dest, self.__next, self.__status.name,
                    self.__is_low_memory, self.__is_mto, self.__is_rr_required))

    @property
    def destination(self):
        """
        Gets the 16-bit address of this route destination.

        Returns:
            :class:`.XBee16BitAddress`: 16-bit address of the destination.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__dest

    @property
    def next_hop(self):
        """
        Gets the 16-bit address of this route next hop.

        Returns:
            :class:`.XBee16BitAddress`: 16-bit address of the next hop.

        .. seealso::
           | :class:`.XBee16BitAddress`
        """
        return self.__next

    @property
    def status(self):
        """
        Gets this route status.

        Returns:
            :class:`.RouteStatus`: The route status.

        .. seealso::
           | :class:`.RouteStatus`
        """
        return self.__status

    @property
    def is_low_memory(self):
        """
        Gets whether the device is a low-memory concentrator.

        Returns:
            Boolean: `True` if the device is a low-memory concentrator, `False` otherwise.
        """
        return self.__is_low_memory

    @property
    def is_many_to_one(self):
        """
        Gets whether the destination is a concentrator.

        Returns:
            Boolean: `True` if destination is a concentrator, `False` otherwise.
        """
        return self.__is_mto

    @property
    def is_route_record_required(self):
        """
        Gets whether a route record message should be sent prior the next data
        transmission.

        Returns:
            Boolean: `True` if a route record message should be sent, `False` otherwise.
        """
        return self.__is_rr_required


class NeighborTableReader(_ZDOCommand):
    """
    This class performs a neighbor table read of the given XBee using a ZDO
    command.

    The node descriptor read works only with Zigbee devices in API mode.
    """

    DEFAULT_TIMEOUT = 20  # seconds

    CLUSTER_ID = 0x0031
    RECEIVE_CLUSTER_ID = 0x8031

    NEIGHBOR_BYTES_LEN = 22

    ROLE_FIELD_OFFSET = 0
    ROLE_FIELD_LEN = 2
    RELATIONSHIP_FIELD_OFFSET = 4
    RELATIONSHIP_FIELD_LEN = 3

    def __init__(self, xbee, configure_ao=True, timeout=DEFAULT_TIMEOUT):
        """
        Class constructor. Instantiates a new :class:`.NeighborTableReader`
        object with the provided parameters.

        Args:
            xbee (class:`.XBeeDevice` or class:`.RemoteXBeeDevice`): XBee to
                send the command.
            configure_ao (Boolean, optional, default=`True`): `True` to set
                AO value before and after executing, `False` otherwise.
            timeout (Float, optional, default=`.DEFAULT_TIMEOUT`): The ZDO
                command timeout in seconds.

        Raises:
            ValueError: If `xbee` is `None`.
            ValueError: If `cluster_id`, `receive_cluster_id`, or `timeout` are
                less than 0.
            TypeError: If the `xbee` is not a `.XBeeDevice` or a
                `.RemoteXBeeDevice`.
        """
        super().__init__(xbee, self.CLUSTER_ID, self.RECEIVE_CLUSTER_ID,
                         configure_ao, timeout)

        self.__neighbors = None
        self.__total_neighbors = 0
        self.__index = 0

        self.__cb = None

    def get_neighbor_table(self, neighbor_cb=None, finished_cb=None):
        """
        Returns the neighbors of the XBee. If `neighbor_cb` is not defined,
        the process blocks until the complete neighbor table is read.

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

        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback)

        .. seealso::
           | :class:`.Neighbor`
        """
        self.__cb = neighbor_cb
        self._start_process(sync=bool(not self.__cb), zdo_cb=finished_cb)

        return self.__neighbors

    def _init_variables(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._init_variables`
        """
        self.__neighbors = []
        self.__total_neighbors = 0
        self.__index = 0

    def _is_broadcast(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._is_broadcast`
        """
        return False

    def _get_zdo_command_data(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._get_zdo_command_data`
        """
        return bytearray([self._current_transaction_id, self.__index])

    def _parse_data(self, data):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._parse_data`
        """
        # Byte 0: Total number of neighbor table entries
        # Byte 1: Starting point in the neighbor table
        # Byte 2: Number of neighbor table entries in the response
        # Byte 3 - end: List of neighbor table entries (as many as indicated in byte 2)

        self.__total_neighbors = int(data[0])
        # Ignore start index and get the number of entries in this response.
        n_items = int(data[2])
        if not n_items:
            # No entries in this response, try again?
            self.__get_next_neighbors()
            return True

        # Parse neighbors
        neighbors_starting_index = 3
        byte_index = neighbors_starting_index
        # Subtract the 3 first bytes: total number of entries, start index,
        # and the number of entries in this response
        n_neighbor_data_bytes = len(data) - 3

        while byte_index + 1 < n_neighbor_data_bytes:
            if byte_index + self.NEIGHBOR_BYTES_LEN \
                    > n_neighbor_data_bytes + neighbors_starting_index:
                break

            neighbor = self.__parse_neighbor(
                data[byte_index:byte_index + self.NEIGHBOR_BYTES_LEN])
            # Do not add the node with Zigbee coordinator address "0000000000000000"
            # The coordinator is already received with its real 64-bit address
            if neighbor and neighbor.node.get_64bit_addr() != XBee64BitAddress.COORDINATOR_ADDRESS:
                self._logger.debug("Neighbor of '%s': %s (relation: %s, depth: %s, lqi: %s)",
                                   self._xbee, neighbor.node, neighbor.relationship.name,
                                   neighbor.depth, neighbor.lq)
                self.__neighbors.append(neighbor)
                if self.__cb:
                    self.__cb(self._xbee, neighbor)

            byte_index += self.NEIGHBOR_BYTES_LEN
            self.__index += 1

        # Check if we already have all the neighbors
        if self.__index < self.__total_neighbors:
            self.__get_next_neighbors()

            return False

        return True

    def _perform_finish_actions(self):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._perform_finish_actions`
        """

    def _notify_process_finished(self, zdo_cb):
        """
        Override.

        .. seealso::
           | :meth:`._ZDOCommand._notify_process_finished`
        """
        if zdo_cb:
            zdo_cb(self._xbee, self.__neighbors, self._error)

    def __parse_neighbor(self, data):
        """
        Parses the given bytearray and returns a neighbor.

        Args:
            data (bytearray): Bytearray with data to parse.

        Returns:
             :class:`.Neighbor`: The neighbor or `None` if not found.
        """
        # Bytes 0 - 7: Extended PAN ID (little endian)
        # Bytes 8 - 15: 64-bit neighbor address (little endian)
        # Bytes 16 - 17: 16-bit neighbor address (little endian)
        # Byte 18: First setting byte:
        #          * Bit 0 - 1: Neighbor role
        #          * Bit 2 - 3: Receiver on when idle (indicates if the
        #                       neighbor's receiver is enabled during idle times)
        #          * Bit 4 - 6: Relationship of this neighbor with the node
        #          * Bit 7: Reserved
        # Byte 19: Second setting byte:
        #          * Bit 0 - 1: Permit joining (indicates if the neighbor accepts join requests)
        #          * Bit 2 - 7: Reserved
        # Byte 20: Depth (Tree depth of the neighbor. A value of 0 indicates
        #          the neighbor is the coordinator)
        # Byte 21: LQI (The estimated link quality of data transmissions from this neighbor)
        x64 = XBee64BitAddress.from_bytes(*data[8:16][:: -1])
        x16 = XBee16BitAddress.from_bytes(data[17], data[16])
        role = Role.get(utils.get_int_from_byte(data[18], self.ROLE_FIELD_OFFSET,
                                                self.ROLE_FIELD_LEN))
        relationship = NeighborRelationship.get(
            utils.get_int_from_byte(data[18], self.RELATIONSHIP_FIELD_OFFSET,
                                    self.RELATIONSHIP_FIELD_LEN))
        depth = int(data[20])
        lqi = int(data[21])

        if not self._xbee.is_remote():
            node = self._xbee
        else:
            node = self._xbee.get_local_xbee_device()

        # Create a new remote node
        n_xb = RemoteZigBeeDevice(node, x64bit_addr=x64, x16bit_addr=x16)
        n_xb._role = role

        return Neighbor(n_xb, relationship, depth, lqi)

    def __get_next_neighbors(self):
        """
        Sends a new ZDO request to get more neighbor table entries.
        """
        if not self._xbee.is_remote():
            node = self._xbee
        else:
            node = self._xbee.get_local_xbee_device()

        try:
            node.send_packet(self._generate_zdo_packet())
        except XBeeException as exc:
            self._error = "Error sending ZDO command: " + str(exc)


class NeighborRelationship(Enum):
    """
    Enumerates the available relationships between two nodes of the same network.
    """

    PARENT = (0, "Neighbor is the parent")
    CHILD = (1, "Neighbor is a child")
    SIBLING = (2, "Neighbor is a sibling")
    UNDETERMINED = (3, "Neighbor has an unknown relationship")
    PREVIOUS_CHILD = (4, "Previous child")
    UNKNOWN = (-1, "Unknown")

    def __init__(self, identifier, name):
        self.__id = identifier
        self.__name = name

    @property
    def id(self):
        """
        Returns the identifier of the NeighborRelationship.

        Returns:
            Integer: NeighborRelationship identifier.
        """
        return self.__id

    @property
    def name(self):
        """
        Returns the name of the NeighborRelationship.

        Returns:
            String: NeighborRelationship name.
        """
        return self.__name

    @classmethod
    def get(cls, identifier):
        """
        Returns the NeighborRelationship for the given identifier.

        Args:
            identifier (Integer): Id corresponding to the neighbor relationship to get.

        Returns:
            :class:`.NeighborRelationship`: the NeighborRelationship with the
                given id. `None` if it does not exist.
        """
        for item in cls:
            if identifier == item.id:
                return item
        return None


class Neighbor:
    """
    This class represents a Zigbee or DigiMesh neighbor.

    This information is read from the neighbor table of a Zigbee XBee, or
    provided by the 'FN' command in a Digimesh XBee.
    """

    def __init__(self, node, relationship, depth, lq):
        """
        Class constructor. Instantiates a new :class:`.Neighbor` object with
        the provided parameters.

        Args:
            node (:class:`.RemoteXBeeDevice`): The neighbor node.
            relationship (:class:`.NeighborRelationship`): The relationship of
                this neighbor with the node.
            depth (Integer): The tree depth of the neighbor. A value of 0
                indicates the device is a Zigbee coordinator for the network.
                -1 means this is unknown.
            lq (Integer): The estimated link quality (LQI or RSSI) of data
                transmission from this neighbor.

        .. seealso::
           | :class:`.NeighborRelationship`
           | :class:`.RemoteXBeeDevice`
        """
        self._node = node
        self.__relationship = relationship
        self.__depth = depth
        self.__lq = lq

    def __str__(self):
        return "Node: {!s} (relationship: {!s}, depth: {!r}, lq: {!r})".format(
            self._node, self.__relationship.name, self.__depth, self.__lq)

    @property
    def node(self):
        """
        Gets the neighbor node.

        Returns:
            :class:`.RemoteXBeeDevice`: The node itself.

        .. seealso::
           | :class:`.RemoteXBeeDevice`
        """
        return self._node

    @property
    def relationship(self):
        """
        Gets the neighbor node.

        Returns:
            :class:`.NeighborRelationship`: The neighbor relationship.

        .. seealso::
           | :class:`.NeighborRelationship`
        """
        return self.__relationship

    @property
    def depth(self):
        """
        Gets the tree depth of the neighbor.

        Returns:
            Integer: The tree depth of the neighbor.
        """
        return self.__depth

    @property
    def lq(self):
        """
        Gets the estimated link quality (LQI or RSSI) of data transmission
        from this neighbor.

        Returns:
            Integer: The estimated link quality of data transmission from this neighbor.
        """
        return self.__lq


class NeighborFinder:
    """
    This class performs a find neighbors (FN) of an XBee. This action requires
    an XBee and optionally a find timeout.

    The process works only in DigiMesh.
    """

    DEFAULT_TIMEOUT = 20  # seconds

    _global_frame_id = 1

    _logger = logging.getLogger(__name__)

    def __init__(self, xbee, timeout=DEFAULT_TIMEOUT):
        """
        Class constructor. Instantiates a new :class:`.NeighborFinder` object
        with the provided parameters.

        Args:
            xbee (class:`.XBeeDevice` or class:`.RemoteXBeeDevice`): The XBee
                to get neighbors from.
            timeout(Float): The timeout for the process in seconds.

        Raises:
            OperationNotSupportedException: If the process is not supported in the XBee.
            TypeError: If the `xbee` is not a `.AbstractXBeeDevice`.
            ValueError: If `xbee` is `None`.
            ValueError: If `timeout` is less than 0.
        """
        if not xbee:
            raise ValueError("XBee cannot be None")
        if not isinstance(xbee, (XBeeDevice, RemoteXBeeDevice)):
            raise TypeError("The xbee must be an XBeeDevice or a RemoteXBeeDevice"
                            "not {!r}".format(xbee.__class__.__name__))
        if xbee.get_protocol() not in (XBeeProtocol.DIGI_MESH, XBeeProtocol.XLR_DM,
                                       XBeeProtocol.XTEND_DM, XBeeProtocol.SX):
            raise OperationNotSupportedException(
                message="Find neighbors is not supported in %s"
                % xbee.get_protocol().description)
        if timeout < 0:
            raise ValueError("Timeout cannot be negative")

        self.__xbee = xbee
        self.__timeout = timeout

        self.__running = False
        self.__error = None
        self.__fn_thread = None
        self.__lock = threading.Event()
        self.__received_answer = False
        self.__neighbors = []
        self.__cb = None

        self.__current_frame_id = self._global_frame_id
        self.__class__._global_frame_id = self.__class__._global_frame_id + 1
        if self.__class__._global_frame_id == 0xFF:
            self.__class__._global_frame_id = 1

    @property
    def running(self):
        """
        Returns whether this find neighbors process is running.

        Returns:
            Boolean: `True` if it is running, `False` otherwise.
        """
        return self.__running

    @property
    def error(self):
        """
        Returns the error string if any.

        Returns:
             String: The error string.
        """
        return self.__error

    def stop(self):
        """
        Stops the find neighbors process if it is running.
        """
        self.__lock.set()

        if self.__fn_thread and self.__running:
            self.__fn_thread.join()
            self.__fn_thread = None

    def get_neighbors(self, neighbor_cb=None, finished_cb=None):
        """
        Returns the neighbors of the XBee. If `neighbor_cb` is not defined,
        the process blocks until the complete neighbor table is read.

        Args:
            neighbor_cb (Function, optional, default=`None`): Method called
                when a new neighbor is received. Receives two arguments:

                * The XBee that owns this new neighbor.
                * The new neighbor.

            finished_cb (Function, optional, default=`None`): Method to execute
                when the process finishes. Receives three arguments:

                * The XBee that executed the FN command.
                * A list with the discovered neighbors.
                * An error message if something went wrong.

        Returns:
            List: List of :class:`.Neighbor` when `neighbor_cb` is not defined,
                `None` otherwise (in this case neighbors are received in the callback)

        .. seealso::
           | :class:`.Neighbor`
        """
        self.__cb = neighbor_cb

        if neighbor_cb:
            self.__fn_thread = threading.Thread(
                target=self.__send_command,
                kwargs={'finished_cb': finished_cb},
                daemon=True)
            self.__fn_thread.start()
        else:
            self.__send_command(finished_cb=finished_cb)

        return self.__neighbors

    def __send_command(self, finished_cb=None):
        """
        Sends the FN command.

        Args:
            finished_cb (Function, optional): Method to execute  when the
                process finishes. Receives three arguments:

                * The XBee that executed the FN command.
                * A list with the discovered neighbors.
                * An error message if something went wrong.
        """
        self.__lock.clear()

        self.__running = True
        self.__error = None
        self.__received_answer = False
        self.__neighbors = []

        if not self.__xbee.is_remote():
            node = self.__xbee
        else:
            node = self.__xbee.get_local_xbee_device()

        node.add_packet_received_callback(self.__fn_packet_cb)

        try:
            node.send_packet(self.__generate_fn_packet())

            self.__lock.wait(self.__timeout)

            if not self.__received_answer:
                if not self.__error:
                    self.__error = "%s command answer not received" % ATStringCommand.FN.command
                return
        except XBeeException as exc:
            self.__error = "Error sending %s command: %s" % (ATStringCommand.FN.command, str(exc))
        finally:
            node.del_packet_received_callback(self.__fn_packet_cb)
            if finished_cb:
                finished_cb(self.__xbee, self.__neighbors, self.__error)
            self.__running = False

    def __generate_fn_packet(self):
        """
        Generates the AT command packet or remote AT command packet.

        Returns:
             :class:`.RemoteATCommandPacket` or :class:`.ATCommandPacket`:
                The packet to send.
        """
        if self.__xbee.is_remote():
            return RemoteATCommandPacket(
                self.__current_frame_id, self.__xbee.get_64bit_addr(),
                XBee16BitAddress.UNKNOWN_ADDRESS, TransmitOptions.NONE.value,
                ATStringCommand.FN.command)

        return ATCommPacket(self.__current_frame_id, ATStringCommand.FN.command)

    def __parse_data(self, data):
        """
        Handles what to do with the received data.

        Args:
            data (bytearray): Byte array containing the frame data.
        """
        # Bytes 0 - 1: 16-bit neighbor address (always 0xFFFE)
        # Bytes 2 - 9: 64-bit neighbor address
        # Bytes 10 - x: Node identifier of the neighbor (ends with a 0x00 character)
        # Next 2 bytes: Neighbor parent 16-bit address (always 0xFFFE)
        # Next byte: Neighbor role:
        #          * 0: Coordinator
        #          * 1: Router
        #          * 2: End device
        # Next byte: Status (reserved)
        # Next 2 bytes: Profile identifier
        # Next 2 bytes: Manufacturer identifier
        # Next 4 bytes: Digi device type (optional, depending on 'NO' settings)
        # Next byte: RSSI of last hop (optional, depending on 'NO' settings)

        # 64-bit address starts at index 2
        x64 = XBee64BitAddress(data[2:10])

        # Node ID starts at index 10
        i = 10
        # Node id: from 'i' to the next 0x00
        while data[i] != 0x00:
            i += 1
        node_id = data[10:i]
        i += 1  # The 0x00

        i += 2  # The parent address (not needed)

        # Role is the next byte
        role = Role.get(utils.bytes_to_int(data[i:i + 1]))
        i += 1

        i += 1  # The status byte
        i += 2  # The profile identifier
        i += 2  # The manufacturer identifier

        # Check if the Digi device type and/or the RSSI are included
        if len(data) >= i + 5:
            # Both included
            rssi = utils.bytes_to_int(data[i+4:i+5])
        elif len(data) >= i + 4:
            # Only Digi device types
            rssi = -9999
        elif len(data) >= i + 1:
            # Only the RSSI
            rssi = utils.bytes_to_int(data[i:i+1])
        else:
            # None of them
            rssi = -9999

        if not self.__xbee.is_remote():
            node = self.__xbee
        else:
            node = self.__xbee.get_local_xbee_device()

        # Create a new remote node
        n_xb = RemoteDigiMeshDevice(
            node, x64bit_addr=x64, node_id=node_id.decode('utf8', errors='ignore'))
        n_xb._role = role

        neighbor = Neighbor(n_xb, NeighborRelationship.SIBLING, -1, rssi)
        self.__neighbors.append(neighbor)
        self._logger.debug("Neighbor of '%s': %s (relation: %s, rssi: -%s)", self.__xbee,
                           neighbor.node, neighbor.relationship.name, neighbor.lq)

        if self.__cb:
            self.__cb(self.__xbee, neighbor)

    def __fn_packet_cb(self, frame):
        """
        Callback notified when a new frame is received.

        Args:
            frame (:class:`.XBeeAPIPacket`): The received packet.
        """
        if not self.__running:
            return

        frame_type = frame.get_frame_type()
        if frame_type in (ApiFrameType.AT_COMMAND_RESPONSE,
                          ApiFrameType.REMOTE_AT_COMMAND_RESPONSE):

            self._logger.debug("Received '%s' frame: %s",
                               frame.get_frame_type().description,
                               utils.hex_to_string(frame.output()))

            # If frame ID does not match, discard: it is not the frame we are
            # waiting for
            if frame.frame_id != self.__current_frame_id:
                return
            # Check the command
            if frame.command != ATStringCommand.FN.command:
                return

            self.__received_answer = True

            # Check for error.
            if frame.status != ATCommandStatus.OK:
                self.__error = "Error executing %s command (status: %s (%d))" \
                               % (ATStringCommand.FN.command,
                                  frame.status.description, frame.status.code)
                self.stop()
                return

            self.__parse_data(frame.command_value)
