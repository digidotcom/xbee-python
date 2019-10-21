# Copyright 2019, Digi International Inc.
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
import time
from collections import OrderedDict
from ipaddress import IPv4Address

from digi.xbee.devices import CellularDevice
from digi.xbee.exception import TimeoutException, XBeeSocketException, XBeeException
from digi.xbee.models.protocol import IPProtocol
from digi.xbee.models.status import SocketState, SocketStatus, TransmitStatus
from digi.xbee.packets.raw import TXStatusPacket
from digi.xbee.packets.socket import SocketConnectPacket, SocketCreatePacket, SocketSendPacket, SocketClosePacket, \
    SocketBindListenPacket, SocketNewIPv4ClientPacket, SocketOptionRequestPacket, SocketSendToPacket


class socket:
    """
    This class represents an XBee socket and provides methods to create,
    connect, bind and close a socket, as well as send and receive data with it.
    """

    __DEFAULT_TIMEOUT = 5
    __MAX_PAYLOAD_BYTES = 1500

    def __init__(self, xbee_device, ip_protocol=IPProtocol.TCP):
        """
        Class constructor. Instantiates a new XBee socket object for the given XBee device.

        Args:
            xbee_device (:class:`.XBeeDevice`): XBee device of the socket.
            ip_protocol (:class:`.IPProtocol`): protocol of the socket.

        Raises:
            ValueError: if ``xbee_device`` is ``None`` or if ``xbee_device`` is not an instance of ``CellularDevice``.
            ValueError: if ``ip_protocol`` is ``None``.
            XBeeException: if the connection with the XBee device is not open.
        """
        if xbee_device is None:
            raise ValueError("XBee device cannot be None")
        if not isinstance(xbee_device, CellularDevice):
            raise ValueError("XBee device must be a Cellular device")
        if ip_protocol is None:
            raise ValueError("IP protocol cannot be None")
        if not xbee_device.is_open():
            raise XBeeException("XBee device must be open")

        # Initialize internal vars.
        self.__xbee_device = xbee_device
        self.__ip_protocol = ip_protocol
        self.__socket_id = None
        self.__connected = False
        self.__source_port = None
        self.__is_listening = False
        self.__backlog = None
        self.__timeout = self.__DEFAULT_TIMEOUT
        self.__data_received = bytearray()
        self.__data_received_lock = threading.Lock()
        self.__data_received_from_dict = OrderedDict()
        self.__data_received_from_dict_lock = threading.Lock()
        # Initialize socket callbacks.
        self.__socket_state_callback = None
        self.__data_received_callback = None
        self.__data_received_from_callback = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self, address):
        """
        Connects to a remote socket at the given address.

        Args:
            address (Tuple): A pair ``(host, port)`` where ``host`` is the domain name or string representation of an
                IPv4 and ``port`` is the numeric port value.

        Raises:
            TimeoutException: if the connect response is not received in the configured timeout.
            ValueError: if ``address`` is ``None`` or not a pair ``(host, port)``.
            ValueError: if ``port`` is less than 1 or greater than 65535.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the connect status is not ``SUCCESS``.
        """
        # Check address and its contents.
        if address is None or len(address) != 2:
            raise ValueError("Invalid address, it must be a pair (host, port).")

        host = address[0]
        port = address[1]
        if isinstance(host, IPv4Address):
            host = str(host)
        if port < 1 or port > 65535:
            raise ValueError("Port number must be between 1 and 65535.")

        # If the socket is not created, create it first.
        if self.__socket_id is None:
            self.__create_socket()

        lock = threading.Condition()
        received_state = list()

        # Define the socket state received callback.
        def socket_state_received_callback(socket_id, state):
            # Check the socket ID.
            if socket_id != self.__socket_id:
                return

            # Add the state to the list and notify the lock.
            received_state.append(state)
            lock.acquire()
            lock.notify()
            lock.release()

        # Add the socket state received callback.
        self.__xbee_device.add_socket_state_received_callback(socket_state_received_callback)

        try:
            # Create, send and check the socket connect packet.
            connect_packet = SocketConnectPacket(self.__xbee_device.get_next_frame_id(), self.__socket_id, port,
                                                 SocketConnectPacket.DEST_ADDRESS_STRING, host)
            response_packet = self.__xbee_device.send_packet_sync_and_get_response(connect_packet,
                                                                                   timeout=self.__get_timeout())
            self.__check_response(response_packet)

            # Wait until the socket state frame is received confirming the connection.
            if not received_state:
                lock.acquire()
                lock.wait(self.__timeout)
                lock.release()

            # Check if the socket state has been received.
            if not received_state:
                raise TimeoutException("Timeout waiting for the socket connection")

            # Check if the socket is connected successfully.
            if received_state[0] != SocketState.CONNECTED:
                raise XBeeSocketException(status=received_state[0])

            self.__connected = True

            # Register internal socket state and data reception callbacks.
            self.__register_state_callback()
            self.__register_data_received_callback()
        finally:
            # Always remove the socket state callback.
            self.__xbee_device.del_socket_state_received_callback(socket_state_received_callback)

    def bind(self, address):
        """
        Binds the socket to the given address. The socket must not already be bound.

        Args:
            address (Tuple): A pair ``(host, port)`` where ``host`` is the local interface (not used) and ``port`` is
                the numeric port value.

        Raises:
            TimeoutException: if the bind response is not received in the configured timeout.
            ValueError: if ``address`` is ``None`` or not a pair ``(host, port)``.
            ValueError: if ``port`` is less than 1 or greater than 65535.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the bind status is not ``SUCCESS``.
            XBeeSocketException: if the socket is already bound.
        """
        # Check address and its contents.
        if address is None or len(address) != 2:
            raise ValueError("Invalid address, it must be a pair (host, port).")

        port = address[1]
        if port < 1 or port > 65535:
            raise ValueError("Port number must be between 1 and 65535.")
        if self.__source_port:
            raise XBeeSocketException(status=SocketStatus.ALREADY_CONNECTED)

        # If the socket is not created, create it first.
        if self.__socket_id is None:
            self.__create_socket()

        # Create, send and check the socket create packet.
        bind_packet = SocketBindListenPacket(self.__xbee_device.get_next_frame_id(), self.__socket_id, port)
        response_packet = self.__xbee_device.send_packet_sync_and_get_response(bind_packet,
                                                                               timeout=self.__get_timeout())
        self.__check_response(response_packet)

        # Register the internal data 'reception from' callback.
        self.__register_data_received_from_callback()

        # Store the source port.
        self.__source_port = port

    def listen(self, backlog=1):
        """
        Enables a server to accept connections.

        Args:
            backlog (Integer, optional): The number of unaccepted connections that the system will allow before refusing
                new connections. If specified, it must be at least 0 (if it is lower, it is set to 0).

        Raises:
            XBeeSocketException: if the socket is not bound.
        """
        if self.__source_port is None:
            raise XBeeSocketException(message="Socket must be bound")

        self.__is_listening = True
        self.__backlog = backlog

    def accept(self):
        """
        Accepts a connection. The socket must be bound to an address and listening for connections.

        Returns:
            Tuple: A pair ``(conn, address)`` where ``conn`` is a new socket object usable to send and receive data on
                the connection, and ``address`` is a pair ``(host, port)`` with the address bound to the socket on the
                other end of the connection.

        Raises:
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket is not bound or not listening.
        """
        if self.__source_port is None:
            raise XBeeSocketException(message="Socket must be bound")
        if not self.__is_listening:
            raise XBeeSocketException(message="Socket must be listening")

        lock = threading.Condition()
        received_packet = list()

        # Define the IPv4 client callback.
        def ipv4_client_callback(packet):
            if not isinstance(packet, SocketNewIPv4ClientPacket) or packet.socket_id != self.__socket_id:
                return

            # Add the packet to the list and notify the lock.
            received_packet.append(packet)
            lock.acquire()
            lock.notify()
            lock.release()

        # Add the socket IPv4 client callback.
        self.__xbee_device.add_packet_received_callback(ipv4_client_callback)

        try:
            # Wait until an IPv4 client packet is received.
            lock.acquire()
            lock.wait()
            lock.release()

            conn = socket(self.__xbee_device, self.__ip_protocol)
            conn.__socket_id = received_packet[0].client_socket_id
            conn.__connected = True

            # Register internal socket state and data reception callbacks.
            conn.__register_state_callback()
            conn.__register_data_received_callback()

            return conn, (received_packet[0].remote_address, received_packet[0].remote_port)
        finally:
            # Always remove the socket IPv4 client callback.
            self.__xbee_device.del_packet_received_callback(ipv4_client_callback)

    def gettimeout(self):
        """
        Returns the configured socket timeout in seconds.

        Returns:
            Integer: the configured timeout in seconds.
        """
        return self.__timeout

    def settimeout(self, timeout):
        """
        Sets the socket timeout in seconds.

        Args:
            timeout (Integer): the new socket timeout in seconds.
        """
        self.__timeout = timeout

    def getblocking(self):
        """
        Returns whether the socket is in blocking mode or not.

        Returns:
            Boolean: ``True`` if the socket is in blocking mode, ``False`` otherwise.
        """
        return self.gettimeout() is None

    def setblocking(self, flag):
        """
        Sets the socket in blocking or non-blocking mode.

        Args:
            flag (Boolean): ``True`` to set the socket in blocking mode, ``False`` to set it in no blocking mode and
                configure the timeout with the default value (``5`` seconds).
        """
        self.settimeout(None if flag else self.__DEFAULT_TIMEOUT)

    def recv(self, bufsize):
        """
        Receives data from the socket.

        Args:
            bufsize (Integer): The maximum amount of data to be received at once.

        Returns:
            Bytearray: the data received.

        Raises:
            ValueError: if ``bufsize`` is less than ``1``.
        """
        if bufsize < 1:
            raise ValueError("Number of bytes to receive must be grater than 0")

        data_received = bytearray()

        # Wait until data is available or the timeout configured in the socket expires.
        if self.getblocking():
            while len(self.__data_received) == 0:
                time.sleep(0.1)
        else:
            dead_line = time.time() + self.__timeout
            while len(self.__data_received) == 0 and dead_line > time.time():
                time.sleep(0.1)
        # Get the number of bytes specified in 'bufsize' from the internal var.
        if len(self.__data_received) > 0:
            self.__data_received_lock.acquire()
            data_received = self.__data_received[0:bufsize].copy()
            self.__data_received = self.__data_received[bufsize:]
            self.__data_received_lock.release()
        # Return the data received.
        return data_received

    def recvfrom(self, bufsize):
        """
        Receives data from the socket.

        Args:
            bufsize (Integer): the maximum amount of data to be received at once.

        Returns:
            Tuple (Bytearray, Tuple): Pair containing the data received (Bytearray) and the address of the socket
                sending the data. The address is also a pair ``(host, port)`` where ``host`` is the string
                representation of an IPv4 and ``port`` is the numeric port value.

        Raises:
            ValueError: if ``bufsize`` is less than ``1``.
        """
        if bufsize < 1:
            raise ValueError("Number of bytes to receive must be grater than 0")

        data_received = bytearray()
        address = None

        # Wait until data is received from any address or the timeout configured in the socket expires.
        if self.getblocking():
            while len(self.__data_received_from_dict) == 0:
                time.sleep(0.1)
        else:
            dead_line = time.time() + self.__timeout
            while len(self.__data_received_from_dict) == 0 and dead_line > time.time():
                time.sleep(0.1)
        # Get the number of bytes specified in 'bufsize' from the first address stored.
        if len(self.__data_received_from_dict) > 0:
            self.__data_received_from_dict_lock.acquire()
            # Get 'bufsize' bytes from the first stored address in the internal dict.
            address = list(self.__data_received_from_dict)[0]
            data_received = self.__data_received_from_dict[address][0:bufsize].copy()
            # Update the number of bytes left for 'address' in the dictionary.
            self.__data_received_from_dict[address] = self.__data_received_from_dict[address][bufsize:]
            # If the number of bytes left for 'address' is 0, remove it from the dictionary.
            if len(self.__data_received_from_dict[address]) == 0:
                self.__data_received_from_dict.pop(address)
            self.__data_received_from_dict_lock.release()
        # Return the data received for 'address'.
        return data_received, address

    def send(self, data):
        """
        Sends data to the socket and returns the number of bytes sent. The socket must be connected to a remote socket.
        Applications are responsible for checking that all data has been sent; if only some of the data was
        transmitted, the application needs to attempt delivery of the remaining data.

        Args:
            data (Bytearray): the data to send.

        Returns:
            Integer: the number of bytes sent.

        Raises:
            ValueError: if the data to send is ``None``.
            ValueError: if the number of bytes to send is ``0``.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket is not valid.
            XBeeSocketException: if the socket is not open.
        """
        self.__send(data, False)

    def sendall(self, data):
        """
        Sends data to the socket. The socket must be connected to a remote socket. Unlike ``send()``, this method
        continues to send data from bytes until either all data has been sent or an error occurs. None is returned
        on success. On error, an exception is raised, and there is no way to determine how much data, if any, was
        successfully sent.

        Args:
            data (Bytearray): the data to send.

        Raises:
            TimeoutException: if the send status response is not received in the configured timeout.
            ValueError: if the data to send is ``None``.
            ValueError: if the number of bytes to send is ``0``.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket is not valid.
            XBeeSocketException: if the send status is not ``SUCCESS``.
            XBeeSocketException: if the socket is not open.
        """
        self.__send(data)

    def sendto(self, data, address):
        """
        Sends data to the socket. The socket should not be connected to a remote socket, since the destination socket
        is specified by ``address``.

        Args:
            data (Bytearray): the data to send.
            address (Tuple): the address of the destination socket. It must be a pair ``(host, port)`` where ``host``
                is the domain name or string representation of an IPv4 and ``port`` is the numeric port value.

        Returns:
            Integer: the number of bytes sent.

        Raises:
            TimeoutException: if the send status response is not received in the configured timeout.
            ValueError: if the data to send is ``None``.
            ValueError: if the number of bytes to send is ``0``.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket is already open.
            XBeeSocketException: if the send status is not ``SUCCESS``.
        """
        if data is None:
            raise ValueError("Data to send cannot be None")
        if len(data) == 0:
            raise ValueError("The number of bytes to send must be at least 1")
        if not self.__xbee_device.is_open():
            raise XBeeException("XBee device must be open")
        if self.__connected:
            raise XBeeSocketException(message="Socket is already connected")

        sent_bytes = 0

        # If the socket is not created, create it first.
        if self.__socket_id is None:
            self.__create_socket()
        # Send as many packets as needed to deliver all the provided data.
        for chunk in self.__split_payload(data):
            send_packet = SocketSendToPacket(self.__xbee_device.get_next_frame_id(), self.__socket_id,
                                             IPv4Address(address[0]), address[1], chunk)
            response_packet = self.__xbee_device.send_packet_sync_and_get_response(send_packet,
                                                                                   timeout=self.__get_timeout())
            self.__check_response(response_packet)
            sent_bytes += len(chunk)
        # Return the number of bytes sent.
        return sent_bytes

    def close(self):
        """
        Closes the socket.

        Raises:
            TimeoutException: if the close response is not received in the configured timeout.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the close status is not ``SUCCESS``.
        """
        if self.__socket_id is None or (not self.__connected and not self.__source_port):
            return
        if not self.__xbee_device.is_open():
            raise XBeeException("XBee device must be open")

        close_packet = SocketClosePacket(self.__xbee_device.get_next_frame_id(), self.__socket_id)
        response_packet = self.__xbee_device.send_packet_sync_and_get_response(close_packet,
                                                                               timeout=self.__get_timeout())
        self.__check_response(response_packet)

        self.__connected = False
        self.__socket_id = None
        self.__source_port = None
        self.__data_received = bytearray()
        self.__data_received_from_dict = OrderedDict()
        self.__unregister_state_callback()
        self.__unregister_data_received_callback()
        self.__unregister_data_received_from_callback()

    def setsocketopt(self, option, value):
        """
        Sets the value of the given socket option.

        Args:
            option (:class:`.SocketOption`): the socket option to set its value.
            value (Bytearray): the new value of the socket option.

        Raises:
            TimeoutException: if the socket option response is not received in the configured timeout.
            ValueError: if the option to set is ``None``.
            ValueError: if the value of the option is ``None``.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket option response status is not ``SUCCESS``.
        """
        if option is None:
            raise ValueError("Option to set cannot be None")
        if value is None:
            raise ValueError("Option value cannot be None")
        if not self.__xbee_device.is_open():
            raise XBeeException("XBee device must be open")

        # If the socket is not created, create it first.
        if self.__socket_id is None:
            self.__create_socket()

        # Create, send and check the socket option packet.
        option_packet = SocketOptionRequestPacket(self.__xbee_device.get_next_frame_id(), self.__socket_id,
                                                  option, value)
        response_packet = self.__xbee_device.send_packet_sync_and_get_response(option_packet,
                                                                               timeout=self.__get_timeout())
        self.__check_response(response_packet)

    def getsocketopt(self, option):
        """
        Returns the value of the given socket option.

        Args:
            option (:class:`.SocketOption`): the socket option to get its value.

        Returns:
            Bytearray: the value of the socket option.

        Raises:
            TimeoutException: if the socket option response is not received in the configured timeout.
            ValueError: if the option to set is ``None``.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket option response status is not ``SUCCESS``.
        """
        if option is None:
            raise ValueError("Option to get cannot be None")
        if not self.__xbee_device.is_open():
            raise XBeeException("XBee device must be open")

        # If the socket is not created, create it first.
        if self.__socket_id is None:
            self.__create_socket()

        # Create, send and check the socket option packet.
        option_packet = SocketOptionRequestPacket(self.__xbee_device.get_next_frame_id(), self.__socket_id, option)
        response_packet = self.__xbee_device.send_packet_sync_and_get_response(option_packet,
                                                                               timeout=self.__get_timeout())
        self.__check_response(response_packet)

        # Return the option data.
        return response_packet.option_data

    def add_socket_state_callback(self, callback):
        """
        Adds a callback for the event :class:`digi.xbee.reader.SocketStateReceived`.

        Args:
            callback (Function): the callback. Receives two arguments.

                * The socket ID as an Integer.
                * The state received as a :class:`.SocketState`
        """
        self.__xbee_device.add_socket_state_received_callback(callback)

    def del_socket_state_callback(self, callback):
        """
        Deletes a callback for the callback list of :class:`digi.xbee.reader.SocketStateReceived` event.

        Args:
            callback (Function): the callback to delete.

        Raises:
            ValueError: if ``callback`` is not in the callback list of
                :class:`digi.xbee.reader.SocketStateReceived` event.
        """
        self.__xbee_device.del_socket_state_received_callback(callback)

    def get_sock_info(self):
        """
        Returns the information of this socket.

        Returns:
            :class:`.SocketInfo`: The socket information.

        Raises:
            InvalidOperatingModeException: if the XBee device's operating mode is not API or ESCAPED API. This
                method only checks the cached value of the operating mode.
            TimeoutException: if the response is not received before the read timeout expires.
            XBeeException: if the XBee device's serial port is closed.

        .. seealso::
           | :class:`.SocketInfo`
        """
        return self.__xbee_device.get_socket_info(self.__socket_id)

    def __create_socket(self):
        """
        Creates a new socket by sending a :class:`.SocketCreatePacket`.

        Raises:
            TimeoutException: if the response is not received in the configured timeout.
            XBeeSocketException: if the response contains any error.
        """
        # Create, send and check the socket create packet.
        create_packet = SocketCreatePacket(self.__xbee_device.get_next_frame_id(), self.__ip_protocol)
        response_packet = self.__xbee_device.send_packet_sync_and_get_response(create_packet,
                                                                               timeout=self.__get_timeout())
        self.__check_response(response_packet)

        # Store the received socket ID.
        self.__socket_id = response_packet.socket_id

    def __register_state_callback(self):
        """
        Registers the socket state callback to be notified when an error occurs.
        """
        if self.__socket_state_callback is not None:
            return

        def socket_state_callback(socket_id, state):
            if self.__socket_id != socket_id:
                return
            if state != SocketState.CONNECTED:
                self.__connected = False
                self.__socket_id = None
                self.__source_port = None
                self.__data_received = bytearray()
                self.__data_received_from_dict = OrderedDict()
                self.__unregister_state_callback()
                self.__unregister_data_received_callback()
                self.__unregister_data_received_from_callback()

        self.__socket_state_callback = socket_state_callback
        self.__xbee_device.add_socket_state_received_callback(socket_state_callback)

    def __unregister_state_callback(self):
        """
        Unregisters the socket state callback.
        """
        if self.__socket_state_callback is None:
            return

        self.__xbee_device.del_socket_state_received_callback(self.__socket_state_callback)
        self.__socket_state_callback = None

    def __register_data_received_callback(self):
        """
        Registers the data received callback to be notified when data is received in the socket.
        """
        if self.__data_received_callback is not None:
            return

        def data_received_callback(socket_id, payload):
            if self.__socket_id != socket_id:
                return

            self.__data_received_lock.acquire()
            self.__data_received += payload
            self.__data_received_lock.release()

        self.__data_received_callback = data_received_callback
        self.__xbee_device.add_socket_data_received_callback(data_received_callback)

    def __unregister_data_received_callback(self):
        """
        Unregisters the data received callback.
        """
        if self.__data_received_callback is None:
            return

        self.__xbee_device.del_socket_data_received_callback(self.__data_received_callback)
        self.__data_received_callback = None

    def __register_data_received_from_callback(self):
        """
        Registers the data received from callback to be notified when data from a specific address is received
        in the socket.
        """
        if self.__data_received_from_callback is not None:
            return

        def data_received_from_callback(socket_id, address, payload):
            if self.__socket_id != socket_id:
                return

            payload_added = False
            # Check if the address already exists in the dictionary to append the payload or insert a new entry.
            self.__data_received_from_dict_lock.acquire()
            for addr in self.__data_received_from_dict.keys():
                if addr[0] == address[0] and addr[1] == address[1]:
                    self.__data_received_from_dict[addr] += payload
                    payload_added = True
                    break
            if not payload_added:
                self.__data_received_from_dict[address] = payload
            self.__data_received_from_dict_lock.release()

        self.__data_received_from_callback = data_received_from_callback
        self.__xbee_device.add_socket_data_received_from_callback(data_received_from_callback)

    def __unregister_data_received_from_callback(self):
        """
        Unregisters the data received from callback.
        """
        if self.__data_received_from_callback is None:
            return

        self.__xbee_device.del_socket_data_received_from_callback(self.__data_received_from_callback)
        self.__data_received_from_callback = None

    def __send(self, data, send_all=True):
        """
        Sends data to the socket. The socket must be connected to a remote socket. Depending on the value of
        ``send_all``, the method will raise an exception or return the number of bytes sent when there is an error
        sending a data packet.

        Args:
            data (Bytearray): the data to send.
            send_all (Boolean): ``True`` to raise an exception when there is an error sending a data packet. ``False``
                to return the number of bytes sent when there is an error sending a data packet.

        Raises:
            TimeoutException: if the send status response is not received in the configured timeout.
            ValueError: if the data to send is ``None``.
            ValueError: if the number of bytes to send is ``0``.
            XBeeException: if the connection with the XBee device is not open.
            XBeeSocketException: if the socket is not valid.
            XBeeSocketException: if the send status is not ``SUCCESS``.
            XBeeSocketException: if the socket is not open.
        """
        if data is None:
            raise ValueError("Data to send cannot be None")
        if len(data) == 0:
            raise ValueError("The number of bytes to send must be at least 1")
        if self.__socket_id is None:
            raise XBeeSocketException(status=SocketStatus.BAD_SOCKET)
        if not self.__xbee_device.is_open():
            raise XBeeException("XBee device must be open")
        if not self.__connected:
            raise XBeeSocketException(message="Socket is not connected")

        sent_bytes = None if send_all else 0

        # Send as many packets as needed to deliver all the provided data.
        for chunk in self.__split_payload(data):
            send_packet = SocketSendPacket(self.__xbee_device.get_next_frame_id(), self.__socket_id, chunk)
            try:
                response_packet = self.__xbee_device.send_packet_sync_and_get_response(send_packet,
                                                                                       timeout=self.__get_timeout())
                self.__check_response(response_packet)
            except (TimeoutException, XBeeSocketException) as e:
                # Raise the exception only if 'send_all' flag is set, otherwise return the number of bytes sent.
                if send_all:
                    raise e
                return sent_bytes
            # Increase the number of bytes sent.
            if not send_all:
                sent_bytes += len(chunk)
        # Return the number of bytes sent.
        return sent_bytes

    def __is_connected(self):
        """
        Returns whether the socket is connected or not.

        Returns:
            Boolean: ``True`` if the socket is connected ``False`` otherwise.
        """
        return self.__connected

    @staticmethod
    def __check_response(response_packet):
        """
        Checks the status of the given response packet and throws an :class:`.XBeeSocketException` if it is not
        :attr:`SocketStatus.SUCCESS`.

        Args:
            response_packet (:class:`.XBeeAPIPacket`): the socket response packet.

        Raises:
            XBeeSocketException: if the socket status is not ``SUCCESS``.
        """
        if isinstance(response_packet, TXStatusPacket):
            if response_packet.transmit_status != TransmitStatus.SUCCESS:
                raise XBeeSocketException(status=response_packet.transmit_status)
        elif response_packet.status != SocketStatus.SUCCESS:
            raise XBeeSocketException(status=response_packet.status)

    @staticmethod
    def __split_payload(payload, size=__MAX_PAYLOAD_BYTES):
        """
        Splits the given array of bytes in chunks of the specified size.

        Args:
            payload (Bytearray): the data to split.
            size (Integer, Optional): the size of the chunks.

        Returns:
            Generator: the generator with all the chunks.
        """
        for i in range(0, len(payload), size):
            yield payload[i:i + size]

    def __get_timeout(self):
        """
        Returns the socket timeout in seconds based on the blocking state.

        Returns:
             Integer: the socket timeout in seconds if the socket is configured to be non blocking or ``-1`` if the
                socket is configured to be blocking.
        """
        return -1 if self.getblocking() else self.__timeout

    is_connected = property(__is_connected)
    """Boolean. Indicates whether the socket is connected or not."""
