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

from digi.xbee.models.protocol import IPProtocol
from digi.xbee.models.status import SocketInfoState
from digi.xbee.util import utils


class SocketInfo:
    """
    This class represents the information of an XBee socket:

      * Socket ID.
      * State.
      * Protocol.
      * Local port.
      * Remote port.
      * Remote address.
    """

    __SEPARATOR = "\r"
    __LIST_LENGTH = 6

    def __init__(self, socket_id, state, protocol, local_port, remote_port, remote_address):
        """
        Class constructor. Instantiates a ``SocketInfo`` object with the given parameters.

        Args:
            socket_id (Integer): The ID of the socket.
            state (:class:`.SocketInfoState`): The state of the socket.
            protocol (:class:`.IPProtocol`):  The protocol of the socket.
            local_port (Integer): The local port of the socket.
            remote_port (Integer): The remote port of the socket.
            remote_address (String): The remote IPv4 address of the socket.
        """
        self.__socket_id = socket_id
        self.__state = state
        self.__protocol = protocol
        self.__local_port = local_port
        self.__remote_port = remote_port
        self.__remote_address = remote_address

    @staticmethod
    def create_socket_info(raw):
        """
        Parses the given bytearray data and returns a ``SocketInfo`` object.

        Args:
            raw (Bytearray): received data from the ``SI`` command with a socket ID as argument.

        Returns:
            :class:`.SocketInfo`: The socket information, or ``None`` if the provided data is invalid.
        """
        info_array = bytearray.fromhex(utils.hex_to_string(raw)).decode("utf8").strip().split(SocketInfo.__SEPARATOR)
        if len(info_array) != SocketInfo.__LIST_LENGTH:
            return None
        socket_id = int(info_array[0], 0)
        state = SocketInfoState.get_by_description(info_array[1])
        protocol = IPProtocol.get_by_description(info_array[2])
        local_port = int(info_array[3], 0)
        remote_port = int(info_array[4], 0)
        remote_address = info_array[5]
        return SocketInfo(socket_id, state, protocol, local_port, remote_port, remote_address)

    @staticmethod
    def parse_socket_list(raw):
        """
        Parses the given bytearray data and returns a list with the active socket IDs.

        Args:
            raw (Bytearray): received data from the ``SI`` command.

        Returns:
            List: list with the IDs of all active (open) sockets, or empty list if there is not any active socket.
        """
        socket_list = list()
        ids_array = bytearray.fromhex(utils.hex_to_string(raw)).decode("utf8").strip().split(SocketInfo.__SEPARATOR)
        for x in ids_array:
            if x != "":
                socket_list.append(int(x, 0))
        return socket_list

    def __get_socket_id(self):
        """
        Returns the ID of the socket.

        Returns:
            Integer: the ID of the socket.
        """
        return self.__socket_id

    def __get_state(self):
        """
        Returns the state of the socket.

        Returns:
            :class:`.SocketInfoState`: the state of the socket.
        """
        return self.__state

    def __get_protocol(self):
        """
        Returns the protocol of the socket.

        Returns:
            :class:`.IPProtocol`: the protocol of the socket.
        """
        return self.__protocol

    def __get_local_port(self):
        """
        Returns the local port of the socket.

        Returns:
            Integer: the local port of the socket.
        """
        return self.__local_port

    def __get_remote_port(self):
        """
        Returns the remote port of the socket.

        Returns:
            Integer: the remote port of the socket.
        """
        return self.__remote_port

    def __get_remote_address(self):
        """
        Returns the remote IPv4 address of the socket.

        Returns:
            String: the remote IPv4 address of the socket.
        """
        return self.__remote_address

    def __str__(self):
        return "ID:             0x%s\n" \
               "State:          %s\n" \
               "Protocol:       %s\n" \
               "Local port:     0x%s\n" \
               "Remote port:    0x%s\n" \
               "Remote address: %s"\
               % (utils.hex_to_string(utils.int_to_bytes(self.__socket_id, num_bytes=1), False),
                  self.__state.description, self.__protocol.description,
                  utils.hex_to_string(utils.int_to_bytes(self.__local_port, num_bytes=2), False),
                  utils.hex_to_string(utils.int_to_bytes(self.__remote_port, num_bytes=2), False),
                  self.__remote_address)

    socket_id = property(__get_socket_id)
    """Integer. The ID of the socket."""

    state = property(__get_state)
    """:class:`.SocketInfoState`: The state of the socket."""

    protocol = property(__get_protocol)
    """:class:`.IPProtocol`: The protocol of the socket."""

    local_port = property(__get_local_port)
    """Integer: The local port of the socket. This is 0 unless the socket is explicitly bound to a port."""

    remote_port = property(__get_remote_port)
    """Integer: The remote port of the socket."""

    remote_address = property(__get_remote_address)
    """String: The remote IPv4 address of the socket. This is ``0.0.0.0`` for an unconnected socket."""
