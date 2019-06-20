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

import re


class XBeeMessage(object):
    """
    This class represents a XBee message, which is formed by a :class:`.RemoteXBeeDevice`
    (the sender) and some data (the data sent) as a bytearray.
    """

    def __init__(self, data, remote_device, timestamp, broadcast=False):
        """
        Class  constructor.

        Args:
            data (Bytearray): the data sent.
            remote_device (:class:`.RemoteXBeeDevice`): the sender.
            broadcast (Boolean, optional, default=``False``): flag indicating whether the  message is
                broadcast (``True``) or not (``False``). Optional.
            timestamp: instant of time when the message was received.
        """
        self.__data = data
        self.__remote_device = remote_device
        self.__is_broadcast = broadcast
        self.__timestamp = timestamp

    def __get_data(self):
        """
        Returns the data of the message.

        Returns:
            Bytearray: the data of the message.
        """
        return self.__data

    def __get_remote_device(self):
        """
        Returns the device which has sent the message.

        Returns:
            :class:`.RemoteXBeeDevice`: the device which has sent the message.
        """
        return self.__remote_device

    def __is_broadcast(self):
        """
        Returns whether the message is broadcast or not.

        Returns:
            Boolean: ``True`` if the message is broadcast, ``False`` otherwise.
        """
        return self.__is_broadcast

    def __get_timestamp(self):
        """
        Returns the moment when the message was received as a ``time.time()``
        function returned value.

        Returns:
            Float: the returned value of using :meth:`time.time()` function when the message was received.
        """
        return self.__timestamp

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"Data: ":        self.__data,
                "Sender: ":      str(self.__remote_device.get_64bit_addr()),
                "Broadcast: ":   self.__is_broadcast,
                "Received at: ": self.__timestamp}

    data = property(__get_data)
    """Bytearray. Bytearray containing the data of the message."""

    remote_device = property(__get_remote_device)
    """:class:`.RemoteXBeeDevice`. The device that has sent the message."""

    is_broadcast = property(__is_broadcast)
    """Boolean. ``True`` to indicate that the message is broadcast, ``False`` otherwise."""
    
    timestamp = property(__get_timestamp)
    """Integer. Instant of time when the message was received."""


class ExplicitXBeeMessage(XBeeMessage):
    """
    This class represents an Explicit XBee message, which is formed by all parameters of a common XBee message and:
    Source endpoint, destination endpoint, cluster ID, profile ID.
    """

    def __init__(self, data, remote_device, timestamp, source_endpoint,
                 dest_endpoint, cluster_id, profile_id, broadcast=False):
        """
        Class constructor.

        Args:
            data (Bytearray): the data sent.
            remote_device (:class:`.RemoteXBeeDevice`): the sender device.
            timestamp: instant of time when the message was received.
            source_endpoint (Integer): source endpoint of the message. 1 byte.
            dest_endpoint (Integer): destination endpoint of the message. 1 byte.
            cluster_id (Integer): cluster id of the message. 2 bytes.
            profile_id (Integer): profile id of the message. 2 bytes.
            broadcast (Boolean, optional, default=``False``): flag indicating whether the message is
                broadcast (``True``) or not (``False``). Optional.
        """
        XBeeMessage.__init__(self, data, remote_device, timestamp, broadcast)
        self.__source_endpoint = source_endpoint
        self.__dest_endpoint = dest_endpoint
        self.__cluster_id = cluster_id
        self.__profile_id = profile_id

    def __get_source_endpoint(self):
        """
        Returns the source endpoint of the message.

        Returns:
            Integer: the source endpoint of the message. 1 byte.
        """
        return self.__source_endpoint

    def __get_dest_endpoint(self):
        """
        Returns the destination endpoint of the message.

        Returns:
            Integer: the destination endpoint of the message. 1 byte.
        """
        return self.__dest_endpoint

    def __get_cluster_id(self):
        """
        Returns the cluster ID of the message.

        Returns:
            Integer: the cluster ID of the message. 2 bytes.
        """
        return self.__cluster_id

    def __get_profile_id(self):
        """
        Returns the profile ID of the message.

        Returns:
            Integer: the profile ID of the message. 2 bytes.
        """
        return self.__profile_id

    def __set_source_endpoint(self, source_endpoint):
        """
        Sets the source endpoint of the message.

        Args:
            source_endpoint (Integer): the new source endpoint of the message.
        """
        self.__source_endpoint = source_endpoint

    def __set_dest_endpoint(self, dest_endpoint):
        """
         Sets the destination endpoint of the message.

         Args:
             dest_endpoint (Integer): the new destination endpoint of the message.
         """
        self.__dest_endpoint = dest_endpoint

    def __set_cluster_id(self, cluster_id):
        """
         Sets the cluster ID of the message.

         Args:
             cluster_id (Integer): the new cluster ID of the message.
         """
        self.__cluster_id = cluster_id

    def __set_profile_id(self, profile_id):
        """
         Sets the profile ID of the message.

         Args:
             profile_id (Integer): the new profile ID of the message.
         """
        self.__profile_id = profile_id

    def to_dict(self):
        dc = XBeeMessage.to_dict(self)
        dc.update({"Src_endpoint":  self.__source_endpoint,
                   "Dest_endpoint": self.__dest_endpoint,
                   "Cluster_id":    self.__cluster_id,
                   "Profile_id":    self.__profile_id})
        return dc

    source_endpoint = property(__get_source_endpoint, __set_source_endpoint)
    """Integer. The source endpoint of the message"""

    dest_endpoint = property(__get_dest_endpoint, __set_dest_endpoint)
    """Integer. The destination endpoint of the message"""

    cluster_id = property(__get_cluster_id, __set_cluster_id)
    """Integer. The Cluster ID of the message."""

    profile_id = property(__get_profile_id, __set_profile_id)
    """Integer. The profile ID of the message."""


class IPMessage(object):
    """
    This class represents an IP message containing the IP address the message belongs to, the source and destination
    ports, the IP protocol, and the content (data) of the message.
    """

    def __init__(self, ip_addr, source_port, dest_port, protocol, data):
        """
        Class  constructor.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address the message comes from.
            source_port (Integer): TCP or UDP source port of the transmission.
            dest_port (Integer): TCP or UDP destination port of the transmission.
            protocol (:class:`.IPProtocol`): IP protocol used in the transmission.
            data (Bytearray): the data sent.

        Raises:
            ValueError: if ``ip_addr`` is ``None``.
            ValueError: if ``protocol`` is ``None``.
            ValueError: if ``data`` is ``None``.
            ValueError: if ``source_port`` is less than 0 or greater than 65535.
            ValueError: if ``dest_port`` is less than 0 or greater than 65535.
        """
        if ip_addr is None:
            raise ValueError("IP address cannot be None")
        if protocol is None:
            raise ValueError("Protocol cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if not 0 <= source_port <= 65535:
            raise ValueError("Source port must be between 0 and 65535")
        if not 0 <= dest_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        self.__ip_addr = ip_addr
        self.__source_port = source_port
        self.__dest_port = dest_port
        self.__protocol = protocol
        self.__data = data

    def __get_ip_addr(self):
        """
        Returns the IPv4 address this message is associated to.

        Returns:
            :class:`ipaddress.IPv4Address`: The IPv4 address this message is associated to.
        """
        return self.__ip_addr

    def __get_source_port(self):
        """
        Returns the source port of the transmission.

        Returns:
            Integer: The source port of the transmission.
        """
        return self.__source_port

    def __get_dest_port(self):
        """
        Returns the destination port of the transmission.

        Returns:
            Integer: The destination port of the transmission.
        """
        return self.__dest_port

    def __get_protocol(self):
        """
        Returns the protocol used in the transmission.

        Returns:
            :class:`.IPProtocol`: The protocol used in the transmission.
        """
        return self.__protocol

    def __get_data(self):
        """
        Returns the data of the message.

        Returns:
            Bytearray: the data of the message.
        """
        return self.__data

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"IP address: ":       self.__ip_addr,
                "Source port: ":      self.__source_port,
                "Destination port: ": self.__dest_port,
                "Protocol: ":         self.__protocol,
                "Data: ":             self.__data}

    ip_addr = property(__get_ip_addr)
    """:class:`ipaddress.IPv4Address`. The IPv4 address this message is associated to."""

    source_port = property(__get_source_port)
    """Integer. The source port of the transmission."""

    dest_port = property(__get_dest_port)
    """Integer. The destination port of the transmission."""

    protocol = property(__get_protocol)
    """:class:`.IPProtocol`. The protocol used in the transmission."""

    data = property(__get_data)
    """Bytearray. Bytearray containing the data of the message."""


class SMSMessage(object):
    """
    This class represents an SMS message containing the phone number that sent
    the message and the content (data) of the message.

    This class is used within the library to read SMS sent to Cellular devices.
    """

    __PHONE_NUMBER_PATTERN = "^\+?\d+$"

    def __init__(self, phone_number, data):
        """
        Class  constructor. Instantiates a new :class:`.SMSMessage` object with the provided parameters.

        Args:
            phone_number (String): The phone number that sent the message.
            data (String): The message text.

        Raises:
            ValueError: if ``phone_number`` is ``None``.
            ValueError: if ``data`` is ``None``.
            ValueError: if ``phone_number`` is not a valid phone number.
        """
        if phone_number is None:
            raise ValueError("Phone number cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")
        if not re.compile(SMSMessage.__PHONE_NUMBER_PATTERN).match(phone_number):
            raise ValueError("Invalid phone number")

        self.__phone_number = phone_number
        self.__data = data

    def __get_phone_number(self):
        """
        Returns the phone number that sent the message.

        Returns:
            String: The phone number that sent the message.
        """
        return self.__phone_number

    def __get_data(self):
        """
        Returns the data of the message.

        Returns:
            String: The data of the message.
        """
        return self.__data

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"Phone number: ": self.__phone_number,
                "Data: ":         self.__data}

    phone_number = property(__get_phone_number)
    """String. The phone number that sent the message."""

    data = property(__get_data)
    """String. The data of the message."""


class UserDataRelayMessage(object):
    """
    This class represents a user data relay message containing the source
    interface and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeLocalInterface`
    """

    def __init__(self, local_interface, data):
        """
        Class constructor. Instantiates a new :class:`.UserDataRelayMessage` object with
        the provided parameters.

        Args:
            local_interface (:class:`.XBeeLocalInterface`): The source XBee local interface.
            data (Bytearray): Byte array containing the data of the message.

        Raises:
            ValueError: if ``relay_interface`` is ``None``.

        .. seealso::
            | :class:`.XBeeLocalInterface`
        """
        if local_interface is None:
            raise ValueError("XBee local interface cannot be None")

        self.__local_interface = local_interface
        self.__data = data

    def __get_src_interface(self):
        """
        Returns the source interface that sent the message.

        Returns:
            :class:`.XBeeLocalInterface`: The source interface that sent the message.
        """
        return self.__local_interface

    def __get_data(self):
        """
        Returns the data of the message.

        Returns:
            Bytearray: The data of the message.
        """
        return self.__data

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"XBee local interface: ": self.__local_interface,
                "Data: ":                 self.__data}

    local_interface = property(__get_src_interface)
    """:class:`.XBeeLocalInterface`. Source interface that sent the message."""

    data = property(__get_data)
    """Bytearray. The data of the message."""
