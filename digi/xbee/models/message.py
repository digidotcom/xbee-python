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

import re
from digi.xbee.models.status import BLEMACAddressType, BLEGAPScanStatus


class XBeeMessage:
    """
    This class represents a XBee message, which is formed by a :class:`.RemoteXBeeDevice`
    (the sender) and some data (the data sent) as a bytearray.
    """

    def __init__(self, data, remote_node, timestamp, broadcast=False):
        """
        Class  constructor.

        Args:
            data (Bytearray): the data sent.
            remote_node (:class:`.RemoteXBeeDevice`): the sender.
            broadcast (Boolean, optional, default=`False`): flag indicating whether the  message is
                broadcast (`True`) or not (`False`). Optional.
            timestamp: instant of time when the message was received.
        """
        self.__data = data
        self.__remote_node = remote_node
        self.__is_broadcast = broadcast
        self.__timestamp = timestamp

    @property
    def data(self):
        """
        Returns a bytearray containing the data of the message.

        Returns:
            Bytearray: the data of the message.
        """
        return self.__data

    @property
    def remote_device(self):
        """
        Returns the device which has sent the message.

        Returns:
            :class:`.RemoteXBeeDevice`: the device which has sent the message.
        """
        return self.__remote_node

    @property
    def is_broadcast(self):
        """
        Returns whether the message is broadcast or not.

        Returns:
            Boolean: `True` if the message is broadcast, `False` otherwise.
        """
        return self.__is_broadcast

    @property
    def timestamp(self):
        """
        Returns the moment when the message was received as a `time.time()`
        function returned value.

        Returns:
            Float: the returned value of using :meth:`time.time()` function
                when the message was received.
        """
        return self.__timestamp

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"Data: ":        self.__data,
                "Sender: ":      str(self.__remote_node.get_64bit_addr()),
                "Broadcast: ":   self.__is_broadcast,
                "Received at: ": self.__timestamp}


class ExplicitXBeeMessage(XBeeMessage):
    """
    This class represents an Explicit XBee message, which is formed by all
    parameters of a common XBee message and: Source endpoint, destination
    endpoint, cluster ID, profile ID.
    """

    def __init__(self, data, remote_node, timestamp, src_endpoint,
                 dest_endpoint, cluster_id, profile_id, broadcast=False):
        """
        Class constructor.

        Args:
            data (Bytearray): the data sent.
            remote_node (:class:`.RemoteXBeeDevice`): the sender device.
            timestamp: instant of time when the message was received.
            src_endpoint (Integer): source endpoint of the message. 1 byte.
            dest_endpoint (Integer): destination endpoint of the message. 1 byte.
            cluster_id (Integer): cluster id of the message. 2 bytes.
            profile_id (Integer): profile id of the message. 2 bytes.
            broadcast (Boolean, optional, default=`False`): flag indicating whether the message is
                broadcast (`True`) or not (`False`). Optional.
        """
        XBeeMessage.__init__(self, data, remote_node, timestamp, broadcast)
        self.__src_ed = src_endpoint
        self.__dest_ed = dest_endpoint
        self.__cluster_id = cluster_id
        self.__profile_id = profile_id

    @property
    def source_endpoint(self):
        """
        Returns the source endpoint of the message.

        Returns:
            Integer: the source endpoint of the message. 1 byte.
        """
        return self.__src_ed

    @property
    def dest_endpoint(self):
        """
        Returns the destination endpoint of the message.

        Returns:
            Integer: the destination endpoint of the message. 1 byte.
        """
        return self.__dest_ed

    @property
    def cluster_id(self):
        """
        Returns the cluster ID of the message.

        Returns:
            Integer: the cluster ID of the message. 2 bytes.
        """
        return self.__cluster_id

    @property
    def profile_id(self):
        """
        Returns the profile ID of the message.

        Returns:
            Integer: the profile ID of the message. 2 bytes.
        """
        return self.__profile_id

    @source_endpoint.setter
    def source_endpoint(self, source_endpoint):
        """
        Sets the source endpoint of the message.

        Args:
            source_endpoint (Integer): the new source endpoint of the message.
        """
        self.__src_ed = source_endpoint

    @dest_endpoint.setter
    def dest_endpoint(self, dest_endpoint):
        """
         Sets the destination endpoint of the message.

         Args:
             dest_endpoint (Integer): the new destination endpoint of the message.
         """
        self.__dest_ed = dest_endpoint

    @cluster_id.setter
    def cluster_id(self, cluster_id):
        """
         Sets the cluster ID of the message.

         Args:
             cluster_id (Integer): the new cluster ID of the message.
         """
        self.__cluster_id = cluster_id

    @profile_id.setter
    def profile_id(self, profile_id):
        """
         Sets the profile ID of the message.

         Args:
             profile_id (Integer): the new profile ID of the message.
         """
        self.__profile_id = profile_id

    def to_dict(self):
        msg_dict = XBeeMessage.to_dict(self)
        msg_dict.update({"Src_endpoint":  self.__src_ed,
                         "Dest_endpoint": self.__dest_ed,
                         "Cluster_id":    self.__cluster_id,
                         "Profile_id":    self.__profile_id})
        return msg_dict


class IPMessage:
    """
    This class represents an IP message containing the IP address the message
    belongs to, the source and destination ports, the IP protocol, and the
    content (data) of the message.
    """

    def __init__(self, ip_addr, src_port, dest_port, protocol, data):
        """
        Class  constructor.

        Args:
            ip_addr (:class:`ipaddress.IPv4Address`): The IP address the message comes from.
            src_port (Integer): TCP or UDP source port of the transmission.
            dest_port (Integer): TCP or UDP destination port of the transmission.
            protocol (:class:`.IPProtocol`): IP protocol used in the transmission.
            data (Bytearray): the data sent.

        Raises:
            ValueError: if `ip_addr` is `None`.
            ValueError: if `protocol` is `None`.
            ValueError: if `data` is `None`.
            ValueError: if `source_port` is less than 0 or greater than 65535.
            ValueError: if `dest_port` is less than 0 or greater than 65535.
        """
        if ip_addr is None:
            raise ValueError("IP address cannot be None")
        if protocol is None:
            raise ValueError("Protocol cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")

        if not 0 <= src_port <= 65535:
            raise ValueError("Source port must be between 0 and 65535")
        if not 0 <= dest_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")

        self.__ip_addr = ip_addr
        self.__src_port = src_port
        self.__dest_port = dest_port
        self.__protocol = protocol
        self.__data = data

    @property
    def ip_addr(self):
        """
        Returns the IPv4 address this message is associated to.

        Returns:
            :class:`ipaddress.IPv4Address`: The IPv4 address this message is associated to.
        """
        return self.__ip_addr

    @property
    def source_port(self):
        """
        Returns the source port of the transmission.

        Returns:
            Integer: The source port of the transmission.
        """
        return self.__src_port

    @property
    def dest_port(self):
        """
        Returns the destination port of the transmission.

        Returns:
            Integer: The destination port of the transmission.
        """
        return self.__dest_port

    @property
    def protocol(self):
        """
        Returns the protocol used in the transmission.

        Returns:
            :class:`.IPProtocol`: The protocol used in the transmission.
        """
        return self.__protocol

    @property
    def data(self):
        """
        Returns a bytearray containing the data of the message.

        Returns:
            Bytearray: the data of the message.
        """
        return self.__data

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"IP address: ":       self.__ip_addr,
                "Source port: ":      self.__src_port,
                "Destination port: ": self.__dest_port,
                "Protocol: ":         self.__protocol,
                "Data: ":             self.__data}


class SMSMessage:
    """
    This class represents an SMS message containing the phone number that sent
    the message and the content (data) of the message.

    This class is used within the library to read SMS sent to Cellular devices.
    """

    __PHONE_NUMBER_PATTERN = r"^\+?\d+$"

    def __init__(self, phone_number, data):
        """
        Class  constructor. Instantiates a new :class:`.SMSMessage` object with
        the provided parameters.

        Args:
            phone_number (String): The phone number that sent the message.
            data (String): The message text.

        Raises:
            ValueError: if `phone_number` is `None`.
            ValueError: if `data` is `None`.
            ValueError: if `phone_number` is not a valid phone number.
        """
        if phone_number is None:
            raise ValueError("Phone number cannot be None")
        if data is None:
            raise ValueError("Data cannot be None")
        if not re.compile(SMSMessage.__PHONE_NUMBER_PATTERN).match(phone_number):
            raise ValueError("Invalid phone number")

        self.__phone_number = phone_number
        self.__data = data

    @property
    def phone_number(self):
        """
        Returns the phone number that sent the message.

        Returns:
            String: The phone number that sent the message.
        """
        return self.__phone_number

    @property
    def data(self):
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


class UserDataRelayMessage:
    """
    This class represents a user data relay message containing the source
    interface and the content (data) of the message.

    .. seealso::
       | :class:`.XBeeLocalInterface`
    """

    def __init__(self, local_iface, data):
        """
        Class constructor. Instantiates a new :class:`.UserDataRelayMessage`
        object with the provided parameters.

        Args:
            local_iface (:class:`.XBeeLocalInterface`): The source XBee local interface.
            data (Bytearray): Byte array containing the data of the message.

        Raises:
            ValueError: if `relay_interface` is `None`.

        .. seealso::
            | :class:`.XBeeLocalInterface`
        """
        if local_iface is None:
            raise ValueError("XBee local interface cannot be None")

        self.__local_iface = local_iface
        self.__data = data

    @property
    def local_interface(self):
        """
        Returns the source interface that sent the message.

        Returns:
            :class:`.XBeeLocalInterface`: The source interface that sent the message.
        """
        return self.__local_iface

    @property
    def data(self):
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
        return {"XBee local interface: ": self.__local_iface,
                "Data: ":                 self.__data}


class _BLEGAPScanBaseAdvertisementMessage:
    """
    This class represents a base BLE advertising message.
    It will contain a common set of values that all BLE advertising
    messages will have.
    This includes:
        The address that the message was received from.
        The type of address it is.
        Whether the device is connectable or not.
        The RSSI of the advertisement.
        The Local/Short name embedded into the payload, if any.
    """

    def __init__(self, address, address_type, advertisement_flags, rssi,
                 payload):
        """
        Class  constructor.

        Args:
            address (:class:`.XBeeBLEAddress`): The BLE address the message
                                                comes from.
            address_type (Integer): The type of BLE address.
            advertisement_flags (Integer): Flags.  Includes whether
                                           connectable or not.
            rssi (Float): The received signal strength of the advertisement,
                          in dBm.
            payload (Bytearray): The data payload of the advertisement.

        Raises:
            ValueError: if `address` is `None`.
            ValueError: if `address_type` is `None`.
            ValueError: if `advertisement_flags` is `None`.
            ValueError: if `rssi` is `None`.
            ValueError: if `payload` is `None`.
        """
        if address is None:
            raise ValueError("BLE address cannot be None")
        if address_type is None:
            raise ValueError("BLE address type cannot be None")
        if advertisement_flags is None:
            raise ValueError("BLE advertisement flags cannot be None")
        if rssi is None:
            raise ValueError("RSSI cannot be None")
        if payload is None:
            raise ValueError("Payload cannot be None")

        self.__address = address
        # Address type comes in as Integer, convert to BLEMACAddressType
        self.__address_type = BLEMACAddressType.get(address_type)
        self.__connectable = bool(advertisement_flags & 0x1)
        self.__rssi = -float(rssi)
        self.__payload = payload
        self.__name = None

        # Attempt to find a Local or Short name, if it exists.
        ltv = self.__find_advertising_str()
        if ltv >= 0:
            # Found a Local/Short name LTV (Length-Type-Value)

            # Length is the first byte
            length = self.__payload[ltv]
            # Jump over Length and Type to get to the name
            start = ltv + 2
            # Mark finish
            finish = ltv + length + 1
            # Extract name as a string from the payload
            self.__name = self.__payload[start:finish].decode(
                          encoding='utf8', errors='ignore')

    def __find_advertising_str(self):
        """
        The Advertising data(AD) is formatted as follows: 1st byte length,
        2nd byte AD type, and  AD DATA.

        Returns:
            Integer: Location in the payload of where to find the start of the
                     advertising data's LTV (Length-type-value).
                     Returns -1 if no advertising data LTV was found.
        """
        # Check if payload length is less then 2 bytes, if so
        # it can't possibly contain an advertising string.
        if len(self.__payload) < 2:
            return -1
        # Walk payload
        offset = 0
        while offset < len(self.__payload):
            # Get the LTV type
            typ = self.__payload[offset + 1]
            if typ in (0x08, 0x09):
                # Found a Long/Short name LTV type, return it
                return offset
            if self.__payload[offset] == 0x00:
                # NULL Byte, no LTV's, return -1
                return -1

            # Jump to the next LTV
            offset += self.__payload[offset] + 1

        # Didn't find anything
        return -1

    @property
    def address(self):
        """
        Returns the BLE MAC address of the sender of the advertisement.

        Returns:
            :class:`.XBeeBLEAddress`: the BLE address of the sender.
        """
        return self.__address

    @property
    def address_type(self):
        """
        Returns the type of BLE address of the sender.

        Returns:
            :class:`.BLEMACAddressType`: The type of BLE address.
        """
        return self.__address_type

    @property
    def connectable(self):
        """
        Returns if the advertising device indicates that BLE central-mode
        devices may connect to it.

        Returns:
            Boolean: `True` if connectable, `False` otherwise.
        """
        return self.__connectable

    @property
    def rssi(self):
        """
        Returns the received signal strength of the advertisement, in dBm.

        Returns:
            Integer: The RSSI value.
        """
        return self.__rssi

    @property
    def name(self):
        """
        Returns the Local/Short name, if the sender presented one.

        Returns:
            Str: The Local/Short name.
        """
        return self.__name

    @property
    def payload(self):
        """
        Returns a bytearray containing the data of the message.

        Returns:
            Bytearray: the data of the message.
        """
        return self.__payload

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"Address":     str(self.address),
                "Type":        self.address_type.description,
                "Name":        self.name,
                "Connectable": self.connectable,
                "RSSI":        self.rssi,
                "Payload":     self.payload}


class BLEGAPScanLegacyAdvertisementMessage(_BLEGAPScanBaseAdvertisementMessage):
    """
    This class represents a 'Legacy' BLE advertising message, that contains
    the address that the message was received from, the type of address it is,
    whether the device is connectable or not, the RSSI of the advertisement,
    and the payload that was sent.
    """


class BLEGAPScanExtendedAdvertisementMessage(_BLEGAPScanBaseAdvertisementMessage):
    """
    This class represents an 'Extended' BLE advertising message, that contains
    the address that the message was received from, the type of address it is,
    whether the device is connectable or not, the RSSI of the advertisement,
    and the payload that was sent.
    """

    def __init__(self, address, address_type, advertisement_flags, rssi,
                 advertisement_set_id, primary_phy, secondary_phy,
                 tx_power, periodic_interval, data_completeness, payload):
        """
        Class  constructor.

        Args:
            address (:class:`.XBeeBLEAddress`): The BLE address the message
                                                comes from.
            address_type (Integer): The type of BLE address.
            advertisement_flags (Integer): Flags.  Includes whether
                                           connectable or not.
            rssi (Float): The received signal strength of the advertisement,
                          in dBm.
            advertisement_set_id (Integer): A device can broadcast multiple
                                            advertisements at a time.
                                            The set identifier will help identify
                                            which advertisement you received.
            primary_phy (Integer): This is the preferred PHY for connecting
                                   with this device. Values are:
                                   0x1: 1M PHY
                                   0x2: 2M PHY
                                   0x4: LE Coded PHY 125k
                                   0x8: LE Coded PHY 500k
                                   0xFF : Any PHY supported
            secondary_phy (Integer): This is the secondary PHY for connecting
                                     with this device.
                                     This has the same values as `primary_phy`.
            tx_power (Integer): Transmission power of received advertisement.
                                This is a signed value.
            periodic_interval (Integer): Interval for periodic advertising.
                                         0 indicates no periodic advertising.
                                         Interval value is in increments of
                                         1.25 ms.
            data_completeness (Integer): Values are:
                0x0: indicates all data of the advertisement has been reported.
                0x1: Data is incomplete, but more data will follow.
                0x2: Data is incomplete, but no more data is following. Data has be truncated.
            payload (Bytearray): The data payload of the advertisement.

        Raises:
            ValueError: if `address` is `None`.
            ValueError: if `address_type` is `None`.
            ValueError: if `advertisement_flags` is `None`.
            ValueError: if `rssi` is `None`.
            ValueError: if `advertisement_set_id` is `None`.
            ValueError: if `primary_phy` is `None`.
            ValueError: if `secondary_phy` is `None`.
            ValueError: if `tx_power` is `None`.
            ValueError: if `periodic_interval` is `None`.
            ValueError: if `data_completeness` is `None`.
            ValueError: if `payload` is `None`.
        """
        if advertisement_set_id is None:
            raise ValueError("BLE advertisement set ID cannot be None")
        if primary_phy is None:
            raise ValueError("BLE primary PHY cannot be None")
        if secondary_phy is None:
            raise ValueError("BLE secondary PHY cannot be None")
        if tx_power is None:
            raise ValueError("BLE tx power cannot be None")
        if periodic_interval is None:
            raise ValueError("BLE periodic interval cannot be None")
        if data_completeness is None:
            raise ValueError("BLE data completeness cannot be None")
        if primary_phy not in (0x01, 0x02, 0x04, 0x08, 0xFF):
            raise ValueError("primary_phy must be 1, 2, 4, 8 or 255")
        if secondary_phy not in (0x01, 0x02, 0x04, 0x08, 0xFF):
            raise ValueError("secondary_phy must be 1, 2, 4, 8 or 255")
        if data_completeness not in (0x0, 0x1, 0x2):
            raise ValueError("BLE data completeness must be 0, 1 or 2")

        super().__init__(address, address_type, advertisement_flags, rssi,
                         payload)

        self.__advertisement_set_id = advertisement_set_id
        self.__primary_phy = primary_phy
        self.__secondary_phy = secondary_phy
        self.__tx_power = tx_power
        self.__periodic_interval = periodic_interval
        self.__data_completeness = data_completeness

    @property
    def advertisement_set_id(self):
        """
        Returns the advertisement set identifier used to help identify
        which advertisement you received.

        Returns:
            Integer: the advertisement set identifier.
        """
        return self.__advertisement_set_id

    @property
    def primary_phy(self):
        """
        Returns the preferred PHY for connecting this device.

        Returns:
            Integer: the primary PHY
        """
        return self.__primary_phy

    @property
    def secondary_phy(self):
        """
        Returns the secondary PHY for connecting this device.

        Returns:
            Integer: the secondary PHY.
        """
        return self.__secondary_phy

    @property
    def tx_power(self):
        """
        Returns the transmission power of received advertisement.
        This is a signed value.

        Returns:
            Integer: transmission power.
        """
        return self.__tx_power

    @property
    def periodic_interval(self):
        """
        Returns the interval for periodic advertising.
        0 indicates no periodic advertising.

        Returns:
            Integer: periodic interval.
        """
        return self.__periodic_interval

    @property
    def data_completeness(self):
        """
        Returns the data completeness field.

        Returns:
            Integer: data completeness field.
        """
        return self.__data_completeness

    def to_dict(self):
        """
        Override.

        .. seealso::
           | :meth:`._BLEGAPScanBaseAdvertisementMessage.to_dict`
        """
        msg_dict = super().to_dict()
        msg_dict.update({
            "Advertisement set ID": self.__advertisement_set_id,
            "Primary PHY": self.__primary_phy,
            "Secondary PHY": self.__secondary_phy,
            "TX power": self.__tx_power,
            "Periodic interval": self.__periodic_interval,
            "Data completeness": self.__data_completeness
        })
        return msg_dict


class BLEGAPScanStatusMessage:
    """
    This class represents a BLE GAP scan status message.
    It will store the Status value received.
    """

    def __init__(self, status):
        """
        Class  constructor.

        Args:
            status (Integer): The status of the GAP scan.

        Raises:
            ValueError: if `status` is invalid.
        """
        if status is None:
            raise ValueError("status cannot be None")

        self.__status = BLEGAPScanStatus.get(status)

    @property
    def status(self):
        """
        Returns the status of the GAP scan.

        Returns:
            :class:`.BLEGAPScanStatus`: The status of the GAP scan.
        """
        return self.__status

    def to_dict(self):
        """
        Returns the message information as a dictionary.
        """
        return {"Status": self.__status.description}
