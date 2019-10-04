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

from enum import Enum, unique
from digi.xbee.util import utils


@unique
class ATCommandStatus(Enum):
    """
    This class lists all the possible states of an AT command after executing it.

    | Inherited properties:
    |     **name** (String): the name (id) of the ATCommandStatus.
    |     **value** (String): the value of the ATCommandStatus.
    """
    OK = (0, "Status OK")
    ERROR = (1, "Status Error")
    INVALID_COMMAND = (2, "Invalid command")
    INVALID_PARAMETER = (3, "Invalid parameter")
    TX_FAILURE = (4, "TX failure")
    UNKNOWN = (255, "Unknown status")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ATCommandStatus element.

        Returns:
            Integer: the code of the ATCommandStatus element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ATCommandStatus element.

        Returns:
            String: the description of the ATCommandStatus element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the AT command status for the given code.

        Args:
            code (Integer): the code of the AT command status to get.

        Returns:
            :class:`.ATCommandStatus`: the AT command status with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return ATCommandStatus.UNKNOWN

    code = property(__get_code)
    """Integer. The AT command status code."""

    description = property(__get_description)
    """String. The AT command status description."""


ATCommandStatus.lookupTable = {x.code: x for x in ATCommandStatus}
ATCommandStatus.__doc__ += utils.doc_enum(ATCommandStatus)


@unique
class DiscoveryStatus(Enum):
    """
    This class lists all the possible states of the discovery process.

    | Inherited properties:
    |     **name** (String): The name of the DiscoveryStatus.
    |     **value** (Integer): The ID of the DiscoveryStatus.
    """
    NO_DISCOVERY_OVERHEAD = (0x00, "No discovery overhead")
    ADDRESS_DISCOVERY = (0x01, "Address discovery")
    ROUTE_DISCOVERY = (0x02, "Route discovery")
    ADDRESS_AND_ROUTE = (0x03, "Address and route")
    EXTENDED_TIMEOUT_DISCOVERY = (0x40, "Extended timeout discovery")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the DiscoveryStatus element.

        Returns:
            Integer: the code of the DiscoveryStatus element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the DiscoveryStatus element.

        Returns:
            String: The description of the DiscoveryStatus element.

        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the discovery status for the given code.

        Args:
            code (Integer): the code of the discovery status to get.

        Returns:
            :class:`.DiscoveryStatus`: the discovery status with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return DiscoveryStatus.UNKNOWN

    code = property(__get_code)
    """Integer. The discovery status code."""

    description = property(__get_description)
    """String. The discovery status description."""


DiscoveryStatus.lookupTable = {x.code: x for x in DiscoveryStatus}
DiscoveryStatus.__doc__ += utils.doc_enum(DiscoveryStatus)


@unique
class TransmitStatus(Enum):
    """
    This class represents all available transmit status.

    | Inherited properties:
    |     **name** (String): the name (id) of ths TransmitStatus.
    |     **value** (String): the value of ths TransmitStatus.
    """
    SUCCESS = (0x00, "Success.")
    NO_ACK = (0x01, "No acknowledgement received.")
    CCA_FAILURE = (0x02, "CCA failure.")
    PURGED = (0x03, "Transmission purged, it was attempted before stack was up.")
    WIFI_PHYSICAL_ERROR = (0x04, "Physical error occurred on the interface with the WiFi transceiver.")
    INVALID_DESTINATION = (0x15, "Invalid destination endpoint.")
    NO_BUFFERS = (0x18, "No buffers.")
    NETWORK_ACK_FAILURE = (0x21, "Network ACK Failure.")
    NOT_JOINED_NETWORK = (0x22, "Not joined to network.")
    SELF_ADDRESSED = (0x23, "Self-addressed.")
    ADDRESS_NOT_FOUND = (0x24, "Address not found.")
    ROUTE_NOT_FOUND = (0x25, "Route not found.")
    BROADCAST_FAILED = (0x26, "Broadcast source failed to hear a neighbor relay the message.")
    INVALID_BINDING_TABLE_INDEX = (0x2B, "Invalid binding table index.")
    INVALID_ENDPOINT = (0x2C, "Invalid endpoint")
    BROADCAST_ERROR_APS = (0x2D, "Attempted broadcast with APS transmission.")
    BROADCAST_ERROR_APS_EE0 = (0x2E, "Attempted broadcast with APS transmission, but EE=0.")
    SOFTWARE_ERROR = (0x31, "A software error occurred.")
    RESOURCE_ERROR = (0x32, "Resource error lack of free buffers, timers, etc.")
    PAYLOAD_TOO_LARGE = (0x74, "Data payload too large.")
    INDIRECT_MESSAGE_UNREQUESTED = (0x75, "Indirect message unrequested")
    SOCKET_CREATION_FAILED = (0x76, "Attempt to create a client socket failed.")
    IP_PORT_NOT_EXIST = (0x77, "TCP connection to given IP address and port doesn't exist. Source port is non-zero so "
                               "that a new connection is not attempted.")
    UDP_SRC_PORT_NOT_MATCH_LISTENING_PORT = (0x78, "Source port on a UDP transmission doesn't match a listening port "
                                                   "on the transmitting module.")
    TCP_SRC_PORT_NOT_MATCH_LISTENING_PORT = (0x79, "Source port on a TCP transmission doesn't match a listening port "
                                                   "on the transmitting module.")
    INVALID_IP_ADDRESS = (0x7A, "Destination IPv4 address is not valid.")
    INVALID_IP_PROTOCOL = (0x7B, "Protocol on an IPv4 transmission is not valid.")
    RELAY_INTERFACE_INVALID = (0x7C, "Destination interface on a User Data Relay Frame "
                                     "doesn't exist.")
    RELAY_INTERFACE_REJECTED = (0x7D, "Destination interface on a User Data Relay Frame "
                                      "exists, but the interface is not accepting data.")
    SOCKET_CONNECTION_REFUSED = (0x80, "Destination server refused the connection.")
    SOCKET_CONNECTION_LOST = (0x81, "The existing connection was lost before the data was sent.")
    SOCKET_ERROR_NO_SERVER = (0x82, "The attempted connection timed out.")
    SOCKET_ERROR_CLOSED = (0x83, "The existing connection was closed.")
    SOCKET_ERROR_UNKNOWN_SERVER = (0x84, "The server could not be found.")
    SOCKET_ERROR_UNKNOWN_ERROR = (0x85, "An unknown error occurred.")
    INVALID_TLS_CONFIGURATION = (0x86, "TLS Profile on a 0x23 API request doesn't exist, or "
                                       "one or more certificates is not valid.")
    KEY_NOT_AUTHORIZED = (0xBB, "Key not authorized.")
    UNKNOWN = (0xFF, "Unknown.")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the TransmitStatus element.

        Returns:
            Integer: the code of the TransmitStatus element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the TransmitStatus element.

        Returns:
            String: the description of the TransmitStatus element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the transmit status for the given code.

        Args:
            code (Integer): the code of the transmit status to get.

        Returns:
            :class:`.TransmitStatus`: the transmit status with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return TransmitStatus.UNKNOWN

    code = property(__get_code)
    """Integer. The transmit status code."""

    description = property(__get_description)
    """String. The transmit status description."""


TransmitStatus.lookupTable = {x.code: x for x in TransmitStatus}
TransmitStatus.__doc__ += utils.doc_enum(TransmitStatus)


@unique
class ModemStatus(Enum):
    """
    Enumerates the different modem status events. This enumeration list is 
    intended to be used within the :class:`.ModemStatusPacket` packet.
    """
    HARDWARE_RESET = (0x00, "Device was reset")
    WATCHDOG_TIMER_RESET = (0x01, "Watchdog timer was reset")
    JOINED_NETWORK = (0x02, "Device joined to network")
    DISASSOCIATED = (0x03, "Device disassociated")
    ERROR_SYNCHRONIZATION_LOST = (0x04, "Configuration error/synchronization lost")
    COORDINATOR_REALIGNMENT = (0x05, "Coordinator realignment")
    COORDINATOR_STARTED = (0x06, "The coordinator started")
    NETWORK_SECURITY_KEY_UPDATED = (0x07, "Network security key was updated")
    NETWORK_WOKE_UP = (0x0B, "Network Woke Up")
    NETWORK_WENT_TO_SLEEP = (0x0C, "Network Went To Sleep")
    VOLTAGE_SUPPLY_LIMIT_EXCEEDED = (0x0D, "Voltage supply limit exceeded")
    REMOTE_MANAGER_CONNECTED = (0x0E, "Remote Manager connected")
    REMOTE_MANAGER_DISCONNECTED = (0x0F, "Remote Manager disconnected")
    MODEM_CONFIG_CHANGED_WHILE_JOINING = (0x11, "Modem configuration changed while joining")
    BLUETOOTH_CONNECTED = (0x32, "A Bluetooth connection has been made and API mode has been unlocked.")
    BLUETOOTH_DISCONNECTED = (0x33, "An unlocked Bluetooth connection has been disconnected.")
    BANDMASK_CONFIGURATION_ERROR = (0x34, "LTE-M/NB-IoT bandmask configuration has failed.")
    ERROR_STACK = (0x80, "Stack error")
    ERROR_AP_NOT_CONNECTED = (0x82, "Send/join command issued without connecting from AP")
    ERROR_AP_NOT_FOUND = (0x83, "Access point not found")
    ERROR_PSK_NOT_CONFIGURED = (0x84, "PSK not configured")
    ERROR_SSID_NOT_FOUND = (0x87, "SSID not found")
    ERROR_FAILED_JOIN_SECURITY = (0x88, "Failed to join with security enabled")
    ERROR_INVALID_CHANNEL = (0x8A, "Invalid channel")
    ERROR_FAILED_JOIN_AP = (0x8E, "Failed to join access point")
    UNKNOWN = (0xFF, "UNKNOWN")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ModemStatus element.

        Returns:
            Integer: the code of the ModemStatus element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ModemStatus element.

        Returns:
            String: the description of the ModemStatus element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the modem status for the given code.

        Args:
            code (Integer): the code of the modem status to get.

        Returns:
            :class:`.ModemStatus`: the ModemStatus with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return ModemStatus.UNKNOWN

    code = property(__get_code)
    """Integer. The modem status code."""

    description = property(__get_description)
    """String. The modem status description."""


ModemStatus.lookupTable = {x.code: x for x in ModemStatus}
ModemStatus.__doc__ += utils.doc_enum(ModemStatus)


@unique
class PowerLevel(Enum):
    """
    Enumerates the different power levels. The power level indicates the output 
    power value of a radio when transmitting data.
    """
    LEVEL_LOWEST = (0x00, "Lowest")
    LEVEL_LOW = (0x01, "Low")
    LEVEL_MEDIUM = (0x02, "Medium")
    LEVEL_HIGH = (0x03, "High")
    LEVEL_HIGHEST = (0x04, "Highest")
    LEVEL_UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the PowerLevel element.

        Returns:
            Integer: the code of the PowerLevel element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the PowerLevel element.

        Returns:
            String: the description of the PowerLevel element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the power level for the given code.

        Args:
            code (Integer): the code of the power level to get.

        Returns:
            :class:`.PowerLevel`: the PowerLevel with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return PowerLevel.LEVEL_UNKNOWN

    code = property(__get_code)
    """Integer. The power level code."""

    description = property(__get_description)
    """String. The power level description."""


PowerLevel.lookupTable = {x.code: x for x in PowerLevel}
PowerLevel.__doc__ += utils.doc_enum(PowerLevel)


@unique
class AssociationIndicationStatus(Enum):
    """
    Enumerates the different association indication statuses.
    """
    SUCCESSFULLY_JOINED = (0x00, "Successfully formed or joined a network.")
    AS_TIMEOUT = (0x01, "Active Scan Timeout.")
    AS_NO_PANS_FOUND = (0x02, "Active Scan found no PANs.")
    AS_ASSOCIATION_NOT_ALLOWED = (0x03, "Active Scan found PAN, but the CoordinatorAllowAssociation bit is not set.")
    AS_BEACONS_NOT_SUPPORTED = (0x04, "Active Scan found PAN, but Coordinator and End Device are not configured to "
                                      "support beacons.")
    AS_ID_DOESNT_MATCH = (0x05, "Active Scan found PAN, but the Coordinator ID parameter does not match the ID "
                                "parameter of the End Device.")
    AS_CHANNEL_DOESNT_MATCH = (0x06, "Active Scan found PAN, but the Coordinator CH parameter does not match "
                                     "the CH parameter of the End Device.")
    ENERGY_SCAN_TIMEOUT = (0x07, "Energy Scan Timeout.")
    COORDINATOR_START_REQUEST_FAILED = (0x08, "Coordinator start request failed.")
    COORDINATOR_INVALID_PARAMETER = (0x09, "Coordinator could not start due to invalid parameter.")
    COORDINATOR_REALIGNMENT = (0x0A, "Coordinator Realignment is in progress.")
    AR_NOT_SENT = (0x0B, "Association Request not sent.")
    AR_TIMED_OUT = (0x0C, "Association Request timed out - no reply was received.")
    AR_INVALID_PARAMETER = (0x0D, "Association Request had an Invalid Parameter.")
    AR_CHANNEL_ACCESS_FAILURE = (0x0E, "Association Request Channel Access Failure. Request was not "
                                       "transmitted - CCA failure.")
    AR_COORDINATOR_ACK_WASNT_RECEIVED = (0x0F, "Remote Coordinator did not send an ACK after Association "
                                               "Request was sent.")
    AR_COORDINATOR_DIDNT_REPLY = (0x10, "Remote Coordinator did not reply to the Association Request, but an ACK "
                                        "was received after sending the request.")
    SYNCHRONIZATION_LOST = (0x12, "Sync-Loss - Lost synchronization with a Beaconing Coordinator.")
    DISASSOCIATED = (0x13, " Disassociated - No longer associated to Coordinator.")
    NO_PANS_FOUND = (0x21, "Scan found no PANs.")
    NO_PANS_WITH_ID_FOUND = (0x22, "Scan found no valid PANs based on current SC and ID settings.")
    NJ_EXPIRED = (0x23, "Valid Coordinator or Routers found, but they are not allowing joining (NJ expired).")
    NO_JOINABLE_BEACONS_FOUND = (0x24, "No joinable beacons were found.")
    UNEXPECTED_STATE = (0x25, "Unexpected state, node should not be attempting to join at this time.")
    JOIN_FAILED = (0x27, "Node Joining attempt failed (typically due to incompatible security settings).")
    COORDINATOR_START_FAILED = (0x2A, "Coordinator Start attempt failed.")
    CHECKING_FOR_COORDINATOR = (0x2B, "Checking for an existing coordinator.")
    NETWORK_LEAVE_FAILED = (0x2C, "Attempt to leave the network failed.")
    DEVICE_DIDNT_RESPOND = (0xAB, "Attempted to join a device that did not respond.")
    UNSECURED_KEY_RECEIVED = (0xAC, "Secure join error - network security key received unsecured.")
    KEY_NOT_RECEIVED = (0xAD, "Secure join error - network security key not received.")
    INVALID_SECURITY_KEY = (0xAF, "Secure join error - joining device does not have the right preconfigured link key.")
    SCANNING_NETWORK = (0xFF, "Scanning for a network/Attempting to associate.")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``AssociationIndicationStatus`` element.

        Returns:
            Integer: the code of the ``AssociationIndicationStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``AssociationIndicationStatus`` element.

        Returns:
            String: the description of the ``AssociationIndicationStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the ``AssociationIndicationStatus`` for the given code.

        Args:
            code (Integer): the code of the ``AssociationIndicationStatus`` to get.

        Returns:
            :class:`.AssociationIndicationStatus`: the ``AssociationIndicationStatus`` with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The association indication status code."""

    description = property(__get_description)
    """String. The association indication status description."""


AssociationIndicationStatus.lookupTable = {x.code: x for x in AssociationIndicationStatus}
AssociationIndicationStatus.__doc__ += utils.doc_enum(AssociationIndicationStatus)


@unique
class CellularAssociationIndicationStatus(Enum):
    """
    Enumerates the different association indication statuses for the Cellular protocol.
    """
    SUCCESSFULLY_CONNECTED = (0x00, "Connected to the Internet.")
    REGISTERING_CELLULAR_NETWORK = (0x22, "Registering to cellular network")
    CONNECTING_INTERNET = (0x23, "Connecting to the Internet")
    MODEM_FIRMWARE_CORRUPT = (0x24, "The cellular component requires a new firmware image.")
    REGISTRATION_DENIED = (0x25, "Cellular network registration was denied.")
    AIRPLANE_MODE = (0x2A, "Airplane mode is active.")
    USB_DIRECT = (0x2B, "USB Direct mode is active.")
    PSM_LOW_POWER = (0x2C, "The cellular component is in the PSM low-power state.")
    BYPASS_MODE = (0x2F, "Bypass mode active")
    INITIALIZING = (0xFF, "Initializing")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``CellularAssociationIndicationStatus`` element.

        Returns:
            Integer: the code of the ``CellularAssociationIndicationStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``CellularAssociationIndicationStatus`` element.

        Returns:
            String: the description of the ``CellularAssociationIndicationStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the ``CellularAssociationIndicationStatus`` for the given code.

        Args:
            code (Integer): the code of the ``CellularAssociationIndicationStatus`` to get.

        Returns:
            :class:`.CellularAssociationIndicationStatus`: the ``CellularAssociationIndicationStatus``
                with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The cellular association indication status code."""

    description = property(__get_description)
    """String. The cellular association indication status description."""


CellularAssociationIndicationStatus.lookupTable = {x.code: x for x in CellularAssociationIndicationStatus}
CellularAssociationIndicationStatus.__doc__ += utils.doc_enum(CellularAssociationIndicationStatus)


@unique
class DeviceCloudStatus(Enum):
    """
    Enumerates the different Device Cloud statuses.
    """
    SUCCESS = (0x00, "Success")
    BAD_REQUEST = (0x01, "Bad request")
    RESPONSE_UNAVAILABLE = (0x02, "Response unavailable")
    DEVICE_CLOUD_ERROR = (0x03, "Device Cloud error")
    CANCELED = (0x20, "Device Request canceled by user")
    TIME_OUT = (0x21, "Session timed out")
    UNKNOWN_ERROR = (0x40, "Unknown error")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``DeviceCloudStatus`` element.

        Returns:
            Integer: the code of the ``DeviceCloudStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``DeviceCloudStatus`` element.

        Returns:
            String: the description of the ``DeviceCloudStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Device Cloud status for the given code.

        Args:
            code (Integer): the code of the Device Cloud status to get.

        Returns:
            :class:`.DeviceCloudStatus`: the ``DeviceCloudStatus`` with the given code, ``None`` if there is not any
                status with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The Device Cloud status code."""

    description = property(__get_description)
    """String. The Device Cloud status description."""


DeviceCloudStatus.lookupTable = {x.code: x for x in DeviceCloudStatus}
DeviceCloudStatus.__doc__ += utils.doc_enum(DeviceCloudStatus)


@unique
class FrameError(Enum):
    """
    Enumerates the different frame errors.
    """
    INVALID_TYPE = (0x02, "Invalid frame type")
    INVALID_LENGTH = (0x03, "Invalid frame length")
    INVALID_CHECKSUM = (0x04, "Erroneous checksum on last frame")
    PAYLOAD_TOO_BIG = (0x05, "Payload of last API frame was too big to fit into a buffer")
    STRING_ENTRY_TOO_BIG = (0x06, "String entry was too big on last API frame sent")
    WRONG_STATE = (0x07, "Wrong state to receive frame")
    WRONG_REQUEST_ID = (0x08, "Device request ID of device response didn't match the number in the request")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``FrameError`` element.

        Returns:
            Integer: the code of the ``FrameError`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``FrameError`` element.

        Returns:
            String: the description of the ``FrameError`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the frame error for the given code.

        Args:
            code (Integer): the code of the frame error to get.

        Returns:
            :class:`.FrameError`: the ``FrameError`` with the given code, ``None`` if there is not any frame error
                with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The frame error code."""

    description = property(__get_description)
    """String. The frame error description."""


FrameError.lookupTable = {x.code: x for x in FrameError}
FrameError.__doc__ += utils.doc_enum(FrameError)


@unique
class WiFiAssociationIndicationStatus(Enum):
    """
    Enumerates the different Wi-Fi association indication statuses.
    """
    SUCCESSFULLY_JOINED = (0x00, "Successfully joined to access point.")
    INITIALIZING = (0x01, "Initialization in progress.")
    INITIALIZED = (0x02, "Initialized, but not yet scanning.")
    DISCONNECTING = (0x13, "Disconnecting from access point.")
    SSID_NOT_CONFIGURED = (0x23, "SSID not configured")
    INVALID_KEY = (0x24, "Encryption key invalid (NULL or invalid length).")
    JOIN_FAILED = (0x27, "SSID found, but join failed.")
    WAITING_FOR_AUTH = (0x40, "Waiting for WPA or WPA2 authentication.")
    WAITING_FOR_IP = (0x41, "Joined to a network and waiting for IP address.")
    SETTING_UP_SOCKETS = (0x42, "Joined to a network and IP configured. Setting up listening sockets.")
    SCANNING_FOR_SSID = (0xFF, "Scanning for the configured SSID.")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``WiFiAssociationIndicationStatus`` element.

        Returns:
            Integer: the code of the ``WiFiAssociationIndicationStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``WiFiAssociationIndicationStatus`` element.

        Returns:
            String: the description of the ``WiFiAssociationIndicationStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Wi-Fi association indication status for the given code.

        Args:
            code (Integer): the code of the Wi-Fi association indication status to get.

        Returns:
            :class:`.WiFiAssociationIndicationStatus`: the ``WiFiAssociationIndicationStatus`` with the given code,
                ``None`` if there is not any Wi-Fi association indication status with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The Wi-Fi association indication status code."""

    description = property(__get_description)
    """String. The Wi-Fi association indication status description."""


WiFiAssociationIndicationStatus.lookupTable = {x.code: x for x in WiFiAssociationIndicationStatus}
WiFiAssociationIndicationStatus.__doc__ += utils.doc_enum(WiFiAssociationIndicationStatus)


@unique
class NetworkDiscoveryStatus(Enum):
    """
    Enumerates the different statuses of the network discovery process.
    """
    SUCCESS = (0x00, "Success")
    ERROR_READ_TIMEOUT = (0x01, "Read timeout error")
    ERROR_NET_DISCOVER = (0x02, "Error executing network discovery")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``NetworkDiscoveryStatus`` element.

        Returns:
            Integer: the code of the ``NetworkDiscoveryStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``NetworkDiscoveryStatus`` element.

        Returns:
            String: the description of the ``NetworkDiscoveryStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the network discovery status for the given code.

        Args:
            code (Integer): the code of the network discovery status to get.

        Returns:
            :class:`.NetworkDiscoveryStatus`: the ``NetworkDiscoveryStatus`` with the given code, ``None`` if
                there is not any status with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The network discovery status code."""

    description = property(__get_description)
    """String. The network discovery status description."""


NetworkDiscoveryStatus.lookupTable = {x.code: x for x in NetworkDiscoveryStatus}
NetworkDiscoveryStatus.__doc__ += utils.doc_enum(NetworkDiscoveryStatus)


@unique
class ZigbeeRegisterStatus(Enum):
    """
    Enumerates the different statuses of the Zigbee Device Register process.
    """
    SUCCESS = (0x00, "Success")
    KEY_TOO_LONG = (0x01, "Key too long")
    ADDRESS_NOT_FOUND = (0xB1, "Address not found in the key table")
    INVALID_KEY = (0xB2, "Key is invalid (00 and FF are reserved)")
    INVALID_ADDRESS = (0xB3, "Invalid address")
    KEY_TABLE_FULL = (0xB4, "Key table is full")
    KEY_NOT_FOUND = (0xFF, "Key not found")
    UNKNOWN = (0xEE, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``ZigbeeRegisterStatus`` element.

        Returns:
            Integer: the code of the ``ZigbeeRegisterStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``ZigbeeRegisterStatus`` element.

        Returns:
            String: the description of the ``ZigbeeRegisterStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Zigbee Device Register status for the given code.

        Args:
            code (Integer): the code of the Zigbee Device Register status to get.

        Returns:
            :class:`.ZigbeeRegisterStatus`: the ``ZigbeeRegisterStatus`` with the given code,
                ``ZigbeeRegisterStatus.UNKNOWN`` if there is not any status with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return ZigbeeRegisterStatus.UNKNOWN

    code = property(__get_code)
    """Integer. The Zigbee Device Register status code."""

    description = property(__get_description)
    """String. The Zigbee Device Register status description."""


ZigbeeRegisterStatus.lookupTable = {x.code: x for x in ZigbeeRegisterStatus}
ZigbeeRegisterStatus.__doc__ += utils.doc_enum(ZigbeeRegisterStatus)


@unique
class SocketStatus(Enum):
    """
    Enumerates the different Socket statuses.
    """
    SUCCESS = (0x00, "Operation successful")
    INVALID_PARAM = (0x01, "Invalid parameters")
    FAILED_TO_READ = (0x02, "Failed to retrieve option value")
    CONNECTION_IN_PROGRESS = (0x03, "Connection already in progress")
    ALREADY_CONNECTED = (0x04, "Already connected/bound/listening")
    UNKNOWN_ERROR = (0x05, "Unknown error")
    BAD_SOCKET = (0x20, "Bad socket ID")
    NOT_REGISTERED = (0x22, "Not registered to cell network")
    INTERNAL_ERROR = (0x31, "Internal error")
    RESOURCE_ERROR = (0x32, "Resource error: retry the operation later")
    INVALID_PROTOCOL = (0x7B, "Invalid protocol")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``SocketStatus`` element.

        Returns:
            Integer: the code of the ``SocketStatus`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``SocketStatus`` element.

        Returns:
            String: the description of the ``SocketStatus`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Socket status for the given code.

        Args:
            code (Integer): the code of the Socket status to get.

        Returns:
            :class:`.SocketStatus`: the ``SocketStatus`` with the given code,
                ``SocketStatus.UNKNOWN`` if there is not any status with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return SocketStatus.UNKNOWN

    code = property(__get_code)
    """Integer. The Socket status code."""

    description = property(__get_description)
    """String. The Socket status description."""


SocketStatus.lookupTable = {x.code: x for x in SocketStatus}
SocketStatus.__doc__ += utils.doc_enum(SocketStatus)


@unique
class SocketState(Enum):
    """
    Enumerates the different Socket states.
    """
    CONNECTED = (0x00, "Connected")
    FAILED_DNS = (0x01, "Failed DNS lookup")
    CONNECTION_REFUSED = (0x02, "Connection refused")
    TRANSPORT_CLOSED = (0x03, "Transport closed")
    TIMED_OUT = (0x04, "Timed out")
    INTERNAL_ERROR = (0x05, "Internal error")
    HOST_UNREACHABLE = (0x06, "Host unreachable")
    CONNECTION_LOST = (0x07, "Connection lost")
    UNKNOWN_ERROR = (0x08, "Unknown error")
    UNKNOWN_SERVER = (0x09, "Unknown server")
    RESOURCE_ERROR = (0x0A, "Resource error")
    LISTENER_CLOSED = (0x0B, "Listener closed")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``SocketState`` element.

        Returns:
            Integer: the code of the ``SocketState`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``SocketState`` element.

        Returns:
            String: the description of the ``SocketState`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Socket state for the given code.

        Args:
            code (Integer): the code of the Socket state to get.

        Returns:
            :class:`.SocketState`: the ``SocketState`` with the given code,
                ``SocketState.UNKNOWN`` if there is not any status with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return SocketState.UNKNOWN

    code = property(__get_code)
    """Integer. The Socket state code."""

    description = property(__get_description)
    """String. The Socket state description."""


SocketState.lookupTable = {x.code: x for x in SocketState}
SocketState.__doc__ += utils.doc_enum(SocketState)


@unique
class SocketInfoState(Enum):
    """
    Enumerates the different Socket info states.
    """
    ALLOCATED = (0x00, "Allocated")
    CONNECTING = (0x01, "Connecting")
    CONNECTED = (0x02, "Connected")
    LISTENING = (0x03, "Listening")
    BOUND = (0x04, "Bound")
    CLOSING = (0x05, "Closing")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the ``SocketInfoState`` element.

        Returns:
            Integer: the code of the ``SocketInfoState`` element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the ``SocketInfoState`` element.

        Returns:
            String: the description of the ``SocketInfoState`` element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Socket info state for the given code.

        Args:
            code (Integer): the code of the Socket info state to get.

        Returns:
            :class:`.SocketInfoState`: the ``SocketInfoState`` with the given code,
                ``SocketInfoState.UNKNOWN`` if there is not any state with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return SocketInfoState.UNKNOWN

    @classmethod
    def get_by_description(cls, description):
        """
        Returns the Socket info state for the given description.

        Args:
            description (String): the description of the Socket info state to get.

        Returns:
            :class:`.SocketInfoState`: the ``SocketInfoState`` with the given description,
                ``SocketInfoState.UNKNOWN`` if there is not any state with the provided description.
        """
        for x in SocketInfoState:
            if x.description.lower() == description.lower():
                return x
        return SocketInfoState.UNKNOWN

    code = property(__get_code)
    """Integer. The Socket info state code."""

    description = property(__get_description)
    """String. The Socket info state description."""


SocketInfoState.lookupTable = {x.code: x for x in SocketInfoState}
SocketInfoState.__doc__ += utils.doc_enum(SocketInfoState)
