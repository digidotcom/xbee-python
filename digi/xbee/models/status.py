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

from enum import Enum, unique
from digi.xbee.util import utils


@unique
class ATCommandStatus(Enum):
    """
    This class lists all the possible states of an AT command after execution.

    | Inherited properties:
    |     **name** (String): the name (id) of the ATCommandStatus.
    |     **value** (String): the value of the ATCommandStatus.
    """
    OK = (0x00, "Status OK")
    ERROR = (0x01, "Status Error")
    INVALID_COMMAND = (0x02, "Invalid command")
    INVALID_PARAMETER = (0x03, "Invalid parameter")
    TX_FAILURE = (0x04, "TX failure")
    NO_SECURE_SESSION = (0x0B, "No secure session: Remote command access "
                               "requires a secure session be established first")
    ENC_ERROR = (0x0C, "Encryption error")
    CMD_SENT_INSECURELY = (0x0D, "Command sent insecurely: A secure session "
                                 "exists, but the request needs to have the "
                                 "appropriate command option set (bit 4)")
    UNKNOWN = (0xFF, "Unknown status")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the ATCommandStatus element.

        Returns:
            Integer: the code of the ATCommandStatus element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the ATCommandStatus element.

        Returns:
            String: the description of the ATCommandStatus element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the AT command status for the given code.

        Args:
            code (Integer): the code of the AT command status to get.

        Returns:
            :class:`.ATCommandStatus`: the AT command status with the given code.
        """
        # For ATCommResponsePacket (0x88) and RemoteATCommandResponsePacket
        # (0x97), use least significant nibble for status
        for status in cls:
            if code & 0x0F == status.code:
                return status
        return ATCommandStatus.UNKNOWN


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
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the DiscoveryStatus element.

        Returns:
            Integer: the code of the DiscoveryStatus element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the DiscoveryStatus element.

        Returns:
            String: The description of the DiscoveryStatus element.

        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the discovery status for the given code.

        Args:
            code (Integer): the code of the discovery status to get.

        Returns:
            :class:`.DiscoveryStatus`: the discovery status with the given code.
        """
        for status in cls:
            if code == status.code:
                return status
        return DiscoveryStatus.UNKNOWN


DiscoveryStatus.__doc__ += utils.doc_enum(DiscoveryStatus)


@unique
class TransmitStatus(Enum):
    """
    This class represents all available transmit status.

    | Inherited properties:
    |     **name** (String): the name (id) of ths TransmitStatus.
    |     **value** (String): the value of ths TransmitStatus.
    """
    SUCCESS = (0x00, "Success")
    NO_ACK = (0x01, "No acknowledgement received")
    CCA_FAILURE = (0x02, "CCA failure")
    PURGED = (
        0x03, "Transmission purged, it was attempted before stack was up")
    WIFI_PHYSICAL_ERROR = (
        0x04, "Transceiver was unable to complete the transmission")
    INVALID_DESTINATION = (0x15, "Invalid destination endpoint")
    NO_BUFFERS = (0x18, "No buffers")
    CONNECTION_NOT_FOUND = (0x20, "Connection not found")
    NETWORK_ACK_FAILURE = (0x21, "Network ACK Failure")
    NOT_JOINED_NETWORK = (0x22, "Not joined to network")
    SELF_ADDRESSED = (0x23, "Self-addressed")
    ADDRESS_NOT_FOUND = (0x24, "Address not found")
    ROUTE_NOT_FOUND = (0x25, "Route not found")
    BROADCAST_FAILED = (
        0x26, "Broadcast source failed to hear a neighbor relay the message")
    INVALID_BINDING_TABLE_INDEX = (0x2B, "Invalid binding table index")
    INVALID_ENDPOINT = (0x2C, "Invalid endpoint")
    BROADCAST_ERROR_APS = (0x2D, "Attempted broadcast with APS transmission")
    BROADCAST_ERROR_APS_EE0 = (
        0x2E, "Attempted broadcast with APS transmission, but EE=0")
    SOFTWARE_ERROR = (0x31, "A software error occurred")
    RESOURCE_ERROR = (
        0x32, "Resource error lack of free buffers, timers, etc")
    NO_SECURE_SESSION = (0x34, "No Secure session connection")
    ENC_FAILURE = (0x35, "Encryption failure")
    PAYLOAD_TOO_LARGE = (0x74, "Data payload too large")
    INDIRECT_MESSAGE_UNREQUESTED = (0x75, "Indirect message unrequested")
    SOCKET_CREATION_FAILED = (0x76, "Attempt to create a client socket failed")
    IP_PORT_NOT_EXIST = (
        0x77, "TCP connection to given IP address and port does not exist. "
              "Source port is non-zero, so a new connection is not attempted")
    UDP_SRC_PORT_NOT_MATCH_LISTENING_PORT = (
        0x78, "Source port on a UDP transmission does not match a listening "
              "port on the transmitting module")
    TCP_SRC_PORT_NOT_MATCH_LISTENING_PORT = (
        0x79, "Source port on a TCP transmission does not match a listening "
              "port on the transmitting module")
    INVALID_IP_ADDRESS = (0x7A, "Destination IPv4 address is invalid")
    INVALID_IP_PROTOCOL = (0x7B, "Protocol on an IPv4 transmission is invalid")
    RELAY_INTERFACE_INVALID = (
        0x7C, "Destination interface on a User Data Relay Frame does not exist")
    RELAY_INTERFACE_REJECTED = (
        0x7D, "Destination interface on a User Data Relay Frame exists, but "
              "the interface is not accepting data")
    MODEM_UPDATE_IN_PROGRESS = (
        0x7E, "Modem update in progress. Try again after update completion.")
    SOCKET_CONNECTION_REFUSED = (
        0x80, "Destination server refused the connection")
    SOCKET_CONNECTION_LOST = (
        0x81, "The existing connection was lost before the data was sent")
    SOCKET_ERROR_NO_SERVER = (0x82, "No server")
    SOCKET_ERROR_CLOSED = (0x83, "The existing connection was closed")
    SOCKET_ERROR_UNKNOWN_SERVER = (0x84, "The server could not be found")
    SOCKET_ERROR_UNKNOWN_ERROR = (0x85, "An unknown error occurred")
    INVALID_TLS_CONFIGURATION = (
        0x86, "TLS Profile on a 0x23 API request does not exist, or one or "
              "more certificates is invalid")
    SOCKET_NOT_CONNECTED = (0x87, "Socket not connected")
    SOCKET_NOT_BOUND = (0x88, "Socket not bound")
    SOCKET_INACTIVITY_TIMEOUT = (0x89, "Socket inactivity timeout")
    PDP_CONTEXT_DEACTIVATED = (0x8A, "PDP context deactivated by network")
    TLS_AUTHENTICATION_ERROR = (0x8B, "TLS Socket Authentication Error")
    KEY_NOT_AUTHORIZED = (0xBB, "Key not authorized")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the TransmitStatus element.

        Returns:
            Integer: the code of the TransmitStatus element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the TransmitStatus element.

        Returns:
            String: the description of the TransmitStatus element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the transmit status for the given code.

        Args:
            code (Integer): the code of the transmit status to get.

        Returns:
            :class:`.TransmitStatus`: the transmit status with the given code.
        """
        for status in cls:
            if code == status.code:
                return status
        return TransmitStatus.UNKNOWN


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
    ERROR_SYNCHRONIZATION_LOST = (
        0x04, "Configuration error/synchronization lost")
    COORDINATOR_REALIGNMENT = (0x05, "Coordinator realignment")
    COORDINATOR_STARTED = (0x06, "The coordinator started")
    NETWORK_SECURITY_KEY_UPDATED = (0x07, "Network security key was updated")
    NETWORK_WOKE_UP = (0x0B, "Network woke up")
    NETWORK_WENT_TO_SLEEP = (0x0C, "Network went to sleep")
    VOLTAGE_SUPPLY_LIMIT_EXCEEDED = (0x0D, "Voltage supply limit exceeded")
    REMOTE_MANAGER_CONNECTED = (0x0E, "Remote Manager connected")
    REMOTE_MANAGER_DISCONNECTED = (0x0F, "Remote Manager disconnected")
    MODEM_CONFIG_CHANGED_WHILE_JOINING = (
        0x11, "Modem configuration changed while joining")
    ACCESS_FAULT = (0x12, "Access fault")
    FATAL_ERROR = (0x13, "Fatal error")
    BLUETOOTH_CONNECTED = (
        0x32, "A Bluetooth connection has been made and API mode has been "
              "unlocked")
    BLUETOOTH_DISCONNECTED = (
        0x33, "An unlocked Bluetooth connection has been disconnected")
    BANDMASK_CONFIGURATION_ERROR = (
        0x34, "LTE-M/NB-IoT bandmask configuration has failed")
    CELLULAR_UPDATE_START = (0x35, "Cellular component update started")
    CELLULAR_UPDATE_FAILED = (0x36, "Cellular component update failed")
    CELLULAR_UPDATE_SUCCESS = (0x37, "Cellular component update completed")
    FIRMWARE_UPDATE_START = (0x38, "XBee firmware update started")
    FIRMWARE_UPDATE_FAILED = (0x39, "XBee firmware update failed")
    FIRMWARE_UPDATE_APPLYING = (0x3A, "XBee firmware update applying")
    SEC_SESSION_ESTABLISHED = (0x3B, "Secure session successfully established")
    SEC_SESSION_END = (0x3C, "Secure session ended")
    SEC_SESSION_AUTH_FAILED = (0x3D, "Secure session authentication failed")
    COORD_PAN_ID_CONFLICT = (
        0x3E, "Coordinator detected a PAN ID conflict but took no action because CR=0")
    COORD_CHANGE_PAN_ID = (
        0x3F, "Coordinator changed PAN ID due to a conflict")
    ROUTER_PAN_ID_CHANGED = (
        0x40, "Router PAN ID was changed by coordinator due to a conflict")
    NET_WATCHDOG_EXPIRED = (0x42, "Network watchdog timeout expired")
    OPEN_JOIN_WINDOW = (0x43, "Joining window open")
    CLOSE_JOIN_WINDOW = (0x44, "Joining window closed")
    NETWORK_KEY_CHANGE_INIT = (0x45, "Network security key change initiated")
    ERROR_STACK = (0x80, "Stack error")
    ERROR_AP_NOT_CONNECTED = (
        0x82, "Send/join command issued without connecting from AP")
    ERROR_AP_NOT_FOUND = (0x83, "Access point not found")
    ERROR_PSK_NOT_CONFIGURED = (0x84, "PSK not configured")
    ERROR_SSID_NOT_FOUND = (0x87, "SSID not found")
    ERROR_FAILED_JOIN_SECURITY = (0x88, "Failed to join with security enabled")
    ERROR_INVALID_CHANNEL = (0x8A, "Invalid channel")
    ERROR_FAILED_JOIN_AP = (0x8E, "Failed to join access point")
    UNKNOWN = (0xFF, "UNKNOWN")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the ModemStatus element.

        Returns:
            Integer: the code of the ModemStatus element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the ModemStatus element.

        Returns:
            String: the description of the ModemStatus element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the modem status for the given code.

        Args:
            code (Integer): the code of the modem status to get.

        Returns:
            :class:`.ModemStatus`: the ModemStatus with the given code.
        """
        for status in cls:
            if code == status.code:
                return status
        return ModemStatus.UNKNOWN


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
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the PowerLevel element.

        Returns:
            Integer: the code of the PowerLevel element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the PowerLevel element.

        Returns:
            String: the description of the PowerLevel element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the power level for the given code.

        Args:
            code (Integer): the code of the power level to get.

        Returns:
            :class:`.PowerLevel`: the PowerLevel with the given code.
        """
        for level in cls:
            if code == level.code:
                return level
        return PowerLevel.LEVEL_UNKNOWN


PowerLevel.__doc__ += utils.doc_enum(PowerLevel)


@unique
class AssociationIndicationStatus(Enum):
    """
    Enumerates the different association indication statuses.
    """
    SUCCESSFULLY_JOINED = (0x00, "Successfully formed or joined a network")
    AS_TIMEOUT = (0x01, "Active Scan Timeout")
    AS_NO_PANS_FOUND = (0x02, "Active Scan found no PANs")
    AS_ASSOCIATION_NOT_ALLOWED = (
        0x03, "Active Scan found PAN, but the CoordinatorAllowAssociation bit "
              "is not set")
    AS_BEACONS_NOT_SUPPORTED = (
        0x04, "Active Scan found PAN, but Coordinator and End Device are not "
              "onfigured to support beacons")
    AS_ID_DOESNT_MATCH = (
        0x05, "Active Scan found PAN, but the Coordinator ID parameter does "
              "not match the ID parameter of the End Device")
    AS_CHANNEL_DOESNT_MATCH = (
        0x06, "Active Scan found PAN, but the Coordinator CH parameter does "
              "not match the CH parameter of the End Device")
    ENERGY_SCAN_TIMEOUT = (0x07, "Energy Scan Timeout")
    COORDINATOR_START_REQUEST_FAILED = (
        0x08, "Coordinator start request failed")
    COORDINATOR_INVALID_PARAMETER = (
        0x09, "Coordinator could not start due to invalid parameter")
    COORDINATOR_REALIGNMENT = (
        0x0A, "Coordinator Realignment is in progress")
    AR_NOT_SENT = (0x0B, "Association Request not sent")
    AR_TIMED_OUT = (
        0x0C, "Association Request timed out - no reply was received")
    AR_INVALID_PARAMETER = (
        0x0D, "Association Request had an Invalid Parameter")
    AR_CHANNEL_ACCESS_FAILURE = (
        0x0E, "Association Request Channel Access Failure. Request was not "
              "transmitted - CCA failure")
    AR_COORDINATOR_ACK_WASNT_RECEIVED = (
        0x0F, "Remote Coordinator did not send an ACK after Association "
              "Request was sent")
    AR_COORDINATOR_DIDNT_REPLY = (
        0x10, "Remote Coordinator did not reply to the Association Request, "
              "but an ACK was received after sending the request")
    SYNCHRONIZATION_LOST = (
        0x12, "Sync-Loss - Lost synchronization with a Beaconing Coordinator")
    DISASSOCIATED = (
        0x13, " Disassociated - No longer associated to Coordinator")
    NO_PANS_FOUND = (0x21, "Scan found no PANs.")
    NO_PANS_WITH_ID_FOUND = (
        0x22, "Scan found no valid PANs based on current SC and ID settings")
    NJ_EXPIRED = (
        0x23, "Valid Coordinator or Routers found, but they are not allowing "
              "joining (NJ expired)")
    NO_JOINABLE_BEACONS_FOUND = (0x24, "No joinable beacons were found")
    UNEXPECTED_STATE = (
        0x25, "Unexpected state, node should not be attempting to join at"
              " this time")
    JOIN_FAILED = (
        0x27, "Node Joining attempt failed (typically due to incompatible "
              "security settings)")
    COORDINATOR_START_FAILED = (0x2A, "Coordinator Start attempt failed")
    CHECKING_FOR_COORDINATOR = (0x2B, "Checking for an existing coordinator")
    NETWORK_LEAVE_FAILED = (0x2C, "Attempt to leave the network failed")
    SEC_JOIN_ATTACHED_TO_NETWORK = (
        0x40, "Secure Join - Successfully attached to network, waiting for new link key")
    SEC_JOIN_SUCCESS_LINK_KEY = (
        0x41, "Secure Join - Successfully received new link key from the trust center")
    SEC_JOIN_FAILED_LINK_KEY = (
        0x44, "Secure Join - Failed to receive new link key from the trust center")
    DEVICE_DIDNT_RESPOND = (
        0xAB, "Attempted to join a device that did not respond")
    UNSECURED_KEY_RECEIVED = (
        0xAC, "Secure join error - network security key received unsecured")
    KEY_NOT_RECEIVED = (
        0xAD, "Secure join error - network security key not received")
    INVALID_SECURITY_KEY = (
        0xAF, "Secure join error - joining device does not have the right "
              "preconfigured link key")
    SCANNING_NETWORK = (0xFF, "Scanning for a network/Attempting to associate")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `AssociationIndicationStatus` element.

        Returns:
            Integer: the code of the `AssociationIndicationStatus` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `AssociationIndicationStatus` element.

        Returns:
            String: the description of the `AssociationIndicationStatus`
                element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the `AssociationIndicationStatus` for the given code.

        Args:
            code (Integer): the `AssociationIndicationStatus` code to get.

        Returns:
            :class:`.AssociationIndicationStatus`: the
                `AssociationIndicationStatus` with the given code.
        """
        for status in cls:
            if code == status.code:
                return status
        return None


AssociationIndicationStatus.__doc__ += utils.doc_enum(AssociationIndicationStatus)


@unique
class CellularAssociationIndicationStatus(Enum):
    """
    Enumerates the different association indication statuses for the Cellular
    protocol.
    """
    SUCCESSFULLY_CONNECTED = (0x00, "Connected to the Internet")
    REGISTERING_CELLULAR_NETWORK = (0x22, "Registering to cellular network")
    CONNECTING_INTERNET = (0x23, "Connecting to the Internet")
    MODEM_FIRMWARE_CORRUPT = (
        0x24, "The cellular component requires a new firmware image")
    REGISTRATION_DENIED = (0x25, "Cellular network registration was denied")
    AIRPLANE_MODE = (0x2A, "Airplane mode is active")
    USB_DIRECT = (0x2B, "USB Direct mode is active")
    PSM_LOW_POWER = (
        0x2C, "The cellular component is in the PSM low-power state")
    MODEM_SHUT_DOWN = (0x2D, "Modem shut down")
    LOW_VOLTAGE_SHUT_DOWN = (0x2E, "Low voltage shut down")
    BYPASS_MODE = (0x2F, "Bypass mode active")
    UPGRADE_IN_PROCESS = (0x30, "An upgrade is in process")
    REGULATORY_TESTING_ENABLED = (0x31, "Regulatory testing has been enabled")
    INITIALIZING = (0xFF, "Initializing")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `CellularAssociationIndicationStatus` element.

        Returns:
            Integer: the code of the `CellularAssociationIndicationStatus`
                element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `CellularAssociationIndicationStatus`
            element.

        Returns:
            String: the description of the `CellularAssociationIndicationStatus`
                element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the `CellularAssociationIndicationStatus` for the given code.

        Args:
            code (Integer): `CellularAssociationIndicationStatus` code.

        Returns:
            :class:`.CellularAssociationIndicationStatus`: the
                `CellularAssociationIndicationStatus` with the given code.
        """
        for status in cls:
            if code == status.code:
                return status
        return None


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
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `DeviceCloudStatus` element.

        Returns:
            Integer: the code of the `DeviceCloudStatus` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `DeviceCloudStatus` element.

        Returns:
            String: the description of the `DeviceCloudStatus` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Device Cloud status for the given code.

        Args:
            code (Integer): the code of the Device Cloud status to get.

        Returns:
            :class:`.DeviceCloudStatus`: the `DeviceCloudStatus` with the given
                code, `None` if not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return None


DeviceCloudStatus.__doc__ += utils.doc_enum(DeviceCloudStatus)


@unique
class FrameError(Enum):
    """
    Enumerates the different frame errors.
    """
    INVALID_TYPE = (0x02, "Invalid frame type")
    INVALID_LENGTH = (0x03, "Invalid frame length")
    INVALID_CHECKSUM = (0x04, "Erroneous checksum on last frame")
    PAYLOAD_TOO_BIG = (
        0x05, "Payload of last API frame was too big to fit into a buffer")
    STRING_ENTRY_TOO_BIG = (
        0x06, "String entry was too big on last API frame sent")
    WRONG_STATE = (0x07, "Wrong state to receive frame")
    WRONG_REQUEST_ID = (
        0x08, "Device request ID of device response do not match the number "
              "in the request")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `FrameError` element.

        Returns:
            Integer: the code of the `FrameError` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `FrameError` element.

        Returns:
            String: the description of the `FrameError` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the frame error for the given code.

        Args:
            code (Integer): the code of the frame error to get.

        Returns:
            :class:`.FrameError`: the `FrameError` with the given code, `None`
                if not found.
        """
        for error in cls:
            if code == error.code:
                return error
        return None


FrameError.__doc__ += utils.doc_enum(FrameError)


@unique
class WiFiAssociationIndicationStatus(Enum):
    """
    Enumerates the different Wi-Fi association indication statuses.
    """
    SUCCESSFULLY_JOINED = (0x00, "Successfully joined to access point")
    INITIALIZING = (0x01, "Initialization in progress")
    INITIALIZED = (0x02, "Initialized, but not yet scanning")
    DISCONNECTING = (0x13, "Disconnecting from access point")
    SSID_NOT_CONFIGURED = (0x23, "SSID not configured")
    INVALID_KEY = (0x24, "Encryption key invalid (NULL or invalid length)")
    JOIN_FAILED = (0x27, "SSID found, but join failed")
    WAITING_FOR_AUTH = (0x40, "Waiting for WPA or WPA2 authentication")
    WAITING_FOR_IP = (0x41, "Joined to a network and waiting for IP address")
    SETTING_UP_SOCKETS = (
        0x42, "Joined to a network and IP configured. "
              "Setting up listening sockets")
    SCANNING_FOR_SSID = (0xFF, "Scanning for the configured SSID")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `WiFiAssociationIndicationStatus` element.

        Returns:
            Integer: the code of the `WiFiAssociationIndicationStatus` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `WiFiAssociationIndicationStatus` element.

        Returns:
            String: the description of the `WiFiAssociationIndicationStatus` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Wi-Fi association indication status for the given code.

        Args:
            code (Integer): the code of the Wi-Fi association indication status
                to get.

        Returns:
            :class:`.WiFiAssociationIndicationStatus`: the
                `WiFiAssociationIndicationStatus` with the given code, `None`
                if not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return None


WiFiAssociationIndicationStatus.__doc__ += utils.doc_enum(WiFiAssociationIndicationStatus)


@unique
class NetworkDiscoveryStatus(Enum):
    """
    Enumerates the different statuses of the network discovery process.
    """
    SUCCESS = (0x00, "Success")
    ERROR_READ_TIMEOUT = (0x01, "Read timeout error")
    ERROR_NET_DISCOVER = (0x02, "Error executing node discovery")
    ERROR_GENERAL = (0x03, "Error while discovering network")
    CANCEL = (0x04, "Discovery process cancelled")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `NetworkDiscoveryStatus` element.

        Returns:
            Integer: the code of the `NetworkDiscoveryStatus` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `NetworkDiscoveryStatus` element.

        Returns:
            String: the description of the `NetworkDiscoveryStatus` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the network discovery status for the given code.

        Args:
            code (Integer): the code of the network discovery status to get.

        Returns:
            :class:`.NetworkDiscoveryStatus`: the `NetworkDiscoveryStatus` with
                the given code, `None` if not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return None


NetworkDiscoveryStatus.__doc__ += utils.doc_enum(NetworkDiscoveryStatus)


@unique
class ZigbeeRegisterStatus(Enum):
    """
    Enumerates the different statuses of the Zigbee Device Register process.
    """
    SUCCESS = (0x00, "Success")
    KEY_TOO_LONG = (0x01, "Key too long")
    TRANSIENT_KEY_TABLE_FULL = (0x18, "Transient key table is full")
    ADDRESS_NOT_FOUND = (0xB1, "Address not found in the key table")
    INVALID_KEY = (0xB2, "Key is invalid (00 and FF are reserved)")
    INVALID_ADDRESS = (0xB3, "Invalid address")
    KEY_TABLE_FULL = (0xB4, "Key table is full")
    INVALID_SECURITY_DATA = (0xBD, "Security data is invalid (Install code CRC fails)")
    KEY_NOT_FOUND = (0xFF, "Key not found")
    UNKNOWN = (0xEE, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `ZigbeeRegisterStatus` element.

        Returns:
            Integer: the code of the `ZigbeeRegisterStatus` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `ZigbeeRegisterStatus` element.

        Returns:
            String: the description of the `ZigbeeRegisterStatus` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Zigbee Device Register status for the given code.

        Args:
            code (Integer): the code of the Zigbee Device Register status to get.

        Returns:
            :class:`.ZigbeeRegisterStatus`: the `ZigbeeRegisterStatus` with the
                given code, `ZigbeeRegisterStatus.UNKNOWN` if not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return ZigbeeRegisterStatus.UNKNOWN


ZigbeeRegisterStatus.__doc__ += utils.doc_enum(ZigbeeRegisterStatus)


@unique
class EmberBootloaderMessageType(Enum):
    """
    Enumerates the different types of the Ember bootloader messages.
    """
    ACK = (0x06, "ACK message")
    NACK = (0x15, "NACK message")
    NO_MAC_ACK = (0x40, "No MAC ACK message")
    QUERY = (0x51, "Query message")
    QUERY_RESPONSE = (0x52, "Query response message")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `EmberBootloaderMessageType` element.

        Returns:
            Integer: the code of the `EmberBootloaderMessageType` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `EmberBootloaderMessageType` element.

        Returns:
            String: the description of the `EmberBootloaderMessageType` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Ember bootloader message type for the given code.

        Args:
            code (Integer): the code of the Ember bootloader message type to get.

        Returns:
            :class:`.EmberBootloaderMessageType`: the `EmberBootloaderMessageType` with the
                given code, `EmberBootloaderMessageType.UNKNOWN` if not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return EmberBootloaderMessageType.UNKNOWN


EmberBootloaderMessageType.__doc__ += utils.doc_enum(EmberBootloaderMessageType)


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
    MODEM_UPDATE_IN_PROGRESS = (0x7E, "A modem update is in process. Try again after update completion")
    UNKNOWN_ERROR_2 = (0x85, "Unknown error")
    INVALID_TLS_CFG = (0x86, "Invalid TLS configuration")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `SocketStatus` element.

        Returns:
            Integer: the code of the `SocketStatus` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `SocketStatus` element.

        Returns:
            String: the description of the `SocketStatus` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Socket status for the given code.

        Args:
            code (Integer): the code of the Socket status to get.

        Returns:
            :class:`.SocketStatus`: the `SocketStatus` with the given code,
                `SocketStatus.UNKNOWN` if there not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return SocketStatus.UNKNOWN


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
    RST_CLOSE_BY_PEER = (0x0C, "RST Close by peer")
    CLOSED_INACTIVITY_TIMEOUT = (0x0D, "Closed due to inactivity timeout")
    PDP_CONTEXT_DEACTIVATED = (0x0E, "PDP context deactivated by network")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `SocketState` element.

        Returns:
            Integer: the code of the `SocketState` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `SocketState` element.

        Returns:
            String: the description of the `SocketState` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Socket state for the given code.

        Args:
            code (Integer): the code of the Socket state to get.

        Returns:
            :class:`.SocketState`: the `SocketState` with the given code,
                `SocketState.UNKNOWN` if not found.
        """
        for state in cls:
            if code == state.code:
                return state
        return SocketState.UNKNOWN


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
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `SocketInfoState` element.

        Returns:
            Integer: the code of the `SocketInfoState` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `SocketInfoState` element.

        Returns:
            String: the description of the `SocketInfoState` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Socket info state for the given code.

        Args:
            code (Integer): the code of the Socket info state to get.

        Returns:
            :class:`.SocketInfoState`: the `SocketInfoState` with the given
                code, `SocketInfoState.UNKNOWN` if not found.
        """
        for state in cls:
            if code == state.code:
                return state
        return SocketInfoState.UNKNOWN

    @classmethod
    def get_by_description(cls, description):
        """
        Returns the Socket info state for the given description.

        Args:
            description (String): the description of the Socket info state to get.

        Returns:
            :class:`.SocketInfoState`: the `SocketInfoState` with the given
                description, `SocketInfoState.UNKNOWN` if not found.
        """
        for state in SocketInfoState:
            if state.description.lower() == description.lower():
                return state
        return SocketInfoState.UNKNOWN


SocketInfoState.__doc__ += utils.doc_enum(SocketInfoState)


@unique
class FSCommandStatus(Enum):
    """
    This class lists all the possible states of an file system command after
    execution.

    | Inherited properties:
    |     **name** (String): Name (id) of the FSCommandStatus.
    |     **value** (String): Value of the FSCommandStatus.
    """
    SUCCESS = (0x00, "Success")
    ERROR = (0x01, "Error")
    INVALID_COMMAND = (0x02, "Invalid file system command")
    INVALID_PARAMETER = (0x03, "Invalid command parameter")
    ACCESS_DENIED = (0x50, "Access denied")
    ALREADY_EXISTS = (0x51, "File or directory already exists")
    DOES_NOT_EXIST = (0x52, "File or directory does not exist")
    INVALID_NAME = (0x53, "Invalid file or directory name")
    IS_DIRECTORY = (0x54, "File operation on directory")
    DIR_NOT_EMPTY = (0x55, "Directory is not empty")
    EOF_REACHED = (0x56, "Attempt to read past EOF (end of file)")
    HW_FAILURE = (0x57, "Hardware failure")
    NO_DEVICE = (0x58, "Volume offline / format required")
    VOLUME_FULL = (0x59, "Volume full")
    TIMED_OUT = (0x5A, "Operation timed out")
    DEVICE_BUSY = (0x5B, "Busy with prior operation")
    RESOURCE_FAILURE = (
        0x5C, "Resource failure (memory allocation failed, try again)")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the FSCommandStatus element.

        Returns:
            Integer: Code of the FSCommandStatus element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the FSCommandStatus element.

        Returns:
            String: Description of the FSCommandStatus element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the file system command status for the given code.

        Args:
            code (Integer): Code of the file system command status to get.

        Returns:
            :class:`.FSCommandStatus`: File system command status with the
                given code, `None` if not found.
        """
        for status in cls:
            if code == status.code:
                return status
        return None

    def __repr__(self):
        return "%s (0x%0.2X)" % (self.__desc, self.__code)

    def __str__(self):
        return "%s (0x%0.2X)" % (self.__desc, self.__code)


FSCommandStatus.__doc__ += utils.doc_enum(FSCommandStatus)


class NodeUpdateType(Enum):
    """
    This class lists the update types.

    | Inherited properties:
    |     **name** (String): Name (id) of the NodeUpdateType.
    |     **value** (String): Value of the NodeUpdateType.
    """
    FIRMWARE = (0x00, "Firmware update")
    PROFILE = (0x01, "Profile update")
    FILESYSTEM = (0x02, "File system update")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the NodeUpdateType element.

        Returns:
            Integer: Code of the NodeUpdateType element.
        """
        return self.__code

    @property
    def desc(self):
        """
        Returns the description of the NodeUpdateType element.

        Returns:
            String: Description of the NodeUpdateType element.
        """
        return self.__desc

    def __str__(self):
        return self.__desc


NodeUpdateType.__doc__ += utils.doc_enum(NodeUpdateType)


class UpdateProgressStatus:
    """
    This class represents the state of a update process.
    """

    def __init__(self, update_type, task_str, percent, finished):
        """
        Class constructor. Instantiates a new :class:`.UpdateProgressState`
        object.

        Args:
            update_type (:class:`.NodeUpdateType`): Type of update.
            task_str (String): The current update task.
            percent (Integer): The current update task percentage.
            finished (Boolean): `True` if the update finished for the XBee,
                `False` otherwise.
        """
        self.__type = update_type
        self.__task = task_str
        self.__percent = percent
        self.__finished = finished

    @property
    def type(self):
        """
        Gets the update type: firmware or profile.

        Returns:
             :class:`.NodeUpdateType`: The update type
        """
        return self.__type

    @property
    def task(self):
        """
        Gets the update task.

        Returns:
             String: The current update task.
        """
        return self.__task

    @property
    def percent(self):
        """
        Gets the progress percentage.

        Returns:
             Integer: The update task percentage
        """
        return self.__percent

    @property
    def finished(self):
        """
        Gets a boolean value indicating if the update process finished for an
        XBee.

        Returns:
             Boolean: `True` if the update process has finished for an XBee,
                `False` otherwise.
        """
        return self.__finished


@unique
class BLEMACAddressType(Enum):
    """
    This class lists all the possible types of BLE Mac Addresses.

    | Inherited properties:
    |     **name** (String): The name of the BLEMACAddressType.
    |     **value** (Integer): The ID of the BLEMACAddressType.
    """
    PUBLIC = (0x00, "Public")
    STATIC = (0x01, "Static")
    RANDOM_RESOLVABLE = (0x02, "Random Resolvable")
    RANDOM_NONRESOLVABLE = (0x03, "Random Nonresolvable")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the BLEMACAddressType element.

        Returns:
            Integer: the code of the BLEMACAddressType element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the BLEMACAddressType element.

        Returns:
            String: The description of the BLEMACAddressType element.

        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the address type for the given code.

        Args:
            code (Integer): the code of the address type to get.

        Returns:
            :class:`.BLEMACAddressType`: the address type with the given code.
        """
        for addr_type in cls:
            if code == addr_type.code:
                return addr_type
        return BLEMACAddressType.UNKNOWN


BLEMACAddressType.__doc__ += utils.doc_enum(BLEMACAddressType)


@unique
class BLEGAPScanStatus(Enum):
    """
    This class lists all the possible statuses of a BLE GAP scan

    | Inherited properties:
    |     **name** (String): The name of the BLEGAPScanStatus.
    |     **value** (Integer): The ID of the BLEGAPScanStatus.
    """
    STARTED = (0x00, "Scanner has started")
    RUNNING = (0x01, "Scanner is running")
    STOPPED = (0x02, "Scanner has stopped")
    ERROR = (0x03, "Scanner was unable to start or stop")
    INVALID_PARAM = (0x04, "Invalid Parameters")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the BLEGAPScanStatus element.

        Returns:
            Integer: the code of the BLEGAPScanStatus element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the BLEGAPScanStatus element.

        Returns:
            String: The description of the BLEGAPScanStatus element.

        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the address type for the given code.

        Args:
            code (Integer): the code of the gap scan status.

        Returns:
            :class:`.BLEGAPScanStatus`: the status type with the given code.
        """
        for status in cls:
            if code == status.code:
                return status
        return BLEGAPScanStatus.ERROR


BLEGAPScanStatus.__doc__ += utils.doc_enum(BLEGAPScanStatus)
