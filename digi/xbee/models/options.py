# Copyright 2017-2021, Digi International Inc.
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

from enum import Enum, unique, IntFlag

from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.util import utils


class ReceiveOptions(Enum):
    """
    This class lists all the possible options that have been set while
    receiving an XBee packet.

    The receive options are usually set as a bitfield meaning that the
    options can be combined using the '|' operand.
    """

    NONE = 0x00
    """
    No special receive options.
    """

    PACKET_ACKNOWLEDGED = 0x01
    """
    Packet was acknowledged.

    Not valid for WiFi protocol.
    """

    BROADCAST_PACKET = 0x02
    """
    Packet was sent as a broadcast.

    Not valid for WiFi protocol.
    """

    BROADCAST_PANS_PACKET = 0x04
    """
    Packet was broadcast accros all PANs.

    Only for 802.15.4 protocol.
    """

    SECURE_SESSION_ENC = 0x10
    """
    Packet sent across a Secure Session.

    Only for XBee 3.
    """

    APS_ENCRYPTED = 0x20
    """
    Packet encrypted with APS encryption.

    Only valid for Zigbee protocol.
    """

    SENT_FROM_END_DEVICE = 0x40
    """
    Packet was sent from an end device (if known).

    Only valid for Zigbee protocol.
    """

    POINT_MULTIPOINT_MODE = 0x40
    """
    Transmission is performed using point-to-Multipoint mode.

    Only valid for DigiMesh 868/900 and Point-to-Multipoint 868/900
    protocols.
    """

    REPEATER_MODE = 0x80
    """
    Transmission is performed using repeater mode.

    Only valid for DigiMesh 868/900 and Point-to-Multipoint 868/900
    protocols.
    """

    DIGIMESH_MODE = 0xC0
    """
    Transmission is performed using DigiMesh mode.

    Only valid for DigiMesh 868/900 and Point-to-Multipoint 868/900
    protocols.
    """


ReceiveOptions.__doc__ += utils.doc_enum(ReceiveOptions)


class TransmitOptions(Enum):
    """
    This class lists all the possible options that can be set while
    transmitting an XBee packet.

    The transmit options are usually set as a bitfield meaning that the options
    can be combined using the '|' operand.

    Not all options are available for all cases, that's why there are different
    names with same values. In each moment, you must be sure that the option
    your are going to use, is a valid option in your context.
    """

    NONE = 0x00
    """
    No special transmit options.
    """

    DISABLE_ACK = 0x01
    """
    Disables acknowledgments on all unicasts.

    Only valid for Zigbee, DigiMesh, 802.15.4, and Point-to-multipoint
    protocols.
    """

    DISABLE_RETRIES_AND_REPAIR = 0x01
    """
    Disables the retries and router repair in the frame.

    Only valid for Zigbee protocol.
    """

    DONT_ATTEMPT_RD = 0x02
    """
    Doesn't attempt Route Discovery.

    Disables Route Discovery on all DigiMesh unicasts.

    Only valid for DigiMesh protocol.
    """

    BROADCAST_PAN = 0x02
    """
    Sends packet with broadcast {@code PAN ID}. Packet will be sent to all
    PANs.

    Only valid for 802.15.4 XBee 3 protocol.
    """

    USE_BROADCAST_PAN_ID = 0x04
    """
    Sends packet with broadcast {@code PAN ID}. Packet will be sent to all
    devices in the same channel ignoring the {@code PAN ID}.

    It cannot be combined with other options.

    Only valid for 802.15.4 XBee protocol.
    """

    ENABLE_UNICAST_NACK = 0x04
    """
    Enables unicast NACK messages.

    NACK message is enabled on the packet.

    Only valid for DigiMesh 868/900 protocol, and XBee 3 DigiMesh.
    """

    INDIRECT_TRANSMISSION = 0x04
    """
    Used for binding transmissions.

    Only valid for Zigbee protocol.
    """

    ENABLE_MULTICAST = 0x08
    """
    Enables multicast transmission request.

    Only valid for Zigbee XBee protocol.
    """

    ENABLE_TRACE_ROUTE = 0x08
    """
    Enable a unicast Trace Route on DigiMesh transmissions
    When set, the transmission will generate a Route Information - 0x8D frame.

    Only valid for DigiMesh XBee protocol.
    """

    ENABLE_UNICAST_TRACE_ROUTE = 0x08
    """
    Enables unicast trace route messages.

    Trace route is enabled on the packets.

    Only valid for DigiMesh 868/900 protocol.
    """

    SECURE_SESSION_ENC = 0x10
    """
    Encrypt payload for transmission across a Secure Session.
    Reduces maximum payload size by 4 bytes.

    Only for XBee 3.
    """

    ENABLE_APS_ENCRYPTION = 0x20
    """
    Enables APS encryption, only if {@code EE=1}.

    Enabling APS encryption decreases the maximum number of RF payload
    bytes by 4 (below the value reported by {@code NP}).

    Only valid for Zigbee XBee protocol.
    """

    USE_EXTENDED_TIMEOUT = 0x40
    """
    Uses the extended transmission timeout.

    Setting the extended timeout bit causes the stack to set the
    extended transmission timeout for the destination address.

    Only valid for Zigbee XBee protocol.
    """

    POINT_MULTIPOINT_MODE = 0x40
    """
    Transmission is performed using point-to-Multipoint mode.

    Only valid for DigiMesh 868/900 and Point-to-Multipoint 868/900
    protocols.
    """

    REPEATER_MODE = 0x80
    """
    Transmission is performed using repeater mode.

    Only valid for DigiMesh 868/900 and Point-to-Multipoint 868/900
    protocols.
    """

    DIGIMESH_MODE = 0xC0
    """
    Transmission is performed using DigiMesh mode.

    Only valid for DigiMesh 868/900 and Point-to-Multipoint 868/900
    protocols.
    """


TransmitOptions.__doc__ += utils.doc_enum(TransmitOptions)


class RemoteATCmdOptions(Enum):
    """
    This class lists all the possible options that can be set while
    transmitting a remote AT Command.

    These options are usually set as a bitfield meaning that the options
    can be combined using the '|' operand.
    """

    NONE = 0x00
    """
    No special transmit options
    """

    DISABLE_ACK = 0x01
    """
    Disables ACK
    """

    APPLY_CHANGES = 0x02
    """
    Applies changes in the remote device.

    If this option is not set, AC command must be sent before changes
    will take effect.
    """

    SECURE_SESSION_ENC = 0x10
    """
    Send the remote command securely.
    Requires a Secure Session be established with the destination.

    Only for XBee 3.
    """

    EXTENDED_TIMEOUT = 0x40
    """
    Uses the extended transmission timeout.

    Setting the extended timeout bit causes the stack to set the extended
    transmission timeout for the destination address.

    Only valid for ZigBee XBee protocol.
    """


RemoteATCmdOptions.__doc__ += utils.doc_enum(RemoteATCmdOptions)


@unique
class SendDataRequestOptions(Enum):
    """
    Enumerates the different options for the :class:`.SendDataRequestPacket`.
    """
    OVERWRITE = (0, "Overwrite")
    ARCHIVE = (1, "Archive")
    APPEND = (2, "Append")
    TRANSIENT = (3, "Transient data (do not store)")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the SendDataRequestOptions element.

        Returns:
            Integer: the code of the SendDataRequestOptions element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the SendDataRequestOptions element.

        Returns:
            String: the description of the SendDataRequestOptions element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the send data request option for the given code.

        Args:
            code (Integer): the code of the send data request option to get.

        Returns:
            :class:`.FrameError`: the SendDataRequestOptions with the given
                code, `None` if not found.
        """
        for option in cls:
            if option.code == code:
                return option
        return None


SendDataRequestOptions.__doc__ += utils.doc_enum(SendDataRequestOptions)


@unique
class DiscoveryOptions(Enum):
    """
    Enumerates the different options used in the discovery process.
    """

    APPEND_DD = (0x01, "Append device type identifier (DD)")
    """
    Append device type identifier (DD) to the discovery response.

    Valid for the following protocols:
      * DigiMesh
      * Point-to-multipoint (Digi Point)
      * Zigbee
    """

    DISCOVER_MYSELF = (0x02, "Local device sends response frame")
    """
    Local device sends response frame when discovery is issued.

    Valid for the following protocols:
      * DigiMesh
      * Point-to-multipoint (Digi Point)
      * Zigbee
      * 802.15.4
    """

    APPEND_RSSI = (0x04, "Append RSSI (of the last hop)")
    """
    Append RSSI of the last hop to the discovery response.

    Valid for the following protocols:
      * DigiMesh
      * Point-to-multipoint (Digi Point)
    """

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `DiscoveryOptions` element.

        Returns:
            Integer: the code of the `DiscoveryOptions` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `DiscoveryOptions` element.

        Returns:
            String: the description of the `DiscoveryOptions` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the `DiscoveryOptions` for the given code.

        Args:
            code (Integer): the code of the `DiscoveryOptions` to get.

        Returns:
            :class:`.FrameError`: the `DiscoveryOptions` with the given code,
                `None` if not found.
        """
        for option in cls:
            if option.code == code:
                return option
        return None

    @staticmethod
    def calculate_discovery_value(protocol, options):
        """
        Calculates the total value of a combination of several options for the
        given protocol.

        Args:
            protocol (:class:`.XBeeProtocol`): the `XBeeProtocol` to calculate
                the value of all the given discovery options.
            options: collection of options to get the final value.

        Returns:
            Integer: The value to be configured in the module depending on the
                given collection of options and the protocol.
        """
        value = 0
        if protocol in [XBeeProtocol.ZIGBEE, XBeeProtocol.ZNET]:
            for opt in options:
                if opt == DiscoveryOptions.APPEND_RSSI:
                    continue
                value = value + opt.code
        elif protocol in [XBeeProtocol.DIGI_MESH, XBeeProtocol.DIGI_POINT,
                          XBeeProtocol.XLR, XBeeProtocol.XLR_DM]:
            for opt in options:
                value = value + opt.code
        else:
            if DiscoveryOptions.DISCOVER_MYSELF in options:
                value = 1  # This is different for 802.15.4.
        return value


DiscoveryOptions.__doc__ += utils.doc_enum(DiscoveryOptions)


@unique
class XBeeLocalInterface(Enum):
    """
    Enumerates the different interfaces for the :class:`.UserDataRelayPacket`
    and :class:`.UserDataRelayOutputPacket`.

    | Inherited properties:
    |     **name** (String): the name (id) of the XBee local interface.
    |     **value** (String): the value of the XBee local interface.
    """
    SERIAL = (0, "Serial port (UART when in API mode, or SPI interface)")
    BLUETOOTH = (1, "BLE API interface (on XBee devices which support BLE)")
    MICROPYTHON = (2, "MicroPython")
    UNKNOWN = (255, "Unknown interface")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `XBeeLocalInterface` element.

        Returns:
            Integer: the code of the `XBeeLocalInterface` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `XBeeLocalInterface` element.

        Returns:
            String: the description of the `XBeeLocalInterface` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the XBee local interface option for the given code.

        Args:
            code (Integer): the code of the XBee local interface to get.

        Returns:
            :class:`.XBeeLocalInterface`: the `XBeeLocalInterface` with the
                given code, `UNKNOWN` if not found.
        """
        for interface in cls:
            if interface.code == code:
                return interface
        return XBeeLocalInterface.UNKNOWN


XBeeLocalInterface.__doc__ += utils.doc_enum(XBeeLocalInterface)


class RegisterKeyOptions(Enum):
    """
    This class lists all the possible options that have been set while
    receiving an XBee packet.

    The receive options are usually set as a bitfield meaning that the
    options can be combined using the '|' operand.
    """

    LINK_KEY = (0x00, "Key is a Link Key (KY on joining node)")
    INSTALL_CODE = (0x01, "Key is an Install Code (I? on joining node,"
                          "DC must be set to 1 on joiner)")
    UNKNOWN = (0xFF, "Unknown key option")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `RegisterKeyOptions` element.

        Returns:
            Integer: the code of the `RegisterKeyOptions` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `RegisterKeyOptions` element.

        Returns:
            String: the description of the `RegisterKeyOptions` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the register key option for the given code.

        Args:
            code (Integer): the code of the register key option to get.

        Returns:
            :class:`.RegisterKeyOptions`: the `RegisterKeyOptions` with the
                given code, `UNKNOWN` if not found.
        """
        for option in cls:
            if option.code == code:
                return option
        return RegisterKeyOptions.UNKNOWN


RegisterKeyOptions.__doc__ += utils.doc_enum(RegisterKeyOptions)


@unique
class SocketOption(Enum):
    """
    Enumerates the different Socket Options.
    """
    TLS_PROFILE = (0x00, "TLS Profile")
    UNKNOWN = (0xFF, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the `SocketOption` element.

        Returns:
            Integer: the code of the `SocketOption` element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the `SocketOption` element.

        Returns:
            String: the description of the `SocketOption` element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the Socket Option for the given code.

        Args:
            code (Integer): the code of the Socket Option to get.

        Returns:
            :class:`.SocketOption`: the `SocketOption` with the given code,
                `SocketOption.UNKNOWN` if not found.
        """
        for option in cls:
            if option.code == code:
                return option
        return SocketOption.UNKNOWN


SocketOption.__doc__ += utils.doc_enum(SocketOption)


@unique
class FileOpenRequestOption(IntFlag):
    """
    This enumeration lists all the available options for `FSCmdType.FILE_OPEN`
    command requests.

    | Inherited properties:
    |     **name** (String): Name (id) of this FileOpenRequestOption.
    |     **value** (String): Value of this FileOpenRequestOption.
    """

    CREATE = 1 << 0
    """
    Create if file does not exist.
    """

    EXCLUSIVE = 1 << 1
    """
    Error out if file exists.
    """

    READ = 1 << 2
    """
    Open file for reading.
    """

    WRITE = 1 << 3
    """
    Open file for writing.
    """

    TRUNCATE = 1 << 4
    """
    Truncate file to 0 bytes.
    """

    APPEND = 1 << 5
    """
    Append to end of file.
    """

    SECURE = 1 << 7
    """
    Create a secure write-only file.
    """


FileOpenRequestOption.__doc__ += utils.doc_enum(FileOpenRequestOption)


@unique
class DirResponseFlag(IntFlag):
    """
    This enumeration lists all the available flags for `FSCmdType.DIR_OPEN` and
    `FSCmdType.DIR_READ` command responses.

    | Inherited properties:
    |     **name** (String): Name (id) of this DirResponseFlag.
    |     **value** (String): Value of this DirResponseFlag.
    """

    IS_DIR = 1 << 7
    """
    Entry is a directory.
    """

    IS_SECURE = 1 << 6
    """
    Entry is stored securely.
    """

    IS_LAST = 1 << 0
    """
    Entry is the last.
    """


DirResponseFlag.__doc__ += utils.doc_enum(DirResponseFlag)
