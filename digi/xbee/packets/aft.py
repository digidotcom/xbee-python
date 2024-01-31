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
class ApiFrameType(Enum):
    """
    This enumeration lists all the available frame types used in any XBee
    protocol.

    | Inherited properties:
    |     **name** (String): the name (id) of this ApiFrameType.
    |     **value** (String): the value of this ApiFrameType.

    """
    TX_64 = (0x00, "TX (Transmit) Request 64-bit address")
    TX_16 = (0x01, "TX (Transmit) Request 16-bit address")
    REMOTE_AT_COMMAND_REQUEST_WIFI = (
        0x07, "Remote AT Command Request (Wi-Fi)")
    AT_COMMAND = (0x08, "AT Command")
    AT_COMMAND_QUEUE = (0x09, "AT Command Queue")
    TRANSMIT_REQUEST = (0x10, "Transmit Request")
    EXPLICIT_ADDRESSING = (0x11, "Explicit Addressing Command Frame")
    REMOTE_AT_COMMAND_REQUEST = (0x17, "Remote AT Command Request")
    TX_SMS = (0x1F, "TX SMS")
    TX_IPV4 = (0x20, "TX IPv4")
    CREATE_SOURCE_ROUTE = (0x21, "Create Source Route")
    REGISTER_JOINING_DEVICE = (0x24, "Register Joining Device")
    SEND_DATA_REQUEST = (0x28, "Send Data Request")
    DEVICE_RESPONSE = (0x2A, "Device Response")
    USER_DATA_RELAY_REQUEST = (0x2D, "User Data Relay Request")
    BLUETOOTH_GAP_SCAN_REQUEST = (0x34, "Bluetooth GAP Scan Request")
    FILE_SYSTEM_REQUEST = (0x3B, "File System Request")
    REMOTE_FILE_SYSTEM_REQUEST = (0x3C, "Remote File System Request")
    SOCKET_CREATE = (0x40, "Socket Create")
    SOCKET_OPTION_REQUEST = (0x41, "Socket Option Request")
    SOCKET_CONNECT = (0x42, "Socket Connect")
    SOCKET_CLOSE = (0x43, "Socket Close")
    SOCKET_SEND = (0x44, "Socket Send (Transmit)")
    SOCKET_SENDTO = (0x45, "Socket SendTo (Transmit Explicit Data): IPv4")
    SOCKET_BIND = (0x46, "Socket Bind/Listen")
    RX_64 = (0x80, "RX (Receive) Packet 64-bit Address")
    RX_16 = (0x81, "RX (Receive) Packet 16-bit Address")
    RX_IO_64 = (0x82, "IO Data Sample RX 64-bit Address Indicator")
    RX_IO_16 = (0x83, "IO Data Sample RX 16-bit Address Indicator")
    REMOTE_AT_COMMAND_RESPONSE_WIFI = (
        0x87, "Remote AT Command Response (Wi-Fi)")
    AT_COMMAND_RESPONSE = (0x88, "AT Command Response")
    TX_STATUS = (0x89, "TX (Transmit) Status")
    MODEM_STATUS = (0x8A, "Modem Status")
    TRANSMIT_STATUS = (0x8B, "Transmit Status")
    DIGIMESH_ROUTE_INFORMATION = (0x8D, "Route Information")
    IO_DATA_SAMPLE_RX_INDICATOR_WIFI = (
        0x8F, "IO Data Sample RX Indicator (Wi-Fi)")
    RECEIVE_PACKET = (0x90, "Receive Packet")
    EXPLICIT_RX_INDICATOR = (0x91, "Explicit RX Indicator")
    IO_DATA_SAMPLE_RX_INDICATOR = (0x92, "IO Data Sample RX Indicator")
    REMOTE_AT_COMMAND_RESPONSE = (0x97, "Remote Command Response")
    RX_SMS = (0x9F, "RX SMS")
    OTA_FIRMWARE_UPDATE_STATUS = (0xA0, "OTA Firmware Update Status")
    ROUTE_RECORD_INDICATOR = (0xA1, "Route Record Indicator")
    REGISTER_JOINING_DEVICE_STATUS = (0xA4, "Register Joining Device Status")
    USER_DATA_RELAY_OUTPUT = (0xAD, "User Data Relay Output")
    RX_IPV4 = (0xB0, "RX IPv4")
    BLUETOOTH_GAP_SCAN_LEGACY_ADVERTISEMENT_RESPONSE = (
        0xB4, "Bluetooth GAP Scan Legacy Advertisement Response")
    BLUETOOTH_GAP_SCAN_EXTENDED_ADVERTISEMENT_RESPONSE = (
        0xB7, "Bluetooth GAP Scan Extended Advertisement Response")
    BLUETOOTH_GAP_SCAN_STATUS = (0xB5, "Bluetooth GAP Scan Status")
    SEND_DATA_RESPONSE = (0xB8, "Send Data Response")
    DEVICE_REQUEST = (0xB9, "Device Request")
    DEVICE_RESPONSE_STATUS = (0xBA, "Device Response Status")
    FILE_SYSTEM_RESPONSE = (0xBB, "File System Response")
    REMOTE_FILE_SYSTEM_RESPONSE = (0xBC, "Remote File System Response")
    SOCKET_CREATE_RESPONSE = (0xC0, "Socket Create Response")
    SOCKET_OPTION_RESPONSE = (0xC1, "Socket Option Response")
    SOCKET_CONNECT_RESPONSE = (0xC2, "Socket Connect Response")
    SOCKET_CLOSE_RESPONSE = (0xC3, "Socket Close Response")
    SOCKET_LISTEN_RESPONSE = (0xC6, "Socket Listen Response")
    SOCKET_NEW_IPV4_CLIENT = (0xCC, "Socket New IPv4 Client")
    SOCKET_RECEIVE = (0xCD, "Socket Receive")
    SOCKET_RECEIVE_FROM = (0xCE, "Socket Receive From")
    SOCKET_STATE = (0xCF, "Socket State")
    FRAME_ERROR = (0xFE, "Frame Error")
    GENERIC = (0xFF, "Generic")
    UNKNOWN = (-1, "Unknown Packet")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    @property
    def code(self):
        """
        Returns the code of the ApiFrameType element.

        Returns:
            Integer: the code of the ApiFrameType element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the ApiFrameType element.

        Returns:
            Integer: the description of the ApiFrameType element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Retrieves the api frame type associated to the given ID.

        Args:
            code (Integer): the code of the API frame type to get.

        Returns:
            :class:`.ApiFrameType`: the API frame type associated to the given
                code or `UNKNOWN` if not found.
        """
        for frame_type in cls:
            if code == frame_type.code:
                return frame_type
        return ApiFrameType.UNKNOWN


ApiFrameType.__doc__ += utils.doc_enum(ApiFrameType)
