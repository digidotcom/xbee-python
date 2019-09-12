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

from digi.xbee.packets.base import *
from digi.xbee.packets.cellular import *
from digi.xbee.packets.common import *
from digi.xbee.packets.devicecloud import *
from digi.xbee.packets.network import *
from digi.xbee.packets.raw import *
from digi.xbee.packets.relay import *
from digi.xbee.packets.socket import *
from digi.xbee.packets.wifi import *
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.mode import OperatingMode
from digi.xbee.packets.zigbee import RegisterJoiningDevicePacket, RegisterDeviceStatusPacket

"""
This module provides functionality to build XBee packets from
bytearray returning the appropriate XBeePacket subclass.

All the API and API2 logic is already included so all packet reads are
independent of the XBee operating mode.

Two API modes are supported and both can be enabled using the ``AP``
(API Enable) command::

    API1 - API Without Escapes
    The data frame structure is defined as follows:

      Start Delimiter          Length                   Frame Data                   Checksum
          (Byte 1)            (Bytes 2-3)               (Bytes 4-n)                (Byte n + 1)
    +----------------+  +-------------------+  +--------------------------- +  +----------------+
    |      0x7E      |  |   MSB   |   LSB   |  |   API-specific Structure   |  |     1 Byte     |
    +----------------+  +-------------------+  +----------------------------+  +----------------+
                   MSB = Most Significant Byte, LSB = Least Significant Byte


API2 - API With Escapes
The data frame structure is defined as follows::

      Start Delimiter          Length                   Frame Data                   Checksum
          (Byte 1)            (Bytes 2-3)               (Bytes 4-n)                (Byte n + 1)
    +----------------+  +-------------------+  +--------------------------- +  +----------------+
    |      0x7E      |  |   MSB   |   LSB   |  |   API-specific Structure   |  |     1 Byte     |
    +----------------+  +-------------------+  +----------------------------+  +----------------+
                        \___________________________________  _________________________________/
                                                            \/
                                                Characters Escaped If Needed

                   MSB = Most Significant Byte, LSB = Least Significant Byte


When sending or receiving an API2 frame, specific data values must be
escaped (flagged) so they do not interfere with the data frame sequencing.
To escape an interfering data byte, the byte 0x7D is inserted before
the byte to be escaped XOR'd with 0x20.

The data bytes that need to be escaped:

- ``0x7E`` - Frame Delimiter - :attr:`.SpecialByte.
- ``0x7D`` - Escape
- ``0x11`` - XON
- ``0x13`` - XOFF

The length field has a two-byte value that specifies the number of
bytes that will be contained in the frame data field. It does not include the
checksum field.

The frame data  forms an API-specific structure as follows::

      Start Delimiter          Length                   Frame Data                   Checksum
          (Byte 1)            (Bytes 2-3)               (Bytes 4-n)                (Byte n + 1)
    +----------------+  +-------------------+  +--------------------------- +  +----------------+
    |      0x7E      |  |   MSB   |   LSB   |  |   API-specific Structure   |  |     1 Byte     |
    +----------------+  +-------------------+  +----------------------------+  +----------------+
                                               /                                                 \\
                                              /  API Identifier        Identifier specific data   \\
                                              +------------------+  +------------------------------+
                                              |       cmdID      |  |           cmdData            |
                                              +------------------+  +------------------------------+


The cmdID frame (API-identifier) indicates which API messages
will be contained in the cmdData frame (Identifier-specific data).

To unit_test data integrity, a checksum is calculated and verified on
non-escaped data.

.. seealso::
   | :class:`.XBeePacket`
   | :class:`.OperatingMode`
"""


def build_frame(packet_bytearray, operating_mode=OperatingMode.API_MODE):
    """
    Creates a packet from raw data.
    
    Args:
        packet_bytearray (Bytearray): the raw data of the packet to build.
        operating_mode (:class:`.OperatingMode`): the operating mode in which the raw data has been captured.

    .. seealso::
       | :class:`.OperatingMode`
    """
    frame_type = ApiFrameType.get(packet_bytearray[3])

    if frame_type == ApiFrameType.GENERIC:
        return GenericXBeePacket.create_packet(packet_bytearray, operating_mode=operating_mode)

    elif frame_type == ApiFrameType.AT_COMMAND:
        return ATCommPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.AT_COMMAND_QUEUE:
        return ATCommQueuePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.AT_COMMAND_RESPONSE:
        return ATCommResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RECEIVE_PACKET:
        return ReceivePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RX_64:
        return RX64Packet.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RX_16:
        return RX16Packet.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.REMOTE_AT_COMMAND_REQUEST:
        return RemoteATCommandPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE:
        return RemoteATCommandResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.TRANSMIT_REQUEST:
        return TransmitPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.TRANSMIT_STATUS:
        return TransmitStatusPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.MODEM_STATUS:
        return ModemStatusPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.TX_STATUS:
        return TXStatusPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RX_IO_16:
        return RX16IOPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RX_IO_64:
        return RX64IOPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR:
        return IODataSampleRxIndicatorPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.EXPLICIT_ADDRESSING:
        return ExplicitAddressingPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.EXPLICIT_RX_INDICATOR:
        return ExplicitRXIndicatorPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.TX_SMS:
        return TXSMSPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.TX_IPV4:
        return TXIPv4Packet.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RX_SMS:
        return RXSMSPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.USER_DATA_RELAY_OUTPUT:
        return UserDataRelayOutputPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.RX_IPV4:
        return RXIPv4Packet.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI:
        return RemoteATCommandWifiPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SEND_DATA_REQUEST:
        return SendDataRequestPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.DEVICE_RESPONSE:
        return DeviceResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.USER_DATA_RELAY_REQUEST:
        return UserDataRelayPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE_WIFI:
        return RemoteATCommandResponseWifiPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.IO_DATA_SAMPLE_RX_INDICATOR_WIFI:
        return IODataSampleRxIndicatorWifiPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SEND_DATA_RESPONSE:
        return SendDataResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.DEVICE_REQUEST:
        return DeviceRequestPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.DEVICE_RESPONSE_STATUS:
        return DeviceResponseStatusPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.FRAME_ERROR:
        return FrameErrorPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.REGISTER_JOINING_DEVICE:
        return RegisterJoiningDevicePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.REGISTER_JOINING_DEVICE_STATUS:
        return RegisterDeviceStatusPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_CREATE:
        return SocketCreatePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_CREATE_RESPONSE:
        return SocketCreateResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_OPTION_REQUEST:
        return SocketOptionRequestPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_OPTION_RESPONSE:
        return SocketOptionResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_CONNECT:
        return SocketConnectPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_CONNECT_RESPONSE:
        return SocketConnectResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_CLOSE:
        return SocketClosePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_CLOSE_RESPONSE:
        return SocketCloseResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_SEND:
        return SocketSendPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_SENDTO:
        return SocketSendToPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_BIND:
        return SocketBindListenPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_LISTEN_RESPONSE:
        return SocketListenResponsePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_NEW_IPV4_CLIENT:
        return SocketNewIPv4ClientPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_RECEIVE:
        return SocketReceivePacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_RECEIVE_FROM:
        return SocketReceiveFromPacket.create_packet(packet_bytearray, operating_mode)

    elif frame_type == ApiFrameType.SOCKET_STATE:
        return SocketStatePacket.create_packet(packet_bytearray, operating_mode)

    else:
        return UnknownXBeePacket.create_packet(packet_bytearray, operating_mode=operating_mode)
