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

from digi.xbee.models.mode import OperatingMode
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.common import ATCommPacket, ATCommQueuePacket, TransmitPacket
from digi.xbee.packets.raw import TX64Packet, TX16Packet, TXStatusPacket
from digi.xbee.packets.wifi import RemoteATCommandWifiPacket
from digi.xbee.util import utils

# from digi.xbee.packets.socket import SocketSendPacket, SocketSendToPacket, SocketBindListenPacket, \
#     SocketListenResponsePacket, SocketNewIPv4ClientPacket, SocketReceivePacket, SocketReceiveFromPacket, \
#     SocketStatusPacket
#
#
# print("Socket Send Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E001A440102005468697320697320612074657374207061796C6F6164B9")
# print(utils.hex_to_string(payload))
# packet = SocketSendPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket SendTo Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E00204501020A6502FF1234005468697320697320612074657374207061796C6F616402")
# print(utils.hex_to_string(payload))
# packet = SocketSendToPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket Bind/Listen Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E0005460102123470")
# print(utils.hex_to_string(payload))
# packet = SocketBindListenPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket Listen Response Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E0004C601020333")
# print(utils.hex_to_string(payload))
# packet = SocketListenResponsePacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket New IPv4 Client Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E0009CC0102C0A8016412341D")
# print(utils.hex_to_string(payload))
# packet = SocketNewIPv4ClientPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket Receive Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E001FCD01020054686973206973206A75737420612074657374205061796C6F61646A")
# print(utils.hex_to_string(payload))
# packet = SocketReceivePacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket Receive From Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E0021CE0102FFFFFFFFFFFF005468697320697320616E6F74686572207061796C6F616485")
# print(utils.hex_to_string(payload))
# packet = SocketReceiveFromPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")
#
# print("Socket Status Packet:")
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E0003CF010728")
# print(utils.hex_to_string(payload))
# packet = SocketStatusPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")





# 0x00 - TX (Transmit) Request 64-bit address
print("%s Packet" % ApiFrameType.TX_64.description)
print("--------------------------")
payload = utils.hex_string_to_bytes("7E001E00010123456789ABCDEF045468697320697320746865207061796C6F61643B")
print(utils.hex_to_string(payload))
packet = TX64Packet.create_packet(payload, OperatingMode.API_MODE)
for key in packet.to_dict():
    print("  - %s: %s" % (key, packet.to_dict()[key]))
assert payload == packet.output(), "%s Packet payload does not match the provided one." % \
                                   ApiFrameType.TX_64.description
print("--------------------------")
print("")

# 0x01 - TX (Transmit) Request 16-bit address
print("%s Packet" % ApiFrameType.TX_16.description)
print("--------------------------")
payload = utils.hex_string_to_bytes("7E00180101ABCD005468697320697320746865207061796C6F616486")
print(utils.hex_to_string(payload))
packet = TX16Packet.create_packet(payload, OperatingMode.API_MODE)
for key in packet.to_dict():
    print("  - %s: %s" % (key, packet.to_dict()[key]))
assert payload == packet.output(), "%s Packet payload does not match the provided one." % \
                                   ApiFrameType.TX_16.description
print("--------------------------")
print("")

# 0x07 - Remote AT Command Request (Wi-Fi)
print("%s - %s Packet" % (ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI.code,
                          ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI.description))
print("--------------------------")
payload = utils.hex_string_to_bytes("7E0016070100000000C0A80164024E494E65772076616C75652A")
print(utils.hex_to_string(payload))
packet = RemoteATCommandWifiPacket.create_packet(payload, OperatingMode.API_MODE)
for key in packet.to_dict():
    print("  - %s: %s" % (key, packet.to_dict()[key]))
assert payload == packet.output(), "%s Packet payload does not match the provided one." % \
                                   ApiFrameType.REMOTE_AT_COMMAND_REQUEST_WIFI.description
print("--------------------------")
print("")

# 0x08 - AT Command
print("%s Packet" % ApiFrameType.AT_COMMAND.description)
print("--------------------------")
payload = utils.hex_string_to_bytes("7E000E08014E494964656E7469666965725C")
print(utils.hex_to_string(payload))
packet = ATCommPacket.create_packet(payload, OperatingMode.API_MODE)
for key in packet.to_dict():
    print("  - %s: %s" % (key, packet.to_dict()[key]))
assert payload == packet.output(), "%s Packet payload does not match the provided one." % \
                                   ApiFrameType.AT_COMMAND.description
print("--------------------------")
print("")

# 0x09 - AT Command Queue
print("%s Packet" % ApiFrameType.AT_COMMAND_QUEUE.description)
print("--------------------------")
payload = utils.hex_string_to_bytes("7E000E09014E494964656E7469666965725B")
print(utils.hex_to_string(payload))
packet = ATCommQueuePacket.create_packet(payload, OperatingMode.API_MODE)
for key in packet.to_dict():
    print("  - %s: %s" % (key, packet.to_dict()[key]))
assert payload == packet.output(), "%s Packet payload does not match the provided one." % \
                                   ApiFrameType.AT_COMMAND_QUEUE.description
print("--------------------------")
print("")

# 0x10 - Transmit Request
print("%s Packet" % ApiFrameType.TRANSMIT_REQUEST.description)
print("--------------------------")
payload = utils.hex_string_to_bytes("7E002110010123456789ABCDEFABCD01025468697320697320746865207061796C6F6164B4")
print(utils.hex_to_string(payload))
packet = TransmitPacket.create_packet(payload, OperatingMode.API_MODE)
for key in packet.to_dict():
    print("  - %s: %s" % (key, packet.to_dict()[key]))
assert payload == packet.output(), "%s Packet payload does not match the provided one." % \
                                   ApiFrameType.TRANSMIT_REQUEST.description
print("--------------------------")
print("")


# # 0x89 - TX (Transmit) Status
# print("%s Packet" % ApiFrameType.TX_STATUS.description)
# print("--------------------------")
# payload = utils.hex_string_to_bytes("7E000389013144")
# print(utils.hex_to_string(payload))
# packet = TXStatusPacket.create_packet(payload, OperatingMode.API_MODE)
# for key in packet.to_dict():
#     print("  - %s: %s" % (key, packet.to_dict()[key]))
# print("--------------------------")
# print("")