# Copyright 2017, Digi International Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from digi.xbee.devices import XBeeDevice
from digi.xbee.util import utils

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

PARAM_NODE_ID = "NI"
PARAM_PAN_ID = "ID"
PARAM_DEST_ADDRESS_H = "DH"
PARAM_DEST_ADDRESS_L = "DL"

PARAM_VALUE_NODE_ID = "Yoda"
PARAM_VALUE_PAN_ID = utils.hex_string_to_bytes("1234")
PARAM_VALUE_DEST_ADDRESS_H = utils.hex_string_to_bytes("00")
PARAM_VALUE_DEST_ADDRESS_L = utils.hex_string_to_bytes("FFFF")


def main():
    print(" +-----------------------------------------------+")
    print(" | XBee Python Library Set/Get parameters Sample |")
    print(" +-----------------------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        # Set parameters.
        device.set_parameter(PARAM_NODE_ID, bytearray(PARAM_VALUE_NODE_ID, 'utf8'))
        device.set_parameter(PARAM_PAN_ID, PARAM_VALUE_PAN_ID)
        device.set_parameter(PARAM_DEST_ADDRESS_H, PARAM_VALUE_DEST_ADDRESS_H)
        device.set_parameter(PARAM_DEST_ADDRESS_L, PARAM_VALUE_DEST_ADDRESS_L)

        # Get parameters.
        print("Node ID:                     %s" % device.get_parameter(PARAM_NODE_ID).decode())
        print("PAN ID:                      %s" % utils.hex_to_string(device.get_parameter(PARAM_PAN_ID)))
        print("Destination address high:    %s" % utils.hex_to_string(device.get_parameter(PARAM_DEST_ADDRESS_H)))
        print("Destination address low:     %s" % utils.hex_to_string(device.get_parameter(PARAM_DEST_ADDRESS_L)))

        print("")
        print("All parameters were set correctly!")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
