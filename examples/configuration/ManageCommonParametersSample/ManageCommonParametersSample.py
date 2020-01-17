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
from digi.xbee.models.address import XBee64BitAddress
from digi.xbee.models.status import PowerLevel

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

PARAM_VALUE_PAN_ID = bytearray(b'\x01\x23')
PARAM_DESTINATION_ADDR = XBee64BitAddress.BROADCAST_ADDRESS
PARAM_POWER_LEVEL = PowerLevel.LEVEL_MEDIUM


def main():
    print(" +-----------------------------------------------------+")
    print(" | XBee Python Library Manage Common parameters Sample |")
    print(" +-----------------------------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        print("Cached parameters\n" + "-" * 50)
        print("64-bit address:   %s" % device.get_64bit_addr())
        print("16-bit address:   %s" % device.get_16bit_addr())
        print("Node Identifier:  %s" % device.get_node_id())
        print("Firmware version: %s" % utils.hex_to_string(device.get_firmware_version()))
        print("Hardware version: %s" % device.get_hardware_version().description)

        print("")

        # Configure and read non-cached parameters.
        device.set_pan_id(PARAM_VALUE_PAN_ID)
        device.set_dest_address(PARAM_DESTINATION_ADDR)
        device.set_power_level(PARAM_POWER_LEVEL)

        print("Non-Cached parameters\n" + "-" * 50)
        print("PAN ID:           %s" % utils.hex_to_string(device.get_pan_id()))
        print("Dest address:     %s" % device.get_dest_address())
        print("Power level:      %s" % device.get_power_level().description)

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
