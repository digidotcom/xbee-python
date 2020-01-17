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

from digi.xbee.devices import ZigBeeDevice

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

REMOTE_NODE_ID = "REMOTE"
DATA_TO_SEND = "Hello XBee!"

SOURCE_ENDPOINT = 0xA0
DESTINATION_ENDPOINT = 0xA1
CLUSTER_ID = 0x1554
PROFILE_ID = 0x1234


def main():
    print(" +--------------------------------------------------------------+")
    print(" | XBee Python Library Send Explicit Data Asynchronously Sample |")
    print(" +--------------------------------------------------------------+\n")

    device = ZigBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        # Obtain the remote XBee local_xbee from the XBee network.
        xbee_network = device.get_network()
        remote_device = xbee_network.discover_device(REMOTE_NODE_ID)
        if remote_device is None:
            print("Could not find the remote local_xbee")
            exit(1)

        print("Sending explicit data asynchronously to %s >> %s..." % (remote_device.get_64bit_addr(), DATA_TO_SEND))

        device.send_expl_data_async(remote_device, DATA_TO_SEND, SOURCE_ENDPOINT,
                                    DESTINATION_ENDPOINT, CLUSTER_ID, PROFILE_ID)

        print("Success")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
