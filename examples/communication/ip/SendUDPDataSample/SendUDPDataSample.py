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

from ipaddress import IPv4Address
from digi.xbee.devices import NBIoTDevice
from digi.xbee.models.protocol import IPProtocol

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the destination IP address.
DEST_IP_ADDRESS = "192.168.1.2"
# TODO: Replace with the destination port number (in decimal format).
DEST_PORT = 9750

PROTOCOL = IPProtocol.UDP
DATA_TO_SEND = "Hello XBee!"


def main():
    print(" +------------------------------------------+")
    print(" | XBee Python Library Send UDP Data Sample |")
    print(" +------------------------------------------+\n")

    device = NBIoTDevice(PORT, BAUD_RATE)

    try:
        device.open()

        if not device.is_connected():
            print(">> Error: the device is not connected to the network")
            return

        print("Sending data to %s:%d >> %s..." % (DEST_IP_ADDRESS, DEST_PORT, DATA_TO_SEND))

        device.send_ip_data(IPv4Address(DEST_IP_ADDRESS), DEST_PORT, PROTOCOL, DATA_TO_SEND)

        print("Success")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
