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
from digi.xbee.devices import CellularDevice
from digi.xbee.models.protocol import IPProtocol

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Optionally, replace with the text you want to send to the server.
TEXT = "Hello XBee!"

ECHO_SERVER = "52.43.121.77"
ECHO_SERVER_PORT = 11001
PROTOCOL = IPProtocol.TCP


def main():
    print(" +---------------------------------------------------+")
    print(" | XBee Python Library Connect to Echo Server Sample |")
    print(" +---------------------------------------------------+\n")

    device = CellularDevice(PORT, BAUD_RATE)

    try:
        device.open()

        if not device.is_connected():
            print(">> Error: the device is not connected to the network")
            return

        print("Sending text to %s:%d >> %s..." % (ECHO_SERVER, ECHO_SERVER_PORT, TEXT))

        device.send_ip_data(IPv4Address(ECHO_SERVER), ECHO_SERVER_PORT, PROTOCOL, TEXT)

        print("Success")

        # Read the echoed data.
        ip_message = device.read_ip_data()
        if ip_message is None:
            print("Echo response was not received from the server.")
            return

        print("Echo response received from %s:%d >> '%s'" % (ip_message.ip_addr, ip_message.source_port,
                                                             ip_message.data.decode("utf8")))

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
