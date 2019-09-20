# Copyright 2019, Digi International Inc.
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

from digi.xbee import xsocket
from digi.xbee.devices import CellularDevice
from digi.xbee.models.protocol import IPProtocol

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
LISTEN_PORT = 0x1234
ECHO_SERVER_ADDRESS = "52.43.121.77"
ECHO_SERVER_PORT = 10001
# TODO: Optionally, replace with the text to be sent to the server.
ECHO_SERVER_REQUEST = "May the force be with you"


def main():
    print(" +-----------------------------------------------------+")
    print(" | XBee Python Library Socket UDP Server Client Sample |")
    print(" +-----------------------------------------------------+\n")

    device = CellularDevice(PORT, BAUD_RATE)

    try:
        device.open()

        with xsocket.socket(device, IPProtocol.UDP) as sock:
            print("- Starting UDP server at port %s" % LISTEN_PORT)
            sock.bind(("0.0.0.0", LISTEN_PORT))
            print("- Sending '%s' to the echo server" % ECHO_SERVER_REQUEST)
            sock.sendto(ECHO_SERVER_REQUEST.encode("utf-8"), (ECHO_SERVER_ADDRESS, ECHO_SERVER_PORT))
            print("- Waiting for incoming data")
            answer, address = sock.recvfrom(4096)
            if answer is not None:
                print("- Data received from %s:%s - '%s'" % (address[0], address[1], answer.decode("utf-8")))
    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
