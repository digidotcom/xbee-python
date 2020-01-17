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

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
DEST_ADDRESS = "numbersapi.com"
DEST_PORT = 80
REQUEST_TEXT = "GET /random/trivia HTTP/1.1\r\n" \
               "Host: numbersapi.com\r\n\r\n"


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Socket TCP Client Sample |")
    print(" +----------------------------------------------+\n")

    device = CellularDevice(PORT, BAUD_RATE)

    try:
        device.open()

        with xsocket.socket(device) as sock:
            print("- Connecting to '%s'" % DEST_ADDRESS)
            sock.connect((DEST_ADDRESS, DEST_PORT))
            print("- Sending request text to the server")
            sock.send(REQUEST_TEXT.encode("utf-8"))
            print("- Waiting for the answer")
            answer = sock.recv(4096)
            print("- Data received:")
            print(answer.decode("utf-8"))

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
