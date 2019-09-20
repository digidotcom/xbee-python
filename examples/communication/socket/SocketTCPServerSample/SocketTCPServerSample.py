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
LISTEN_PORT = 0x1234


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Socket TCP Server Sample |")
    print(" +----------------------------------------------+\n")

    device = CellularDevice(PORT, BAUD_RATE)

    try:
        device.open()

        with xsocket.socket(device) as sock:
            print("- Starting TCP server at port %s" % LISTEN_PORT)
            sock.bind(("0.0.0.0", LISTEN_PORT))
            sock.listen()
            print("- Waiting for client")
            client, client_addr = sock.accept()
            print("- Client '%s:%s' connected" % (client_addr[0], client_addr[1]))
            print("- Waiting for incoming data")
            answer = None
            while not answer and client.is_connected:
                answer = client.recv(4096)

            if answer is not None:
                print("- Data received: %s" % answer.decode("utf-8"))
                print("- Sending data back to the client")
                client.sendall(answer)
            else:
                print("- Could not receive data from the client")
            print("- Closing client socket")
            client.close()

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
