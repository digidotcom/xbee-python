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

import socket

# TODO: Replace with the public IP of the XBee Cellular device.
TCP_SERVER_ADDRESS = "52.43.121.77"
TCP_SERVER_PORT = 0x1234
# TODO: Optionally, replace with the text to be sent to the server.
TCP_SERVER_REQUEST = "May the force be with you"


def main():
    print(" +----------------------------------------------------------+")
    print(" | XBee Python Library Socket TCP Server Sample - PC Client |")
    print(" +----------------------------------------------------------+\n")

    with socket.socket() as sock:
        print("- Connecting to TCP server '%s:%s'" % (TCP_SERVER_ADDRESS, TCP_SERVER_PORT))
        sock.connect((TCP_SERVER_ADDRESS, TCP_SERVER_PORT))
        print("- Sending '%s' to the TCP server" % TCP_SERVER_REQUEST)
        sock.sendall(TCP_SERVER_REQUEST.encode("utf-8"))
        print("- Waiting for echoed data")
        answer = sock.recv(4096)
        if answer is not None:
            print("- Data received: %s" % answer.decode("utf-8"))


if __name__ == '__main__':
    main()
