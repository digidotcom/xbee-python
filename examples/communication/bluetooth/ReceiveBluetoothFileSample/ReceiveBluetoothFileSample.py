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

from digi.xbee.devices import XBeeDevice
from datetime import datetime

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

SEPARATOR = "@@@"

MSG_START = "START" + SEPARATOR
MSG_END = "END"
MSG_ACK = "OK"


def main():
    print(" +---------------------------------------------------+")
    print(" | XBee Python Library Receive Bluetooth File Sample |")
    print(" +---------------------------------------------------+\n")

    file = None

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        def bluetooth_data_callback(data):
            global file

            # Check if the data is 'START' or 'END'.
            if data.startswith(bytearray(MSG_START, 'utf-8')):
                # Get the file name.
                file_name = data.decode('utf-8').split(SEPARATOR)[1]
                # Open the file for writing.
                file = open(file_name, "w+b")
                print(">> START message received, saving data to file...")
                send_ack(device)
            elif data == bytearray(MSG_END, 'utf-8'):
                file.close()
                print(">> END message received, file '%s'\n" % file.name)
                send_ack(device)
            elif file is not None:
                payload = data[:-1]
                checksum = data[-1]
                # Validate the checksum.
                if 0xFF - (sum(payload) & 0xFF) == checksum:
                    # Write block to file.
                    file.write(payload)
                    send_ack(device)

        device.add_bluetooth_data_received_callback(bluetooth_data_callback)

        print("Waiting for data from the Bluetooth interface...\n")
        input()

    finally:
        if file is not None and file.closed:
            file.close()
        if device is not None and device.is_open():
            device.close()


def send_ack(device):
    """
    Sends the ACK message to the given XBee device.

    Args:
        device: XBee device to send the message to.
    """
    device.send_bluetooth_data(MSG_ACK.encode("utf-8"))


if __name__ == '__main__':
    main()
