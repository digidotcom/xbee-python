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

import logging

from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import OperationNotSupportedException, XBeeException, RecoveryException

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# List of baudrates
BAUD_RATES = (115200, 57600, 38400, 19200, 9600)


def main():
    print("""
 +------------------------------------------------------+
 | XBee Python Library Recover serial connection Sample |
 +------------------------------------------------------+
    """)

    for baudrate in BAUD_RATES:
        print("Opening the XBee device by forcing its baudrate to %d" % baudrate)
        device = XBeeDevice(PORT, baudrate)

        try:
            device.open(force_settings=True)
            print("Device opened and set to operate at %d bauds" % baudrate)
        except XBeeException as e:
            print("ERROR: %s" % str(e))
            return
        finally:
            if device is not None and device.is_open():
                device.close()


if __name__ == '__main__':
    main()
