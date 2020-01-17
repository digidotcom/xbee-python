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
from digi.xbee.io import IOLine, IOMode
import threading
import time

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

IOLINE_IN = IOLine.DIO1_AD1


def main():
    print(" +-------------------------------------------+")
    print(" | XBee Python Library Read Local ADC Sample |")
    print(" +-------------------------------------------+\n")

    th = None

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        device.set_io_configuration(IOLINE_IN, IOMode.ADC)

        stop = False

        def polling_adc():
            while not stop:
                # Read the analog value from the input line.
                value = device.get_adc_value(IOLINE_IN)
                print("%s: %d" % (IOLINE_IN, value))
                time.sleep(1)

        th = threading.Thread(target=polling_adc)
        th.start()

        input()

    finally:
        stop = True
        if th is not None and th.isAlive():
            th.join()
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
