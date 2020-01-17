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
import time
import threading

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

IO_LINE_IN = IOLine.DIO3_AD3
IO_LINE_OUT = IOLine.DIO4_AD4


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Get/Set Local DIO Sample |")
    print(" +----------------------------------------------+\n")

    stop = False
    th = None

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        def io_detection_callback():
            while not stop:
                # Read the digital value from the input line.
                io_value = device.get_dio_value(IO_LINE_IN)
                print("%s: %s" % (IO_LINE_IN, io_value))

                # Set the previous value to the output line.
                device.set_dio_value(IO_LINE_OUT, io_value)

                time.sleep(1)

        th = threading.Thread(target=io_detection_callback)

        device.set_io_configuration(IO_LINE_IN, IOMode.DIGITAL_IN)
        device.set_io_configuration(IO_LINE_OUT, IOMode.DIGITAL_OUT_LOW)

        time.sleep(1)
        th.start()

        input()

    finally:
        stop = True
        if th is not None and th.is_alive():
            th.join()
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
