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

from digi.xbee.devices import CellularDevice

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the phone number of the device to send the SMS to.
PHONE = ""
# TODO: Optionally, replace with the text of the SMS.
SMS_TEXT = "Hello from XBee Cellular!"


def main():
    print(" +-------------------------------------+")
    print(" | XBee Python Library Send SMS Sample |")
    print(" +-------------------------------------+\n")

    device = CellularDevice(PORT, BAUD_RATE)

    try:
        device.open()

        print("Sending SMS to %s >> %s..." % (PHONE, SMS_TEXT))

        device.send_sms(PHONE, SMS_TEXT)

        print("Success")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
