# Copyright 2017-2019, Digi International Inc.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from digi.xbee.models.address import XBee64BitAddress
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice
from digi.xbee.io import IOLine, IOMode

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the 64-bit address of the remote device.
REMOTE_DEVICE_ADDRESS = XBee64BitAddress.from_hex_string("0013A20040D47B73")


def main():

    print(" +---------------------+")
    print(" | Read IO Sample Test |")
    print(" +---------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        device.set_io_configuration(IOLine.DIO1_AD1, IOMode.DIGITAL_IN)

        sample = device.read_io_sample()
        assert (sample.has_digital_value(IOLine.DIO1_AD1))

        remote = RemoteXBeeDevice(device, x64bit_addr=REMOTE_DEVICE_ADDRESS)

        remote.set_io_configuration(IOLine.DIO1_AD1, IOMode.DIGITAL_IN)
        sample = remote.read_io_sample()
        assert (sample.has_digital_value(IOLine.DIO1_AD1))

        print("Test finished successfully")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == "__main__":
    main()
