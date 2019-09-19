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

import time

from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice

# TODO: Replace with the serial port where your first local module is connected to.
PORT_A = "COM1"
# TODO: Replace with the baud rate of your first local module.
BAUD_RATE_A = 9600
# TODO: Replace with the serial port where your second local module is connected to.
PORT_B = "COM2"
# TODO: Replace with the baud rate of your second local module.
BAUD_RATE_B = 9600


def main():

    print(" +-----------------------------+")
    print(" | Add Remote Device by Reader |")
    print(" +-----------------------------+\n")

    device_a = XBeeDevice(PORT_A, BAUD_RATE_A)
    device_b = XBeeDevice(PORT_B, BAUD_RATE_B)

    try:
        device_a.open()
        device_b.open()

        network = device_a.get_network()

        remote = RemoteXBeeDevice(device_b, x64bit_addr=device_a.get_64bit_addr())

        # Send a message from B to A.
        device_b.send_data(remote, "Test")

        # Give some time to device A to receive the packet.
        time.sleep(1)

        # Check that B is in the network of A.
        assert(len(network.get_devices()) == 1)
        try:
            assert(network.get_device_by_64(device_b.get_64bit_addr()) == device_b)
        except AssertionError:
            assert (network.get_device_by_16(device_b.get_16bit_addr()).get_16bit_addr() == device_b.get_16bit_addr())

        # Send another message from B to A.
        device_b.send_data(remote, "Test")

        # Check that B is not duplicated.
        assert (len(network.get_devices()) == 1)
        try:
            assert (network.get_device_by_64(device_b.get_64bit_addr()) == device_b)
        except AssertionError:
            assert (network.get_device_by_16(device_b.get_16bit_addr()).get_16bit_addr() == device_b.get_16bit_addr())

        print("Test finished successfully")

    finally:
        if device_a is not None and device_a.is_open():
            device_a.close()
        if device_b is not None and device_b.is_open():
            device_b.close()


if __name__ == "__main__":
    main()
