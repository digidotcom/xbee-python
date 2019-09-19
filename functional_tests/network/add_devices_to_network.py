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


from digi.xbee.devices import RemoteXBeeDevice, XBeeDevice
from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress


# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

ADDR_64_REMOTE_A = XBee64BitAddress.from_hex_string("0013A200AAAAAAAA")
ADDR_64_REMOTE_B = XBee64BitAddress.from_hex_string("0013A200BBBBBBBB")

ADDR_16_REMOTE_A = XBee16BitAddress.from_hex_string("AAAA")
ADDR_16_REMOTE_A_2 = XBee16BitAddress.from_hex_string("BBBB")

NODE_ID_REMOTE_A = "TEST"


def main():

    print(" +---------------------------------+")
    print(" | Add Devices to the Network Test |")
    print(" +---------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        network = device.get_network()

        # Add "Remote A" device with 64-bit address.
        remote_a = RemoteXBeeDevice(device, x64bit_addr=ADDR_64_REMOTE_A)
        network.add_remote(remote_a)
        assert (len(network.get_devices()) == 1)
        assert (network.get_device_by_64(ADDR_64_REMOTE_A) == remote_a)

        # Add "Remote B" device with 64-bit address.
        remote_b = RemoteXBeeDevice(device, x64bit_addr=ADDR_64_REMOTE_B)
        network.add_remote(remote_b)
        assert (len(network.get_devices()) == 2)
        assert (network.get_device_by_64(ADDR_64_REMOTE_B) == remote_b)

        # Construct again "Remote A" with 16-bit address and add it to the network.
        remote_a = RemoteXBeeDevice(device, x64bit_addr=ADDR_64_REMOTE_A,
                                    x16bit_addr=ADDR_16_REMOTE_A)
        network.add_remote(remote_a)
        assert (len(network.get_devices()) == 2)
        assert (network.get_device_by_64(ADDR_64_REMOTE_A) == remote_a)
        assert (network.get_device_by_16(ADDR_16_REMOTE_A) == remote_a)

        # Construct again "Remote A" with a different 16-bit address and add it to the network.
        remote_a = RemoteXBeeDevice(device, x64bit_addr=ADDR_64_REMOTE_A,
                                    x16bit_addr=ADDR_16_REMOTE_A_2)
        network.add_remote(remote_a)
        assert (len(network.get_devices()) == 2)
        assert (network.get_device_by_64(ADDR_64_REMOTE_A) == remote_a)
        assert (network.get_device_by_16(ADDR_16_REMOTE_A) is None)
        assert (network.get_device_by_16(ADDR_16_REMOTE_A_2) == remote_a)

        # Set the node ID to "Remote A" and add it again to the network.
        remote_a = RemoteXBeeDevice(device, x64bit_addr=ADDR_64_REMOTE_A,
                                    x16bit_addr=ADDR_16_REMOTE_A_2, node_id=NODE_ID_REMOTE_A)
        network.add_remote(remote_a)
        assert (len(network.get_devices()) == 2)
        assert (network.get_device_by_node_id(NODE_ID_REMOTE_A) == remote_a)

        print("Test finished successfully")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == "__main__":
    main()
