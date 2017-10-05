# Copyright 2017, Digi International Inc.
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

from digi.xbee.devices import XBeeDevice
from digi.xbee.models.options import DiscoveryOptions
from digi.xbee.models.protocol import XBeeProtocol

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the node identifier of the remote device.
REMOTE_NODE_ID = "REMOTE"


def main():

    print(" +--------------------------------+")
    print(" | Discover Specific Devices Test |")
    print(" +--------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        network = device.get_network()

        # Discover a valid remote device.
        remote = network.discover_device(REMOTE_NODE_ID)
        assert (remote is not None)
        assert (remote.get_node_id() == REMOTE_NODE_ID)

        # Discover an invalid remote device.
        remote = network.discover_device("!inv4lid_1d!")
        assert (remote is None)

        # Discover myself.
        network.set_discovery_options({DiscoveryOptions.DISCOVER_MYSELF})
        if device.get_protocol() == XBeeProtocol.RAW_802_15_4:
            assert (network.get_discovery_options()[0] == 1)
        else:
            assert (network.get_discovery_options()[0] == 2)
        remote = network.discover_device(device.get_node_id())
        assert (remote == device)

        network.clear()

        # Discover the remote device and myself.
        devices_list = network.discover_devices([REMOTE_NODE_ID, device.get_node_id()])
        assert (len(devices_list) == 2)
        assert (network.get_device_by_node_id(device.get_node_id()) == device)

        # Restore the discovery options.
        network.set_discovery_options({})
        assert (network.get_discovery_options()[0] == 0)

        print("Test finished successfully")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == "__main__":
    main()
