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

import time

from digi.xbee.models.address import XBee64BitAddress
from digi.xbee.models.status import NetworkDiscoveryStatus
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def callback_discovery_finished(status):
    if status == NetworkDiscoveryStatus.SUCCESS:
        print("  Discovery process finished successfully.")
    else:
        print("  There was an error discovering devices: %s" % status.description)


def cb_network_modified(event_type, reason, node):
    print("  >>>> Network event:")
    print("         Type: %s (%d)" % (event_type.description, event_type.code))
    print("         Reason: %s (%d)" % (reason.description, reason.code))

    if not node:
        return

    print("         Node:")
    print("            %s" % node)


def print_nodes(xb_net):
    print("\n  Current network nodes:\n    ", end='')
    if xb_net.has_devices():
        print("%s" % '\n    '.join(map(str, xb_net.get_devices())))
    else:
        print("None")


def main():
    print(" +----------------------------------------------------------+")
    print(" | XBee Python Library Network modifications Devices Sample |")
    print(" +----------------------------------------------------------+\n")

    xbee_network = None

    xbee = XBeeDevice(PORT, BAUD_RATE)

    try:
        xbee.open()

        xbee_network = xbee.get_network()

        xbee_network.set_discovery_timeout(15)  # 15 seconds.

        xbee_network.add_discovery_process_finished_callback(callback_discovery_finished)

        xbee_network.add_network_modified_callback(cb_network_modified)

        print("* Discover remote XBee devices...")

        xbee_network.start_discovery_process()

        while xbee_network.is_discovery_running():
            time.sleep(1)

        print_nodes(xbee_network)

        print("\n* Manually add a new remote XBee device...")
        remote = RemoteXBeeDevice(
            xbee,
            x64bit_addr=XBee64BitAddress.from_hex_string("1234567890ABCDEF"),
            node_id="manually_added")
        xbee_network.add_remote(remote)

        print_nodes(xbee_network)

        time.sleep(1)

        print("\n* Update the last added remote XBee device...")
        remote = RemoteXBeeDevice(xbee, x64bit_addr=remote.get_64bit_addr(), node_id="updated_node")
        xbee_network.add_remote(remote)

        print_nodes(xbee_network)

        time.sleep(1)

        print("\n* Manually remove a remote XBee device...")
        xbee_network.remove_device(remote)

        print_nodes(xbee_network)

        time.sleep(1)

        print("\n* Clear network...")
        xbee_network.clear()

        print_nodes(xbee_network)

    finally:
        if xbee_network is not None:
            xbee_network.del_discovery_process_finished_callback(callback_discovery_finished)
            xbee_network.del_network_modified_callback(cb_network_modified)

        if xbee is not None and xbee.is_open():
            xbee.close()


if __name__ == '__main__':
    main()
