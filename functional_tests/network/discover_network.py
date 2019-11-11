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

import time

from digi.xbee.devices import XBeeDevice


# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def main():

    print(" +-----------------------+")
    print(" | Discover Network Test |")
    print(" +-----------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    def device_discovered_callback(remote):
        devices_callback.append(remote)

    try:
        device.open()

        network = device.get_network()

        devices_callback = []

        network.add_device_discovered_callback(device_discovered_callback)

        network.start_discovery_process()

        while network.is_discovery_running():
            time.sleep(0.1)

        assert(devices_callback == network.get_devices())

        print("Test finished successfully")

    finally:
        network.del_device_discovered_callback(device_discovered_callback)

        if device is not None and device.is_open():
            device.close()


if __name__ == "__main__":
    main()
