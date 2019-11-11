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

import datetime
import random
import string
import time

import sys

from digi.xbee.devices import ZigBeeDevice
from digi.xbee.exception import TimeoutException
from digi.xbee.util import utils


SOURCE_ENDPOINT = 0xE8
DEST_ENDPOINT = 0xE8
CLUSTER_ID = 0x0012
PROFILE_ID = 0xC105
MAX_RETRIES = 3


def main(argv):

    if len(argv) != 3:
        print("Usage: long_test.py <port> <baud_rate> <duration_in_seconds>")
        return

    print(" +-------------------------------+")
    print(" | Long duration and stress test |")
    print(" +-------------------------------+\n")

    port = argv[0]
    baud_rate = int(argv[1])
    duration = int(argv[2])

    device = ZigBeeDevice(port, baud_rate)

    # Add a data received callback.
    def data_callback(message):
        if message.remote_device.get_64bit_addr() == remote.get_64bit_addr():
            print("%s - [C] - %s" % (datetime.datetime.now(), message.data.decode()))
            # Ensure that the sent and received messages are equal.
            assert (data == message.data.decode())

    try:
        device.open()

        # Discover the network.
        network = device.get_network()
        network.start_discovery_process()

        print("Discovering network...")

        # Wait until the discovery process has finished.
        while network.is_discovery_running():
            time.sleep(0.1)

        if not network.has_devices():
            print("No remote modules in the network")
            return

        # Get the first device of the network that is not an end device.
        remote = None
        for dev in network.get_devices():
            if utils.bytes_to_int(dev.get_parameter("SM")) == 0:
                remote = dev
                break

        if remote is None:
            print("No routers in the network")
            return

        print("Selected remote device: %s" % remote)

        device.add_data_received_callback(data_callback)

        print("Sending data...\n")

        dead_line = time.time() + duration

        while dead_line > time.time():
            retries = MAX_RETRIES
            data_received = False
            while not data_received:
                try:
                    data = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(1, 84)))
                    print("%s - [S] - %s" % (datetime.datetime.now(), data))
                    # Send explicit data to the loopback cluster.
                    device.send_expl_data(remote, data, SOURCE_ENDPOINT, DEST_ENDPOINT, CLUSTER_ID, PROFILE_ID)
                    # Read new data from the remote device.
                    msg = device.read_data_from(remote, timeout=10)
                    print("%s - [P] - %s" % (datetime.datetime.now(), msg.data.decode()))
                    data_received = True
                    # Ensure that the sent and received messages are equal.
                    assert (data == msg.data.decode())
                except TimeoutException as ex:
                    retries -= 1
                    if retries == 0:
                        raise ex

                # Wait some time between 1 and 5 seconds.
                time.sleep(random.randint(1, 5))

        print("\nTest finished successfully")

    finally:

        device.del_data_received_callback(data_callback)

        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main(sys.argv[1:])
