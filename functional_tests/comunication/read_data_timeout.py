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

from digi.xbee.devices import XBeeDevice
from digi.xbee.devices import RemoteXBeeDevice
from digi.xbee.exception import TimeoutException

# TODO: Replace with the serial port where your first local module is connected to.
PORT_LOCAL = "COM1"
# TODO: Replace with the baud rate of your first local module.
BAUD_RATE_LOCAL = 9600
# TODO: Replace with the serial port where your second local module is connected to.
PORT_REMOTE = "COM2"
# TODO: Replace with the baud rate of your second local module.
BAUD_RATE_REMOTE = 9600


def main():

    print(" +------------------------+")
    print(" | Read Data Timeout Test |")
    print(" +------------------------+\n")

    local = XBeeDevice(PORT_LOCAL, BAUD_RATE_LOCAL)
    local_remote = XBeeDevice(PORT_REMOTE, BAUD_RATE_REMOTE)

    message = None
    timeout_exception = None

    try:
        local.open()
        local_remote.open()

        message = local_remote.read_data()
        assert (message is None)

        remote = RemoteXBeeDevice(local, x64bit_addr=local_remote.get_64bit_addr())
        local.send_data(remote, "Test message")

        time.sleep(1)

        message = local_remote.read_data()
        assert (message is not None)
        message = None
        message = local_remote.read_data(3)

    except TimeoutException as e:
        timeout_exception = e

    finally:
        assert (timeout_exception is not None)
        assert (message is None)

        print("Test finished successfully")

        if local is not None and local.is_open():
            local.close()
        if local_remote is not None and local_remote.is_open():
            local_remote.close()


if __name__ == "__main__":
    main()
