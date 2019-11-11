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
from digi.xbee.models.status import ModemStatus

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def main():

    print(" +------------+")
    print(" | Reset Test |")
    print(" +------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    def modem_status_callback(status):
        if status == ModemStatus.COORDINATOR_STARTED:
            return
        assert (status in [ModemStatus.HARDWARE_RESET, ModemStatus.WATCHDOG_TIMER_RESET])

    try:
        device.open()

        device.add_modem_status_received_callback(modem_status_callback)

        for i in range(10):
            device.reset()
            time.sleep(1)

        print("Test finished successfully")

    finally:
        device.del_modem_status_received_callback(modem_status_callback)

        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
