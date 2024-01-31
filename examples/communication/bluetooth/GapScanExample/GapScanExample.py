# Copyright 2024, Digi International Inc.
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
from digi.xbee.devices import BluDevice
from digi.xbee.models.message import (
    BLEGAPScanLegacyAdvertisementMessage,
    BLEGAPScanExtendedAdvertisementMessage,
)


# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

# Time for the BLE GAP scan to run for
TIME_TO_SCAN = 10


def main():
    print(" +---------------------------------------------------+")
    print(" | XBee Python Library Receive Bluetooth Data Sample |")
    print(" +---------------------------------------------------+\n")

    device = BluDevice(PORT, BAUD_RATE)

    try:
        ble_manager = device.get_ble_manager()
        device.open()

        def scan_callback(data):
            """
            BLE GAP scan Callback

            This function will get called whenever
            a new GAP scan entry has been received.
            """
            if isinstance(
                data,
                (BLEGAPScanLegacyAdvertisementMessage, BLEGAPScanExtendedAdvertisementMessage)
            ):
                print(data.to_dict())

        ble_manager.add_ble_gap_advertisement_received_callback(scan_callback)

        print("Starting BLE GAP scan...\n")
        ble_manager.start_ble_gap_scan(TIME_TO_SCAN, 10000, 10000, False, "")

        # Wait for a moment to allow the radio to start the scan
        time.sleep(.5)

        # Wait until the scan finishes.
        while ble_manager.is_scan_running():
            time.sleep(1)

    finally:
        if device is not None and device.is_open():
            ble_manager.del_ble_gap_advertisement_received_callback(scan_callback)
            device.close()


if __name__ == '__main__':
    main()
