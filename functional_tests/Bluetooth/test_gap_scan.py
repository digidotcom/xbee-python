# Copyright 2024, Digi International Inc.
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
from typing import cast
from digi.xbee.devices import BluDevice
from digi.xbee.models.message import BLEGAPScanLegacyAdvertisementMessage, BLEGAPScanExtendedAdvertisementMessage
from digi.xbee.models.status import BLEMACAddressType
from digi.xbee.exception import TimeoutException
from digi.xbee.models.status import BLEGAPScanStatus


# Configure your test device port and baud rate
PORT_LOCAL = "/dev/ttyUSB0"
BAUD_RATE_LOCAL = "9600"
# Configure a FILTER for testing that you only receive messages from this device
FILTER_TEST = None
# FILTER_TEST = 'ResMed'
# FILTER_TEST = 'ResMed 289272'

# Set to True to check and verify that legacy advertisements are properly received
TEST_LEGACY_ADVERTISEMENTS = True

# Set to True to check and verify that extended advertisements are properly received
TEST_EXTENDED_ADVERTISEMENTS = False


def flush_advertisements(ble_manager):
    # Make sure scanning is off
    ble_manager.stop_ble_gap_scan()
    time.sleep(1)
    print("Flushed advertisements")


def flush_gap_status_messages(ble_manager):
    # Make sure scanning is off
    ble_manager.stop_ble_gap_scan()
    time.sleep(1)
    print("Flushed gap status messages")


def test_gap_scan_request(ble_manager):
    rx_msg = None

    def gap_scan_callback(msg):
        nonlocal rx_msg
        print(f"{msg.to_dict()}")
        rx_msg = msg

    flush_advertisements(ble_manager)

    print("\n\nTest GAP scan request")

    print("Test scan with infinite duration")
    ble_manager.add_ble_gap_advertisement_received_callback(gap_scan_callback)
    print("Start scanning")
    ble_manager.start_ble_gap_scan(0, 0x1111111, 0x1111111, False, "")
    max_time = 60.0
    print("Wait {} seconds for messages".format(max_time))
    start_time = time.time()
    while True:
        time.sleep(0.1)
        if ((time.time() - start_time > max_time) or (rx_msg is not None)):
            break
    print("Stop scanning")
    ble_manager.stop_ble_gap_scan()
    # Verify we got at least 1 message
    if rx_msg is None:
        raise RuntimeError("Failed to receive any Bluetooth advertisements")

    # Test GAP scan for short duration
    duration = 2
    print("Test GAP scan of {} seconds".format(duration))
    ble_manager.start_ble_gap_scan(duration, 0x2222222, 0x2222222, False, "")
    print("Wait for messages for {} seconds".format(duration + 1))
    time.sleep(duration + 1)
    print("Clear messages, we don't expect to get any more")
    rx_msg = None
    time.sleep(2)
    if rx_msg is not None:
        raise RuntimeError("Got message past the duration time")
    print("Stop scanning")
    ble_manager.stop_ble_gap_scan()
    ble_manager.del_ble_gap_advertisement_received_callback(gap_scan_callback)

    print("Success")


def test_gap_scan_parameters(ble_manager):
    flush_advertisements(ble_manager)

    print("\n\nTest different parameter ranges for start_ble_gap_scan")
    duration = 0xFFFF
    print("Test maximum duration {}".format(duration))
    ble_manager.start_ble_gap_scan(duration, 0x1111111, 0x1111111, False, "")
    ble_manager.stop_ble_gap_scan()

    duration += 1
    print("Test maximum duration plus 1 ({}) fails".format(duration))
    try:
        ble_manager.start_ble_gap_scan(duration, 0x1111111, 0x1111111, False, "")
    except Exception:
        pass
    else:
        raise RuntimeError("Failed to see exception passing in duration value of {}".format(duration))

    scan_window = 0x9C4
    print("Test scan window minimum value")
    ble_manager.start_ble_gap_scan(0, scan_window, 0x1111111, False, "")
    ble_manager.stop_ble_gap_scan()

    scan_window -= 1
    print("Test scan window minimum value minus 1 ({}) fails".format(scan_window))
    try:
        ble_manager.start_ble_gap_scan(0, scan_window, 0x1111111, False, "")
    except Exception:
        pass
    else:
        raise RuntimeError("Failed to see exception passing in scan window value of {}".format(scan_window))

    scan_window = 0x270FD8F
    scan_interval = scan_window  # Must be greater or equal to scan window
    print("Test scan window max value of ({})".format(scan_window))
    ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    ble_manager.stop_ble_gap_scan()

    scan_window += 1
    print("Test scan window max value plus 1 ({}) fails".format(scan_window))
    try:
        ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    except Exception:
        pass
    else:
        raise RuntimeError("Failed to see exception passing in scan window value of {}".format(scan_window))

    scan_interval = 0x9C4
    scan_window = scan_interval
    print("Test scan interval minimum value")
    ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    ble_manager.stop_ble_gap_scan()

    scan_interval -= 1
    print("Test scan interval minimum value minus 1 ({}) fails".format(scan_interval))
    try:
        ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    except Exception:
        pass
    else:
        raise RuntimeError("Failed to see exception passing in scan interval value of {}".format(scan_interval))

    scan_interval = 0x270FD8F
    scan_window = 0x1111111
    print("Test scan interval max value of ({})".format(scan_interval))
    ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    ble_manager.stop_ble_gap_scan()

    scan_interval += 1
    print("Test scan interval max value plus 1 ({}) fails".format(scan_interval))
    try:
        ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    except Exception:
        pass
    else:
        raise RuntimeError("Failed to see exception passing in scan interval value of {}".format(scan_interval))

    print("Test scan window greater than scan interval fails")
    scan_interval = 0x1111111
    scan_window = scan_interval + 1
    try:
        ble_manager.start_ble_gap_scan(0, scan_window, scan_interval, False, "")
    except Exception:
        pass
    else:
        raise RuntimeError("Failed to see exception passing in scan window value of {} and scan interval value of {}".format(
            scan_window, scan_interval))

    print("Success")


def test_gap_scan_filter(ble_manager):
    global FILTER_TEST
    rx_msg = None
    failed = False

    def gap_scan_callback(msg):
        global FILTER_TEST
        nonlocal rx_msg
        nonlocal failed
        print(f"{msg.to_dict()}")
        name = msg.name
        if name is None or FILTER_TEST not in name:
            failed = True
            raise RuntimeError("For filter test expected to get: {} but got {}".format(FILTER_TEST, name))
        rx_msg = msg

    flush_advertisements(ble_manager)

    print("\n\nTest scan with filtering")
    ble_manager.add_ble_gap_advertisement_received_callback(gap_scan_callback)
    print("Start scanning")
    ble_manager.start_ble_gap_scan(0, 0x1111111, 0x1111111, True, FILTER_TEST)
    min_time = 5.0  # Test should run for at least this time
    max_time = 60.0
    print("Wait {} seconds for messages".format(max_time))
    start_time = time.time()
    while True:
        time.sleep(0.1)
        current_time = time.time()
        if ((current_time - start_time > max_time) or failed):
            break
        if ((current_time - start_time > min_time) and (rx_msg is not None)):
            break

    print("Stop scanning")
    ble_manager.stop_ble_gap_scan()
    ble_manager.del_ble_gap_advertisement_received_callback(gap_scan_callback)
    # Verify we got at least 1 message
    if rx_msg is None:
        raise RuntimeError("Failed to receive any Bluetooth advertisements")
    if failed:
        raise RuntimeError("Failed to properly filter advertisements")

    print("Success")


def test_legacy_advertisement(ble_manager):
    rx_msg = None

    def gap_scan_callback(msg):
        nonlocal rx_msg
        print(f"{msg.to_dict()}")
        if isinstance(msg, BLEGAPScanLegacyAdvertisementMessage):
            rx_msg = msg

    flush_advertisements(ble_manager)

    print("\n\nTest that we can receive legacy advertisement and that the advertisement message class is correct")
    ble_manager.add_ble_gap_advertisement_received_callback(gap_scan_callback)
    print("Start scanning")
    ble_manager.start_ble_gap_scan(0, 0x1111111, 0x1111111, False, "")
    max_time = 60.0
    print("Wait {} seconds for a message".format(max_time))
    start_time = time.time()
    while True:
        time.sleep(0.1)
        if ((time.time() - start_time > max_time) or (rx_msg is not None)):
            break
    print("Stop scanning")
    ble_manager.stop_ble_gap_scan()
    ble_manager.del_ble_gap_advertisement_received_callback(gap_scan_callback)
    # Verify we got a message
    if rx_msg is None:
        raise RuntimeError("Failed to receive any Bluetooth legacy advertisements")

    msg = cast(BLEGAPScanLegacyAdvertisementMessage, rx_msg)

    # Verify address
    address = msg.address
    if len(address.address) != 6:
        raise RuntimeError("Invalid address {}".format(address.address))

    # Verify address type
    address_type = msg.address_type
    if (address_type not in (
            BLEMACAddressType.PUBLIC,
            BLEMACAddressType.STATIC,
            BLEMACAddressType.RANDOM_RESOLVABLE,
            BLEMACAddressType.RANDOM_NONRESOLVABLE,
            BLEMACAddressType.UNKNOWN)):
        raise RuntimeError("Invalid address_type {}".format(address_type))

    connectable = msg.connectable
    if not isinstance(connectable, bool):
        raise RuntimeError("Invalid connectable {}".format(connectable))

    rssi = msg.rssi
    if not isinstance(rssi, float):
        raise TypeError("rssi is not a float, but {}".format(type(rssi)))
    if ((rssi > 0.0) or (rssi < -255.0)):
        raise ValueError("rssi value {} is out of range".format(rssi))

    name = msg.name
    if name is not None and not isinstance(name, str):
        raise TypeError("name is not a string type or None, but {}".format(type(name)))


def test_extended_advertisement(ble_manager):
    rx_msg = None

    def gap_scan_callback(msg):
        nonlocal rx_msg
        print(f"{msg.to_dict()}")
        if isinstance(msg, BLEGAPScanExtendedAdvertisementMessage):
            rx_msg = msg

    flush_advertisements(ble_manager)

    print("\n\nTest that we can receive extended advertisement and that the advertisement message class is correct")
    ble_manager.add_ble_gap_advertisement_received_callback(gap_scan_callback)
    print("Start scanning")
    ble_manager.start_ble_gap_scan(0, 0x1111111, 0x1111111, False, "")
    max_time = 60.0
    print("Wait {} seconds for a message".format(max_time))
    start_time = time.time()
    while True:
        time.sleep(0.1)
        if ((time.time() - start_time > max_time) or (rx_msg is not None)):
            break
    print("Stop scanning")
    ble_manager.stop_ble_gap_scan()
    ble_manager.del_ble_gap_advertisement_received_callback(gap_scan_callback)
    # Verify we got a message
    if rx_msg is None:
        raise RuntimeError("Failed to receive any Bluetooth extended advertisements")

    msg = cast(BLEGAPScanExtendedAdvertisementMessage, rx_msg)

    # Verify address
    address = msg.address
    if len(address.address) != 6:
        raise RuntimeError("Invalid address {}".format(address.address))

    # Verify address type
    address_type = msg.address_type
    if (address_type not in (
            BLEMACAddressType.PUBLIC,
            BLEMACAddressType.STATIC,
            BLEMACAddressType.RANDOM_RESOLVABLE,
            BLEMACAddressType.RANDOM_NONRESOLVABLE,
            BLEMACAddressType.UNKNOWN)):
        raise RuntimeError("Invalid address_type {}".format(address_type))

    connectable = msg.connectable
    if not isinstance(connectable, bool):
        raise RuntimeError("Invalid connectable {}".format(connectable))

    rssi = msg.rssi
    if not isinstance(rssi, float):
        raise TypeError("rssi is not a float, but {}".format(type(rssi)))
    if ((rssi > 0.0) or (rssi < -255.0)):
        raise ValueError("rssi value {} is out of range".format(rssi))

    name = msg.name
    if name is not None and not isinstance(name, str):
        raise TypeError("name is not a string type or None, but {}".format(type(name)))

    advertisement_set_id = msg.advertisement_set_id
    if not isinstance(advertisement_set_id, int):
        raise TypeError("advertisement_set_id is not type int, but {}".format(type(advertisement_set_id)))

    primary_phy = msg.primary_phy
    if not isinstance(primary_phy, int):
        raise TypeError("primary_phy is not type int, but {}".format(type(primary_phy)))

    secondary_phy = msg.secondary_phy
    if not isinstance(secondary_phy, int):
        raise TypeError("secondary_phy is not type int, but {}".format(type(secondary_phy)))

    periodic_interval = msg.periodic_interval
    if not isinstance(periodic_interval, int):
        raise TypeError("periodic_interval is not type int, but {}".format(type(periodic_interval)))

    data_completeness = msg.data_completeness
    if not isinstance(data_completeness, int):
        raise TypeError("data_completeness is not type int, but {}".format(type(data_completeness)))


def test_gap_scan_status_callback(ble_manager):
    scan_started = 0
    scan_running = 0
    scan_stopped = 0
    scan_error = 0
    scan_invalid_param = 0
    scan_unknown = 0


def main():

    xbee = BluDevice(PORT_LOCAL, BAUD_RATE_LOCAL)
    ble_manager = xbee.get_ble_manager()

    try:
        xbee.open()

        test_gap_scan_request(ble_manager)

        if FILTER_TEST is not None:
            test_gap_scan_filter(ble_manager)

        test_gap_scan_parameters(ble_manager)

        if TEST_LEGACY_ADVERTISEMENTS:
            test_legacy_advertisement(ble_manager)

        if TEST_EXTENDED_ADVERTISEMENTS:
            test_extended_advertisement(ble_manager)

    finally:

        if xbee.is_open():
            xbee.close()


if __name__ == "__main__":
    main()
