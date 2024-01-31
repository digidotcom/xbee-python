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

import copy
import curses
from digi.xbee.devices import BluDevice
from digi.xbee.models.message import (
    BLEGAPScanLegacyAdvertisementMessage,
    BLEGAPScanExtendedAdvertisementMessage
)

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


class GapScanCursesDemo:
    """
    BLE GAP Scan Demo using the python curses module
    """

    # Various screen offsets to draw on the screen
    _HEADER_ROW_OFFSET = 0
    _DATA_ROW_OFFSET = 2
    _NAME_COL_OFFSET = 0
    _MAC_COL_OFFSET = 26
    _RSSI_COL_OFFSET = 48
    _CONNECTABLE_COL_OFFSET = 58
    _SEEN_COL_OFFSET = 74

    def __init__(self, ble_manager=None):
        """
        Class constructor for the GapScanCursesDemo
        """
        self._ble_manager = ble_manager
        self._list = []
        self._stdscr = None

    def run(self):
        """
        Runs the BLE GAP scan demo
        """
        curses.wrapper(self._main_loop)

    def _add_advertisement_to_list(self, new_item):
        # Attempt to find the device in current list, if it exists
        found = next((item for item in self._list if item['Address'] == new_item['Address']), None)
        if found:
            # Found it.  Update data and increase counter
            found['Name'] = new_item['Name']
            found['RSSI'] = new_item['RSSI']
            found['Connectable'] = new_item['Connectable']
            found['Count'] += 1
        else:
            # New device.  Add it to our current list
            new_item["Count"] = 1
            self._list.append(new_item)

    def _scan_callback(self, data):
        """
        BLE GAP Scan Callback
        """
        if isinstance(
            data,
            (BLEGAPScanLegacyAdvertisementMessage, BLEGAPScanExtendedAdvertisementMessage)
        ):
            new_item = copy.deepcopy(data.to_dict())
            self._add_advertisement_to_list(new_item)

            count = 0
            for item in self._list:
                name = item['Name'] if item['Name'] else "N/A"
                # Clear name area, and then write the name
                self._stdscr.addstr(self._DATA_ROW_OFFSET + count,
                                    self._NAME_COL_OFFSET, ' ' * 22)
                self._stdscr.addstr(self._DATA_ROW_OFFSET + count,
                                    self._NAME_COL_OFFSET, name)
                # Add rest of the data points
                addr = ':'.join(item['Address'][i:i+2] for i in range(0, 12, 2))
                self._stdscr.addstr(self._DATA_ROW_OFFSET + count,
                                    self._MAC_COL_OFFSET, addr)
                self._stdscr.addstr(self._DATA_ROW_OFFSET + count,
                                    self._RSSI_COL_OFFSET - 1,
                                    str(int(item['RSSI'])) + ' dBm')
                self._stdscr.addstr(self._DATA_ROW_OFFSET + count,
                                    self._CONNECTABLE_COL_OFFSET,
                                    str(item['Connectable']))
                self._stdscr.addstr(self._DATA_ROW_OFFSET + count,
                                    self._SEEN_COL_OFFSET, str(item['Count']))
                count += 1

            # Finally, refresh the screen
            self._stdscr.refresh()

    def _setup_screen(self):
        """
        Set up the initial screen
        """

        # Start colors in curses
        curses.use_default_colors()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)

        # Clear and set the bacoground screen for a blank canvas
        self._stdscr.clear()
        self._stdscr.bkgd(' ', curses.color_pair(1))

        # Hide the cursor
        curses.curs_set(0)

        # Set up our titles at the top of the screen
        self._stdscr.addstr(self._HEADER_ROW_OFFSET,
                            self._NAME_COL_OFFSET, "Name")
        self._stdscr.addstr(self._HEADER_ROW_OFFSET,
                            self._MAC_COL_OFFSET, "MAC Address")
        self._stdscr.addstr(self._HEADER_ROW_OFFSET,
                            self._RSSI_COL_OFFSET, "RSSI")
        self._stdscr.addstr(self._HEADER_ROW_OFFSET,
                            self._CONNECTABLE_COL_OFFSET, "Connectable")
        self._stdscr.addstr(self._HEADER_ROW_OFFSET,
                            self._SEEN_COL_OFFSET, "Seen")

        # Refresh once more
        self._stdscr.refresh()

    def _main_loop(self, stdscr):
        """
        The GapScanCursesDemo's main loop
        """
        self._stdscr = stdscr

        # Set up the basic screen
        self._setup_screen()

        # Set up callback for any results that come in
        self._ble_manager.add_ble_gap_advertisement_received_callback(self._scan_callback)

        # Start the GAP scan request
        self._ble_manager.start_ble_gap_scan(0, 10000, 10000, False, '')

        # Loop where k is the last character pressed
        k = 0
        while (k != ord('q')):
            k = self._stdscr.getch()

        # Out of loop, stop scan
        self._ble_manager.stop_ble_gap_scan()
        self._ble_manager.del_ble_gap_advertisement_received_callback(self._scan_callback)


def main():
    ble_manager = None
    device = BluDevice(PORT, BAUD_RATE)
    try:
        device.open()
        ble_manager = device.get_ble_manager()
        ret = GapScanCursesDemo(ble_manager)
        ret.run()
    except Exception as e:
        print(str(e))
        exit(1)
    finally:
        if device.is_open():
            if ble_manager:
                ble_manager.close()
            device.close()


if __name__ == "__main__":
    main()
