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

from digi.xbee.packets.bluetooth import BluetoothGAPScanRequestPacket
from digi.xbee.models.status import BLEGAPScanStatus


class BLEManager:
    """
    Helper class used to manage the BLE Interface on the XBee.

    NOTE: For more information about Shortened and Local Names
    when running a GAP scan, see:
    <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf?v=1707939725200
    """

    GAP_SCAN_DURATION_INDEFINITELY = BluetoothGAPScanRequestPacket.INDEFINITE_SCAN_DURATION
    """
    Value to have the GAP scan run indefinitely
    """

    def __init__(self, xbee):
        """
        Class constructor. Instantiates a new :class:`.BLEManager` with
        the given parameters.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): XBee to manage its
                                                 BLE interface.
        """
        from digi.xbee.devices import XBeeDevice
        if not isinstance(xbee, XBeeDevice):
            raise ValueError("XBee must be an XBee class")

        self.__xbee = xbee
        self.__listening_for_status_events = False
        self.__gap_scan_status = None

    def __str__(self):
        return "BLE (%s)" % self.__xbee

    def __status_callback(self, data):
        """
        Internal BLE GAP scan status Callback

        This function will get called whenever the GAP scanning status
        has changed.
        """
        self.__gap_scan_status = data.status

    def open(self):
        """
        Opens the communication with the BLE Manager.

        This method guarantees that all callbacks are started.
        """
        if not self.__listening_for_status_events:
            self.__xbee._packet_listener.add_ble_gap_scan_status_received_callback(
                                         self.__status_callback)
            self.__listening_for_status_events = True

    def close(self):
        """
        Closes the communication with the BLE Manager.

        This method guarantees that all callbacks are stopped/deleted.
        """
        if self.__status_callback in self.__xbee._packet_listener.get_ble_gap_scan_status_received_callbacks():
            self.__xbee._packet_listener.del_ble_gap_scan_status_received_callback(self.__status_callback)
            self.__listening_for_status_events = False

    @property
    def xbee(self):
        """
        Returns the XBee of this BLE manager.

        Returns:
            :class:`.AbstractXBeeDevice`: XBee to manage its BLE interface.
        """
        return self.__xbee

    def start_ble_gap_scan(self, duration, window, interval, enable_filter,
                           custom_filter):
        """
        Starts a Bluetooth BLE GAP Scan request

        Args:
            duration (Integer): Scan Duration
                                The Scan Duration parameter defines how long
                                the scan should run.
                                Scan duration should be between
                                0 - 65535 (x 1s) (18.20 hr.)
                                If the scan is set to 0 the scan will run
                                indefinitely.

            window (Integer): Scan Window
                              The Scan Window parameter defines how long to
                              scan at each interval.
                              The range is from 2500 – 40959375 (x 1 us)
                              (41 seconds)
                              The window cannot be bigger than the
                              scan interval.

            interval (Integer): Scan Interval
                              The Scan Interval parameter is the duration of
                              time between two consecutive times that the
                              scanner wakes up to receive the advertising messages.
                              The range is from 2500 – 40959375 (x 1 us)
                              (41 seconds)
                              The Interval cannot be smaller than the
                              scan window

            enable_filter (Bool): Filter Type
                                Supported Filter Types:
                                False = Filter Disabled
                                True = Filter advertisements containing the
                                Shortened or Complete Local Name.

            custom_filter (bytes): Filter (optional)
                                   When the 'enable_filter' option is enabled,
                                   the scan will filter the results returned
                                   by matching the filter against the Shortened
                                   or Complete Local Name.
                                   Only items that match will be returned.
                                   The range for the Filter is from 0-22 bytes
                                   In other words, it can only accept up to
                                   22 characters.

        Returns:
            :class:`.XBeePacket`: Received response packet.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TimeoutException: If response is not received in the configured
                timeout.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :meth:`.stop_ble_gap_scan`
        """
        # Ensure we are always listening for status events
        if not self.__listening_for_status_events:
            self.open()

        packet = BluetoothGAPScanRequestPacket(BluetoothGAPScanRequestPacket.START_SCAN,
                                               duration, window, interval,
                                               enable_filter, custom_filter)
        return self.__xbee.send_packet_sync_and_get_response(packet)

    def stop_ble_gap_scan(self):
        """
        Stops a Bluetooth BLE GAP Scan request

        Returns:
            :class:`.XBeePacket`: Received response packet.

        Raises:
            InvalidOperatingModeException: If the XBee's operating mode is not
                API or ESCAPED API. This method only checks the cached value of
                the operating mode.
            TimeoutException: If response is not received in the configured
                timeout.
            XBeeException: If the XBee's communication interface is closed.

        .. seealso::
           | :meth:`.start_ble_gap_scan`
           | :meth:`.is_scan_running`
        """
        packet = BluetoothGAPScanRequestPacket(BluetoothGAPScanRequestPacket.STOP_SCAN,
                                               BluetoothGAPScanRequestPacket.INDEFINITE_SCAN_DURATION,
                                               0x9C4, 0x9C4,
                                               0x00, "")
        return self.__xbee.send_packet_sync_and_get_response(packet)

    def add_ble_gap_advertisement_received_callback(self, callback):
        """
        Adds a callback for the event :class:`.BLEGAPScanReceived`.

        Args:
            callback (Function): The callback. Receives one argument.

                * The data received as a
                      :class:`.BLEGAPScanLegacyAdvertisementMessage` or
                      :class:`.BLEGAPScanExtendedAdvertisementMessage`

        .. seealso::
           | :meth:`.del_ble_gap_advertisement_received_callback`
           | :meth:`.is_scan_running`
        """
        self.__xbee._packet_listener.add_ble_gap_advertisement_received_callback(callback)

    def del_ble_gap_advertisement_received_callback(self, callback):
        """
        Deletes a callback for the callback list of
        :class:`.BLEGAPScanReceived` event.

        Args:
            callback (Function): The callback to delete.

        .. seealso::
           | :meth:`.add_ble_gap_advertisement_received_callback`
        """
        if callback in self.__xbee._packet_listener.get_ble_gap_scan_received_callbacks():
            self.__xbee._packet_listener.del_ble_gap_advertisement_received_callback(callback)

    def is_scan_running(self):
        """
        Returns whether a Bluetooth BLE GAP scan is currently running

        Returns:
            Boolean: `True` if scan is running, `False` otherwise.

        .. seealso::
           | :meth:`.start_ble_gap_scan`
           | :meth:`.stop_ble_gap_scan`
        """
        return self.__gap_scan_status in (BLEGAPScanStatus.STARTED,
                                          BLEGAPScanStatus.RUNNING)
