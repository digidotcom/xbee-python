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

from digi.xbee.packets.base import XBeeAPIPacket, DictKeys
from digi.xbee.exception import InvalidOperatingModeException, \
                                InvalidPacketException
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.models.mode import OperatingMode
from digi.xbee.util import utils
from digi.xbee.models.address import XBeeBLEAddress


class BluetoothGAPScanRequestPacket(XBeeAPIPacket):
    """
    This class represents a Bluetooth GAP scan request packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    .. seealso::
       | :class:`.BluetoothGAPScanRequestPacket`
       | :class:`.XBeeAPIPacket`
    """

    # Various defines, max/mins
    STOP_SCAN = 0x00
    """
    Constant value used to stop the scan
    """
    START_SCAN = 0x01
    """
    Constant value used to start the scan
    """
    INDEFINITE_SCAN_DURATION = 0x00
    """
    Constant value for an indefinite scan
    """

    # Internal only
    __SCAN_DURATION_MINIMUM = 0x1
    __SCAN_DURATION_MAXIMUM = 0xFFFF
    __SCAN_WINDOW_MINIMUM = 0x9C4
    __SCAN_WINDOW_MAXIMUM = 0x270FD8F
    __SCAN_INTERVAL_MINIMUM = 0x9C4
    __SCAN_INTERVAL_MAXIMUM = 0x270FD8F
    __SCAN_FILTER_DISABLED = 0x00
    __SCAN_FILTER_ENABLED = 0x01
    __SCAN_CUSTOM_FILTER_MAXIMUM_LENGTH = 22

    __MIN_PACKET_LENGTH = 17

    def __init__(self, start_command, scan_duration, scan_window,
                 scan_interval, filter_type, filter_data,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.BluetoothGAPScanRequestPacket`
        object with the provided parameters.

        Args:
            start_command (Integer): To start scan set to 1.
                                     To stop scan set to 0.
            scan_duration (Integer): Scan duration in seconds.
                                     Value must be between 0 and 0xFFFF.
            A value of 0 indicates the scan will run indefinitely.
            scan_window (Integer): Scan window in microseconds.
            Value must be between 0x9C4 and 0x270FD8F and
            value can't be larger than the scan_interval.
            scan_interval (Integer): Scan interval in microseconds.
                                     Value must be between 0x9C4 and
                                     0x270FD8F and
                                     value can't be smaller than the
                                     scan_window.
            filter_type (Integer): Value of 0 disables filter.
                                   Value of 1 enables filter looking for
                                   Complete Local Name (0x09) and
                                   Short Local Name (0x08) types.
            filter_data (String or bytearray): The size of the filter_data is
                                               from 0-22 bytes.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                     The mode in which the frame was captured.


        Raises:
            ValueError: if `start_command` is not 0 nor 1.
            ValueError: if `scan_duration` is not between 0 and 0xFFFF.
            ValueError: if `scan_window` is not between 0x9C4 and 0x270FD8F
                        or larger than the scan_interval.
            ValueError: if `scan_interval` is not between 0x9C4 and 0x270FD8F
                        or smaller than the scan_window.
            ValueError: if `filter_type` is not 0 nor 1.

        .. seealso::
           | :class:`.XBeeAPIPacket`
        """
        if start_command not in (self.START_SCAN, self.STOP_SCAN):
            raise ValueError(f"Command must be {self.START_SCAN} or {self.STOP_SCAN}")

        if scan_duration is None:
            raise ValueError("The scan duration cannot be None")

        if not self.INDEFINITE_SCAN_DURATION <= scan_duration <= self.__SCAN_DURATION_MAXIMUM:
            raise ValueError(f"scan_duration must be between {self.INDEFINITE_SCAN_DURATION} and {self.__SCAN_DURATION_MAXIMUM}")

        if scan_window is None:
            raise ValueError("The scan window cannot be None")

        if not self.__SCAN_WINDOW_MINIMUM <= scan_window <= self.__SCAN_WINDOW_MAXIMUM:
            raise ValueError(f"scan_window must be between {self.__SCAN_WINDOW_MINIMUM} and {self.__SCAN_WINDOW_MAXIMUM}")

        if scan_interval is None:
            raise ValueError("The scan interval cannot be None")

        if not self.__SCAN_INTERVAL_MINIMUM <= scan_interval <= self.__SCAN_INTERVAL_MAXIMUM:
            raise ValueError(f"scan_interval must be between {self.__SCAN_INTERVAL_MINIMUM} and {self.__SCAN_INTERVAL_MAXIMUM}")

        if scan_interval < scan_window:
            raise ValueError("scan_interval can't be smaller than the scan_window")

        if filter_type not in (self.__SCAN_FILTER_DISABLED, self.__SCAN_FILTER_DISABLED):
            raise ValueError(f"filter_type must be {self.__SCAN_FILTER_DISABLED} or {self.__SCAN_FILTER_DISABLED}")

        if filter_data and len(filter_data) > self.__SCAN_CUSTOM_FILTER_MAXIMUM_LENGTH:
            raise ValueError(f"The length of the custom filter must be from 0-{self.__SCAN_CUSTOM_FILTER_MAXIMUM_LENGTH}")

        super().__init__(ApiFrameType.BLUETOOTH_GAP_SCAN_REQUEST,
                         op_mode=op_mode)

        self.__start_command = start_command
        self.__scan_duration = scan_duration
        self.__scan_window = scan_window
        self.__scan_interval = scan_interval
        self.__filter_type = filter_type

        if isinstance(filter_data, str):
            self.__filter_data = filter_data.encode('utf8', errors='ignore')
        else:
            self.__filter_data = filter_data

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.BluetoothGAPScanRequestPacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 17.
                (start delim, length (2 bytes), frame type,
                start_command, scan_duration (2 bytes), scan_window (4 bytes),
                scan_interval (4 bytes), filter_type, checksum = 17 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :py:attr:`.ApiFrameType.BLUETOOTH_GAP_SCAN_REQUEST`.
            InvalidOperatingModeException: if `operating_mode`
                                           is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(raw, min_length=BluetoothGAPScanRequestPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.BLUETOOTH_GAP_SCAN_REQUEST.code:
            raise InvalidPacketException(message="This packet is not a BluetoothGAPScanRequestPacket packet")

        filter_data = None
        if len(raw) > BluetoothGAPScanRequestPacket.__MIN_PACKET_LENGTH:
            filter_data = raw[17:-1]
        return BluetoothGAPScanRequestPacket(
            raw[4], utils.bytes_to_int(raw[5:7]),
            utils.bytes_to_int(raw[7:11]),
            utils.bytes_to_int(raw[11:15]), raw[15],
            filter_data, op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data`
        """
        ret = bytearray()
        ret.append(self.__start_command)
        ret += utils.int_to_bytes(self.__scan_duration, num_bytes=2)
        ret += utils.int_to_bytes(self.__scan_window, num_bytes=4)
        ret += utils.int_to_bytes(self.__scan_interval, num_bytes=4)
        ret.append(self.__filter_type)
        if self.__filter_data is not None:
            ret += self.__filter_data
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_api_packet_spec_data_dict`
        """
        return {DictKeys.BLE_SCAN_START: self.__start_command,
                DictKeys.BLE_SCAN_DURATION.value: "%02X" %
                                                  self.__scan_duration,
                DictKeys.BLE_SCAN_WINDOW.value: "%04X" % self.__scan_window,
                DictKeys.BLE_SCAN_INTERVAL.value: "%04X" %
                                                  self.__scan_interval,
                DictKeys.BLE_SCAN_FILTER_TYPE: self.__scan_interval,
                DictKeys.PAYLOAD.value: utils.hex_to_string(self.__filter_data,
                                                            True) if self.__filter_data is not None else None}

    @property
    def start_command(self):
        """
        Returns the start_command.

        Returns:
            Integer: the start_command.
        """
        return self.__start_command

    @start_command.setter
    def start_command(self, start_command):
        """
        Sets the start_command.

        Args:
             start_command (Integer): To start scan set to 1.
                                      To stop scan set to 0.

        Raises:
            ValueError: if `start_command` is less than 0 or greater than 1.
        """
        if start_command < 0 or start_command > 1:
            raise ValueError("start_command must be between 0 and 1.")
        self.__start_command = start_command

    @property
    def scan_duration(self):
        """
        Returns the scan duration.

        Returns:
            Integer: the scan duration.
        """
        return self.__scan_duration

    @scan_duration.setter
    def scan_duration(self, scan_duration):
        """
        Sets the scan duration.

        Args:
             scan_duration (Integer): Scan duration in seconds.
                                      Value must be between 0 and 0xFFFF.

        Raises:
            ValueError: if `scan_duration` is less than 0 or greater
                        than 0xFFFF.
        """
        if scan_duration < 0 or scan_duration > 0xFFFF:
            raise ValueError("scan_duration must be between 0 and 0xFFFF.")
        self.__scan_duration = scan_duration

    @property
    def scan_window(self):
        """
        Returns the scan window.

        Returns:
            Integer: the scan window.
        """
        return self.__scan_window

    @scan_window.setter
    def scan_window(self, scan_window):
        """
        Sets the scan window.

        Args:
             scan_window (Integer): Scan window in microseconds.
             Scan window in microseconds.
             Value must be between 0x9C4 and 0x270FD8F.

        Raises:
            ValueError: if `scan_window` is less than 0x9C4 or greater
                        than 0x270FD8F.
        """
        if scan_window < 0x9C4 or scan_window > 0x270FD8F:
            raise ValueError(f"scan_window must be between {self.__SCAN_WINDOW_MINIMUM} and {self.__SCAN_WINDOW_MAXIMUM}.")
        self.__scan_window = scan_window

    @property
    def scan_interval(self):
        """
        Returns the scan interval.

        Returns:
            Integer: the scan interval.
        """
        return self.__scan_interval

    @scan_interval.setter
    def scan_interval(self, scan_interval):
        """
        Sets the scan interval.

        Args:
             scan_interval (Integer): Scan window in microseconds.
             Scan window in microseconds.
             Value must be between 0x9C4 and 0x270FD8F.

        Raises:
            ValueError: if `scan_interval` is less than 0x9C4 or greater
                        than 0x270FD8F.
        """
        if scan_interval < 0x9C4 or scan_interval > 0x270FD8F:
            raise ValueError(f"scan_interval must be between {self.__SCAN_INTERVAL_MINIMUM} and {self.__SCAN_INTERVAL_MAXIMUM}.")
        self.__scan_interval = scan_interval

    @property
    def filter_type(self):
        """
        Returns the filter_type.

        Returns:
            Integer: the filter_type.
        """
        return self.__filter_type

    @filter_type.setter
    def filter_type(self, filter_type):
        """
        Sets the filter_type.
        Args:
             filter_type (Integer): Value of 0 disables filter.
                                    Value of 1 enables filter looking for
            Complete Local Name (0x09) and Short Local Name (0x08) types.

        Raises:
            ValueError: if `filter_type` is less than 0 or greater than 1.
        """
        if filter_type < 0 or filter_type > 1:
            raise ValueError("filter_type must be between 0 and 1.")
        self.__filter_type = filter_type

    @property
    def filter_data(self):
        """
        Returns the filter data.

        Returns:
            Bytearray: packet's filter data.
        """
        return self.__filter_data

    @filter_data.setter
    def filter_data(self, filter_data):
        """
        Sets the filter data.

        Args:
            filter_data (String or Bytearray): the new filter data.
        """
        if isinstance(filter_data, str):
            self.__filter_data = filter_data.encode('utf8', errors='ignore')
        else:
            self.__filter_data = filter_data


class BluetoothGAPScanLegacyAdvertisementResponsePacket(XBeeAPIPacket):
    """
    This class represents a Bluetooth GAP scan legacy advertisement
    response packet.
    Packet is built using the parameters of the constructor or providing a
    valid byte array.

    .. seealso::
       | :class:`.BluetoothGAPScanLegacyAdvertisementResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 16

    def __init__(self, address, address_type, advertisement_flags, rssi,
                 payload, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new :class:`.BluetoothGAPScanLegacyAdvertisementResponsePacket`
        object with the provided parameters.

        Args:
            address (:class:`.XBeeBLEAddress`): The Bluetooth MAC address of
                                                the received advertisement
            address_type (Integer): Indicates whether the Bluetooth address
                                    is a public address or a randomly
                                    generated address.
            advertisement_flags (Integer): bitfield structure where bit0
                                           indicates whether the advertisement
                                           is connectable.
                                           Other bits are reserved.
            rssi (Integer): The received signal strength of the advertisement,
                            in dBm.
            payload (bytearray): The actual data payload of the advertisement
                                 which can contain various information elements,
                                 manufacturer-specific data, or other relevant
                                 details about the advertising device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                     The mode in which the frame was captured.

        Raises:
            ValueError: if length of `payload` is less than 16 or greater
                        than 255.

        .. seealso::
            | :class:`.XBeeBLEAddress`
        """
        if len(payload) > 255:
            raise ValueError("Response payload length must be less than 256 bytes")

        super().__init__(ApiFrameType.BLUETOOTH_GAP_SCAN_LEGACY_ADVERTISEMENT_RESPONSE,
                         op_mode=op_mode)

        self.__address = address
        self.__address_type = address_type
        self.__advertisement_flags = advertisement_flags
        self.__rssi = rssi
        self.__payload = payload

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.BluetoothGAPScanLegacyAdvertisementResponsePacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 32.
                (start delim + length (2 bytes) + frame type
                + address (6 bytes) + address_type + advertisement_flags
                + rssi + reserved + payload_length + checksum = 16 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :py:attr:`.ApiFrameType.BluetoothGAPScanLegacyAdvertisementResponsePacket`.
            InvalidPacketException: if the payload_length field does not match
                                    the actual
                length of the payload.
            InvalidOperatingModeException: if `operating_mode` is not
                                           supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=BluetoothGAPScanLegacyAdvertisementResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.BLUETOOTH_GAP_SCAN_LEGACY_ADVERTISEMENT_RESPONSE.code:
            raise InvalidPacketException(message="This packet is not an BLUETOOTH_GAP_SCAN_LEGACY_ADVERTISEMENT_RESPONSE")

        payload = None
        if len(raw) > BluetoothGAPScanLegacyAdvertisementResponsePacket.__MIN_PACKET_LENGTH:
            payload = raw[15:-1]

        payload_length = raw[14]
        if len(payload) != payload_length:
            raise InvalidPacketException(
                message="BluetoothGAPScanLegacyAdvertisementResponsePacket payload length field is %u and does not match actual length of payload that is %u".format(
                    payload_length, len(payload)
                ))

        return BluetoothGAPScanLegacyAdvertisementResponsePacket(
            XBeeBLEAddress(raw[4:10]), raw[10], raw[11], raw[12], payload,
            op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = bytearray()
        ret.append(len(self.__address.address))
        ret.append(self.__address_type)
        ret.append(self.__advertisement_flags)
        ret.append(self.__rssi)
        ret.append(0)
        if self.__payload is not None:
            ret.append(len(self.__payload))
            ret += self.__payload
        else:
            ret.append(0)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {DictKeys.BLE_ADDRESS: "%s (%s)" % (self.__address.packed,
                                                   self.__address.exploded),
                DictKeys.BLE_ADDRESS_TYPE: self.__address_type,
                DictKeys.BLE_ADVERTISEMENT_FLAGS: self.__advertisement_flags,
                DictKeys.RSSI: self.__rssi,
                DictKeys.RESERVED: 0,
                DictKeys.PAYLOAD.value: utils.hex_to_string(self.__payload,
                                                            True) if self.__payload is not None else None}

    @property
    def address(self):
        """
        Returns the Bluetooth MAC address of the received advertisement.

        Returns:
            address (:class:`.XBeeBLEAddress`): returns the Bluetooth
                                                MAC address.
        """
        return self.__address

    @address.setter
    def address(self, address):
        """
        Sets the BLE MAC address of the received advertisement

        Args:
            address (:class:`.XBeeBLEAddress`): the 48 bit BLE MAC address.
        """
        if address is not None:
            self.__address = address

    @property
    def address_type(self):
        """
        Returns the address type of the received advertisement.

        Returns:
            Integer: the address type.
        """
        return self.__address_type

    @address_type.setter
    def address_type(self, address_type):
        """
        Sets the address type indicating whether the Bluetooth address is a
            public or randomly generated address.

        Args:
             address_type (Integer): address type
        """
        self.__address_type = address_type

    @property
    def advertisement_flags(self):
        """
        Returns the advertisement flags.

        Returns:
            Integer: the advertisement flags.
        """
        return self.__advertisement_flags

    @advertisement_flags.setter
    def advertisement_flags(self, advertisement_flags):
        """
        Sets the Advertisement flags type.
        Bit 0 indicates whether the advertisement is connectable.

        Args:
             advertisement_flags (Integer): advertisement flag
        """
        self.__advertisement_flags = advertisement_flags

    @property
    def rssi(self):
        """
        Returns the RSSI of the advertisement.

        Returns:
            Integer: the RSSI.
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the RSSI of the advertisement in dBm.

        Args:
             rssi (Integer): the RSSI
        """
        self.__rssi = rssi

    @property
    def payload(self):
        """
        Returns the payload that was received.

        Returns:
            Bytearray: the payload that was received.
        """
        if self.__payload is None:
            return None
        return self.__payload.copy()

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload that was received.

        Args:
            payload (Bytearray): the new payload that was received.
        """
        if payload is None:
            self.__payload = None
        else:
            self.__payload = payload.copy()


class BluetoothGAPScanExtendedAdvertisementResponsePacket(XBeeAPIPacket):
    """
    This class represents a Bluetooth GAP scan extended advertisement response
    packet. Packet is built using the parameters of the constructor or
    providing a valid byte array.

    .. seealso::
       | :class:`.BluetoothGAPScanExtendedAdvertisementResponsePacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 23

    def __init__(self, address, address_type, advertisement_flags, rssi,
                 advertisement_set_id, primary_phy, secondary_phy, tx_power,
                 periodic_interval, data_completeness, payload,
                 op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.BluetoothGAPScanExtendedAdvertisementResponsePacket` object
        with the provided parameters.

        Args:
            address (:class:`.XBeeBLEAddress`): The Bluetooth MAC address of
                                                the received advertisement
            address_type (Integer): Indicates whether the Bluetooth address is
                                    a public address or a randomly
                                    generated address.
            advertisement_flags (Integer): bitfield structure where bit0
                indicates whether the advertisement is connectable.
                Other bits are reserved.
            rssi (Integer) The received signal strength of the advertisement,
                           in dBm.
            advertisement_set_id (Integer): A device can broadcast multiple
                                            advertisements at a time.
                                            The set identifier will help
                                            identify which advertisement
                                            you received.
            primary_phy (Integer): This is the preferred PHY for connecting
                                   with this device.  Values are:
                                   0x1 : 1M PHY
                                   0x2 : 2M PHY
                                   0x4 : LE Coded PHY 125k
                                   0x8 : LE Coded PHY 500k
                                   0xFF : Any PHY supported
            secondary_phy (Integer): This is the secondary PHY for connecting
                                     with this device.
                                     This has the same values as primary_phy.
            tx_power (Integer): Transmission power of received advertisement.
                                This is a signed value.
            periodic_interval (Integer): Interval for periodic advertising.
                                         0 indicates no periodic advertising.
                                         Interval value is in increments of 1.25 ms.
            data_completeness (Integer): Values are
                                         0x0 indicates all data of the advertisement has been reported.
                                         0x1 : Data is incomplete, but more data will follow.
                                         0x2 : Data is incomplete, but no more data is following.
                                         Data has be truncated.
            payload (bytearray): The actual data payload of the advertisement
                                 which can contain various information elements,
                                 manufacturer-specific data, or other relevant details
                                 about the advertising device.
            op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                     The mode in which the frame was captured.

        Raises:
            ValueError: if length of `payload` is less than 22 or
                        greater than 255.
        """

        if len(payload) > 255:
            raise ValueError("Response payload length must be less than 256 bytes")

        super().__init__(ApiFrameType.BLUETOOTH_GAP_SCAN_EXTENDED_ADVERTISEMENT_RESPONSE,
                         op_mode=op_mode)

        self.__address = address
        self.__address_type = address_type
        self.__advertisement_flags = advertisement_flags
        self.__rssi = rssi
        self.__advertisement_set_id = advertisement_set_id
        self.__primary_phy = primary_phy
        self.__secondary_phy = secondary_phy
        self.__tx_power = tx_power
        self.__periodic_interval = periodic_interval
        self.__data_completeness = data_completeness
        self.__payload = payload

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.BluetoothGAPScanExtendedAdvertisementResponsePacket`

        Raises:
            InvalidPacketException: if the bytearray length is less than 45.
                (start delim + length (2 bytes) + frame type
                + address (6 bytes) + address_type + advertisement_flags
                + rssi + reserved + advertisement_set_id + primary_phy
                + secondary_phy + tx_power + periodic_interval (2 bytes)
                + data_completeness + payload_length + checksum = 23 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :py:attr:`.ApiFrameType.BluetoothGAPScanExtendedAdvertisementResponsePacket`.
            InvalidOperatingModeException: if `operating_mode` is not
                                           supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=BluetoothGAPScanExtendedAdvertisementResponsePacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.BLUETOOTH_GAP_SCAN_EXTENDED_ADVERTISEMENT_RESPONSE.code:
            raise InvalidPacketException(message="This packet is not an BLUETOOTH_GAP_SCAN_EXTENDED_ADVERTISEMENT_RESPONSE")

        payload = None
        if len(raw) > BluetoothGAPScanExtendedAdvertisementResponsePacket.__MIN_PACKET_LENGTH:
            payload = raw[22:-1]

        payload_length = raw[21]
        if len(payload) != payload_length:
            raise InvalidPacketException(
                message="BluetoothGAPScanExtendedAdvertisementResponsePacket payload length field is %u and does not match actual length of payload that is %u".format(
                    payload_length, len(payload)
                ))

        return BluetoothGAPScanExtendedAdvertisementResponsePacket(
            XBeeBLEAddress(raw[4:10]), raw[10], raw[11], raw[12], raw[14],
            raw[15], raw[16], raw[17], raw[18:19], raw[20],
            payload, op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = bytearray()
        ret.append(len(self.__address.address))
        ret.append(self.__address_type)
        ret.append(self.__advertisement_flags)
        ret.append(self.__rssi)
        ret.append(self.__advertisement_set_id)
        ret.append(self.__primary_phy)
        ret.append(self.__secondary_phy)
        ret.append(self.__tx_power)
        ret += self.__periodic_interval
        ret.append(self.__data_completeness)
        ret.append(0)
        if self.__payload is not None:
            ret.append(len(self.__payload))
            ret += self.__payload
        else:
            ret.append(0)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`

        """
        return {DictKeys.BLE_ADDRESS: "%s (%s)" % (self.__address.packed,
                                                   self.__address.exploded),
                DictKeys.BLE_ADDRESS_TYPE: self.__address_type,
                DictKeys.BLE_ADVERTISEMENT_FLAGS: self.__advertisement_flags,
                DictKeys.RSSI: self.__rssi,
                DictKeys.RESERVED: 0,
                DictKeys.ADVERTISEMENT_SET_ID: self.__advertisement_set_id,
                DictKeys.PRIMARY_PHY: self.__primary_phy,
                DictKeys.SECONDARY_PHY: self.__secondary_phy,
                DictKeys.TX_POWER: self.__tx_power,
                DictKeys.PERIODIC_INTERVAL: self.__periodic_interval,
                DictKeys.DATA_COMPLETENESS: self.__data_completeness,
                DictKeys.PAYLOAD.value: utils.hex_to_string(self.__payload,
                                                            True) if self.__payload is not None else None}

    @property
    def address(self):
        """
        Returns the Bluetooth MAC address of the received advertisement.

        Returns:
            address (:class:`.XBeeBLEAddress`): returns the Bluetooth
                                                MAC address.
        """
        return self.__address

    @address.setter
    def address(self, address):
        """
        Sets the BLE MAC address of the received advertisement

        Args:
            address (byt:class:`.XBeeBLEAddress`): the 48 bit BLE MAC address.
        """
        self.__address = address

    @property
    def address_type(self):
        """
        Returns the address type

        Returns:
            Integer: the address type.
        """
        return self.__address_type

    @address_type.setter
    def address_type(self, address_type):
        """
        Sets the address type indicating whether the Bluetooth address is a
        public or randomly generated address.

        Args:
             address_type (Integer): address type
        """
        self.__address_type = address_type

    @property
    def advertisement_flags(self):
        """
        Returns the Advertisement flags

        Returns:
            Integer: the advertisement flags.
        """
        return self.__advertisement_flags

    @advertisement_flags.setter
    def advertisement_flags(self, advertisement_flags):
        """
        Sets the Advertisement flags type.
        Bit 0 indicates whether the advertisement is connectable.

        Args:
             advertisement_flags (Integer): advertisement flag
        """
        self.__advertisement_flags = advertisement_flags

    @property
    def rssi(self):
        """
        Returns the RSSI of the advertisement.

        Returns:
            Integer: the RSSI.
        """
        return self.__rssi

    @rssi.setter
    def rssi(self, rssi):
        """
        Sets the RSSI of the advertisement in dBm.

        Args:
             rssi (Integer): the RSSI
        """
        self.__rssi = rssi

    @property
    def advertisement_set_id(self):
        """
        Returns the advertisement set identifier used to help identify which
        advertisement you received.

        Returns:
            Integer: the advertisement set identifier.
        """
        return self.__advertisement_set_id

    @advertisement_set_id.setter
    def advertisement_set_id(self, advertisement_set_id):
        """
        Sets the advertisement set identifier.

        Args:
             advertisement_set_id (Integer):
        """
        self.__advertisement_set_id = advertisement_set_id

    @property
    def primary_phy(self):
        """
        Returns the preferred PHY for connecting this device.

        Returns:
            Integer: the primary PHY
        """
        return self.__primary_phy

    @primary_phy.setter
    def primary_phy(self, primary_phy):
        """
        Sets the preferred PHY for connecting this device.

        Args:
             primary_phy (Integer): primary PHY
        """
        self.__primary_phy = primary_phy

    @property
    def secondary_phy(self):
        """
        Returns the secondary PHY for connecting this device.

        Returns:
            Integer: the secondary PHY.
        """
        return self.__secondary_phy

    @secondary_phy.setter
    def secondary_phy(self, secondary_phy):
        """
        Sets the secondary PHY for connecting this device.

        Args:
             secondary_phy (Integer): secondary PHY
        """
        self.__secondary_phy = secondary_phy

    @property
    def tx_power(self):
        """
        Returns the transmission power of received advertisement.
        This is a signed value.

        Returns:
            Integer: transmission power.
        """
        return self.__tx_power

    @tx_power.setter
    def tx_power(self, tx_power):
        """
        Sets the transmission power of received advertisement.

        Args:
             tx_power (Integer): transmission power.
        """
        self.__tx_power = tx_power

    @property
    def periodic_interval(self):
        """
        Returns the interval for periodic advertising.
        0 indicates no periodic advertising.

        Returns:
            Integer: periodic interval.
        """
        return int.from_bytes(self.__periodic_interval, "big")

    @periodic_interval.setter
    def periodic_interval(self, periodic_interval):
        """
        Sets the Interval for periodic advertising.

        Args:
             periodic_interval (Integer): periodic interval.
        """
        self.__periodic_interval = periodic_interval

    @property
    def data_completeness(self):
        """
        Returns the data completeness field.

        Returns:
            Integer: data completeness field.
        """
        return self.__data_completeness

    @data_completeness.setter
    def data_completeness(self, data_completeness):
        """
        Sets the data completeness field.

        Args:
             data_completeness (Integer): data completeness.
        """
        self.__data_completeness = data_completeness

    @property
    def payload(self):
        """
        Returns the payload that was received.

        Returns:
            Bytearray: the payload that was received.
        """
        if self.__payload is None:
            return None
        return self.__payload.copy()

    @payload.setter
    def payload(self, payload):
        """
        Sets the payload that was received.

        Args:
            payload (Bytearray): the new payload that was received.
        """
        if payload is None:
            self.__payload = None
        else:
            self.__payload = payload.copy()


class BluetoothGAPScanStatusPacket(XBeeAPIPacket):
    """
    This class represents a Bluetooth GAP scan status packet. Packet is built
    using the parameters of the constructor or providing a valid byte array.

    .. seealso::
       | :class:`.BluetoothGAPScanStatusPacket`
       | :class:`.XBeeAPIPacket`
    """

    __MIN_PACKET_LENGTH = 6

    def __init__(self, scan_status, op_mode=OperatingMode.API_MODE):
        """
        Class constructor. Instantiates a new
        :class:`.BluetoothGAPScanStatusPacket` object with the provided parameters.

        Args:
            scan_status (Integer): Reflects the status of the
                        Bluetooth scanner.  Values are:
                        0x00: Scanner has successfully started.
                        0x01: Scanner is currently running.
                        0x02: Scanner has successfully stopped.
                        0x03: Scanner was unable to start or stop.
                        0x04: Invalid parameters.

           op_mode (:class:`.OperatingMode`, optional, default=`OperatingMode.API_MODE`):
                The mode in which the frame was captured.
        """

        super().__init__(ApiFrameType.BLUETOOTH_GAP_SCAN_STATUS,
                         op_mode=op_mode)

        self.__scan_status = scan_status

    @staticmethod
    def create_packet(raw, operating_mode):
        """
        Override method.

        Returns:
            :class:`.BluetoothGAPScanStatusPacket`

        Raises:
            InvalidPacketException: if the bytearray length is not 6.
                (start delim + length (2 bytes) + frame type
                + scan_status + checksum = 6 bytes)
            InvalidPacketException: if the length field of `raw` is different
                from its real length. (length field: bytes 2 and 3)
            InvalidPacketException: if the first byte of `raw` is not the
                header byte. See :class:`.SPECIAL_BYTE`.
            InvalidPacketException: if the calculated checksum is different
                from the checksum field value (last byte).
            InvalidPacketException: if the frame type is different from
                :py:attr:`.ApiFrameType.BluetoothGAPScanLegacyAdvertisementResponsePacket`.
            InvalidOperatingModeException: if `operating_mode`
                                           is not supported.

        .. seealso::
           | :meth:`.XBeePacket.create_packet`
        """
        if operating_mode not in (OperatingMode.ESCAPED_API_MODE,
                                  OperatingMode.API_MODE):
            raise InvalidOperatingModeException(op_mode=operating_mode)

        XBeeAPIPacket._check_api_packet(
            raw, min_length=BluetoothGAPScanStatusPacket.__MIN_PACKET_LENGTH)

        if raw[3] != ApiFrameType.BLUETOOTH_GAP_SCAN_STATUS.code:
            raise InvalidPacketException(
                      message="This packet is not an BLUETOOTH_GAP_SCAN_STATUS"
                      )

        return BluetoothGAPScanStatusPacket(
            raw[4], op_mode=operating_mode)

    def needs_id(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket.needs_id`
        """
        return False

    def _get_api_packet_spec_data(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data`
        """
        ret = bytearray()
        ret.append(self.__scan_status)
        ret.append(0)
        return ret

    def _get_api_packet_spec_data_dict(self):
        """
        Override method.

        .. seealso::
           | :meth:`.XBeeAPIPacket._get_API_packet_spec_data_dict`
        """
        return {DictKeys.SCAN_STATUS: self.__scan_status}

    @property
    def scan_status(self):
        """
        Returns the scan status of the Bluetooth scanner.

        Returns:
            Integer: scan status
        """
        return self.__scan_status

    @scan_status.setter
    def scan_status(self, scan_status):
        """
        Sets the scan status.

        Args:
            scan_status: (Integer) scan status
        """
        self.__scan_status = scan_status
