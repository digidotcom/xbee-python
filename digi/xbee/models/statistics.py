# Copyright 2022, Digi International Inc.
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

import copy

from digi.xbee.models.status import TransmitStatus, ATCommandStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.packets.base import DictKeys


class Statistics:
    """
    This class represents all available XBee statistics.
    """

    def __init__(self):
        _dict = {}
        for elem in ApiFrameType:
            _dict[elem.name] = {}
            _dict[elem.name]["pkts"] = 0
            _dict[elem.name]["bytes"] = 0
            _dict[elem.name]["errors"] = 0
        self._tx_dict = copy.deepcopy(_dict)
        self._rx_dict = copy.deepcopy(_dict)

    def _update_rx_stats(self, rx_packet):
        """
        Increases the XBee statistics related with received packets.

        Args:
            rx_packet (:class: `.XBeeAPIPacket`): The received API packet.
        """
        _key = rx_packet.get_frame_type().name
        if _key not in self._rx_dict.keys():
            return

        self._rx_dict[_key]["pkts"] += 1
        self._rx_dict[_key]["bytes"] += rx_packet.effective_len

        if _key in (ApiFrameType.TRANSMIT_STATUS.name, ApiFrameType.TX_STATUS.name):
            tx_status = rx_packet._get_api_packet_spec_data_dict()[DictKeys.TS_STATUS]
            if tx_status != TransmitStatus.SUCCESS:
                self._rx_dict[_key]["errors"] += 1

        if _key == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE.name:
            if rx_packet.status != ATCommandStatus.OK:
                self._rx_dict[_key]["errors"] += 1

    def _update_tx_stats(self, tx_packet):
        """
        Increments the XBee statistics related with transmitted packets.

        Args:
            tx_packet (:class: `.XBeeAPIPacket`): The sent API packet.
        """
        _key = tx_packet.get_frame_type().name
        if _key in self._tx_dict.keys():
            self._tx_dict[_key]["pkts"] += 1
            self._tx_dict[_key]["bytes"] += tx_packet.effective_len

    @property
    def tx_packets(self):
        """
        Gets the current amount of TX packets.

        Returns:
            Integer: Number of TX packets.
        """
        return sum(self._tx_dict[item]["pkts"] for item in self._tx_dict)

    @property
    def rx_packets(self):
        """
        Gets the current amount of RX packets.

        Returns:
            Integer: Number of RX packets.
        """
        return sum(self._rx_dict[item]["pkts"] for item in self._rx_dict)

    @property
    def tx_bytes(self):
        """
        Gets the current amount of TX bytes.

        Returns:
            Integer: Number of TX bytes.
        """
        return sum(self._tx_dict[item]["bytes"] for item in self._tx_dict)

    @property
    def rx_bytes(self):
        """
        Gets the current amount of RX bytes.

        Returns:
            Integer: Number of RX bytes.
        """
        return sum(self._rx_dict[item]["bytes"] for item in self._rx_dict)

    @property
    def rmt_cmd_errors(self):
        """
        Gets the current amount of remote AT command errors.

        Returns:
            Integer: Number of remote AT command errors.
        """
        return self._rx_dict[ApiFrameType.REMOTE_AT_COMMAND_RESPONSE.name]["errors"]

    @property
    def tx_errors(self):
        """
        Gets the current amount of transmit errors.

        Returns:
            Integer: Number of transmit errors.
        """
        return (self._rx_dict[ApiFrameType.TRANSMIT_STATUS.name]["errors"] +
                self._rx_dict[ApiFrameType.TX_STATUS.name]["errors"])
