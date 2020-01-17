# Copyright 2017, Digi International Inc.
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

from digi.xbee.devices import ZigBeeDevice
from digi.xbee.models.mode import APIOutputModeBit
from digi.xbee.util import utils

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def main():
    print(" +--------------------------------------------------+")
    print(" | XBee Python Library Explicit Data Polling Sample |")
    print(" +--------------------------------------------------+\n")

    device = ZigBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        device.set_api_output_mode_value(
            APIOutputModeBit.calculate_api_output_mode_value(
                device.get_protocol(), {APIOutputModeBit.EXPLICIT}))

        device.flush_queues()

        print("Waiting for data in explicit format...\n")

        while True:
            explicit_xbee_message = device.read_expl_data(None)
            if explicit_xbee_message is not None:
                print("From %s >> %s"
                      % (explicit_xbee_message.remote_device.get_64bit_addr(),
                         explicit_xbee_message.data.decode()))
                print(" - Source endpoint:        %s"
                      % utils.hex_to_string(utils.int_to_length(explicit_xbee_message.source_endpoint)))
                print(" - Destination endpoint:   %s"
                      % utils.hex_to_string(utils.int_to_length(explicit_xbee_message.dest_endpoint)))
                print(" - Cluster ID:             %s"
                      % utils.hex_to_string(utils.int_to_length(explicit_xbee_message.cluster_id)))
                print(" - Profile ID:             %s"
                      % utils.hex_to_string(utils.int_to_length(explicit_xbee_message.profile_id)))

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
