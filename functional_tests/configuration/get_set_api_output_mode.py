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

from digi.xbee.devices import XBeeDevice
from digi.xbee.models.mode import APIOutputModeBit
from digi.xbee.models.protocol import XBeeProtocol

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600

NATIVE = 0
EXPLICIT = APIOutputModeBit.calculate_api_output_mode_value(XBeeProtocol.ZIGBEE,
                                                            {APIOutputModeBit.EXPLICIT})
EXPLICIT_ZDO_PASSTHRU = APIOutputModeBit.calculate_api_output_mode_value(
    XBeeProtocol.ZIGBEE,
    {APIOutputModeBit.EXPLICIT, APIOutputModeBit.UNSUPPORTED_ZDO_PASSTHRU})


def main():

    print(" +----------------------------------+")
    print(" | Get and Set API Output Mode Test |")
    print(" +----------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        for api_output_mode in [EXPLICIT, EXPLICIT_ZDO_PASSTHRU, NATIVE]:
            device.set_api_output_mode_value(api_output_mode)
            ao_mode = device.get_api_output_mode_value()
            assert (ao_mode[0] == api_output_mode)

        print("Test finished successfully")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
