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

import random
import string
from digi.xbee.devices import XBeeDevice, RemoteXBeeDevice
from digi.xbee.models.address import XBee64BitAddress
from digi.xbee.util.utils import hex_to_string


# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the 64-bit address of the remote device.
REMOTE_DEVICE_ADDRESS = XBee64BitAddress.from_hex_string("0013A20040D47B73")


def main():

    print(" +---------------------------------+")
    print(" | Get and Set Params Local/Remote |")
    print(" +---------------------------------+\n")

    local_xbee = XBeeDevice(PORT, BAUD_RATE)

    try:
        local_xbee.open()
        remote_xbee = RemoteXBeeDevice(local_xbee, x64bit_addr=REMOTE_DEVICE_ADDRESS)

        local_xbee.read_device_info()
        print("Read device info of local device successfully")
        remote_xbee.read_device_info()
        print("Read device info of remote device successfully")

        print("\nLocal:")
        print(local_xbee.get_node_id())
        print(local_xbee.get_hardware_version())
        print(hex_to_string(local_xbee.get_firmware_version()))
        print(local_xbee.get_protocol())
        print("\nRemote:")
        print(remote_xbee.get_node_id())
        print(remote_xbee.get_hardware_version())
        print(hex_to_string(remote_xbee.get_firmware_version()))
        print(remote_xbee.get_protocol())

        ni = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(1, 20)))
        local_xbee.set_parameter("NI", bytearray(ni, "utf8"))
        param = local_xbee.get_parameter("NI")
        assert (param.decode() == ni)

        ni = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(1, 20)))
        remote_xbee.set_parameter("NI", bytearray(ni, "utf8"))
        param = remote_xbee.get_parameter("NI")
        assert (param.decode() == ni)

        print("\nTest finished successfully")

    finally:
        if local_xbee is not None and local_xbee.is_open():
            local_xbee.close()


if __name__ == '__main__':
    main()
