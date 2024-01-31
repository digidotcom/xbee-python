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

from digi.xbee.devices import BluDevice

# Configure your test device port and baud rate
PORT_LOCAL = "COM1"
BAUD_RATE_LOCAL = 9600


def main():
    print(" +---------------------------+")
    print(" | XBee BLU device info test |")
    print(" +---------------------------+\n")

    local = BluDevice(PORT_LOCAL, BAUD_RATE_LOCAL)

    try:
        local.open()
        local.read_device_info()

        print("Firmware Version:", local.get_firmware_version().hex())

        hv = local.get_hardware_version()
        print("Hardware Version: %s (0x%02X)" % (hv, hv.code))

        print("Bluetooth MAC:", local.get_bluetooth_mac_addr())
        print(
            "Bluetooth Identifier:",
            ascii(
                local.get_parameter("BI").decode(
                    "ascii", errors="backslashreplace"
                )
            )
        )

        print("Serial Number:", local.get_64bit_addr())
        print("Node ID:", ascii(local.get_node_id()))

    finally:
        if local.is_open():
            local.close()


if __name__ == "__main__":
    main()
