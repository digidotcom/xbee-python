# Copyright 2017-2019, Digi International Inc.
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

from digi.xbee.devices import WiFiDevice
from digi.xbee.models.mode import IPAddressingMode
from digi.xbee.models.status import ModemStatus

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO Fill with the SSID of the access point you want to connect to.
SSID = ""
# TODO Fill with the password of the access point you want to connect to.
PASSWORD = ""


def main():
    print(" +----------------------------------------------------+")
    print(" | XBee Python Library Connect to Access Point Sample |")
    print(" +----------------------------------------------------+\n")

    device = WiFiDevice(PORT, BAUD_RATE)

    try:
        device.open()

        if device.is_connected():
            device.disconnect()

        device.set_ip_addressing_mode(IPAddressingMode.DHCP)

        def modem_status_receive_callback(modem_status):
            print("Modem status: %s" % modem_status.description)
            if modem_status == ModemStatus.JOINED_NETWORK:
                print(">> Successfully connected to '%s'" % SSID)
            elif modem_status == ModemStatus.STATUS_DISASSOCIATED:
                print(">> Disconnected from the access point")

        device.add_modem_status_received_callback(modem_status_receive_callback)

        if not device.connect_by_ssid(SSID, password=PASSWORD):
            print(">> Error: could not connect to '%s'\n" % SSID)

        print("")
        print("  - IP addressing mode: %s" % device.get_ip_addressing_mode().description)
        print("  - IP address:         %s" % device.get_ip_addr().exploded)
        print("  - IP address mask:    %s" % device.get_mask_address().exploded)
        print("  - Gateway IP address: %s" % device.get_gateway_address().exploded)
        print("  - DNS address:        %s" % device.get_dns_address().exploded)
        print("")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
