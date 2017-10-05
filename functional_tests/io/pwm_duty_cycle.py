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
from digi.xbee.io import IOLine, IOMode

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def main():

    print(" +---------------------+")
    print(" | PWM Duty Cycle Test |")
    print(" +---------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()

        device.set_io_configuration(IOLine.DIO10_PWM0, IOMode.PWM)
        device.set_io_configuration(IOLine.DIO11_PWM1, IOMode.PWM)

        device.set_pwm_duty_cycle(IOLine.DIO10_PWM0, 50)
        device.set_pwm_duty_cycle(IOLine.DIO11_PWM1, 100)

        dc1 = device.get_pwm_duty_cycle(IOLine.DIO10_PWM0)
        dc2 = device.get_pwm_duty_cycle(IOLine.DIO11_PWM1)

        assert (dc1 == 50)
        assert (dc2 == 100)

        print("Test finished successfully")

    finally:
        if device is not None and device.is_open():
            device.close()


if __name__ == "__main__":
    main()
