# Copyright 2019, Digi International Inc.
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

from digi.xbee.devices import XBeeDevice

# TODO: Replace with the location of the XBee profile file to read.
PROFILE_PATH = "<path_to_profile>"
# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Read XBee Profile Sample |")
    print(" +----------------------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)
    try:
        device.open()
        print("Updating profile '%s'...\n" % PROFILE_PATH)
        device.apply_profile(PROFILE_PATH, progress_callback=progress_callback)
        print("\nProfile updated successfully!")
    except Exception as e:
        print(str(e))
        exit(1)
    finally:
        if device.is_open():
            device.close()


def progress_callback(task, percent):
    if percent is not None:
        print("%s: %d%%" % (task, percent))
    else:
        print("%s" % task)


if __name__ == '__main__':
    main()
