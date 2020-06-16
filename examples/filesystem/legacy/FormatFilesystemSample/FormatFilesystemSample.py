# Copyright 2019, 2020, Digi International Inc.
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

from digi.xbee.filesystem import LocalXBeeFileSystemManager, FileSystemException
from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import XBeeException

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600


def get_fs_info(fs_manager):
    try:
        info = fs_manager.get_usage_information()
        print("Filesystem information\n---------------------------")
        for entry in info:
            print("%s: %s bytes" % (entry, info[entry]))
    except FileSystemException:
        pass


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Format Filesystem Sample |")
    print(" +----------------------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()
        filesystem_manager = LocalXBeeFileSystemManager(device)
        print("Starting file system manager...", end=" ")
        filesystem_manager.connect()
        print("OK\n")

        get_fs_info(filesystem_manager)

        print("\nFormatting filesystem...", end=" ")
        filesystem_manager.format_filesystem()
        print("OK\n")

        get_fs_info(filesystem_manager)

    except (XBeeException, FileSystemException) as e:
        print("ERROR: %s" % str(e))
        exit(1)
    finally:
        if filesystem_manager.is_connected:
            print("\nStopping file system manager...", end=" ")
            filesystem_manager.disconnect()
            print("OK")
        if device is not None and device.is_open():
            device.close()


if __name__ == '__main__':
    main()
