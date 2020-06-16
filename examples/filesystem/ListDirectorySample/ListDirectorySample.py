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

from digi.xbee.filesystem import LocalXBeeFileSystemManager, FileSystemElement, FileSystemException
from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import XBeeException

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the XBee file system path to list its contents. Leave as 'None' to use current dir.
PATH_TO_LIST = None


def main():
    print(" +-------------------------------------------+")
    print(" | XBee Python Library List Directory Sample |")
    print(" +-------------------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()
        filesystem_manager = LocalXBeeFileSystemManager(device)
        print("Starting file system manager...", end=" ")
        filesystem_manager.connect()
        print("OK\n")
        current_directory = filesystem_manager.get_current_directory()
        print("Current directory: %s" % current_directory)
        path_to_list = PATH_TO_LIST
        if path_to_list is None:
            path_to_list = current_directory
        files = filesystem_manager.list_directory(path_to_list)
        print("Contents of '%s':" % path_to_list)
        for file in files:
            print(str(file))
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
