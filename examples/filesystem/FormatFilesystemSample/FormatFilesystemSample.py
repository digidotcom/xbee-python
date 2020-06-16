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

from digi.xbee.filesystem import FileSystemException
from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import XBeeException
from digi.xbee.models.status import FSCommandStatus

# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the name of the remote XBee to use. If empty, local is used.
REMOTE_NODE_ID = None


def get_volume_info(f_mng):
    try:
        info = f_mng.get_volume_info()
        print_fs_info(f_mng.xbee, info)
    except FileSystemException as e:
        if e.status != FSCommandStatus.NO_DEVICE.code:
            raise e


def print_fs_info(xbee, info):
    title_str = "'%s' XBee filesystem information" % \
                (xbee if xbee.is_remote() else "local")
    print("%s\n%s" % (title_str, "-" * len(title_str)))
    for entry in info:
        print("%s: %s bytes" % (entry, info[entry]))


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Format Filesystem Sample |")
    print(" +----------------------------------------------+\n")

    local_xbee = XBeeDevice(PORT, BAUD_RATE)
    fs_xbee = local_xbee

    try:
        local_xbee.open()

        if REMOTE_NODE_ID:
            # Obtain the remote XBee from the network.
            xbee_network = local_xbee.get_network()
            fs_xbee = xbee_network.discover_device(REMOTE_NODE_ID)
            if not fs_xbee:
                print("Could not find remote device '%s'" % REMOTE_NODE_ID)
                exit(1)

        filesystem_manager = fs_xbee.get_file_manager()

        get_volume_info(filesystem_manager)

        print("\nFormatting filesystem of '%s' XBee..." %
              (fs_xbee if fs_xbee.is_remote() else "local"), end=" ")
        info = filesystem_manager.format()
        print("OK\n")

        print_fs_info(fs_xbee, info)

    except (XBeeException, FileSystemException) as e:
        print("ERROR: %s" % str(e))
        exit(1)
    finally:
        if local_xbee and local_xbee.is_open():
            local_xbee.close()


if __name__ == '__main__':
    main()
