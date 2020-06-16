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

import hashlib
import os

from digi.xbee.filesystem import FileSystemException
from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import XBeeException


# TODO: Replace with the serial port where your local module is connected to.
from digi.xbee.util import utils

PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the name of the remote XBee to use. If empty, local is used.
REMOTE_NODE_ID = None
# TODO: Replace with the absolute path of the source file in your computer.
FILE_TO_UPLOAD_PATH = "<path_to_file>"
# TODO: Replace with the XBee directory absolute path to upload the file.
XBEE_UPLOAD_DIR_PATH = "/flash"
# TODO: Replace with the computer directory absolute path to download the file.
LOCAL_DOWNLOAD_DIR_PATH = "/tmp"


def main():
    print(" +-------------------------------------------------+")
    print(" | XBee Python Library Upload/Download File Sample |")
    print(" +-------------------------------------------------+\n")

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

        xb_upload_path = os.path.join(XBEE_UPLOAD_DIR_PATH,
                                      os.path.basename(FILE_TO_UPLOAD_PATH))
        filesystem_manager.put_file(FILE_TO_UPLOAD_PATH, xb_upload_path,
                                    overwrite=True, progress_cb=progress_upload_callback)

        download_path = os.path.join(LOCAL_DOWNLOAD_DIR_PATH,
                                     os.path.basename(FILE_TO_UPLOAD_PATH))
        filesystem_manager.get_file(xb_upload_path, download_path,
                                    progress_cb=progress_download_callback)

        print("\nFile hash summary\n-----------------------")
        print("%s %s" % ("Local:".ljust(15), get_sha256_hash(FILE_TO_UPLOAD_PATH).upper()))
        print("%s %s" % ("Uploaded:".ljust(15),
                         utils.hex_to_string(filesystem_manager.get_file_hash(xb_upload_path), pretty=False)))
        print("%s %s\n" % ("Downloaded:".ljust(15), get_sha256_hash(download_path).upper()))
    except (XBeeException, FileSystemException) as e:
        print("ERROR: %s" % str(e))
        exit(1)
    finally:
        if local_xbee and local_xbee.is_open():
            local_xbee.close()


def progress_upload_callback(percent, dst, src):
    print("Uploading file '%s' to '%s': %d%%" % (src, dst, percent))


def progress_download_callback(percent, dst, src):
    print("Downloading file '%s' to '%s': %d%%" % (src, dst, percent))


def get_sha256_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()


if __name__ == '__main__':
    main()
