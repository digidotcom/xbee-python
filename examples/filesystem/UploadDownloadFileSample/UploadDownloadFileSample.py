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

from digi.xbee.filesystem import LocalXBeeFileSystemManager, FileSystemException
from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import XBeeException


# TODO: Replace with the serial port where your local module is connected to.
PORT = "COM1"
# TODO: Replace with the baud rate of your local module.
BAUD_RATE = 9600
# TODO: Replace with the location of the file to upload.
FILE_PATH = "<path_to_file>"
# TODO: Replace with the location to upload the file to.
UPLOAD_PATH = ""
# TODO: Replace with the location to download the file to.
DOWNLOAD_PATH = "/tmp"


def main():
    print(" +-------------------------------------------------+")
    print(" | XBee Python Library Upload/Download File Sample |")
    print(" +-------------------------------------------------+\n")

    device = XBeeDevice(PORT, BAUD_RATE)

    try:
        device.open()
        filesystem_manager = LocalXBeeFileSystemManager(device)
        print("Starting file system manager...", end=" ")
        filesystem_manager.connect()
        print("OK")
        upload_path = os.path.join(UPLOAD_PATH, os.path.basename(FILE_PATH))
        filesystem_manager.put_file(FILE_PATH, upload_path, progress_callback=progress_upload_callback)
        download_path = os.path.join(DOWNLOAD_PATH, os.path.basename(FILE_PATH))
        filesystem_manager.get_file(upload_path, download_path, progress_callback=progress_download_callback)
        print("\nFile hash summary\n-----------------------")
        print("%s %s" % ("Local:".ljust(15), get_sha256_hash(FILE_PATH)))
        print("%s %s" % ("Uploaded:".ljust(15), filesystem_manager.get_file_hash(upload_path)))
        print("%s %s\n" % ("Downloaded:".ljust(15), get_sha256_hash(download_path)))
    except (XBeeException, FileSystemException) as e:
        print("ERROR: %s" % str(e))
        exit(1)
    finally:
        if filesystem_manager.is_connected:
            print("Stopping file system manager...", end=" ")
            filesystem_manager.disconnect()
            print("OK")
        if device is not None and device.is_open():
            device.close()


def progress_upload_callback(percent):
    print("Uploading file: %d%%" % percent)


def progress_download_callback(percent):
    print("Downloading file: %d%%" % percent)


def get_sha256_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()


if __name__ == '__main__':
    main()
