# Copyright 2020, Digi International Inc.
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
import logging
import os
import sys
import time
from tempfile import TemporaryDirectory

from digi.xbee.filesystem import FileSystemException, FileSystemElement, get_local_file_hash
from digi.xbee.devices import XBeeDevice
from digi.xbee.exception import XBeeException

from digi.xbee.models.status import FSCommandStatus
from digi.xbee.util import utils

RESOURCES = "resources"
LOCAL_FILE_1K = "f_1K.txt"
LOCAL_FILE_2K = "f_2K.txt"
LOCAL_FILE_3K = "f_3K.txt"
LOCAL_FILE_5K = "f_5K.txt"
LOCAL_FILE_10K = "f_10K.txt"
PATH_TO_UPLOAD = "/flash/uploaded"


def data_hash(data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.digest()


def check_hash(f_mng, xbee_file, local_file):
    xb_path = xbee_file
    if isinstance(xbee_file, FileSystemElement):
        xb_path = xbee_file.path
    print("    Check local and XBee files ('%s', '%s')..." % (local_file, xb_path), end=" ")
    start = time.time()
    xb_hash = f_mng.get_file_hash(xb_path)
    print("%f" % (time.time() - start))
    local_hash = get_local_file_hash(local_file)
    print("    XBee:  %s" % utils.hex_to_string(xb_hash, pretty=False))
    print("    Local: %s" % utils.hex_to_string(local_hash, pretty=False))
    if xb_hash != local_hash:
        print("    ERROR: Hash are different!!!!\n")
        return False

    print("    Same hash!!!\n")
    return True


def put_get_file(f_mng, local_path, xb_path, name=None, secure=False, overwrite=False):
    def p_cb(percent, dst, src):
        print("        '%s' to '%s': %f%%" % (src, dst, percent))

    if not name:
        name = os.path.basename(local_path)
    sec_str = "(secure) " if secure else ""
    xb_file_path = os.path.join(xb_path, name)
    print("    Uploading file %s'%s' to '%s'" % (sec_str, local_path, xb_file_path))
    start = time.time()
    xb_file = f_mng.put_file(local_path, xb_file_path, secure=secure, overwrite=overwrite, progress_cb=p_cb)
    print("    Time: %f" % (time.time() - start))
    print("    Uploaded file %s%s (%d)\n" % (sec_str, xb_file.name, xb_file.size))

    if not check_hash(f_mng, xb_file, local_path):
        exit(1)

    local_dir = TemporaryDirectory(
        suffix="_%s" % time.strftime("%H:%M:%S", time.localtime()),
        prefix="fs_", dir='.')
    local_file = os.path.join(local_dir.name, xb_file.name)
    print("    Downloading file %s'%s' to '%s'" % (sec_str, xb_file.path, local_file))
    success = True
    start = time.time()
    try:
        f_mng.get_file(xb_file.path, local_file, progress_cb=p_cb)
        print("    Time: %f" % (time.time() - start))
        print("    Downloaded file %s (%d)\n" % (local_file, os.stat(local_file).st_size))
        success = check_hash(f_mng, xb_file, local_file)
    except FileSystemException as exc:
        if secure and exc.status == FSCommandStatus.ACCESS_DENIED.code:
            print("    Expected error: %s" % str(exc))
        else:
            raise exc
    finally:
        local_dir.cleanup()

    return success


def write_read_chunks(f_mng, path):
    file_path = os.path.join(path, os.path.basename(LOCAL_FILE_5K))
    print("    * Writing to file chunk by chunk '%s'..." % file_path)

    def w_chunk_cb(n_bytes, percent, status):
        if status:
            st = FSCommandStatus.get(status)
            msg = str(st) if st else "Unknown status (0x%0.2X)" % status
            print("          ERROR WRITE '%s': %s" % (file_path, msg))
            return
        print("          '%s' written %d bytes: %f%%" % (file_path, n_bytes, percent))

    start = time.time()
    w_proc = f_mng.write_file(file_path, offset=0, secure=False,
                              options=[], progress_cb=w_chunk_cb)
    with open(LOCAL_FILE_5K, "rb+") as file:
        try:
            data = file.read(1024)
            while data:
                w_proc.next(data, last=False)
                data = file.read(1024)
        finally:
            w_proc.next("", last=True)
    print("      Time: %f\n" % (time.time() - start))

    print("    * Reading file chunk by chunk '%s'..." % file_path)

    def r_chunk_cb(r_data, percent, _size, status):
        if status:
            st = FSCommandStatus.get(status)
            msg = str(st) if st else "Unknown status (0x%0.2X)" % status
            print("          ERROR READ: '%s': %s" % (file_path, msg))
            return
        print("          '%s' read %d bytes: %f%%" % (file_path, len(r_data), percent))
        # print("              Data: %s" % r_data.decode('utf-8'))

    start = time.time()
    r_proc = f_mng.read_file(file_path, offset=0, progress_cb=r_chunk_cb)
    data = bytearray()
    c_data = r_proc.next(size=1024, last=False)
    data += c_data
    while c_data:
        # print("        Chunk: %s\n" % c_data.decode('utf-8'))
        c_data = r_proc.next(size=1024, last=False)
        data += c_data
    print("      Time: %f\n" % (time.time() - start))
    # print("      Complete data read '%s':\n    %s\n" % (file_path, data.decode('utf-8')))

    xb_hash = f_mng.get_file_hash(file_path)
    local_hash = data_hash(data)
    print("      Hash XBee:  %s" % utils.hex_to_string(xb_hash, pretty=False))
    print("      Hash Local: %s" % utils.hex_to_string(local_hash, pretty=False))
    if xb_hash != local_hash:
        print("      ERROR HASH: Hash are different!!!!\n")
        return False

    print("      Same hash!!!\n")
    return True


def read_local_file(path, offset, size):
    with open(path, "rb+") as file:
        file.seek(offset)
        return file.read(size)


def main(argv):

    if len(argv) < 2:
        print("Usage: fs_test.py <port> <baud_rate> <r_name> <ota-len>")
        exit(1)

    print(" +------------------+")
    print(" | File System test |")
    print(" +------------------+\n")

    log_enabled = False
    test_cnt = 1

    if log_enabled:
        utils.enable_logger("digi.xbee.devices", logging.DEBUG)
        utils.enable_logger("digi.xbee.reader", logging.DEBUG)
        utils.enable_logger("digi.xbee.filesystem", logging.DEBUG)

    local_xbee = XBeeDevice(argv[0], int(argv[1]))
    dut = local_xbee

    try:
        local_xbee.open()

        if len(argv) > 2:
            dut = local_xbee.get_network().discover_device(argv[2])
            dut.set_ota_max_block_size(int(argv[3], 0) if len(argv) > 3 else 0)

        script_start = time.time()

        f_mng = dut.get_file_manager()

        print("%2d. Formatting..." % test_cnt)
        start = time.time()
        info = f_mng.format(vol="/flash")
        print("    Time: %f" % (time.time() - start))
        print("    %s\n" % info)
        test_cnt += 1

        root = f_mng.get_root()
        print("%2d. Listing directory '%s'..." % (test_cnt, root.path))
        start = time.time()
        files = f_mng.list_directory(root)
        flash_dir = files[0]
        print("    Time: %f" % (time.time() - start))
        print("    Contents of '%s'" % root.path)
        for file in files:
            print("        %s" % str(file))
        print("")
        test_cnt += 1

        print("%2d. Getting volume info '%s'..." % (test_cnt, flash_dir.path))
        start = time.time()
        info = f_mng.get_volume_info(vol=flash_dir)
        print("    Time: %f" % (time.time() - start))
        print("    %s\n" % info)
        test_cnt += 1

        print("%2d. Creating directory '%s'..." % (test_cnt, PATH_TO_UPLOAD))
        start = time.time()
        upload_dir = f_mng.make_directory(PATH_TO_UPLOAD, mk_parents=True)[0]
        print("    Time: %f" % (time.time() - start))
        print("")
        test_cnt += 1

        print("%2d. Putting complete directory '%s'..." % (test_cnt, PATH_TO_UPLOAD))

        def put_dir_cb(percent, dest, src):
            print("    Uploading '%s' to '%s' bytes: %f%%" % (src, dest, percent))

        start = time.time()
        f_mng.put_dir(os.path.dirname(RESOURCES), dest=PATH_TO_UPLOAD, verify=True, progress_cb=put_dir_cb)
        print("    Time: %f" % (time.time() - start))
        print("")
        test_cnt += 1

        print("%2d. Put/get secure file '%s'..." % (test_cnt, os.path.join(upload_dir.path, "secure.txt")))
        try:
            if not put_get_file(f_mng, LOCAL_FILE_2K, upload_dir.path, name="secure.txt", secure=True):
                exit(1)
        except FileSystemException as exc:
            if exc.status == FSCommandStatus.INVALID_PARAMETER.code:
                print("    ***** SECURE NOT SUPPORTED: %s" % str(exc))
        test_cnt += 1

        print("\n%2d. Write/read file chunks '%s'..." % (test_cnt, os.path.join(flash_dir.path, os.path.basename(LOCAL_FILE_5K))))
        if not write_read_chunks(f_mng, flash_dir.path):
            exit(1)
        test_cnt += 1

        print("%2d. Overwrite file '%s'..." % (test_cnt, os.path.join(flash_dir.path, os.path.basename(LOCAL_FILE_5K))))
        if not put_get_file(f_mng, LOCAL_FILE_2K, flash_dir.path, name=os.path.basename(LOCAL_FILE_5K), overwrite=True):
            exit(1)
        test_cnt += 1

        path_long = "/flash"
        for i in range(1, 26):
            path_long = os.path.join(path_long, "directory%d" % i)

        print("%2d. Creating long directory '%s'..." % (test_cnt, path_long))
        start = time.time()
        dirs = f_mng.make_directory(path_long, mk_parents=True)
        print("    Time: %f" % (time.time() - start))
        print("")
        test_cnt += 1

        print("%2d. Put/get file to long directory '%s'..." %
              (test_cnt, os.path.join(dirs[len(dirs) - 1].path, os.path.basename(LOCAL_FILE_1K))))
        if not put_get_file(f_mng, LOCAL_FILE_1K, dirs[len(dirs) - 1].path):
            exit(1)
        test_cnt += 1

        print("%2d. Creating files in created directories '%s'..." % (test_cnt, dirs[0].path))
        cnt = 0
        for directory in dirs:
            cnt += 1
            file_name = "file_%d.txt" % cnt
            file_path = os.path.join(directory.path, file_name)

            def w_p_cb(n_bytes, percent, status):
                if status:
                    st = FSCommandStatus.get(status)
                    msg = str(st) if st else "Unknown status (0x%0.2X)" % status
                    print("            ERROR WRITE '%s': %s" % (file_name, msg))
                    return
                print("            '%s' written %d bytes: %f%%" % (file_name, n_bytes, percent))

            def r_p_cb(r_data, percent, _size, status):
                if status:
                    st = FSCommandStatus.get(status)
                    msg = str(st) if st else "Unknown status (0x%0.2X)" % status
                    print("            ERROR READ: '%s': %s" % (file_name, msg))
                    return
                print("            '%s' read %d bytes: %f%%" % (file_name, len(r_data), percent))
                # print("                Data: %s" % r_data.decode('utf-8'))

            size = cnt * 20
            offset = cnt + 31
            data = read_local_file(LOCAL_FILE_3K, offset=offset, size=size)

            print("        Writing to file '%s'..." % file_path)
            start = time.time()
            w_proc = f_mng.write_file(file_path, offset=0, secure=False,
                                      options=[], progress_cb=w_p_cb)
            w_proc.next(data, last=True)
            print("        Time: %f" % (time.time() - start))

            print("        Reading file '%s'..." % file_path)
            start = time.time()
            r_proc = f_mng.read_file(file_path, offset=0, progress_cb=r_p_cb)
            c_data = r_proc.next(size=-1, last=True)
            print("        Time: %f" % (time.time() - start))
            # print("        Complete data read '%s':\n        %s\n" % (file_name, c_data.decode('utf-8')))

            xb_hash = f_mng.get_file_hash(file_path)
            local_hash = data_hash(data)
            print("        Hash XBee:  %s" % utils.hex_to_string(xb_hash, pretty=False))
            print("        Hash Local: %s" % utils.hex_to_string(local_hash, pretty=False))
            if xb_hash != local_hash:
                print("        ERROR HASH: Hash are different!!!!\n")
                exit(1)
            print("        Same hash!!!\n")
        test_cnt += 1

        print("%2d. Listing files in subdirectories of '%s'..." % (test_cnt, dirs[0].path))
        for directory in dirs:
            print("        Listing directory '%s'..." % directory.name)
            start = time.time()
            file_list = f_mng.list_directory(directory)
            print("        Time: %f" % (time.time() - start))
            print("        Contents of '%s':" % directory.name)
            for file in file_list:
                print("            %s" % str(file))
            print("")
        test_cnt += 1

        print("%2d. Listing directory '%s'..." % (test_cnt, flash_dir.path))
        start = time.time()
        flash_files = f_mng.list_directory(flash_dir)
        print("    Time: %f" % (time.time() - start))
        print("    Contents of '%s'" % flash_dir.path)
        for file in flash_files:
            print("        %s" % str(file))
        print("")
        test_cnt += 1

        print("%2d. Getting volume info '%s'..." % (test_cnt, flash_dir.path))
        start = time.time()
        info = f_mng.get_volume_info(vol=flash_dir)
        print("    Time: %f" % (time.time() - start))
        print("    %s\n" % info)
        test_cnt += 1

        print("%2d. Full volume ..." % test_cnt)
        for i in range(1, 51):
            try:
                if not put_get_file(f_mng, LOCAL_FILE_10K,
                                    upload_dir.path, name="f_10K_%d.txt" % i):
                    exit(1)
            except FileSystemException as exc:
                if exc.status == FSCommandStatus.VOLUME_FULL.code:
                    print("    VOLUME FULL: %s" % str(exc))
                    break
        test_cnt += 1

        # Sometimes (802.15.4) when the volume is full the device resets itself,
        # so reset it before continuing, and wait for it to be joined and to
        # accommodate the file system.
        dut.reset()
        if dut.is_remote():
            time.sleep(20)

        print("%2d. Listing directory '%s'..." % (test_cnt, upload_dir.path))
        start = time.time()
        upload_files = f_mng.list_directory(upload_dir)
        print("    Time: %f" % (time.time() - start))
        print("    Contents of '%s'" % upload_dir.path)
        for file in upload_files:
            print("        %s" % str(file))
        print("")
        test_cnt += 1

        print("%2d. Getting volume info '%s'..." % (test_cnt, flash_dir.path))
        start = time.time()
        info = f_mng.get_volume_info(vol=flash_dir)
        print("    Time: %f" % (time.time() - start))
        print("    %s\n" % info)
        test_cnt += 1

        print("%2d. Removing all entries in '%s'..." % (test_cnt, flash_dir.path))
        for file in flash_files:
            print("    Removing '%s'..." % file.path, end=" ")
            start = time.time()
            f_mng.remove(file.path, rm_children=True)
            print("%f" % (time.time() - start))
            print("")
        test_cnt += 1

        print("%2d. Getting volume info '%s'..." % (test_cnt, flash_dir.path))
        start = time.time()
        info = f_mng.get_volume_info(vol=flash_dir)
        print("    Time: %f" % (time.time() - start))
        print("    %s\n" % info)
        test_cnt += 1

        print("\nTest finished successfully: %f s" % (time.time() - script_start))

    except (XBeeException, FileSystemException) as e:
        print("ERROR: %s" % str(e))
        exit(1)
    finally:
        if local_xbee is not None and local_xbee.is_open():
            local_xbee.close()


if __name__ == '__main__':
    sc_path = os.path.dirname(sys.argv[0])
    RESOURCES = os.path.join(sc_path, RESOURCES)
    LOCAL_FILE_1K = os.path.join(RESOURCES, LOCAL_FILE_1K)
    LOCAL_FILE_2K = os.path.join(RESOURCES, LOCAL_FILE_2K)
    LOCAL_FILE_3K = os.path.join(RESOURCES, LOCAL_FILE_3K)
    LOCAL_FILE_5K = os.path.join(RESOURCES, LOCAL_FILE_5K)
    LOCAL_FILE_10K = os.path.join(RESOURCES, LOCAL_FILE_10K)
    main(sys.argv[1:])
