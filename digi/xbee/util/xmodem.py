# Copyright 2019, Digi International Inc.
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

import collections
import os
import time

from enum import Enum

_ERROR_VALUE_DEST_PATH = "Destination path must be a non empty String"
_ERROR_VALUE_READ_CB = "Read callback must be a valid callable function"
_ERROR_VALUE_SRC_PATH = "Source path must be a non empty String"
_ERROR_VALUE_WRITE_CB = "Write callback must be a valid callable function"
_ERROR_XMODEM_BAD_BLOCK_NUMBER = "Bad block number in block #%d (received %d)"
_ERROR_XMODEM_BAD_DATA = "Data verification failed"
_ERROR_XMODEM_CANCELLED = "XModem transfer was cancelled by the remote end"
_ERROR_XMODEM_FINISH_TRANSFER = "Could not finish XModem transfer after %s retries"
_ERROR_XMODEM_READ_PACKET = "XModem packet could not be read after %s retries"
_ERROR_XMODEM_READ_PACKET_TIMEOUT = "Timeout reading XModem packet"
_ERROR_XMODEM_READ_VERIFICATION = "Could not read XModem verification byte after %s retries"
_ERROR_XMODEM_SEND_ACK_BYTE = "Could not send XModem ACK byte"
_ERROR_XMODEM_SEND_NAK_BYTE = "Could not send XModem NAK byte"
_ERROR_XMODEM_SEND_VERIFICATION_BYTE = "Could not send XModem verification byte"
_ERROR_XMODEM_UNEXPECTED_EOT = "Unexpected end of transmission"
_ERROR_XMODEM_TRANSFER_NAK = "XModem packet not acknowledged after %s retries"
_ERROR_XMODEM_WRITE_TO_FILE = "Could not write data to file '%s': %s"

_PADDING_BYTE_XMODEM = 0xFF
_PADDING_BYTE_YMODEM = 0x1A

XMODEM_ACK = 0x06  # Packet acknowledged.
XMODEM_CAN = 0x18  # Cancel transmission.
XMODEM_CRC = "C"
XMODEM_CRC_POLYNOMINAL = 0x1021
XMODEM_EOT = 0x04  # End of transmission.
XMODEM_NAK = 0x15  # Packet not acknowledged.
XMODEM_SOH = 0x01  # Start of header (128 data bytes).
XMODEM_STX = 0x02  # Start of header (1024 data bytes).

_XMODEM_BLOCK_SIZE_128 = 128
_XMODEM_BLOCK_SIZE_1K = 1024
_XMODEM_READ_HEADER_TIMEOUT = 3  # Seconds
_XMODEM_READ_DATA_TIMEOUT = 1  # Seconds.
_XMODEM_READ_RETRIES = 10
_XMODEM_WRITE_RETRIES = 10


class XModemException(Exception):
    """
    This exception will be thrown when any problem related with the XModem/YModem transfer occurs.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class XModemCancelException(XModemException):
    """
    This exception will be thrown when the XModem/YModem transfer is cancelled by the remote end.

    All functionality of this class is the inherited from `Exception
    <https://docs.python.org/2/library/exceptions.html?highlight=exceptions.exception#exceptions.Exception>`_.
    """
    pass


class _XModemMode(Enum):
    """
    This class lists the available XModem modes.

    | Inherited properties:
    |     **name** (String): The name of this _XModemMode.
    |     **value** (Integer): The ID of this _XModemMode.
    """
    XMODEM = ("XModem", _XMODEM_BLOCK_SIZE_128, _PADDING_BYTE_XMODEM)
    YMODEM = ("YModem", _XMODEM_BLOCK_SIZE_1K, _PADDING_BYTE_YMODEM)

    def __init__(self, name, block_size, eof_pad):
        self.__name = name
        self.__block_size = block_size
        self.__eof_pad = eof_pad

    @property
    def name(self):
        """
        Returns the name of the _XModemMode element.

        Returns:
            String: the name of the _XModemMode element.
        """
        return self.__name

    @property
    def block_size(self):
        """
        Returns the block size of the _XModemMode element.

        Returns:
            Integer: the block size of the _XModemMode element.
        """
        return self.__block_size

    @property
    def eof_pad(self):
        """
        Returns the end of file padding byte of the _XModemMode element.

        Returns:
            Integer: the end of file padding byte of the _XModemMode element.
        """
        return self.__eof_pad


class _XModemVerificationMode(Enum):
    """
    This class lists the available XModem verification modes.

    | Inherited properties:
    |     **name** (String): The name of this _XModemVerificationMode.
    |     **value** (Integer): The ID of this _XModemVerificationMode.
    """
    CHECKSUM = ("Checksum", 1, XMODEM_NAK)
    CRC_16 = ("16-bit CRC", 2, ord(XMODEM_CRC))

    def __init__(self, name, length, byte):
        self.__name = name
        self.__length = length
        self.__byte = byte

    @property
    def name(self):
        """
        Returns the name of the _XModemVerificationMode element.

        Returns:
            String: the name of the _XModemVerificationMode element.
        """
        return self.__name

    @property
    def length(self):
        """
        Returns the byte length of the _XModemVerificationMode element.

        Returns:
            Integer: the byte length of the _XModemVerificationMode element.
        """
        return self.__length

    @property
    def byte(self):
        """
        Returns the _XModemVerificationMode element byte.

        Returns:
            Integer: the _XModemVerificationMode element byte.
        """
        return self.__byte


class _TransferFile(object):
    """
    Helper class used to read and split the file to transfer in data chunks.
    """

    def __init__(self, file_path, mode):
        """
        Class constructor. Instantiates a new :class:`._TransferFile` with the given parameters.

        Args:
            file_path (String): location of the file.
            mode (:class:`._XModemMode`): the XModem transfer mode.
        """
        self._file_path = file_path
        self._mode = mode
        # Calculate the total number of chunks (for percentage purposes later).
        file_size = os.stat(file_path).st_size
        self._chunk_index = 1
        self._num_chunks = file_size // mode.block_size
        if file_size % mode.block_size:
            self._num_chunks += 1

    def get_next_data_chunk(self):
        """
        Returns the next data chunk of this file.

        Returns:
            Bytearray: the next data chunk of the file as byte array.
        """
        with open(self._file_path, "rb") as file:
            while True:
                read_bytes = file.read(self._mode.block_size)
                if not read_bytes:
                    break
                if len(read_bytes) < self._mode.block_size:
                    # Since YModem allows for mixed block sizes transmissions, optimize
                    # the packet size if the last block is < 128 bytes.
                    if len(read_bytes) < _XMODEM_BLOCK_SIZE_128:
                        data = bytearray([self._mode.eof_pad] * _XMODEM_BLOCK_SIZE_128)
                    else:
                        data = bytearray([self._mode.eof_pad] * self._mode.block_size)
                    data[0:len(read_bytes)] = read_bytes
                    yield data
                else:
                    yield read_bytes
                self._chunk_index += 1

    @property
    def num_chunks(self):
        """
        Returns the total number of data chunks of this file.

        Returns:
            Integer: the total number of data chunks of this file.
        """
        return self._num_chunks

    @property
    def chunk_index(self):
        """
        Returns the current data chunk index.

        Returns:
            Integer: the current data chunk index.
        """
        return self._chunk_index

    @property
    def percent(self):
        """
        Returns the transfer file progress percent.

        Returns:
            Integer: the transfer file progress percent.
        """
        return (self._chunk_index * 100) // self._num_chunks


class _DownloadFile(object):
    """
    Helper class used to create and write the download file from the given data chunks.
    """

    def __init__(self, file_path, mode):
        """
        Class constructor. Instantiates a new :class:`._DownloadFile` with the given parameters.

        Args:
            file_path (String): location of the file.
            mode (:class:`._XModemMode`): the XModem transfer mode.
        """
        self._file_path = file_path
        self._mode = mode
        self._size = 0
        self._name = None
        self._num_chunks = 0
        self._chunk_index = 1
        self._written_bytes = 0
        self._file = None

    def write_data_chunk(self, data):
        """
        Writes the given data chunk in the file.

        Args:
            data (Bytearray): the data chunk to write in the file.
        """
        try:
            if self._file is None:
                self._file = open(self._file_path, "wb+")

            bytes_to_write = len(data)
            # It might be the case that the last data block contains padding data.
            # Get rid of it by calculating remaining bytes to write.
            if self._size != 0:
                bytes_to_write = min(bytes_to_write, self.size - self._written_bytes)
            self._file.write(data[0:bytes_to_write])
            self._written_bytes += bytes_to_write
            self._chunk_index += 1
        except Exception as e:
            self.close_file()
            raise XModemException(_ERROR_XMODEM_WRITE_TO_FILE % (self._file_path, str(e)))

    def close_file(self):
        """
        Closes the file.
        """
        if self._file:
            self._file.close()

    @property
    def num_chunks(self):
        """
        Returns the total number of data chunks of this file.

        Returns:
            Integer: the total number of data chunks of this file.
        """
        return self._num_chunks

    @property
    def chunk_index(self):
        """
        Returns the current data chunk index.

        Returns:
            Integer: the current data chunk index.
        """
        return self._chunk_index

    @property
    def size(self):
        """
        Returns the size of the download file.

        Returns:
            Integer: the size of the download file.
        """
        return self._size

    @size.setter
    def size(self, size):
        """
        Sets the download file size.

        Args:
            size (Integer): the download file size.
        """
        self._size = size
        self._num_chunks = self._size // self._mode.block_size
        if self._size % self._mode.block_size:
            self._num_chunks += 1

    @property
    def name(self):
        """
        Returns the name of the download file.

        Returns:
            String: the name of the download file.
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the download file name.

        Args:
            name (String): the download file name.
        """
        self._name = name

    @property
    def percent(self):
        """
        Returns the download file progress percent.

        Returns:
            Integer: the download file progress percent.
        """
        if self.size == 0:
            return 0

        return (self._chunk_index * 100) // self._num_chunks


class _XModemTransferSession(object):
    """
    Helper class used to manage a XModem file transfer session.
    """

    def __init__(self, src_path, write_cb, read_cb, mode=_XModemMode.XMODEM, progress_cb=None, log=None):
        """
        Class constructor. Instantiates a new :class:`._XModemTransferSession` with the given parameters.

        Args:
            src_path (String): absolute path of the file to transfer.
            write_cb (Function): function to execute in order to write data to the remote end.
                Takes the following arguments:

                    * The data to write as byte array.

                The function returns the following:

                    Boolean: ``True`` if the write succeeded, ``False`` otherwise

            read_cb (Function): function to execute in order to read data from the remote end.
                Takes the following arguments:

                    * The size of the data to read.
                    * The timeout to wait for data. (seconds)

                The function returns the following:

                    Bytearray: the read data, ``None`` if data could not be read

            mode (:class:`._XModemMode`, optional): the XModem transfer mode. Defaults to XModem.
            progress_cb (Function, optional): function to execute in order to receive transfer progress information.

                 Takes the following arguments:

                    * The progress percentage as integer.

            log (:class:`.Logger`, optional): logger used to log transfer debug messages
        """
        self._src_path = src_path
        self._write_cb = write_cb
        self._read_cb = read_cb
        self._mode = mode
        self._progress_cb = progress_cb
        self._log = log
        self._seq_index = 0
        self._transfer_file = None
        self._verification_mode = _XModemVerificationMode.CHECKSUM

    def _read_verification_mode(self):
        """
        Reads the transmission verification mode.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error reading the verification mode.
        """
        if self._log:
            self._log.debug("Reading verification mode...")
        retries = _XMODEM_WRITE_RETRIES
        while retries > 0:
            verification = self._read_cb(1, timeout=_XMODEM_READ_DATA_TIMEOUT)
            if not verification:
                retries -= 1
                continue
            verification = verification[0]
            if verification == ord(XMODEM_CRC):
                self._verification_mode = _XModemVerificationMode.CRC_16
                break
            elif verification == XMODEM_NAK:
                self._verification_mode = _XModemVerificationMode.CHECKSUM
                break
            elif verification == XMODEM_CAN:
                # Cancel requested from remote device.
                raise XModemCancelException(_ERROR_XMODEM_CANCELLED)
            else:
                # We got either NAK or something unexpected.
                retries -= 1

        # Check result.
        if retries <= 0:
            raise XModemException(_ERROR_XMODEM_READ_VERIFICATION % _XMODEM_WRITE_RETRIES)
        if self._log:
            self._log.debug("Verification mode is '%s'" % self._verification_mode.name)

    def _send_block_0(self):
        """
        Sends the special YModem block 0 to the remote end.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error transferring the block 0.
        """
        self._seq_index = 0
        name = str.encode(os.path.basename(self._src_path), encoding='utf-8')
        size = str.encode(str(os.path.getsize(self._src_path)), encoding='utf-8')
        mod_time = str.encode(str(oct(int(os.path.getctime(self._src_path)))), encoding='utf-8')
        if (len(name) + len(size) + len(mod_time)) > 110:
            data = bytearray(_XMODEM_BLOCK_SIZE_1K)
        else:
            data = bytearray(_XMODEM_BLOCK_SIZE_128)
        data[0:len(name)] = name
        data[len(name) + 1:len(name) + 1 + len(size)] = size
        data[len(name) + len(size) + 1] = str.encode(" ", encoding='utf-8')[0]
        data[len(name) + len(size) + 2:len(name) + len(size) + len(mod_time)] = mod_time[2:]
        self._send_next_block(data)

    def _send_empty_block_0(self):
        """
        Sends an empty YModem block 0 indicating YModem transmission has ended.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error transferring the empty header block 0.
        """
        self._seq_index = 0
        data = bytearray([0] * _XMODEM_BLOCK_SIZE_128)
        self._send_next_block(data)

    def _send_next_block(self, data):
        """
        Sends the next XModem block using the given data chunk.

        Args:
            data (Bytearray): data to send in the next block.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error transferring the next block.
        """
        # Build XModem packet.
        packet_size = len(data) + 3 + self._verification_mode.length  # Extra 3 bytes for header and seq bytes.
        packet = bytearray(packet_size)
        # Write header, depends on the data block size.
        if len(data) == _XMODEM_BLOCK_SIZE_1K:
            packet[0] = XMODEM_STX
        else:
            packet[0] = XMODEM_SOH
        # Write sequence index.
        packet[1] = self._seq_index
        # Write diff sequence index.
        packet[2] = (255 - self._seq_index) & 0xFF
        # Write data.
        packet[3: 3 + len(data)] = data
        # Write verification byte(s).
        if self._verification_mode == _XModemVerificationMode.CHECKSUM:
            packet[packet_size - _XModemVerificationMode.CHECKSUM.length:packet_size] = _calculate_checksum(data)
        elif self._verification_mode == _XModemVerificationMode.CRC_16:
            packet[packet_size - _XModemVerificationMode.CRC_16.length:packet_size] = _calculate_crc16_ccitt(data)
        # Send XModem packet.
        retries = _XMODEM_WRITE_RETRIES
        answer = None
        while retries > 0:
            if self._log:
                if self._seq_index == 0:
                    if self._mode == _XModemMode.YMODEM and len(data) == _XModemMode.XMODEM.block_size and data[0] == 0:
                        self._log.debug("Sending empty header - retry %d" % (_XMODEM_WRITE_RETRIES - retries + 1))
                    else:
                        self._log.debug("Sending block 0 - retry %d" % (_XMODEM_WRITE_RETRIES - retries + 1))
                else:
                    self._log.debug("Sending chunk %d/%d %d%% - retry %d" % (self._transfer_file.chunk_index,
                                                                             self._transfer_file.num_chunks,
                                                                             self._transfer_file.percent,
                                                                             _XMODEM_WRITE_RETRIES - retries + 1))
            if not self._write_cb(packet):
                retries -= 1
                continue
            answer = self._read_cb(1, timeout=_XMODEM_READ_DATA_TIMEOUT)
            if not answer:
                retries -= 1
                continue
            answer = answer[0]
            if answer == XMODEM_ACK:
                # Block was sent successfully.
                break
            elif answer == XMODEM_CAN:
                # Cancel requested from remote device.
                raise XModemCancelException(_ERROR_XMODEM_CANCELLED)
            else:
                # We got either NAK or something unexpected.
                retries -= 1

        # Check result.
        if answer == XMODEM_NAK or retries <= 0:
            raise XModemException(_ERROR_XMODEM_TRANSFER_NAK % _XMODEM_WRITE_RETRIES)
        self._seq_index = (self._seq_index + 1) & 0xFF

    def _send_eot(self):
        """
        Sends the XModem end of transfer request (EOT).

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error sending the end of transfer request.
        """
        if self._log:
            self._log.debug("Sending EOT")
        retries = _XMODEM_WRITE_RETRIES
        answer = None
        while retries > 0:
            if not self._write_cb(bytes([XMODEM_EOT])):
                retries -= 1
                continue
            # Read answer.
            answer = self._read_cb(1, timeout=_XMODEM_READ_DATA_TIMEOUT)
            if not answer:
                retries -= 1
                continue
            answer = answer[0]
            if answer == XMODEM_ACK:
                # Block was sent successfully.
                break
            elif answer == XMODEM_CAN:
                # Transfer cancelled by the remote end.
                raise XModemCancelException(_ERROR_XMODEM_CANCELLED)
            else:
                # We got either NAK or something unexpected.
                retries -= 1

        # Check result.
        if answer == XMODEM_NAK or retries <= 0:
            raise XModemException(_ERROR_XMODEM_FINISH_TRANSFER % _XMODEM_WRITE_RETRIES)

    def transfer_file(self):
        """
        Performs the file transfer operation.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error during the file transfer.
        """
        if self._log:
            self._log.debug("Sending '%s' file through XModem" % self._src_path)
        self._transfer_file = _TransferFile(self._src_path, self._mode)
        # Read requested verification mode.
        self._read_verification_mode()
        # Execute special protocol pre-actions.
        if self._mode == _XModemMode.YMODEM:
            self._send_block_0()
        else:
            self._seq_index = 1
        # Perform file transfer.
        previous_percent = None
        for data_chunk in self._transfer_file.get_next_data_chunk():
            if self._progress_cb is not None and self._transfer_file.percent != previous_percent:
                self._progress_cb(self._transfer_file.percent)
                previous_percent = self._transfer_file.percent
            self._send_next_block(data_chunk)
        # Finish transfer.
        self._send_eot()
        # Execute special protocol post-actions.
        if self._mode == _XModemMode.YMODEM:
            self._read_verification_mode()
            self._send_empty_block_0()


class _XModemReadSession(object):
    """
    Helper class used to manage a XModem file read session.
    """

    def __init__(self, dest_path, write_cb, read_cb, mode=_XModemMode.XMODEM,
                 verification_mode=_XModemVerificationMode.CRC_16, progress_cb=None, log=None):
        """
        Class constructor. Instantiates a new :class:`._XModemReadSession` with the given parameters.

        Args:
            dest_path (String): absolute path to store downloaded file in.
            write_cb (Function): function to execute in order to write data to the remote end.
                Takes the following arguments:

                    * The data to write as byte array.

                The function returns the following:

                    Boolean: ``True`` if the write succeeded, ``False`` otherwise

            read_cb (Function): function to execute in order to read data from the remote end.
                Takes the following arguments:

                    * The size of the data to read.
                    * The timeout to wait for data. (seconds)

                The function returns the following:

                    Bytearray: the read data, ``None`` if data could not be read

            mode (:class:`._XModemMode`, optional): the XModem transfer mode. Defaults to XModem.
            verification_mode (:class:`._XModemVerificationMode`, optional): the XModem verification mode to use.
                                                                             Defaults to 16-bit CRC.
            progress_cb (Function, optional): function to execute in order to receive progress information.

                 Takes the following arguments:

                    * The progress percentage as integer.

            log (:class:`.Logger`, optional): logger used to log download debug messages
        """
        self._dest_path = dest_path
        self._write_cb = write_cb
        self._read_cb = read_cb
        self._mode = mode
        self._verification_mode = verification_mode
        self._progress_cb = progress_cb
        self._log = log
        self._seq_index = 0
        self._download_file = None

    def _send_data_with_retries(self, data, retries=_XMODEM_WRITE_RETRIES):
        """
        Sends the given data to the remote end using the given number of retries.

        Args:
            data (Bytearray): the data to send to the remote end.
            retries (Integer, optional): the number of retries to perform.

        Returns:
            Boolean: ``True`` if the data was sent successfully, ``False`` otherwise.
        """
        _retries = retries
        while _retries > 0:
            if self._write_cb(data):
                return True
            time.sleep(0.1)
            _retries -= 1

        return False

    def _send_verification_char(self):
        """
        Sends the verification request byte to indicate we are ready to receive data.

        Raises:
            XModemException: if there is any error sending the verification request byte.
        """
        if self._log:
            self._log.debug("Sending verification character")
        if not self._send_data_with_retries(bytearray([self._verification_mode.byte])):
            raise XModemException(_ERROR_XMODEM_SEND_VERIFICATION_BYTE)

    def _send_ack(self):
        """
        Sends the ACK byte to acknowledge the received data.

        Raises:
            XModemException: if there is any error sending the ACK byte.
        """
        if not self._send_data_with_retries(bytes([XMODEM_ACK])):
            raise XModemException(_ERROR_XMODEM_SEND_ACK_BYTE)

    def _send_nak(self):
        """
        Sends the NAK byte to discard received data.

        Raises:
            XModemException: if there is any error sending the NAK byte.
        """
        if not self._send_data_with_retries(bytes([XMODEM_NAK])):
            raise XModemException(_ERROR_XMODEM_SEND_NAK_BYTE)

    def _purge(self):
        """
        Purges the remote end by consuming all data until timeout (no data) is received.
        """
        if self._log:
            self._log.debug("Purging remote end...")
        data = self._read_cb(1, timeout=1)
        while data:
            data = self._read_cb(1, timeout=1)

    def _read_packet(self):
        """
        Reads an XModem packet from the remote end.

        Returns:
            Bytearray: the packet data without protocol overheads. If data size is 0, it means end of transmission.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error reading the XModem packet.
        """
        block_size = _XModemMode.XMODEM.block_size
        retries = _XMODEM_READ_RETRIES
        # Keep reading until a valid packet is received or retries are consumed.
        while retries > 0:
            if self._log:
                if self._seq_index == 0:
                    self._log.debug("Reading block 0 - retry %d" % (_XMODEM_READ_RETRIES - retries + 1))
                elif self._download_file.size != 0 and \
                        self._download_file.chunk_index <= self._download_file.num_chunks:
                    self._log.debug("Reading chunk %d/%d %d%% - retry %d" % (self._download_file.chunk_index,
                                                                             self._download_file.num_chunks,
                                                                             self._download_file.percent,
                                                                             _XMODEM_WRITE_RETRIES - retries + 1))
            # Read the packet header (first byte). Use a timeout strategy to read it.
            header = 0
            deadline = _get_milliseconds() + (_XMODEM_READ_HEADER_TIMEOUT * 1000)
            while _get_milliseconds() < deadline:
                header = self._read_cb(1, timeout=_XMODEM_READ_DATA_TIMEOUT)
                if not header or len(header) == 0:
                    # Wait a bit and continue reading.
                    time.sleep(0.2)
                    continue
                header = header[0]
                if header == XMODEM_STX:
                    block_size = _XModemMode.YMODEM.block_size
                    break
                elif header == XMODEM_SOH:
                    block_size = _XModemMode.XMODEM.block_size
                    break
                elif header == XMODEM_EOT:
                    # Transmission from the remote end has finished. ACK it and return an empty byte array.
                    self._send_ack()
                    return bytearray(0)
                elif header == XMODEM_CAN:
                    # The remote end has cancelled the transfer.
                    raise XModemCancelException(_ERROR_XMODEM_CANCELLED)
                else:
                    # Unexpected content, read again.
                    continue
            # If header is not valid, consume one retry and try again.
            if header not in (XMODEM_STX, XMODEM_SOH):
                retries -= 1
                continue
            # At this point we have the packet header, SOH/STX. Read the sequence bytes.
            seq_byte = self._read_cb(1, timeout=_XMODEM_READ_DATA_TIMEOUT)
            if not seq_byte or len(seq_byte) == 0:
                raise XModemException(_ERROR_XMODEM_READ_PACKET_TIMEOUT)
            seq_byte = seq_byte[0]
            seq_byte_2 = self._read_cb(1, timeout=_XMODEM_READ_DATA_TIMEOUT)
            if not seq_byte_2 or len(seq_byte_2) == 0:
                raise XModemException(_ERROR_XMODEM_READ_PACKET_TIMEOUT)
            # Second sequence byte should be the same as first as 1's complement
            seq_byte_2 = 0xff - seq_byte_2[0]
            if not (seq_byte == seq_byte_2 == self._seq_index):
                # Invalid block index.
                if self._log:
                    self._log.error(_ERROR_XMODEM_BAD_BLOCK_NUMBER % (self._seq_index, seq_byte))
                # Consume data.
                self._read_cb(block_size + self._verification_mode.length)
            else:
                data = self._read_cb(block_size, timeout=_XMODEM_READ_DATA_TIMEOUT)
                if not data or len(data) != block_size:
                    raise XModemException(_ERROR_XMODEM_READ_PACKET_TIMEOUT)
                verification = self._read_cb(self._verification_mode.length, timeout=_XMODEM_READ_DATA_TIMEOUT)
                if not verification or len(verification) != self._verification_mode.length:
                    raise XModemException(_ERROR_XMODEM_READ_PACKET_TIMEOUT)
                data_valid = True
                if self._verification_mode == _XModemVerificationMode.CHECKSUM:
                    checksum = _calculate_checksum(data)
                    if checksum != verification[0]:
                        data_valid = False
                else:
                    crc = _calculate_crc16_ccitt(data)
                    if crc[0] != verification[0] or crc[1] != verification[1]:
                        data_valid = False
                if data_valid:
                    # ACK packet
                    self._send_ack()
                    self._seq_index = (self._seq_index + 1) & 0xFF
                    return data
                else:
                    # Checksum/CRC is invalid.
                    if self._log:
                        self._log.error(_ERROR_XMODEM_BAD_DATA)

            # Reaching this point means the packet is not valid. Purge port and send NAK before trying again.
            self._purge()
            self._send_nak()
            retries -= 1

        # All read retries are consumed, throw exception.
        raise XModemException(_ERROR_XMODEM_READ_PACKET % _XMODEM_READ_RETRIES)

    def _read_block_0(self):
        """
        Reads the block 0 of the file download process and extract file information.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error reading the XModem block 0.
        """
        self._seq_index = 0
        data = self._read_packet()
        if not data or len(data) == 0:
            raise XModemException(_ERROR_XMODEM_UNEXPECTED_EOT)
        # If it is an empty header just ACK it and return.
        if all(byte == 0 for byte in data):
            self._send_ack()
            return
        # File name is the first data block until a '0' (0x00) is found.
        index = 0
        name = bytearray()
        for byte in data:
            if byte == 0:
                break
            name.append(byte)
            index += 1
        name = name.decode(encoding='utf-8')
        self._download_file.name = name
        # File size is the next data block until a '0' (0x00) is found.
        size = bytearray()
        for byte in data[index + 1:]:
            if byte == 0:
                break
            size.append(byte)
            index += 1
        size = int(size.decode(encoding='utf-8'))
        self._download_file.size = size

        self._send_ack()
        self._seq_index += 1

    def get_file(self):
        """
        Performs the file read operation.

        Raises:
            XModemCancelException: if the transfer is cancelled by the remote end.
            XModemException: if there is any error during the file read process.
        """
        if self._log:
            self._log.debug("Downloading '%s' file through XModem" % self._dest_path)
        self._download_file = _DownloadFile(self._dest_path, self._mode)
        # Notify we are ready to receive data.
        self._send_verification_char()
        # Execute special protocol pre-actions.
        if self._mode == _XModemMode.YMODEM:
            self._read_block_0()
        else:
            self._seq_index = 1
        # Perform file download process.
        data = self._read_packet()
        previous_percent = None
        while len(data) > 0:
            if self._progress_cb is not None and self._download_file.percent != previous_percent:
                self._progress_cb(self._download_file.percent)
                previous_percent = self._download_file.percent
            self._download_file.write_data_chunk(data)
            data = self._read_packet()
        self._download_file.close_file()
        # Execute special protocol post-actions.
        if self._mode == _XModemMode.YMODEM:
            self._send_verification_char()
            self._read_block_0()


def _calculate_crc16_ccitt(data):
    """
    Calculates and returns the CRC16 CCITT verification sequence of the given data.

    Args:
        data (Bytearray): the data to calculate its CRC16 CCITT verification sequence.

    Returns:
        Bytearray: the CRC16 CCITT verification sequence of the given data as a 2 bytes byte array.
    """
    crc = 0x0000
    for i in range(0, len(data)):
        crc ^= data[i] << 8
        for j in range(0, 8):
            if (crc & 0x8000) > 0:
                crc = (crc << 1) ^ XMODEM_CRC_POLYNOMINAL
            else:
                crc = crc << 1
            crc &= 0xFFFF

    return (crc & 0xFFFF).to_bytes(2, byteorder='big')


def _calculate_checksum(data):
    """
    Calculates and returns the checksum verification byte of the given data.

    Args:
        data (Bytearray): the data to calculate its checksum verification byte.

    Returns:
        Integer: the checksum verification byte of the given data.
    """
    checksum = 0
    for byte in data:
        ch = byte & 0xFF
        checksum += ch

    return checksum & 0xFF


def _get_milliseconds():
    """
    Returns the current time in milliseconds.

    Returns:
         Integer: the current time in milliseconds.
    """
    return int(time.time() * 1000.0)


def send_file_xmodem(src_path, write_cb, read_cb, progress_cb=None, log=None):
    """
    Sends a file using the XModem protocol to a remote end.

    Args:
        src_path (String): absolute path of the file to transfer.
        write_cb (Function): function to execute in order to write data to the remote end.
            Takes the following arguments:

                * The data to write as byte array.

            The function returns the following:

                Boolean: ``True`` if the write succeeded, ``False`` otherwise

        read_cb (Function): function to execute in order to read data from the remote end.
            Takes the following arguments:

                * The size of the data to read.
                * The timeout to wait for data. (seconds)

            The function returns the following:

                Bytearray: the read data, ``None`` if data could not be read

        progress_cb (Function, optional): function to execute in order to receive progress information.

             Takes the following arguments:

                * The progress percentage as integer.

        log (:class:`.Logger`, optional): logger used to log transfer debug messages

    Raises:
        ValueError: if any input value is not valid.
        XModemCancelException: if the transfer is cancelled by the remote end.
        XModemException: if there is any error during the file transfer.
    """
    # Sanity checks.
    if not isinstance(src_path, str) or len(src_path) == 0:
        raise ValueError(_ERROR_VALUE_SRC_PATH)
    if not isinstance(write_cb, collections.Callable):
        raise ValueError(_ERROR_VALUE_WRITE_CB)
    if not isinstance(read_cb, collections.Callable):
        raise ValueError(_ERROR_VALUE_READ_CB)

    session = _XModemTransferSession(src_path, write_cb, read_cb, mode=_XModemMode.XMODEM, progress_cb=progress_cb,
                                     log=log)
    session.transfer_file()


def send_file_ymodem(src_path, write_cb, read_cb, progress_cb=None, log=None):
    """
    Sends a file using the YModem protocol to a remote end.

    Args:
        src_path (String): absolute path of the file to transfer.
        write_cb (Function): function to execute in order to write data to the remote end.
            Takes the following arguments:

                * The data to write as byte array.

            The function returns the following:

                Boolean: ``True`` if the write succeeded, ``False`` otherwise

        read_cb (Function): function to execute in order to read data from the remote end.
            Takes the following arguments:

                * The size of the data to read.
                * The timeout to wait for data. (seconds)

            The function returns the following:

                Bytearray: the read data, ``None`` if data could not be read

        progress_cb (Function, optional): function to execute in order to receive progress information.

             Takes the following arguments:

                * The progress percentage as integer.

        log (:class:`.Logger`, optional): logger used to log transfer debug messages

    Raises:
        ValueError: if any input value is not valid.
        XModemCancelException: if the transfer is cancelled by the remote end.
        XModemException: if there is any error during the file transfer.
    """
    # Sanity checks.
    if not isinstance(src_path, str) or len(src_path) == 0:
        raise ValueError(_ERROR_VALUE_SRC_PATH)
    if not isinstance(write_cb, collections.Callable):
        raise ValueError(_ERROR_VALUE_WRITE_CB)
    if not isinstance(read_cb, collections.Callable):
        raise ValueError(_ERROR_VALUE_READ_CB)

    session = _XModemTransferSession(src_path, write_cb, read_cb, mode=_XModemMode.YMODEM, progress_cb=progress_cb,
                                     log=log)
    session.transfer_file()


def get_file_ymodem(dest_path, write_cb, read_cb, crc=True, progress_cb=None, log=None):
    """
    Retrieves a file using the YModem protocol from a remote end.

    Args:
        dest_path (String): absolute path to store downloaded file in.
        write_cb (Function): function to execute in order to write data to the remote end.
            Takes the following arguments:

                * The data to write as byte array.

            The function returns the following:

                Boolean: ``True`` if the write succeeded, ``False`` otherwise

        read_cb (Function): function to execute in order to read data from the remote end.
            Takes the following arguments:

                * The size of the data to read.
                * The timeout to wait for data. (seconds)

            The function returns the following:

                Bytearray: the read data, ``None`` if data could not be read

        crc (Boolean, optional): ``True`` to use 16-bit CRC verification, ``False`` for standard 1 byte checksum.
                                 Defaults to ``True``
        progress_cb (Function, optional): function to execute in order to receive progress information.

             Takes the following arguments:

                * The progress percentage as integer.

        log (:class:`.Logger`, optional): logger used to log download debug messages

    Raises:
        ValueError: if any input value is not valid.
        XModemCancelException: if the file download is cancelled by the remote end.
        XModemException: if there is any error during the file download process.
    """
    # Sanity checks.
    if not isinstance(dest_path, str) or len(dest_path) == 0:
        raise ValueError(_ERROR_VALUE_DEST_PATH)
    if not isinstance(write_cb, collections.Callable):
        raise ValueError(_ERROR_VALUE_WRITE_CB)
    if not isinstance(read_cb, collections.Callable):
        raise ValueError(_ERROR_VALUE_READ_CB)

    if crc:
        session = _XModemReadSession(dest_path, write_cb, read_cb, mode=_XModemMode.YMODEM,
                                     verification_mode=_XModemVerificationMode.CRC_16,
                                     progress_cb=progress_cb, log=log)
    else:
        session = _XModemReadSession(dest_path, write_cb, read_cb, mode=_XModemMode.YMODEM,
                                     verification_mode=_XModemVerificationMode.CHECKSUM,
                                     progress_cb=progress_cb, log=log)
    session.get_file()
