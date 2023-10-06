# Copyright 2019-2023, Digi International Inc.
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

import abc
from abc import abstractmethod


class XBeeCommunicationInterface(metaclass=abc.ABCMeta):
    """
    This class represents the way the communication with the local XBee is
    established.
    """

    @abstractmethod
    def open(self):
        """
        Establishes the underlying hardware communication interface.

        Subclasses may throw specific exceptions to signal implementation
        specific errors.
        """

    @abstractmethod
    def close(self):
        """
        Terminates the underlying hardware communication interface.

        Subclasses may throw specific exceptions to signal implementation
        specific hardware errors.
        """

    @property
    @abstractmethod
    def is_interface_open(self):
        """
        Returns whether the underlying hardware communication interface is
        active or not.

        Returns:
            Boolean: `True` if the interface is active, `False` otherwise.
        """

    @abstractmethod
    def wait_for_frame(self, operating_mode):
        """
        Reads the next API frame packet.

        This method blocks until:
         * A complete frame is read, in which case returns it.
         * The configured timeout goes by, in which case returns `None`.
         * Another thread calls quit_reading, in which case returns `None`.

        This method is not thread-safe, so no more than one thread should
        invoke it at the same time.

        Subclasses may throw specific exceptions to signal implementation
        specific hardware errors.

        Args:
            operating_mode (:class:`.OperatingMode`): The operating mode of the
                XBee connected to this hardware interface.
                Note: If this parameter does not match the connected XBee
                configuration, the behavior is undefined.

        Returns:
            Bytearray: The read packet as bytearray if a packet is read,
                `None` otherwise.
        """

    @abstractmethod
    def quit_reading(self):
        """
        Makes the thread (if any) blocking on wait_for_frame return.

        If a thread was blocked on wait_for_frame, this method blocks (for a
        maximum of 'timeout' seconds) until the blocked thread is resumed.
        """

    @abstractmethod
    def write_frame(self, frame):
        """
        Writes an XBee frame to the underlying hardware interface.

        Subclasses may throw specific exceptions to signal implementation
        specific hardware errors.

        Args:
            frame (Bytearray): The XBee API frame packet to write.
                If the bytearray does not correctly represent an XBee frame,
                the behaviour is undefined.

        Raises:
            CommunicationException: If there is any error writing the frame.
        """

    def get_network(self, local_xbee):
        """
        Returns the XBeeNetwork object associated to the XBeeDevice associated
        to this `XBeeCommunicationInterface`.

        Some `XBeeCommunicationInterface implementations may need to handle the
        `XBeeNetwork` associated to the `XBeeDevice` themselves. If that is the
        case, a implementation-specific XBeeNetwork object that complains to
        the generic `XBeeNetwork` class will be returned. Otherwise, this
        method returns `None` and the associated `XBeeNetwork` is handled as
        for a serial-connected `XBeeDevice`.

        Args:
            local_xbee (:class:`.XBeeDevice`): The local XBee device.

        Returns:
            :class: `.XBeeNetwork`: `None` if the XBeeNetwork should handled as
                usual, otherwise a `XBeeNetwork` object.
        """
        return None

    def get_local_xbee_info(self):
        """
        Returns a tuple with the local XBee information.

        This is used when opening the local XBee. If this information is
        provided, it is used as internal XBee data, if not provided, the data
        is requested to the XBee.

        Returns:
            Tuple: Tuple with local XBee information: operation mode (int),
                hardware version (int), firmware version (int),
                64-bit address (string), 16-bit address (string),
                node identifier (string), and role (int).
        """
        return None

    def get_stats(self):
        """
        Returns a statistics object.

        Returns:
             :class: `.Statistics`: `None` if not implemented,
              otherwise a `Statistics` object.
        """
        return None

    def supports_update_firmware(self):
        """
        Returns if the interface supports the firmware update feature.

        Returns:
             Boolean: `True` if it is supported, `False` otherwise.
        """
        return False

    def update_firmware(self, xbee, xml_fw_file, xbee_fw_file=None,
                        bootloader_fw_file=None, timeout=None,
                        progress_callback=None):
        """
        Performs a firmware update operation of the provided XBee.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): Local or remote XBee node to
                be updated.
            xml_fw_file (String): Path of the XML file that describes the
                firmware to upload.
            xbee_fw_file (String, optional): Location of the XBee binary
                firmware file.
            bootloader_fw_file (String, optional): Location of the bootloader
                binary firmware file.
            timeout (Integer, optional): Maximum time to wait for target read
                operations during the update process.
            progress_callback (Function, optional): Function to execute to
                receive progress information. Receives two arguments:

                * The current update task as a String
                * The current update task percentage as an Integer

        Raises:
            XBeeException: If the local XBee is not open.
            InvalidOperatingModeException: If the local XBee operating mode is
                invalid.
            OperationNotSupportedException: If the firmware update is not
                supported in the XBee.
            FirmwareUpdateException: If there is any error performing the
                firmware update.
        """

    def supports_apply_profile(self):
        """
        Returns if the interface supports the apply profile feature.

        Returns:
             Boolean: `True` if it is supported, `False` otherwise.
        """
        return False

    def apply_profile(self, xbee, profile_path, timeout=None, progress_callback=None):
        """
        Applies the given XBee profile to the XBee device.

        Args:
            xbee (:class:`.AbstractXBeeDevice`): Local or remote XBee node to
                be updated.
            profile_path (String): Path of the XBee profile file to apply.
            timeout (Integer, optional): Maximum time to wait for target read
                operations during the apply profile.
            progress_callback (Function, optional): Function to execute to
                receive progress information. Receives two arguments:

                * The current apply profile task as a String
                * The current apply profile task percentage as an Integer

        Raises:
            XBeeException: If the local XBee is not open.
            InvalidOperatingModeException: If the local XBee operating mode is
                invalid.
            UpdateProfileException: If there is any error applying the XBee
                profile.
            OperationNotSupportedException: If XBee profiles are not supported
                in the XBee.
        """

    @property
    @abstractmethod
    def timeout(self):
        """
        Returns the read timeout.

        Returns:
            Integer: Read timeout in seconds.
        """

    @timeout.setter
    @abstractmethod
    def timeout(self, timeout):
        """
        Sets the read timeout in seconds.

        Args:
            timeout (Integer): The new read timeout in seconds.
        """
