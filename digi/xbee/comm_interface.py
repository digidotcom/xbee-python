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

import abc
from abc import abstractmethod


class XBeeCommunicationInterface(metaclass=abc.ABCMeta):
    """
    This class represents the way the communication with the local XBee is established.
    """

    @abstractmethod
    def open(self):
        """
        Establishes the underlying hardware communication interface.

        Subclasses may throw specific exceptions to signal implementation specific
        errors.
        """
        pass

    @abstractmethod
    def close(self):
        """
        Terminates the underlying hardware communication interface.

        Subclasses may throw specific exceptions to signal implementation specific
        hardware errors.
        """
        pass

    @property
    @abstractmethod
    def is_interface_open(self):
        """
        Returns whether the underlying hardware communication interface is active or not.

        Returns:
            Boolean. ``True`` if the interface is active, ``False`` otherwise.
        """
        pass

    @abstractmethod
    def wait_for_frame(self, operating_mode):
        """
        Reads the next API frame packet.

        This method blocks until:
         * A complete frame is read, in which case returns it.
         * The configured timeout goes by, in which case returns None.
         * Another thread calls quit_reading, in which case returns None.

        This method is not thread-safe, so no more than one thread should invoke it at the same time.

        Subclasses may throw specific exceptions to signal implementation specific
        hardware errors.

        Args:
            operating_mode (:class:`.OperatingMode`): the operating mode of the XBee connected to this hardware
                interface.
                Note: if this parameter does not match the connected XBee configuration, the behavior is undefined.

        Returns:
            Bytearray: the read packet as bytearray if a packet is read, ``None`` otherwise.
        """
        pass

    @abstractmethod
    def quit_reading(self):
        """
        Makes the thread (if any) blocking on wait_for_frame return.

        If a thread was blocked on wait_for_frame, this method blocks (for a maximum of 'timeout' seconds) until
        the blocked thread is resumed.
        """
        pass

    @abstractmethod
    def write_frame(self, frame):
        """
        Writes an XBee frame to the underlying hardware interface.

        Subclasses may throw specific exceptions to signal implementation specific
        hardware errors.

        Args:
            frame (:class:`.Bytearray`): The XBee API frame packet to write. If the bytearray does not
                correctly represent an XBee frame, the behaviour is undefined.
        """
        pass

    @property
    @abstractmethod
    def timeout(self):
        """
        Returns the read timeout.

        Returns:
            Integer: read timeout in seconds.
        """
        pass

    @timeout.setter
    @abstractmethod
    def timeout(self, timeout):
        """
        Sets the read timeout in seconds.

        Args:
            timeout (Integer): the new read timeout in seconds.
        """
        pass