# Copyright 2017, Digi International Inc.
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

from enum import Enum, unique
from digi.xbee.util import utils


class AccessPoint(object):
    """
    This class represents an Access Point for the Wi-Fi protocol. It contains 
    SSID, the encryption type and the link quality between the Wi-Fi module and 
    the access point.
    
    This class is used within the library to list the access points
    and connect to a specific one in the Wi-Fi protocol.

    .. seealso::
       | :class:`.WiFiEncryptionType`
    """

    __ERROR_CHANNEL = "Channel cannot be negative."
    __ERROR_SIGNAL_QUALITY = "Signal quality must be between 0 and 100."

    def __init__(self, ssid, encryption_type, channel=0, signal_quality=0):
        """
        Class constructor. Instantiates a new :class:`.AccessPoint` object with the provided parameters.

        Args:
            ssid (String): the SSID of the access point.
            encryption_type (:class:`.WiFiEncryptionType`): the encryption type configured in the access point.
            channel (Integer, optional): operating channel of the access point. Optional.
            signal_quality (Integer, optional): signal quality with the access point in %. Optional.

        Raises:
            ValueError: if length of ``ssid`` is 0.
            ValueError: if ``channel`` is less than 0.
            ValueError: if ``signal_quality`` is less than 0 or greater than 100.

        .. seealso::
           | :class:`.WiFiEncryptionType`
        """
        if len(ssid) == 0:
            raise ValueError("SSID cannot be empty.")
        if channel < 0:
            raise ValueError(self.__ERROR_CHANNEL)
        if signal_quality < 0 or signal_quality > 100:
            raise ValueError(self.__ERROR_SIGNAL_QUALITY)

        self.__ssid = ssid
        self.__encryption_type = encryption_type
        self.__channel = channel
        self.__signal_quality = signal_quality

    def __str__(self):
        """
        Returns the string representation of the access point.

        Returns:
            String: representation of the access point.
        """
        return "%s (%s) - CH: %s - Signal: %s%%" % (self.__ssid, self.__encryption_type.description,
                                                    self.__channel, self.__signal_quality)

    def __get_ssid(self):
        """
        Returns the SSID of the access point.

        Returns:
            String: the SSID of the access point.
        """
        return self.__ssid

    def __get_encryption_type(self):
        """
        Returns the encryption type of the access point.

        Returns:
            :class:`.WiFiEncryptionType`: the encryption type of the access point.

        .. seealso::
           | :class:`.WiFiEncryptionType`
        """
        return self.__encryption_type

    def __get_channel(self):
        """
        Returns the channel of the access point.

        Returns:
            Integer: the channel of the access point.

        .. seealso::
           | :func:`.AccessPoint.set_channel`
        """
        return self.__channel

    def __set_channel(self, channel):
        """
        Sets the channel of the access point.

        Args:
            channel (Integer): the new channel of the access point

        Raises:
            ValueError: if ``channel`` is less than 0.

        .. seealso::
           | :func:`.AccessPoint.get_channel`
        """
        if channel < 0:
            raise ValueError(self.__ERROR_CHANNEL)
        self.__channel = channel

    def __get_signal_quality(self):
        """
        Returns the signal quality with the access point in %.

        Returns:
            Integer: the signal quality with the access point in %.

        .. seealso::
           | :func:`.AccessPoint.__set_signal_quality`
        """
        return self.__signal_quality

    def __set_signal_quality(self, signal_quality):
        """
        Sets the channel of the access point.

        Args:
            signal_quality (Integer): the new signal quality with the access point.

        Raises:
            ValueError: if ``signal_quality`` is less than 0 or greater than 100.

        .. seealso::
           | :func:`.AccessPoint.__get_signal_quality`
        """
        if signal_quality < 0 or signal_quality > 100:
            raise ValueError(self.__ERROR_SIGNAL_QUALITY)
        self.__signal_quality = signal_quality

    ssid = property(__get_ssid)
    """String. SSID of the access point."""

    encryption_type = property(__get_encryption_type)
    """:class:`.WiFiEncryptionType`. Encryption type of the access point."""

    channel = property(__get_channel, __set_channel)
    """String. Channel of the access point."""

    signal_quality = property(__get_signal_quality, __set_signal_quality)
    """String. The signal quality with the access point in %."""


@unique
class WiFiEncryptionType(Enum):
    """
    Enumerates the different Wi-Fi encryption types.
    """
    NONE = (0, "No security")
    WPA = (1, "WPA (TKIP) security")
    WPA2 = (2, "WPA2 (AES) security")
    WEP = (3, "WEP security")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the WiFiEncryptionType element.

        Returns:
            Integer: the code of the WiFiEncryptionType element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the WiFiEncryptionType element.

        Returns:
            String: the description of the WiFiEncryptionType element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the Wi-Fi encryption type for the given code.

        Args:
            code (Integer): the code of the Wi-Fi encryption type to get.

        Returns:
            :class:`.WiFiEncryptionType`: the WiFiEncryptionType with the given code, ``None`` if there is
                not any Wi-Fi encryption type with the provided code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The Wi-Fi encryption type code."""

    description = property(__get_description)
    """String. The Wi-Fi encryption type description."""


WiFiEncryptionType.lookupTable = {x.code: x for x in WiFiEncryptionType}
WiFiEncryptionType.__doc__ += utils.doc_enum(WiFiEncryptionType)
