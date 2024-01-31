# Copyright 2017-2024, Digi International Inc.
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

import re
from digi.xbee.util import utils


class XBee16BitAddress:
    """
    This class represent a 16-bit network address.

    This address is only applicable for:

    1. 802.15.4
    2. Zigbee
    3. ZNet 2.5
    4. XTend (Legacy)

    DigiMesh and Point-to-multipoint does not support 16-bit addressing.

    Each device has its own 16-bit address which is unique in the network.
    It is automatically assigned when the radio joins the network for Zigbee
    and Znet 2.5, and manually configured in 802.15.4 radios.

    | Attributes:
    |     **COORDINATOR_ADDRESS** (XBee16BitAddress): 16-bit address reserved for the coordinator.
    |     **BROADCAST_ADDRESS** (XBee16BitAddress): 16-bit broadcast address.
    |     **UNKNOWN_ADDRESS** (XBee16BitAddress): 16-bit unknown address.
    |     **PATTERN** (String): Pattern for the 16-bit address string: `(0[xX])?[0-9a-fA-F]{1,4}`

    """

    PATTERN = "^(0[xX])?[0-9a-fA-F]{1,4}$"
    """
    16-bit address string pattern.
    """

    COORDINATOR_ADDRESS = None
    """
    16-bit address reserved for the coordinator (value: 0000).
    """

    BROADCAST_ADDRESS = None
    """
    16-bit broadcast address (value: FFFF).
    """

    UNKNOWN_ADDRESS = None
    """
    16-bit unknown address (value: FFFE).
    """

    __REGEXP = re.compile(PATTERN)

    def __init__(self, address):
        """
        Class constructor. Instantiates a new :class:`.XBee16BitAddress`
        object with the provided parameters.

        Args:
            address (Bytearray): address as byte array. Must be 1-2 digits.

        Raises:
            TypeError: if `address` is `None`.
            ValueError: if `address` is `None` or  has less than 1 byte or more than 2.
        """
        if not address:
            raise ValueError("Address must contain at least 1 byte")
        if len(address) > 2:
            raise ValueError("Address can't contain more than 2 bytes")

        if len(address) == 1:
            address.insert(0, 0)
        self.__address = address

    @classmethod
    def from_hex_string(cls, address):
        """
        Class constructor.  Instantiates a new :`.XBee16BitAddress` object from
        the provided hex string.

        Args:
            address (String): String containing the address. Must be made by
                hex. digits without blanks. Minimum 1 character, maximum 4 (16-bit).

        Raises:
            ValueError: if `address` has less than 1 character.
            ValueError: if `address` contains non-hexadecimal characters.
        """
        if not address:
            raise ValueError("Address must contain at least 1 digit")
        if not cls.__REGEXP.match(address):
            raise ValueError("Address must follow this pattern: " + cls.PATTERN)

        return cls(utils.hex_string_to_bytes(address))

    @classmethod
    def from_bytes(cls, hsb, lsb):
        """
        Class constructor.  Instantiates a new :`.XBee16BitAddress` object from
        the provided high significant byte and low significant byte.

        Args:
            hsb (Integer): high significant byte of the address.
            lsb (Integer): low significant byte of the address.

        Raises:
            ValueError: if `lsb` is less than 0 or greater than 255.
            ValueError: if `hsb` is less than 0 or greater than 255.
        """
        if hsb > 255 or hsb < 0:
            raise ValueError("HSB must be between 0 and 255.")
        if lsb > 255 or lsb < 0:
            raise ValueError("LSB must be between 0 and 255.")

        return cls(bytearray([hsb, lsb]))

    @classmethod
    def is_valid(cls, address):
        """
        Checks if the provided hex string is a valid 16-bit address.

        Args:
            address (String or Bytearray, or :class:`.XBee16BitAddress`):
                String: String with the address only with hex digits without
                blanks. Minimum 1 character, maximum 4 (16-bit).
                Bytearray: Address as byte array. Must be 1-2 digits.

        Returns:
            Boolean: `True` for a valid 16-bit address, `False` otherwise.
        """
        if isinstance(address, XBee16BitAddress):
            return True

        if isinstance(address, bytearray):
            return 1 <= len(address) <= 2

        if isinstance(address, str):
            return bool(cls.__REGEXP.match(address))

        return False

    @classmethod
    def is_known_node_addr(cls, address):
        """
        Checks if a provided address is a known value. That is, if it is a
        valid 16-bit address and it is not the unknown or the broadcast address.

        Args:
            address (String, Bytearray, or :class:`.XBee16BitAddress`): The 16-bit
                address to check as a string, bytearray or
                :class:`.XBee16BitAddress`.

        Returns:
            Boolean: `True` for a known node 16-bit address, `False` otherwise.
        """
        if not cls.is_valid(address):
            return False

        if isinstance(address, str):
            address = XBee16BitAddress.from_hex_string(address)
        elif isinstance(address, bytearray):
            address = XBee16BitAddress(address)

        return address not in (XBee16BitAddress.BROADCAST_ADDRESS,
                               XBee16BitAddress.UNKNOWN_ADDRESS)

    def __get_item__(self, index):
        """
        Operator []

        Args:
            index (Integer): index to be accessed.

        Returns:
            Integer. 'index' component of the address bytearray.
        """
        return self.__address.__get_item__(index)

    def __str__(self):
        """
        Called by the str() built-in function and by the print statement to
        compute the "informal" string representation of an object. This differs
        from __repr__() in that it does not have to be a valid Python
        expression: a more convenient or concise representation may be used instead.

        Returns:
            String: "informal" representation of this XBee16BitAddress.
        """
        return utils.hex_to_string(self.__address, pretty=False)

    def __hash__(self):
        """
        Returns a hash code value for the object.

        Returns:
            Integer: hash code value for the object.
        """
        res = 23
        for byte in self.__address:
            res = 31 * (res + byte)
        return res

    def __eq__(self, other):
        """
        Operator ==

        Args:
            other (:class`.XBee16BitAddress`): another XBee16BitAddress object.

        Returns:
            Boolean: `True` if self and other have the same value and type, `False` in other case.
        """
        if not isinstance(other, XBee16BitAddress):
            return False

        return self.address == other.address

    def __iter__(self):
        """
        Gets an iterator class of this instance address.

        Returns:
            Iterator: iterator of this address.
        """
        return self.__address.__iter__()

    def get_hsb(self):
        """
        Returns the high part of the bytearray (component 0).

        Returns:
            Integer: high part of the bytearray.
        """
        return self.__address[0]

    def get_lsb(self):
        """
        Returns the low part of the bytearray (component 1).

        Returns:
            Integer: low part of the bytearray.
        """
        return self.__address[1]

    @property
    def address(self):
        """
        Returns a bytearray representation of this XBee16BitAddress.

        Returns:
            Bytearray: bytearray representation of this XBee16BitAddress.
        """
        return bytearray(self.__address)


XBee16BitAddress.COORDINATOR_ADDRESS = XBee16BitAddress.from_hex_string("0000")
XBee16BitAddress.BROADCAST_ADDRESS = XBee16BitAddress.from_hex_string("FFFF")
XBee16BitAddress.UNKNOWN_ADDRESS = XBee16BitAddress.from_hex_string("FFFE")


class XBee64BitAddress:
    """
    This class represents a 64-bit address (also known as MAC address).

    The 64-bit address is a unique device address assigned during manufacturing.
    This address is unique to each physical device.
    """

    PATTERN = "^(0[xX])?[0-9a-fA-F]{1,16}$"
    """
    64-bit address string pattern.
    """

    COORDINATOR_ADDRESS = None
    """
    64-bit address reserved for the coordinator (value: 0000000000000000).
    """

    BROADCAST_ADDRESS = None
    """
    64-bit broadcast address (value: 000000000000FFFF).
    """

    UNKNOWN_ADDRESS = None
    """
    64-bit unknown address (value: FFFFFFFFFFFFFFFF).
    """

    __REGEXP = re.compile(PATTERN)

    def __init__(self, address):
        """
        Class constructor. Instantiates a new :class:`.XBee64BitAddress` object
        with the provided parameters.

        Args:
            address (Bytearray): the XBee 64-bit address as byte array.

        Raise:
            ValueError: if `address` is `None` or its length less than 1 or greater than 8.
        """
        if not address:
            raise ValueError("Address must contain at least 1 byte")
        if len(address) > 8:
            raise ValueError("Address cannot contain more than 8 bytes")

        self.__address = bytearray(address.rjust(8, b'\x00'))

    @classmethod
    def from_hex_string(cls, address):
        """
        Class constructor. Instantiates a new :class:`.XBee64BitAddress`
        object from the provided hex string.

        Args:
            address (String): The XBee 64-bit address as a string.

        Raises:
            ValueError: if the address' length is less than 1 or does not match
                with the pattern: `(0[xX])?[0-9a-fA-F]{1,16}`.
        """
        if not address:
            raise ValueError("Address must contain at least 1 byte")
        if not cls.__REGEXP.match(address):
            raise ValueError("Address must follow this pattern: " + cls.PATTERN)

        return cls(utils.hex_string_to_bytes(address))

    @classmethod
    def from_bytes(cls, *args):
        """
        Class constructor. Instantiates a new :class:`.XBee64BitAddress`
        object from the provided bytes.

        Args:
            args (8 Integers): 8 integers that represent the bytes 1 to 8 of
                this XBee64BitAddress.

        Raises:
            ValueError: if the amount of arguments is not 8 or if any of the
                arguments is not between 0 and 255.
        """
        if len(args) != 8:
            raise ValueError("Number of bytes given as arguments must be 8.")
        for i, val in enumerate(args):
            if val > 255 or val < 0:
                raise ValueError("Byte " + str(i + 1) + " must be between 0 and 255")

        return cls(bytearray(args))

    @classmethod
    def is_valid(cls, address):
        """
        Checks if the provided hex string is a valid 64-bit address.

        Args:
            address (String, Bytearray, or :class:`.XBee64BitAddress`):
                String: String with the address only with hex digits without
                blanks. Minimum 1 character, maximum 16 (64-bit).
                Bytearray: Address as byte array. Must be 1-8 digits.

        Returns
            Boolean: `True` for a valid 64-bit address, `False` otherwise.
        """
        if isinstance(address, XBee64BitAddress):
            return True

        if isinstance(address, bytearray):
            return 1 <= len(address) <= 8

        if isinstance(address, str):
            return bool(cls.__REGEXP.match(address))

        return False

    @classmethod
    def is_known_node_addr(cls, address):
        """
        Checks if a provided address is a known value. That is, if it is a
        valid 64-bit address and it is not the unknown or the broadcast address.

        Args:
            address (String, Bytearray, or :class:`.XBee64BitAddress`): The 64-bit
                address to check as a string, bytearray or
                :class:`.XBee64BitAddress`.

        Returns:
            Boolean: `True` for a known node 64-bit address, `False` otherwise.
        """
        if not cls.is_valid(address):
            return False

        if isinstance(address, str):
            address = XBee64BitAddress.from_hex_string(address)
        elif isinstance(address, bytearray):
            address = XBee64BitAddress(address)

        return address not in (XBee64BitAddress.BROADCAST_ADDRESS,
                               XBee64BitAddress.UNKNOWN_ADDRESS)

    def __str__(self):
        """
        Called by the str() built-in function and by the print statement to
        compute the "informal" string representation of an object. This differs
        from __repr__() in that it does not have to be a valid Python
        expression: a more convenient or concise representation may be used instead.

        Returns:
            String: "informal" representation of this XBee64BitAddress.
        """
        return "".join(["%02X" % i for i in self.__address])

    def __hash__(self):
        """
        Returns a hash code value for the object.

        Returns:
            Integer: hash code value for the object.
        """
        res = 23
        for byte in self.__address:
            res = 31 * (res + byte)
        return res

    def __eq__(self, other):
        """
        Operator ==

        Args:
            other: another XBee64BitAddress.

        Returns:
            Boolean: `True` if self and other have the same value and type, `False` in other case.
        """
        if other is None:
            return False
        if not isinstance(other, XBee64BitAddress):
            return False

        return self.address == other.address

    def __iter__(self):
        """
        Gets an iterator class of this instance address.

        Returns:
            Iterator: iterator of this address.
        """
        return self.__address.__iter__()

    @property
    def address(self):
        """
        Returns a bytearray representation of this XBee64BitAddress.

        Returns:
            Bytearray: bytearray representation of this XBee64BitAddress.
        """
        return bytearray(self.__address)


XBee64BitAddress.COORDINATOR_ADDRESS = XBee64BitAddress.from_hex_string("0000")
XBee64BitAddress.BROADCAST_ADDRESS = XBee64BitAddress.from_hex_string("FFFF")
XBee64BitAddress.UNKNOWN_ADDRESS = XBee64BitAddress.from_hex_string("F"*16)


class XBeeIMEIAddress:
    """
    This class represents an IMEI address used by cellular devices.

    This address is only applicable for Cellular protocol.
    """

    PATTERN = r"^\d{0,15}$"
    """
    IMEI address string pattern.
    """

    __REGEXP = re.compile(PATTERN)

    def __init__(self, address):
        """
        Class constructor. Instantiates a new :`.XBeeIMEIAddress` object with
        the provided parameters.

        Args:
            address (Bytearray): The XBee IMEI address as byte array.

        Raises:
            ValueError: if `address` is `None`.
            ValueError: if length of `address` greater than 8.
        """
        if address is None:
            raise ValueError("IMEI address cannot be None")
        if len(address) > 8:
            raise ValueError("IMEI address cannot be longer than 8 bytes")

        self.__address = self.__generate_byte_array(address)

    @classmethod
    def from_string(cls, address):
        """
        Class constructor. Instantiates a new :`.XBeeIMEIAddress` object from the provided string.

        Args:
            address (String): The XBee IMEI address as a string.

        Raises:
            ValueError: if `address` is `None`.
            ValueError: if `address` does not match the pattern: `^\\d{0,15}$`.
        """
        if address is None:
            raise ValueError("IMEI address cannot be None")
        if not cls.__REGEXP.match(address):
            raise ValueError("Address must follow this pattern: " + cls.PATTERN)

        return cls(utils.hex_string_to_bytes(address))

    @classmethod
    def is_valid(cls, address):
        """
        Checks if the provided hex string is a valid IMEI.

        Args:
            address (String or Bytearray): The XBee IMEI address as a string or bytearray.

        Returns:
            Boolean: `True` for a valid IMEI, `False` otherwise.
        """
        if isinstance(address, bytearray):
            return len(address) >= 8

        if isinstance(address, str):
            return cls.__REGEXP.match(address)

        return False

    @staticmethod
    def __generate_byte_array(byte_address):
        """
        Generates the IMEI byte address based on the given byte array.

        Args:
            byte_address (Bytearray): the byte array used to generate the final
                IMEI byte address.

        Returns:
            Bytearray: the IMEI in byte array format.
        """
        # Pad zeros in the MSB of the address
        return bytearray(8 - len(byte_address)) + byte_address

    @property
    def address(self):
        """
        Returns a string representation of this XBeeIMEIAddress.

        Returns:
            String: the IMEI address in string format.
        """
        return "".join(["%02X" % i for i in self.__address])[1:]

    def __str__(self):
        """
        Called by the str() built-in function and by the print statement to
        compute the "informal" string representation of an object. This differs
        from __repr__() in that it does not have to be a valid Python
        expression: a more convenient or concise representation may be used instead.

        Returns:
            String: "informal" representation of this XBeeIMEIAddress.
        """
        return self.address

    def __hash__(self):
        """
        Returns a hash code value for the object.

        Returns:
            Integer: hash code value for the object.
        """
        res = 23
        for byte in self.__address:
            res = 31 * (res + byte)
        return res

    def __eq__(self, other):
        """
        Operator ==

        Args:
            other (:class:`.XBeeIMEIAddress`): another XBeeIMEIAddress.

        Returns:
            Boolean: `True` if self and other have the same value and type, `False` in other case.
        """
        if other is None:
            return False
        if not isinstance(other, XBeeIMEIAddress):
            return False

        return self.address == other.address


class XBeeBLEAddress:
    """
    This class represents a 48-bit address (also known as MAC address).

    The 48-bit address is a unique device address assigned during
    manufacturing.
    This address is unique to each physical device.
    """

    PATTERN = "^(0[xX])?[0-9a-fA-F]{1,12}$"
    """
    48-bit address string pattern.
    """

    __REGEXP = re.compile(PATTERN)

    def __init__(self, address):
        """
        Class constructor. Instantiates a new :class:`.XBeeBLEAddress` object
        with the provided parameters.

        Args:
            address (Bytearray): the XBee BLE 48-bit address as byte array.

        Raise:
            ValueError: if `address` is `None` or its length less than 1
            or greater than 6.
        """
        if not address:
            raise ValueError("Address must contain at least 1 byte")
        if len(address) > 6:
            raise ValueError("Address cannot contain more than 6 bytes")

        self.__address = bytearray(address.rjust(6, b'\x00'))

    @classmethod
    def from_hex_string(cls, address):
        """
        Class constructor. Instantiates a new :class:`.XBeeBLEAddress`
        object from the provided hex string.

        Args:
            address (String): The XBee BLE 48-bit address as a string.

        Raises:
            ValueError: if the address' length is less than 1 or does not match
                with the pattern: `(0[xX])?[0-9a-fA-F]{1,12}`.
        """
        if not address:
            raise ValueError("Address must contain at least 1 byte")
        if not cls.__REGEXP.match(address):
            raise ValueError("Address must follow this pattern: " +
                             cls.PATTERN)

        return cls(utils.hex_string_to_bytes(address))

    @classmethod
    def from_bytes(cls, *args):
        """
        Class constructor. Instantiates a new :class:`.XBeeBLEAddress`
        object from the provided bytes.

        Args:
            args (6 Integers): 6 integers that represent the bytes 1 to 6 of
                this XBeeBLEAddress.

        Raises:
            ValueError: if the amount of arguments is not 6 or if any of the
                arguments is not between 0 and 255.
        """
        if len(args) != 6:
            raise ValueError("Number of bytes given as arguments must be 6.")
        for i, val in enumerate(args):
            if val > 255 or val < 0:
                raise ValueError("Byte " + str(i + 1) +
                                 " must be between 0 and 255")

        return cls(bytearray(args))

    @classmethod
    def is_valid(cls, address):
        """
        Checks if the provided hex string is a valid BLE 48-bit address.

        Args:
            address (String, Bytearray, or :class:`.XBeeBLEAddress`):
                String: String with the address only with hex digits without
                blanks. Minimum 1 character, maximum 12 (48-bit).
                Bytearray: Address as byte array. Must be 1-6 digits.

        Returns
            Boolean: `True` for a valid BLE 48-bit address, `False` otherwise.
        """
        if isinstance(address, XBeeBLEAddress):
            return True

        if isinstance(address, bytearray):
            return 1 <= len(address) <= 6

        if isinstance(address, str):
            return bool(cls.__REGEXP.match(address))

        return False

    def __str__(self):
        """
        Called by the str() built-in function and by the print statement to
        compute the "informal" string representation of an object. This differs
        from __repr__() in that it does not have to be a valid Python
        expression: a more convenient or concise representation may be
        used instead.

        Returns:
            String: "informal" representation of this XBeeBLEAddress.
        """
        return utils.hex_to_string(self.__address, pretty=False)

    def __hash__(self):
        """
        Returns a hash code value for the object.

        Returns:
            Integer: hash code value for the object.
        """
        res = 23
        for byte in self.__address:
            res = 31 * (res + byte)
        return res

    def __eq__(self, other):
        """
        Operator ==

        Args:
            other: another XBeeBLEAddress.

        Returns:
            Boolean: `True` if self and other have the same value and type,
                     `False` in other case.
        """
        if not isinstance(other, XBeeBLEAddress):
            return False

        return self.address == other.address

    def __iter__(self):
        """
        Gets an iterator class of this instance address.

        Returns:
            Iterator: iterator of this address.
        """
        return self.__address.__iter__()

    @property
    def address(self):
        """
        Returns a bytearray representation of this XBeeBLEAddress.

        Returns:
            Bytearray: bytearray representation of this XBeeBLEAddress.
        """
        return bytearray(self.__address)
