# Copyright 2017-2019, Digi International Inc.
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

import logging
from functools import wraps

# Number of bits to extract with the mask (__MASK)
__MASK_NUM_BITS = 8

# Bit mask to extract the less important __MAS_NUM_BITS bits of a number.
__MASK = 0xFF


def is_bit_enabled(number, position):
    """
    Returns whether the bit located at ``position`` within ``number`` is enabled or not.

    Args:
        number (Integer): the number to check if a bit is enabled.
        position (Integer): the position of the bit to check if is enabled in ``number``.

    Returns:
        Boolean: ``True`` if the bit located at ``position`` within ``number`` is enabled, ``False`` otherwise.
    """
    return ((number & 0xFFFFFFFF) >> position) & 0x01 == 0x01


def get_int_from_byte(number, offset, length):
    """
    Reads an integer value from the given byte using the provived bit offset and length.

    Args:
        number (Integer): Byte to read the integer from.
        offset (Integer): Bit offset inside the byte to start reading (LSB = 0, MSB = 7).
        length (Integer): Number of bits to read.

    Returns:
        Integer: The integer value read.

    Raises:
        ValueError: If ``number`` is lower than 0 or higher than 255.
                    If ``offset`` is lower than 0 or higher than 7.
                    If ``length`` is lower than 0 or higher than 8.
                    If ``offset + length`` is higher than 8.
    """
    if number < 0 or number > 255:
        raise ValueError("Number must be between 0 and 255")
    if offset < 0 or offset > 7:
        raise ValueError("Offset must be between 0 and 7")
    if length < 0 or length > 8:
        raise ValueError("Length must be between 0 and 8")
    if offset + length > 8:
        raise ValueError(
            "Starting at offset=%d, length must be between 0 and %d" % (offset, 8 - offset))

    if not length:
        return 0

    binary = "{0:08b}".format(number)
    end = len(binary) - offset - 1
    start = end - length + 1

    return int(binary[start:end + 1], 2)


def hex_string_to_bytes(hex_string):
    """
    Converts a String (composed by hex. digits) into a bytearray with same digits.
    
    Args:
        hex_string (String): String (made by hex. digits) with "0x" header or not.

    Returns:
        Bytearray: bytearray containing the numeric value of the hexadecimal digits.
        
    Raises:
        ValueError: if invalid literal for int() with base 16 is provided.
    
    Example:
        >>> a = "0xFFFE"
        >>> for i in hex_string_to_bytes(a): print(i)
        255
        254
        >>> print(type(hex_string_to_bytes(a)))
        <type 'bytearray'>
        
        >>> b = "FFFE"
        >>> for i in hex_string_to_bytes(b): print(i)
        255
        254
        >>> print(type(hex_string_to_bytes(b)))
        <type 'bytearray'>
        
    """
    aux = int(hex_string, 16)
    return int_to_bytes(aux)


def int_to_bytes(number, num_bytes=None):
    """
    Converts the provided integer into a bytearray.
    
    If ``number`` has less bytes than ``num_bytes``, the resultant bytearray
    is filled with zeros (0x00) starting at the beginning.
    
    If ``number`` has more bytes than ``num_bytes``, the resultant bytearray
    is returned without changes.
    
    Args:
        number (Integer): the number to convert to a bytearray.
        num_bytes (Integer): the number of bytes that the resultant bytearray will have.

    Returns:
        Bytearray: the bytearray corresponding to the provided number.

    Example:
        >>> a=0xFFFE
        >>> print([i for i in int_to_bytes(a)])
        [255,254]
        >>> print(type(int_to_bytes(a)))
        <type 'bytearray'>
        
    """
    byte_array = bytearray()
    byte_array.insert(0, number & __MASK)
    number >>= __MASK_NUM_BITS
    while number != 0:
        byte_array.insert(0, number & __MASK)
        number >>= __MASK_NUM_BITS

    if num_bytes is not None:
        while len(byte_array) < num_bytes:
            byte_array.insert(0, 0x00)

    return byte_array


def length_to_int(byte_array):
    """
    Calculates the length value for the given length field of a packet.
    Length field are bytes 1 and 2 of any packet.
    
    Args:
        byte_array (Bytearray): length field of a packet.
        
    Returns:
        Integer: the length value.
    
    Raises:
        ValueError: if ``byte_array`` is not a valid length field (it has length distinct than 0).
    
    Example:
        >>> b = bytearray([13,14])
        >>> c = length_to_int(b)
        >>> print("0x%02X" % c)
        0x1314
        >>> print(c)
        4884
    """
    if len(byte_array) != 2:
        raise ValueError("bArray must have length 2")
    return (byte_array[0] << 8) + byte_array[1]


def bytes_to_int(byte_array):
    """
    Converts the provided bytearray in an Integer.
    This integer is result of concatenate all components of ``byte_array``
    and convert that hex number to a decimal number.

    Args:
        byte_array (Bytearray): bytearray to convert in integer.

    Returns:
        Integer: the integer corresponding to the provided bytearray.

    Example:
        >>> x = bytearray([0xA,0x0A,0x0A]) #this is 0xA0A0A
        >>> print(bytes_to_int(x))
        657930
        >>> b = bytearray([0x0A,0xAA])    #this is 0xAAA
        >>> print(bytes_to_int(b))
        2730
    """
    if len(byte_array) == 0:
        return 0
    return int("".join(["%02X" % i for i in byte_array]), 16)


def ascii_to_int(ni):
    """
    Converts a bytearray containing the ASCII code of each number digit in an Integer.
    This integer is result of the number formed by all ASCII codes of the bytearray.
    
    Example:
        >>> x = bytearray( [0x31,0x30,0x30] )   #0x31 => ASCII code for number 1.
                                                #0x31,0x30,0x30 <==> 1,0,0
        >>> print(ascii_to_int(x))
        100
    """
    return int("".join([str(i - 0x30) for i in ni]))


def int_to_ascii(number):
    """
    Converts an integer number to a bytearray. Each element of the bytearray is the ASCII
    code that corresponds to the digit of its position.

    Args:
        number (Integer): the number to convert to an ASCII bytearray.

    Returns:
        Bytearray: the bytearray containing the ASCII value of each digit of the number.

    Example:
        >>> x = int_to_ascii(100)
        >>> print(x)
        100
        >>> print([i for i in x])
        [49, 48, 48]
    """
    return bytearray([ord(i) for i in str(number)])


def int_to_length(number):
    """
    Converts am integer into a bytearray of 2 bytes corresponding to the length field of a
    packet. If this bytearray has length 1, a byte with value 0 is added at the beginning.

    Args:
        number (Integer): the number to convert to a length field.

    Returns:


    Raises:
        ValueError: if ``number`` is less than 0 or greater than 0xFFFF.
        
    Example:
        >>> a = 0
        >>> print(hex_to_string(int_to_length(a)))
        00 00
        
        >>> a = 8
        >>> print(hex_to_string(int_to_length(a)))
        00 08
        
        >>> a = 200
        >>> print(hex_to_string(int_to_length(a)))
        00 C8
        
        >>> a = 0xFF00
        >>> print(hex_to_string(int_to_length(a)))
        FF 00
        
        >>> a = 0xFF
        >>> print(hex_to_string(int_to_length(a)))
        00 FF
    """
    if number < 0 or number > 0xFFFF:
        raise ValueError("The number must be between 0 and 0xFFFF.")
    length = int_to_bytes(number)
    if len(length) < 2:
        length.insert(0, 0)
    return length


def hex_to_string(byte_array, pretty=True):
    """
    Returns the provided bytearray in a pretty string format. All bytes are separated by blank spaces and
    printed in hex format.

    Args:
        byte_array (Bytearray): the bytearray to print in pretty string.
        pretty (Boolean, optional): ``True`` for pretty string format, ``False`` for plain string format.
            Default to ``True``.

    Returns:
        String: the bytearray formatted in a string format.
    """
    separator = " " if pretty else ""
    return separator.join(["%02X" % i for i in byte_array])


def doc_enum(enum_class, descriptions=None):
    """
    Returns a string with the description of each value of an enumeration.
    
    Args:
        enum_class (Enumeration): the Enumeration to get its values documentation.
        descriptions (dictionary): each enumeration's item description. The key is the enumeration element name
            and the value is the description.
            
    Returns:
        String: the string listing all the enumeration values and their descriptions.
    """
    tab = " "*4
    data = "\n| Values:\n"
    for x in enum_class:
        data += """| {:s}**{:s}**{:s} {:s}\n""".format(tab, x,
                                                       ":" if descriptions is not None else " =",
                                                       str(x.value) if descriptions is None else descriptions[x])
    return data + "| \n"


def enable_logger(name, level=logging.DEBUG):
    """
    Enables a logger with the given name and level.

    Args:
        name (String): name of the logger to enable.
        level (Integer): logging level value.
    
    Assigns a default formatter and a default handler (for console).
    """
    log = logging.getLogger(name)
    log.disabled = False
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)-7s - %(message)s')
    ch.setFormatter(formatter)
    log.addHandler(ch)
    log.setLevel(level)


def disable_logger(name):
    """
    Disables the logger with the give name.

    Args:
        name (String): the name of the logger to disable.
    """
    log = logging.getLogger(name)
    log.disabled = True


def deprecated(version, details="None"):
    """
    Decorates a method to mark as deprecated.
    This adds a deprecation note to the method docstring and also raises a
    :class:``warning.DeprecationWarning``.

    Args:
        version (String): Version that deprecates this feature.
        details (String, optional, default=``None``): Extra details to be added to the
            method docstring and warning.
    """
    def _function_wrapper(func):
        docstring = func.__doc__ or ""
        msg = ".. deprecated:: %s\n" % version

        doc_list = docstring.split(sep="\n", maxsplit=1)
        leading_spaces = 0
        if len(doc_list) > 1:
            leading_spaces = len(doc_list[1]) - len(doc_list[1].lstrip())

        doc_list.insert(0, "\n\n")
        doc_list.insert(0, ' ' * (leading_spaces + 4) + details if details else "")
        doc_list.insert(0, ' ' * leading_spaces + msg)
        doc_list.insert(0, "\n")

        func.__doc__ = "".join(doc_list)

        @wraps(func)
        def _inner(*args, **kwargs):
            message = "'%s' is deprecated." % func.__name__
            if details:
                message = "%s %s" % (message, details)
                import warnings
                warnings.simplefilter("default")
                warnings.warn(message, category=DeprecationWarning, stacklevel=2)

            return func(*args, **kwargs)

        return _inner

    return _function_wrapper
