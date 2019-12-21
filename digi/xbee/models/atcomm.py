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

from digi.xbee.models.status import ATCommandStatus
from enum import Enum, unique
from digi.xbee.util import utils


@unique
class ATStringCommand(Enum):
    """
    This class represents basic AT commands.

    | Inherited properties:
    |     **name** (String): name (ID) of this ATStringCommand.
    |     **value** (String): value of this ATStringCommand.
    """

    NI = "NI"
    KY = "KY"
    NK = "NK"
    ZU = "ZU"
    ZV = "ZV"
    CC = "CC"

    def __init__(self, command):
        self.__command = command

    def __get_command(self):
        return self.__command

    command = property(__get_command)
    """String. AT Command alias."""


ATStringCommand.__doc__ += utils.doc_enum(ATStringCommand)


@unique
class SpecialByte(Enum):
    """
    Enumerates all the special bytes of the XBee protocol that must be escaped
    when working on API 2 mode.

    | Inherited properties:
    |     **name** (String): name (ID) of this SpecialByte.
    |     **value** (String): the value of this SpecialByte.
    """

    ESCAPE_BYTE = 0x7D
    HEADER_BYTE = 0x7E
    XON_BYTE = 0x11
    XOFF_BYTE = 0x13

    def __init__(self, code):
        self.__code = code

    def __get_code(self):
        """
        Returns the code of the SpecialByte element.

        Returns:
            Integer: the code of the SpecialByte element.
        """
        return self.__code

    @classmethod
    def get(cls, value):
        """
        Returns the special byte for the given value.

        Args:
            value (Integer): value associated to the special byte.

        Returns:
            SpecialByte: SpecialByte with the given value.
        """
        return SpecialByte.lookupTable[value]

    @staticmethod
    def escape(value):
        """
        Escapes the byte by performing a XOR operation with 0x20 value.

        Args:
            value (Integer): value to escape.

        Returns:
            Integer: value ^ 0x20 (escaped).
        """
        return value ^ 0x20

    @staticmethod
    def is_special_byte(value):
        """
        Checks whether the given byte is special or not.

        Args:
            value (Integer): byte to check.

        Returns:
            Boolean: ``True`` if value is a special byte, ``False`` in other case.
        """
        return True if value in [i.value for i in SpecialByte] else False

    code = property(__get_code)
    """Integer. The special byte code."""


SpecialByte.lookupTable = {x.code: x for x in SpecialByte}
SpecialByte.__doc__ += utils.doc_enum(SpecialByte)


class ATCommand(object):
    """
    This class represents an AT command used to read or set different properties
    of the XBee device.

    AT commands can be sent directly to the connected device or to remote
    devices and may have parameters.

    After executing an AT Command, an AT Response is received from the device.
    """

    def __init__(self, command, parameter=None):
        """
        Class constructor. Instantiates a new :class:`.ATCommand` object with the provided parameters.

        Args:
            command (String): AT Command, must have length 2.
            parameter (String or Bytearray, optional): The AT parameter value. Defaults to ``None``. Optional.

        Raises:
            ValueError: if command length is not 2.
        """
        if len(command) != 2:
            raise ValueError("Command length must be 2.")

        self.__command = command
        self.__set_parameter(parameter)

    def __str__(self):
        """
        Returns a string representation of this ATCommand.

        Returns:
            String: representation of this ATCommand.
        """
        return "Command: " + self.__command + "\n" + "Parameter: " + str(self.__parameter)

    def __len__(self):
        """
        Returns the length of this ATCommand.

        Returns:
            Integer: length of command + length of parameter.
        """
        if self.__parameter:
            return len(self.__command) + len(self.__parameter)
        else:
            return len(self.__command)

    def __get_command(self):
        """
        Returns the AT command.

        Returns:
            ATCommand: the AT command.
        """
        return self.__command

    def __get_parameter(self):
        """
        Returns the AT command parameter.

        Returns:
            Bytearray: the AT command parameter. ``None`` if there is no parameter.
        """
        return self.__parameter

    def get_parameter_string(self):
        """
        Returns this ATCommand parameter as a String.

        Returns:
            String: this ATCommand parameter. ``None`` if there is no parameter.
        """
        return self.__parameter.decode() if self.__parameter else None

    def __set_parameter(self, parameter):
        """
        Sets the AT command parameter.

        Args:
            parameter (Bytearray): the parameter to be set.
        """
        if isinstance(parameter, str):
            self.__parameter = bytearray(parameter, 'utf8')
        else:
            self.__parameter = parameter

    command = property(__get_command)
    """String. The AT command"""

    parameter = property(__get_parameter, __set_parameter)
    """Bytearray. The AT command parameter"""


class ATCommandResponse(object):
    """
    This class represents the response of an AT Command sent by the connected
    XBee device or by a remote device after executing an AT Command.
    """

    def __init__(self, command, response=None, status=ATCommandStatus.OK):
        """
        Class constructor.

        Args:
            command (ATCommand): The AT command that generated the response.
            response (bytearray, optional): The command response. Default to ``None``.
            status (ATCommandStatus, optional): The AT command status. Default to ATCommandStatus.OK
        """
        self.__atCommand = command
        self.__response = response
        self.__comm_status = status

    def __get_command(self):
        """
        Returns the AT command.

        Returns:
            ATCommand: the AT command.
        """
        return self.__atCommand

    def __get_response(self):
        """
        Returns the AT command response.

        Returns:
            Bytearray: the AT command response.
        """
        return self.__response

    def __get_status(self):
        """
        Returns the AT command response status.

        Returns:
            ATCommandStatus: The AT command response status.
        """
        return self.__comm_status

    command = property(__get_command)
    """String. The AT command."""

    response = property(__get_response)
    """Bytearray. The AT command response data."""

    status = property(__get_status)
    """ATCommandStatus. The AT command response status."""
