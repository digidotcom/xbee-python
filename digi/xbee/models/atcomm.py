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
from enum import Enum, unique

from digi.xbee.models.status import ATCommandStatus
from digi.xbee.util import utils


@unique
class ATStringCommand(Enum):
    """
    This class represents basic AT commands.

    | Inherited properties:
    |     **name** (String): name (ID) of this ATStringCommand.
    |     **value** (String): value of this ATStringCommand.
    """

    AC = ("AC", "Apply changes")
    AG = ("AG", "Aggregator support")
    AI = ("AI", "Association indication")
    AO = ("AO", "API options")
    AP = ("AP", "API enable")
    AR = ("AR", "Many-to-one route broadcast time")
    AS = ("AS", "Active scan")
    BD = ("BD", "UART baudrate")
    BI = ("BI", "Bluetooth identifier")
    BL = ("BL", "Bluetooth address")
    BP = ("BP", "Bluetooth advertisement power")
    BT = ("BT", "Bluetooth enable")
    BR = ("BR", "RF data rate")
    C0 = ("C0", "Source port")
    C8 = ("C8", "Compatibility mode")
    CC = ("CC", "Command sequence character")
    CE = ("CE", "Device role")
    CH = ("CH", "Channel")
    CK = ("CK", "Configuration checksum")
    CM = ("CM", "Channel mask")
    CN = ("CN", "Exit command mode")
    DA = ("DA", "Force Disassociation")
    DB = ("DB", "RSSI")
    DD = ("DD", "Device type")
    DH = ("DH", "Destination address high")
    DJ = ("DJ", "Disable joining")
    DL = ("DL", "Destination address low")
    DM = ("DM", "Disable device functionality")
    DO = ("DO", "Device options")
    D0 = ("D0", "DIO0 configuration")
    D1 = ("D1", "DIO1 configuration")
    D2 = ("D2", "DIO2 configuration")
    D3 = ("D3", "DIO3 configuration")
    D4 = ("D4", "DIO4 configuration")
    D5 = ("D5", "DIO5 configuration")
    D6 = ("D6", "RTS configuration")
    D7 = ("D7", "CTS configuration")
    D8 = ("D8", "DIO8 configuration")
    D9 = ("D9", "DIO9 configuration")
    EE = ("EE", "Encryption enable")
    EO = ("EO", "Encryption options")
    FN = ("FN", "Find neighbors")
    FR = ("FR", "Software reset")
    FS = ("FS", "File system")
    GW = ("GW", "Gateway address")
    GT = ("GT", "Guard times")
    HV = ("HV", "Hardware version")
    HP = ("HP", "Preamble ID")
    IC = ("IC", "Digital change detection")
    ID = ("ID", "Network PAN ID/Network ID/SSID")
    IM = ("IM", "IMEI")
    IR = ("IR", "I/O sample rate")
    IS = ("IS", "Force sample")
    JN = ("JN", "Join notification")
    JV = ("JV", "Join verification")
    KY = ("KY", "Link/Encryption key")
    MA = ("MA", "IP addressing mode")
    MK = ("MK", "IP address mask")
    MP = ("MP", "16-bit parent address")
    MY = ("MY", "16-bit address/IP address")
    M0 = ("M0", "PWM0 configuration")
    M1 = ("M1", "PWM1 configuration")
    NB = ("NB", "Parity")
    NH = ("NH", "Maximum hops")
    NI = ("NI", "Node identifier")
    ND = ("ND", "Node discover")
    NJ = ("NJ", "Join time")
    NK = ("NK", "Trust Center network key")
    NO = ("NO", "Node discover options")
    NR = ("NR", "Network reset")
    NS = ("NS", "DNS address")
    NP = ("NP", "Maximum number of transmission bytes")
    NT = ("NT", "Node discover back-off")
    N_QUESTION = ("N?", "Network discovery timeout")
    OP = ("OP", "Operating extended PAN ID")
    OS = ("OS", "Operating sleep time")
    OW = ("OW", "Operating wake time")
    PK = ("PK", "Passphrase")
    PL = ("PL", "TX power level")
    PP = ("PP", "Output power")
    PS = ("PS", "MicroPython auto start")
    P0 = ("P0", "DIO10 configuration")
    P1 = ("P1", "DIO11 configuration")
    P2 = ("P2", "DIO12 configuration")
    P3 = ("P3", "UART DOUT configuration")
    P4 = ("P4", "UART DIN configuration")
    P5 = ("P5", "DIO15 configuration")
    P6 = ("P6", "DIO16 configuration")
    P7 = ("P7", "DIO17 configuration")
    P8 = ("P8", "DIO18 configuration")
    P9 = ("P9", "DIO19 configuration")
    RE = ("RE", "Restore defaults")
    RR = ("RR", "XBee retries")
    R_QUESTION = ("R?", "Region lock")
    SB = ("SB", "Stop bits")
    SC = ("SC", "Scan channels")
    SD = ("SD", "Scan duration")
    SH = ("SH", "Serial number high")
    SI = ("SI", "Socket info")
    SL = ("SL", "Serial number low")
    SM = ("SM", "Sleep mode")
    SN = ("SN", "Sleep count")
    SO = ("SO", "Sleep options")
    SP = ("SP", "Sleep time")
    SS = ("SS", "Sleep status")
    ST = ("ST", "Wake time")
    TP = ("TP", "Temperature")
    VH = ("VH", "Bootloader version")
    VR = ("VR", "Firmware version")
    WR = ("WR", "Write")
    DOLLAR_S = ("$S", "SRP salt")
    DOLLAR_V = ("$V", "SRP salt verifier")
    DOLLAR_W = ("$W", "SRP salt verifier")
    DOLLAR_X = ("$X", "SRP salt verifier")
    DOLLAR_Y = ("$Y", "SRP salt verifier")
    PERCENT_C = ("%C", "Hardware/software compatibility")
    PERCENT_P = ("%P", "Invoke bootloader")
    PERCENT_U = ("%U", "Recover")
    PERCENT_V = ("%V", "Supply voltage")

    def __init__(self, command, description):
        self.__cmd = command
        self.__desc = description

    @property
    def command(self):
        """
        AT command alias

        Returns:
             String: The AT command alias.
        """
        return self.__cmd

    @property
    def description(self):
        """
        AT command description.

        Returns:
            String: The AT command description.
        """
        return self.__desc


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

    @property
    def code(self):
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
            :class:`.SpecialByte`: SpecialByte with the given value.
        """
        for special_byte in cls:
            if special_byte.code == value:
                return special_byte
        return None

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
            Boolean: `True` if value is a special byte, `False` in other case.
        """
        return value in [i.value for i in SpecialByte]


SpecialByte.__doc__ += utils.doc_enum(SpecialByte)


class ATCommand:
    """
    This class represents an AT command used to read or set different
    properties of the XBee device.

    AT commands can be sent directly to the connected device or to remote
    devices and may have parameters.

    After executing an AT Command, an AT Response is received from the device.
    """

    def __init__(self, command, parameter=None):
        """
        Class constructor. Instantiates a new :class:`.ATCommand` object with
        the provided parameters.

        Args:
            command (String): AT Command, must have length 2.
            parameter (String or Bytearray, optional): The AT parameter value.
                Defaults to `None`. Optional.

        Raises:
            ValueError: if command length is not 2.
        """
        if len(command) != 2:
            raise ValueError("Command length must be 2.")

        self.__cmd = command
        if isinstance(parameter, str):
            self.__param = bytearray(parameter, encoding='utf8', errors='ignore')
        else:
            self.__param = parameter

    def __str__(self):
        """
        Returns a string representation of this ATCommand.

        Returns:
            String: representation of this ATCommand.
        """
        return "Command: %s - Parameter: %s" \
               % (self.__cmd, utils.hex_to_string(self.__param) if self.__param else "-")

    def __len__(self):
        """
        Returns the length of this ATCommand.

        Returns:
            Integer: length of command + length of parameter.
        """
        if self.__param:
            return len(self.__cmd) + len(self.__param)

        return len(self.__cmd)

    @property
    def command(self):
        """
        Returns the AT command.

        Returns:
            String: the AT command.
        """
        return self.__cmd

    @property
    def parameter(self):
        """
        Returns the AT command parameter.

        Returns:
            Bytearray: the AT command parameter.
                `None` if there is no parameter.
        """
        return self.__param

    def get_parameter_string(self):
        """
        Returns this ATCommand parameter as a String.

        Returns:
            String: this ATCommand parameter. `None` if there is no parameter.
        """
        if not self.__param:
            return None
        return str(self.__param, encoding='utf8', errors='ignore')

    @parameter.setter
    def parameter(self, parameter):
        """
        Sets the AT command parameter.

        Args:
            parameter (Bytearray or String): the parameter to be set.
        """
        if isinstance(parameter, str):
            self.__param = bytearray(parameter, encoding='utf8', errors='ignore')
        else:
            self.__param = parameter


class ATCommandResponse:
    """
    This class represents the response of an AT Command sent by the connected
    XBee device or by a remote device after executing an AT Command.
    """

    def __init__(self, command, response=None, status=ATCommandStatus.OK):
        """
        Class constructor.

        Args:
            command (:class:`.ATCommand`): The AT command that generated the
                response.
            response (bytearray, optional): The command response.
                Default to `None`.
            status (:class:`.ATCommandStatus`, optional): The AT command
                status. Default to ATCommandStatus.OK
        """
        self.__at_cmd = command
        self.__resp = response
        self.__comm_status = status

    @property
    def command(self):
        """
        Returns the AT command.

        Returns:
            :class:`.ATCommand`: the AT command.
        """
        return self.__at_cmd

    @property
    def response(self):
        """
        Returns the AT command response.

        Returns:
            Bytearray: the AT command response.
        """
        return self.__resp

    @property
    def status(self):
        """
        Returns the AT command response status.

        Returns:
            :class:`.ATCommandStatus`: The AT command response status.
        """
        return self.__comm_status
