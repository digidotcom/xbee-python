# Copyright 2017-2021, Digi International Inc.
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

from digi.xbee.models.protocol import XBeeProtocol
from digi.xbee.util import utils


@unique
class OperatingMode(Enum):
    """
    This class represents all operating modes available.

    | Inherited properties:
    |     **name** (String): the name (id) of this OperatingMode.
    |     **value** (String): the value of this OperatingMode.
    """

    AT_MODE = (0, "AT mode")
    API_MODE = (1, "API mode")
    ESCAPED_API_MODE = (2, "API mode with escaped characters")
    MICROPYTHON_MODE = (4, "MicroPython REPL")
    BYPASS_MODE = (5, "Bypass mode")
    UNKNOWN = (99, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the OperatingMode element.

        Returns:
            String: the code of the OperatingMode element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the OperatingMode element.

        Returns:
            String: the description of the OperatingMode element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the OperatingMode for the given code.

        Args:
            code (Integer): the code corresponding to the operating mode to get.

        Returns:
            :class:`.OperatingMode`: the OperatingMode with the given code.
        """
        for mode in cls:
            if mode.code == code:
                return mode
        return OperatingMode.UNKNOWN


OperatingMode.__doc__ += utils.doc_enum(OperatingMode)


@unique
class APIOutputMode(Enum):
    """
    Enumerates the different API output modes. The API output mode establishes
    the way data will be output through the serial interface of an XBee device.

    | Inherited properties:
    |     **name** (String): the name (id) of this OperatingMode.
    |     **value** (String): the value of this OperatingMode.
    """

    NATIVE = (0x00, "Native")
    EXPLICIT = (0x01, "Explicit")
    EXPLICIT_ZDO_PASSTHRU = (0x03, "Explicit with ZDO Passthru")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the APIOutputMode element.

        Returns:
            String: the code of the APIOutputMode element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the APIOutputMode element.

        Returns:
            String: the description of the APIOutputMode element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the APIOutputMode for the given code.

        Args:
            code (Integer): the code corresponding to the API output mode to get.

        Returns:
            :class:`.APIOutputMode`: the APIOutputMode with the given code,
                `None` if not found.
        """
        for mode in cls:
            if mode.code == code:
                return mode
        return None


APIOutputMode.__doc__ += utils.doc_enum(APIOutputMode)


@unique
class APIOutputModeBit(Enum):
    """
    Enumerates the different API output mode bit options. The API output mode
    establishes the way data will be output through the serial interface of an XBee.

    | Inherited properties:
    |     **name** (String): the name (id) of this APIOutputModeBit.
    |     **value** (String): the value of this APIOutputModeBit.
    """

    EXPLICIT = (0x01, "Output in Native/Explicit API format")
    SUPPORTED_ZDO_PASSTHRU = (0x02, "Zigbee: Supported ZDO request "
                                    "pass-through\n802.15.4/DigiMesh: Legacy "
                                    "API Indicator")
    UNSUPPORTED_ZDO_PASSTHRU = (0x04, "Unsupported ZDO request pass-through."
                                      " Only Zigbee")
    BINDING_PASSTHRU = (0x08, "Binding request pass-through. Only Zigbee")
    ECHO_RCV_SUPPORTED_ZDO = (0x10, "Echo received supported ZDO requests out "
                                    "the serial port. Only Zigbee")
    SUPPRESS_ALL_ZDO_MSG = (0x20, "Suppress all ZDO messages from being sent "
                                  "out the serial port and disable "
                                  "pass-through. Only Zigbee")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the APIOutputModeBit element.

        Returns:
            Integer: the code of the APIOutputModeBit element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the APIOutputModeBit element.

        Returns:
            String: the description of the APIOutputModeBit element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the APIOutputModeBit for the given code.

        Args:
            code (Integer): the code corresponding to the API output mode to get.

        Returns:
            :class:`.OperatingMode`: the APIOutputModeBit with the given code,
                `None` if not found.
        """
        for item in cls:
            if code == item.code:
                return item
        return None

    @classmethod
    def calculate_api_output_mode_value(cls, protocol, options):
        """
        Calculates the total value of a combination of several option bits for
        the given protocol.

        Args:
            protocol (:class:`digi.xbee.models.protocol.XBeeProtocol`): The
                `XBeeProtocol` to calculate the value of all the given API
                output options.
            options: Collection of option bits to get the final value.

        Returns:
            Integer: The value to be configured in the module depending on the
                given collection of option bits and the protocol.
        """
        if not options:
            return 0

        if protocol == XBeeProtocol.ZIGBEE:
            return sum(op.code for op in options)
        if protocol in (XBeeProtocol.DIGI_MESH, XBeeProtocol.DIGI_POINT,
                        XBeeProtocol.XLR, XBeeProtocol.XLR_DM,
                        XBeeProtocol.RAW_802_15_4):
            return sum(op.code for op in options
                       if op < cls.UNSUPPORTED_ZDO_PASSTHRU)

        return 0


APIOutputModeBit.__doc__ += utils.doc_enum(APIOutputModeBit)


@unique
class IPAddressingMode(Enum):
    """
    Enumerates the different IP addressing modes.
    """

    DHCP = (0x00, "DHCP")
    STATIC = (0x01, "Static")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the IPAddressingMode element.

        Returns:
            String: the code of the IPAddressingMode element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the IPAddressingMode element.

        Returns:
            String: the description of the IPAddressingMode element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the IPAddressingMode for the given code.

        Args:
            code (Integer): the code corresponding to the IP addressing mode to get.

        Returns:
            :class:`.IPAddressingMode`: the IPAddressingMode with the given
                code, `None` if not found.
        """
        for mode in cls:
            if mode.code == code:
                return mode
        return None


IPAddressingMode.__doc__ += utils.doc_enum(IPAddressingMode)


@unique
class NeighborDiscoveryMode(Enum):
    """
    Enumerates the different neighbor discovery modes. This mode establishes
    the way the network discovery process is performed.

    | Inherited properties:
    |     **name** (String): the name (id) of this OperatingMode.
    |     **value** (String): the value of this OperatingMode.
    """

    CASCADE = (0, "Cascade")
    """
    The discovery of a node neighbors is requested once the previous request
    finishes.
    This means that just one discovery process is running at the same time.

    This mode is recommended for large networks, it might be a slower method
    but it generates less traffic than 'Flood'.
    """

    FLOOD = (1, "Flood")
    """
    The discovery of a node neighbors is requested when the node is found in
    the network. This means that several discovery processes might be running
    at the same time.
    """

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the NeighborDiscoveryMode element.

        Returns:
            String: the code of the NeighborDiscoveryMode element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the NeighborDiscoveryMode element.

        Returns:
            String: the description of the NeighborDiscoveryMode element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the NeighborDiscoveryMode for the given code.

        Args:
            code (Integer): the code corresponding to the mode to get.

        Returns:
            :class:`.NeighborDiscoveryMode`: the NeighborDiscoveryMode with
                the given code. `None` if not found.
        """
        for mode in cls:
            if mode.code == code:
                return mode
        return None


NeighborDiscoveryMode.__doc__ += utils.doc_enum(NeighborDiscoveryMode)
