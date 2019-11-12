# Copyright 2017, 2018, Digi International Inc.
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
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.util import utils


@unique
class XBeeProtocol(Enum):
    """
    Enumerates the available XBee protocols. The XBee protocol is determined
    by the combination of hardware and firmware of an XBee device.

    | Inherited properties:
    |     **name** (String): the name (id) of this XBeeProtocol.
    |     **value** (String): the value of this XBeeProtocol.
    """

    ZIGBEE = (0, "ZigBee")
    RAW_802_15_4 = (1, "802.15.4")
    XBEE_WIFI = (2, "Wi-Fi")
    DIGI_MESH = (3, "DigiMesh")
    XCITE = (4, "XCite")
    XTEND = (5, "XTend (Legacy)")
    XTEND_DM = (6, "XTend (DigiMesh)")
    SMART_ENERGY = (7, "Smart Energy")
    DIGI_POINT = (8, "Point-to-multipoint")
    ZNET = (9, "ZNet 2.5")
    XC = (10, "XSC")
    XLR = (11, "XLR")
    XLR_DM = (12, "XLR")
    SX = (13, "XBee SX")
    XLR_MODULE = (14, "XLR Module")
    CELLULAR = (15, "Cellular")
    CELLULAR_NBIOT = (16, "Cellular NB-IoT")
    UNKNOWN = (99, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the XBeeProtocol element.

        Returns:
            Integer: the code of the XBeeProtocol element.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the XBeeProtocol element.

        Returns:
            String: the description of the XBeeProtocol element.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the XBeeProtocol for the given code.

        Args:
            code (Integer): code of the XBeeProtocol to get.

        Returns:
            XBeeProtocol: XBeeProtocol for the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return XBeeProtocol.UNKNOWN

    @staticmethod
    def determine_protocol(hardware_version, firmware_version):
        """
        Determines the XBee protocol based on the given hardware and firmware
        versions.

        Args:
            hardware_version (Integer): hardware version of the protocol to determine.
            firmware_version (String): firmware version of the protocol to determine.

        Returns:
            The XBee protocol corresponding to the given hardware and firmware versions.
        """
        firmware_version = "".join(["%02X" % i for i in firmware_version])

        if hardware_version is None or firmware_version is None or hardware_version < 0x09 or \
                HardwareVersion.get(hardware_version) is None:
            return XBeeProtocol.UNKNOWN

        elif hardware_version in [HardwareVersion.XC09_009.code,
                                  HardwareVersion.XC09_038.code]:
            return XBeeProtocol.XCITE

        elif hardware_version in [HardwareVersion.XT09_XXX.code,
                                  HardwareVersion.XT09B_XXX.code]:
            if ((len(firmware_version) == 4 and firmware_version.startswith("8")) or
                    (len(firmware_version) == 5 and firmware_version[1] == '8')):
                return XBeeProtocol.XTEND_DM
            return XBeeProtocol.XTEND

        elif hardware_version in [HardwareVersion.XB24_AXX_XX.code,
                                  HardwareVersion.XBP24_AXX_XX.code]:
            if len(firmware_version) == 4 and firmware_version.startswith("8"):
                    return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.RAW_802_15_4

        elif hardware_version in [HardwareVersion.XB24_BXIX_XXX.code,
                                  HardwareVersion.XBP24_BXIX_XXX.code]:
            if ((len(firmware_version) == 4 and firmware_version.startswith("1") and firmware_version.endswith("20"))
                    or (len(firmware_version) == 4 and firmware_version.startswith("2"))):
                return XBeeProtocol.ZIGBEE
            elif len(firmware_version) == 4 and firmware_version.startswith("3"):
                return XBeeProtocol.SMART_ENERGY
            return XBeeProtocol.ZNET

        elif hardware_version == HardwareVersion.XBP09_DXIX_XXX.code:
            if ((len(firmware_version) == 4 and firmware_version.startswith("8") or
                (len(firmware_version) == 4 and firmware_version[1] == '8')) or
                    (len(firmware_version) == 5 and firmware_version[1] == '8')):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.DIGI_POINT

        elif hardware_version == HardwareVersion.XBP09_XCXX_XXX.code:
            return XBeeProtocol.XC

        elif hardware_version == HardwareVersion.XBP08_DXXX_XXX.code:
            return XBeeProtocol.DIGI_POINT

        elif hardware_version == HardwareVersion.XBP24B.code:
            if len(firmware_version) == 4 and firmware_version.startswith("3"):
                return XBeeProtocol.SMART_ENERGY
            return XBeeProtocol.ZIGBEE

        elif hardware_version in [HardwareVersion.XB24_WF.code,
                                  HardwareVersion.WIFI_ATHEROS.code,
                                  HardwareVersion.SMT_WIFI_ATHEROS.code]:
            return XBeeProtocol.XBEE_WIFI

        elif hardware_version in [HardwareVersion.XBP24C.code,
                                  HardwareVersion.XB24C.code]:
            if (len(firmware_version) == 4 and (firmware_version.startswith("5")) or
                    (firmware_version.startswith("6"))):
                return XBeeProtocol.SMART_ENERGY
            elif firmware_version.startswith("2"):
                return XBeeProtocol.RAW_802_15_4
            elif firmware_version.startswith("9"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.ZIGBEE

        elif hardware_version in [HardwareVersion.XSC_GEN3.code,
                                  HardwareVersion.SRD_868_GEN3.code]:
            if len(firmware_version) == 4 and firmware_version.startswith("8"):
                return XBeeProtocol.DIGI_MESH
            elif len(firmware_version) == 4 and firmware_version.startswith("1"):
                return XBeeProtocol.DIGI_POINT
            return XBeeProtocol.XC

        elif hardware_version == HardwareVersion.XBEE_CELL_TH.code:
            return XBeeProtocol.UNKNOWN

        elif hardware_version == HardwareVersion.XLR_MODULE.code:
            # This is for the old version of the XLR we have (K60), and it is
            # reporting the firmware of the module (8001), this will change in
            # future (after K64 integration) reporting the hardware and firmware
            # version of the baseboard (see the case HardwareVersion.XLR_BASEBOARD).
            # TODO maybe this should be removed in future, since this case will never be released.
            if firmware_version.startswith("1"):
                return XBeeProtocol.XLR
            else:
                return XBeeProtocol.XLR_MODULE

        elif hardware_version == HardwareVersion.XLR_BASEBOARD.code:
            # XLR devices with K64 will report the baseboard hardware version,
            # and also firmware version (the one we have here is 1002, but this value
            # is not being reported since is an old K60 version, the module fw version
            # is reported instead).

            # TODO [XLR_DM] The next version of the XLR will add DigiMesh support should be added.
            # Probably this XLR_DM and XLR will depend on the firmware version.
            if firmware_version.startswith("1"):
                return XBeeProtocol.XLR
            else:
                return XBeeProtocol.XLR_MODULE

        elif hardware_version == HardwareVersion.XB900HP_NZ.code:
            return XBeeProtocol.DIGI_POINT

        elif hardware_version in [HardwareVersion.XBP24C_TH_DIP.code,
                                  HardwareVersion.XB24C_TH_DIP.code,
                                  HardwareVersion.XBP24C_S2C_SMT.code]:
            if (len(firmware_version) == 4 and
                    (firmware_version.startswith("5") or firmware_version.startswith("6"))):
                return XBeeProtocol.SMART_ENERGY
            elif firmware_version.startswith("2"):
                return XBeeProtocol.RAW_802_15_4
            elif firmware_version.startswith("9"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.ZIGBEE

        elif hardware_version in [HardwareVersion.SX_PRO.code,
                                  HardwareVersion.SX.code,
                                  HardwareVersion.XTR.code]:
            if firmware_version.startswith("2"):
                return XBeeProtocol.XTEND
            elif firmware_version.startswith("8"):
                return XBeeProtocol.XTEND_DM
            return XBeeProtocol.DIGI_MESH

        elif hardware_version in [HardwareVersion.S2D_SMT_PRO.code,
                                  HardwareVersion.S2D_SMT_REG.code,
                                  HardwareVersion.S2D_TH_PRO.code,
                                  HardwareVersion.S2D_TH_REG.code]:
            return XBeeProtocol.ZIGBEE

        elif hardware_version in [HardwareVersion.CELLULAR_CAT1_LTE_VERIZON.code,
                                  HardwareVersion.CELLULAR_3G.code,
                                  HardwareVersion.CELLULAR_LTE_ATT.code,
                                  HardwareVersion.CELLULAR_LTE_VERIZON.code,
                                  HardwareVersion.CELLULAR_3_CAT1_LTE_ATT.code,
                                  HardwareVersion.CELLULAR_3_LTE_M_VERIZON.code,
                                  HardwareVersion.CELLULAR_3_LTE_M_ATT.code]:
            return XBeeProtocol.CELLULAR

        elif hardware_version == HardwareVersion.CELLULAR_NBIOT_EUROPE.code:
            return XBeeProtocol.CELLULAR_NBIOT

        elif hardware_version in [HardwareVersion.XBEE3.code,
                                  HardwareVersion.XBEE3_SMT.code,
                                  HardwareVersion.XBEE3_TH.code]:
            if firmware_version.startswith("2"):
                return XBeeProtocol.RAW_802_15_4
            elif firmware_version.startswith("3"):
                return XBeeProtocol.DIGI_MESH
            else:
                return XBeeProtocol.ZIGBEE

        elif hardware_version == HardwareVersion.XB8X.code:
            return XBeeProtocol.DIGI_MESH

        return XBeeProtocol.ZIGBEE

    code = property(__get_code)
    """Integer. XBee protocol code."""

    description = property(__get_description)
    """String. XBee protocol description."""


XBeeProtocol.lookupTable = {x.code: x for x in XBeeProtocol}
XBeeProtocol.__doc__ += utils.doc_enum(XBeeProtocol)


@unique
class IPProtocol(Enum):
    """
    Enumerates the available network protocols.

    | Inherited properties:
    |     **name** (String): the name (id) of this IPProtocol.
    |     **value** (String): the value of this IPProtocol.
    """

    UDP = (0, "UDP")
    TCP = (1, "TCP")
    TCP_SSL = (4, "TLS")

    def __init__(self, code, description):
        self.__code = code
        self.__description = description

    def __get_code(self):
        """
        Returns the code of the IP protocol.

        Returns:
            Integer: code of the IP protocol.
        """
        return self.__code

    def __get_description(self):
        """
        Returns the description of the IP protocol.

        Returns:
            String: description of the IP protocol.
        """
        return self.__description

    @classmethod
    def get(cls, code):
        """
        Returns the IPProtocol for the given code.

        Args:
            code (Integer): code associated to the IP protocol.

        Returns:
            :class:`.IPProtocol`: IP protocol for the given code or ``None`` if there
                is not any ``IPProtocol`` with the given code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    @classmethod
    def get_by_description(cls, description):
        """
        Returns the IP Protocol for the given description.

        Args:
            description (String): the description of the IP Protocol to get.

        Returns:
            :class:`.IPProtocol`: IP protocol for the given description or ``None`` if there
                is not any ``IPProtocol`` with the given description.
        """
        for x in IPProtocol:
            if x.description.lower() == description.lower():
                return x
        return None

    code = property(__get_code)
    """Integer: IP protocol code."""

    description = property(__get_description)
    """String: IP protocol description."""


IPProtocol.lookupTable = {x.code: x for x in IPProtocol}
IPProtocol.__doc__ += utils.doc_enum(IPProtocol)


@unique
class Role(Enum):
    """
    Enumerates the available roles for an XBee.

    | Inherited properties:
    |     **name** (String): the name (id) of this Role.
    |     **value** (String): the value of this Role.
    """

    COORDINATOR = (0, "Coordinator")
    ROUTER = (1, "Router")
    END_DEVICE = (2, "End device")
    UNKNOWN = (3, "Unknown")

    def __init__(self, identifier, description):
        self.__id = identifier
        self.__desc = description

    @property
    def id(self):
        """
        Gets the identifier of the role.

        Returns:
            Integer: the role identifier.
        """
        return self.__id

    @property
    def description(self):
        """
        Gets the description of the role.

        Returns:
            String: the role description.
        """
        return self.__desc

    @classmethod
    def get(cls, identifier):
        """
        Returns the Role for the given identifier.

        Args:
            identifier (Integer): the id value corresponding to the role to get.

        Returns:
            :class:`.Role`: the Role with the given identifier. ``None`` if it does not exist.
        """
        for item in cls:
            if identifier == item.id:
                return item

        return None


Role.__doc__ += utils.doc_enum(Role)
