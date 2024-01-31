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

from enum import Enum, unique, auto
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

    ZIGBEE = (0, "Zigbee")
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
    BLE = (17, "BLE")
    UNKNOWN = (99, "Unknown")

    def __init__(self, code, description):
        self.__code = code
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the XBeeProtocol element.

        Returns:
            Integer: the code of the XBeeProtocol element.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the XBeeProtocol element.

        Returns:
            String: the description of the XBeeProtocol element.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the XBeeProtocol for the given code.

        Args:
            code (Integer): code of the XBeeProtocol to get.

        Returns:
            :class: `.XBeeProtocol`: XBeeProtocol for the given code.
        """
        for protocol in cls:
            if protocol.code == code:
                return protocol
        return XBeeProtocol.UNKNOWN

    @staticmethod
    def is_ip_protocol(protocol):
        """
        Checks if the provided protocol is an IP protocol.

        Args:
            protocol (:class: `.XBeeProtocol`): The protocol to check.

        Returns:
            Boolean: `True` if it is an IP protocol, `False` otherwise.
        """
        return protocol in (XBeeProtocol.CELLULAR, XBeeProtocol.CELLULAR_NBIOT,
                            XBeeProtocol.XBEE_WIFI)

    @staticmethod
    def determine_protocol(hw_version, fw_version, br_value=None):
        """
        Determines the XBee protocol based on the given hardware and firmware
        versions.

        Args:
            hw_version (Integer): hardware version of the protocol to determine.
            fw_version (Bytearray): firmware version of the protocol to determine.
            br_value (Integer, optional, default=`None`): Value of BR setting
                for XBee SX 900/868.

        Returns:
            :class: `.XBeeProtocol`: The XBee protocol corresponding to the
                given hardware and firmware versions.
        """
        fw_version = "".join(["%02X" % i for i in fw_version])

        if (hw_version is None or fw_version is None or hw_version < 0x09
                or HardwareVersion.get(hw_version) is None):
            return XBeeProtocol.UNKNOWN

        if hw_version in (HardwareVersion.XC09_009.code,
                          HardwareVersion.XC09_038.code):
            return XBeeProtocol.XCITE

        if hw_version in (HardwareVersion.XT09_XXX.code,
                          HardwareVersion.XT09B_XXX.code):
            if ((len(fw_version) == 4 and fw_version.startswith("8"))
                    or (len(fw_version) == 5 and fw_version[1] == '8')):
                return XBeeProtocol.XTEND_DM
            return XBeeProtocol.XTEND

        if hw_version in (HardwareVersion.XB24_AXX_XX.code,
                          HardwareVersion.XBP24_AXX_XX.code):
            if len(fw_version) == 4 and fw_version.startswith("8"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.RAW_802_15_4

        if hw_version in (HardwareVersion.XB24_BXIX_XXX.code,
                          HardwareVersion.XBP24_BXIX_XXX.code):
            if ((len(fw_version) == 4 and fw_version.startswith("1") and fw_version.endswith("20"))
                    or (len(fw_version) == 4 and fw_version.startswith("2"))):
                return XBeeProtocol.ZIGBEE
            if len(fw_version) == 4 and fw_version.startswith("3"):
                return XBeeProtocol.SMART_ENERGY
            return XBeeProtocol.ZNET

        if hw_version == HardwareVersion.XBP09_DXIX_XXX.code:
            if ((len(fw_version) == 4 and fw_version.startswith("8") or
                 (len(fw_version) == 4 and fw_version[1] == '8')) or
                    (len(fw_version) == 5 and fw_version[1] == '8')):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.DIGI_POINT

        if hw_version == HardwareVersion.XBP09_XCXX_XXX.code:
            return XBeeProtocol.XC

        if hw_version == HardwareVersion.XBP08_DXXX_XXX.code:
            return XBeeProtocol.DIGI_POINT

        if hw_version == HardwareVersion.XBP24B.code:
            if len(fw_version) == 4 and fw_version.startswith("3"):
                return XBeeProtocol.SMART_ENERGY
            return XBeeProtocol.ZIGBEE

        if hw_version in (HardwareVersion.XB24_WF.code,
                          HardwareVersion.WIFI_ATHEROS.code,
                          HardwareVersion.SMT_WIFI_ATHEROS.code):
            return XBeeProtocol.XBEE_WIFI

        if hw_version in (HardwareVersion.XBP24C.code, HardwareVersion.XB24C.code):
            if (len(fw_version) == 4 and (fw_version.startswith("5"))
                    or (fw_version.startswith("6"))):
                return XBeeProtocol.SMART_ENERGY
            if fw_version.startswith("2"):
                return XBeeProtocol.RAW_802_15_4
            if fw_version.startswith("9"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.ZIGBEE

        if hw_version in (HardwareVersion.XSC_GEN3.code,
                          HardwareVersion.SRD_868_GEN3.code):
            if len(fw_version) == 4 and fw_version.startswith("8"):
                return XBeeProtocol.DIGI_MESH
            if len(fw_version) == 4 and fw_version.startswith("1"):
                return XBeeProtocol.DIGI_POINT
            return XBeeProtocol.XC

        if hw_version == HardwareVersion.XBEE_CELL_TH.code:
            return XBeeProtocol.UNKNOWN

        if hw_version == HardwareVersion.XLR_MODULE.code:
            # This is for the old version of the XLR we have (K60), and it is
            # reporting the firmware of the module (8001), this will change in
            # future (after K64 integration) reporting the hardware and firmware
            # version of the baseboard (see the case HardwareVersion.XLR_BASEBOARD).
            # TODO maybe this should be removed in future, since this case will never be released.
            if fw_version.startswith("1"):
                return XBeeProtocol.XLR
            return XBeeProtocol.XLR_MODULE

        if hw_version == HardwareVersion.XLR_BASEBOARD.code:
            # XLR devices with K64 will report the baseboard hardware version,
            # and also firmware version (the one we have here is 1002, but this value
            # is not being reported since is an old K60 version, the module fw version
            # is reported instead).

            # TODO [XLR_DM] The next version of the XLR will add DigiMesh support should be added.
            # Probably this XLR_DM and XLR will depend on the firmware version.
            if fw_version.startswith("1"):
                return XBeeProtocol.XLR
            return XBeeProtocol.XLR_MODULE

        if hw_version == HardwareVersion.XB900HP_NZ.code:
            return XBeeProtocol.DIGI_POINT

        if hw_version in (HardwareVersion.XBP24C_TH_DIP.code,
                          HardwareVersion.XB24C_TH_DIP.code,
                          HardwareVersion.XBP24C_S2C_SMT.code):
            if (len(fw_version) == 4
                    and (fw_version.startswith("5") or fw_version.startswith("6"))):
                return XBeeProtocol.SMART_ENERGY
            if fw_version.startswith("2"):
                return XBeeProtocol.RAW_802_15_4
            if fw_version.startswith("9"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.ZIGBEE

        if hw_version in (HardwareVersion.SX_PRO.code, HardwareVersion.SX.code,
                          HardwareVersion.XTR.code):
            if fw_version.startswith("2"):
                return XBeeProtocol.XTEND
            if fw_version.startswith("8"):
                return XBeeProtocol.XTEND_DM

            if hw_version in (HardwareVersion.SX.code, HardwareVersion.SX_PRO.code):
                if br_value == 0:
                    return XBeeProtocol.DIGI_POINT

            return XBeeProtocol.DIGI_MESH

        if hw_version in (HardwareVersion.S2D_SMT_PRO.code,
                          HardwareVersion.S2D_SMT_REG.code,
                          HardwareVersion.S2D_TH_PRO.code,
                          HardwareVersion.S2D_TH_REG.code):
            return XBeeProtocol.ZIGBEE

        if hw_version in (HardwareVersion.CELLULAR_CAT1_LTE_VERIZON.code,
                          HardwareVersion.CELLULAR_3G.code,
                          HardwareVersion.CELLULAR_LTE_ATT.code,
                          HardwareVersion.CELLULAR_LTE_VERIZON.code,
                          HardwareVersion.CELLULAR_3_CAT1_LTE_ATT.code,
                          HardwareVersion.CELLULAR_3_LTE_M_VERIZON.code,
                          HardwareVersion.CELLULAR_3_LTE_M_ATT.code,
                          HardwareVersion.CELLULAR_3_CAT1_LTE_VERIZON.code,
                          HardwareVersion.CELLULAR_3_LTE_M_TELIT.code,
                          HardwareVersion.CELLULAR_3_GLOBAL_LTE_CAT1.code,
                          HardwareVersion.CELLULAR_3_NA_LTE_CAT1.code,
                          HardwareVersion.CELLULAR_3_LTE_M_LOW_POWER.code,
                          HardwareVersion.CELLULAR_3_GLOBAL_CAT4.code,
                          HardwareVersion.CELLULAR_3_NA_CAT4.code):
            return XBeeProtocol.CELLULAR

        if hw_version == HardwareVersion.CELLULAR_NBIOT_EUROPE.code:
            return XBeeProtocol.CELLULAR_NBIOT

        if hw_version in (HardwareVersion.XBEE3.code,
                          HardwareVersion.XBEE3_SMT.code,
                          HardwareVersion.XBEE3_TH.code,
                          HardwareVersion.XBEE3_RR.code,
                          HardwareVersion.XBEE3_RR_TH.code):
            if fw_version.startswith("2"):
                return XBeeProtocol.RAW_802_15_4
            if fw_version.startswith("3"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.ZIGBEE

        if hw_version == HardwareVersion.XB8X.code:
            return (XBeeProtocol.DIGI_MESH
                    if br_value != 0 else XBeeProtocol.DIGI_POINT)

        if hw_version in (HardwareVersion.XBEE3_DM_LR.code,
                          HardwareVersion.XBEE3_DM_LR_868.code,
                          HardwareVersion.XBEE_XR_900_TH.code,
                          HardwareVersion.XBEE_XR_868_TH.code):
            return XBeeProtocol.DIGI_MESH

        if hw_version == HardwareVersion.S2C_P5.code:
            if fw_version.startswith("C"):
                return XBeeProtocol.RAW_802_15_4
            if fw_version.startswith("B"):
                return XBeeProtocol.DIGI_MESH
            return XBeeProtocol.ZIGBEE

        if hw_version in (HardwareVersion.XBEE_BLU.code,
                          HardwareVersion.XBEE_BLU_TH.code):
            return XBeeProtocol.BLE

        return XBeeProtocol.ZIGBEE


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
        self.__desc = description

    @property
    def code(self):
        """
        Returns the code of the IP protocol.

        Returns:
            Integer: code of the IP protocol.
        """
        return self.__code

    @property
    def description(self):
        """
        Returns the description of the IP protocol.

        Returns:
            String: description of the IP protocol.
        """
        return self.__desc

    @classmethod
    def get(cls, code):
        """
        Returns the IPProtocol for the given code.

        Args:
            code (Integer): code associated to the IP protocol.

        Returns:
            :class:`.IPProtocol`: IP protocol for the given code or `None` if
                there is not any `IPProtocol` with the given code.
        """
        for protocol in cls:
            if protocol.code == code:
                return protocol
        return None

    @classmethod
    def get_by_description(cls, description):
        """
        Returns the IP Protocol for the given description.

        Args:
            description (String): the description of the IP Protocol to get.

        Returns:
            :class:`.IPProtocol`: IP protocol for the given description or
                `None` if there is not any `IPProtocol` with the given
                description.
        """
        for prot in IPProtocol:
            if prot.description.lower() == description.lower():
                return prot
        return None


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
            identifier (Integer): the id value of the role to get.

        Returns:
            :class:`.Role`: the Role with the given identifier. `None` if it
                does not exist.
        """
        for item in cls:
            if identifier == item.id:
                return item

        return None


Role.__doc__ += utils.doc_enum(Role)


@unique
class Region(Enum):
    """
    Enumerates the available regions for an XBee.

    | Inherited properties:
    |     **name** (String): the name (id) of this Region.
    |     **value** (String): the value of this Region.
    """

    ALL = (0, "Any")
    USA = (1, "USA")
    AUSTRALIA = (2, "Australia")
    BRAZIL = (3, "Brazil")
    MEXICO = (4, "Mexico")
    PERU = (5, "Peru")
    NEW_ZEALAND = (6, "New Zealand")
    SINGAPORE = (7, "Singapore")
    CHILE = (8, "Chile")
    FRANCE = (9, "France")
    EUROPE = (10, "Europe")
    SKIP = (99, "Skip")
    UNKNOWN = (999, "Unknown")
    ALL2 = (65535, "Any")

    def __init__(self, identifier, description):
        self.__id = identifier
        self.__desc = description

    def __str__(self):
        return "%s (%s)" % (self.__desc, self.__id)

    @property
    def id(self):
        """
        Gets the identifier of the region.

        Returns:
            Integer: the region identifier.
        """
        return self.__id

    @property
    def description(self):
        """
        Gets the description of the region.

        Returns:
            String: the region description.
        """
        return self.__desc

    @classmethod
    def get(cls, identifier):
        """
        Returns the Region for the given identifier.

        Args:
            identifier (Integer): the id value of the region to get.

        Returns:
            :class:`.Region`: the Region with the given identifier. `None` if it
                does not exist.
        """
        for item in cls:
            if identifier == item.id:
                return item

        return None

    def allows_any(self):
        """
        Returns whether this region accepts any region specified in the firmware.

        Returns:
            Boolean: `True` if this region accepts any region `False` otherwise.
        """
        return self in (Region.ALL, Region.ALL2)


Region.__doc__ += utils.doc_enum(Region)


@unique
class OTAMethod(Enum):
    """
    Enumerates the over-the-air firmware update mechanisms of XBee modules.
    """

    UNDEFINED = auto()
    EMBER = auto()
    GPM = auto()
    ZCL = auto()
