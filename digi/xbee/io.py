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

from digi.xbee.util import utils
from enum import Enum, unique
from digi.xbee.exception import OperationNotSupportedException


@unique
class IOLine(Enum):
    """
    Enumerates the different IO lines that can be found in the XBee devices. 

    Depending on the hardware and firmware of the device, the number of lines 
    that can be used as well as their functionality may vary. Refer to the 
    product manual to learn more about the IO lines of your XBee device.
    """

    DIO0_AD0 = ("DIO0/AD0", 0, "D0")
    DIO1_AD1 = ("DIO1/AD1", 1, "D1")
    DIO2_AD2 = ("DIO2/AD2", 2, "D2")
    DIO3_AD3 = ("DIO3/AD3", 3, "D3")
    DIO4_AD4 = ("DIO4/AD4", 4, "D4")
    DIO5_AD5 = ("DIO5/AD5", 5, "D5")
    DIO6 = ("DIO6", 6, "D6")
    DIO7 = ("DIO7", 7, "D7")
    DIO8 = ("DIO8", 8, "D8")
    DIO9 = ("DIO9", 9, "D9")
    DIO10_PWM0 = ("DIO10/PWM0", 10, "P0", "M0")
    DIO11_PWM1 = ("DIO11/PWM1", 11, "P1", "M1")
    DIO12 = ("DIO12", 12, "P2")
    DIO13 = ("DIO13", 13, "P3")
    DIO14 = ("DIO14", 14, "P4")
    DIO15 = ("DIO15", 15, "P5")
    DIO16 = ("DIO16", 16, "P6")
    DIO17 = ("DIO17", 17, "P7")
    DIO18 = ("DIO18", 18, "P8")
    DIO19 = ("DIO19", 19, "P9")

    def __init__(self, description, index, at_command, pwm_command=None):
        self.__description = description
        self.__index = index
        self.__at_command = at_command
        self.__pwm_command = pwm_command

    def __get_description(self):
        """
        Returns the description of the IOLine element.

        Returns:
            String: the description of the IOLine element.
        """
        return self.__description

    def __get_index(self):
        """
        Returns the index of the IOLine element.

        Returns:
            Integer: the index of the IOLine element.
        """
        return self.__index

    def __get_at_command(self):
        """
        Returns the AT command of the IOLine element.

        Returns:
            String: the AT command of the IOLine element.
        """
        return self.__at_command

    def __get_pwm_command(self):
        """
        Returns the PWM AT command associated to the IOLine element.

        Returns:
            String: the PWM AT command associated to the IO line, ``None`` if the IO line does not have a PWM
                AT command associated.
        """
        return self.__pwm_command

    def has_pwm_capability(self):
        """
        Returns whether the IO line has PWM capability or not.

        Returns:
            Boolean: ``True`` if the IO line has PWM capability, ``False`` otherwise.
        """
        return self.__pwm_command is not None

    @classmethod
    def get(cls, index):
        """
        Returns the :class:`.IOLine` for the given index.

        Args:
            index (Integer): Returns the :class:`.IOLine` for the given index.

        Returns:
            :class:`.IOLine`: :class:`.IOLine` with the given code, ``None`` if there is not any line with that index.
        """
        try:
            return cls.lookupTable[index]
        except KeyError:
            return None

    description = property(__get_description)
    """String. The IO line description."""

    index = property(__get_index)
    """Integer. The IO line index."""

    at_command = property(__get_at_command)
    """String. The IO line AT command."""

    pwm_at_command = property(__get_pwm_command)
    """String. The IO line PWM AT command."""


IOLine.lookupTable = {x.index: x for x in IOLine}
IOLine.__doc__ += utils.doc_enum(IOLine)


@unique
class IOValue(Enum):
    """
    Enumerates the possible values of a :class:`.IOLine` configured as digital I/O.
    """

    LOW = 4
    HIGH = 5

    def __init__(self, code):
        self.__code = code

    def __get_code(self):
        """
        Returns the code of the IOValue element.

        Returns:
            String: the code of the IOValue element.
        """
        return self.__code

    @classmethod
    def get(cls, code):
        """
        Returns the IOValue for the given code.

        Args:
            code (Integer): the code corresponding to the IOValue to get.

        Returns:
            :class:`.IOValue`: the IOValue with the given code, ``None`` if there is not any IOValue with that code.
        """
        try:
            return cls.lookupTable[code]
        except KeyError:
            return None

    code = property(__get_code)
    """Integer. The IO value code."""


IOValue.lookupTable = {x.code: x for x in IOValue}
IOValue.__doc__ += utils.doc_enum(IOValue)


class IOSample(object):
    """
    This class represents an IO Data Sample. The sample is built using the
    the constructor. The sample contains an analog and digital mask indicating 
    which IO lines are configured with that functionality.

    Depending on the protocol the XBee device is executing, the digital and 
    analog masks are retrieved in separated bytes (2 bytes for the digital mask 
    and 1 for the analog mask) or merged contained (digital and analog masks 
    are contained in 2 bytes). 

    Digital and analog channels masks
    Indicates which digital and ADC IO lines are configured in the module. Each
    bit corresponds to one digital or ADC IO line on the module:
    ::

            bit 0 =  DIO01
            bit 1 =  DIO10
            bit 2 =  DIO20
            bit 3 =  DIO31
            bit 4 =  DIO40
            bit 5 =  DIO51
            bit 6 =  DIO60
            bit 7 =  DIO70
            bit 8 =  DIO80
            bit 9 =  AD00
            bit 10 = AD11
            bit 11 = AD21
            bit 12 = AD30
            bit 13 = AD40
            bit 14 = AD50
            bit 15 = NA0

            Example: mask of 0x0C29 means DIO0, DIO3, DIO5, AD1 and AD2 enabled.
            0 0 0 0 1 1 0 0 0 0 1 0 1 0 0 1

    Digital Channel Mask
    Indicates which digital IO lines are configured in the module. Each bit 
    corresponds to one digital IO line on the module:
    ::

            bit 0 =  DIO0AD0
            bit 1 =  DIO1AD1 
            bit 2 =  DIO2AD2
            bit 3 =  DIO3AD3
            bit 4 =  DIO4AD4
            bit 5 =  DIO5AD5ASSOC
            bit 6 =  DIO6RTS
            bit 7 =  DIO7CTS
            bit 8 =  DIO8DTRSLEEP_RQ
            bit 9 =  DIO9ON_SLEEP
            bit 10 = DIO10PWM0RSSI
            bit 11 = DIO11PWM1
            bit 12 = DIO12CD
            bit 13 = DIO13
            bit 14 = DIO14
            bit 15 = NA

            Example: mask of 0x040B means DIO0, DIO1, DIO2, DIO3 and DIO10 enabled.
            0 0 0 0 0 1 0 0 0 0 0 0 1 0 1 1

    Analog Channel Mask
    Indicates which lines are configured as ADC. Each bit in the analog 
    channel mask corresponds to one ADC line on the module.
    ::

            bit 0 = AD0DIO0
            bit 1 = AD1DIO1
            bit 2 = AD2DIO2
            bit 3 = AD3DIO3
            bit 4 = AD4DIO4
            bit 5 = AD5DIO5ASSOC
            bit 6 = NA
            bit 7 = Supply Voltage Value

            Example: mask of 0x83 means AD0, and AD1 enabled.
            0 0 0 0 0 0 1 1
    """

    __pattern = "[{key}: {value}], "
    """Pattern for digital and analog values in __str__ method."""

    __pattern2 = "[Power supply voltage: {value}], "
    """Pattern for power supply voltage in __str__ method."""

    __MIN_IO_SAMPLE_PAYLOAD_LENGTH = 5

    def __init__(self, io_sample_payload):
        """
        Class constructor. Instantiates a new :class:`.IOSample` object with the provided parameters.

        Args:
            io_sample_payload (Bytearray): The payload corresponding to an IO sample.

        Raises:
            ValueError: if io_sample_payload length is less than 5.
        """
        # dictionaries
        self.__digital_values_map = {}  # {IOLine : IOValue}
        self.__analog_values_map = {}  # {IOLine : Integer}

        # Integers:
        self.__digital_hsb_mask = None
        self.__digital_lsb_mask = None
        self.__digital_mask = None
        self.__analog_mask = None
        self.__digital_hsb_values = None
        self.__digital_lsb_values = None
        self.__digital_values = None
        self.__power_supply_voltage = None

        if len(io_sample_payload) < IOSample.__MIN_IO_SAMPLE_PAYLOAD_LENGTH:
            raise ValueError("IO sample payload must be longer than 4.")

        self.__io_sample_payload = io_sample_payload

        if len(self.__io_sample_payload) % 2 != 0:
            self.__parse_raw_io_sample()
        else:
            self.__parse_io_sample()

    def __str__(self):
        s = "{"
        if self.has_digital_values():
            s += (''.join([self.__pattern.format(key=x, value=self.__digital_values_map[x]) for x in
                           self.__digital_values_map.keys()]))
        if self.has_analog_values():
            s += (''.join([self.__pattern.format(key=x, value=self.__analog_values_map[x]) for x in
                           self.__analog_values_map.keys()]))
        if self.has_power_supply_value():
            try:
                s += self.__pattern2.format(value=self.__power_supply_voltage)
            except OperationNotSupportedException:
                pass
        s += "}"
        aux = s.replace(", }", "}")
        return aux

    @staticmethod
    def min_io_sample_payload():
        """
        Returns  the minimum IO sample payload length.

        Returns:
            Integer: the minimum IO sample payload length.
        """
        return IOSample.__MIN_IO_SAMPLE_PAYLOAD_LENGTH

    def __parse_raw_io_sample(self):
        """
        Parses the information contained in the IO sample bytes reading the 
        value of each configured DIO and ADC.
        """
        data_index = 3

        # Obtain the digital mask.                                    # Available digital IOs in 802.15.4
        self.__digital_hsb_mask = self.__io_sample_payload[1] & 0x01  # 0 0 0 0 0 0 0 1
        self.__digital_lsb_mask = self.__io_sample_payload[2] & 0xFF  # 1 1 1 1 1 1 1 1
        # Combine the masks.
        self.__digital_mask = (self.__digital_hsb_mask << 8) + self.__digital_lsb_mask
        # Obtain the analog mask.
        self.__analog_mask = ((self.__io_sample_payload[1] << 8)       # Available analog IOs in 802.15.4
                              + self.__io_sample_payload[2]) & 0x7E00  # 0 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0

        # Read the digital values (if any). There are 9 possible digital lines in
        # 802.15.4 protocol. The digital mask indicates if there is any digital
        # line enabled to read its value. If 0, no digital values are received.
        if self.__digital_mask > 0:
            # Obtain the digital values.
            self.__digital_hsb_values = self.__io_sample_payload[3] & 0x7F
            self.__digital_lsb_values = self.__io_sample_payload[4] & 0xFF
            # Combine the values.
            self.__digital_values = (self.__digital_hsb_values << 8) + self.__digital_lsb_values

            for i in range(16):
                if not utils.is_bit_enabled(self.__digital_mask, i):
                    continue
                if utils.is_bit_enabled(self.__digital_values, i):
                    self.__digital_values_map[IOLine.get(i)] = IOValue.HIGH
                else:
                    self.__digital_values_map[IOLine.get(i)] = IOValue.LOW

            # Increase the data index to read the analog values.
            data_index += 2

        # Read the analog values (if any). There are 6 possible analog lines.
        # The analog mask indicates if there is any analog line enabled to read
        # its value. If 0, no analog values are received.
        adc_index = 9
        while (len(self.__io_sample_payload) - data_index) > 1 and adc_index < 16:
            if not (utils.is_bit_enabled(self.__analog_mask, adc_index)):
                adc_index += 1
                continue

            # 802.15.4 protocol does not provide power supply value, so get just the ADC data.
            self.__analog_values_map[IOLine.get(adc_index - 9)] = \
                ((self.__io_sample_payload[data_index] & 0xFF) << 8) + (self.__io_sample_payload[data_index + 1] & 0xFF)
            # Increase the data index to read the next analog values.
            data_index += 2
            adc_index += 1

    def __parse_io_sample(self):
        """
        Parses the information contained in the IO sample bytes reading the 
        value of each configured DIO and ADC.
        """
        data_index = 4

        # Obtain the digital masks.                                   # Available digital IOs
        self.__digital_hsb_mask = self.__io_sample_payload[1] & 0x7F  # 0 1 1 1 1 1 1 1
        self.__digital_lsb_mask = self.__io_sample_payload[2] & 0xFF  # 1 1 1 1 1 1 1 1
        # Combine the masks.
        self.__digital_mask = (self.__digital_hsb_mask << 8) + self.__digital_lsb_mask
        # Obtain the analog mask.                                # Available analog IOs
        self.__analog_mask = self.__io_sample_payload[3] & 0xBF  # 1 0 1 1 1 1 1 1

        # Read the digital values (if any). There are 16 possible digital lines.
        # The digital mask indicates if there is any digital line enabled to read
        # its value. If 0, no digital values are received.
        if self.__digital_mask > 0:
            # Obtain the digital values.
            self.__digital_hsb_values = self.__io_sample_payload[4] & 0x7F
            self.__digital_lsb_values = self.__io_sample_payload[5] & 0xFF
            # Combine the values.
            self.__digital_values = (self.__digital_hsb_values << 8) + self.__digital_lsb_values

            for i in range(16):
                if not utils.is_bit_enabled(self.__digital_mask, i):
                    continue
                if utils.is_bit_enabled(self.__digital_values, i):
                    self.__digital_values_map[IOLine.get(i)] = IOValue.HIGH
                else:
                    self.__digital_values_map[IOLine.get(i)] = IOValue.LOW
            # Increase the data index to read the analog values.
            data_index += 2

        # Read the analog values (if any). There are 6 possible analog lines.
        # The analog mask indicates if there is any analog line enabled to read
        # its value. If 0, no analog values are received.
        adc_index = 0
        while (len(self.__io_sample_payload) - data_index) > 1 and adc_index < 8:
            if not utils.is_bit_enabled(self.__analog_mask, adc_index):
                adc_index += 1
                continue
            # When analog index is 7, it means that the analog value corresponds to the power
            # supply voltage, therefore this value should be stored in a different value.
            if adc_index == 7:
                self.__power_supply_voltage = ((self.__io_sample_payload[data_index] & 0xFF) << 8) + \
                                              (self.__io_sample_payload[data_index + 1] & 0xFF)
            else:
                self.__analog_values_map[IOLine.get(adc_index)] = \
                    ((self.__io_sample_payload[data_index] & 0xFF) << 8) + \
                    (self.__io_sample_payload[data_index + 1] & 0xFF)
            # Increase the data index to read the next analog values.
            data_index += 2
            adc_index += 1

    def __get_digital_hsb_mask(self):
        """
        Returns the High Significant Byte (HSB) of the digital mask.

        Returns:
            Integer: the HSB of the digital mask.
        """
        return self.__digital_hsb_mask

    def __get_digital_lsb_mask(self):
        """
        Returns the Low Significant Byte (HSB) of the digital mask.

        Returns:
            Integer: the LSB of the digital mask.
        """
        return self.__digital_lsb_mask

    def __get_digital_mask(self):
        """
        Returns the combined (HSB + LSB) of the digital mask.

        Returns:
            Integer: the digital mask.
        """
        return self.__digital_mask

    def __get_digital_values(self):
        """
        Returns the digital values map.

        To verify if this sample contains a valid digital values, use the 
        method :meth:`.IOSample.has_digital_values`.

        Returns:
            Dictionary: the digital values map.
        """
        return self.__digital_values_map.copy()

    def __get_analog_mask(self):
        """
        Returns the analog mas.

        Returns:
            Integer: the analog mask.
        """
        return self.__analog_mask

    def __get_analog_values(self):
        """
        Returns the analog values map.

        To verify if this sample contains a valid analog values, use the 
        method :meth:`.IOSample.has_analog_values`.

        Returns:
            Dictionary: the analog values map.
        """
        return self.__analog_values_map.copy()

    def __get_power_supply_value(self):
        """
        Returns the value of the power supply voltage.

        To verify if this sample contains the power supply voltage, use the 
        method :meth:`.IOSample.has_power_supply_value`.

        Returns:
            Integer: the power supply value, ``None`` if the sample does not contain power supply value.
        """
        return self.__power_supply_voltage if self.has_power_supply_value() else None

    def has_digital_values(self):
        """
        Checks whether the IOSample has digital values or not.

        Returns:
            Boolean: ``True`` if the sample has digital values, ``False`` otherwise.
        """
        return len(self.__digital_values_map) > 0

    def has_digital_value(self, io_line):
        """
        Returns whether th IO sample contains a digital value for the provided IO line or not.

        Args:
            io_line (:class:`IOLine`): The IO line to check if it has a digital value.

        Returns:
            Boolean: ``True`` if the given IO line has a digital value, ``False`` otherwise.
        """
        return io_line in self.__digital_values_map.keys()

    def has_analog_value(self, io_line):
        """
        Returns whether the given IOLine has an analog value or not.

        Returns:
            Boolean: ``True`` if the given IOLine has an analog value, ``False`` otherwise.
        """
        return io_line in self.__analog_values_map.keys()

    def has_analog_values(self):
        """
        Returns whether the {@code IOSample} has analog values or not.

        Returns:
            Boolean. ``True`` if there are analog values, ``False`` otherwise.
        """
        return len(self.__analog_values_map) > 0

    def has_power_supply_value(self):
        """
        Returns whether the IOSample has power supply value or not.

        Returns:
            Boolean. ``True`` if the given IOLine has a power supply value, ``False`` otherwise.
        """
        return utils.is_bit_enabled(self.__analog_mask, 7)

    def get_digital_value(self, io_line):
        """
        Returns the digital value of the provided IO line.

        To verify if this sample contains a digital value for the given :class:`.IOLine`,
        use the method :meth:`.IOSample.has_digital_value`.

        Args:
            io_line (:class:`.IOLine`): The IO line to get its digital value.

        Returns:
            :class:`.IOValue`: The :class:`.IOValue` of the given IO line or ``None`` if the
                IO sample does not contain a digital value for the given IO line.

        .. seealso::
           | :class:`.IOLine`
           | :class:`.IOValue`
        """
        if io_line in self.__digital_values_map:
            return self.__digital_values_map[io_line]
        return None

    def get_analog_value(self, io_line):
        """
        Returns the analog value of the provided IO line.

        To verify if this sample contains an analog value for the given :class:`.IOLine`,
        use the method :meth:`.IOSample.has_analog_value`.

        Args:
            io_line (:class:`.IOLine`): The IO line to get its analog value.

        Returns:
            Integer: The analog value of the given IO line or ``None`` if the IO sample does not
                contain an analog value for the given IO line.

        .. seealso::
           | :class:`.IOLine`
        """
        if io_line in self.__analog_values_map:
            return self.__analog_values_map[io_line]
        return None

    digital_hsb_mask = property(__get_digital_hsb_mask)
    """Integer. High Significant Byte (HSB) of the digital mask."""

    digital_lsb_mask = property(__get_digital_lsb_mask)
    """Integer. Low Significant Byte (LSB) of the digital mask."""

    digital_mask = property(__get_digital_mask)
    """Integer. Digital mask of the IO sample."""

    analog_mask = property(__get_analog_mask)
    """Integer. Analog mask of the IO sample."""

    digital_values = property(__get_digital_values)
    """Dictionary. Digital values map."""

    analog_values = property(__get_analog_values)
    """Dictionary. Analog values map."""

    power_supply_value = property(__get_power_supply_value)
    """Integer. Power supply value, ``None`` if the sample does not contain power supply value."""


class IOMode(Enum):
    """
    Enumerates the different Input/Output modes that an IO line can be
    configured with.
    """

    DISABLED = 0
    """Disabled"""

    SPECIAL_FUNCTIONALITY = 1
    """Firmware special functionality"""

    PWM = 2
    """PWM output"""

    ADC = 2
    """Analog to Digital Converter"""

    DIGITAL_IN = 3
    """Digital input"""

    DIGITAL_OUT_LOW = 4
    """Digital output, Low"""

    DIGITAL_OUT_HIGH = 5
    """Digital output, High"""

    I2C_FUNCTIONALITY = 6
    """I2C functionality"""
