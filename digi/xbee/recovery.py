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

import logging
import time

from serial import EIGHTBITS, STOPBITS_ONE, PARITY_NONE
from serial.serialutil import SerialException

from digi.xbee.devices import XBeeDevice
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.hw import HardwareVersion
from digi.xbee.models.mode import OperatingMode
from digi.xbee.profile import FirmwareBaudrate, FirmwareParity, FirmwareStopbits
from digi.xbee.exception import RecoveryException, XBeeException
from digi.xbee.util import utils


SUPPORTED_HARDWARE_VERSIONS = (HardwareVersion.XBEE3.code,
                               HardwareVersion.XBEE3_SMT.code,
                               HardwareVersion.XBEE3_TH.code)

_BAUDRATE_KEY = "baudrate"
_PARITY_KEY = "parity"
_STOPBITS_KEY = "stopbits"
_API_ENABLE_KEY = "api_enable"
_CMD_SEQ_CHAR_KEY = "cmd_seq_char"
_GUARD_TIME_KEY = "guard_time"
_APPLY_CHANGES_KEY = "apply_changes"
_WRITE_REGISTER_KEY = "write_register"
_EXIT_MODE_KEY = "exit_mode"

_RECOVERY_PORT_PARAMETERS = {_BAUDRATE_KEY: 38400,
                             "bytesize": EIGHTBITS,
                             _PARITY_KEY: PARITY_NONE,
                             _STOPBITS_KEY: STOPBITS_ONE,
                             "xonxoff": False,
                             "dsrdtr": False,
                             "rtscts": False,
                             "timeout": 0.1,
                             "write_timeout": None,
                             "inter_byte_timeout": None
                             }

_RECOVERY_CHAR_TO_BAUDRATE = {
    0xf8: 9600,
    0x80: 9600,
    0xfe: 19200,
    0x30: 38400,
    0x7e: 38400,
    0x63: 115200
}

_DEFAULT_GUARD_TIME = 1  # seconds
_DEVICE_BREAK_RESET_TIMEOUT = 10  # seconds
_BOOTLOADER_CONTINUE_KEY = "2"
_RECOVERY_DETECTION_TRIES = 2
_BOOTLOADER_BAUDRATE = 115200
_AT_COMMANDS = {_BAUDRATE_KEY: "at%s" % ATStringCommand.BD.command,
                _PARITY_KEY: "at%s" % ATStringCommand.NB.command,
                _STOPBITS_KEY: "at%s" % ATStringCommand.SB.command,
                _API_ENABLE_KEY: "at%s" % ATStringCommand.AP.command,
                _CMD_SEQ_CHAR_KEY: "at%s" % ATStringCommand.CC.command,
                _GUARD_TIME_KEY: "at%s" % ATStringCommand.GT.command,
                _APPLY_CHANGES_KEY: "at%s\r" % ATStringCommand.AC.command,
                _WRITE_REGISTER_KEY: "at%s\r" % ATStringCommand.WR.command,
                _EXIT_MODE_KEY: "at%s\r" % ATStringCommand.CN.command
                }
AT_OK_RESPONSE = b'OK\r'
_BAUDS_LIST = tuple(e.value[1] for e in FirmwareBaudrate)
_PARITY_LIST = tuple(e.value[1] for e in FirmwareParity)
_STOPBITS_LIST = tuple(e.value[1] for e in FirmwareStopbits)

_log = logging.getLogger(__name__)


class _LocalRecoverDevice(object):
    """
    Helper class used to handle the local recovery process.
    """

    def __init__(self, target):
        """
        Class constructor. Instantiates a new :class:`._LocalRecoverDevice` with the given parameters.

        Args:
            target (String or :class:`.XBeeDevice`): target of the recovery operation.
                String: serial port identifier.
                :class:`.XBeeDevice`: the XBee device.
        """
        self._xbee_serial_port = None
        if isinstance(target, XBeeDevice):
            self._xbee_device = target
            self._device_was_connected = self._xbee_device.is_open()
            self._xbee_serial_port = self._xbee_device.serial_port
        else:
            self._xbee_serial_port = target
            self._xbee_device = None
            self._device_was_connected = False

        self._desired_cfg = self._xbee_serial_port.get_settings()
        self._desired_cfg[_CMD_SEQ_CHAR_KEY] = hex(ord('+'))[2:]
        self._desired_cfg[_GUARD_TIME_KEY] = hex(1000)[2:]  # 1000ms in hex

        if isinstance(target, XBeeDevice) \
                and self._xbee_device.operating_mode in \
                (OperatingMode.API_MODE, OperatingMode.ESCAPED_API_MODE):
            self._desired_cfg[_API_ENABLE_KEY] = self._xbee_device.operating_mode.code
        else:
            self._desired_cfg[_API_ENABLE_KEY] = 1

    def _enter_in_recovery(self):
        """
        Enters the device in recovery mode.

        Returns:
             Int: The baudrate if success or ``None`` in case of failure.
        """

        # Set break line and baudrate
        self._xbee_serial_port.apply_settings(_RECOVERY_PORT_PARAMETERS)
        self._xbee_serial_port.purge_port()
        self._xbee_serial_port.break_condition = True

        recovery_baudrate = None
        timeout = time.time() + _DEVICE_BREAK_RESET_TIMEOUT
        while time.time() < timeout:
            time.sleep(0.2)
            try:
                # The first byte indicates the baudrate
                if self._xbee_serial_port.in_waiting > 0:
                    read_bytes = self._xbee_serial_port.read(self._xbee_serial_port.in_waiting)
                    _log.debug("Databytes read from recovery are %s" % repr(utils.hex_to_string(read_bytes)))
                    if read_bytes[0] in _RECOVERY_CHAR_TO_BAUDRATE.keys():
                        recovery_baudrate = _RECOVERY_CHAR_TO_BAUDRATE[read_bytes[0]]
                    # The valid byte is only the first one, so do not retry the loop
                    break
            except SerialException as e:
                _log.exception(e)

        self._xbee_serial_port.break_condition = False
        return recovery_baudrate

    def autorecover_device(self):
        """
        Recovers the XBee from an unknown state.

        Raises:
            RecoveryException: if there is any error performing the recovery action.
        """
        if self._xbee_device is not None:
            if self._xbee_device.is_open:
                self._xbee_device.close()
        self._xbee_serial_port.open()
        self._xbee_serial_port.purge_port()

        _log.debug("Autorecovering the device by entering in recovery mode")
        # Enter in recovery mode
        recovery_baudrate = None
        for tries in range(_RECOVERY_DETECTION_TRIES):
            recovery_baudrate = self._enter_in_recovery()
            if recovery_baudrate is None:
                _log.debug("[try %d] Could not determine the baudrate to get the values in recovery mode" % tries)
            else:
                _log.debug("Recovery baudrate is %d" % recovery_baudrate)
                break

        # If we couldn't enter in recovery mode, assume we are in bootloader and retry
        if recovery_baudrate is None:
            _log.error("Could not determine the baudrate in recovery mode, assuming device is in bootloader mode and "
                       "retrying")
            self._xbee_serial_port.apply_settings({_BAUDRATE_KEY: _BOOTLOADER_BAUDRATE})
            self._xbee_serial_port.write(str.encode(_BOOTLOADER_CONTINUE_KEY))

            _log.debug("Retrying to determine the baudrate in recovery mode")
            for tries in range(_RECOVERY_DETECTION_TRIES):
                recovery_baudrate = self._enter_in_recovery()
                if recovery_baudrate is None:
                    _log.debug("[try %d] Could not determine the baudrate to get the values in recovery mode" % tries)
                else:
                    _log.debug("Recovery baudrate is %d" % recovery_baudrate)
                    break

        if recovery_baudrate is None:
            self._do_exception("Could not determine the baudrate in recovery mode")

        # Here we are in recovery mode
        _log.debug("Reconfiguring the serial port to recovery baudrate of %d" % recovery_baudrate)
        self._xbee_serial_port.apply_settings({_BAUDRATE_KEY: recovery_baudrate})

        # Set the desired configuration permanently.
        _log.debug("Forcing the current setup to {!r}".format(self._desired_cfg))

        for command in ("%s%s\r" % (
                                _AT_COMMANDS[_BAUDRATE_KEY],
                                _BAUDS_LIST.index(self._desired_cfg[_BAUDRATE_KEY])),
                        "%s%s\r" % (
                                _AT_COMMANDS[_PARITY_KEY],
                                _PARITY_LIST.index(self._desired_cfg[_PARITY_KEY])),
                        "%s%s\r" % (
                                _AT_COMMANDS[_STOPBITS_KEY],
                                _STOPBITS_LIST.index(self._desired_cfg[_STOPBITS_KEY])),
                        "%s%s\r" % (
                                _AT_COMMANDS[_API_ENABLE_KEY], self._desired_cfg[_API_ENABLE_KEY]),
                        "%s%s\r" % (
                                _AT_COMMANDS[_CMD_SEQ_CHAR_KEY],
                                self._desired_cfg[_CMD_SEQ_CHAR_KEY]),
                        "%s%s\r" % (
                                _AT_COMMANDS[_GUARD_TIME_KEY], self._desired_cfg[_GUARD_TIME_KEY]),
                        _AT_COMMANDS[_APPLY_CHANGES_KEY],
                        _AT_COMMANDS[_WRITE_REGISTER_KEY],
                        _AT_COMMANDS[_EXIT_MODE_KEY]):
            self._xbee_serial_port.write(str.encode(command))
            if command in (_AT_COMMANDS[_EXIT_MODE_KEY]):
                time.sleep(_DEFAULT_GUARD_TIME)
            timeout = time.time() + 2
            while self._xbee_serial_port.inWaiting() == 0 and time.time() < timeout:
                time.sleep(0.1)
            read = self._xbee_serial_port.read(self._xbee_serial_port.inWaiting())
            _log.debug("command {!r} = {!r}".format(command, read))
            if AT_OK_RESPONSE not in read:
                self._do_exception(
                    "Command {!r} failed, non OK returned value of {!r}".format(command, read))
            if command == _AT_COMMANDS[_APPLY_CHANGES_KEY]:
                self._xbee_serial_port.apply_settings(self._desired_cfg)

        self._restore_target_connection()

    def _do_exception(self, msg):
        """
        Logs the "msg" at error level and restores the target connection

        Args:
            msg (String): message to log

        Raises:
            RecoveryException: if the restore of the connection was successful.
            XBeeException: if there is any error restoring the device connection.
        """
        _log.error(msg)
        try:
            self._restore_target_connection()
        except XBeeException as e:
            _log.error("Could not restore connection: %s" % e)
        raise RecoveryException(msg)

    def _restore_target_connection(self):
        """
        Leaves the firmware update target connection (XBee device or serial port) in its original state.

        Raises:
            SerialException: if there is any error restoring the serial port connection.
            XBeeException: if there is any error restoring the device connection.
        """
        if self._xbee_device is not None:
            if self._xbee_serial_port is not None:
                if self._xbee_serial_port.isOpen():
                    self._xbee_serial_port.close()
            if self._device_was_connected and not self._xbee_device.is_open():
                self._xbee_device.open()
            elif not self._device_was_connected and self._xbee_device.is_open():
                self._xbee_device.close()
        elif self._xbee_serial_port is not None and self._xbee_serial_port.isOpen():
            self._xbee_serial_port.close()
        _log.debug("Restored target connection")


def recover_device(target):
    """
    Recovers the XBee from an unknown state and leaves if configured for normal operations.

    Args:
        target (String or :class:`.XBeeDevice`): target of the recovery operation.

    Raises:
        RecoveryException: if there is any error performing the recovery action.
    """
    # Launch the recover process.
    recovery_process = _LocalRecoverDevice(target)
    recovery_process.autorecover_device()
