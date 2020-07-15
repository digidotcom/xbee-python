# Copyright 2020, Digi International Inc.
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

from digi.xbee.models.address import XBee64BitAddress, XBee16BitAddress
from digi.xbee.models.atcomm import ATStringCommand
from digi.xbee.models.mode import OperatingMode
from digi.xbee.models.options import RemoteATCmdOptions
from digi.xbee.models.status import ATCommandStatus
from digi.xbee.packets.aft import ApiFrameType
from digi.xbee.util import utils


class PacketSender:

    _LOG_PATTERN = "{comm_iface:s} - {event:s} - {opmode:s}: {content:s}"
    """
    Pattern used to log packet events.
    """

    _log = logging.getLogger(__name__)
    """
    Logger.
    """

    def __init__(self, xbee):
        """
        Class constructor. Instantiates a new :class:`.PacketSender` object
        with the provided parameters.

        Args:
            xbee (:class:`.XBeeDevice`): The XBee.
        """
        self.__xbee = xbee
        self._at_cmds_sent = {}
        self._future_apply = {}

    def send_packet(self, packet):
        """
        Sends a packet to the XBee. The packet to send is escaped depending on
        the current operating mode.

        Args:
            packet (:class:`.XBeePacket`): The packet to send.

        Raises:
            InvalidOperatingModeException: If the XBee device's operating mode
                is not API or ESCAPED API. This method only checks the cached
                value of the operating mode.
            XBeeException: if the XBee device's communication interface is closed.

        .. seealso::
           | :class:`.XBeePacket`
        """
        f_type = packet.get_frame_type()
        # Do not allow to set a non API operating mode in the local XBee
        if (f_type in (ApiFrameType.AT_COMMAND, ApiFrameType.AT_COMMAND_QUEUE)
                and packet.parameter
                and packet.command.upper() == ATStringCommand.AP.command
                and not self.is_op_mode_valid(packet.parameter)):
            return

        comm_iface = self.__xbee.comm_iface
        op_mode = self.__xbee.operating_mode

        out = packet.output(escaped=op_mode == OperatingMode.ESCAPED_API_MODE)
        comm_iface.write_frame(out)
        self._log.debug(self._LOG_PATTERN.format(comm_iface=str(comm_iface),
                                                 event="SENT",
                                                 opmode=op_mode,
                                                 content=utils.hex_to_string(out)))

        # Refresh cached parameters if this method modifies some of them.
        if f_type in (ApiFrameType.AT_COMMAND, ApiFrameType.AT_COMMAND_QUEUE,
                      ApiFrameType.REMOTE_AT_COMMAND_REQUEST):
            node = self.__xbee
            # Get remote node in case of a remote at command
            if (f_type == ApiFrameType.REMOTE_AT_COMMAND_REQUEST
                    and packet.x64bit_dest_addr not in (XBee64BitAddress.UNKNOWN_ADDRESS,
                                                        XBee64BitAddress.BROADCAST_ADDRESS)):
                node = self.__xbee.get_network().get_device_by_64(packet.x64bit_dest_addr)

            # Store the sent AT command packet
            if node:
                key = str(node.get_64bit_addr())
                if key not in self._at_cmds_sent:
                    self._at_cmds_sent[key] = {}

                self._at_cmds_sent[key].update({packet.frame_id: packet})

    def is_op_mode_valid(self, value):
        """
        Returns `True` if the provided value is a valid operating mode for
        the library.

        Args:
            value (Bytearray): The value to check.

        Returns:
            Boolean: `True` for a valid value, `False` otherwise.
        """
        op_mode_value = utils.bytes_to_int(value)
        op_mode = OperatingMode.get(op_mode_value)
        if op_mode not in (OperatingMode.API_MODE,
                           OperatingMode.ESCAPED_API_MODE):
            self._log.error(
                "Operating mode '%d' (%s) not set not to loose XBee connection",
                op_mode_value, op_mode.description if op_mode else "Unknown")
            return False

        return True

    def at_response_received_cb(self, response):
        """
        Callback to deal with AT command responses and update the
        corresponding node. Only for internal use.

        Args:
            response (:class: `.XBeeAPIPacket`): The received API packet.
        """
        f_type = response.get_frame_type()
        if f_type not in (ApiFrameType.AT_COMMAND_RESPONSE,
                          ApiFrameType.REMOTE_AT_COMMAND_RESPONSE):
            return

        node = self.__xbee
        # Get remote node in case of a remote at command
        if (f_type == ApiFrameType.REMOTE_AT_COMMAND_RESPONSE
                and response.x64bit_source_addr not in (XBee64BitAddress.UNKNOWN_ADDRESS,
                                                        XBee64BitAddress.BROADCAST_ADDRESS)):
            node = self.__xbee.get_network().get_device_by_64(response.x64bit_source_addr)

        if not node:
            return

        key = str(node.get_64bit_addr())
        requests = self._at_cmds_sent.get(key, {})
        req = requests.pop(response.frame_id, None)

        if not req or response.status != ATCommandStatus.OK:
            return

        def is_req_apply(at_req):
            fr_type = at_req.get_frame_type()
            return (at_req.command.upper() == ATStringCommand.AC.command
                    or fr_type == ApiFrameType.AT_COMMAND
                    or (fr_type == ApiFrameType.REMOTE_AT_COMMAND_REQUEST
                        and at_req.transmit_options & RemoteATCmdOptions.APPLY_CHANGES.value))

        def is_node_info_param(at_pkt):
            at_cmd = at_pkt.command.upper()
            return at_cmd in (ATStringCommand.NI.command,
                              ATStringCommand.MY.command)

        def is_port_param(at_pkt):
            at_cmd = at_pkt.command.upper()
            return at_cmd in (ATStringCommand.AP.command,
                              ATStringCommand.BD.command,
                              ATStringCommand.NB.command,
                              ATStringCommand.SB.command)

        apply = is_req_apply(req)
        if apply:
            if key not in self._future_apply:
                self._future_apply[key] = {}

            node_fut_apply = self._future_apply.get(key, {})
            node_fut_apply.pop(req.command.upper(), None)
            for key, value in list(node_fut_apply.items()):
                self._refresh_if_cached(node, key, value, apply=True)

        if req.parameter and (is_port_param(req) or is_node_info_param(req)):
            self._refresh_if_cached(node, req.command.upper(), req.parameter,
                                    apply=apply)

    def _refresh_if_cached(self, node, parameter, value, apply=True):
        """
        Refreshes the proper cached parameter depending on `parameter` value.

        If `parameter` is not a cached parameter, this method does nothing.

        Args:
            node (:class:`.AbstractXBeeDevice`): The XBee to refresh.
            parameter (String): the parameter to refresh its value.
            value (Bytearray): the new value of the parameter.
            apply (Boolean, optional, default=`True`): `True` to apply
                immediately, `False` otherwise.
        """
        updated = False
        param = parameter.upper()

        key = str(node.get_64bit_addr())
        if key not in self._future_apply:
            self._future_apply[key] = {}

        node_fut_apply = self._future_apply.get(key, {})

        # Node identifier
        if param == ATStringCommand.NI.command:
            node_id = value.decode()
            changed = node.get_node_id() != node_id
            updated = changed and apply
            if updated:
                node._node_id = node_id
                node_fut_apply.pop(param, None)
            elif changed:
                node_fut_apply.update({param: value})
        # 16-bit address
        elif param == ATStringCommand.MY.command:
            x16bit_addr = XBee16BitAddress(value)
            changed = node.get_16bit_addr() != x16bit_addr
            updated = changed and apply
            if updated:
                node._16bit_addr = x16bit_addr
                node_fut_apply.pop(param, None)
            elif changed:
                node_fut_apply.update({param: value})
        elif not node.is_remote():
            updated = self._refresh_serial_params(node, param, value, apply=apply)

        if updated:
            network = node.get_local_xbee_device().get_network() if node.is_remote() \
                else node.get_network()
            if (network
                    and (not node.is_remote()
                         or network.get_device_by_64(node.get_64bit_addr())
                         or network.get_device_by_16(node.get_16bit_addr()))):
                from digi.xbee.devices import NetworkEventType, NetworkEventReason
                network._network_modified(
                    NetworkEventType.UPDATE, NetworkEventReason.READ_INFO, node=node)

    def _refresh_serial_params(self, node, parameter, value, apply=True):
        """
        Refreshes the proper cached parameter depending on `parameter` value.

        If `parameter` is not a cached parameter, this method does nothing.

        Args:
            node (:class:`.AbstractXBeeDevice`): The XBee to refresh.
            parameter (String): the parameter to refresh its value.
            value (Bytearray): the new value of the parameter.
            apply (Boolean, optional, default=`True`): `True` to apply
                immediately, `False` otherwise.

        Returns:
            Boolean: `True` if a network event must be sent, `False` otherwise.
        """
        node_fut_apply = self._future_apply.get(str(node.get_64bit_addr()), {})

        if parameter == ATStringCommand.AP.command:
            new_op_mode = OperatingMode.get(utils.bytes_to_int(value))
            changed = bool(
                new_op_mode != node.operating_mode
                and new_op_mode in (OperatingMode.API_MODE,
                                    OperatingMode.ESCAPED_API_MODE))

            if changed and apply:
                node._operating_mode = new_op_mode
                node_fut_apply.pop(parameter, None)
            elif changed:
                node_fut_apply.update({parameter: value})

            return changed and apply

        if not node.serial_port or parameter not in (ATStringCommand.BD.command,
                                                     ATStringCommand.NB.command,
                                                     ATStringCommand.SB.command):
            return False

        if parameter == ATStringCommand.BD.command:
            from digi.xbee.profile import FirmwareBaudrate
            new_bd = utils.bytes_to_int(value)
            baudrate = FirmwareBaudrate.get(new_bd)
            new_bd = baudrate.baudrate if baudrate else new_bd
            changed = new_bd != node.serial_port.baudrate
            parameter = "baudrate" if changed and apply else parameter
            value = new_bd if changed and apply else value
        elif parameter == ATStringCommand.NB.command:
            from digi.xbee.profile import FirmwareParity
            new_parity = FirmwareParity.get(utils.bytes_to_int(value))
            new_parity = new_parity.parity if new_parity else None
            changed = new_parity != node.serial_port.parity
            parameter = "parity" if changed and apply else parameter
            value = new_parity if changed and apply else value
        else:
            from digi.xbee.profile import FirmwareStopbits
            new_sbits = FirmwareStopbits.get(utils.bytes_to_int(value))
            new_sbits = new_sbits.stop_bits if new_sbits else None
            changed = new_sbits != node.serial_port.stopbits
            parameter = "stopbits" if changed and apply else parameter
            value = new_sbits if changed and apply else value

        if changed and apply:
            node.serial_port.apply_settings({parameter: value})
            node_fut_apply.pop(parameter, None)
        elif changed:
            node_fut_apply.update({parameter: value})

        return False
