# Copyright 2021 Digi International Inc., All Rights Reserved
#
# This software contains proprietary and confidential information of Digi
# International Inc.  By accepting transfer of this copy, Recipient agrees
# to retain this software in confidence, to prevent disclosure to others,
# and to make no use of this software other than that for which it was
# delivered.  This is an unpublished copyrighted work of Digi International
# Inc.  Except as permitted by federal law, 17 USC 117, copying is strictly
# prohibited.
#
# Restricted Rights Legend
#
# Use, duplication, or disclosure by the Government is subject to
# restrictions set forth in sub-paragraph (c)(1)(ii) of The Rights in
# Technical Data and Computer Software clause at DFARS 252.227-7031 or
# subparagraphs (c)(1) and (2) of the Commercial Computer Software -
# Restricted Rights at 48 CFR 52.227-19, as applicable.
#
# Digi International Inc., 9350 Excelsior Blvd., Suite 700, Hopkins, MN 55343
import logging
import datetime
import json

from xml.etree.ElementTree import Element, SubElement, ElementTree

from digi.xbee.devices import RemoteZigBeeDevice
from digi.xbee.profile import FirmwareParity
from digi.xbee.util import utils


def generate_network_json(xbee, date_now=None, name=None, desc=None):
    """
    Generates the JSON heirarchy representing the network of the given XBee.

    Params:
        xbee (:class:`.XBeeDevice`): Local Xbee node.
        date_now (:class: `datetime.datetime`, option, default=`None`): Date to set in JSON
        name (String, optional, default=`None`): Human readable network name.
        desc (String, optional, default=`None`): Description of the network.

    Return:
        :class:`str`: JSON formatted `str`.
    """
    network_name = "xbee_network" if name is None else f"{name}_network"
    if not date_now:
        date_now = datetime.datetime.now()

    root = {
        network_name: {
            "description": "" if not desc else str(desc),
            "date": str(date_now),
            "map_type": "dynamic",
            "protocol": str(xbee.get_protocol().code),
            "devices": _generate_nodes_json(xbee)
        }
    }

    try:
        return json.dumps(root, indent=2)
    except TypeError:
        logging.error("Unable to parse network into valid json")
        return None


def _generate_nodes_json(xbee):
    """
    Generates a JSON element representing the network of the given XBee.

    Params:
        xbee (:class:`.XBeeDevice`): Local XBee node.

    Return:
        :class:`dict`: A dict of nodes.
    """
    nodes = dict()

    network = xbee.get_network()
    for node in [xbee] + network.get_devices():
        addr = str(node.get_64bit_addr())
        nodes[addr] = _generate_node_json(node)

    return nodes


def _generate_node_json(node) -> dict:
    """
    Generates a JSON element representing the given XBee node.

    Params:
        xbee (:class:`.AbstractXBeeDevice`): XBee node.

    Return:
        :class:`dict`: Generated dict that represents the node.
    """

    hw = node.get_hardware_version()
    fw = node.get_firmware_version()

    node_info = {
        'nwk_address': str(node.get_16bit_addr()),
        'node_id': node.get_node_id(),
        'role': node.get_role().description,
        'hw_version':
        f"{utils.hex_to_string([hw.code], pretty=False) if hw else '???'}",
        "fw_version":
        f"{utils.hex_to_string(fw,pretty=False) if fw else '???'}"
    }

    # handle ZiGBee specifics
    if isinstance(node, RemoteZigBeeDevice) and node.parent:
        node_info['parent_address'] = str(node.parent.get_64bit_addr())

    # if node is NOT remote then add serial information
    if not node.is_remote():
        ser = node.serial_port

        node_info['serial_config'] = {
            'port': str(ser.port),
            'baud_rate': str(ser.baudrate),
            'data_bits': str(ser.bytesize),
            'stop_bits': str(ser.stopbits),
            'parity': str(FirmwareParity.get_by_parity(ser.parity).index),
        }
        # handle flow control based on logic provided in `_generatoe_serial_config_xml`
        fc = "0"
        if ser.rtscts:
            fc = "3"
        elif ser.xonxoff:
            fc = "12"
        node_info['serial_config']['flow_control'] = fc

    network = node.get_local_xbee_device().get_network() \
        if node.is_remote() else node.get_network()

    node_info['connections'] = _generate_connections_json(
        node, network.get_node_connections(node))

    return node_info


def _generate_connections_json(node, connections):
    """
    Generates the XML node representing the given connections.

    Params:
        xbee (:class:`.AbstractXBeeDevice`): XBee node.
        connections (List): List of :class:`.Connection`.

    Return:
        :class:`dict`: Generated dictionary list of Connections.
    """
    conn_info = dict()
    for conn in connections:
        end_device = conn.node_b if node == conn.node_a else conn.node_a
        addr = str(end_device.get_64bit_addr())
        conn_info[addr] = {
            'strength':
            str(conn.lq_a2b if node == conn.node_a else conn.lq_b2a),
            'status':
            str(conn.status_a2b.id if node ==
                conn.node_a else conn.status_b2a.id)
        }
    return conn_info


def generate_network_xml(xbee, date_now=None, name=None, desc=None):
    """
    Generates the XML hierarchy representing the network of the given XBee.

    Params:
        xbee (:class:`.XBeeDevice`): Local XBee node.
        date_now (:class: `datetime.datetime`, optional, default=`None`): Date
            to set in the XML.
        name (String, optional, default=`None`): Human readable network name.
        desc (String, optional, default=`None`): Description of the network.

    Return:
        :class:`xml.etree.ElementTree.ElementTree`: Generated XML hierarchy.
    """
    level = 1

    if not date_now:
        date_now = datetime.datetime.now()

    net_node = Element("network",
                       attrib={"name": "%s_network" if not name else name})
    net_node.text = "\n" + '\t' * level
    desc_node = SubElement(net_node, "description")
    desc_node.text = "" if not desc else desc
    desc_node.tail = "\n" + '\t' * level
    date = SubElement(net_node, "date")
    date.text = date_now.strftime("%-m/%-d/%y %-I:%-M:%-S %p")
    date.tail = "\n" + '\t' * level
    protocol = SubElement(net_node, "protocol")
    protocol.text = str(xbee.get_protocol().code)
    protocol.tail = "\n" + '\t' * level
    map_type = SubElement(net_node, "map_type")
    map_type.text = "dynamic"
    map_type.tail = "\n" + '\t' * level

    net_node.append(_generate_nodes_xml(xbee, level + 1))

    return ElementTree(element=net_node)


def _generate_nodes_xml(xbee, level=0):
    """
    Generates the XML element representing the network of the given XBee.

    Params:
        xbee (:class:`.XBeeDevice`): Local XBee node.
        level (Integer, optional, default=0): Indentation level.

    Return:
        :class:`xml.etree.ElementTree.Element`: Generated XML element.
    """
    network = xbee.get_network()
    devices_node = Element("devices")
    devices_node.text = "\n" + '\t' * level
    devices_node.tail = "\n"
    level += 1
    for node in [xbee] + network.get_devices():
        devices_node.append(_generate_node_xml(node, level))

    last_device = devices_node.find("./device[last()]")
    if last_device:
        last_device.tail = "\n" + '\t' * (level - 2)

    return devices_node


def _generate_node_xml(node, level=0):
    """
    Generates the XML element representing the given XBee node.

    Params:
        xbee (:class:`.AbstractXBeeDevice`): XBee node.
        level (Integer, optional, default=0): Indentation level.

    Return:
        :class:`xml.etree.ElementTree.Element`: Generated XML element.
    """
    device_node = Element("device",
                          attrib={"address": str(node.get_64bit_addr())})
    device_node.text = "\n" + '\t' * level
    device_node.tail = "\n" + '\t' * (level - 1)
    net_addr = SubElement(device_node, "nwk_address")
    net_addr.text = str(node.get_16bit_addr())
    net_addr.tail = "\n" + '\t' * level
    node_id = SubElement(device_node, "node_id")
    node_id.text = node.get_node_id()
    node_id.tail = "\n" + '\t' * level
    role = SubElement(device_node, "role")
    role.text = node.get_role().description
    role.tail = "\n" + '\t' * level
    if isinstance(node, RemoteZigBeeDevice) and node.parent:
        parent = SubElement(device_node, "parent_address")
        parent.text = str(node.parent.get_64bit_addr())
        parent.tail = "\n" + '\t' * level
    hw_version = SubElement(device_node, "hw_version")
    if node.get_hardware_version():
        hw_version.text = "0x%s" % utils.hex_to_string(
            [node.get_hardware_version().code], pretty=False)
    hw_version.tail = "\n" + '\t' * level
    fw_version = SubElement(device_node, "fw_version")
    if node.get_firmware_version():
        fw_version.text = utils.hex_to_string(node.get_firmware_version(),
                                              pretty=False)
    fw_version.tail = "\n" + '\t' * level

    if not node.is_remote():
        device_node.append(
            _generate_serial_config_xml(node.serial_port, level + 1))

    network = node.get_local_xbee_device().get_network() \
        if node.is_remote() else node.get_network()

    device_node.append(
        _generate_connections_xml(node, network.get_node_connections(node),
                                  level + 1))

    return device_node


def _generate_serial_config_xml(serial_port, level=0):
    """
    Generates the XML element representing the given serial port.

    Params:
        serial_port (:class:`serial.serialutil.SerialBase`): Serial port.
        level (Integer, optional, default=0): Indentation level.

    Return:
        :class:`xml.etree.ElementTree.Element`: Generated XML element.
    """
    serial_cfg_node = Element("serial_config")
    serial_cfg_node.text = "\n" + '\t' * level
    serial_cfg_node.tail = "\n" + '\t' * (level - 1)
    port = SubElement(serial_cfg_node, "port")
    port.text = serial_port.port
    port.tail = "\n" + '\t' * level
    baud_rate = SubElement(serial_cfg_node, "baud_rate")
    baud_rate.text = str(serial_port.baudrate)
    baud_rate.tail = "\n" + '\t' * level
    data_bits = SubElement(serial_cfg_node, "data_bits")
    data_bits.text = str(serial_port.bytesize)
    data_bits.tail = "\n" + '\t' * level
    stop_bits = SubElement(serial_cfg_node, "stop_bits")
    stop_bits.text = str(serial_port.stopbits)
    stop_bits.tail = "\n" + '\t' * level
    parity = SubElement(serial_cfg_node, "parity")
    parity.text = str(FirmwareParity.get_by_parity(serial_port.parity).index)
    parity.tail = "\n" + '\t' * level
    flow_control = SubElement(serial_cfg_node, "flow_control")
    # Values used in XCTU and XNA
    if serial_port.rtscts:
        flow_control.text = "3"
    elif serial_port.xonxoff:
        flow_control.text = "12"
    else:
        flow_control.text = "0"
    flow_control.tail = "\n" + '\t' * (level - 1)

    return serial_cfg_node


def _generate_connections_xml(node, connections, level=0):
    """
    Generates the XML node representing the given connections.

    Params:
        xbee (:class:`.AbstractXBeeDevice`): XBee node.
        connections (List): List of :class:`.Connection`.
        level (Integer, optional, default=0): Indentation level.

    Return:
        :class:`xml.etree.ElementTree.Element`: Generated XML element.
    """
    connections_node = Element("connections")
    connections_node.text = "\n" + '\t' * (level if connections else level - 1)
    connections_node.tail = "\n" + '\t' * (level - 2)
    for conn in connections:
        end_device = conn.node_b if node == conn.node_a else conn.node_a
        conn_node = SubElement(
            connections_node,
            "connection",
            attrib={"address": str(end_device.get_64bit_addr())})
        conn_node.text = "\n" + '\t' * (level + 1)
        conn_node.tail = "\n" + '\t' * level
        conn_lq = SubElement(conn_node, "strength")
        conn_lq.text = str(conn.lq_a2b if node == conn.node_a else conn.lq_b2a)
        conn_lq.tail = "\n" + '\t' * (level + 1)
        conn_status = SubElement(conn_node, "status")
        conn_status.text = str(conn.status_a2b.id if node ==
                               conn.node_a else conn.status_b2a.id)
        conn_status.tail = "\n" + '\t' * level

    last_conn = connections_node.find("./connection[last()]")
    if last_conn:
        last_conn.tail = "\n" + '\t' * (level - 1)

    return connections_node
