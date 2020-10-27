Work with XBee classes
======================

When working with the XBee Python Library, start with an XBee device object
that represents a physical module. A physical XBee device is the combination
of hardware and firmware. Depending on that combination, the device runs a
specific wireless communication protocol such as Zigbee, 802.15.4, DigiMesh,
Wi-Fi, or cellular. An XBeeDevice class represents the XBee module in the
API.

Most of the protocols share the same features and settings, but there are some
differences between them. For that reason, the XBee Python Library also
includes a set of classes that represent XBee devices running different
communication protocols. The XBee Python Library supports one XBee device
class per protocol, as follows:

.. image:: ../images/xbplib_class_hierarchy.png
   :align: center
   :alt: XBee Class hierarchy

* XBee Zigbee device (``ZigBeeDevice``)
* XBee 802.15.4 device (``Raw802Device``)
* XBee DigiMesh device (``DigiMeshDevice``)
* XBee Point-to-multipoint device (``DigiPointDevice``)
* XBee IP devices (This is a non-instantiable class)

  * XBee Cellular device (``CellularDevice``)
  * XBee Wi-Fi device (``WiFiDevice``)

All these XBee device classes allow you to configure the physical XBee device,
communicate with the device, send data to other nodes on the network, receive
data from remote devices, and so on. Depending on the class, you may have
additional methods to execute protocol-specific features or similar methods.

To work with the API and perform actions involving the physical device, you
must instantiate a generic ``XBeeDevice`` object or one that is
protocol-specific. This documentation refers to the ``XBeeDevice`` object
generically when describing the different features, but they can be applicable
to any XBee device class.


Instantiate an XBee device
--------------------------

When you are working with the XBee Python Library, the first step is to
instantiate an XBee device object. The API works well using the generic
``XBeeDevice`` class, but you can also instantiate a protocol-specific XBee
device object if you know the protocol your physical XBee device is running.

An XBee device is represented as either **local** or **remote** in the XBee
Python Library, depending upon how you communicate with the device.


Local XBee device
`````````````````

A local XBee device is the object in the library representing the device that
is physically attached to your PC through a serial or USB port. The classes
you can instantiate to represent a local device are listed in the following
table:

+-----------------+--------------------------------------+
| Class           | Description                          |
+=================+======================================+
| XBeeDevice      | Generic object, protocol-independent |
+-----------------+--------------------------------------+
| ZigBeeDevice    | Zigbee protocol                      |
+-----------------+--------------------------------------+
| Raw802Device    | 802.15.4 protocol                    |
+-----------------+--------------------------------------+
| DigiMeshDevice  | DigiMesh protocol                    |
+-----------------+--------------------------------------+
| DigiPointDevice | Point-to-multipoint protocol         |
+-----------------+--------------------------------------+
| CellularDevice  | Cellular protocol                    |
+-----------------+--------------------------------------+
| WiFiDevice      | Wi-Fi protocol                       |
+-----------------+--------------------------------------+

To instantiate a generic or protocol-specific XBee device, you need to provide
the following two parameters:

* Serial port name
* Serial port baud rate

**Instantiate a local XBee device**

.. code:: python

  [...]

  xbee = XBeeDevice("COM1", 9600)

  [...]


Remote XBee device
``````````````````

Remote XBee device objects represent remote nodes of the network. These are
XBee devices that are not attached to your PC but operate in the same network
as the attached (local) device.

.. warning::
  When working with remote XBee devices, it is very important to understand
  that you cannot communicate directly with them. You need to provide a local
  XBee device operating in the same network that acts as bridge between your
  serial port and the remote node.

Managing remote devices is similar to managing local devices, but with
limitations. You can configure them, handle their IO lines, and so on, in the
same way you manage local devices. Local XBee devices have several methods for
sending data to remote devices, but the remote devices cannot use these
methods because they are already remote. Therefore, a remote device cannot send
data to another remote device.

In the local XBee device instantiation, you can choose between instantiating a
generic remote XBee device object or a protocol-specific remote XBee device.
The following table lists the remote XBee device classes:

+-----------------------+--------------------------------------+
| Class                 | Description                          |
+=======================+======================================+
| RemoteXBeeDevice      | Generic object, protocol independent |
+-----------------------+--------------------------------------+
| RemoteZigBeeDevice    | Zigbee protocol                      |
+-----------------------+--------------------------------------+
| RemoteRaw802Device    | 802.15.4 protocol                    |
+-----------------------+--------------------------------------+
| RemoteDigiMeshDevice  | DigiMesh protocol                    |
+-----------------------+--------------------------------------+
| RemoteDigiPointDevice | Point-to-multipoint protocol         |
+-----------------------+--------------------------------------+


.. note::
  XBee Cellular and Wi-Fi protocols do not support remote devices.

To instantiate a remote XBee device object, you need to provide the following
parameters:

* Local XBee device attached to your PC that serves as the communication
  interface.
* 64-bit address of the remote device.

``RemoteRaw802Device`` objects can be also instantiated by providing the local
XBee device attached to your PC and the **16-bit address** of the remote
device.

**Instantiate a remote XBee device**

.. code:: python

  [...]

  local_xbee = XBeeDevice("COM1", 9600)
  remote_xbee = RemoteXBeeDevice(local_xbee, XBee64BitAddress.from_hex_string("0013A20012345678"))

  [...]

The local device must also be the same protocol for protocol-specific remote
XBee devices.

.. _openXBeeConnection:

Open the XBee device connection
-------------------------------

Before trying to communicate with the local XBee device attached to your PC,
you need to open its communication interface, which is typically a serial/USB
port. Use the ``open()`` method of the instantiated XBee device, and you can
then communicate and configure the device.

Remote XBee devices do not have an open method. They use a local XBee device
as the connection interface. If you want to perform any operation with a remote
XBee device you must open the connection of the associated local device.

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)

  # Open the device connection.
  local_xbee.open()

  [...]

The ``open()`` method may fail for the following reasons:

* All the possible errors are caught as ``XBeeException``:

    * If there is any problem with the communication, throwing a
      ``TimeoutException``.
    * If the operating mode of the device is not ``API`` or ``API_ESCAPE``,
      throwing an ``InvalidOperatingModeException``.
    * There is an error writing to the XBee interface, or device is closed,
      throwing a generic ``XBeeException``.

The ``open()`` action performs some other operations apart from opening the
connection interface of the device. It reads the device information (reads
some sensitive data from it) and determines the operating mode of the device.

Use ``force_settings=True`` as ``open()`` method parameter, to reconfigure
the XBee serial settings (baud rate, data bits, stop bits, etc.) to those
specified in the XBee object constructor.

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)

  # Open the connection using constructor parameters: 9600 8N1.
  # This reconfigures the XBee if its serial settings do not match.
  local_xbee.open(force_settings=True)

  [...]

+--------------------------------------------------------------------------------------------------------------------------------+
| Example: Recover XBee serial communication                                                                                     |
+================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to recover the serial connection with a local XBee.    |
| It can be located in the following path:                                                                                       |
|                                                                                                                                |
| **examples/configuration/RecoverSerialConnection/RecoverSerialConnection.py**                                                  |
+--------------------------------------------------------------------------------------------------------------------------------+

Read device information
```````````````````````

The read device information process reads the following parameters from the
local or remote XBee device and stores them inside. You can then access
parameters at any time, calling their corresponding getters.

* 64-bit address
* 16-bit address
* Node identifier
* Firmware version
* Hardware version
* IPv4 address (only for cellular and Wi-Fi modules)
* IMEI (only for cellular modules)

The read process is performed automatically in local XBee devices when
opening them with the ``open()`` method. If remote XBee devices cannot be
opened, you must use ``read_device_info()`` to read their device information.

**Initialize a remote XBee device**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)
  local_xbee.open()

  # Instantiate a remote XBee device object.
  remote_xbee = RemoteXBeeDevice(local_xbee, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Read the device information of the remote XBee device.
  remote_xbee.read_device_info()

  [...]

The ``read_device_info()`` method may fail for the following reasons:

* ACK of the command sent is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * If the operating mode of the device is not ``API`` or ``API_ESCAPE``,
      throwing an ``InvalidOperatingModeException``.
    * If the response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, or device is closed,
      throwing a generic ``XBeeException``.

.. note::
  Although the ``readDeviceInfo`` method is executed automatically in local XBee
  devices when they are open, you can issue it at any time to refresh the
  information of the device.

**Get device information**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)
  local_xbee.open()

  # Get the 64-bit address of the device.
  addr_64 = device.get_64bit_addr()
  # Get the node identifier of the device.
  node_id = device.get_node_id()
  # Get the hardware version of the device.
  hardware_version = device.get_hardware_version()
  # Get the firmware version of the device.
  firmware_version = device.get_firmware_version()

The read device information process also determines the communication protocol
of the local or remote XBee device object. This is typically something you
need to know beforehand if you are not using the generic ``XBeeDevice`` object.

However, the API performs this operation to ensure that the class you
instantiated is the correct one. So, if you instantiated a Zigbee device and
the ``open()`` process realizes that the physical device is actually a DigiMesh
device, you receive an ``XBeeDeviceException`` indicating the device mismatch.

You can retrieve the protocol of the XBee device from the object executing the
corresponding getter.

**Get the XBee protocol**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)
  local_xbee.open()

  # Get the protocol of the device.
  protocol = local_xbee.get_protocol()


Device operating mode
`````````````````````

The ``open()`` process also reads the operating mode of the physical local
device and stores it in the object. As with previous settings, you can
retrieve the operating mode from the object at any time by calling the
corresponding getter.

**Get the operating mode**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)
  local_xbee.open()

  # Get the operating mode of the device.
  operating_mode = local_xbee.get_operating_mode()

Remote devices do not have an ``open()`` method, so you receive ``UNKNOWN``
when retrieving the operating mode of a remote XBee device.

The XBee Python Library supports two operating modes for local devices:

* API
* API with escaped characters

This means that AT (transparent) mode is not supported by the API. So, if
you try to execute the ``open()`` method in a local device working in AT mode,
you get an ``XBeeException`` caused by an ``InvalidOperatingModeException``.


Close the XBee device connection
--------------------------------

You must call the ``close()`` method each time you finish your XBee
application. You can use this in the finally block or something similar.

If you don't do this, you may have problems with the packet listener
being executed in a separate thread.

This method guarantees that the listener thread will be stopped and the
serial port will be closed.

**Close the connection**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  local_xbee = XBeeDevice("COM1", 9600)

  try:
      xbee.open()

      [...]

  finally:
      if xbee is not None and xbee.is_open():
          xbee.close()

.. note::
  Remote XBee devices cannot be opened, so they cannot be closed either. To close
  the connection of a remote device you need to close the connection of the local
  associated device.
