Communicate with XBee devices
=============================

The XBee Python Library provides the ability to communicate with remote nodes in
the network. The communication between XBee devices in a network involves the
transmission and reception of data.

.. warning::
  Communication features described in this topic and sub-topics are only
  applicable for local XBee devices. Remote XBee device classes do not include
  methods for transmitting or receiving data.


.. _communicateSendData:

Send data
---------

A data transmission operation sends data from your local (attached) XBee device
to a remote device on the network. The operation sends data in API frames, but
the XBee Python library abstracts the process so you only need to specify the
device you want to send data to and the data itself.

You can send data either using a unicast or broadcast transmission. Unicast
transmissions route data from one source device to one destination device,
whereas broadcast transmissions are sent to all devices in the network.


Send data to one device
```````````````````````

Unicast transmissions are sent from one source device to another destination
device. The destination device could be an immediate neighbor of the source,
or it could be several hops away.

Data transmission can be synchronous or asynchronous, depending on the method
used.


Synchronous operation
'''''''''''''''''''''

This type of operation is blocking. This means the method waits until the
transmit status response is received or the default timeout is reached.

The ``XBeeDevice`` class of the API provides the following method to perform a
synchronous unicast transmission with a remote node of the network:

+---------------------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| Method                                                        | Description                                                                                         |
+===============================================================+=====================================================================================================+
| **send_data(RemoteXBeeDevice, String or Bytearray, Integer)** | Specifies the remote XBee destination object, the data to send and optionally the transmit options. |
+---------------------------------------------------------------+-----------------------------------------------------------------------------------------------------+

Protocol-specific classes offer additional synchronous unicast transmission
methods apart from the one provided by the ``XBeeDevice`` object:

+-----------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XBee class      | Method                                                                          | Description                                                                                                                                                                                       |
+=================+=================================================================================+===================================================================================================================================================================================================+
| ZigBeeDevice    | **send_data(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Raw802Device    | **send_data(XBee16BitAddress, String or Bytearray, Integer)**                   | Specifies the 16-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+                 +---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                 | **send_data(XBee64BitAddress, String or Bytearray, Integer)**                   | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiMeshDevice  | **send_data(XBee64BitAddress, String or Bytearray, Integer)**                   | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiPointDevice | **send_data(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send data synchronously**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Instantiate a remote XBee device object.
  remote_device = RemoteXBeeDevice(device, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send data using the remote object.
  device.send_data(remote_device, "Hello XBee!")

  [...]

The previous methods may fail for the following reasons:

* ACK of the command sent is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

The default timeout to wait for the send status is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout`` and
``set_sync_ops_timeout`` methods of an XBee device class.

**Get/set the timeout for synchronous operations**

.. code:: python

  [...]

  NEW_TIMEOUT_FOR_SYNC_OPERATIONS = 5 # 5 seconds

  device = [...]

  # Retrieving the configured timeout for synchronous operations.
  print("Current timeout: %d seconds" % device.get_sync_ops_timeout())

  [...]

  # Configuring the new timeout (in seconds) for synchronous operations.
  device.set_sync_ops_timeout(NEW_TIMEOUT_FOR_SYNC_OPERATIONS)

  [...]

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Synchronous unicast transmission                                                                                                                                  |
+============================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to send data to another XBee device on the network. The example is located in the following path: |
|                                                                                                                                                                            |
| **examples/communication/SendDataSample**                                                                                                                                  |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Asynchronous operation
''''''''''''''''''''''

Transmitting data asynchronously means that your application does not block
during the transmit process. However, you cannot ensure that the data was
successfully sent to the remote device.

The ``XBeeDevice`` class of the API provides the following method to perform
an asynchronous unicast transmission with a remote node on the network:

+---------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| Method                                                              | Description                                                                                         |
+=====================================================================+=====================================================================================================+
| **send_data_async(RemoteXBeeDevice, String or Bytearray, Integer)** | Specifies the remote XBee destination object, the data to send and optionally the transmit options. |
+---------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------+

Protocol-specific classes offer some other asynchronous unicast transmission
methods in addition to the one provided by the XBeeDevice object:

+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XBee class      | Method                                                                                | Description                                                                                                                                                                                       |
+=================+=======================================================================================+===================================================================================================================================================================================================+
| ZigBeeDevice    | **send_data_async(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Raw802Device    | **send_data_async(XBee16BitAddress, String or Bytearray, Integer)**                   | Specifies the 16-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+                 +---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                 | **send_data_async(XBee64BitAddress, String or Bytearray, Integer)**                   | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiMeshDevice  | **send_data_async(XBee64BitAddress, String or Bytearray, Integer)**                   | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiPointDevice | **send_data_async(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send data asynchronously**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Instantiate a remote XBee device object.
  remote_device = RemoteXBeeDevice(device, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send data using the remote object.
  device.send_data_async(remote_device, "Hello XBee!")

  [...]

The previous methods may fail for the following reasons:

* All the possible errors are caught as an ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Asynchronous unicast transmission                                                                                                                                 |
+============================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to send data to another XBee device asynchronously. The example is located in the following path: |
|                                                                                                                                                                            |
| **examples/communication/SendDataAsyncSample**                                                                                                                             |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateSendBroadcastData:

Send data to all devices of the network
```````````````````````````````````````

Broadcast transmissions are sent from one source device to all the other
devices on the network.

All the XBee device classes (generic and protocol specific) provide the same
method to send broadcast data:

+-------------------------------------------------------+-----------------------------------------------------------------+
| Method                                                | Description                                                     |
+=======================================================+=================================================================+
| **send_data_broadcast(String or Bytearray, Integer)** | Specifies the data to send and optionally the transmit options. |
+-------------------------------------------------------+-----------------------------------------------------------------+

**Send broadcast data**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Send broadcast data.
  device.send_data_broadcast("Hello XBees!")

  [...]

The ``send_data_broadcast`` method may fail for the following reasons:

* Transmit status is not received in the configured timeout, throwing a
  ``TimeoutException`` exception.
* Error types catch as ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * The transmit status is not ``SUCCESS``, throwing a ``TransmitException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Broadcast transmission                                                                                                                                                    |
+====================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to send data to all the devices on the network (broadcast). The example is located in the following path: |
|                                                                                                                                                                                    |
| **examples/communication/SendBroadcastDataSample**                                                                                                                                 |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateSendExplicitData:

Send explicit data
------------------

Some ZigBee applications may require communication with third-party (non-Digi)
RF modules. These applications often send data of different public profiles
such as Home Automation or Smart Energy to other modules.

XBee ZigBee modules offer a special type of frame for this purpose. Explicit
frames transmit explicit data. When sending public profile packets, the frames
transmit the data itself plus the application-layer-specific fields: the source
and destination endpoints, profile ID, and cluster ID.

.. warning::
  Only ZigBee, DigiMesh, and Point-to-Multipoint protocols support the
  transmission of data in explicit format. This means you cannot transmit
  explicit data using a generic XBeeDevice object. You must use a
  protocol-specific XBee device object such as a ZigBeeDevice.

You can send explicit data as either unicast or broadcast transmissions.
Unicast transmissions route data from one source device to one destination
device, whereas broadcast transmissions are sent to all devices in the network.


Send explicit data to one device
````````````````````````````````

Unicast transmissions are sent from one source device to another destination
device. The destination device could be an immediate neighbor of the source,
or it could be several hops away.

Unicast explicit data transmission can be a synchronous or asynchronous
operation, depending on the method used.


Synchronous operation
'''''''''''''''''''''

The synchronous data transmission is a blocking operation. That is, the method
waits until it either receives the transmit status response or the default
timeout is reached.

All local XBee device classes that support explicit data transmission provide a
method to transmit unicast and synchronous explicit data to a remote node of
the network:

+--------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                                 | Description                                                                                                                                                                                        |
+========================================================================================================+====================================================================================================================================================================================================+
| **send_expl_data(RemoteXBeeDevice, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies remote XBee destination object, four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. |
+--------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Every protocol-specific XBee device object with support for explicit data
includes at least one more method to transmit unicast explicit data
synchronously:

+-----------------+--------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XBee class      | Method                                                                                                                   | Description                                                                                                                                                                                                                                                                                                       |
+=================+==========================================================================================================================+===================================================================================================================================================================================================================================================================================================================+
| ZigBeeDevice    | **send_expl_data(XBee64BitAddress, XBee16BitAddress, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses in addition to the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. If the 16-bit address is unknown, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+--------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiMeshDevice  | **send_expl_data(XBee64BitAddress, Integer, Integer, Integer, Integer, String or Bytearray, Integer)**                   | Specifies the 64-bit destination address, the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options.                                                                                                            |
+-----------------+--------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiPointDevice | **send_expl_data(XBee64BitAddress, XBee16BitAddress, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses in addition to the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. If the 16-bit address is unknown, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+--------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send unicast explicit data synchronously**

.. code:: python

  [...]

  # Instantiate a ZigBee device object.
  device = ZigBeeDevice("COM1", 9600)
  device.open()

  # Instantiate a remote ZigBee device object.
  remote_device = RemoteZigBeeDevice(device, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send explicit data using the remote object.
  device.send_expl_data(remote_device, 0xA0, 0xA1, 0x1554, 0xC105, "Hello XBee!")

  [...]

The previous methods may fail for the following reasons:

* The method throws a ``TimeoutException`` exception if the response is not
  received in the configured timeout.
* Other errors register as ``XBeeException``:
    * If the operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``
      , the method throws an ``InvalidOperatingModeException``.
    * If the transmit status is not ``SUCCESS``, the method throws a
      ``TransmitException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.

The default timeout to wait for the send status is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout`` and
``set_sync_ops_timeout`` methods of an XBee device class.

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Transmit explicit synchronous unicast data                                                                                                                                     |
+=========================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send explicit data to a remote device of the network (unicast). It can be located in the following path: |
|                                                                                                                                                                                         |
| **examples/communication/explicit/SendExplicitDataSample**                                                                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Asynchronous operation
''''''''''''''''''''''

Transmitting explicit data asynchronously means that your application does not
block during the transmit process. However, you cannot ensure that the data was
successfully sent to the remote device.

All local XBee device classes that support explicit data transmission provide
a method to transmit unicast and asynchronous explicit data to a remote node
of the network:

+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                                       | Description                                                                                                                                                                                        |
+==============================================================================================================+====================================================================================================================================================================================================+
| **send_expl_data_async(RemoteXBeeDevice, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies remote XBee destination object, four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Every protocol-specific XBee device object that supports explicit data includes
at least one additional method to transmit unicast explicit data asynchronously:

+-----------------+--------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XBee class      | Method                                                                                                                         | Description                                                                                                                                                                                                                                                                                                       |
+=================+================================================================================================================================+===================================================================================================================================================================================================================================================================================================================+
| ZigBeeDevice    | **send_expl_data_async(XBee64BitAddress, XBee16BitAddress, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses in addition to the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. If the 16-bit address is unknown, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+--------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiMeshDevice  | **send_expl_data_async(XBee64BitAddress, Integer, Integer, Integer, Integer, String or Bytearray, Integer)**                   | Specifies the 64-bit destination address, the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options.                                                                                                            |
+-----------------+--------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiPointDevice | **send_expl_data_async(XBee64BitAddress, XBee16BitAddress, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses in addition to the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. If the 16-bit address is unknown, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+--------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send unicast explicit data asynchronously**

.. code:: python

  [...]

  # Instantiate a ZigBee device object.
  device = ZigBeeDevice("COM1", 9600)
  device.open()

  # Instantiate a remote ZigBee device object.
  remote_device = RemoteZigBeeDevice(device, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send explicit data asynchronously using the remote object.
  device.send_expl_data_async(remote_device, 0xA0, 0xA1, 0x1554, 0xC105, "Hello XBee!")

  [...]

The previous methods may fail for the following reasons:

* All the possible errors are caught as an ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Transmit explicit asynchronous unicast data                                                                                                                             |
+==================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send explicit data to other XBee devices asynchronously. It can be located in the following path: |
|                                                                                                                                                                                  |
| **examples/communication/explicit/SendExplicitDataAsyncSample**                                                                                                                  |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateSendBroadcastExplicitData:

Send explicit data to all devices in the network
````````````````````````````````````````````````

Broadcast transmissions are sent from one source device to all other devices in
the network.

All protocol-specific XBee device classes that support the transmission of
explicit data provide the same method to send broadcast explicit data:

+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                         | Description                                                                                                                                                            |
+================================================================================================+========================================================================================================================================================================+
| **send_expl_data_broadcast(Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. |
+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send broadcast data**

.. code:: python

  [...]

  # Instantiate a ZigBee device object.
  device = ZigBeeDevice("COM1", 9600)
  device.open()

  # Send broadcast data.
  device.send_expl_data_broadcast(0xA0, 0xA1, 0x1554, 0xC105, "Hello XBees!")

  [...]

The ``send_expl_data_broadcast`` method may fail for the following reasons:

* Transmit status is not received in the configured timeout, throwing a
  ``TimeoutException`` exception.
* Error types catch as ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * The transmit status is not ``SUCCESS``, throwing a ``TransmitException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Send explicit broadcast data                                                                                                                                                 |
+=======================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send explicit data to all devices in the network (broadcast). It can be located in the following path: |
|                                                                                                                                                                                       |
| **examples/communication/explicit/SendBroadcastExplicitDataSample**                                                                                                                   |
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateSendIPData:

Send IP data
------------

In contrast to XBee protocols like ZigBee, DigiMesh or 802.15.4, where the
devices are connected each other, in cellular and Wi-Fi protocols the modules
are part of the Internet.

XBee Cellular and Wi-Fi modules offer a special type of frame for communicating
with other Internet-connected devices. It allows sending data specifying the
destination IP address, port, and protocol (TCP, TCP SSL or UDP).

.. warning::
  Only cellular, NB-IoT, and Wi-Fi protocols support the transmission of IP data.
  This means you cannot transmit IP data using a generic XBeeDevice object; you
  must use the protocol-specific XBee device objects ``CellularDevice``,
  ``NBIoTDevice``, or ``WiFiDevice``.

IP data transmission can be a synchronous or asynchronous operation, depending
on the method you use.


Synchronous operation
`````````````````````

The synchronous data transmission is a blocking operation; that is, the method
waits until it either receives the transmit status response or it reaches the
default timeout.

The ``CellularDevice``, ``NBIoTDevice``, and ``WiFiDevice`` classes include
several methods to transmit IP data synchronously:

+----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                           | Description                                                                                                                                                                                                 |
+==================================================================================+=============================================================================================================================================================================================================+
| **send_ip_data(IPv4Address, Integer, IPProtocol, String or Bytearray, Boolean)** | Specifies the destination IP address, destination port, IP protocol (UDP, TCP or TCP SSL), data to send for transmissions and whether the socket should be closed after the transmission or not (optional). |
+----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. note::
  NB-IoT modules only support UDP transmissions, so make sure you use that
  protocol when calling the previous methods.

**Send network data synchronously**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Send IP data using TCP.
  dest_addr = IPv4Address("56.23.102.96")
  dest_port = 5050
  protocol = IPProtocol.TCP
  data = "Hello XBee!"

  xbee.send_ip_data(dest_addr, dest_port, protocol, data)

  [...]

The ``send_ip_data`` method may fail for the following reasons:

* There is a timeout setting the IP addressing parameter, throwing a
  ``TimeoutException``.
* Other errors caught as ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Transmit IP data synchronously                                                                                                        |
+================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send IP data. You can locate the example in the following path: |
|                                                                                                                                                |
| **examples/communication/ip/SendIPDataSample**                                                                                                 |
+------------------------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Transmit UDP data                                                                                                                      |
+=================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send UDP data. You can locate the example in the following path: |
|                                                                                                                                                 |
| **examples/communication/ip/SendUDPDataSample**                                                                                                 |
+-------------------------------------------------------------------------------------------------------------------------------------------------+

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Connect to echo server                                                                                                                                                                            |
+============================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to connect to an echo server, send a message to it and receive its response. You can locate the example in the following path: |
|                                                                                                                                                                                                            |
| **examples/communication/ip/ConnectToEchoServerSample**                                                                                                                                                    |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Asynchronous operation
``````````````````````

Transmitting IP data asynchronously means that your application does not block
during the transmit process. However, you cannot ensure that the data was
successfully sent.

The ``CellularDevice``, ``NBIoTDevice``, and ``WiFiDevice`` classes include
several methods to transmit IP data asynchronously:

+----------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                 | Description                                                                                                                                                                                                 |
+========================================================================================+=============================================================================================================================================================================================================+
| **send_ip_data_async(IPv4Address, Integer, IPProtocol, String or Bytearray, Boolean)** | Specifies the destination IP address, destination port, IP protocol (UDP, TCP or TCP SSL), data to send for transmissions and whether the socket should be closed after the transmission or not (optional). |
+----------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. note::
  NB-IoT modules only support UDP transmissions, so make sure you use that
  protocol when calling the previous methods.

**Send network data asynchronously**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Send IP data using TCP.
  dest_addr = IPv4Address("56.23.102.96")
  dest_port = 5050
  protocol = IPProtocol.TCP
  data = "Hello XBee!"

  xbee.send_ip_data_async(dest_addr, dest_port, protocol, data)

  [...]

The ``send_ip_data_async`` method may fail for the following reasons:

* All possible errors are caught as ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


.. _communicateSendSMS:

Send SMS messages
-----------------

Another feature of the XBee Cellular module is the ability to send and receive
Short Message Service (SMS) transmissions. This allows you to send and receive
text messages to and from an SMS capable device such as a mobile phone.

For that purpose, these modules offer a special type of frame for sending text
messages, specifying the destination phone number and data.

.. warning::
  Only cellular protocol supports the transmission of SMS. This means you cannot
  send text messages using a generic ``XBeeDevice`` object; you must use the
  protocol-specific XBee device object ``CellularDevice``.

SMS transmissions can be a synchronous or asynchronous operation, depending on
the method you use.


Synchronous operation
`````````````````````

The synchronous SMS transmission is a blocking operation; that is, the method
waits until it either receives the transmit status response or it reaches the
default timeout.

The ``CellularDevice`` class includes the following method to send SMS messages
synchronously:

+------------------------------+--------------------------------------------------------------------------------------------------------+
| Method                       | Description                                                                                            |
+==============================+========================================================================================================+
| **send_sms(String, String)** | Specifies the the phone number to send the SMS to and the data to send as the body of the SMS message. |
+------------------------------+--------------------------------------------------------------------------------------------------------+

**Send SMS message synchronously**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  phone_number = "+34665963205"
  data = "Hello XBee!"

  # Send SMS message.
  xbee.send_sms(phone_number, data)

  [...]

The ``send_sms`` method may fail for the following reasons:

* If the response is not received in the configured timeout, the method throws
  a ``TimeoutException``.
* If the phone number has an invalid format, the method throws a ``ValueError``.
* Errors register as ``XBeeException``:
    * If the operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``
      , the method throws an ``InvalidOperatingModeException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.

+-----------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Send synchronous SMS                                                                                                                       |
+=====================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send SMS messages. You can locate the example in the following path: |
|                                                                                                                                                     |
| **examples/communication/cellular/SendSMSSample**                                                                                                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+


Asynchronous operation
``````````````````````

Transmitting SMS messages asynchronously means that your application does not
block during the transmit process. However, you cannot verify the SMS was
successfully sent.

The ``CellularDevice`` class includes the following method to send SMS
asynchronously:

+------------------------------------+--------------------------------------------------------------------------------------------------------+
| Method                             | Description                                                                                            |
+====================================+========================================================================================================+
| **send_sms_async(String, String)** | Specifies the the phone number to send the SMS to and the data to send as the body of the SMS message. |
+------------------------------------+--------------------------------------------------------------------------------------------------------+

**Send SMS message asynchronously**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  phone_number = "+34665963205"
  data = "Hello XBee!"

  # Send SMS message.
  xbee.send_sms_async(phone_number, data)

  [...]

The ``send_sms_async`` method may fail for the following reasons:

* If the phone number has an invalid format, the method throws a ``ValueError``.
* Errors register as ``XBeeException``:
    * If the operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``
      , the method throws an ``InvalidOperatingModeException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.


Receive data
------------

The data reception operation allows you to receive and handle data sent by
other remote nodes of the network.

There are two different ways to read data from the device:

* **Polling for data**. This mechanism allows you to read (ask) for new data in
  a polling sequence. The read method blocks until data is received or until a
  configurable timeout has expired.
* **Data reception callback**. In this case, you must register a listener that
  executes a callback each time new data is received by the local XBee device
  (that is, the device attached to your PC) providing data and other related
  information.


.. _communicateReceiveDataPolling:

Polling for data
````````````````

The simplest way to read for data is by executing the ``read_data`` method of
the local XBee device. This method blocks your application until data from any
XBee device of the network is received or the timeout provided has expired:

+------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                 | Description                                                                                                                                                                                                                                                                   |
+========================+===============================================================================================================================================================================================================================================================================+
| **read_data(Integer)** | Specifies the time to wait for data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data. |
+------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Reading data from any remote XBee device (polling)**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Read data.
  xbee_message = device.read_data()

  [...]

The method returns the read data inside an ``XBeeMessage`` object. This object
contains the following information:

* ``RemoteXBeeDevice`` that sent the message.
* Byte array with the contents of the received data.
* Flag indicating if the data was sent via broadcast.
* Time when the message was received.

You can retrieve the previous information using the corresponding attributes of
the ``XBeeMessage`` object:

**Get the XBeeMessage information**

.. code:: python

  [...]

  xbee_message = device.read_data()

  remote_device = xbee_message.remote_device
  data = xbee_message.data
  is_broadcast = xbee_message.is_broadcast
  timestamp = xbee_message.timestamp

  [...]

You can also read data from a specific remote XBee device of the network. For
that purpose, the XBee device object provides the ``read_data_from`` method:

+-----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                        | Description                                                                                                                                                                                                                                                                                                                |
+===============================================+============================================================================================================================================================================================================================================================================================================================+
| **read_data_from(RemoteXBeeDevice, Integer)** | Specifies the remote XBee device to read data from and the time to wait for data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data. |
+-----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read data from a specific remote XBee device (polling)**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Instantiate a remote XBee device object.
  remote_device = RemoteXBeeDevice(device, XBee64BitAddress.from_hex_string("0013A200XXXXXX"))

  # Read data sent by the remote device.
  xbee_message = device.read_data(remote_device)

  [...]

As in the previous method, this method also returns an ``XBeeMessage`` object
with all the information inside.

The default timeout to wait for the send status is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout`` and
``set_sync_ops_timeout`` methods of an XBee device class.

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive data with polling                                                                                                                                  |
+=====================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to receive data using the polling mechanism. The example is located in the following path: |
|                                                                                                                                                                     |
| **examples/communication/ReceiveDataPollingSample**                                                                                                                 |
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveDataCallback:

Data reception callback
```````````````````````

This mechanism for reading data does not block your application. Instead,
you can be notified when new data has been received if you are subscribed or
registered to the data reception service using the
``add_data_received_callback`` method with a data reception callback as
parameter.

**Register for data reception**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Define callback.
  def my_data_received_callback(xbee_message):
      address = xbee_message.remote_device.get_64bit_addr()
      data = xbee_message.data.decode("utf8")
      print("Received data from %s: %s" % (address, data))

  # Add the callback.
  device.add_data_received_callback(my_data_received_callback)

  [...]

When new data is received, your callback is executed providing as parameter an
``XBeeMessage`` object which contains the data and other useful information:

* ``RemoteXBeeDevice`` that sent the message.
* Byte array with the contents of the received data.
* Flag indicating if the data was sent via broadcast.
* Time when the message was received.

To stop listening to new received data, use the ``del_data_received_callback``
method to unsubscribe the already-registered callback.

**Deregister data reception**

.. code:: python

  [...]

  def my_data_received_callback(xbee_message):
      [...]

  device.add_data_received_callback(my_data_received_callback)

  [...]

  # Delete the callback
  device.del_data_received_callback(my_data_received_callback)

  [...]

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Register for data reception                                                                                                                                               |
+====================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to subscribe to the data reception service to receive data. The example is located in the following path: |
|                                                                                                                                                                                    |
| **examples/communication/ReceiveDataSample**                                                                                                                                       |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Receive explicit data
---------------------

Some applications developed with the XBee Python Library may require modules to
receive data in application layer, or explicit, data format.

.. warning::
  Only ZigBee, DigiMesh, and Point-to-Multipoint support the reception of
  explicit data.

To receive data in explicit format, you must first configure the data output
mode of the receiver XBee device to explicit format using the
``set_api_output_mode`` method.

+----------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                 | Description                                                                                                                                                                                                                                                                                                          |
+========================================+======================================================================================================================================================================================================================================================================================================================+
| **get_api_output_mode()**              | Returns the API output mode of the data received by the XBee device.                                                                                                                                                                                                                                                 |
+----------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **set_api_output_mode(APIOutputMode)** | Specifies the API output mode of the data received by the XBee device. The mode can be one of the following:                                                                                                                                                                                                         |
|                                        |   * **APIOutputMode.NATIVE**: The data received by the device will be output as standard received data and it must be read using standard data-reading methods. It does not matter if the data sent by the remote device was sent in standard or explicit format.                                                    |
|                                        |   * **APIOutputMode.EXPLICIT**: The data received by the device will be output as explicit received data and it must be read using explicit data-reading methods. It does not matter if the data sent by the remote device was sent in standard or explicit format.                                                  |
|                                        |   * **APIOutputMode.EXPLICIT_ZDO_PASSTHRU**: The data received by the device will be output as explicit received data, like the **APIOutputMode.EXPLICIT** option. In addition, this mode also outputs as explicit data ZigBee Device Object (ZDO) packets received by the XBee module through the serial interface. |
+----------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Once you have configured the device to receive data in explicit format, you can
read it using one of the following mechanisms provided by the XBee device
object.


.. _communicateReceiveExplicitDataPolling:

Polling for explicit data
`````````````````````````

The simplest way to read for explicit data is by executing the
``read_expl_data`` method of the local XBee device. This method blocks your
application until explicit data from any XBee device of the network is received
or the provided timeout has expired:

+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                      | Description                                                                                                                                                                                                                                                                                       |
+=============================+===================================================================================================================================================================================================================================================================================================+
| **read_expl_data(Integer)** | Specifies the time to wait in seconds for explicit data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data. |
+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read explicit data from any remote XBee device (polling)**

.. code:: python

  [...]

  # Instantiate a ZigBee device object.
  device = ZigBeeDevice("COM1", 9600)
  device.open()

  # Read data.
  xbee_message = device.read_expl_data()

  [...]

The method returns the read data inside an ``ExplicitXBeeMessage`` object. This
object contains the following information:

* ``RemoteXBeeDevice`` that sent the message.
* Endpoint of the source that initiated the transmission.
* Endpoint of the destination where the message is addressed.
* Cluster ID where the data was addressed.
* Profile ID where the data was addressed.
* Byte array with the contents of the received data.
* Flag indicating if the data was sent via broadcast.
* Time when the message was received.

You can retrieve the previous information using the corresponding attributes of
the ``ExplicitXBeeMessage`` object:

**Get the ExplicitXBeeMessage information**

.. code:: python

  [...]

  expl_xbee_message = device.read_expl_data()

  remote_device = expl_xbee_message.remote_device
  source_endpoint = expl_xbee_message.source_endpoint
  dest_endpoint = expl_xbee_message.dest_endpoint
  cluster_id = expl_xbee_message.cluster_id
  profile_id = expl_xbee_message.profile_id
  data = xbee_message.data
  is_broadcast = expl_xbee_message.is_broadcast
  timestamp = expl_xbee_message.timestamp

  [...]

You can also read explicit data from a specific remote XBee device of the
network. For that purpose, the XBee device object provides the
``read_expl_data_from`` method:

+----------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                             | Description                                                                                                                                                                                                                                                                                                                                  |
+====================================================+==============================================================================================================================================================================================================================================================================================================================================+
| **read_expl_data_from(RemoteXBeeDevice, Integer)** | Specifies the remote XBee device to read explicit data from and the time to wait for explicit data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data. |
+----------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read explicit data from a specific remote XBee device (polling)**

.. code:: python

  [...]

  # Instantiate a ZigBee device object.
  device = ZigBeeDevice("COM1", 9600)
  device.open()

  # Instantiate a remote ZigBee device object.
  remote_device = RemoteZigBeeDevice(device, XBee64BitAddress.from_hex_string("0013A200XXXXXX"))

  # Read data sent by the remote device.
  expl_xbee_message = device.read_expl_data(remote_device)

  [...]

As in the previous method, this method also returns an ``ExplicitXBeeMessage``
object with all the information inside.

The default timeout to wait for data is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout`` and
``set_sync_ops_timeout`` methods of an XBee device class.

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive explicit data with polling                                                                                                                                |
+============================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to receive explicit data using the polling mechanism. It can be located in the following path: |
|                                                                                                                                                                            |
| **examples/communication/explicit/ReceiveExplicitDataPollingSample**                                                                                                       |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveExplicitDataCallback:

Explicit data reception callback
````````````````````````````````

This mechanism for reading explicit data does not block your application.
Instead, you can be notified when new explicit data has been received if you
are subscribed or registered to the explicit data reception service by using the
``add_expl_data_received_callback``.

**Explicit data reception registration**

.. code:: python

  [...]

  # Instantiate a ZigBee device object.
  device = ZigBeeDevice("COM1", 9600)
  device.open()

  # Define callback.
  def my_expl_data_received_callback(expl_xbee_message):
      address = expl_xbee_message.remote_device.get_64bit_addr()
      source_endpoint = expl_xbee_message.source_endpoint
      dest_endpoint = expl_xbee_message.dest_endpoint
      cluster = expl_xbee_message.cluster_id
      profile = expl_xbee_message.profile_id
      data = expl_xbee_message.data.decode("utf8")

      print("Received explicit data from %s: %s" % (address, data))

  # Add the callback.
  device.add_expl_data_received_callback(my_expl_data_received_callback)

  [...]

When new explicit data is received, your callback is executed providing as
parameter an ``ExplicitXBeeMessage`` object which contains the data and other
useful information:

* ``RemoteXBeeDevice`` that sent the message.
* Endpoint of the source that initiated the transmission.
* Endpoint of the destination where the message is addressed.
* Cluster ID where the data was addressed.
* Profile ID where the data was addressed.
* Byte array with the contents of the received data.
* Flag indicating if the data was sent via broadcast.
* Time when the message was received.

To stop listening to new received explicit data, use the
``del_expl_data_received_callback`` method to unsubscribe the already-registered
callback.

**Explicit data reception deregistration**

.. code:: python

  [...]

  def my_expl_data_received_callback(xbee_message):
      [...]

  device.add_expl_data_received_callback(my_expl_data_received_callback)

  [...]

  # Delete the callback
  device.del_expl_data_received_callback(my_expl_data_received_callback)

  [...]

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive explicit data via callback                                                                                                                                                                 |
+=============================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to subscribe to the explicit data reception service in order to receive explicit data. It can be located in the following path: |
|                                                                                                                                                                                                             |
| **examples/communication/explicit/ReceiveExplicitDataSample**                                                                                                                                               |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. note::
  If your XBee module is configured to receive explicit data
  (``APIOutputMode.EXPLICIT`` or ``APIOutputMode.EXPLICIT_ZDO_PASSTHRU``) and
  another device sends non-explicit data, you receive an explicit message whose
  application layer field values are:

  * Source endpoint: 0xE8
  * Destination endpoint: 0xE8
  * Cluster ID: 0x0011
  * Profile ID: 0xC10

  When an XBee module receives explicit data with these values, the message
  notifies both data reception callbacks (explicit and non-explicit) in case you
  have registered them. If you read the received data with the polling
  mechanism, you also receive the message through both methods.


.. _communicateReceiveIPData:

Receive IP data
---------------

Some applications developed with the XBee Python Library may require modules to
receive IP data.

.. warning::
  Only cellular, NB-IoT and Wi-Fi protocols support the transmission of IP data.
  This means you cannot receive IP data using a generic ``XBeeDevice`` object;
  you must use the protocol-specific XBee device objects ``CellularDevice``,
  ``NBIoTDevice`` or ``WiFiDevice``.

XBee Cellular and Wi-Fi modules operate the same way as other TCP/IP devices.
They can initiate communications with other devices or listen for TCP or UDP
transmissions at a specific port. In either case, you must apply any of the
receive methods explained in this section in order to read IP data from other
devices.


Listen for incoming transmissions
`````````````````````````````````

If the cellular or Wi-Fi module operates as a server, listening for incoming
TCP or UDP transmissions, you must start listening at a specific port,
similar to the bind operation of a socket. The XBee Python Library
provides a method to listen for incoming transmissions:

+------------------------------+----------------------------------------------------------------------------+
| Method                       | Description                                                                |
+==============================+============================================================================+
| **start_listening(Integer)** | Starts listening for incoming IP transmissions in the provided port.       |
+------------------------------+----------------------------------------------------------------------------+

**Listen for incoming transmissions**

.. code:: python

  [...]


  # Instantiate a Cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()

  # Listen for TCP or UDP transmissions at port 1234.
  device.start_listening(1234);

  [...]

The ``start_listening`` method may fail for the following reasons:

* If the listening port provided is lesser than 0 or greater than 65535, the
  method throws a ``ValueError`` error.
* If there is a timeout setting the listening port, the method throws a
  ``TimeoutException`` exception .
* Errors that register as an ``XBeeException``:
    * If the operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``
      , the method throws an ``InvalidOperatingModeException``.
    * If the response of the listening port command is not valid, the method
      throws an ``ATCommandException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.

You can call the ``stop_listening`` method to stop listening for incoming TCP or
UDP transmissions:

+----------------------+-----------------------------------------------------+
| Method               | Description                                         |
+======================+=====================================================+
| **stop_listening()** | Stops listening for incoming IP transmissions.      |
+----------------------+-----------------------------------------------------+

**Stop listening for incoming transmissions**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()

  # Stop listening for TCP or UDP transmissions.
  device.stop_listening()

  [...]

The ``stop_listening`` method may fail for the following reasons:

* There is a timeout setting the listening port, throwing a
  ``TimeoutException``.
* Other errors caught as ``XBeeException``:
    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


Polling for IP data
```````````````````

The simplest way to read IP data is by executing the ``read_ip_data`` method of
the local Cellular or Wi-Fi devices. This method blocks your application until
IP data is received or the provided timeout has expired.

+---------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                    | Description                                                                                                                                                                                                                          |
+===========================+======================================================================================================================================================================================================================================+
| **read_ip_data(Integer)** | Specifies the time to wait in seconds for IP data reception (method blocks during that time or until IP data is received). If you don't specify a timeout, the method uses the default receive timeout configured in **XBeeDevice**. |
+---------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read IP data (polling)**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()

  # Read IP data.
  ip_message = device.read_ip_data()

  [...]

The method returns the read data inside an ``IPMessage`` object and contains the
following information:

* IP address of the device that sent the data
* Transmission protocol
* Source and destination ports
* Byte array with the contents of the received data

You can retrieve the previous information using the corresponding attributes of
the ``IPMessage`` object:

**Get the IPMessage information**

.. code:: python

  [...]

  # Instantiate a cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()

  # Read IP data.
  ip_message = device.read_ip_data()


  ip_addr = ip_message.ip_addr
  source_port = ip_message.source_port
  dest_port = ip_message.dest_port
  protocol = ip_message.protocol
  data = ip_message.data

  [...]

You can also read IP data that comes from a specific IP address. For that
purpose, the cellular and Wi-Fi device objects provide the ``read_ip_data_from``
method:

**Read IP data from a specific IP address (polling)**

.. code:: python

  [...]

  # Instantiate a cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()

  # Read IP data.
  ip_message = device.read_ip_data_from(IPv4Address("52.36.102.96"))

  [...]

This method also returns an ``IPMessage`` object containing the same information
described before.

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive IP data with polling                                                                                                                                         |
+===============================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to receive IP data using the polling mechanism. You can locate the example in the following path: |
|                                                                                                                                                                               |
| **examples/communication/ip/ConnectToEchoServerSample**                                                                                                                       |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


IP data reception callback
``````````````````````````

This mechanism for reading IP data does not block your application. Instead,
you can be notified when new IP data has been received if you have subscribed
or registered with the IP data reception service by using the
``add_ip_data_received_callback`` method.

**IP data reception registration**

.. code:: python

  [...]

  # Instantiate a Cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()


  # Define the callback.
  def my_ip_data_received_callback(ip_message):
      print("Received IP data from %s: %s" % (ip_message.ip_addr, ip_message.data))

  # Add the callback.
  device.add_ip_data_received_callback(my_ip_data_received_callback)

  [...]

When new IP data is received, your callback is executed providing as parameter
an ``IPMessage`` object which contains the data and other useful information:

* IP address of the device that sent the data
* Transmission protocol
* Source and destination ports
* Byte array with the contents of the received data

To stop listening to new received IP data, use the
``del_ip_data_received_callback`` method to unsubscribe the already-registered
listener.

**Data reception deregistration**

.. code:: python

  [...]

  device = [...]

  def my_ip_data_received_callback(ip_message):
      [...]

  device.add_ip_data_received_callback(my_ip_data_received_callback)

  [...]

  # Delete the IP data callback.
  device.del_ip_data_received_callback(my_ip_data_received_callback)

  [...]

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive IP data with listener                                                                                                                               |
+======================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to receive IP data using the listener. You can locate the example in the following path: |
|                                                                                                                                                                      |
| **examples/communication/ip/ReceiveIPDataSample**                                                                                                                    |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveSMS:

Receive SMS messages
--------------------

Some applications developed with the XBee Python Library may require modules to
receive SMS messages.

.. warning::
  Only cellular modules support the reception of SMS messages.


SMS reception callback
``````````````````````

You can be notified when a new SMS has been received if you are subscribed or
registered to the SMS reception service by using the ``add_sms_callback``
method.

**SMS reception registration**

.. code:: python

  [...]

  # Instantiate a cellular device object.
  device = CellularDevice("COM1", 9600)
  device.open()


  # Define the callback.
  def my_sms_callback(sms_message):
      print("Received SMS from %s: %s" % (sms_message.phone_number, sms_message.data))

  # Add the callback.
  device.add_sms_callback(my_sms_callback)

  [...]

When a new SMS message is received, your callback is executed providing an
``SMSMessage`` object as paramater. This object contains the data and the
phone number that sent the message.

To stop listening to new SMS messages, use the ``del_sms_callback`` method to
unsubscribe the already-registered listener.

**Deregister SMS reception**

.. code:: python

  [...]

  device = [...]

  def my_sms_callback(sms_message):
      [...]

  device.add_sms_callback(my_sms_callback)

  [...]

  # Delete the SMS callback.
  device.del_sms_callback(my_sms_callback)

  [...]

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive SMS messages                                                                                                                                                                              |
+============================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to subscribe to the SMS reception service in order to receive text messages. You can locate the example in the following path: |
|                                                                                                                                                                                                            |
| **examples/communication/cellular/ReceiveSMSSample**                                                                                                                                                       |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveModemStatus:

Receive modem status events
---------------------------

A local XBee device is able to determine when it connects to a network, when it
is disconnected, and when any kind of error or other events occur. The local
device generates these events, and they can be handled using the XBee Python
library via the modem status frames reception.

When a modem status frame is received, you are notified through the callback of
a custom listener so you can take the proper actions depending on the event
received.

For that purpose, you must subscribe or register to the modem status reception
service using a modem status listener as parameter with the method
``add_modem_status_received_callback``.

**Subscribe to modem status reception service**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  device = XBeeDevice("COM1", 9600)
  device.open()

  # Define the callback.
  def my_modem_status_callback(status):
      print("Modem status: %s" % status.description)

  # Add the callback.
  device.add_modem_status_received_callback(my_modem_status_callback)

  [...]

When a new modem status is received, your callback is executed providing as
parameter a ``ModemStatus`` object.

To stop listening to new modem statuses, use the
``del_modem_status_received_callback`` method to unsubscribe the
already-registered listener.

**Deregister modem status**

.. code:: python

  [...]

  device = [...]

  def my_modem_status_callback(status):
      [...]

  device.add_modem_status_received_callback(my_modem_status_callback)

  [...]

  # Delete the modem status callback.
  device.del_modem_status_received_callback(my_modem_status_callback)

  [...]

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Subscribe to modem status reception service                                                                                                                                                      |
+===========================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to subscribe to the modem status reception service to receive modem status events. The example is located in the following path: |
|                                                                                                                                                                                                           |
| **examples/communication/ReceiveModemStatusSample**                                                                                                                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
