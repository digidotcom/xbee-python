Communicate with XBee devices
=============================

The XBee Python Library provides the ability to communicate with remote nodes in
the network, IoT devices and other interfaces of the local device. The
communication between XBee devices in a network involves the transmission and
reception of data.

.. warning::
  Communication features described in this topic and sub-topics are only
  applicable for local XBee devices. Remote XBee classes do not include
  methods for transmitting or receiving data.


Send and receive data
---------------------

XBee modules can communicate with other devices that are on the same network and
use the same radio frequency. The XBee Python Library provides several methods
to send and receive data between the local XBee and any remote on the network.

* :ref:`communicateSendData`
* :ref:`communicateReceiveData`


.. _communicateSendData:

Send data
`````````

A data transmission operation sends data from your local (attached) XBee to a
remote device on the network. The operation sends data in API frames. The XBee
Python Library abstracts the process so you only have to specify the device to
send data to and the data itself.

You can send data either using a unicast or a broadcast transmission. Unicast
transmissions route data from one source device to one destination device,
whereas broadcast transmissions are sent to all devices in the network.


Send data to one device
'''''''''''''''''''''''

Unicast transmissions are sent from one source device to another destination
device. The destination device could be an immediate neighbor of the source,
or it could be several hops away.

Data transmission can be synchronous or asynchronous, depending on the method
used.


Synchronous operation
.....................

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

+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XBee class      | Method                                                                                | Description                                                                                                                                                                                       |
+=================+=======================================================================================+===================================================================================================================================================================================================+
| ZigBeeDevice    | **send_data_64_16(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Raw802Device    | **send_data_16(XBee16BitAddress, String or Bytearray, Integer)**                      | Specifies the 16-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+                 +---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                 | **send_data_64(XBee64BitAddress, String or Bytearray, Integer)**                      | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiMeshDevice  | **send_data_64(XBee64BitAddress, String or Bytearray, Integer)**                      | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiPointDevice | **send_data_64_16(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send data synchronously**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote XBee object.
  remote = RemoteXBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send data using the remote object.
  xbee.send_data(remote, "Hello XBee!")

  [...]

The previous methods may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

The default timeout to wait for the send status is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout()`` and
``set_sync_ops_timeout()`` methods of an XBee class.

**Get/set the timeout for synchronous operations**

.. code:: python

  [...]

  NEW_TIMEOUT_FOR_SYNC_OPERATIONS = 5 # 5 seconds

  xbee = [...]

  # Retrieving the configured timeout for synchronous operations.
  print("Current timeout: %d seconds" % xbee.get_sync_ops_timeout())

  [...]

  # Configuring the new timeout (in seconds) for synchronous operations.
  xbee.set_sync_ops_timeout(NEW_TIMEOUT_FOR_SYNC_OPERATIONS)

  [...]

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Synchronous unicast transmission                                                                                                                                  |
+============================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to send data to another XBee on the network. The example is located in the following path:        |
|                                                                                                                                                                            |
| **examples/communication/SendDataSample**                                                                                                                                  |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Asynchronous operation
......................

Transmitting data asynchronously means that your application does not block
during the transmit process. However, you cannot ensure that the data was
successfully sent to the remote node.

The ``XBeeDevice`` class of the API provides the following method to perform
an asynchronous unicast transmission with a remote node on the network:

+---------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------+
| Method                                                              | Description                                                                                         |
+=====================================================================+=====================================================================================================+
| **send_data_async(RemoteXBeeDevice, String or Bytearray, Integer)** | Specifies the remote XBee destination object, the data to send and optionally the transmit options. |
+---------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------+

Protocol-specific classes offer some other asynchronous unicast transmission
methods in addition to the one provided by the XBeeDevice object:

+-----------------+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XBee class      | Method                                                                                      | Description                                                                                                                                                                                       |
+=================+=============================================================================================+===================================================================================================================================================================================================+
| ZigBeeDevice    | **send_data_async_64_16(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Raw802Device    | **send_data_async_16(XBee16BitAddress, String or Bytearray, Integer)**                      | Specifies the 16-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+                 +---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                 | **send_data_async_64(XBee64BitAddress, String or Bytearray, Integer)**                      | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiMeshDevice  | **send_data_async_64(XBee64BitAddress, String or Bytearray, Integer)**                      | Specifies the 64-bit destination address, the data to send and optionally the transmit options.                                                                                                   |
+-----------------+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DigiPointDevice | **send_data_async_64_16(XBee64BitAddress, XBee16BitAddress, String or Bytearray, Integer)** | Specifies the 64-bit and 16-bit destination addresses, the data to send and optionally the transmit options. If you do not know the 16-bit address, use the ``XBee16BitAddress.UNKNOWN_ADDRESS``. |
+-----------------+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send data asynchronously**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote XBee object.
  remote = RemoteXBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send data using the remote object.
  xbee.send_data_async(remote, "Hello XBee!")

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
| The XBee Python Library includes a sample application that shows you how to send data to another XBee asynchronously. The example is located in the following path:        |
|                                                                                                                                                                            |
| **examples/communication/SendDataAsyncSample**                                                                                                                             |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateSendBroadcastData:

Send data to all devices of the network
'''''''''''''''''''''''''''''''''''''''

Broadcast transmissions are sent from one source device to all the other
devices on the network.

All the XBee classes (generic and protocol specific) provide the same method to
send broadcast data:

+-------------------------------------------------------+-----------------------------------------------------------------+
| Method                                                | Description                                                     |
+=======================================================+=================================================================+
| **send_data_broadcast(String or Bytearray, Integer)** | Specifies the data to send and optionally the transmit options. |
+-------------------------------------------------------+-----------------------------------------------------------------+

**Send broadcast data**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Send broadcast data.
  xbee.send_data_broadcast("Hello XBees!")

  [...]

The ``send_data_broadcast()`` method may fail for the following reasons:

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


.. _communicateReceiveData:

Receive data
````````````

The data reception operation allows you to receive and handle data sent by
other remote nodes of the network.

There are two different ways to read data from the device:

* **Polling for data**. This mechanism allows you to read (ask) for new data in
  a polling sequence. The read method blocks until data is received or until a
  configurable timeout has expired.
* **Data reception callback**. In this case, you must register a listener that
  executes a callback each time new data is received by the local XBee (that is,
  the device attached to your PC) providing data and other related information.


.. _communicateReceiveDataPolling:

Polling for data
''''''''''''''''

The simplest way to read for data is by executing the ``read_data()`` method of
the local XBee. This method blocks your application until data from any XBee
on the network is received or the provided timeout expires:

+------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                 | Description                                                                                                                                                                                                                                                                   |
+========================+===============================================================================================================================================================================================================================================================================+
| **read_data(Integer)** | Specifies the time to wait for data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data. |
+------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Reading data from any remote XBee (polling)**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Read data.
  xbee_message = xbee.read_data()

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

  xbee_message = xbee.read_data()

  remote = xbee_message.remote_device
  data = xbee_message.data
  is_broadcast = xbee_message.is_broadcast
  timestamp = xbee_message.timestamp

  [...]

You can also read data from a specific remote XBee of the network. For that
purpose, the XBee object provides the ``read_data_from()`` method:

+-----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                        | Description                                                                                                                                                                                                                                                                                                                |
+===============================================+============================================================================================================================================================================================================================================================================================================================+
| **read_data_from(RemoteXBeeDevice, Integer)** | Specifies the remote XBee to read data from and the time to wait for data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data.        |
+-----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read data from a specific remote XBee (polling)**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote XBee object.
  remote = RemoteXBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A200XXXXXX"))

  # Read data sent by the remote device.
  xbee_message = xbee.read_data(remote)

  [...]

As in the previous method, this method also returns an ``XBeeMessage`` object
with all the information inside.

The default timeout to wait for the send status is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout()`` and
``set_sync_ops_timeout()`` methods of an XBee class.

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive data with polling                                                                                                                                  |
+=====================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to receive data using the polling mechanism. The example is located in the following path: |
|                                                                                                                                                                     |
| **examples/communication/ReceiveDataPollingSample**                                                                                                                 |
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveDataCallback:

Data reception callback
'''''''''''''''''''''''

This mechanism for reading data does not block your application. Instead,
you can be notified when new data has been received if you are subscribed or
registered to the data reception service using the
``add_data_received_callback()`` method with a data reception callback as
parameter.

**Register for data reception**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Define callback.
  def my_data_received_callback(xbee_message):
      address = xbee_message.remote_device.get_64bit_addr()
      data = xbee_message.data.decode("utf8")
      print("Received data from %s: %s" % (address, data))

  # Add the callback.
  xbee.add_data_received_callback(my_data_received_callback)

  [...]

When new data is received, your callback is executed providing as parameter an
``XBeeMessage`` object which contains the data and other useful information:

* ``RemoteXBeeDevice`` that sent the message.
* Byte array with the contents of the received data.
* Flag indicating if the data was sent via broadcast.
* Time when the message was received.

To stop listening to new received data, use the ``del_data_received_callback()``
method to unsubscribe the already-registered callback.

**Deregister data reception**

.. code:: python

  [...]

  def my_data_received_callback(xbee_message):
      [...]

  xbee.add_data_received_callback(my_data_received_callback)

  [...]

  # Delete the callback
  xbee.del_data_received_callback(my_data_received_callback)

  [...]

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Register for data reception                                                                                                                                               |
+====================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to subscribe to the data reception service to receive data. The example is located in the following path: |
|                                                                                                                                                                                    |
| **examples/communication/ReceiveDataSample**                                                                                                                                       |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Send and receive explicit data
------------------------------

Some Zigbee applications may require communication with third-party (non-Digi)
RF modules. These applications often send and receive data on different public
profiles such as Home Automation or Smart Energy to other modules.

XBee Zigbee modules offer a special type of frame for this purpose. Explicit
frames are used to transmit and receive explicit data. When sending public
profile packets, the frames transmit the data itself plus the application
layer-specific fields—the source and destination endpoints, profile ID, and
cluster ID.

.. warning::
  Only Zigbee, DigiMesh, and Point-to-Multipoint protocols support the
  transmission and reception of data in explicit format. This means you cannot
  transmit or receive explicit data using a generic ``XBeeDevice`` object. You
  must use a protocol-specific XBee object such as a ``ZigBeeDevice``.

* :ref:`communicateSendExplicitData`
* :ref:`communicateReceiveExplicitData`


.. _communicateSendExplicitData:

Send explicit data
``````````````````

You can send explicit data as either unicast or broadcast transmissions.
Unicast transmissions route data from one source device to one destination
device, whereas broadcast transmissions are sent to all devices in the network.


Send explicit data to one device
''''''''''''''''''''''''''''''''

Unicast transmissions are sent from one source device to another destination
device. The destination device could be an immediate neighbor of the source,
or it could be several hops away.

Unicast explicit data transmission can be a synchronous or asynchronous
operation, depending on the method used.


Synchronous operation
.....................

The synchronous data transmission is a blocking operation. That is, the method
waits until it either receives the transmit status response or the default
timeout is reached.

All local XBee classes that support explicit data transmission provide a method
to transmit unicast and synchronous explicit data to a remote node of the
network:

+--------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                                 | Description                                                                                                                                                                                        |
+========================================================================================================+====================================================================================================================================================================================================+
| **send_expl_data(RemoteXBeeDevice, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies remote XBee destination object, four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. |
+--------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send unicast explicit data synchronously**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote Zigbee object.
  remote = RemoteZigBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send explicit data using the remote object.
  xbee.send_expl_data(remote, 0xA0, 0xA1, 0x1554, 0xC105, "Hello XBee!")

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
can configure the timeout using the ``get_sync_ops_timeout()`` and
``set_sync_ops_timeout()`` methods of an XBee class.

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Transmit explicit synchronous unicast data                                                                                                                                     |
+=========================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send explicit data to a remote device of the network (unicast). It can be located in the following path: |
|                                                                                                                                                                                         |
| **examples/communication/explicit/SendExplicitDataSample**                                                                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Asynchronous operation
......................

Transmitting explicit data asynchronously means that your application does not
block during the transmit process. However, you cannot ensure that the data was
successfully sent to the remote device.

All local XBee classes that support explicit data transmission provide
a method to transmit unicast and asynchronous explicit data to a remote node
of the network:

+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                                       | Description                                                                                                                                                                                        |
+==============================================================================================================+====================================================================================================================================================================================================+
| **send_expl_data_async(RemoteXBeeDevice, Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies remote XBee destination object, four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send unicast explicit data asynchronously**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote Zigbee object.
  remote = RemoteZigBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Send explicit data asynchronously using the remote object.
  xbee.send_expl_data_async(remote, 0xA0, 0xA1, 0x1554, 0xC105, "Hello XBee!")

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
''''''''''''''''''''''''''''''''''''''''''''''''

Broadcast transmissions are sent from one source device to all other devices in
the network.

All protocol-specific XBee classes that support the transmission of explicit
data provide the same method to send broadcast explicit data:

+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                         | Description                                                                                                                                                            |
+================================================================================================+========================================================================================================================================================================+
| **send_expl_data_broadcast(Integer, Integer, Integer, Integer, String or Bytearray, Integer)** | Specifies the four application layer fields (source endpoint, destination endpoint, cluster ID, and profile ID), the data to send and optionally the transmit options. |
+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send broadcast data**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

  # Send broadcast data.
  xbee.send_expl_data_broadcast(0xA0, 0xA1, 0x1554, 0xC105, "Hello XBees!")

  [...]

The ``send_expl_data_broadcast()`` method may fail for the following reasons:

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

.. _communicateReceiveExplicitData:

Receive explicit data
`````````````````````

Some applications developed with the XBee Python Library may require modules to
receive data in application layer, or explicit, data format.

To receive data in explicit format, configure the data output mode of the
receiver XBee to explicit format using the ``set_api_output_mode_value()``
method.

+----------------------------------------+----------------------------------------------------------------------------------------------+
| Method                                 | Description                                                                                  |
+========================================+==============================================================================================+
| **get_api_output_mode_value()**        | Returns the API output mode of the data received by the XBee.                                |
+----------------------------------------+----------------------------------------------------------------------------------------------+
| **set_api_output_mode_value(Integer)** | Specifies the API output mode of the data received by the XBee. Calculate the mode           |
|                                        | with the method `calculate_api_output_mode_value` with a set of `APIOutputModeBit`.          |
+----------------------------------------+----------------------------------------------------------------------------------------------+

**Set API output mode**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

  # Set explicit output mode
  mode = APIOutputModeBit.calculate_api_output_mode_value(xbee.get_protocol(),
    {APIOutputModeBit.EXPLICIT})
  xbee.set_api_output_mode_value(mode)

  # Set native output mode
  mode = 0
  xbee.set_api_output_mode_value(mode)

  # Set explicit plus unsupported ZDO request pass-through
  mode = APIOutputModeBit.calculate_api_output_mode_value(xbee.get_protocol(),
    {APIOutputModeBit.EXPLICIT, APIOutputModeBit.UNSUPPORTED_ZDO_PASSTHRU})
  xbee.set_api_output_mode_value(mode)

  [...]

Once you have configured the device to receive data in explicit format, you can
read it using one of the following mechanisms provided by the XBee device
object.


.. _communicateReceiveExplicitDataPolling:

Polling for explicit data
'''''''''''''''''''''''''

The simplest way to read for explicit data is by executing the
``read_expl_data()`` method of the local XBee. This method blocks your
application until explicit data from any XBee device of the network is received
or the provided timeout has expired:

+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                      | Description                                                                                                                                                                                                                                                                                       |
+=============================+===================================================================================================================================================================================================================================================================================================+
| **read_expl_data(Integer)** | Specifies the time to wait in seconds for explicit data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data. |
+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read explicit data from any remote XBee (polling)**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

  # Read data.
  xbee_message = xbee.read_expl_data()

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

  expl_xbee_message = xbee.read_expl_data()

  remote = expl_xbee_message.remote_device
  source_endpoint = expl_xbee_message.source_endpoint
  dest_endpoint = expl_xbee_message.dest_endpoint
  cluster_id = expl_xbee_message.cluster_id
  profile_id = expl_xbee_message.profile_id
  data = xbee_message.data
  is_broadcast = expl_xbee_message.is_broadcast
  timestamp = expl_xbee_message.timestamp

  [...]

You can also read explicit data from a specific remote XBee of the network. For
that purpose, the XBee object provides the ``read_expl_data_from()`` method:

+----------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                             | Description                                                                                                                                                                                                                                                                                                                                  |
+====================================================+==============================================================================================================================================================================================================================================================================================================================================+
| **read_expl_data_from(RemoteXBeeDevice, Integer)** | Specifies the remote XBee to read explicit data from and the time to wait for explicit data reception (method blocks during that time and throws a ``TimeoutException`` if no data is received). If you do not specify a timeout, the method returns immediately the read message or ``None`` if the device did not receive new data.        |
+----------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read explicit data from a specific remote XBee (polling)**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote Zigbee object.
  remote = RemoteZigBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A200XXXXXX"))

  # Read data sent by the remote device.
  expl_xbee_message = xbee.read_expl_data(remote)

  [...]

As in the previous method, this method also returns an ``ExplicitXBeeMessage``
object with all the information inside.

The default timeout to wait for data is two seconds. However, you
can configure the timeout using the ``get_sync_ops_timeout()`` and
``set_sync_ops_timeout()`` methods of an XBee class.

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive explicit data with polling                                                                                                                                |
+============================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to receive explicit data using the polling mechanism. It can be located in the following path: |
|                                                                                                                                                                            |
| **examples/communication/explicit/ReceiveExplicitDataPollingSample**                                                                                                       |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveExplicitDataCallback:

Explicit data reception callback
''''''''''''''''''''''''''''''''

This mechanism for reading explicit data does not block your application.
Instead, you can be notified when new explicit data has been received if you
are subscribed or registered to the explicit data reception service by using the
``add_expl_data_received_callback()``.

**Explicit data reception registration**

.. code:: python

  [...]

  # Instantiate a local Zigbee object.
  xbee = ZigBeeDevice("COM1", 9600)
  xbee.open()

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
  xbee.add_expl_data_received_callback(my_expl_data_received_callback)

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
``del_expl_data_received_callback()`` method to unsubscribe the
already-registered callback.

**Explicit data reception deregistration**

.. code:: python

  [...]

  def my_expl_data_received_callback(xbee_message):
      [...]

  xbee.add_expl_data_received_callback(my_expl_data_received_callback)

  [...]

  # Delete the callback
  xbee.del_expl_data_received_callback(my_expl_data_received_callback)

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
  (API output mode greater than 0) and another device sends non-explicit data or
  a IO sample, you receive an explicit message whose application layer field
  values are:

  * For remote data:

    * Source endpoint: 0xE8
    * Destination endpoint: 0xE8
    * Cluster ID: 0x0011
    * Profile ID: 0xC105

  * For remote IO sample:

    * Source endpoint: 0xE8
    * Destination endpoint: 0xE8
    * Cluster ID: 0x0092
    * Profile ID: 0xC105

  That is, when an XBee receives explicit data with these values, the message
  notifies the following reception callbacks in case you have registered them:

  * Explicit and non-explicit data callbacks when receiving remote data.
  * Explicit data callback and IO sample callback when receiving remote samples.

  If you read the received data with the polling mechanism, you also receive
  the message through both methods.


.. _communicateSendReceiveIPData:

Send and receive IP data
------------------------

In contrast to XBee protocols like Zigbee, DigiMesh or 802.15.4, where the
devices are connected each other, in cellular and Wi-Fi protocols the modules
are part of the Internet.

XBee Cellular and Wi-Fi modules offer a special type of frame for communicating
with other Internet-connected devices. It allows sending and receiving data
specifying the destination IP address, port, and protocol (TCP, TCP SSL or UDP).

.. warning::
  Only Cellular and Wi-Fi protocols support the transmission and reception of IP
  data. This means you cannot transmit or receive IP data using a generic
  ``XBeeDevice`` object; you must use the protocol-specific XBee objects
  ``CellularDevice`` or ``WiFiDevice``.

* :ref:`communicateSendIPData`
* :ref:`communicateReceiveIPData`

.. _communicateSendIPData:

Send IP data
````````````

IP data transmission can be a synchronous or asynchronous operation, depending
on the method you use.


Synchronous operation
'''''''''''''''''''''

The synchronous data transmission is a blocking operation; that is, the method
waits until it either receives the transmit status response or it reaches the
default timeout.

The ``CellularDevice`` and ``WiFiDevice`` classes include several methods to
transmit IP data synchronously:

+----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                           | Description                                                                                                                                                                                                 |
+==================================================================================+=============================================================================================================================================================================================================+
| **send_ip_data(IPv4Address, Integer, IPProtocol, String or Bytearray, Boolean)** | Specifies the destination IP address, destination port, IP protocol (UDP, TCP or TCP SSL), data to send for transmissions and whether the socket should be closed after the transmission or not (optional). |
+----------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send network data synchronously**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Send IP data using TCP.
  dest_addr = IPv4Address("56.23.102.96")
  dest_port = 5050
  protocol = IPProtocol.TCP
  data = "Hello XBee!"

  xbee.send_ip_data(dest_addr, dest_port, protocol, data)

  [...]

The ``send_ip_data()`` method may fail for the following reasons:

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
''''''''''''''''''''''

Transmitting IP data asynchronously means that your application does not block
during the transmit process. However, you cannot ensure that the data was
successfully sent.

The ``CellularDevice`` and ``WiFiDevice`` classes include several methods to
transmit IP data asynchronously:

+----------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                                                 | Description                                                                                                                                                                                                 |
+========================================================================================+=============================================================================================================================================================================================================+
| **send_ip_data_async(IPv4Address, Integer, IPProtocol, String or Bytearray, Boolean)** | Specifies the destination IP address, destination port, IP protocol (UDP, TCP or TCP SSL), data to send for transmissions and whether the socket should be closed after the transmission or not (optional). |
+----------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Send network data asynchronously**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Send IP data using TCP.
  dest_addr = IPv4Address("56.23.102.96")
  dest_port = 5050
  protocol = IPProtocol.TCP
  data = "Hello XBee!"

  xbee.send_ip_data_async(dest_addr, dest_port, protocol, data)

  [...]

The ``send_ip_data_async()`` method may fail for the following reasons:

* All possible errors are caught as ``XBeeException``:

    * The operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


.. _communicateReceiveIPData:

Receive IP data
```````````````

Some applications developed with the XBee Python Library may require modules to
receive IP data.

XBee Cellular and Wi-Fi modules operate the same way as other TCP/IP devices.
They can initiate communications with other devices or listen for TCP or UDP
transmissions at a specific port. In either case, you must apply any of the
receive methods explained in this section in order to read IP data from other
devices.


Listen for incoming transmissions
'''''''''''''''''''''''''''''''''

If the cellular or Wi-Fi module operates as a server, listening for incoming
TCP or UDP transmissions, you must start listening at a specific port,
similar to the bind operation of a socket. The XBee Python Library
provides a method to listen for incoming transmissions:

+------------------------------+----------------------------------------------------------------------+
| Method                       | Description                                                          |
+==============================+======================================================================+
| **start_listening(Integer)** | Starts listening for incoming IP transmissions in the provided port. |
+------------------------------+----------------------------------------------------------------------+

**Listen for incoming transmissions**

.. code:: python

  [...]


  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Listen for TCP or UDP transmissions at port 1234.
  xbee.start_listening(1234);

  [...]

The ``start_listening()`` method may fail for the following reasons:

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

You can call the ``stop_listening()`` method to stop listening for incoming TCP
or UDP transmissions:

+----------------------+-----------------------------------------------------+
| Method               | Description                                         |
+======================+=====================================================+
| **stop_listening()** | Stops listening for incoming IP transmissions.      |
+----------------------+-----------------------------------------------------+

**Stop listening for incoming transmissions**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Stop listening for TCP or UDP transmissions.
  xbee.stop_listening()

  [...]

The ``stop_listening()`` method may fail for the following reasons:

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
'''''''''''''''''''

The simplest way to read IP data is by executing the ``read_ip_data()`` method
of the local Cellular or Wi-Fi devices. This method blocks your application
until IP data is received or the provided timeout has expired.

+---------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                    | Description                                                                                                                                                                                                                          |
+===========================+======================================================================================================================================================================================================================================+
| **read_ip_data(Integer)** | Specifies the time to wait in seconds for IP data reception (method blocks during that time or until IP data is received). If you don't specify a timeout, the method uses the default receive timeout configured in **XBeeDevice**. |
+---------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Read IP data (polling)**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Read IP data.
  ip_message = xbee.read_ip_data()

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

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Read IP data.
  ip_message = xbee.read_ip_data()


  ip_addr = ip_message.ip_addr
  source_port = ip_message.source_port
  dest_port = ip_message.dest_port
  protocol = ip_message.protocol
  data = ip_message.data

  [...]

You can also read IP data that comes from a specific IP address. For that
purpose, the cellular and Wi-Fi device objects provide the
``read_ip_data_from()`` method:

**Read IP data from a specific IP address (polling)**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Read IP data.
  ip_message = xbee.read_ip_data_from(IPv4Address("52.36.102.96"))

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
''''''''''''''''''''''''''

This mechanism for reading IP data does not block your application. Instead,
you can be notified when new IP data has been received if you have subscribed
or registered with the IP data reception service by using the
``add_ip_data_received_callback()`` method.

**IP data reception registration**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()


  # Define the callback.
  def my_ip_data_received_callback(ip_message):
      print("Received IP data from %s: %s" % (ip_message.ip_addr, ip_message.data))

  # Add the callback.
  xbee.add_ip_data_received_callback(my_ip_data_received_callback)

  [...]

When new IP data is received, your callback is executed providing as parameter
an ``IPMessage`` object which contains the data and other useful information:

* IP address of the device that sent the data
* Transmission protocol
* Source and destination ports
* Byte array with the contents of the received data

To stop listening to new received IP data, use the
``del_ip_data_received_callback()`` method to unsubscribe the already-registered
listener.

**Data reception deregistration**

.. code:: python

  [...]

  xbee = [...]

  def my_ip_data_received_callback(ip_message):
      [...]

  xbee.add_ip_data_received_callback(my_ip_data_received_callback)

  [...]

  # Delete the IP data callback.
  xbee.del_ip_data_received_callback(my_ip_data_received_callback)

  [...]

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive IP data with listener                                                                                                                               |
+======================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to receive IP data using the listener. You can locate the example in the following path: |
|                                                                                                                                                                      |
| **examples/communication/ip/ReceiveIPDataSample**                                                                                                                    |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Send and receive SMS messages
-----------------------------

Another feature of the XBee Cellular module is the ability to send and receive
Short Message Service (SMS) transmissions. This allows you to send and receive
text messages to and from an SMS capable device such as a mobile phone.

For that purpose, these modules offer a special type of frame for sending and
receiving text messages, specifying the destination phone number and data.

.. warning::
  Only Cellular protocol supports the transmission and reception of SMS. This
  means you cannot send or receive text messages using a generic ``XBeeDevice``
  object; you must use the protocol-specific XBee object ``CellularDevice``.

* :ref:`communicateSendSMS`
* :ref:`communicateReceiveSMS`


.. _communicateSendSMS:

Send SMS messages
`````````````````

SMS transmissions can be a synchronous or asynchronous operation, depending on
the method you use.


Synchronous operation
'''''''''''''''''''''

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

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  phone_number = "+34665963205"
  data = "Hello XBee!"

  # Send SMS message.
  xbee.send_sms(phone_number, data)

  [...]

The ``send_sms()`` method may fail for the following reasons:

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
''''''''''''''''''''''

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

  # Instantiate an XBee Cellular object.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  phone_number = "+34665963205"
  data = "Hello XBee!"

  # Send SMS message.
  xbee.send_sms_async(phone_number, data)

  [...]

The ``send_sms_async()`` method may fail for the following reasons:

* If the phone number has an invalid format, the method throws a ``ValueError``.
* Errors register as ``XBeeException``:

    * If the operating mode of the device is not ``API`` or ``ESCAPED_API_MODE``
      , the method throws an ``InvalidOperatingModeException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.


.. _communicateReceiveSMS:

Receive SMS messages
````````````````````

Some applications developed with the XBee Python Library may require modules to
receive SMS messages.


SMS reception callback
''''''''''''''''''''''

You can be notified when a new SMS has been received if you are subscribed or
registered to the SMS reception service by using the ``add_sms_callback()``
method.

**SMS reception registration**

.. code:: python

  [...]

  # Instantiate an XBee Cellular object.
  xbee CellularDevice("COM1", 9600)
  xbee.open()


  # Define the callback.
  def my_sms_callback(sms_message):
      print("Received SMS from %s: %s" % (sms_message.phone_number, sms_message.data))

  # Add the callback.
  xbee.add_sms_callback(my_sms_callback)

  [...]

When a new SMS message is received, your callback is executed providing an
``SMSMessage`` object as parameter. This object contains the data and the
phone number that sent the message.

To stop listening to new SMS messages, use the ``del_sms_callback()`` method to
unsubscribe the already-registered listener.

**Deregister SMS reception**

.. code:: python

  [...]

  xbee = [...]

  def my_sms_callback(sms_message):
      [...]

  xbee.add_sms_callback(my_sms_callback)

  [...]

  # Delete the SMS callback.
  xbee.del_sms_callback(my_sms_callback)

  [...]

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive SMS messages                                                                                                                                                                              |
+============================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to subscribe to the SMS reception service in order to receive text messages. You can locate the example in the following path: |
|                                                                                                                                                                                                            |
| **examples/communication/cellular/ReceiveSMSSample**                                                                                                                                                       |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Send and receive Bluetooth data
-------------------------------

XBee 3 modules have the ability to send and receive data from the Bluetooth Low
Energy interface of the local XBee through User Data Relay frames. This can be
useful if your application wants to transmit or receive data from a cellphone
connected to it over BLE.

.. warning::
  Only XBee 3 modules support Bluetooth Low Energy. This means that you cannot
  transmit or receive Bluetooth data if you don't have one of these modules.

* :ref:`communicateSendBluetoothData`
* :ref:`communicateReceiveBluetoothData`


.. _communicateSendBluetoothData:

Send Bluetooth data
```````````````````

The ``XBeeDevice`` class and its subclasses provide the following method to
send data to the Bluetooth Low Energy interface:

+------------------------------------+-------------------------------------------------------------------+
| Method                             | Description                                                       |
+====================================+===================================================================+
| **send_bluetooth_data(Bytearray)** | Specifies the data to send to the Bluetooth Low Energy interface. |
+------------------------------------+-------------------------------------------------------------------+

This method is asynchronous, which means that your application does not block
during the transmit process.

**Send data to Bluetooth**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  data = "Bluetooth, are you there?"

  # Send the data to the Bluetooth interface.
  xbee.send_bluetooth_data(data.encode("utf8"))

  [...]

The ``send_bluetooth_data()`` method may fail for the following reasons:

* Errors register as ``XBeeException``:

    * If the operating mode of the device is not ``API`` or
      ``ESCAPED_API_MODE``, the method throws an
      ``InvalidOperatingModeException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Send Bluetooth data                                                                                                                                           |
+========================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send data to the Bluetooth interface. You can locate the example in the following path: |
|                                                                                                                                                                        |
| **examples/communication/bluetooth/SendBluetoothDataSample**                                                                                                           |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveBluetoothData:

Receive Bluetooth data
``````````````````````

You can be notified when new data from the Bluetooth Low Energy interface has
been received if you are subscribed or registered to the Bluetooth data
reception service by using the ``add_bluetooth_data_received_callback()`` method.

**Bluetooth data reception registration**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Define the callback.
  def my_bluetooth_data_callback(data):
      print("Data received from the Bluetooth interface >> '%s'" % data.decode("utf-8"))

  # Add the callback.
  xbee.add_bluetooth_data_received_callback(my_bluetooth_data_callback)

  [...]

When a new data from the Bluetooth interface is received, your callback is
executed providing the data in byte array format as parameter.

To stop listening to new data messages from the Bluetooth interface, use the
``del_bluetooth_data_received_callback()`` method to unsubscribe the
already-registered listener.

**Deregister Bluetooth data reception**

.. code:: python

  [...]

  xbee = [...]

  def my_bluetooth_data_callback(data):
      [...]

  xbee.add_bluetooth_data_received_callback(my_bluetooth_data_callback)

  [...]

  # Delete the Bluetooth data callback.
  xbee.del_bluetooth_data_received_callback(my_bluetooth_data_callback)

  [...]

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive Bluetooth data                                                                                                                                                                                                                      |
+======================================================================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to subscribe to the Bluetooth data reception service in order to receive data from the Bluetooth Low Energy interface. You can locate the example in the following path: |
|                                                                                                                                                                                                                                                      |
| **examples/communication/bluetooth/ReceiveBluetoothDataSample**                                                                                                                                                                                      |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Send and receive MicroPython data
---------------------------------

XBee 3 modules have the ability to send and receive data from the MicroPython
interface of the local XBee through User Data Relay frames. This can be useful
if your application wants to transmit or receive data from a MicroPython program
running on the module.

.. warning::
  Only XBee 3 and XBee Cellular modules support MicroPython. This means that you
  cannot transmit or receive MicroPython data if you don't have one of these
  modules.

* :ref:`communicateSendMicroPythonData`
* :ref:`communicateReceiveMicroPythonData`


.. _communicateSendMicroPythonData:

Send MicroPython data
`````````````````````

The ``XBeeDevice`` class and its subclasses provide the following method to
send data to the MicroPython interface:

+--------------------------------------+----------------------------------------------------------+
| Method                               | Description                                              |
+======================================+==========================================================+
| **send_micropython_data(Bytearray)** | Specifies the data to send to the MicroPython interface. |
+--------------------------------------+----------------------------------------------------------+

This method is asynchronous, which means that your application does not block
during the transmit process.

**Send data to MicroPython**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  data = "MicroPython, are you there?"

  # Send the data to the MicroPython interface.
  xbee.send_micropython_data(data.encode("utf8"))

  [...]

The ``send_micropython_data()`` method may fail for the following reasons:

* Errors register as ``XBeeException``:

    * If the operating mode of the device is not ``API`` or
      ``ESCAPED_API_MODE``, the method throws an
      ``InvalidOperatingModeException``.
    * If there is an error writing to the XBee interface, the method throws a
      generic ``XBeeException``.

+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Send MicroPython data                                                                                                                                           |
+==========================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to send data to the MicroPython interface. You can locate the example in the following path: |
|                                                                                                                                                                          |
| **examples/communication/micropython/SendMicroPythonDataSample**                                                                                                         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveMicroPythonData:

Receive MicroPython data
````````````````````````

You can be notified when new data from the MicroPython interface has been
received if you are subscribed or registered to the MicroPython data reception
service by using the ``add_micropython_data_received_callback()`` method.

**MicroPython data reception registration**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Define the callback.
  def my_micropython_data_callback(data):
      print("Data received from the MicroPython interface >> '%s'" % data.decode("utf-8"))

  # Add the callback.
  xbee.add_micropython_data_received_callback(my_micropython_data_callback)

  [...]

When a new data from the MicroPython interface is received, your callback is
executed providing the data in byte array format as parameter.

To stop listening to new data messages from the MicroPython interface, use the
``del_micropython_data_received_callback()`` method to unsubscribe the
already-registered listener.

**Deregister MicroPython data reception**

.. code:: python

  [...]

  xbee = [...]

  def my_micropython_data_callback(data):
      [...]

  xbee.add_micropython_data_received_callback(my_micropython_data_callback)

  [...]

  # Delete the MicroPython data callback.
  xbee.del_micropython_data_received_callback(my_micropython_data_callback)

  [...]

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive MicroPython data                                                                                                                                                                                                             |
+===============================================================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to subscribe to the MicroPython data reception service in order to receive data from the MicroPython interface. You can locate the example in the following path: |
|                                                                                                                                                                                                                                               |
| **examples/communication/micropython/ReceiveMicroPythonDataSample**                                                                                                                                                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateReceiveModemStatus:

Receive modem status events
---------------------------

A local XBee is able to determine when it connects to a network, when it is
disconnected, and when any kind of error or other events occur. The local device
generates these events, and they can be handled using the XBee Python Library
via the modem status frames reception.

When a modem status frame is received, you are notified through the callback of
a custom listener so you can take the proper actions depending on the event
received.

For that purpose, subscribe or register to the modem status reception service
using a modem status listener as parameter with the method
``add_modem_status_received_callback()``.

**Subscribe to modem status reception service**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Define the callback.
  def my_modem_status_callback(status):
      print("Modem status: %s" % status.description)

  # Add the callback.
  xbee.add_modem_status_received_callback(my_modem_status_callback)

  [...]

When a new modem status is received, your callback is executed providing as
parameter a ``ModemStatus`` object.

To stop listening to new modem statuses, use the
``del_modem_status_received_callback()`` method to unsubscribe the
already-registered listener.

**Deregister modem status**

.. code:: python

  [...]

  xbee = [...]

  def my_modem_status_callback(status):
      [...]

  xbee.add_modem_status_received_callback(my_modem_status_callback)

  [...]

  # Delete the modem status callback.
  xbee.del_modem_status_received_callback(my_modem_status_callback)

  [...]

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Subscribe to modem status reception service                                                                                                                                                      |
+===========================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to subscribe to the modem status reception service to receive modem status events. The example is located in the following path: |
|                                                                                                                                                                                                           |
| **examples/communication/ReceiveModemStatusSample**                                                                                                                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _communicateXBeeSockets:

Communicate using XBee sockets
------------------------------

Starting from firmware versions \*13, the XBee Cellular product line includes a
new set of frames to communicate with other Internet-connected devices using
sockets.

The XBee Python Library provides several methods that allow you to create,
connect, bind and close a socket, as well as send and receive data with it. You
can use this API where the existing methods listed in the
:ref:`communicateSendReceiveIPData` section limit the possibilities for an
application.

.. warning::
  Only the Cellular protocol supports the use of XBee sockets. This means you
  cannot use this API with a generic ``XBeeDevice`` object; you must use the
  protocol-specific XBee object ``CellularDevice``.

The XBee socket API is available through the ``socket`` class of the
``digi.xbee.xsocket`` module.


Create an XBee socket
`````````````````````

Before working with an XBee socket to communicate with other devices, you have
to instantiate a ``socket`` object in order to create it. To do so, provide the
following parameters:

* XBee Cellular object used to work with the socket.
* IP protocol of the socket (optional). It can be ``IPProtocol.TCP`` (default),
  ``IPProtocol.UDP`` or ``IPProtocol.TCP_SSL``.

**Create an XBee socket**

.. code:: python

  from digi.xbee import xsocket
  from digi.xbee.devices import CellularDevice
  from digi.xbee.models.protocol import IPProtocol

  # Create and open an XBee Cellular.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Create a new XBee socket.
  sock = xsocket.socket(xbee, IPProtocol.TCP)


Work with an XBee socket
````````````````````````

Once the XBee socket is created, you can work with it to behave as a client
or a server. The API offers the following methods:

+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                  | Description                                                                                                                                                                                                                                                                                                                                         |
+=========================================+=====================================================================================================================================================================================================================================================================================================================================================+
| **connect(Tuple)**                      | Connects to a remote socket at the provided address. The address must be a pair ``(host, port)``, where *host* is the domain name or string representation of an IPv4 and *port* is the numeric port value.                                                                                                                                         |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **close()**                             | Closes the socket.                                                                                                                                                                                                                                                                                                                                  |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **bind(Tuple)**                         | Binds the socket to the provided address. The address must be a pair ``(host, port)``, where *host* is the local interface (not used) and *port* is the numeric port value. The socket must not already be bound.                                                                                                                                   |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **listen(Integer)**                     | Enables a server to accept connections.                                                                                                                                                                                                                                                                                                             |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **accept()**                            | Accepts a connection. The socket must be bound to an address and listening for connections. The return value is a pair ``(conn, address)`` where *conn* is a new socket object usable to send and receive data on the connection, and *address* is a pair ``(host, port)`` with the address bound to the socket on the other end of the connection. |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **send(Bytearray)**                     | Sends the provided data to the socket. The socket must be connected to a remote socket.                                                                                                                                                                                                                                                             |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **sendto(Bytearray, Tuple)**            | Sends the provided data to the socket. The socket should not be connected to a remote socket, since the destination socket is specified by *address* (a pair ``(host, port)``).                                                                                                                                                                     |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **recv(Integer)**                       | Receives data from the socket, specifying the maximum amount of data to be received at once. The return value is a bytearray object representing the data received.                                                                                                                                                                                 |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **recvfrom(Integer)**                   | Receives data from the socket, specifying the maximum amount of data to be received at once. The return value is a pair ``(bytes, address)`` where *bytes* is a bytearray object representing the data received and *address* is the address of the socket sending the data(a pair ``(host, port)``).                                               |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **getsockopt(SocketOption)**            | Returns the value of the provided socket option.                                                                                                                                                                                                                                                                                                    |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **setsockopt(SocketOption, Bytearray)** | Sets the value of the provided socket option.                                                                                                                                                                                                                                                                                                       |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **gettimeout()**                        | Returns the configured socket timeout in seconds.                                                                                                                                                                                                                                                                                                   |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **settimeout(Integer)**                 | Sets the socket timeout in seconds.                                                                                                                                                                                                                                                                                                                 |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **getblocking()**                       | Returns whether the socket is in blocking mode or not.                                                                                                                                                                                                                                                                                              |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **setblocking(Boolean)**                | Sets the socket in blocking or non-blocking mode. In blocking mode, operations block until complete or the system returns an error. In non-blocking mode, operations fail if they cannot be completed within the configured timeout.                                                                                                                |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_sock_info()**                     | Returns the information of the socket, including the socket ID, state, protocol, local port, remote port and remote address.                                                                                                                                                                                                                        |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **add_socket_state_callback(Function)** | Adds the provided callback to be notified when a new socket state is received.                                                                                                                                                                                                                                                                      |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **del_socket_state_callback(Function)** | Deletes the provided socket state callback.                                                                                                                                                                                                                                                                                                         |
+-----------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Client sockets
''''''''''''''

When the socket acts as a client, you just have to create and connect the
socket before sending or receiving data with a remote host.

**Work with an XBee socket as client**

.. code:: python

  [...]

  HOST = "numbersapi.com"
  PORT = "80"
  REQUEST = "GET /random/trivia HTTP/1.1\r\nHost: numbersapi.com\r\n\r\n"

  # Create and open an XBee Cellular.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Create a new XBee socket.
  with xsocket.socket(xbee, IPProtocol.TCP) as sock:
      # Connect the socket.
      sock.connect((HOST, PORT))

      # Send an HTTP request.
      sock.send(REQUEST.encode("utf8"))

      # Receive and print the response.
      data = sock.recv(1024)
      print(data.decode("utf8"))


+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Create a TCP client socket                                                                                                                                         |
+=============================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to create a TCP client socket to send HTTP requests. The example is located in the following path: |
|                                                                                                                                                                             |
| **examples/communication/socket/SocketTCPClientSample**                                                                                                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Server sockets
''''''''''''''

When the socket acts as a server, you must create the socket and then perform
the sequence ``bind()``, ``listen()``, ``accept()``.

**Work with an XBee socket as server**

.. code:: python

  [...]

  PORT = "1234"

  # Create and open an XBee Cellular.
  xbee = CellularDevice("COM1", 9600)
  xbee.open()

  # Create a new XBee socket.
  with xsocket.socket(xbee, IPProtocol.TCP) as sock:
      # Bind the socket to the local port.
      sock.bind((None, PORT))

      # Listen for new connections.
      sock.listen()

      # Accept new connections.
      conn, addr = sock.accept()

      with conn:
          print("Connected by %s", str(addr))
          while True:
              # Print the received data (if any).
              data = conn.recv(1024)
              if data:
                  print(data.decode("utf8"))


+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Create a TCP server socket                                                                                                                                                         |
+=============================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to create a TCP server socket to receive data from incoming sockets. The example is located in the following path: |
|                                                                                                                                                                                             |
| **examples/communication/socket/SocketTCPServerSample**                                                                                                                                     |
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Create a UDP server/client socket                                                                                                                                                                                |
+===========================================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that shows how to create a UDP socket to deliver messages to a server and listen for data coming from multiple peers. The example is located in the following path: |
|                                                                                                                                                                                                                           |
| **examples/communication/socket/SocketUDPServerClientSample**                                                                                                                                                             |
+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
