Discover the XBee network
=========================

Several XBee modules working together and communicating with each other form a
network. XBee networks have different topologies and behaviors depending on the
protocol of the XBee devices that form it.

The XBee Python Library includes a class, called ``XBeeNetwork``, that represents
the set of nodes forming the actual XBee network. This class allows you to
perform some operations related to the nodes. The XBee Network object can be
retrieved from a local XBee device after it has been opened using
the ``get_network()`` method.

.. warning::
  Because XBee Cellular and Wi-Fi module protocols are directly connected to the
  Internet and do not share a connection, these protocols do not support XBee
  networks.

**Retrieve the XBee network**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Get the network.
  xnet = xbee.get_network()
  [...]

A main feature of the ``XBeeNetwork`` class is the ability to
discover the XBee devices that form the network. The ``XBeeNetwork`` object
provides the following operations related to the XBee devices discovery feature:

* :ref:`configDiscoveryProcess`
* :ref:`discoverNetwork`
* :ref:`accessDiscoveredDevices`
* :ref:`addAndRemoveDevices`

.. _configDiscoveryProcess:

Configure the discovery process
-------------------------------

Before discovering all the nodes of a network, you can configure the
settings of that process. The API provides two methods to configure the
discovery timeout and discovery options. These methods set the values
in the module.

+--------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                           | Description                                                                                                                                                                                                                                                                                  |
+==================================================+==============================================================================================================================================================================================================================================================================================+
| **set_discovery_timeout(Float)**                 | Configures the discovery timeout (``NT`` parameter) with the given value in seconds.                                                                                                                                                                                                         |
+--------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **set_discovery_options(Set<DiscoveryOptions>)** | Configures the discovery options (``NO`` parameter) with the set of options. The set of discovery options contains the different ``DiscoveryOptions`` configuration values that are applied to the local XBee module when performing the discovery process. These options are the following: |
|                                                  |   * **DiscoveryOptions.APPEND_DD**: Appends the device type identifier (DD) to the information retrieved when a node is discovered. This option is valid for DigiMesh, Point-to-multipoint (Digi Point) and ZigBee protocols.                                                                |
|                                                  |   * **DiscoveryOptions.DISCOVER_MYSELF**: The local XBee device is returned as a discovered device. This option is valid for all protocols.                                                                                                                                                  |
|                                                  |   * **DiscoveryOptions.APPEND_RSSI**: Appends the RSSI value of the last hop to the information retrieved when a node is discovered. This option is valid for DigiMesh and Point-to-multipoint (Digi Point) protocols.                                                                       |
+--------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Configure discovery timeout and options**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  [...]

  # Get the network.
  xnet = xbee.get_network()

  # Configure the discovery options.
  xnet.set_discovery_options({DiscoveryOptions.DISCOVER_MYSELF, DiscoveryOptions.APPEND_DD})

  # Configure the discovery timeout, in SECONDS.
  xnet.set_discovery_timeout(25)

  [...]


.. _discoverNetwork:

Discover the network
--------------------

The ``XBeeNetwork`` object discovery process allows you to discover and store
all the XBee devices that form the network. The XBeeNetwork object provides a
method for executing the discovery process:

+-------------------------------+-------------------------------------------------------------------------------------------------------+
| Method                        | Description                                                                                           |
+===============================+=======================================================================================================+
| **start_discovery_process()** | Starts the discovery process, saving the remote XBee devices found inside the ``XBeeNetwork`` object. |
+-------------------------------+-------------------------------------------------------------------------------------------------------+

When a discovery process has started, you can monitor and manage it using the
following methods provided by the ``XBeeNetwork`` object:

+------------------------------+----------------------------------------------------------+
| Method                       | Description                                              |
+==============================+==========================================================+
| **is_discovery_running()**   | Returns whether or not the discovery process is running. |
+------------------------------+----------------------------------------------------------+
| **stop_discovery_process()** | Stops the discovery process that is taking place.        |
+------------------------------+----------------------------------------------------------+

.. warning::
  Although you call the ``stop_discovery_process`` method, DigiMesh and
  DigiPoint devices are blocked until the configured discovery time has elapsed.
  If you try to get or set any parameter during that time, a
  ``TimeoutException`` is thrown.

Once the process has finished, you can retrieve the list of devices that form
the network using the ``get_devices()`` method provided by the network object.
If the discovery process is running, this method returns ``None``.

**Discover the network**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  # Start the discovery process and wait for it to be over.
  xnet.start_discovery_process()
  while xnet.is_discovery_running():
      time.sleep(0.5)

  # Get a list of the devices added to the network.
  devices = xnet.get_devices()

  [...]


Discover the network with an event notification
```````````````````````````````````````````````

The API also allows you to add a discovery event listener to notify you when new
devices are discovered, the process finishes, or an error occurs during the
process. In this case, you must provide an event listener before
starting the discovery process using the ``add_device_discovered_callback()``
method.

**Add a callback to device discovered event**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  # Define the device discovered callback.
  def callback(remote):
      [...]

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  # Add the device discovered callback.
  xnet.add_device_discovered_callback(callback)

  # Start the discovery process.
  xnet.start_discovery_process()

  [...]

The behavior of the event is as follows:

* When a new remote XBee device is discovered, the ``DeviceDiscovered`` event
  is raised, executing all device discovered callbacks, even if the discovered
  device is already in the devices list of the network. The callback 
  receives a ``RemoteXBeeDevice`` as argument, with all available information.
  Unknown parameters of this remote device will be ``None``.

There is also another event, ``DiscoveryProcessFinished``. This event is raised
all times that a discovery process finishes.

**Add a callback to discovery process finished event**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  # Define the discovery process finished callback.
  def callback(status):
      if status == NetworkDiscoveryStatus.ERROR_READ_TIMEOUT:
          [...]

  # Add the discovery process finished callback.
  xnet.add_discovery_process_finished_callback(callback)

  [...]

The behavior of the event is as follows:

* When a discovery process has finished for any reason (either successfully or
  with an error), this event is raised, and all callbacks associated with it
  are executed. This method receives a ``NetworkDiscoveryStatus`` object as
  parameter. This status represents the result of the network discovery process.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Device discovery                                                                                                                                        |
+==================================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to perform a device discovery using a callback. It can be located in the following path: |
|                                                                                                                                                                  |
| **examples/network/DiscoverDevicesSample/DiscoverDevicesSample.py**                                                                                              |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Discover specific devices
`````````````````````````

The ``XBeeNetwork`` object also provides methods to discover specific devices 
within a network. This is useful, for example, if you only need
to work with a particular remote device.

+--------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                         | Description                                                                                                                                                                                                                                              |
+================================+==========================================================================================================================================================================================================================================================+
| **discover_device(String)**    | Specify the node identifier of the XBee device to be found. Returns the remote XBee device whose node identifier equals the one provided or ``None`` if the device was not found. In the case of finding more than one device, it returns the first one. |
+--------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **discover_devices([String])** | Specify the node identifiers of the XBee devices to be found. Returns a list with the remote XBee devices whose node identifiers equal those provided.                                                                                                   |
+--------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. Note::
  These methods are blocking, so the application will block until the
  devices are found or the configured timeout expires.

**Discover specific devices**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  # Discover the remote device whose node ID is ‘SOME NODE ID’.
  remote = xnet.discover_device("SOME NODE ID")

  # Discover the remote devices whose node IDs are ‘ID 2’ and ‘ID 3’.
  remote_list = xnet.discover_devices(["ID 2", "ID 3"])

  [...]

.. _accessDiscoveredDevices:

Access the discovered devices
-----------------------------

Once a discovery process has finished, the discovered nodes are saved inside
the ``XBeeNetwork`` object. This means that you can get a list of discovered
devices at any time. Using the ``get_devices()`` method you can obtain all the
devices in this list, as well as work with the list object as you would with
other lists.

This is the list of methods provided by the ``XBeeNetwork`` object that allow
you to retrieve already discovered devices:

+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                 | Description                                                                                                                                                  |
+========================================+==============================================================================================================================================================+
| **get_devices(String)**                | Returns a copy of the list of remote XBee devices. If some device is added to the network before calling this method, the list returned will not be updated. |
+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_device_by_64(XBee64BitAddress)** | Returns the remote device already contained in the network whose 64-bit address matches the given one or ``None`` if the device is not in the network.       |
+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_device_by_16(XBee16BitAddress)** | Returns the remote device already contained in the network whose 16-bit address matches the given one or ``None`` if the device is not in the network.       |
+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_device_by_node_id(String)**      | Returns the remote device already contained in the network whose node identifier matches the given one or ``None`` if the device is not in the network.      |
+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Access discovered devices**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  [...]

  x64addr = XBee64BitAddress(...)
  node_id = "SOME_XBEE"

  # Discover a device based on a 64-bit address.
  spec_device = xnet.get_device_by_64(x64addr)
  if spec_device is None:
      print("Device with 64-bit addr: %s not found" % str(x64addr))

  # Discover a device based on a Node ID.
  spec_device = xnet.get_device_by_node_id(node_id)
  if spec_device is not None:
      print("Device with node id: %s not found" % node_id)

  [...]

.. _addAndRemoveDevices:

Add and remove devices manually
-------------------------------

This section provides information on methods for adding, removing, and clearing
the list of remote XBee devices.


Manually add devices to the XBee network
````````````````````````````````````````

There are several methods for adding remote XBee devices to an XBee network, in
addition to the discovery methods provided by the ``XBeeNetwork`` object.

+-------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                              | Description                                                                                                                                                                                                                                                 |
+=====================================+=============================================================================================================================================================================================================================================================+
| **add_remote(RemoteXBeeDevice)**    | Specifies the remote XBee device to be added to the list of remote devices of the ``XBeeNetwork`` object.                                                                                                                                                   |
|                                     |                                                                                                                                                                                                                                                             |
|                                     | **Notice** that this operation does not join the remote XBee device to the network; it just tells the network that it contains that device. However, the device has only been added to the device list, and may not be physically in the same network.      |
|                                     |                                                                                                                                                                                                                                                             |
|                                     | **Note** that if the given device already exists in the network, it won't be added, but the device in the current network will be updated with the not None parameters of the given device.                                                                 |
|                                     |                                                                                                                                                                                                                                                             |
|                                     | This method returns the given device with the parameters updated. If the device was not in the list yet, this method returns it without changes.                                                                                                            |
+-------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **add_remotes([RemoteXBeeDevice])** | Specifies the remote XBee devices to be added to the list of remote devices of the ``XBeeNetwork`` object.                                                                                                                                                  |
|                                     |                                                                                                                                                                                                                                                             |
|                                     | **Notice** that this operation does not join the remote XBee devices to the network; it just tells the network that it contains those devices. However, the devices have only been added to the device list, and may not be physically in the same network. |
+-------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Add a remote device manually to the network**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  # Get the remote XBee device.
  remote = xnet.get_remote(...)

  # Add the remote device to the network.
  xnet.add_remote(remote)

  [...]


Remove an existing device from the XBee network
```````````````````````````````````````````````

It is also possible to remove a remote XBee device from the list of remote XBee
devices of the ``XBeeNetwork`` object by calling the following method.

+-------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                              | Description                                                                                                                                                                                                                                                           |
+=====================================+=======================================================================================================================================================================================================================================================================+
| **remove_device(RemoteXBeeDevice)** | Specifies the remote XBee device to be removed from the list of remote devices of the XBeeNetwork object. If the device was not contained in the list, the method will raise a ``ValueError``.                                                                        |
|                                     |                                                                                                                                                                                                                                                                       |
|                                     | **Notice** that this operation does not remove the remote XBee device from the actual XBee network; it just tells the network object that it will no longer contain that device. However, next time you perform a discovery, it could be added again automatically.   |
+-------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Remove a remote device from the network**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  # Get the remote XBee device and add it to the network.
  remote = xnet.get_remote(...)
  xnet.add_remote(remote)

  # Remove the remote device from the network.
  xnet.remove_device(remote)

  [...]


Clear the list of remote XBee devices from the XBee network
```````````````````````````````````````````````````````````

The ``XBeeNetwork`` object also includes a method to clear the list of remote
devices. This can be useful when you want to perform a clean discovery,
cleaning the list before calling the discovery method.

+-------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method      | Description                                                                                                                                                                                                                                               |
+=============+===========================================================================================================================================================================================================================================================+
| **clear()** | Removes all the devices from the list of remote devices of the network.                                                                                                                                                                                   |
|             |                                                                                                                                                                                                                                                           |
|             | **Notice** that this does not imply removing the XBee devices from the actual XBee network; it just tells the object that the list should be empty now. Next time you perform a discovery, the list could be filled with the remote XBee devices found.   |
+-------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Clear the list of remote devices**

.. code:: python

  [...]

  # Instantiate an XBee device object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee Network object from the XBee device.
  xnet = xbee.get_network()

  # Discover devices in the network and add them to the list of devices.
  [...]

  # Clear the list of devices.
  xnet.clear()

  [...]
