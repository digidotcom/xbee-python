Discover the XBee network
=========================

Several XBee modules working together and communicating with each other form a
network. XBee networks have different topologies and behaviors depending on the
protocol of the XBee nodes that form it.

The XBee Python Library includes a class, called ``XBeeNetwork``, that
represents the set of nodes forming the actual XBee network. This class allows
you to perform some operations related to the nodes.

.. note::
  There are ``XBeeNetwork`` subclasses for different protocols which correspond
  to the ``XBeeDevice`` subclasses:

  * XBee Zigbee network (``ZigBeeNetwork``)
  * XBee 802.15.4 network (``Raw802Network``)
  * XBee DigiMesh network (``DigiMeshNetwork``)
  * XBee DigiPoint network (``DigiPointNetwork``)

.. warning::
  Because XBee Cellular and Wi-Fi module protocols are directly connected to the
  Internet and do not share a connection, these protocols do not support XBee
  networks.

The XBee network object can be retrieved from a local XBee after it has been
opened with the method ``get_network()``.

**Retrieve the XBee network**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Get the network.
  xnet = xbee.get_network()
  [...]

A main feature of the ``XBeeNetwork`` class is the ability to discover the XBee
nodes that form the network and store them in a internal list. The
``XBeeNetwork`` object provides the following operations related to the XBee
discovery feature:

* :ref:`discoveryTypes`
* :ref:`deepDiscovery`
* :ref:`standardDiscovery`
* :ref:`discoverNetwork`
* :ref:`accessDiscoveredDevices`
* :ref:`accessConnections`
* :ref:`addAndRemoveDevices`
* :ref:`listenToNetworkCacheModifications`


.. _discoveryTypes:

Discovery types
---------------

There are two different types of discovery processes available in this API:

* :ref:`deepDiscovery` finds network nodes and connections between them
  (including quality) even if they are sleeping. It also allows to establish a
  number of rounds to continually explore the network.

* :ref:`standardDiscovery` only identifies network nodes. It may not
  discover sleeping nodes.

See :ref:`discoverNetwork` to know how to launch a deep or standard discovery
process.

.. note::
  In 802.15.4, both (deep and standard discovery) are the same and none discover
  the node connections nor their quality. The difference is the possibility of
  running more than one round using a deep discovery.


.. _deepDiscovery:

Deep discovery
--------------

This discovery process finds network nodes and their connections including the
quality. It asks each node for its neighbors and retrieves information about
the signal quality between them.

This mechanism also discovers sleeping nodes.

It is possible to configure the discovery process to run a specific number of
times or even endlessly. Each discovery round is called a scan.


.. _deepDiscoveryMode:

Deep discovery modes
````````````````````

This mode establishes the way the network deep discovery process is performed.
Available modes are defined in the ``NeighborDiscoveryMode`` enumeration:

* **Cascade** (``NeighborDiscoveryMode.CASCADE``): The discovery of the
  neighbors of a node is requested once the previous request finishes. This
  means that just one discovery process is running at the same time.
  This mode is recommended for large networks, it might be a slower method but
  it generates less traffic than 'Flood'.

* **Flood** (``NeighborDiscoveryMode.FLOOD``): The discovery of the neighbors
  of a node is requested when the node is found in the network. This means that
  several discovery processes might be running at the same time.
  This might be a faster method, but it generates a lot of traffic and might
  saturate the network.

The default discovery mode is **Cascade**. You can configure the discovery mode
with the method ``set_deep_discovery_options(NeighborDiscoveryMode, Boolean)``.


.. _configDeepDiscoveryProcess:

Configure the deep discovery process
````````````````````````````````````

Before discovering the nodes of a network, you can configure the settings of
the process. The API provides two methods to configure the discovery timeout
and discovery options.

+----------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                                         | Description                                                                                                                                                      |
+================================================================+==================================================================================================================================================================+
| **set_deep_discovery_timeouts(Float, Float, Float)**           | Configures the deep discovery timeouts:                                                                                                                          |
|                                                                |                                                                                                                                                                  |
|                                                                |   * **node_timeout (Float, optional)**: Maximum duration in seconds of the discovery process used to find neighbors of a node.                                   |
|                                                                |   * **time_bw_requests (Float, optional)**: Time to wait between node neighbors requests (in seconds)                                                            |
|                                                                |                                                                                                                                                                  |
|                                                                |      * For cascade: Time to wait after completion of the a node neighbor discovery process and before next node request.                                         |
|                                                                |      * For flood: Minimum time to wait between each neighbor request.                                                                                            |
|                                                                |   * **time_bw_scans (Float, optional)**: Time to wait before starting a new network scan (in seconds)                                                            |
+----------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **set_deep_discovery_options(NeighborDiscoveryMode, Boolean)** | Configures the deep discovery options:                                                                                                                           |
|                                                                |                                                                                                                                                                  |
|                                                                |   * **deep_mode (NeighborDiscoveryMode, optional)**: Neighbor discovery mode, the way to perform the network discovery process. See **:ref:`deepDiscoveryMode`** |
|                                                                |   * **del_not_discovered_nodes_in_last_scan (Boolean, optional)**: ``True`` to remove nodes from the network if they were not discovered in the last scan.       |
+----------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Configure deep discovery timeout and options**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Get the network.
  xnet = xbee.get_network()

  # Configure the discovery options.
  xnet.set_deep_discovery_options(deep_mode=NeighborDiscoveryMode.CASCADE,
                                  del_not_discovered_nodes_in_last_scan=False)

  # Configure the discovery timeout, in SECONDS.
  xnet.set_deep_discovery_timeout(node_timeout=30, time_bw_requests=10,
                                  time_bw_scans=20)

  [...]


.. _standardDiscovery:

Standard discovery
------------------

This type of discovery process only finds network nodes, it does not include
information about the quality of the connections between them.

XBee nodes sleeping may not respond to this request, this means, it may not be
found using this discovery process type.

The discovery process runs until the configured timeout expires or, in case of
802.15.4, until the 'end' packet is received (see
:ref:`configStandardDiscoveryProcess`)


.. _configStandardDiscoveryProcess:

Configure the standard discovery process
````````````````````````````````````````

Before discovering the nodes of a network, you can configure the settings of
the process. The API provides two methods to configure the discovery timeout
and discovery options. These methods set the values in the radio module.

+--------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                           | Description                                                                                                                                                                                                                                                                                  |
+==================================================+==============================================================================================================================================================================================================================================================================================+
| **set_discovery_timeout(Float)**                 | Configures the discovery timeout (``NT`` parameter) with the given value in seconds.                                                                                                                                                                                                         |
+--------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **set_discovery_options(Set<DiscoveryOptions>)** | Configures the discovery options (``NO`` parameter) with the set of options. The set of discovery options contains the different ``DiscoveryOptions`` configuration values that are applied to the local XBee module when performing the discovery process. These options are the following: |
|                                                  |                                                                                                                                                                                                                                                                                              |
|                                                  |   * **DiscoveryOptions.APPEND_DD**: Appends the device type identifier (``DD``) to the information retrieved when a node is discovered. This option is valid for DigiMesh, Point-to-multipoint (Digi Point) and Zigbee protocols.                                                            |
|                                                  |   * **DiscoveryOptions.DISCOVER_MYSELF**: The local XBee is returned as a discovered node. This option is valid for all protocols.                                                                                                                                                           |
|                                                  |   * **DiscoveryOptions.APPEND_RSSI**: Appends the RSSI value of the last hop to the information retrieved when a node is discovered. This option is valid for DigiMesh and Point-to-multipoint (Digi Point) protocols.                                                                       |
+--------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Configure discovery timeout and options**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Get the network.
  xnet = xbee.get_network()

  # Configure the discovery options.
  xnet.set_discovery_options({DiscoveryOptions.DISCOVER_MYSELF,
                              DiscoveryOptions.APPEND_DD})

  # Configure the discovery timeout, in SECONDS.
  xnet.set_discovery_timeout(25)

  [...]


.. _discoverNetwork:

Discover the network
--------------------

The ``XBeeNetwork`` object discovery process allows you to discover and store
all the XBee nodes that form the network. The ``XBeeNetwork`` object provides a
method for executing a discovery process of the selected type:

+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------+
| Method                                        | Description                                                                                                         |
+===============================================+=====================================================================================================================+
| **start_discovery_process(Boolean, Integer)** | Starts the discovery process, saving the remote XBee found inside the ``XBeeNetwork`` object.                       |
|                                               |                                                                                                                     |
|                                               |   * **deep (Boolean, optional)**: ``True`` for a deep network scan, ``False`` otherwise. See :ref:`discoveryTypes`. |
|                                               |   * **n_deep_scans (Integer, optional)**: Number of discovery scans to perform. Only for deep discovery.            |
+-----------------------------------------------+---------------------------------------------------------------------------------------------------------------------+

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
  For a standard discovery and depending on your hardware and firmware version,
  although you call the ``stop_discovery_process`` method, DigiMesh and
  DigiPoint modules are blocked until the configured discovery time has elapsed.
  This means, if you try to get or set any parameter during that time, a
  ``TimeoutException`` may be thrown.
  This does not occur for:

  * XBee 3 modules running DigiMesh firmware 300B or higher.
  * XBee SX modules running firmware A008 or higher, 9008 or higher.

Once the process has finished, you can retrieve the list of nodes that form
the network using the ``get_devices()`` method provided by the network object.
If the discovery process is running, this method returns ``None``.

All discovered XBee nodes are stored in the ``XBeeNetwork`` instance.

**Discover the network (deep)**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Start the discovery process and wait for it to be over.
  xnet.start_discovery_process(deep=True, n_deep_scans=1)
  while xnet.is_discovery_running():
      time.sleep(0.5)

  # Get the list of the nodes in the network.
  nodes = xnet.get_devices()

  [...]


**Discover the network (standard)**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Start the discovery process and wait for it to be over.
  xnet.start_discovery_process()
  while xnet.is_discovery_running():
      time.sleep(0.5)

  # Get the list of the nodes in the network.
  nodes = xnet.get_devices()

  [...]


Discover the network with an event notification
```````````````````````````````````````````````

The API also allows you to add a discovery event listener to notify when:

* New nodes are discovered.
* The process finishes.
* An error occurs during the process.

Notify new discovered nodes
'''''''''''''''''''''''''''

To get notifications when nodes are discovered, you must provide a callback
before starting the discovery process using the
``add_device_discovered_callback()`` method.

**Add a callback to device discovered event**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Define the device discovered callback.
  def callback(remote):
      [...]

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Add the device discovered callback.
  xnet.add_device_discovered_callback(callback)

  # Start the discovery process.
  xnet.start_discovery_process(deep=True)

  [...]

Every time a new remote XBee node is discovered all registered device discovered
callbacks are executed, even if the discovered node is already in the node list
of the network. Each callback receives a ``RemoteXBeeDevice`` as argument, with
all the available information. Unknown parameters of this remote node are ``None``.

Notify discovery finishes
'''''''''''''''''''''''''

To get notifications when a discovery process finishes, you must provide a
callback before starting the discovery process using the
``add_discovery_process_finished_callback()`` method.

**Add a callback to discovery process finished event**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Define the discovery process finished callback.
  def callback(status):
      if status == NetworkDiscoveryStatus.ERROR_READ_TIMEOUT:
          [...]

  # Add the discovery process finished callback.
  xnet.add_discovery_process_finished_callback(callback)

  [...]

When a discovery process finishes (either successfully or with an error), all
registered discovery finished callbacks are executed. This method receives a
``NetworkDiscoveryStatus`` object as parameter. This status represents the
result of the network discovery process.

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Device discovery                                                                                                                                         |
+===================================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to perform a network discovery using a callback. It can be located in the following path: |
|                                                                                                                                                                   |
| **examples/network/DiscoverDevicesSample/DiscoverDevicesSample.py**                                                                                               |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Discover specific nodes
```````````````````````

The ``XBeeNetwork`` object also provides methods to discover specific nodes
within a network. This may be useful, for example, if you only need to work
with a particular remote node.

+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                         | Description                                                                                                                                                                                                                          |
+================================+======================================================================================================================================================================================================================================+
| **discover_device(String)**    | Specify the node identifier of the XBee to find. Returns the remote XBee whose node identifier equals the one provided or ``None`` if the node was not found. In the case of more than one coincidences, it returns the first one.   |
+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **discover_devices([String])** | Specify the node identifiers of the XBee nodes to find. Returns a list with the remote XBee nodes whose node identifiers equal those provided.                                                                                       |
+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. Note::
  These methods are blocking, so the application will block until the nodes are
  found or the configured timeout expires.

.. Note::
  These methods may not discover sleeping nodes.


**Discover specific nodes**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Discover the remote node whose node ID is ‘SOME NODE ID’.
  remote = xnet.discover_device("SOME NODE ID")

  # Discover the remote nodes whose node IDs are ‘ID 2’ and ‘ID 3’.
  remote_list = xnet.discover_devices(["ID 2", "ID 3"])

  [...]

.. _accessDiscoveredDevices:

Access discovered nodes
-----------------------

Once a discovery process finishes, the discovered nodes are saved inside the
``XBeeNetwork`` object. You can get a list of discovered nodes at any time
using the ``get_devices()``.

This is the list of methods provided by the ``XBeeNetwork`` object that allow
you to retrieve already discovered nodes:

+----------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                 | Description                                                                                                                                       |
+========================================+===================================================================================================================================================+
| **get_devices()**                      | Returns a copy of the list of remote XBee nodes. If any node is added to the network after calling this method, the returned list is not updated. |
+----------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_device_by_64(XBee64BitAddress)** | Returns the remote node already in the network whose 64-bit address matches the given one or ``None`` if the node is not in the network.          |
+----------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_device_by_16(XBee16BitAddress)** | Returns the remote node already in the network whose 16-bit address matches the given one or ``None`` if the node is not in the network.          |
+----------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_device_by_node_id(String)**      | Returns the remote node already in the network whose node identifier matches the given one or ``None`` if the node is not in the network.         |
+----------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------+

**Access discovered nodes**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  [...]

  x64addr = XBee64BitAddress(...)
  node_id = "SOME_XBEE"

  # Discover a node based on a 64-bit address.
  spec_node = xnet.get_device_by_64(x64addr)
  if spec_node is None:
      print("Device with 64-bit addr: %s not found" % str(x64addr))

  # Discover a node based on a Node ID.
  spec_node = xnet.get_device_by_node_id(node_id)
  if spec_node is not None:
      print("Device with node id: %s not found" % node_id)

  [...]

.. _accessConnections:

Access connections between nodes
--------------------------------

A deep discovery process stores the connections between found nodes inside the
``XBeeNetwork`` object. You can get these connections using the
``get_connections()`` method.

This is the list of methods provided by the ``XBeeNetwork`` object that allow
you to retrieve the connections between nodes:

+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                                       | Description                                                                                                                                                                |
+==============================================+============================================================================================================================================================================+
| **get_connections()**                        | Returns a copy of the network connections. If any connection is added after the execution of this method, returned list is not updated.                                    |
+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **get_node_connections(AbstractXBeeDevice)** | Returns a copy of the connections with the provided node in one of its ends. If any connection is added after the execution of this method, returned list is not updated.  |
+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. warning::
  A deep discovery process must be performed to have network connections
  available.

Each ``Connection`` object contains:

* The two nodes between this connection is established.
* The link quality of the connection in both directions (``LinkQuality``):

  * From node A to node B
  * From node B to node A
* The connection status in both directions (``RouteStatus``), active, inactive,
  etc:

  * From node A to node B
  * From node B to node A

**Access network connections**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  [...]

  # Start the discovery process and wait for it to be over.
  xnet.start_discovery_process(deep=True, n_deep_scans=1)
  while xnet.is_discovery_running():
      time.sleep(0.5)

  print("%s" % '\n'.join(map(str, xnet.get_connections())))

  [...]


.. _addAndRemoveDevices:

Add and remove nodes manually
-----------------------------

This section provides information on methods for adding, removing, and clearing
the list of remote XBee nodes.

.. note::
  These methods modifies the list of nodes inside the ``XBeeNetwork`` object,
  but do not change the real XBee network. They do not trigger a node join
  event, a disassociation, or a network reset.


Manually add nodes to the XBee network
``````````````````````````````````````

There are several methods for adding remote XBee nodes to an XBee network, in
addition to the discovery methods provided by the ``XBeeNetwork`` object.

+-------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                              | Description                                                                                                                                                                                              |
+=====================================+==========================================================================================================================================================================================================+
| **add_remote(RemoteXBeeDevice)**    | Specifies the remote XBee to add to the list of remote nodes of the ``XBeeNetwork`` object.                                                                                                              |
|                                     |                                                                                                                                                                                                          |
|                                     | **Notice** that this operation does not join the remote XBee to the network; it just adds that node to the list. The node is added to the node list, but may not be physically in the same network.      |
|                                     |                                                                                                                                                                                                          |
|                                     | **Note** that if the given node already exists in the network, it will not be added, but the node in the current network will be updated with the known parameters of the given node.                    |
|                                     |                                                                                                                                                                                                          |
|                                     | This method returns the same node with its information updated. If the node was not in the list yet, this method returns it without changes.                                                             |
+-------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **add_remotes([RemoteXBeeDevice])** | Specifies the remote XBee nodes to add to the list of remote nodes of the ``XBeeNetwork`` object.                                                                                                        |
|                                     |                                                                                                                                                                                                          |
|                                     | **Notice** that this operation does not join the remote XBee nodes to the network; it just adds those nodes to the list. Nodes are added to the node list but may not be physically in the same network. |
+-------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Add a remote node manually to the network**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Get the remote XBee node.
  remote = xnet.get_remote(...)

  # Add the remote node to the network.
  xnet.add_remote(remote)

  [...]


Remove an existing node from the XBee network
`````````````````````````````````````````````

It is also possible to remove a remote XBee from the list of remote XBee nodes
of the ``XBeeNetwork`` object by calling the following method.

+-------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                              | Description                                                                                                                                                                                                                                   |
+=====================================+===============================================================================================================================================================================================================================================+
| **remove_device(RemoteXBeeDevice)** | Specifies the remote XBee to remove from the list of remote nodes of the XBeeNetwork object. If the node was not contained in the list, the method will raise a ``ValueError``.                                                               |
|                                     |                                                                                                                                                                                                                                               |
|                                     | **Notice** that this operation does not disassociates the remote XBee from the actual XBee network; it just deletes the node from the network object list. However, next time you perform a discovery, it could be added again automatically. |
+-------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


**Remove a remote node from the network**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Get the remote XBee and add it to the network.
  remote = xnet.get_remote(...)
  xnet.add_remote(remote)

  # Remove the remote node from the network.
  xnet.remove_device(remote)

  [...]


Clear the list of remote XBee nodes from the XBee network
`````````````````````````````````````````````````````````

The ``XBeeNetwork`` object also includes a method to clear the list of remote
nodes. This can be useful when you want to perform a clean discovery, cleaning
the list before calling the discovery method.

+-------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method      | Description                                                                                                                                                                                                                                       |
+=============+===================================================================================================================================================================================================================================================+
| **clear()** | Removes all the devices from the list of remote nodes of the network.                                                                                                                                                                             |
|             |                                                                                                                                                                                                                                                   |
|             | **Notice** that this does not imply dismantling the XBee the actual XBee network; it just clears the list of nodes in the ``XBeeNetwork`` object. Next time you perform a discovery, the list could be filled with the found remote XBee nodes.   |
+-------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

**Clear the list of remote nodes**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Get the XBee network object from the local XBee.
  xnet = xbee.get_network()

  # Discover XBee devices in the network and add them to the list of nodes.
  [...]

  # Clear the list of nodes.
  xnet.clear()

  [...]

.. _listenToNetworkCacheModifications:

Listen to network modification events
-------------------------------------

When a discovery process finds new nodes that were not in the XBee network
list (``XBeeNetwork`` or a subclass), they are stored generating a modification
event in the XBee network object. A manual removal or addition of an XBee to the
network also launches modification events.

The XBee library notifies about these network list modification events to
registered callbacks. These events inform about the following network
modifications:

* Addition of new nodes
* Removal of existing nodes
* Update of nodes
* Network clear

To receive any of these modification events you must provide a callback using
the ``add_network_modified_callback()`` method.
This callback must follow the format:

.. code:: python

  def my_callback(event_type, reason, node):
    """
    Callback to notify about a new network modification event.

    Args:
      event_type (:class:`.NetworkEventType`): The type of modification.
      reason (:class:`.NetworkEventReason`): The cause of the modification.
      node (:class:`.AbstractXBeeDevice`): The node involved in the
        modification (``None`` for ``NetworkEventType.CLEAR`` events)
    """
    [...]

When a modification in the network list occurs, all network modification
callbacks are executed. Each callback receives the following arguments:

* The type of network modification as a ``NetworkEventType``
  (addition, removal, update or clear)
* The modification cause as a ``NetworkEventReason`` (discovered, discovered as
  neighbor, received message, hop of a network route, refresh node information,
  firmware update, manual)
* The XBee node, local or remote, (``AbstractXBeeDevice``) involved in the
  modification (``None`` for a clear event type)

**Register a network modifications callback**

.. code:: python

  [...]

  # Define the network modified callback.
  def cb_network_modified(event_type, reason, node):
    print("  >>>> Network event:")
    print("         Type: %s (%d)" % (event_type.description, event_type.code))
    print("         Reason: %s (%d)" % (reason.description, reason.code))

    if not node:
      return

    print("         Node:")
    print("            %s" % node)

  xnet = xbee.get_network()

  # Add the network modified callback.
  xnet.add_network_modified_callback(cb_network_modified)

  [...]


Network events
``````````````

The ``NetworkEventType`` class enumerates the possible network cache
modification types:

* Addition (``NetworkEventType.ADD``): A new XBee has just been added to the
  network cache.
* Deletion (``NetworkEventType.DEL``): An XBee in the network cache has just
  been removed.
* Update (``NetworkEventType.UPDATE``): An existing XBee in the network cache
  has just been updated. This means any of its parameters (node id, 16-bit
  address, role, ...) changed.
* Clear (``NetworkEventType.CLEAR``): The network cached has just been cleared.

As well, ``NetworkEventReason`` enumerates the network modification causes:

* ``NetworkEventReason.DISCOVERED``: The node was added/removed/updated during
  a standard discovery process.
* ``NetworkEventReason.NEIGHBOR``: The node was added/removed/updated during
  a deep discovery process.
* ``NetworkEventReason.RECEIVED_MSG``: The node was added/updated after
  receiving a message from it.
* ``NetworkEventReason.ROUTE``: The node was added/updated as a hop of a
  received network route.
* ``NetworkEventReason.READ_INFO``: The node was updated after refreshing its
  information.
* ``NetworkEventReason.FIRMWARE_UPDATE``: The node was updated/removed, or the
  network cleared after a firmware update.
* ``NetworkEventReason.MANUAL``: The node was manually added/updated/removed, or
  the network cleared.

For example, if, during a deep discovery process, a new node is found and:

* it is not in the network list yet, the addition triggers a new event with:

  * type: ``NetworkEventType.ADD``
  * cause: ``NetworkEventReason.NEIGHBOR``

* it is already in the network list but its node identifier is updated, a new
  event is raised with:

  * type: ``NetworkEventType.UPDATE``
  * cause: ``NetworkEventReason.NEIGHBOR``

* it is already in the network and nothing has changed, no event is triggered.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Network modifications                                                                                                                                   |
+==================================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to receive network modification events. It can be located in the following path:         |
|                                                                                                                                                                  |
| **examples/network/NetworkModificationsSample/NetworkModificationsSample.py**                                                                                    |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
