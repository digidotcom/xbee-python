.. _configureXBee:

Configure the XBee
==================

One of the features of the XBee Python Library is the ability to configure the
parameters of local and remote XBee devices and execute some actions or commands
on them.

To apply a complete configuration profile see :ref:`applyProfile`.

.. warning::
  The values set on the different parameters are not persistent through
  subsequent resets unless you store these changes in the device. For more
  information, see :ref:`writeConfigurationChanges`.


.. _configCommonParameters:

Read and set common parameters
------------------------------

Local and remote XBee objects provide a set of methods to get and set common
parameters of the device. Some of these parameters are saved inside the XBee
object, and a cached value is returned when the parameter is requested. Other
parameters are read directly from the physical XBee when requested.


Cached parameters
`````````````````

Certain XBee parameters are used or requested frequently. To avoid the overhead
of reading them from the physical XBee every time they are requested, their
values are cached inside the ``XBeeDevice`` object being returned when the
getters are called.

The following table lists cached parameters and their corresponding getters:

+------------------------+----------------------------+
| Parameter              | Method                     |
+========================+============================+
| 64-bit address         | **get_64bit_addr()**       |
+------------------------+----------------------------+
| 16-bit address         | **get_16bit_addr()**       |
+------------------------+----------------------------+
| Node identifier        | **get_node_id()**          |
+------------------------+----------------------------+
| Firmware version       | **get_firmware_version()** |
+------------------------+----------------------------+
| Hardware version       | **get_hardware_version()** |
+------------------------+----------------------------+
| Role                   | **get_role()**             |
+------------------------+----------------------------+

Local XBee devices read and save previous parameters automatically when opening
the connection of the device. In remote XBee devices, you must issue the
``read_device_info()`` method to initialize their values.

You can refresh the value of these parameters (that is, read their values and
update them inside the XBee object) at any time by calling the
``read_device_info()`` method.

+----------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Method                           | Description                                                                                                                          |
+==================================+======================================================================================================================================+
| **read_device_info(init=False)** | Updates cached parameters reading them from the XBee: If ``init`` is ``True``, it reads all values, else only those not initialized. |
+----------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+


**Refresh cached parameters**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Refresh the cached values.
  xbee.refresh_device_info()

  [...]

The ``read_device_info()`` method may fail for the following reasons:

* There is a timeout getting any of the device parameters, throwing a
  ``TimeoutException``.
* The operating mode of the device is not ``API_MODE`` or ``ESCAPED_API_MODE``,
  throwing an ``InvalidOperatingModeException``.
* The response of the command is not valid, throwing an ``ATCommandException``.
* There is an error writing to the XBee interface, or device is closed,
  throwing a generic ``XBeeException``.

All the cached parameters but the Node Identifier (``NI``) do not change;
therefore, they cannot be set. For the Node Identifier, there is a method within
all the XBee classes that allows you to change it:

+-------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method                  | Description                                                                                                                                                                     |
+=========================+=================================================================================================================================================================================+
| **set_node_id(String)** | Specifies the new Node Identifier of the device. This method configures the physical XBee with the provided Node Identifier and updates the cached value with the one provided. |
+-------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Non-cached parameters
`````````````````````

The following non-cached parameters have their own methods to be configured
within the XBee classes:

* **Destination Address**: This setting specifies the default 64-bit destination
  address of a module that is used to report data generated by the XBee (that
  is, IO sampling data). This setting can be read and set.

  +----------------------------------------+-----------------------------------------------------------------------------+
  | Method                                 | Description                                                                 |
  +========================================+=============================================================================+
  | **get_dest_address()**                 | Returns the 64-bit address of the device that data will be reported to.     |
  +----------------------------------------+-----------------------------------------------------------------------------+
  | **set_dest_address(XBee64BitAddress)** | Specifies the 64-bit address of the device where the data will be reported. |
  +----------------------------------------+-----------------------------------------------------------------------------+

* **PAN ID**: This is the ID of the Personal Area Network the XBee is operating
  in. This setting can be read and set.

  +---------------------------+--------------------------------------------------------------------------------------------------+
  | Method                    | Description                                                                                      |
  +===========================+==================================================================================================+
  | **get_pan_id()**          | Returns a byte array containing the ID of the Personal Area Network where the XBee is operating. |
  +---------------------------+--------------------------------------------------------------------------------------------------+
  | **set_pan_id(Bytearray)** | Specifies the value in byte array format of the PAN ID where the XBee should work.               |
  +---------------------------+--------------------------------------------------------------------------------------------------+

* **Power level**: This setting specifies the output power level of the XBee.
  This setting can be read and set.

  +---------------------------------+-----------------------------------------------------------------------------------------------+
  | Method                          | Description                                                                                   |
  +=================================+===============================================================================================+
  | **get_power_level()**           | Returns a **PowerLevel** enumeration entry indicating the power level of the XBee.            |
  +---------------------------------+-----------------------------------------------------------------------------------------------+
  | **set_power_level(PowerLevel)** | Specifies a **PowerLevel** enumeration entry containing the desired output level of the XBee. |
  +---------------------------------+-----------------------------------------------------------------------------------------------+

**Configure non-cached parameters**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Set the destination address of the device.
  dest_address = XBee64BitAddress.from_hex_string("0013A20040XXXXXX")
  xbee.set_dest_address(dest_address)

  # Read the operating PAN ID of the device.
  dest_addr = xbee.get_dst_address()

  # Read the operating PAN ID of the device.
  pan_id = xbee.get_pan_id()

  # Read the output power level.
  p_level = xbee.get_power_level()

  [...]

All the previous getters and setters of the different options may fail for the
following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+----------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Common parameters                                                                                                                         |
+====================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to get and set common parameters. It can be located in the following path: |
|                                                                                                                                                    |
| **examples/configuration/ManageCommonParametersSample**                                                                                            |
+----------------------------------------------------------------------------------------------------------------------------------------------------+


.. _configOtherParameters:

Read, set and execute other parameters
--------------------------------------

You can read or set a parameter that does not have a custom getter or setter
within the XBee object. All the XBee classes (local or remote) include two
methods to get and set any AT parameter, and a third one to run a command in
the XBee.


Get a parameter
```````````````

You can read the value of any parameter of an XBee using the ``get_parameter()``
method provided by all the XBee classes. Use this method to get the value of a
parameter that does not have a specific getter method within the XBee object.

+---------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Method                    | Description                                                                                                                      |
+===========================+==================================================================================================================================+
| **get_parameter(String)** | Specifies the AT parameter (string format) to retrieve its value. The method returns the value of the parameter in a byte array. |
+---------------------------+----------------------------------------------------------------------------------------------------------------------------------+

You can also use ``get_parameter()`` for settings with a specific getter in the
API.

**Get a parameter from the XBee**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Get the value of the Sleep Time (SP) parameter.
  sp = xbee.get_parameter("SP")

  [...]

The ``get_parameter()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``,
      throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Set and get parameters                                                                                                                                                    |
+====================================================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to get and set parameters using the methods explained previously. It can be located in the following path: |
|                                                                                                                                                                                    |
| **examples/configuration/SetAndGetParametersSample**                                                                                                                               |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Set a parameter
```````````````

To set a parameter that does not have its own setter method, use the
``set_parameter()`` method provided by all the XBee classes.

+--------------------------------------+----------------------------------------------------------------------------------------------------------------------------+
| Method                               | Description                                                                                                                |
+======================================+============================================================================================================================+
| **set_parameter(String, Bytearray)** | Specifies the AT parameter (String format) to be set in the device and a byte array containing the value of the parameter. |
+--------------------------------------+----------------------------------------------------------------------------------------------------------------------------+

You can also use ``set_parameter()`` for settings with a specific setter in the
API.

**Set a parameter in the XBee**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Configure the Node ID using 'set_parameter' method.
  xbee.set_parameter("NI",  bytearray("Yoda", 'utf8'))

  [...]

The ``set_parameter()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Set and get parameters                                                                                                                                                    |
+====================================================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to get and set parameters using the methods explained previously. It can be located in the following path: |
|                                                                                                                                                                                    |
| **examples/configuration/SetAndGetParametersSample**                                                                                                                               |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Execute a command
`````````````````

There are other AT parameters that cannot be read or written. They are actions
that are executed by the XBee. The XBee Python Library has several commands
that handle the most common executable parameters.
To run a parameter that does not have a custom command, you can use the
``execute_command()`` method provided by all the XBee classes.

+-----------------------------+-------------------------------------------------------------------+
| Method                      | Description                                                       |
+=============================+===================================================================+
| **execute_command(String)** | Specifies the AT command (String format) to be run in the device. |
+-----------------------------+-------------------------------------------------------------------+

**Run a command in the XBee**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Run the apply changes command.
  xbee.execute_command("AC")

  [...]

The ``execute_command()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


Apply configuration changes
---------------------------

By default, when you perform any configuration on a local or remote XBee, the
changes are automatically applied. However, you may want to configure different
settings or parameters of a device and apply these changes at the same time. For
that purpose, the ``XBeeDevice`` and ``RemoteXBeeDevice`` objects provide some
methods to manage when to apply configuration changes.

+-----------------------------------+---------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------+
| Method                            | Description                                                                           | Notes                                                                                     |
+===================================+=======================================================================================+===========================================================================================+
| **enable_apply_changes(Boolean)** | Specifies whether the changes on settings and parameters are applied when set.        | The apply configuration changes flag is enabled by default.                               |
+-----------------------------------+---------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------+
| **is_apply_changes_enabled()**    | Returns whether the XBee is configured to apply parameter changes when they are set.  |                                                                                           |
+-----------------------------------+---------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------+
| **apply_changes()**               | Applies parameters changes that were already set but are pending to be applied.       | This method is useful when the XBee is configured not to apply changes when they are set. |
+-----------------------------------+---------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------+

**Apply configuration changes**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Check if device is configured to apply changes.
  apply_changes_enabled = xbee.is_apply_changes_enabled()

  # Configure the device not to apply parameter changes automatically.
  if apply_changes_enabled:
      xbee.enable_apply_changes(False)

  # Set the PAN ID of the XBee to BABE.
  xbee.set_pan_id(utils.hex_string_to_bytes("BABE"))

  # Perform other configurations.
  [...]

  # Apply changes.
  xbee.apply_changes()

  [...]

The ``apply_changes()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

.. _writeConfigurationChanges:

Write configuration changes
---------------------------

For the configuration changes performed in an XBee to persist through subsequent
resets, save those changes. Saving changes means that configured parameter
values in the device are written to the non-volatile memory of the XBee. The
module loads these values from non-volatile memory every time it is started.

The XBee classes (local and remote) provide a method to save (write) the
parameter modifications in the XBee memory so they persist through subsequent
resets: ``write_changes()``.

**Write configuration changes**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Set the PAN ID of the XBee to BABE.
  xbee.set_pan_id(utils.hex_string_to_bytes("BABE"))

  # Perform other configurations.
  [...]

  # Apply changes.
  xbee.apply_changes()

  # Write changes.
  xbee.write_changes()

  [...]

The ``write_changes()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


.. _configReset:

Reset the device
----------------

It may be necessary to reset the XBee when the system is not operating properly
or you are initializing the system. All the XBee classes of the XBee API provide
the ``reset()`` method to perform a software reset on the local or remote XBee
module.

In local modules, the ``reset()`` method blocks until a confirmation from the
module is received, which, usually, takes one or two seconds. Remote modules do
not send any kind of confirmation, so the method does not block when resetting
them.

**Reset the module**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Reset the module.
  xbee.reset()

  [...]

The ``reset()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+---------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Reset module                                                                                                                                   |
+=========================================================================================================================================================+
| The XBee Python Library includes a sample application that shows you how to perform a reset on your XBee. The example is located in the following path: |
|                                                                                                                                                         |
| **examples/configuration/ResetModuleSample**                                                                                                            |
+---------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _configWiFi:

Configure Wi-Fi settings
------------------------

Unlike other protocols, such as Zigbee or DigiMesh, where devices are connected
to each other, the XBee Wi-Fi protocol requires that the module is connected to
an access point in order to communicate with other TCP/IP devices.

This configuration and connection with access points can be done using
applications such as XCTU; however, the XBee Python Library includes a set of
methods to configure the network settings, scan access points, and connect to
an access point.

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Configure Wi-Fi settings and connect to an access point                                                                                                                                                  |
+===================================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to configure the network settings of a Wi-Fi device and connect to an access point. You can locate the example in the following path: |
|                                                                                                                                                                                                                   |
| **examples/configuration/ConnectToAccessPointSample**                                                                                                                                                             |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Configure IP addressing mode
````````````````````````````

Before connecting your Wi-Fi module to an access point, you must decide how to
configure the network settings using the IP addressing mode option. The
supported IP addressing modes are contained in an enumerator called
``IPAddressingMode``. It allows you to choose between:

* DHCP
* STATIC

+----------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------+
| Method                                       | Description                                                                                                                   |
+==============================================+===============================================================================================================================+
| **set_ip_addressing_mode(IPAddressingMode)** | Sets the IP addressing mode of the Wi-Fi module. Depending on the provided mode, network settings are configured differently: |
|                                              |                                                                                                                               |
|                                              |   * **DHCP**: Network settings are assigned by a server.                                                                      |
|                                              |   * **STATIC**: Network settings must be provided manually one by one.                                                        |
+----------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------+

**Configure IP addressing mode**

.. code:: python

  [...]

  # Instantiate an XBee Wi-Fi object.
  xbee = WiFiDevice("COM1", 9600)
  xbee.open()

  # Configure the IP addressing mode to DHCP.
  xbee.set_ip_addressing_mode(IPAddressingMode.DHCP)

  # Save the IP addressing mode.
  xbee.write_changes()

  [...]

The ``set_ip_addressing_mode()`` method may fail for the following reasons:

* There is a timeout setting the IP addressing parameter, throwing a
  ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


Configure IP network settings
`````````````````````````````

Like any TCP/IP protocol device, the XBee Wi-Fi modules have the IP address,
subnet mask, default gateway, and DNS settings that you can get at any time
using the XBee Python Library.

Unlike some general configuration settings, these parameters are not saved
inside the ``WiFiDevice`` object. Every time you request the parameters, they
are read directly from the Wi-Fi module connected to the computer. The following
parameters are used in the configuration of the TCP/IP protocol:

+-------------+---------------------------+
| Parameter   | Method                    |
+=============+===========================+
| IP address  | **get_ip_address()**      |
+-------------+---------------------------+
| Subnet mask | **get_mask_address()**    |
+-------------+---------------------------+
| Gateway IP  | **get_gateway_address()** |
+-------------+---------------------------+
| DNS address | **get_dns_address()**     |
+-------------+---------------------------+

**Read IP network settings**

.. code:: python

  [...]

  # Instantiate an XBee Wi-Fi object.
  xbee = WiFiDevice("COM1", 9600)
  xbee.open()

  # Configure the IP addressing mode to DHCP.
  xbee.set_ip_addressing_mode(IPAddressingMode.DHCP)

  # Connect to access point with SSID 'My SSID' and password 'myPassword'
  xbee.connect_by_ssid("My SSID", "myPassword")

  # Display the IP network settings that were assigned by the DHCP server.
  print("- IP address: %s" % xbee.get_ip_address())
  print("- Subnet mask: %s" % xbee.get_mask_address())
  print("- Gateway IP address: %s" % xbee.get_gateway_address())
  print("- DNS IP address: %s" % xbee.get_dns_address())

  [...]

You can also change these settings when the module has static IP configuration
with the following methods:

+-------------+---------------------------+
| Parameter   | Method                    |
+=============+===========================+
| IP address  | **set_ip_addr()**         |
+-------------+---------------------------+
| Subnet mask | **set_mask_address()**    |
+-------------+---------------------------+
| Gateway IP  | **set_gateway_address()** |
+-------------+---------------------------+
| DNS address | **set_dns_address()**     |
+-------------+---------------------------+


.. _configBluetooth:

Configure Bluetooth settings
----------------------------

Newer XBee 3 devices have a Bluetooth® Low Energy (BLE) interface that enables
you to connect your XBee to another device such as a cellphone. The XBee classes
(local and remote) offer some methods that allow you to:

* :ref:`configBluetoothEnableDisable`
* :ref:`configBluetoothConfigurePassword`
* :ref:`configBluetoothReadMacAddress`


.. _configBluetoothEnableDisable:

Enable and disable Bluetooth
````````````````````````````

Before connecting to your XBee over Bluetooth Low Energy, you first have to
enable this interface. The XBee Python Library provides a couple of methods to
enable or disable this interface:

+-------------------------+-----------------------------------------------------------+
| Method                  | Description                                               |
+=========================+===========================================================+
| **enable_bluetooth()**  | Enables the Bluetooth Low Energy interface of your XBee.  |
+-------------------------+-----------------------------------------------------------+
| **disable_bluetooth()** | Disables the Bluetooth Low Energy interface of your XBee. |
+-------------------------+-----------------------------------------------------------+

**Enabling and disabling the Bluetooth interface**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Enable the Bluetooth interface.
  xbee.enable_bluetooth()

  [...]

  # Disable the Bluetooth interface.
  xbee.disable_bluetooth()

  [...]

These methods may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


.. _configBluetoothConfigurePassword:

Configure the Bluetooth password
````````````````````````````````

Once you have enabled the Bluetooth Low Energy, you must configure the password
to connect to the device over that interface (if not previously done). For this
purpose, the API offers the following method:

+----------------------------------------+----------------------------------------------------+
| Method                                 | Description                                        |
+========================================+====================================================+
| **update_bluetooth_password(String)**  | Specifies the new Bluetooth password of the XBee.  |
+----------------------------------------+----------------------------------------------------+

**Configuring or changing the Bluetooth password**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  new_password = "myBluetoothPassword" # Do not hard-code it in the app!

  # Configure the Bluetooth password.
  xbee.update_bluetooth_password(new_password)

  [...]

The ``update_bluetooth_password()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

.. warning::
  Never hard-code the Bluetooth password in the code, a malicious person could
  decompile the application and find it out.


.. _configBluetoothReadMacAddress:

Read the Bluetooth MAC address
``````````````````````````````

The XBee Java Library provides the ``get_bluetooth_mac_addr()`` method to return
the EUI-48 Bluetooth MAC address of your XBee following the format
"00112233AABB".

**Reading the Bluetooth MAC address**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  print("The Bluetooth MAC address is: %s" % xbee.get_bluetooth_mac_addr())

  [...]

The ``get_bluetooth_mac_addr()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.
