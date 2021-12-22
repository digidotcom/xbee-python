Changelog
=========

v1.4.1 - 12/22/2021
-------------------

* Support for new hardware variants:

  * XBee 3 Cellular LTE-M/NB-IoT (Telit)
  * XBee 3 Reduced RAM
  * S2C P5
  * XB3-DMLR
  * XB3-DMLR868
* OTA firmware update:

  * Implementation of considerations for versions 1009, 300A, 200A or prior
    (XBPL-375)
    See:

      * `Zigbee (1009 an prior) considerations <https://www.digi.com/resources/documentation/digidocs/90001539/#reference/r_considerations.htm>`_
      * `DigiMesh (older than 300A) considerations <https://www.digi.com/resources/documentation/Digidocs/90002277/#Reference/r_considerations.htm>`_
      * `802.15.4 (older than 200A) considerations <https://www.digi.com/resources/documentation/digidocs/90002273/#reference/r_considerations.htm>`_
  * When updating a remote profile, let the library calculate the `*.otb`
    file path based on the `*.xml` firmware file, as it does for the `*.ota`.
* XBee Cellular:

  * Do not work with network if the XBee does not support it (XBPL-374)
  * Fix creation of IMEI when reading cellular information.
* Support to update a bunch of nodes at the same time (DAL-5285)
* Documentation:

  * Add info about the ``force_settings`` parameter of ``open`` method (#241)
  * Add missing ``exportutils`` module to documentation.
* Set exclusive access mode to the XBee serial port (#222, #252)
* Do not stop frames reader if a serial buffer empty exception occurs (#222, #252)
* Do not use 'os.path.join()' for relative paths of zip entries (#247)
* Fix bad conditions when checking for a received packet (#242)
* Fix attribute name in find neighbors debug message (#122)
* Fix remote firmware update issue with binary file on SX devices.
* Fix protocol change issues during firmware update operation on SX devices.
* Do not reconfigure SP and SN values after a firmware update operation in P2MP protocol.
* Add new method to update salt and verifier values of Bluetooth password SRP authentication.
* Several minor bug fixes.

v1.4.0 - 03/18/2021
-------------------

* Deep node discovery for Zigbee, DigiMesh, and 802.15.4.
* Get route from local XBee to a remote XBee:

  * New method to register a callback to listen for new received routes
    (``add_route_received_callback()``)
  * New blocking method to ask for the route to the remote node
    (``get_route_to_node()``)
* Allow to recover a local node from a profile not only from firmware.
* Support to be notified when new frames are received from a specific node
  (``add_packet_received_from_callback()``).
* Update network information from sent/received AT Command frames.
* New optional argument for parameter value in ``execute_command()``.
* New optional argument to apply pending settings in ``get_parameter()``,
  ``set_parameter()``, and ``execute_command()``.
* XBee 3:

  * Support to update remote file system OTA images.
* XBee SX 900/868:

  * Firmware update for local and remote XBee devices.
  * Profile update for local and remote XBee devices.
* XBee S2C:

  * OTA firmware/profile update support for remote nodes.
* Zigbee:

  * Methods to get nodes routing and neighbor tables: ``get_routes()`` and
    ``get_neighbors()``.
  * Methods to get/set many-to-one broadcasting time:
    ``get_many_to_one_broadcasting_time()`` and
    ``set_many_to_one_broadcasting_time()``.
  * Support for source route creation: ``create_source_route()``.
  * New frames:
    * 'Route Record Indicator' (0xA1)
    * 'Create Source Route Packet' (0x21)
* DigiMesh:

  * Method to get node neighbors: ``get_neighbors()``.
  * Method to build aggregate route: ``build_aggregate_routes()``.
  * New frames:
    * 'Route Information Packet' (0x8D)
* Documentation update
* Bug fixing:

  * Captured possible exception while determining the XBee role (#103)
  * Memory leak: empty list of last discovered nodes using ND (#172)
  * Fix Python 3.9 syntax error (#204)
  * Use least significant nibble of status field in local/remote AT Command
    Responses (XCTUNG-376)
  * Do not lose already registered socket callbacks when closing a local XBee.
  * Reload node information after firmware/profile update (XBPL-348)
  * OTA firmware update:

    * Fix sequence number in ZCL responses during fw update (XCTUNG-1975)
    * Immediate update after transferring the OTA file (XBPL-350)
    * Use requested file offset and size instead of fixed chunks (XBPL-344)
    * Mechanism to calculate the proper block size based on the maximum size
      received by the client and the maximum payload size (XBPL-346)
    * For asyncronous sleeping nodes (Zigbee, DigiMesh, 802.15.4) and
      synchronous sleeping networks (DigiMesh), configure a minimum sleep time
      before update and restore settings at the end.
      For DigiMesh synchronous sleeping network, the local XBee must be a
      non-sleeping node but synchronized with the network (SM=7)
  * Profile application:

    * Do not uncompress profile when reading its information. This change avoids
      extra processing time and required space when retrieving profile info.
    * Remove profile extracted files. A profile is opened to access to its
      contents, and must be closed when done with it.
    * Fixed the application of XBee profiles with 'AP' setting changes
      (XBPL-340)
    * Fixed bootloader update from profile due to bootloader image path
      mismatch (XBPL-338)
    * Fix bootloader update operation by waiting some time until the new
      bootloader is running (XBPL-339)
    * Fixed application of profile with filesystem from Windows(XBPL-341)
    * Read firmware version as an hexadecimal value (#177)
  * Several minor bug fixes.


v1.3.0 - 11/05/2019
-------------------

* Zigbee: Support to register joining devices to a trust center.
* Cellular: XBee TCP/UDP socket support.
* XBee 3:

  * Firmware update for local and remote XBee devices.
  * Profile update for local and remote XBee devices.
  * File system management for local XBee devices.
* New recover serial connection functionality to force the XBee serial
  connection settings.
* Support for notification of network cache modifications events (new node
  added, removed of existing node, network clear, ...)
* Deprecate ``get_api_output_mode`` and ``set_api_output_mode`` methods to
  use new ``get_api_output_mode_value`` and ``set_api_output_mode_value``
  with ``APIOutputModeBit`` enumeration.
* Role as one of the cached parameters.
* Report an error on 'finished discovery' callback if node discovery fails.
* Several minor bug fixes.


v1.2.0 - 04/05/2019
-------------------

* Add new methods to send and receive data from other XBee interfaces through
  User Data Relay frames.
* Add new methods to manage the Bluetooth interface.
* Add support to set AT parameters without applying them with the AT Command
  Queue packet.
* Improve the callbacks mechanism:

  * Callbacks are now executed in parallel.
  * Internal callbacks are now defined when needed to avoid issues when more
    than one callback of the same type is defined.
* Add missing 'Transmit Status', 'Modem Status' and 'Cellular Association
  Indication Status' values to cover all XBee Cellular/XBee3 Cellular features.
* Bug Fixing:

  * Fix some bugs related to package spec data.
  * Log an error when processing a wrong frame instead of stopping the reader.
  * Fix an issue parsing Explicit RX Indicator packets.
  * Fix a couple of leaks with StreamHandlers.


v1.1.1 - 04/25/2018
-------------------

* Add support for DigiMesh and 802.15.4 protocols on XBee3 modules.
* Return an unknown XBee packet when the received packet is not supported by
  the library instead of raising an exception.
* Change logging handler to log messages in the console.
* Bug Fixing:

  * Fix a problem when closing the device connection in the reader.
  * Fix how is determined whether the module has entered in AT command mode
    or not.
  * Fix the string encoding and decoding in some API packets.
  * Fix the message displayed when the XBee device protocol is not correct one.


v1.1.0 - 01/19/2018
-------------------

* Add support for new hardware variants:

  * XB8X
* Add missing 'Modem Status' values for Remote Manager connect and disconnect
  events.
* Bug Fixing:

  * Fix timeouts on Unix platforms.
  * Fix the return source endpoint method from the 'ExplicitRXIndicatorPacket'
    class.
  * Perform general bug fixing when working in API escaped mode.


v1.0.0 - 10/02/2017
-------------------

Initial release of XBee Python library. The main features of the library
include:

* Support for ZigBee, 802.15.4, DigiMesh, Point-to-Multipoint, Wi-Fi,
  Cellular and NB-IoT devices.
* Support for API and API escaped operating modes.
* Management of local (attached to the PC) and remote XBee device objects.
* Discovery of remote XBee devices associated with the same network as the
  local device.
* Configuration of local and remote XBee devices:

  * Configure common parameters with specific setters and getters.
  * Configure any other parameter with generic methods.
  * Execute AT commands.
  * Apply configuration changes.
  * Write configuration changes.
  * Reset the device.
* Transmission of data to all the XBee devices on the network or to a
  specific device.
* Reception of data from remote XBee devices:

  * Data polling.
  * Data reception callback.
* Transmission and reception of IP and SMS messages.
* Reception of network status changes related to the local XBee device.
* IO lines management:

  * Configure IO lines.
  * Set IO line value.
  * Read IO line value.
  * Receive IO data samples from any remote XBee device on the network.
* Support for explicit frames and application layer fields (Source endpoint,
  Destination endpoint, Profile ID, and Cluster ID).
* Multiple examples that show how to use the available APIs.
