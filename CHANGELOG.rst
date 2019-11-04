Changelog
=========

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
