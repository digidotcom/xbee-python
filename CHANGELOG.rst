Changelog
=========

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
