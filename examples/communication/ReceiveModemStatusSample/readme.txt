  Introduction
  ------------
  This sample Python application shows how modem status packets (events related
  to the device and the network) are handled using the API.

  The application prints the modem status events to the standard output when
  received.

  NOTE: This example uses the generic XBee device (XBeeDevice) class,
        but it can be applied to any other local XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * 802.15.4
    * Cellular
    * Cellular NB-IoT
    * DigiMesh
    * Point-to-Multipoint
    * Wi-Fi
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radio into the XBee adapter and connect it to your
       computer's USB or serial ports.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the XBee radio in the sample file.
       If you configured the module in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. When the application is executed,
  it will print the following message in the output console:

      "Waiting for Modem Status events..."

  Now you have to generate a Modem Status event. The easiest way to do so is
  by resetting the XBee device. So, press the Reset button of the carrier board
  the XBee device is attached to.

  As soon as the module is reset, the application will display a line
  containing a Reset Modem Status event:

     "Modem Status event received: 00: Device was reset"

  If the device joins a network you will also see a Joined Network Modem
  Status event in the output console:

     "Modem Status event received: 02: Device joined to network"
