  Introduction
  ------------
  This sample Python application shows how to get XBee statistics using
  the XBee Python Library.

  The application sets the value of four parameters with different value types:
  string, byte array and integer. Then it reads them from the device to verify
  that the read values are the same as the values that were set. After that, it
  gets the current XBee statistics.

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
    * DigiMesh
    * Point-to-Multipoint
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radio into the XBee adapter and connect it to your
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the XBee radio in the sample file class.
       If you configured the module in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the output console displays the parameters set and then states the
  following message:

    "All parameters were set correctly!"

  That message indicates that all the parameters could be set and their read
  values are the same as the values that were set.
  Next, the XBee statistics are read and the next message appers:

      "All XBee Statistics displayed!"

  That message indicates that all XBee statistics were displayed. The statistics
  shown are:
      * RX info: Number of receive packets and bytes.
      * TX info: Number of transmitted packets and bytes.
      * Remote AT command errors: Number of packets of remote AT commands
        that failed.
      * TX numbers: Number of packets which transmission failed.
