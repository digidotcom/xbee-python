  Introduction
  ------------
  This sample Python application shows how to format the filesystem of a
  local XBee device and retrieve usage information.

  The application uses the LocalXBeeFileSystemManager to access the device
  filesystem and execute the required actions.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible hardware
  --------------------
    * Local XBee3 devices


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
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
  the filesystem usage information reported in the console before and after the
  filesystem format operation.

  If any error occurs during the process, it will be displayed in the console.
