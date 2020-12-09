  Introduction
  ------------
  This sample Python application shows how to update the firmware of a local
  XBee device.

  The application provides the required hardware files to the update method
  as well as a callback function to be notified of progress.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).
    * The firmware files to update the device.


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

    4) Configure the paths of the firmware files in the sample file class.
       Only the XML firmware file path is mandatory, the rest can be left as
       'None'. In that case, the API will look for the firmware files in the same
       directory as the XML firmware file one.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the output console displays this message:

    "Starting firmware update process..."

  Followed by percentage progress messages:

    "Updating XBee firmware: 1%"
    "Updating XBee firmware: 2%"
    . . .

  When the process completes, the following message is displayed:

    "Firmware updated successfully!"

  If any error occurs during the process, it will be displayed in the console.
