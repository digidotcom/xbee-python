  Introduction
  ------------
  This sample Python application shows how to update the filesystem of a remote
  XBee device.

  The application provides the required hardware files to the update method
  as well as a callback function to be notified of progress.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local device class.


  Requirements
  ------------
  To run this example you will need:

    * At least two XBee radios in API mode and their corresponding carrier
      board (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).
    * A signed filesystem OTA image file to update to the remote device.


  Compatible hardware
  --------------------
    * XBee3 devices


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    2) Configure the remote XBee device with the Node Identifier you will use
       in the example to communicate with. To do so follow these steps:

          1) Launch the XCTU application.

          2) Add the remote XBee module to the XCTU, specifying its port
             settings.

          3) Once the module is added, open the 'Configuration' working mode,
             look for the 'NI' setting and configure it with the name you will
             use in the example.

             Notice that by default the 'NI' setting has a blank space
             configured, make sure that there is not a blank space before
             setting the new remote device NI.

    3) Ensure that the modules are both in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    4) Set the port and baud rate of the local XBee radio in the sample file
       class. If you configured the modules in the previous step with the XCTU,
       you will see the port number and baud rate in the 'Port' label of the
       device on the left view.

    5) Configure the Node ID (NI) of the remote XBee device in the sample file.

    6) Configure the path of the filesystem OTA file in the sample file.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the output console displays this message:

    "Starting filesystem image update process..."

  Followed by percentage progress messages:

    "Updating remote XBee filesystem: 1%"
    "Updating remote XBee filesystem: 2%"
    . . .

  When the process completes, the following message is displayed:

    "Filesystem image updated successfully!"

  If any error occurs during the process, it will be displayed in the console.
