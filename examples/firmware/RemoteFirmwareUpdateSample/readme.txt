  Introduction
  ------------
  This sample Python application shows how to update the firmware of a remote
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
    * The firmware files to update the remote device.


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
       in the example to communicate with it. To do so follow these steps:

          1) Launch the XCTU application.

          2) Add the remote XBee module to the XCTU, specifying it's port
             settings.

          3) Once the module is added, open the 'Configuration' working mode,
             look for the 'NI' setting and configure it with the name you will
             use in the example.

             Notice that by default the 'NI' setting has a blank space
             configured, make sure that there is not a blank space before the
             'REMOTE' text.

    3) Ensure that the modules are both in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    4) Set the port and baud rate of the local XBee radio in the sample file
       class. If you configured the module in the previous step with the XCTU.

    5) Configure the Node ID (NI) of the remote XBee device in the sample file.

    6) Configure the paths of the firmware files in the sample file. Only the
       XML firmware file path is mandatory, the rest can be left as 'None'. In
       that case, the API will look for the firmware files in the same
       directory as the XML firmware file one.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the output console displays this message:

    "Starting firmware update process..."

  Followed by percentage progress messages:

    "Updating remote XBee firmware: 1%"
    "Updating remote XBee firmware: 2%"
    . . .

  When the process completes, the following message is displayed:

    "Firmware updated successfully!"

  If any error occurs during the process, it will be displayed in the console.
