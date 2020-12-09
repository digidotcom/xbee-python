  Introduction
  ------------
  This sample Python application shows how to set and read XBee digital lines of
  remote devices.

  The application configures two IO lines of the XBee devices, one in the
  remote device as a digital input (button) and the other in the local device
  as a digital output (LED). Then, the application reads the status of the
  input line periodically and updates the output to follow the input.

  While the push button is pressed, the LED should be lighting.

  NOTE: This example uses the generic remote XBee device (RemoteXBeeDevice)
        class, but it can be applied to any other remote XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * At least two XBee radios in API mode and their corresponding carrier board
      (XBIB or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
    * Point-to-Multipoint
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    2) Configure the remote XBee device with the Node Identifier used by the
       example to communicate with it. To do so follow these steps:

          1) Launch the XCTU application.

          2) Add the remote XBee module to the XCTU, specifying it's port
             settings.

          3) Once the module is added, open the 'Configuration' working mode,
             look for the 'NI' setting and configure it with 'REMOTE'
             (without quotes).

             Notice that by default the 'NI' setting has a blank space
             configured, make sure that there is not a blank space before the
             'REMOTE' text.

    3) Ensure that the modules are in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    4) Set the port and baud rate of the local XBee radio in the sample file.
       If you configured the modules in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.

    5) The final step is to configure the IO lines in the example. Depending
       on the carrier board you are using you may need to change a couple of
       lines in the example code:
         - XBIB-U-DEV board:
             * The example is already configured to use this carrier board.
               The input line is configured to use the SW5 user button of the
               board and the output line is connected to the DS4 user LED. No
               further changes are necessary.

         - XBee Development Board:
             * If you are using the XBee Development Board, update the IOLINE_IN
               constant accordingly.

         NOTE: It is recommended to verify the capabilities of the pins used
               in the example in the product manual of your XBee Device to
               ensure that everything is configured correctly.


  Running the example
  -------------------
  First, build and launch the application.
  To test the functionality, follow these steps:

    1) Press the button corresponding to the digital input line in the remote
       XBee device. In the XBIB boards it is the DIO3.

    2) Verify that the status of the LED corresponding to the digital output
       line in the local XBee device changes. In the XBIB boards it is the
       DIO4.
