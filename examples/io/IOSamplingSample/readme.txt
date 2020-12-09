  Introduction
  ------------
  This sample Python application shows how to configure a remote device to send
  automatic IO samples and how to read them from the local module.

  The application configures two IO lines of the remote XBee device: one as
  digital input (button) and the other as ADC, and enables periodic sampling
  and change detection. The device sends a sample every five seconds containing
  the values of the two monitored lines. It sends another sample every time the
  button is pressed or released, which only contains the value of this digital
  line.

  Then, the application registers a listener in the local device to receive and
  handle all IO samples sent by the remote XBee module.

  NOTE: This example uses the generic XBee device (XBeeDevice) and remote XBee
        device (RemoteXBeeDevice) classes, but it can be applied to any other
        local or remote XBee device classes.


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
               board. No further changes are necessary.

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

    1) Verify that the samples are received and printed in the output console
       every 5 seconds. These samples should contain the values of the two lines
       that are monitored.

    2) Press the button corresponding to the digital input line in the remote
       XBee device and verify that a new sample is received and printed in the
       output console (in the XBIB boards it is the DIO3). This sample should
       only contain the value of the digital line.
