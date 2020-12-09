  Introduction
  ------------
  This sample Python application shows how to set and read XBee digital lines of
  the device attached to the serial/USB port of your PC.

  The application configures two IO lines of the XBee device, one as a digital
  input (button) and the other as a digital output (LED). Then, the application
  reads the status of the input line periodically and updates the output to
  follow the input.

  While the push button is pressed, the LED should be lighting.

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
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the XBee radio in the sample file.
       If you configured the module in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.

    4) The final step is to configure the IO lines in the example. Depending
       on the carrier board you are using you may need to change a couple of
       lines in the example code:
         - XBIB-U-DEV board:
             * The example is already configured to use this carrier board.
               The input line is configured to use the SW5 user button of the
               board and the output line is connected to the DS4 user LED. No
			   further changes are necessary.

         - XBee Development Board:
             * If you are using the XBee Development Board, update the
               IO_LINE_IN constant accordingly.

         NOTE: It is recommended to verify the capabilities of the pins used
               in the example in the product manual of your XBee Device to
               ensure that everything is configured correctly.


  Running the example
  -------------------
  First, build and launch the application.
  To test the functionality, follow these steps:

    1) Press the button corresponding to the digital input line. In the XBIB
       boards it is the DIO3.

    2) Verify that the status of the LED corresponding to the digital output
       line changes. In the XBIB boards it is the DIO4.
