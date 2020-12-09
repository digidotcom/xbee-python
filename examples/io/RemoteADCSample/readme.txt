  Introduction
  ------------
  This sample Python application shows how to read XBee analog inputs of remote
  XBee devices.

  The application configures an IO line of the remote XBee device as ADC. Then,
  it periodically reads its value and prints it in the output console.

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

    5) The final step is to connect a voltage variable source to the pin
       configured as ADC in the remote XBee device (light sensor, temperature
       sensor, etc). For testing purposes we recommend using a potentiometer.
       Depending on the carrier board you are using you will need to follow a
       different set of instructions to connect it:
         - XBIB-U-DEV board:
             * Isolate the pin configured as ADC so it does not use the
               functionality provided by the board.
             * Connect the potentiometer to VCC, to the pin configured as ADC
               and to GND. Something similar to this:

                   O   VCC
                   |
                   <
                   >___ XBee device pin (ADC)
                   >
                   <
                  _|_
                   -   GND

             * If you prefer not to isolate the pin of the board and not to use
               a potentiometer, you can still test the example. The IO line
               configured as ADC (DIO1/AD1) is connected to the SW3 user button
               of the XBIB-U-DEV board, so the analog value will change from
               nothing to all depending on the status of the button.

         - XBee Development Board:
             * Connect a voltage to VRef pin of the device (you can take it
               from the Vcc pin).
             * Configure the micro-switch of AD1 line to "Potentiometer", this
               way the DIO1/AD1 line of the device will be connected to the
               board's potentiometer

         NOTE: It is recommended to verify the capabilities of the pins used
               in the example as well as the electrical characteristics in the
               product manual of your XBee Device to ensure that everything is
               configured correctly.


  Running the example
  -------------------
  First, build and launch the application.
  To test the functionality, follow these steps:

    1) Rotate the potentiometer.

    2) Verify that the value displayed in the output console is changing.
