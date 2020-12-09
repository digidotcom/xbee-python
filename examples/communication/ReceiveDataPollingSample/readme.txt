  Introduction
  ------------
  This sample Python application shows how data packets are received from
  another XBee device on the same network using a polling mechanism.

  The application prints the data that was received to the standard output in
  ASCII and hexadecimal formats after the sender address.

  NOTE: This example uses the generic XBee device (XBeeDevice) class,
        but it can be applied to any other local XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * At least two XBee radios in API mode and their corresponding carrier
      board (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
    * Point-to-Multipoint
    * Zigbee


  Example setup
  -------------
    1) Find the 64-bit address labeled on the back of your local XBee device,
       which is a 16 character string that follows the format 0013A20040XXXXXX.
       It will be used later in the example.

    2) Plug the XBee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    3) Ensure that the modules are in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    4) Set the port and baud rate of the receiver XBee radio in the sample
       file.
       If you configured the modules in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. Then, you need to send a data frame
  to the receiver (local) module from another device on the network. Follow the
  steps below to do so:

    1) Launch the XCTU application.

    2) Add the sender (remote) XBee module to the XCTU, specifying its port
       settings.

    3) Once the module is added, change to the 'Consoles' working mode and
       open the serial connection.

    4) Create and add a frame using the 'Frames Generator' tool with the
       following parameters:

       - Protocol:                               Select the protocol of your device.
       - Frame type:                             Select a 64-bit Transmit Request frame.
       - Frame ID:                               01
       - 64-bit dest. address:                   Use the 64-bit address you copied before.
       - 16-bit dest. address (only if present): FF FE
       - Broadcast radius (only if present):     00
       - Options:                                00
       - RF data (ASCII):                        Hello XBee!

    5) Send this frame by selecting it and clicking the 'Send selected Frame'
       button.

  When the data frame is sent, verify that a line with the data frame and the
  data included in the 'RF data' field is printed out in the console of the
  launched application:

    From 0013A20040XXXXXX >> Hello XBee!

     - Where 0013A20040XXXXXX is the 64-bit address of the remote XBee device
       that sent the data frame.
