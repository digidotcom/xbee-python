  Introduction
  ------------
  This sample Python application shows how data in the application layer
  (explicit) format is received by a Zigbee device using a polling mechanism.
  Before receiving data in explicit format, the API output mode of the Zigbee
  device is configured in explicit mode.

  The application prints the data that was received as well as the application
  layer fields to the standard output.

  NOTE: This example uses the Zigbee device (ZigBeeDevice) class, but it can
        be applied to any other protocol specific device class that supports
        receiving data in explicit format.


  Requirements
  ------------
  To run this example you will need:

    * At least two Zigbee radios in API mode and their corresponding carrier
      board (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * DigiMesh
    * Point-to-Multipoint
    * Zigbee


  Example setup
  -------------
    1) Find the 64-bit address labeled on the back of your local Zigbee device,
       which is a 16 character string that follows the format 0013A20040XXXXXX.
       It will be used later in the example. The application will display this
       address at the beginning of the execution.

    2) Plug the Zigbee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    3) Ensure that the modules are in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    4) Set the port and baud rate of the receiver Zigbee radio in the sample
       file.
       If you configured the modules in the previous step with XCTU, you will
       see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, launch the application. Then, you need to send a Transmit
  Request frame to the receiver (local) module from another device on the
  network. Follow the steps below to do so:

    1) Launch the XCTU application.

    2) Add the sender (remote) Zigbee module to XCTU, specifying its port
       settings.

    3) Once the module is added, change to the 'Consoles' working mode and
       open the serial connection.

    4) Create and add a frame using the 'Frames Generator' tool with the
       following parameters:

       - Protocol:                               Select the protocol of your device.
       - Frame type:                             Select a Transmit Request frame.
       - Frame ID:                               01
       - 64-bit dest. address:                   Use the 64-bit address you copied before.
       - 16-bit dest. address (only if present): FF FE
       - Broadcast radius (only if present):     00
       - Options:                                00
       - RF data (ASCII):                        Hello XBee!

    5) Send this frame by selecting it and clicking the 'Send selected Frame'
       button.

  When the Transmit Request frame is sent, verify that the receiver device has
  received the data in explicit format. Some lines with the frame information,
  the data included in the 'RF data' field and the application layer values are
  printed out in the console of the launched application:

    From 0013A20040XXXXXX >> Hello XBee!
     - Source endpoint:       0xE8
     - Destination endpoint:  0xE8
     - Cluster ID:            0x0011
     - Profile ID:            0xC105

   - Where 0013A20040XXXXXX is the 64-bit address of the remote Zigbee device
     that sent the data frame.
