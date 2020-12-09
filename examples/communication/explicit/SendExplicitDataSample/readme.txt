  Introduction
  ------------
  This sample Python application shows how to send data in the application layer
  (explicit) format to a remote Zigbee device using the XBee Python Library. In
  this example, explicit data is sent using a reliable transmission method. The
  application blocks during the transmission request, but you are notified if
  there is any error during the process.

  The application sends data in the application layer (explicit) format to a
  remote Zigbee device on the network with a specific node identifier (name).

  NOTE: This example uses the Zigbee device (ZigBeeDevice) class, but it can
        be applied to any other protocol specific device class that supports
        sending data in explicit format.


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
    1) Plug the Zigbee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    2) Configure the remote Zigbee device with the Node Identifier used by the
       example to communicate with it and to receive data in application layer
       (explicit) format. To do so follow these steps:

          1) Launch the XCTU application.

          2) Add the remote Zigbee module to XCTU, specifying its port settings.

          3) Once the module is added, open the 'Configuration' working mode,
             look for the 'NI' setting and configure it with 'REMOTE'
             (without quotes).

             Notice that by default the 'NI' setting has a blank space
             configured, make sure that there is not a blank space before the
             'REMOTE' text.

          4) Look for the 'AO' setting and configure it with '1' (without
             quotes)

    3) Ensure that the modules are in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    4) Set the port and baud rate of the sender (local) Zigbee radio in the
       sample file.
       If you configured the modules in the previous step with XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build the application. Then, you need to setup XCTU to see the data
  received by the remote Zigbee device in explicit format. Follow these steps to
  do so:

    1) Launch the XCTU application.

    2) Add the remote Zigbee module to XCTU, specifying its port settings.

    3) Switch to the 'Consoles' working mode and open the serial connection
       so you can see the data when it is received.

  Finally, launch the sample application, data in explicit format is sent to
  the configured remote Zigbee device whose Node Identifier is 'REMOTE'.

  Verify that in the XCTU console a new Explicit Rx Indicator frame has been
  received by the remote Zigbee device. Select it and review the details, some
  of the details will be similar to:

    - Start delimiter:         7E
    - Length:                  00 1D
    - Frame type:              91
    - 64-bit source address:   The XBee sender's 64-bit address.
    - 16-bit source address:   The XBee sender's 16-bit address.
    - Source endpoint:         A0
    - Destination endpoint:    A1
    - Cluster ID:              15 54
    - Profile ID:              12 34
    - Receive options:         01
    - RF data/Received data:   48 65 6C 6C 6F 20 58 42 65 65 21
                               Hello XBee!
