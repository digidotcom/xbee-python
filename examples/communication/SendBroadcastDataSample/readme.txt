  Introduction
  ------------
  This sample Python application shows how to send data from the local XBee
  device to all remote devices in the network (broadcast). The application
  blocks during the transmission request, but you are notified if there is any
  error during the process.

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
    1) Plug the XBee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    2) Ensure that the modules are in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the sender XBee radio in the sample file.
       If you configured the modules in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build the application. Then, you need to setup XCTU to see the data
  received by the remote XBee device, in this case it will be broadcast data.
  To do this:

    1) Launch the XCTU application.

    2) Add the receiver XBee module to the XCTU, specifying its port settings.

    3) Once the module is added, change to the 'Consoles' working mode and
       open the serial connection so you can see the data when it is received.

  Finally, launch the sample application, some data is sent to all remote
  modules of the network. When that happens, a line with the result of the
  operation is printed to the standard output:

    Sending broadcast data: Hello XBee!...
    Success

  Verify that in the XCTU console a new RX frame has been received. Select it
  and review the details, some of the details will be similar to:

    - Start delimiter:         7E
    - Length:                  Depends on the XBee protocol.
    - Frame type:              Depends on the XBee protocol.
    - 64-bit source address:   The XBee sender's 64-bit address.
    - RF data/Received data:   48 65 6C 6C 6F 20 58 42 65 65 20 57 6F 72 6C 64 21
                               Hello XBee World!
