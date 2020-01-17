  Introduction
  ------------
  This sample Python application shows how IP data messages are received from
  another XBee device connected to the Internet.

  The application prints the received IP data to the standard output in ASCII
  and hexadecimal formats after the sender IP address.

  NOTE: This example uses the Wi-Fi device (WiFiDevice) class, but it can be
        applied to other Internet capable XBee device classes such as
        CellularDevice.


  Requirements
  ------------
  To run this example you will need:

    * At least two XBee Wi-Fi radios in API mode and their corresponding carrier
      boards (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).


Compatible protocols
  --------------------
    * Cellular
    * Wi-Fi


  Example setup
  -------------
    1) Plug the XBee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    2) Ensure that the modules are in API mode and connected to the same access
       point.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the receiver XBee radio in the sample
       file.
       If you configured the modules in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. Then, you need to send a data frame
  to the receiver (local) module from another device. Follow the steps below to
  do so:

    1) Launch the XCTU application.

    2) Add the sender (remote) XBee module to the XCTU, specifying its port
       settings.

    3) Once the module is added, change to the 'Consoles' working mode and
       open the serial connection.

    4) Create and add a frame using the 'Frames Generator' tool with the
       following parameters:

       - Protocol:                        Select the protocol of your device.
       - Frame type:                      0x20 - TX IPv4
       - Frame ID:                        01
       - IPv4 32-bit dest. address:       The IP address ('MY') of the receiver module
                                          in hexadecimal format.
       - 16-bit dest. port:               The port number ('C0') of the receiver module,
                                          26 16 by default.
       - 16-bit source port:              00 00
       - Protocol:                        TCP
       - Transmit options:                00
       - RF data (ASCII):                 Hello XBee!

    5) Send this frame by selecting it and clicking the 'Send selected Frame'
       button.

  When the IP data frame is sent, verify that a line with the IP address and
  the data included in the 'RF data' field is printed out in the console of the
  launched application:

    From XXX.XXX.XXX.XXX >> Hello XBee!

     - Where XXX.XXX.XXX.XXX is the IP address of the remote XBee device that
       sent the IP data frame.
