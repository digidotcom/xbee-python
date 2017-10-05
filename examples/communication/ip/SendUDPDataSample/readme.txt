  Introduction
  ------------
  This sample Python application shows how to send UDP data from an IP device to
  another one connected to the Internet.

  The application sends UDP data to the specified IP address and port number.

  NOTE: This example uses the NB-IoT device (NBIoTDevice) class, but it can be
        applied to other Internet capable XBee device classes such as
        CellularDevice.


  Requirements
  ------------
  To run this example you will need:

    * One XBee NB-IoT radio in API mode and its corresponding carrier board
      (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * Cellular
    * Cellular NB-IoT
    * Wi-Fi


  Example setup
  -------------
    1) Plug the XBee radio into the XBee adapter and connect it to your
       computer's USB or serial ports.

    2) Ensure that the module is in API mode and connected to the Internet.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the XBee radio in the sample file.
       If you configured the module in the previous step with XCTU, you will
       see the port number and baud rate in the 'Port' label of the device
       on the left view.

    4) Set the destination IP address and port number in the sample file.


  Running the example
  -------------------
  First, build and launch the application. As soon as the application is
  executed, it will send the UDP packet to the specified IP address and port
  number. If the transmission was sent successfully, the following message
  will be printed out in the console:

    Sending data to 192.168.1.2:9750 >> Hello XBee!... Success
