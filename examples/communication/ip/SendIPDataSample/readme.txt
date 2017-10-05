  Introduction
  ------------
  This sample Python application shows how to send IP data from an IP device to
  another one connected to the Internet.

  The application sends IP data to another Wi-Fi device on the network with a
  specific IP address and port number.

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

    3) Set the port and baud rate of the sender (local) XBee radio in the
       sample file.
       If you configured the modules in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.

    4) Set the destination IP address and port number in the sample file.
       You can find them by reading the 'MY' and 'C0' settings of the
       destination XBee device with XCTU.
       Note that the value of the 'C0' setting has hexadecimal format, so you
       have to convert it to decimal before setting it in the sample file.


  Running the example
  -------------------
  First, build the application. Then, you need to set up XCTU to see the data
  received by the remote XBee device. Follow these steps to do so:

    1) Launch the XCTU application.

    2) Add the remote XBee module to the XCTU, specifying its port settings.

    3) Switch to the 'Consoles' working mode and open the serial connection
       so you can see the data when it is received.

  Finally, launch the sample application, some IP data is sent to the configured
  remote XBee device. When that happens, a line with the result of the operation
  is printed to the standard output:

    Sending data to XXX.XXX.XXX.XXX:XXXX >> Hello XBee!... Success

     - Where XXX.XXX.XXX.XXX is the IP address address of the remote XBee device
       and XXXX its port number.

  Verify that in the XCTU console a new RX IPv4 frame has been received by the
  remote XBee device. Select it and review the details, some of the details
  will be similar to:

    - Start delimiter:         7E
    - Length:                  Variable
    - Frame type:              B0 (RX IPv4)
    - Source address:          The XBee sender's IP address.
    - Destination port:        The configured port number.
    - Source port:             A random port chosen by the sender module.
    - Protocol:                01 (TCP)
    - Status:                  00 (Reserved)
    - RF data:                 48 65 6C 6C 6F 20 58 42 65 65 21
                               Hello XBee!
