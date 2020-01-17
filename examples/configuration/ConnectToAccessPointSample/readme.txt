  Introduction
  ------------
  This sample Python application how to scan, connect to an access point and
  configure an XBee Wi-Fi module using the XBee Python Library.

  NOTE: This example uses the Wi-Fi device (WiFiDevice) class as it is the only
        device able to connect to access points.


  Requirements
  ------------
  To run this example you will need:

    * One XBee Wi-Fi radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).
    * An access point to connect to.


  Compatible protocols
  --------------------
    * Wi-Fi


  Example setup
  -------------
    1) Plug the Wi-Fi radio into the XBee adapter and connect it to your
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the Wi-Fi radio in the
       sample file. If you configured the module in the
       previous step with XCTU, you will see the port number and baud rate in
       the 'Port' label of the device on the left view.

    4) Set the SSID and password of the access point you are going to connect to
       in the 'SSID' and 'PASSWORD' variables of the sample file.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the following message is printed out in the console of the launched
  application:

    ">> Successfully connected to '<SSID>'"

  That message indicates that the module is connected to the access point
  correctly. Other addressing information should be printed out as well.
