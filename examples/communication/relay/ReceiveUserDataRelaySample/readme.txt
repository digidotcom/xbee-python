  Introduction
  ------------
  This sample Python application shows how to receive and process data coming
  from other interfaces of the XBee device using a callback executed every time
  a new User Data Relay message is received.

  The application prints the interface that sent the message and the data of
  the message.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee3 module in API mode and its corresponding carrier board (XBIB
      or equivalent).
    * The XCTU application (available at www.digi.com/xctu).
    * An Android or iOS device with the Digi XBee Mobile application installed
      (available at Google Play and App Store).


  Compatible protocols
  --------------------
    * 802.15.4
    * Cellular
    * DigiMesh
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radio into the XBee adapter and connect it to your
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Enable the Bluetooth interface of the XBee device and configure the
       Bluetooth authentication using XCTU.
       For further information on how to perform this task, refer to the
       XCTU user manual.

    4) Set the port and baud rate of the XBee radio in the sample file.
       If you configured the module in the previous step with XCTU, you will
       see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. Then, you need to send a User Data
  Relay message from the XBee Mobile application to the serial interface.
  Follow the steps below to do so:

    1) Launch the XBee Mobile application on your mobile device.

    2) Wait until your XBee device is discovered and connect to it with the
       password you configured during the setup.

    3) Open the Relay Console from the Options menu.

    4) Tap on the Add (+) button to create a new frame. Select 'SERIAL' as
       Relay interface and enter 'Hello XBee!' as data. Then, tap on 'Add'.

    5) Send this frame by selecting it and taping on 'Send selected frame'.

  When the User Data Relay frame is sent, verify that a line with the source
  interface and data is printed out in the console of the launched application:

    Relay data received from BLUETOOTH >> 'Hello XBee!'
