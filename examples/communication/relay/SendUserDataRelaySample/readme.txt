  Introduction
  ------------
  This sample Python application shows how to send data to other interfaces of
  the XBee device.

  The application sends 10 User Data Relay messages to the Bluetooth Low Energy
  interface.

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
       If you configured the module in the previous step with XCTU, you
       will see the port number and baud rate in the 'Port' label of the
       device on the left view.


  Running the example
  -------------------
  First, build the application. Then, you need to set up the XBee Mobile app
  to see the data received. Follow these steps to do so:

    1) Launch the XBee Mobile application on your mobile device.

    2) Wait until your XBee device is discovered and connect to it with the
       password you configured during the setup.

    3) Open the Relay Console from the Options menu.

  Finally, launch the sample application. A total of 10 User Data Relay
  messages are sent to the Bluetooth interface. When that happens, a line with
  the result of each operation is printed to the standard output:

    Sending User Data Relay to BLUETOOTH >> 'Hello from the serial interface (#1)'... Success
    Sending User Data Relay to BLUETOOTH >> 'Hello from the serial interface (#2)'... Success
    Sending User Data Relay to BLUETOOTH >> 'Hello from the serial interface (#3)'... Success
    ...

  Verify in the Relay Console of the XBee Mobile app that new frames have been
  received. Tap on one of them and then on the info button, the details will be
  similar to:

    - Time:                    Received time.
    - Relay interface          SERIAL.
    - Data:                    Hello from the serial interface (#1)
