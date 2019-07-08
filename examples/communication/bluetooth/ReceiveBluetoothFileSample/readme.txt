  Introduction
  ------------
  This sample Python application shows how to receive and process data coming
  from the Bluetooth interface of the XBee device.

  The application registers a callback to be notified when new data coming from
  Bluetooth is received and and stores it in a file.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee3 module in API mode and its corresponding carrier board (XBIB
      or equivalent).
    * The XCTU application (available at www.digi.com/xctu).
    * An Android or iOS device with the 'XBee BLE Microcontroller' sample
      installed.


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
  First, build and launch the application. Then, launch the 'XBee BLE
  Microcontroller' sample of the Digi Mobile SDK and follow the instructions
  explained in that sample's README file.

  When you load and send a file in your mobile device, the sample prints out
  the following messages in the console at the beginning and at the end of the
  process:

    >> START message received, saving data to file...
    >> END message received, file '<file_name>'

  Verify that the received file is created successfully and is the same as the
  one you sent with the mobile application.
