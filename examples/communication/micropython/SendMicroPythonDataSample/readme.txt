  Introduction
  ------------
  This sample Python application shows how to send data to the MicroPython
  interface of the XBee device.

  The application sends 10 messages to the MicroPython interface in order to
  turn on and off an LED of the XBee carrier board.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee3 module in API mode and its corresponding carrier board (XBIB
      or equivalent).
    * The XCTU application (available at www.digi.com/xctu).
    * The PyCharm IDE with the Digi XBee MicroPython plugin installed.


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

    3) Set the port and baud rate of the XBee radio in the sample file.
       If you configured the module in the previous step with XCTU, you
       will see the port number and baud rate in the 'Port' label of the
       device on the left view.


  Running the example
  -------------------
  First, build the application. Then, you need to run the MicroPython
  'relay_frames_led' sample in the module. Follow these steps to do so:

    1) Launch PyCharm.

    2) In the Welcome screen, click the 'Import XBee MicroPython Sample Project'
       option and import the 'Relay Frames LED' sample (XBEE > COMMUNICATION).

    3) Run the sample project.
       NOTE: when asked to enable the MicroPython REPL mode, click No.

  Finally, launch this sample application. A total of 10 data messages are sent
  to the MicroPython interface to turn on and off an LED. When that happens, a
  line with the result of each operation is printed to the standard output:

    Sending data to MicroPython interface >> 'ON'... Success
    Sending data to MicroPython interface >> 'OFF'... Success
    Sending data to MicroPython interface >> 'ON'... Success
    ...

  Verify that the On/Sleep LED of the XBee carrier board blinks during 10
  seconds.
