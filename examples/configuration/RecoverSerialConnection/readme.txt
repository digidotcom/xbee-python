  Introduction
  ------------
  This sample Python application shows how to recover the serial settings of a
  local XBee device.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).


  Compatible hardware
  --------------------
    * Local XBee3 devices


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radio into the XBee adapter and connect it to your
       computer's USB or serial port.


  Running the example
  -------------------
  First, build and launch the application. You will see the next message:

    "Opening the XBee device by forcing its baudrate to <baudrate>"

  When the process completes, the following message is displayed:

    "Device opened and set to operate at <baudrate> bauds"

  If any error occurs during the process, it will be displayed in the console.
