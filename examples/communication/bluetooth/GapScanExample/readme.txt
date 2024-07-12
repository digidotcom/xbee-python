  Introduction
  ------------
  This Python example shows how to set up a BLE GAP scan, start it,
  receive and process the scan results and scan status coming from
  the scan on the XBee device.

  The application registers a callback to be notified when new GAP scan data
  coming from Bluetooth BLE is received and displays it on the screen,
  and also registers a callback to be notified when the GAP scan status
  changes.

  NOTE: This example is currently only supported on the XBee 3 BLU device
        which uses 'XBeeBLU' device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee 3 BLU module in API mode and its corresponding carrier board
      (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * Bluetooth/BLE


  Example setup
  -------------
    1) Plug the XBee 3 BLU radio into the XBee adapter and connect it to your
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Enable the Bluetooth interface of the XBee 3 BLU device using XCTU.
       For further information on how to perform this task, refer to the
       XCTU user manual.

    4) Set the port and baud rate of the XBee 3 BLU radio in the example file.
       If you configured the module in the previous step with XCTU, you will
       see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  Launch the application by running it:
      python3 GapScanExample.py

  As devices are discovered by the scan, the scan data
  will be displayed.
