  Introduction
  ------------
  This demo Python application shows how to set up a BLE GAP scan, start it,
  receive and process the scan results coming from the scan on the XBee device.

  The application registers a callback to be notified when new GAP scan data
  coming from Bluetooth BLE is received and displays it on the screen.

  NOTE: This demo is currently only supported on the XBee 3 BLU device
        which uses 'XBeeBLU' device class.


  Requirements
  ------------
  To run this demo you will need:

    * One XBee 3 BLU module in API mode and its corresponding carrier board
      (XBIB or equivalent).
    * The XCTU application (available at www.digi.com/xctu).
    * The Python 'curses' library installed.


  Compatible protocols
  --------------------
    * Bluetooth/BLE


  Demo setup
  -------------
    1) Plug the XBee 3 BLU radio into the XBee adapter and connect it to your
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Enable the Bluetooth interface of the XBee 3 BLU device using XCTU.
       For further information on how to perform this task, refer to the
       XCTU user manual.

    4) Set the port and baud rate of the XBee 3 BLU radio in the demo file.
       If you configured the module in the previous step with XCTU, you will
       see the port number and baud rate in the 'Port' label of the device
       on the left view.

    5) Install the Python 'curses' library in your Python environment.
       - For Linux based installations, this typically has already been done
         for you by your Linux distribution.
         If not, use 'pip' to install the 'curses' package.

       - For Windows based installations, you will need to install the
         'windows-curses' library using PIP.
         For example, the following steps should work, assuming the
         Python environment has been properly set up:

             python.exe -m ensurepip --upgrade
             python.exe -m pip install --upgrade pip setuptools wheel
             python.exe -m pip install windows-curses


  Running the demo
  -------------------
  Launch the application by running it:
      python3 GapScanCursesDemo.py

  The window/display will be cleared, and then a BLE GAP scan
  will be started.

  As devices are discovered by the scan, they will be displayed
  in the window/display.

  Each device will be displayed by:
      - Short name, if the device provides it, otherwise "N/A".
      - BLE MAC address.
      - Current RSSI value.
      - Whether the device is Connectable or not.
      - Number of times they have been seen.
        (Number of times we have seen them send a BLE packet over the air)
         
  To quit the application, press 'q'.
