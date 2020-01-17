  Introduction
  ------------
  This sample Python application shows how to list the contents of an XBee
  device filesystem directory.

  The application uses the LocalXBeeFileSystemManager to access the device
  filesystem and execute the required actions.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).


  Compatible hardware
  --------------------
    * Local XBee3 devices


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
    * ZigBee


  Example setup
  -------------
    1) Plug the XBee radio into the XBee adapter and connect it to your
       computer's USB or serial port.

    2) Ensure that the module is in API mode.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the XBee radio in the sample file class.
       If you configured the module in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.

    4) Configure the path of the XBee directory to list.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the console lists the selected directory contents like this:

    Starting file system manager... OK

    Current directory: /flash
    Contents of '/flash':
    <DIR> ./
    <DIR> ../
    <DIR> lib/
    <DIR> folder_1/
    <DIR> folder_2/
    42664 firmware.py

    Stopping file system manager... OK

  If any error occurs during the process, it will be displayed in the console.
