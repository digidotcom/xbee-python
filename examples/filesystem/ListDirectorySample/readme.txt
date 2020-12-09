  Introduction
  ------------
  This sample Python application shows how to list the contents of an XBee
  device filesystem directory.

  The application uses the FileSystemManager to access the device filesystem
  and execute the required actions.

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
    * Zigbee


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

    4) To use a remote XBee, configure its node identifier (NI) in the sample
       file. Leave it empty to use the local XBee.

    5) Configure the path of the XBee directory to list.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the console lists the selected directory contents like this:

    Contents of '/flash' (local):

    d  0.00B     lib                       /flash/lib
    d  0.00B     dir_1                     /flash/dir_1
    d  0.00B     dir_2                     /flash/dir_2
    - 47.00B     file.txt                  /flash/file.txt
    *  1.95KB    secure.txt                /flash/uploaded/secure.txt

  If any error occurs during the process, it will be displayed in the console.
