  Introduction
  ------------
  This sample Python application shows how to upload and download a file from
  a local XBee device filesystem.

  The application uses the FileSystemManager to access the device filesystem
  and provides the local file and the necessary paths to the upload/download
  methods as well as callback functions to be notified of progress.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local device class.


  Requirements
  ------------
  To run this example you will need:

    * One XBee radio in API mode and its corresponding carrier board (XBIB
      or XBee Development Board).
    * The XCTU application (available at www.digi.com/xctu).
    * The file to upload to the local XBee device filesystem.


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

    5) Configure the path of the file to upload as well as the remote and
       local paths to upload and download the file to.


  Running the example
  -------------------
  First, build and launch the application. To test the functionality, check
  that the SHA256 hash reported in the console for the local file, the uploaded
  file and the downloaded file are the same:

    File hash summary
    -----------------------
    Local:          017825c2c9c86e52b96e5d835205386badc8a3f3ebea36a53bba17abf8f058fe
    Uploaded:       017825c2c9c86e52b96e5d835205386badc8a3f3ebea36a53bba17abf8f058fe
    Downloaded:     017825c2c9c86e52b96e5d835205386badc8a3f3ebea36a53bba17abf8f058fe

  If any error occurs during the process, it will be displayed in the console.
