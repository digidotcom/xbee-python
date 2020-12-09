  Introduction
  ------------
  This sample Python application demonstrates how to obtain the XBee network
  object from a local XBee device and discover the remote XBee devices that
  compose the network. The example adds a discovery listener, so the events
  will be received by the callbacks provided by the listener object.

  The remote XBee devices are printed out as soon as they are found during the
  discovery.

  NOTE: This example uses the generic XBee device (XBeeDevice) class, but it
        can be applied to any other local XBee device class.


  Requirements
  ------------
  To run this example you will need:

    * At least two XBee radios in API mode and their corresponding carrier
      board (XBIB or equivalent). More than two radios are recommended.
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * 802.15.4
    * DigiMesh
    * Point-to-Multipoint
    * Zigbee


  Example setup
  -------------
    1) Plug the XBee radios into the XBee adapters and connect them to your
       computer's USB or serial ports.

    2) Ensure that the modules are in API mode and on the same network.
       For further information on how to perform this task, read the
       'Configuring Your XBee Modules' topic of the Getting Started guide.

    3) Set the port and baud rate of the local XBee radio in the sample file.
       If you configured the modules in the previous step with the XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. As soon as the application is
  executed, it will perform a device discovery in the network. To verify the
  application is working properly, check that the following happens:

    1) The output console states the following message:

         "Discovering remote XBee devices..."

    2) For each discovered device the output console should display the
       following message:

         "Device discovered: XXXXXXXXXXXXXXXX"

           - Where XXXXXXXXXXXXXXXX is the MAC address of the remote XBee
             device.

    3) When the discovery process finishes the following message should be
       displayed:

         "Discovery process finished successfully."
