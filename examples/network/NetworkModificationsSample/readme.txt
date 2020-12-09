  Introduction
  ------------
  This sample Python application demonstrates how to listen to network
  modification events. The example adds a modifications network callback,
  so modifications events are received and printed out.

  A network is modified when:

     * a new node is added by discovering, manually, or because data is
       received from it
     * an existing node is removed from the network
     * an existing node is updated with new information
     * it is fully cleared

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
  executed:

    1) It performs a device discovery in the network.
       For each discovered device the output console displays the following
       message:

         >>>> Network event:
           Type: XBee added to the network (0)
           Reason: Discovered XBee (0)
           Node:
              XXXXXXXXXXXXXXXX - <NODE_ID>

       Where XXXXXXXXXXXXXXXX is the MAC address of the remote XBee, and <NODE_ID>
       its node identifier.

    2) Then, it manually adds a new node to the network cache.

        * Manually add a new remote XBee device...
           >>>> Network event:
             Type: XBee added to the network (0)
             Reason: Manual modification (2)
             Node:
                1234567890ABCDEF - manually_added

    3) It manually adds the same node but with a different node identifier.

        * Update the last added remote XBee device...
           >>>> Network event:
             Type: XBee in the network updated (2)
             Reason: Manual modification (2)
             Node:
                1234567890ABCDEF - updated_node

    3) Then, it removes this node from the network cache.

        * Manually remove a remote XBee device...
           >>>> Network event:
             Type: XBee removed from the network (1)
             Reason: Manual modification (2)
             Node:
                1234567890ABCDEF - updated_node

    4) Finally, it clears the network.

        * Clear network...
           >>>> Network event:
             Type: Network cleared (3)
             Reason: Manual modification (2)
