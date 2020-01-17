  Introduction
  ------------
  This sample Python application shows how to start a TCP server to listen for
  incoming connections using the XBee socket API.

  The application creates a TCP socket and binds it to a specific port to
  listen for incoming connections. When a client connects, the application
  starts listening for data coming from the client socket to send it back.

  The example also includes the 'PCClient.py' Python script that creates a
  client socket to connect with the TCP server started by the XBee device.

  NOTE: A SIM card with fixed IP address is required for to the TCP server to
        be accessed externally.

  NOTE: This example uses the Cellular device (CellularDevice) class as it is
        the only device able to use the XBee socket API.


  Requirements
  ------------
  To run this example you will need:

    * One Cellular radio with a micro SIM card (with fixed IP) inserted and its
      corresponding carrier board (XBIB or equivalent). The Cellular module
      must be working in API mode and connected to the Internet.
    * The XCTU application (available at www.digi.com/xctu).


  Compatible protocols
  --------------------
    * Cellular


  Example setup
  -------------
    1) Plug the Cellular radio into the XBee adapter and connect it to your
       computer's USB or serial ports.

    2) Ensure that the module is in API mode and connected to the Internet
       (associated to the cellular network). For further information on how to
       perform this task, read the 'Configuring Your XBee Modules' topic of
       the Getting Started guide.

    3) Set the port and baud rate of the Cellular device in the sample file.
       If you configured the module in the previous step with XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.

    4) Read the MY parameter of the XBee Cellular device using XCTU and
       configure the 'TCP_SERVER_ADDRESS' variable of the 'PCClient.py'
       file with that value. This way, the client socket can connect with the
       TCP server started by the XBee Cellular device.

  Running the example
  -------------------
  First, build and launch the application. Then, wait for the example to
  start the TCP server and listen for incoming connections. The application
  displays the following output:

      - Starting TCP server at port 4660
      - Waiting for client

  Now, execute the 'PCClient.py' Python script. It creates a client socket
  that connects with the Cellular device and sends the text configured in the
  script ('May the force be with you'). When the server detects the connection
  and the data reception, it sends the data back to the client.

  Verify the 'PCClient.py' displays the following output:

      - Connecting to TCP server '10.24.152.36:4660'
      - Sending 'May the force be with you' to the TCP server
      - Waiting for echoed data
      - Data received: May the force be with you

  Verify also that the sample application displays the following output when it
  detects the client connection and data reception:

      - Client '38.142.96.224:12543' connected
      - Waiting for incoming data
      - Data received: May the force be with you
      - Sending data back to the client
      - Closing client socket
