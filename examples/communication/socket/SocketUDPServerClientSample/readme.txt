  Introduction
  ------------
  This sample Python application shows how to create a UDP socket to deliver
  messages to a server and and listen for data coming from multiple peers using
  the XBee socket API.

  The application associates the UDP socket with a port (binds it) to listen
  for individual messages. Then, it sends a message to a server Digi has at
  52.43.121.77 port 10001, which echos all UDP traffic sent to it. This causes
  the socket to receive the echoed message and prints it.

  NOTE: This example uses the Cellular device (CellularDevice) class as it is
        the only device able to use the XBee socket API.


  Requirements
  ------------
  To run this example you will need:

    * One Cellular radio with a micro SIM card inserted and its corresponding
      carrier board (XBIB or equivalent). The Cellular module must be working
      in API mode and connected to the Internet.
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


  Running the example
  -------------------
  First, build and launch the application. Then, wait for the example to
  start the UDP server and send a request to the echo server. The application
  displays the following output:

      - Starting UDP server at port 4660
      - Sending 'May the force be with you' to the echo server
      - Waiting for incoming data

  When the answer from the echo server is received, the application prints it:

      - Data received from 52.43.121.77:10001 - 'May the force be with you'
