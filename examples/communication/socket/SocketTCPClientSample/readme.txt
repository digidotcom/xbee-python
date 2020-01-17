  Introduction
  ------------
  This sample Python application shows how to perform a complete request with
  an HTTP server using the XBee socket API.

  The application opens the connection with an XBee device and, using the XBee
  socket API, it fetches a random fact about a number from a web services API
  offered by the website 'http://numbersapi.com'.

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
  connect with the server, send the request and get the answer. The following
  messages are printed by the application:

      - Connecting to 'numbersapi.com'
      - Sending request text to the server
      - Waiting for the answer

  If the answer is received successfully, the example prints it. After the HTTP
  header there should be an interesting fact about a number:

      - Data received:

        [...]

        10000000000000000000 is the estimated insect population.
