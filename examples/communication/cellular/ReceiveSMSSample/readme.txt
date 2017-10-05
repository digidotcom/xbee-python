  Introduction
  ------------
  This sample Python application shows how SMS messages are received by a
  Cellular device using a callback executed every time a new SMS is received.

  The application prints the phone that sent the message and the text of the
  SMS itself.

  NOTE: This example uses the Cellular device (CellularDevice) class as it is
        the only device able to receive SMS messages.


  Requirements
  ------------
  To run this example you will need:

    * One Cellular radio with a micro SIM card inserted and its corresponding
      carrier board (XBIB or equivalent). The Cellular module must be working
      in API mode and connected to the Internet.
    * The XCTU application (available at www.digi.com/xctu).
    * A mobile phone to send the SMS message.


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

    3) Set the port and baud rate of the receiver Cellular radio in the sample
       file.
       If you configured the module in the previous step with XCTU, you will
       see the port number and baud rate in the 'Port' label of the device
       on the left view.


  Running the example
  -------------------
  First, build and launch the application. Then, you need to send an SMS
  message from a mobile phone or from other Cellular device.

  When the SMS is sent, verify that the Cellular device has received it. The
  application prints out in the console of the launched application the
  following line:

    "Received SMS from XXXXXXXXXX >> '<TEXT>'"

   - Where XXXXXXXXXX is the phone number that send the SMS and <TEXT> is the
     text contained in the SMS message.
