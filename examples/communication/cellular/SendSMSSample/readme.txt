  Introduction
  ------------
  This sample Python application shows how SMS messages are sent by a Cellular
  device.

  The application sends an SMS message to a mobile phone and prints the result
  of the operation.

  NOTE: This example uses the Cellular device (CellularDevice) class as it is
        the only device able to send SMS messages.


  Requirements
  ------------
  To run this example you will need:

    * One Cellular radio with a micro SIM card inserted and its corresponding
      carrier board (XBIB or equivalent). The Cellular module must be working
      in API mode and connected to the Internet.
    * The XCTU application (available at www.digi.com/xctu).
    * A mobile phone to receive the SMS message.


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
       If you configured the module in the previous step with XCTU, you
       will see the port number and baud rate in the 'Port' label of the device
       on the left view.

    4) Set the phone number of the mobile phone to send the SMS to in the
       'PHONE' variable of the sample file. Optionally, modify the text of
       the SMS changing the value of the 'SMS_TEXT' variable.


  Running the example
  -------------------
  First, build and launch the application. Then, wait for the SMS reception in
  your mobile phone.

  When the SMS is sent, the following line is printed out in the console of
  the launched application:

    "Sending SMS to XXXXXXXXXX >> '<TEXT>'... Success"

   - Where XXXXXXXXXX is the phone number that send the SMS and <TEXT> is the
     text contained in the SMS message.
