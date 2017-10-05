XBee Python samples
===================

The XBee Python Library includes several samples to demonstrate how to do the
following:

* Communicate with your modules
* Configure your modules
* Read the IO lines
* Perform other common operations

All of the sample applications are contained in the examples folder, organized
by category. Every sample includes the source code and a **readme.txt** file
to clarify the purpose and the required setup to launch the application.

Examples are split by categories:

* :ref:`samplesConfiguration`
* :ref:`samplesNetwork`
* :ref:`samplesCommunication`
* :ref:`samplesIO`


.. _samplesConfiguration:

Configuration samples
---------------------

Manage common parameters
````````````````````````

This sample application shows how to get and set common parameters of the XBee
device. Common parameters are split in cached and non-cached parameters. For
that reason, the application refreshes the cached parameters before reading and
displaying them. The application then configures, reads, and displays the value
of non-cached parameters.

The application uses the specific setters and getters provided by the XBee
device object to configure and read the different parameters.

You can locate the example in the following path:
**examples/configuration/ManageCommonParametersSample**

.. note::
   For more information about how to manage common parameters, see
   :ref:`configCommonParameters`.


Set and get parameters
``````````````````````

This sample application shows how to set and get parameters of a local or
remote XBee device. Use this method when you need to set or get the value of a
parameter that does not have its own getter and setter within the XBee device
object.

The application sets the value of four parameters with different value types:

* String
* Byte
* Array
* Integer

The application then reads the parameters from the device to verify that the
read values are the same as the values that were set.

You can locate the example in the following path:
**examples/configuration/SetAndGetParametersSample**

.. note::
   For more information about how to get and set other parameters, see
   :ref:`configOtherParameters`.


Reset module
````````````

This sample application shows how to perform a software reset on the local XBee
module.

You can locate the example in the following path:
**examples/configuration/ResetModuleSample**

.. note::
   For more information about how to reset a module, see
   :ref:`configReset`.


Connect to access point (Wi-Fi)
```````````````````````````````

This sample application shows how to configure a Wi-Fi module to connect to a
specific access point and read its addressing settings.

You can locate the example at the following path:
**examples/configuration/ConnectToAccessPoint**

.. note::
   For more information about connecting to an access point, see
   :ref:`configWiFi`.


.. _samplesNetwork:

Network samples
---------------

Discover devices
````````````````

This sample application demonstrates how to obtain the XBee network object
from a local XBee device and discover the remote XBee devices that compose the
network. The example adds a discovery listener, so the callbacks provided by
the listener object receive the events.

The remote XBee devices are printed out as soon as they are found during
discovery.

You can locate the example in the following path:
**examples/network/DiscoverDevicesSample**

.. note::
   For more information about how to perform a network discovery, see
   :ref:`discoverNetwork`.


.. _samplesCommunication:

Communication samples
---------------------

Send data
`````````

This sample application shows how to send data from the XBee device to another
remote device on the same network using the XBee Python Library. In this
example, the application sends data using a reliable transmission method. The
application blocks during the transmission request, but you are notified if
there is any error during the process.

The application sends data to a remote XBee device on the network with a
specific node identifier (name).

You can locate the example in the following path:
**examples/communication/SendDataSample**

.. note::
   For more information about how to send data, see
   :ref:`communicateSendData`.


Send data asynchronously
````````````````````````

This sample application shows how to send data asynchronously from the XBee
device to another remote device on the same network using the XBee Python
Library. Transmitting data asynchronously means the execution is not blocked
during the transmit request, but you cannot determine if the data was sent
successfully.

The application sends data asynchronously to a remote XBee device on the
network with a specific node identifier (name).

You can locate the example in the following path:
**examples/communication/SendDataAsyncSample**

.. note::
   For more information about how to send data, see
   :ref:`communicateSendData`.


Send broadcast data
```````````````````

This sample application shows how to send data from the local XBee device to
all remote devices on the same network (broadcast) using the XBee Python
Library. The application blocks during the transmission request, but you are
notified if there is any error during the process.

You can locate the example in the following path:
**examples/communication/SendBroadcastDataSample**

.. note::
   For more information about how to send broadcast data, see
   :ref:`communicateSendBroadcastData`.


Send explicit data
``````````````````

This sample application shows how to send data in application layer (explicit)
format to a remote ZigBee device on the same network as the local one using the
XBee Python Library. In this example, the XBee module sends explicit data using
a reliable transmission method. The application blocks during the transmission
request, but you are notified if there is any error during the process.

You can locate the example in the following path:
**examples/communication/explicit/SendExplicitDataSample**

.. note::
   For more information about how to send explicit data, see
   :ref:`communicateSendExplicitData`.


Send explicit data asynchronously
`````````````````````````````````

This sample application shows how to send data in application layer (explicit)
format asynchronously to a remote ZigBee device on the same network as the
local one using the XBee Python Library. Transmitting data asynchronously means
the execution is not blocked during the transmit request, but you cannot
determine if the data was sent successfully.

You can locate the example in the following path:
**examples/communication/explicit/SendExplicitDataAsyncSample**

.. note::
   For more information about how to send explicit data, see
   :ref:`communicateSendExplicitData`.


Send broadcast explicit data
````````````````````````````

This sample application shows how to send data in application layer (explicit)
format to all remote devices on the same network (broadcast) as the local one
using the XBee Python Library. The application blocks during the transmission
request, but you are notified if there is any error during the process.

You can locate the example in the following path:
**examples/communication/explicit/SendBroadcastExplicitDataSample**

.. note::
   For more information about how to send broadcast explicit data, see
   :ref:`communicateSendBroadcastExplicitData`.


Send IP data (IP devices)
`````````````````````````

This sample application shows how to send IP data to another device specified
by its IP address and port number.

You can find the example at the following path:
**examples/communication/ip/SendIPDataSample**

.. note::
   For more information about how to send IP data, see
   :ref:`communicateSendIPData`.


Send SMS (cellular devices)
```````````````````````````

This sample application shows how to send an SMS to a phone or cellular device.

You can find the example at the following path:
**examples/communication/cellular/SendSMSSample**

.. note::
   For more information about how to send SMS messages, see
   :ref:`communicateSendSMS`.


Send UDP data (IP devices)
``````````````````````````

This sample application shows how to send UDP data to another device specified
by its IP address and port number.

You can find the example at the following path:
**examples/communication/ip/SendUDPDataSample**

.. note::
   For more information about how to send IP data, see
   :ref:`communicateSendIPData`.


Receive data
````````````

This sample application shows how data packets are received from another XBee
device on the same network.

The application prints the received data to the standard output in ASCII and
hexadecimal formats after the sender address.

You can locate the example in the following path:
**examples/communication/ReceiveDataSample**

.. note::
   For more information about how to receive data using a callback, see
   :ref:`communicateReceiveDataCallback`.


Receive data polling
````````````````````

This sample application shows how data packets are received from another XBee
device on the same network using a polling mechanism.

The application prints the data that was received to the standard output in
ASCII and hexadecimal formats after the sender address.

You can locate the example in the following path:
**examples/communication/ReceiveDataPollingSample**

.. note::
   For more information about how to receive data using a polling mechanism,
   see :ref:`communicateReceiveDataPolling`.


Receive explicit data
`````````````````````

This sample application shows how a ZigBee device receives data in application
layer (explicit) format using a callback executed every time new data is
received. Before receiving data in explicit format, the API output mode of the
ZigBee device is configured in explicit mode.

You can locate the example in the following path:
**examples/communication/explicit/ReceiveExplicitDataSample**

.. note::
   For more information about how to receive explicit data using a callback,
   see :ref:`communicateReceiveExplicitDataCallback`.


Receive explicit data polling
`````````````````````````````

This sample application shows how a ZigBee device receives data in application
layer (explicit) format using a polling mechanism. Before receiving data in
explicit format, the API output mode of the ZigBee device is configured in
explicit mode.

You can locate the example in the following path:
**examples/communication/explicit/ReceiveExplicitDataPollingSample**

.. note::
   For more information about how to receive explicit data using a polling
   mechanism, see :ref:`communicateReceiveExplicitDataPolling`.


Receive IP data (IP devices)
````````````````````````````

This sample application shows how an IP device receives IP data using a
callback executed every time it receives new IP data.

You can find the example at the following path:
**examples/communication/ip/ReceiveIPDataSample**

.. note::
   For more information about how to receive IP data using a polling mechanism,
   see :ref:`communicateReceiveIPData`.


Receive SMS (cellular devices)
``````````````````````````````

This sample application shows how to receive SMS messages configuring a
callback executed when new SMS is received.

You can find the example at the following path:
**examples/communication/cellular/ReceiveSMSSample**

.. note::
   For more information about how to receive SMS messages, see
   :ref:`communicateReceiveSMS`.


Receive modem status
````````````````````

This sample application shows how modem status packets (events related to the
device and the network) are handled using the API.

The application prints the modem status events to the standard output when
received.

You can locate the example in the following path:
**examples/communication/ReceiveModemStatusSample**

.. note::
   For more information about how to receive modem status events, see
   :ref:`communicateReceiveModemStatus`.


Connect to echo server (IP devices)
```````````````````````````````````

This sample application shows how IP devices can connect to an echo server,
send data to it and reads the echoed data.

You can find the example at the following path:
**examples/communication/ip/ConnectToEchoServerSample**

.. note::
   For more information about how to send and receive IP data, see
   :ref:`communicateSendIPData` and :ref:`communicateReceiveIPData`.


.. _samplesIO:

IO samples
----------

Local DIO
`````````

This sample application shows how to set and read XBee digital lines of the
device attached to the serial/USB port of your PC.

The application configures two IO lines of the XBee device:  one as a digital
input (button) and the other as a digital output (LED). The application reads
the status of the input line periodically and updates the output to follow the
input.

The LED lights up while you press the button.

You can locate the example in the following path:
**examples/io/LocalDIOSample**

.. note::
   For more information about how to set and read digital lines, see
   :ref:`linesDIO`.


Local ADC
`````````

This sample application shows how to read XBee analog inputs of the device
attached to the serial/USB port of your PC.

The application configures an IO line of the XBee device as ADC. It
periodically reads its value and prints it in the output console.

You can locate the example in the following path:
**examples/io/LocalADCSample**

.. note::
   For more information about how to read analog lines, see
   :ref:`linesADC`.


Remote DIO
``````````
This sample application shows how to set and read XBee digital lines of remote
devices.

The application configures two IO lines of the XBee devices: one in the remote
device as a digital input (button) and the other in the local device as a
digital output (LED). The application reads the status of the input line
periodically and updates the output to follow the input.

The LED lights up while you press the button.

You can locate the example in the following path:
**examples/io/RemoteDIOSample**

.. note::
   For more information about how to set and read digital lines, see
   :ref:`linesDIO`.


Remote ADC
``````````

This sample application shows how to read XBee analog inputs of remote XBee
devices.

The application configures an IO line of the remote XBee device as ADC. It
periodically reads its value and prints it in the output console.

You can locate the example in the following path:
**examples/io/RemoteADCSample**

.. note::
   For more information about how to read analog lines, see
   :ref:`linesADC`.


IO sampling
```````````

This sample application shows how to configure a remote device to send
automatic IO samples and how to read them from the local module.

The application configures two IO lines of the remote XBee device: one as
digital input (button) and the other as ADC, and enables periodic sampling and
change detection. The device sends a sample every five seconds containing the
values of the two monitored lines. The device sends another sample every time
the button is pressed or released, which only contains the value of this
digital line.

The application registers a listener in the local device to receive and handle
all IO samples sent by the remote XBee module.

You can locate the example in the following path:
**examples/io/IOSamplingSample**

.. note::
   For more information about how to read IO samples, see
   :ref:`linesReadIOSamples`.
