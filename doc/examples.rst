XBee Python samples
===================

The XBee Python Library includes several samples to demonstrate how to do the
following:

* Communicate with your modules
* Configure your modules
* Read the IO lines
* Update device's firmware
* Work with device's file system
* Apply XBee profiles
* Perform other common operations

All of the sample applications are contained in the examples folder, organized
by category. Every sample includes the source code and a **readme.txt** file
to clarify the purpose and the required setup to launch the application.

Examples are split by categories:

* :ref:`samplesConfiguration`
* :ref:`samplesNetwork`
* :ref:`samplesCommunication`
* :ref:`samplesIO`
* :ref:`samplesFirmware`
* :ref:`samplesFilesystem`
* :ref:`samplesProfile`


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


Recover XBee serial connection
``````````````````````````````

This sample application shows how to recover the serial settings of a local XBee.

You can locate the example at the following path:
**examples/configuration/RecoverSerialConnection**

.. note::
   For more information about this, see :ref:`openXBeeConnection`.


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


Network modifications sample
````````````````````````````

This sample application demonstrates how to listen to network modification
events. The example adds a modifications network callback, so modifications
events are received and printed out.

A network is modified when:

* a new node is added by discovering, manually, or because data is
  received from it
* an existing node is removed from the network
* an existing node is updated with new information
* it is fully cleared

You can locate the example in the following path:
**examples/network/NetworkModificationsSample**

.. note::
   For more information about how to listen to network modifications, see
   :ref:`listenToNetworkCacheModifications`.

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
during the transmit request, but you cannot determine if the data was
successfully sent.

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

This sample application shows how to send data in the application layer
(explicit) format to a remote Zigbee device using the XBee Python Library.
In this example, the XBee module sends explicit data using a reliable
transmission method. The application blocks during the transmission request,
but you are notified if there is any error during the process.

You can locate the example in the following path:
**examples/communication/explicit/SendExplicitDataSample**

.. note::
   For more information about how to send explicit data, see
   :ref:`communicateSendExplicitData`.


Send explicit data asynchronously
`````````````````````````````````

This sample application shows how to send data in the application layer
(explicit) format asynchronously to a remote Zigbee device using the XBee
Python Library. Transmitting data asynchronously means the execution is not
blocked during the transmit request, but you cannot determine if the data was
successfully sent.

You can locate the example in the following path:
**examples/communication/explicit/SendExplicitDataAsyncSample**

.. note::
   For more information about how to send explicit data, see
   :ref:`communicateSendExplicitData`.


Send broadcast explicit data
````````````````````````````

This sample application shows how to send data in the application layer
(explicit) format to all remote devices on the network (broadcast) using the
XBee Python Library. The application blocks during the transmission request,
but you are notified if there is any error during the process.

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


Send Bluetooth Data
```````````````````

This sample application shows how to send data to the XBee Bluetooth Low Energy
interface.

You can find the example at the following path:
**examples/communication/bluetooth/SendBluetoothDataSample**

.. note::
   For more information about sending Bluetooth data, see
   :ref:`communicateSendBluetoothData`.


Send MicroPython Data
`````````````````````

This sample application shows how to send data to the XBee MicroPython
interface.

You can find the example at the following path:
**examples/communication/micropython/SendMicroPythonDataSample**

.. note::
   For more information about sending MicroPython data, see
   :ref:`communicateSendMicroPythonData`.


Send User Data Relay
````````````````````

This sample application shows how to send data to other XBee interface.

You can find the example at the following path:
**examples/communication/relay/SendUserDataRelaySample**

.. note::
   For more information about sending User Data Relay messages, see
   :ref:`communicateSendBluetoothData` or :ref:`communicateSendMicroPythonData`.


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

This sample application shows how a Zigbee device receives data in the
application layer (explicit) format using a callback executed every time new
data is received. Before receiving data in explicit format, the API output mode
of the Zigbee device is configured in explicit mode.

You can locate the example in the following path:
**examples/communication/explicit/ReceiveExplicitDataSample**

.. note::
   For more information about how to receive explicit data using a callback,
   see :ref:`communicateReceiveExplicitDataCallback`.


Receive explicit data polling
`````````````````````````````

This sample application shows how a Zigbee device receives data in the
application layer (explicit) format using a polling mechanism. Before receiving
data in explicit format, the API output mode of the Zigbee device is configured
in explicit mode.

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


Receive Bluetooth data
``````````````````````

This sample application shows how to receive data from the XBee Bluetooth Low
Energy interface.

You can find the example at the following path:
**examples/communication/bluetooth/ReceiveBluetoothDataSample**

.. note::
   For more information about receiving Bluetooth data, see
   :ref:`communicateReceiveBluetoothData`.


Receive Bluetooth file
``````````````````````

This sample application shows how to receive a file from the XBee Bluetooth Low
Energy interface.

You can find the example at the following path:
**examples/communication/bluetooth/ReceiveBluetoothFileSample**

.. note::
   For more information about receiving Bluetooth data, see
   :ref:`communicateReceiveBluetoothData`.


Receive MicroPython data
````````````````````````

This sample application shows how to receive data from the XBee MicroPython
interface.

You can find the example at the following path:
**examples/communication/micropython/ReceiveMicroPythonDataSample**

.. note::
   For more information about receiving MicroPython data, see
   :ref:`communicateReceiveMicroPythonData`.


Receive User Data Relay
```````````````````````

This sample application shows how to receive data from other XBee interface.

You can find the example at the following path:
**examples/communication/relay/ReceiveUserDataRelaySample**

.. note::
   For more information about receiving User Data Relay messages, see
   :ref:`communicateReceiveBluetoothData` or
   :ref:`communicateReceiveMicroPythonData`.


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


Create a TCP client socket (cellular devices)
`````````````````````````````````````````````

This sample application shows how to create a TCP client socket to send HTTP
requests.

You can find the example at the following path:
**examples/communication/socket/SocketTCPClientSample**

.. note::
   For more information about how to use the XBee socket API, see
   :ref:`communicateXBeeSockets`.


Create a TCP server socket (cellular devices)
`````````````````````````````````````````````

This sample application shows how to create a TCP server socket to receive data
from incoming sockets.

You can find the example at the following path:
**examples/communication/socket/SocketTCPServerSample**

.. note::
   For more information about how to use the XBee socket API, see
   :ref:`communicateXBeeSockets`.


Create a UDP server/client socket (cellular devices)
````````````````````````````````````````````````````

This sample application shows how to create a UDP socket to deliver messages to
a server and listen for data coming from multiple peers.

You can find the example at the following path:
**examples/communication/socket/SocketUDPServerClientSample**

.. note::
   For more information about how to use the XBee socket API, see
   :ref:`communicateXBeeSockets`.


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


.. _samplesFirmware:

Firmware samples
----------------

Update local firmware
`````````````````````

This sample Python application shows how to update the firmware of a local
XBee device.

The application provides the required hardware files to the update method
as well as a callback function to be notified of progress.

You can locate the example in the following path:
**examples/firmware/LocalFirmwareUpdateSample**


Update remote firmware
``````````````````````

This sample Python application shows how to update the firmware of a remote
XBee device.

The application provides the required hardware files to the update method
as well as a callback function to be notified of progress.

You can locate the example in the following path:
**examples/firmware/RemotelFirmwareUpdateSample**


.. _samplesFilesystem:

File system samples
-------------------

Format file system
``````````````````

This sample Python application shows how to format the filesystem of a
local XBee device and retrieve usage information.

The application uses the LocalXBeeFileSystemManager to access the device
filesystem and execute the required actions.

You can locate the example in the following path:
**examples/filesystem/FormatFilesystemSample**


List directory contents
```````````````````````

This sample Python application shows how to list the contents of an XBee
device filesystem directory.

The application uses the LocalXBeeFileSystemManager to access the device
filesystem and executes the required actions.

You can locate the example in the following path:
**examples/filesystem/ListDirectorySample**


Upload/download file
````````````````````

This sample Python application shows how to upload and download a file from
a local XBee device filesystem.

The application uses the LocalXBeeFileSystemManager to access the device
filesystem and provides the local file and the necessary paths to the
upload/download methods as well as callback functions to be notified of
progress.

You can locate the example in the following path:
**examples/filesystem/UploadDownloadFileSample**


.. _samplesProfile:

Profile samples
---------------

Apply local profile
```````````````````

This sample Python application shows how to apply an existing XBee profile
to a XBee device.

The application provides the profile file to the update method as well as a
callback function to be notified of progress.

You can locate the example in the following path:
**examples/profile/ApplyXBeeProfileSample**


Apply remote profile
````````````````````

This sample Python application shows how to apply an existing XBee profile
to a remote XBee device.

The application provides the profile file to the update method as well as a
callback function to be notified of progress.

You can locate the example in the following path:
**examples/profile/ApplyXBeeProfileRemoteSample**


Read profile
````````````

This sample Python application shows how to read an existing XBee profile
and extract its properties.

The application creates an XBee profile object from an existing XBee profile
file and prints all the accessible settings and properties.

You can locate the example in the following path:
**examples/profile/ReadXBeeProfileSample**
