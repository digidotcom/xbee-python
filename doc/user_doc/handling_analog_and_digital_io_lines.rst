Handle analog and digital IO lines
==================================

All the XBee modules, regardless of the protocol they run, have a set of IO
lines (pins). You can use these pins to connect sensors or actuators and
configure them with specific behavior.

You can configure the IO lines of an XBee to be digital input/output (DIO),
analog to digital converter (ADC), or pulse-width modulation output (PWM). The
configuration you provide to a line depends on the device you are connecting.

.. note::
  All the IO management features displayed in this topic and sub-topics are
  applicable for both local and remote XBee devices.

The XBee Python Library exposes an easy way to configure, read, and write the
IO lines of the local and remote XBee devices through the following
corresponding classes:

* ``XBeeDevice`` for local devices.
* ``RemoteXBeeDevice`` for remotes.


Configure the IO lines
----------------------

All XBee objects include a configuration method, ``set_io_configuration()``,
to specify the IO line to configure and their desired function.

For the IO line parameter, the API provides an enumerator called ``IOLine``
that helps you specify the desired IO line by functional name. This enumerator
is used along all the IO related methods in the API.

The supported functions are also contained in an enumerator called ``IOMode``.
You can choose between the following functions:

* DISABLED
* SPECIAL_FUNCTIONALITY (Shouldn't be used to configure IOs)
* PWM
* ADC
* DIGITAL_IN
* DIGITAL_OUT_LOW
* DIGITAL_OUT_HIGH

**Configure local or remote IO lines**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Instantiate a remote XBee object.
  remote = RemoteXBeeDevice(xbee, XBee64BitAddress.from_hex_string("0013A20012345678"))

  # Configure the DIO1_AD1 line of the local device to be Digital output (set high by default).
  xbee.set_io_configuration(IOLine.DIO1_AD1, IOMode.DIGITAL_OUT_HIGH)

  # Configure the DIO2_AD2 line of the local device to be Digital input.
  xbee.set_io_configuration(IOLine.DIO2_AD2, IOMode.DIGITAL_IN)

  # Configure the DIO3_AD3 line of the remote device to be Analog input (ADC).
  remote.set_io_configuration(IOLine.DIO3_AD3, IOMode.ADC)

  # Configure the DIO10_PWM0 line of the remote device to be PWM output (PWM).
  remote.set_io_configuration(IOLine.DIO10_PWM0, IOMode.PWM)

  [...]

The ``set_io_configuration()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

You can read the current configuration of any IO line using the corresponding
getter, ``get_io_configuration()``.

**Get IO configuration**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Get the configuration mode of the DIO1_AD1 line.
  io_mode = xbee.get_io_configuration(IOLine.DIO1_AD1)

  [...]

The ``get_io_configuration()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


.. _linesDIO:

Digital Input/Output
````````````````````

If your IO line is configured as digital output, you can set its state
(high/low). All the XBee classes provide the method ``set_dio_value()``, with
the desired ``IOLine`` as the first parameter and an ``IOValue`` as the second
one. The ``IOValue`` enumerator includes ``HIGH`` and ``LOW`` as possible
values.

**Set digital output values**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Set the DIO2_AD2 line low.
  xbee.set_dio_value(IOLine.DIO2_AD2, IOValue.LOW)

  # Set the DIO2_AD2 line high.
  xbee.set_dio_value(IOLine.DIO2_AD2, IOValue.HIGH)

  [...]

The ``set_dio_value()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

You can also read the current status of the pin (high/low) by issuing the
method ``get_dio_value()``. The parameter of the method must be the IO line to
read.

**Read digital input values**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  # Get the value of the DIO2_AD2.
  value = xbee.get_dio_value(IOLine.DIO2_AD2)

  [...]

The ``get_dio_value()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * If the received response does not contain the value for the given IO
      line, throwing an ``OperationNotSupportedException``. This can happen (for
      example) if you try to read the DIO value of an IO line that is not
      configured as DIO.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Handle DIO IO lines                                                                                                                                                             |
+==========================================================================================================================================================================================+
| The XBee Python Library includes two sample applications that demonstrate how to handle DIO lines in your local and remote XBee Devices. The examples are located in the following path: |
|                                                                                                                                                                                          |
| **examples/io/LocalDIOSample/LocalDIOSample.py**                                                                                                                                         |
|                                                                                                                                                                                          |
| **examples/io/RemoteDIOSample/RemoteDIOSample.py**                                                                                                                                       |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _linesADC:

ADC
```

When you configure an IO line as analog to digital converter (ADC), read its
value (counts) with ``get_adc_value()``. The method used to read ADCs is
different than the digital I/O method, but the parameter provided is the same:
the IO line to read the value from.

**Read ADC values**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Get the value of the DIO 3 (analog to digital converter).
  value = xbee.get_adc_value(IOLine.DIO3_AD3)

  [...]

The ``get_adc_value()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as `XBeeException`:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * If the received response does not contain the value for the given IO
      line, throwing an ``OperationNotSupportedException``. This can happen (for
      example) if you try to read the ADC value of an IO line that is not
      configured as ADC.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Handle ADC IO lines                                                                                                                                                             |
+==========================================================================================================================================================================================+
| The XBee Python Library includes two sample applications that demonstrate how to handle ADC lines in your local and remote XBee devices. The examples are located in the following path: |
|                                                                                                                                                                                          |
| **examples/io/LocalADCSample/LocalADCSample.py**                                                                                                                                         |
|                                                                                                                                                                                          |
| **examples/io/RemoteADCSample/RemoteADCSample.py**                                                                                                                                       |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


PWM
```

Not all the XBee protocols support pulse-width modulation (PWM) output handling,
but the XBee Python Library provides functionality to manage them.
When you configure an IO line as PWM output, you must use specific methods to
set and read the duty cycle of the PWM.

The duty cycle is the proportion of 'ON' time to the regular interval or
'period' of time. A high duty cycle corresponds to high power, because the power
is ON for most of the time.

To set de duty cycle value, use the method ``set_pwm_duty_cycle()`` and provide
the IO line configured as PWM, and the value of the duty cycle in % of the PWM.
The percentage parameter is a double, which allows you to be more precise in the
configuration.

**Set the duty cycle of an IO line configure as PWM**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Set a duty cycle of 75% to the DIO10_PWM0 line (PWM output).
  xbee.set_pwm_duty_cycle(IOLine.DIO10_PWM0, 75)

  [...]

The ``set_pwm_duty_cycle()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

The ``get_pwm_duty_cycle()`` method returns a double value with the current
duty cycle percentage of the provided PWM line.

**Get the duty cycle of an IO line configured as PWM**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Get the duty cycle of the DIO10_PWM0 line (PWM output).
  duty_cycle = xbee.get_pwm_duty_cycle(IOLine.DIO10_PWM0);

  [...]

.. note::
  In both cases (get and set), the IO line provided must be PWM capable and
  configured as PWM output.


.. _linesReadIOSamples:

Read IO samples
---------------

XBee modules can monitor and sample the analog and digital IO lines. You can
read IO samples locally or transmit them to another node to provide an
indication of the current IO line states.

There are three ways to obtain IO samples on a local or remote device:

* Queried sampling
* Periodic sampling
* Change detection sampling

The XBee Python Library represents an IO sample by the ``IOSample`` class, which
contains:

* Digital and analog channel masks that indicate which lines have sampling
  enabled.
* Values of those enabled lines.

You must configure the IO lines you want to receive in the IO samples before
enabling IO sampling.


Queried sampling
````````````````

The XBee Python Library provides a method to read an IO sample that contains
all enabled digital IO and analog input channels, ``read_io_sample()``. The
method returns an IOSample object.

**Read an IO sample and getting the DIO value**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Read an IO sample from the device.
  io_sample = xbee.read_io_sample()

  # Select the desired IO line.
  io_line = IOLine.DIO3_AD3

  # Check if the IO sample contains the expected IO line and value.
  if io_sample.has_digital_value(io_line):
      print("DIO3 value: %s" % io_sample.get_digital_value(ioLine))

  [...]

The ``read_io_sample()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


Periodic sampling
`````````````````

Periodic sampling allows an XBee module to take an IO sample and transmit it
to another node at a periodic rate. This destination node is defined in the
destination address through the ``set_dest_address()`` method. The XBee Python
Library provides the ``set_io_sampling_rate()`` method to configure the periodic
sampling.

The XBee module samples and transmits all enabled digital IO and analog inputs
to the configured destination node every X seconds. A sample rate of 0s disables
this feature.

**Set the IO sampling rate**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Set the destination address.
  xbee.set_dest_address(XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Set the IO sampling rate.
  xbee.set_io_sampling_rate(5)  # 5 seconds.

  [...]

The ``set_io_sampling_rate()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

You can also read this value using the ``get_io_sampling_rate()`` method. This
method returns the IO sampling rate in milliseconds and '0' when the feature
is disabled.

**Get the IO sampling rate**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Get the IO sampling rate.
  value = xbee.get_io_sampling_rate()

  [...]

The ``get_io_sampling_rate()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


Change detection sampling
-------------------------

You can configure modules to transmit a data sample immediately whenever a
monitored digital IO pin changes state. The ``set_dio_change_detection()``
method establishes the set of digital IO lines that are monitored for change
detection. A ``None`` set disables the change detection sampling.

As in the periodic sampling, change detection samples are transmitted to the
configured destination address.

.. note::
  This feature only monitors and samples digital IOs, so it is not valid for
  analog lines.

**Set the DIO change detection**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Set the destination address.
  xbee.set_dest_address(XBee64BitAddress.from_hex_string("0013A20040XXXXXX"))

  # Create a set of IO lines to be monitored.
  lines = [IOLine.DIO3_AD3, IOLine.DIO4_AD4]

  # Enable the DIO change detection sampling.
  xbee.set_dio_change_detection(lines)

  [...]

The ``set_dio_change_detection()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:

    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.

You can also get the lines being monitored using the
``get_dio_change_detection()`` method. A ``None`` value indicates that this
feature is disabled.

**Get the DIO change detection**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Get the set of lines that are monitored.
  lines = xbee.get_dio_change_detection()

  [...]

The ``get_dio_change_detection()`` method may fail for the following reasons:

* ACK of the sent command is not received in the configured timeout, throwing
  a ``TimeoutException``.
* Other errors caught as ``XBeeException``:
    * The operating mode of the device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.
    * The response of the command is not valid, throwing an
      ``ATCommandException``.
    * There is an error writing to the XBee interface, throwing a generic
      ``XBeeException``.


Register an IO sample listener
``````````````````````````````

In addition to configuring an XBee to monitor and sample the analog and digital
IO lines, you must register a callback in the local device where you want to
receive the IO samples. Then, you are notified when the local XBee receives a
new IO sample.

You must subscribe to the IO samples reception service by using the method
``add_io_sample_received_callback()`` with an IO sample reception callback
function as parameter.

**Add an IO sample callback**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Define the IO sample receive callback.
  def io_sample_callback(io_sample, remote_xbee, send_time):
      print("IO sample received at time %s." % str(send_time))
      print("IO sample:")
      print(str(io_sample))

  # Subscribe to IO samples reception.
  xbee.add_io_sample_received_callback(io_sample_callback)

  [...]

This callback function receives three parameters when an IO sample arrives:

* The received IO sample as an ``IOSample`` object.
* The remote XBee that sent the IO sample as a ``RemoteXBeeDevice`` object.
* The time in which the IO sample was received as an ``Float`` (calculated
  with Python standard ``time.time()``).

To stop receiving notifications of new IO samples, remove the added callback
using the ``del_io_sample_received_callback()`` method.

**Remove an IO sample callback**

.. code:: python

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice("COM1", 9600)
  xbee.open()

  [...]

  # Define the IO sample receive callback.
  def io_sample_callback(io_sample, remote_xbee, send_time):
      print("IO sample received at time %s." % str(send_time))
      print("IO sample:")
      print(str(io_sample))

  # Subscribe to IO samples reception by adding the callback.
  xbee.add_io_sample_received_callback(io_sample_callback)

  [...]

  # Unsubscribe from IO samples reception by removing the callback.
  xbee.del_io_sample_received_callback(io_sample_callback)

  [...]

The ``del_io_sample_received_callback()`` method raises a ``ValueError`` if
you try to delete a callback that you have not added yet.

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Receive IO samples                                                                                                                                                                                                |
+============================================================================================================================================================================================================================+
| The XBee Python Library includes a sample application that demonstrates how to configure a remote device to monitor IO lines and receive the IO samples in the local device. The example is located in the following path: |
|                                                                                                                                                                                                                            |
| **examples/io/IOSamplingSample/IOSamplingSample.py**                                                                                                                                                                       |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
