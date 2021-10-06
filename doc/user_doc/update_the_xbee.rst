Update the XBee
===============

To keep your XBee devices up to date, the XBee Python Library provides several
methods to update the device software including firmware, file system and XBee
profiles:

* :ref:`updateFirmware`
* :ref:`updateFilesystem`
* :ref:`applyProfile`
* :ref:`updateMultiple`

.. warning::
  At the moment, update features are only supported in:
    * **XBee 3**:
        * Local and remote firmware updates
        * Local and remote file system updates
        * Local and remote profile updates
    * **XBee SX 868/900 MHz**
        * Local and remote firmware updates
        * Local and remote profile updates
    * **XBee S2C**
        * Remote firmware updates
        * Remote profile updates


.. _updateFirmware:

Update the XBee firmware
------------------------

You may need to update the running firmware of your XBee devices to, for
example, change their XBee protocol, fix issues and security risks, or access to
new features and functionality.

The XBee Python Library provides methods to perform firmware updates in local
and remote devices:

* :ref:`updateFirmwareLocal`
* :ref:`updateFirmwareRemote`

.. warning::
  At the moment, firmware update is only supported in:
    * **XBee 3**: Local and remote firmware updates
    * **XBee SX 868/900 MHz**: Local and remote firmware updates
    * **XBee S2C**: Remote firmware updates


.. _updateFirmwareLocal:

Update the firmware of a local XBee
```````````````````````````````````

The firmware update process of a local XBee is performed over the serial
connection. For this operation, you need the following components:

* The XBee object instance or the serial port name where the device is
  attached to.
* The new firmware XML descriptor file.
* The new firmware binary file (\*.gbl)
* Optionally, the new bootloader binary file (\*.gbl) required by the new
  firmware.

.. warning::
  Firmware update will fail if the firmware requires a new bootloader and it is
  not provided.

.. warning::
  At the moment, local firmware update is only supported in **XBee 3** and
  **XBee SX 868/900 MHz** devices.


+------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Local Firmware Update                                                                                                                       |
+======================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to perform a local firmware update. It can be located in the following path: |
|                                                                                                                                                      |
| **examples/firmware/LocalFirmwareUpdateSample/LocalFirmwareUpdateSample.py**                                                                         |
+------------------------------------------------------------------------------------------------------------------------------------------------------+


Update the local firmware using an XBee object
''''''''''''''''''''''''''''''''''''''''''''''

If you have an object instance of your local XBee, call the
``update_firmware()`` method of the ``XBeeDevice`` class providing the required
parameters:

+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------+
| Method                                 | Description                                                                                                                    |
+========================================+================================================================================================================================+
| **update_firmware(String, String,**    | Performs a firmware update operation of the local XBee.                                                                        |
| **String, Integer, Function)**         |                                                                                                                                |
|                                        | * **xml_firmware_file (String)**: path of the XML file that describes the firmware to upload.                                  |
|                                        | * **xbee_firmware_file (String, optional)**: location of the XBee binary firmware file (\*.gbl).                               |
|                                        | * **bootloader_firmware_file (String, optional)**: location of the bootloader binary firmware file (\*.gbl).                   |
|                                        | * **timeout (Integer, optional)**: the maximum amount of seconds to wait for target read operations during the update process. |
|                                        | * **progress_callback (Function, optional)**: function to execute to receive progress information. Receives two arguments:     |
|                                        |                                                                                                                                |
|                                        |   * The current update task as a String                                                                                        |
|                                        |   * The current update task percentage as an Integer                                                                           |
+----------------------------------------+--------------------------------------------------------------------------------------------------------------------------------+

The ``update_firmware()`` method may fail for the following reasons:

* The device does not support the firmware update operation, throwing a
  ``OperationNotSupportedException``.
* There is an error during the firmware update operation, throwing a
  ``FirmwareUpdateException``.
* Other errors caught as ``XBeeException``:

    * The device is not open, throwing a generic ``XBeeException``.
    * The operating mode of the local XBee is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.

**Update local XBee firmware using an XBee object**

.. code:: python

  [...]

  XML_FIRMWARE_FILE = "/home/user/my_firmware.xml"
  XBEE_FIRMWARE_FILE = "/home/user/my_firmware.gbl"
  BOOTLOADER_FIRMWARE_FILE = "/home/user/my_bootloader.gbl"

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Update the XBee firmware.
  xbee.update_firmware(XML_FIRMWARE_FILE,
                       xbee_firmware_file=XBEE_FIRMWARE_FILE,
                       bootloader_firmware_file=BOOTLOADER_FIRMWARE_FILE,
                       progress_callback=progress_callback,)

  [...]


Update the local firmware using a serial port
'''''''''''''''''''''''''''''''''''''''''''''

If you do not know the XBee serial communication parameters or you cannot
instantiate the XBee object (for example, if the device must be recovered), you
can perform the firmware update process by providing the serial port identifier
where the XBee is attached to.

In this scenario, use the ``update_local_firmware()`` method of the XBee
``firmware`` module providing the required parameters. The library forces the
XBee to reboot into bootloader mode, using the recovery mechanism, and performs
the firmware update from that point.

+---------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------+
| Method                                            | Description                                                                                                                    |
+===================================================+================================================================================================================================+
| **update_local_firmware(String or XBeeDevice,**   | Performs a local firmware update operation in the given target.                                                                |
| **String, String, String, Integer, Function)**    |                                                                                                                                |
|                                                   | * **target (String or ``XBeeDevice`)**: target of the firmware upload operation.                                               |
|                                                   |   * **String**: serial port identifier.                                                                                        |
|                                                   |   * **``XBeeDevice`**: the XBee to upload its firmware.                                                                        |
|                                                   | * **xml_firmware_file (String)**: path of the XML file that describes the firmware to upload.                                  |
|                                                   | * **xbee_firmware_file (String, optional)**: location of the XBee binary firmware file (\*.gbl).                               |
|                                                   | * **bootloader_firmware_file (String, optional)**: location of the bootloader binary firmware file.                            |
|                                                   | * **timeout (Integer, optional)**: the maximum amount of seconds to wait for target read operations during the update process. |
|                                                   | * **progress_callback (Function, optional)**: function to execute to receive progress information. Receives two arguments:     |
|                                                   |                                                                                                                                |
|                                                   |   * The current update task as a String                                                                                        |
|                                                   |   * The current update task percentage as an Integer                                                                           |
+---------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------+

The ``update_local_firmware()`` method may fail for the following reasons:

* There is an error during the firmware update operation, throwing a
  ``FirmwareUpdateException``.

**Update local XBee firmware using a serial port**

.. code:: python

  import digi.xbee.firmware

  [...]

  SERIAL_PORT = "COM1"

  XML_FIRMWARE_FILE = "/home/user/my_firmware.xml"
  XBEE_FIRMWARE_FILE = "/home/user/my_firmware.gbl"
  BOOTLOADER_FIRMWARE_FILE = "/home/user/my_bootloader.gbl"

  [...]

  # Update the XBee firmware using the serial port name.
  firmware.update_local_firmware(SERIAL_PORT,
                                 XML_FIRMWARE_FILE,
                                 xbee_firmware_file=XBEE_FIRMWARE_FILE,
                                 bootloader_firmware_file=BOOTLOADER_FIRMWARE_FILE,
                                 progress_callback=progress_callback,)

  [...]


.. _updateFirmwareRemote:

Update the firmware of a remote XBee
````````````````````````````````````

The firmware update process for remote XBee devices is performed over the air
using special XBee frames. For this operation, you need the following
components:

* The remote XBee object instance.
* The new firmware XML descriptor file.
* The new firmware binary file (\*.ota)
* Optionally, the new firmware binary file with the bootloader embedded (\*.otb)

.. warning::
  Firmware update fails if the firmware requires a new bootloader and the
  \*.otb file is not provided.

.. warning::
  At the moment, remote firmware update is only supported in **XBee 3**,
  **XBee SX 868/900 MHz**, and **XBee S2C** devices.

To perform the remote firmware update, call the ``update_firmware()`` method of
the ``RemoteXBeeDevice`` class providing the required parameters:

+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Method                                | Description                                                                                                                     |
+=======================================+=================================================================================================================================+
| **update_firmware(String, String,**   | Performs a remote firmware update operation of the device.                                                                      |
| **String, Integer, Function)**        |                                                                                                                                 |
|                                       | * **xml_firmware_file (String)**: path of the XML file that describes the firmware to upload.                                   |
|                                       | * **xbee_firmware_file (String, optional)**: location of the XBee binary firmware file (\*.ota).                                |
|                                       | * **bootloader_firmware_file (String, optional)**: location of the XBee binary firmware file with bootloader embedded (\*.otb). |
|                                       | * **timeout (Integer, optional)**: the maximum amount of seconds to wait for target read operations during the update process.  |
|                                       | * **progress_callback (Function, optional)**: function to execute to receive progress information. Receives two arguments:      |
|                                       |                                                                                                                                 |
|                                       |   * The current update task as a String                                                                                         |
|                                       |   * The current update task percentage as an Integer                                                                            |
+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+

The ``update_firmware()`` method may fail for the following reasons:

* The remote device does not support the firmware update operation, throwing a
  ``OperationNotSupportedException``.
* There is an error during the firmware update operation, throwing a
  ``FirmwareUpdateException``.
* Other errors caught as ``XBeeException``:

    * The local device is not open, throwing a generic ``XBeeException``.
    * The operating mode of the local device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.

**Update a remote XBee firmware**

.. code:: python

  [...]

  XML_FIRMWARE_FILE = "/home/user/my_firmware.xml"
  OTA_FIRMWARE_FILE = "/home/user/my_firmware.ota"
  OTB_FIRMWARE_FILE = "/home/user/my_firmware.otb"

  REMOTE_NODE_NAME = "REMOTE"

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the network.
  xnet = xbee.get_network()

  # Get the remote node.
  remote = xnet.discover_device(REMOTE_NODE_NAME)

  # Update the remote XBee firmware.
  remote.update_firmware(SERIAL_PORT,
                         XML_FIRMWARE_FILE,
                         xbee_firmware_file=OTA_FIRMWARE_FILE,
                         bootloader_firmware_file=OTB_FIRMWARE_FILE,
                         progress_callback=progress_callback,)

  [...]

+-------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Remote Firmware Update                                                                                                                       |
+=======================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to perform a remote firmware update. It can be located in the following path: |
|                                                                                                                                                       |
| **examples/firmware/RemoteFirmwareUpdateSample/RemoteFirmwareUpdateSample.py**                                                                        |
+-------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _updateFilesystem:

Update the XBee file system
---------------------------

XBee 3 devices feature file system capabilities, meaning that they are able to
persistently store files and folders in flash. The XBee Python Library provides
classes and methods to manage these files.

* :ref:`filesystemManager`
* :ref:`filesystemOperations`

.. warning::
  At the moment file system capabilities are only supported in **XBee 3**
  devices.


.. _filesystemManager:

Create file system manager
``````````````````````````

A ``LocalXBeeFileSystemManager`` object is required to work with local devices
file system. You can instantiate this class by providing the local XBee object.
Once you have the object instance, you must call the ``connect()`` method to
open the file system connection and leave it ready to work.

.. warning::
  File system operations take ownership of the serial port, meaning that you
  will stop receiving messages from the device until file system connection is
  closed. For this reason, it is recommended to call the ``disconnect()``
  method of the file system manager as soon as you finish working with it.

+------------------+-------------------------------------------------------------------------+
| Method           | Description                                                             |
+==================+=========================================================================+
| **connect()**    | Connects the file system manager.                                       |
+------------------+-------------------------------------------------------------------------+
| **disconnect()** | Disconnects the file system manager and restores the device connection. |
+------------------+-------------------------------------------------------------------------+

The ``connect()`` method may fail for the following reasons:

* The device does not support the file system capabilities, throwing a
  ``FileSystemNotSupportedException``.
* There is an error during the connect operation, throwing a
  ``FileSystemException``.

**Create a local file system manager**

.. code:: python

  from digi.xbee.filesystem import LocalXBeeFileSystemManager

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Create the file system manager and connect it.
  filesystem_manager = LocalXBeeFileSystemManager(xbee)
  filesystem_manager.connect()

  [...]

  filesystem_manager.disconnect()

  [...]


.. _filesystemOperations:

File system operations
``````````````````````

The file system manager provides several methods to navigate through the device
file system and operate with the different files and folders:

+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| Method                               | Description                                                                                                                                   |
+======================================+===============================================================================================================================================+
| **get_current_directory()**          | Returns the current device directory.                                                                                                         |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **change_directory(String)**         | Changes the current device working directory to the given one.                                                                                |
|                                      |                                                                                                                                               |
|                                      | * **directory (String)**: the new directory to change to.                                                                                     |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **make_directory(String)**           | Creates the provided directory.                                                                                                               |
|                                      |                                                                                                                                               |
|                                      | * **directory (String)**: the new directory to create.                                                                                        |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **list_directory(String)**           | Lists the contents of the given directory.                                                                                                    |
|                                      |                                                                                                                                               |
|                                      | * **directory (String, optional)**: the directory to list its contents. Optional. If not provided, the current directory contents are listed. |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **remove_element(String)**           | Removes the given file system element path.                                                                                                   |
|                                      |                                                                                                                                               |
|                                      | * **element_path (String)**: path of the file system element to remove.                                                                       |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **move_element(String, String)**     | Moves the given source element to the given destination path.                                                                                 |
|                                      |                                                                                                                                               |
|                                      | * **source_path (String)**: source path of the element to move.                                                                               |
|                                      | * **dest_path (String)**: destination path of the element to move.                                                                            |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **put_file(String, String,**         | Transfers the given file in the specified destination path of the XBee.                                                                       |
| **Boolean, Function)**               |                                                                                                                                               |
|                                      | * **source_path (String)**: the path of the file to transfer.                                                                                 |
|                                      | * **dest_path (String)**: the destination path to put the file in.                                                                            |
|                                      | * **secure (Boolean, optional)**: ``True`` if the file should be stored securely, ``False`` otherwise. Defaults to ``False``.                 |
|                                      | * **progress_callback (Function, optional)**: function to execute to receive progress information. Takes the following arguments:             |
|                                      |                                                                                                                                               |
|                                      |   * The progress percentage as integer.                                                                                                       |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **put_dir(String, String, Function)**| Uploads the given source directory contents into the given destination directory in the device.                                               |
|                                      |                                                                                                                                               |
|                                      | * **source_dir (String)**: the local directory to upload its contents.                                                                        |
|                                      | * **dest_dir (String, optional)**: the remote directory to upload the contents to. Defaults to current directory.                             |
|                                      | * **progress_callback (Function, optional)**: function to execute to receive progress information. Takes the following arguments:             |
|                                      |                                                                                                                                               |
|                                      |   * The file being uploaded as string.                                                                                                        |
|                                      |   * The progress percentage as integer.                                                                                                       |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **get_file(String, String,**         | Downloads the given XBee file in the specified destination path.                                                                              |
| **Function)**                        |                                                                                                                                               |
|                                      | * **source_path (String)**: the path of the XBee file to download.                                                                            |
|                                      | * **dest_path (String)**: the destination path to store the file in.                                                                          |
|                                      | * **progress_callback (Function, optional)**: function to execute to receive progress information. Takes the following arguments:             |
|                                      |                                                                                                                                               |
|                                      |   * The progress percentage as integer.                                                                                                       |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **format_filesystem()**              | Formats the device file system.                                                                                                               |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **get_usage_information()**          | Returns the file system usage information.                                                                                                    |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+
| **get_file_hash(String)**            | Returns the SHA256 hash of the given file path.                                                                                               |
|                                      |                                                                                                                                               |
|                                      | * **file_path (String)**: path of the file to get its hash.                                                                                   |
+--------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------+

The methods above may fail for the following reasons:

* There is an error executing the requested operation, throwing a
  ``FileSystemException``.

+----------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Format file system                                                                                                                        |
+====================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to format the device file system. It can be located in the following path: |
|                                                                                                                                                    |
| **examples/filesystem/FormatFilesystemSample/FormatFilesystemSample.py**                                                                           |
+----------------------------------------------------------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: List directory                                                                                                                                      |
+==============================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to list the contents of a device directory. It can be located in the following path: |
|                                                                                                                                                              |
| **examples/filesystem/ListDirectorySample/ListDirectorySample.py**                                                                                           |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Upload/download file                                                                                                                               |
+=============================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to upload/download a file from the device. It can be located in the following path: |
|                                                                                                                                                             |
| **examples/filesystem/UploadDownloadFileSample/UploadDownloadFileSample.py**                                                                                |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _applyProfile:

Apply an XBee profile
---------------------

An XBee profile is a snapshot of a specific XBee configuration, including
firmware, settings, and file system contents. The XBee Python API includes a
set of classes and methods to work with XBee profiles and apply them to local
and remote devices.

* :ref:`readXBeeProfile`
* :ref:`applyProfileLocal`
* :ref:`applyProfileRemote`

To configure individual settings see :ref:`configureXBee`.

.. note::
   Use `XCTU <http://www.digi.com/xctu>`_ to create configuration profiles.

.. warning::
  At the moment, firmware update is only supported in:
    * **XBee 3**: Local and remote profile updates
    * **XBee SX 868/900 MHz**: Local and remote profile updates
    * **XBee S2C**: Remote profile updates


.. _readXBeeProfile:

Read an XBee profile
````````````````````

The library provides a class called ``XBeeProfile`` that is used to read and
extract information of an existing XBee profile file.

To create an ``XBeeProfile`` object, provide the location of the profile file
in the class constructor.

**Instantiate a profile**

.. code:: python

  from digi.xbee.profile import XBeeProfile

  [...]

  PROFILE_PATH = "/home/user/my_profile.xpro"

  [...]

  # Create the XBee profile object.
  xbee_profile = XBeeProfile(PROFILE_PATH)

  [...]

The creation of the XBee profile object may fail for the following reasons:

* The provided profile file is not valid, throwing a ``ValueError``.
* There is any error reading the profile file, throwing a
  ``ProfileReadException``.

Once the XBee profile object is created, you can extract some profile
information by accessing each of the exposed properties:

+-------------------------------+--------------------------------------------------------------------------------------------------------+
| Property                      | Description                                                                                            |
+===============================+========================================================================================================+
| **profile_file**              | Returns the profile file.                                                                              |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **version**                   | Returns the profile version.                                                                           |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **flash_firmware_option**     | Returns the profile flash firmware option.                                                             |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **description**               | Returns the profile description.                                                                       |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **reset_settings**            | Returns whether the settings of the XBee are reset before applying the profile ones.                   |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **has_firmware_files**        | Returns whether the profile has firmware binaries (local or remote)                                    |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **has_local_firmware_files**  | Returns whether the profile has local firmware binaries.                                               |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **has_remote_firmware_files** | Returns whether the profile has remote firmware binaries.                                              |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **has_filesystem**            | Returns whether the profile has filesystem information (local or remote)                               |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **has_local_filesystem**      | Returns whether the profile has local filesystem information.                                          |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **has_remote_filesystem**     | Returns whether the profile has remote filesystem information.                                         |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **profile_settings**          |  Returns all the firmware settings that the profile configures.                                        |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **firmware_version**          | Returns the compatible firmware version of the profile.                                                |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **hardware_version**          | Returns the compatible hardware version of the profile.                                                |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **compatibility_number**      | Returns the compatibility number of the profile.                                                       |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **region_lock**               | Returns the region lock of the profile.                                                                |
+-------------------------------+--------------------------------------------------------------------------------------------------------+

To access to the files inside, use ``open()`` method. Once done with it, use
``close()`` method.

**Open/close a profile**

.. code:: python

  xbee_profile = XBeeProfile(PROFILE_PATH)

  xbee_profile.open()

  [...]

  xbee_profile.close()

  [...]

An opened profile also offers the following properties:

+-------------------------------+--------------------------------------------------------------------------------------------------------+
| Property                      | Description                                                                                            |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **profile_description_file**  | Returns the path of the profile description file.                                                      |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **firmware_description_file** | Returns the path of the profile firmware description file.                                             |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **file_system_path**          | Returns the profile file system path.                                                                  |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **remote_file_system_image**  | Returns the path of the remote OTA file system image.                                                  |
+-------------------------------+--------------------------------------------------------------------------------------------------------+
| **bootloader_file**           | Returns the profile bootloader file path.                                                              |
+-------------------------------+--------------------------------------------------------------------------------------------------------+

**Read a profile**

.. code:: python

  from digi.xbee.profile import XBeeProfile

  [...]

  PROFILE_PATH = "/home/user/my_profile.xpro"

  [...]

  # Create the XBee profile object.
  xbee_profile = XBeeProfile(PROFILE_PATH)

  # Print profile compatible hardware and software versions
  print("  - Firmware version: %s" % xbee_profile.firmware_version)
  print("  - Hardware version: %s" % xbee_profile.hardware_version)

  [...]

+-------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Read an XBee profile                                                                                                             |
+===========================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to read an XBee profile. It can be located in the following path: |
|                                                                                                                                           |
| **examples/profile/ReadXBeeProfileSample/ReadXBeeProfileSample.py**                                                                       |
+-------------------------------------------------------------------------------------------------------------------------------------------+


.. _applyProfileLocal:

Apply a profile to a local XBee
```````````````````````````````

Applying a profile to a local XBee requires the following components:

* The local XBee object instance.
* The profile file to apply (\*.xpro).

.. note::
   Use `XCTU <http://www.digi.com/xctu>`_ to create configuration profiles.

.. warning::
  At the moment, local profile update is only supported in **XBee 3** and
  **XBee SX 868/900 MHz** devices.

To apply the XBee profile to a local XBee, call the ``apply_profile()`` method
of the ``XBeeDevice`` class providing the required parameters:

+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+
| Method                                       | Description                                                                                                                |
+==============================================+============================================================================================================================+
| **apply_profile(String, timeout, Function)** | Applies the given XBee profile to the XBee.                                                                                |
|                                              |                                                                                                                            |
|                                              | * **profile_path (String)**: path of the XBee profile file to apply.                                                       |
|                                              | * **timeout (Integer, optional)**: maximum time to wait for read operations during the apply profile.                      |
|                                              | * **progress_callback (Function, optional)**: function to execute to receive progress information. Receives two arguments: |
|                                              |                                                                                                                            |
|                                              |   * The current apply profile task as a String                                                                             |
|                                              |   * The current apply profile task percentage as an Integer                                                                |
+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+

The ``apply_profile()`` method may fail for the following reasons:

* The local device does not support the apply profile operation, throwing a
  ``OperationNotSupportedException``.
* There is an error while applying the XBee profile, throwing a
  ``UpdateProfileException``.
* Other errors caught as ``XBeeException``:

    * The local device is not open, throwing a generic ``XBeeException``.
    * The operating mode of the local device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.

**Apply a profile to a local device**

.. code:: python

  [...]

  PROFILE_PATH = "/home/user/my_profile.xpro"

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Apply the XBee device profile.
  xbee.apply_profile(PROFILE_PATH, progress_callback=progress_callback)

  [...]

+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Apply local XBee profile                                                                                                                            |
+==============================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to apply an XBee profile to a local device. It can be located in the following path: |
|                                                                                                                                                              |
| **examples/profile/ApplyXBeeProfileSample/ApplyXBeeProfileSample.py**                                                                                        |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+


.. _applyProfileRemote:

Apply a profile to a remote XBee
````````````````````````````````

Applying a profile to a remote XBee requires the following components:

* The remote XBee object instance.
* The profile file to apply (\*.xpro).

.. note::
   Use `XCTU <http://www.digi.com/xctu>`_ to create configuration profiles.

.. warning::
  At the moment, remote profile update is only supported in **XBee 3**,
  **XBee SX 868/900 MHz**, and **XBee S2C** devices.

To apply the XBee profile to a remote XBee, call the ``apply_profile()`` method
of the ``RemoteXBeeDevice`` class providing the required parameters:

+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+
| Method                                       | Description                                                                                                                |
+==============================================+============================================================================================================================+
| **apply_profile(String, timeout, Function)** | Applies the given XBee profile to the remote XBee.                                                                         |
|                                              |                                                                                                                            |
|                                              | * **profile_path (String)**: path of the XBee profile file to apply.                                                       |
|                                              | * **timeout (Integer, optional)**: maximum time to wait for read operations during the apply profile.                      |
|                                              | * **progress_callback (Function, optional)**: function to execute to receive progress information. Receives two arguments: |
|                                              |                                                                                                                            |
|                                              |   * The current apply profile task as a String                                                                             |
|                                              |   * The current apply profile task percentage as an Integer                                                                |
+----------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+

The ``apply_profile()`` method may fail for the following reasons:

* The remote device does not support the apply profile operation, throwing a
  ``OperationNotSupportedException``.
* There is an error while applying the XBee profile, throwing a
  ``UpdateProfileException``.
* Other errors caught as ``XBeeException``:

    * The local device is not open, throwing a generic ``XBeeException``.
    * The operating mode of the local device is not ``API_MODE`` or
      ``ESCAPED_API_MODE``, throwing an ``InvalidOperatingModeException``.

**Apply a profile to a remote device**

.. code:: python

  [...]

  PROFILE_PATH = "/home/user/my_profile.xpro"
  REMOTE_NODE_NAME = "REMOTE"

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the network.
  xnet = xbee.get_network()

  # Get the remote node.
  remote = xnet.discover_device(REMOTE_NODE_NAME)

  [...]

  # Apply the XBee profile.
  remote.apply_profile(PROFILE_PATH, progress_callback=progress_callback)

  [...]

+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Example: Apply remote XBee profile                                                                                                                            |
+===============================================================================================================================================================+
| The XBee Python Library includes a sample application that displays how to apply an XBee profile to a remote device. It can be located in the following path: |
|                                                                                                                                                               |
| **examples/profile/ApplyXBeeProfileRemoteSample/ApplyXBeeProfileRemoteSample.py**                                                                             |
+---------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. _updateMultiple:

Update multiple nodes
---------------------

The XBee Python Library provides a mechanism to update several nodes at once.
For this, define the update tasks to perform. An update task includes:

* The node to be updated, local or remote.
* The required file(s) for the update.
* Other parameters such as the timeout or a callback to notify the progress.

There are two types of update task:

* A ``FwUpdateTask`` defines a firmware update task for a local or remote node.

.. code:: python

  from digi.xbee.firmware import FwUpdateTask

  [...]

  XML_FIRMWARE_FILE = "/home/user/my_firmware.xml"
  XBEE_FIRMWARE_FILE = "/home/user/my_firmware.gbl"
  BOOTLOADER_FIRMWARE_FILE = "/home/user/my_bootloader.gbl"

  [...]

  # Instantiate an XBee object.
  xbee = XBeeDevice(...)

  [...]

  # Define an update progress callback for the firmware update task
  def my_fw_update_cb(task_msg, percentage):
      print("%s: %%d" %(task_msg, percentage))

  # Define a firmware update task for the local node
  fw_update_task = FwUpdateTask(xbee, XML_FIRMWARE_FILE,
                                fw_path=XBEE_FIRMWARE_FILE,
                                bl_fw_path=BOOTLOADER_FIRMWARE_FILE,
                                progress_cb=my_fw_update_cb)

  [...]

* A ``ProfileUpdateTask`` defines a profile update task for a local or remote
  node.

.. code:: python

  from digi.xbee.firmware import ProfileUpdateTask

  [...]

  PROFILE_PATH = "/home/user/my_profile.xpro"

  [...]

  # Get the remote node.
  remote = ...

  [...]

  # Define an update progress callback for the profile update task
  def my_profile_update_cb(task_msg, percentage):
      print("%s: %%d" %(task_msg, percentage))

  # Define a firmware update task
  profile_update_task = ProfileUpdateTask(remote, PROFILE_PATH,
                                          progress_cb=my_profile_update_cb)

  [...]

You can define as many update tasks as you need. Then use the ``update_nodes()``
method of the ``XBeeNetwork`` to perform all of them.

+-------------------------+---------------------------------------------------------------------------------------+
| Method                  | Description                                                                           |
+=========================+=======================================================================================+
| **update_nodes(List)**  | Performs the provided update tasks. It blocks until all tasks finish.                 |
|                         |                                                                                       |
|                         | * **task_list (List)**: List of ``FwUpdateTask`` or ``ProfileUpdateTask`` to perform. |
|                         |   The method returns a dictionary with the 64-bit address of the XBee as key and, as  |
|                         |   value, a ``Tuple`` with the XBee (``XBeeDevice`` or ``RemoteXBeeDevice``) and an    |
|                         |   ``XBeeException`` if the process failed for that node (``None`` if it successes)    |
+-------------------------+---------------------------------------------------------------------------------------+

**Update several nodes**

.. code:: python

  from digi.xbee.firmware import ProfileUpdateTask

  [...]

  ROUTER_PROFILE_PATH = "/home/user/my_routers_profile.xpro"

  [...]

  # Instantiate a local XBee object.
  xbee = XBeeDevice(...)

  # Get the network.
  xnet = xbee.get_network()

  [...]

  profile_tasks = []
  for node in xnet.get_devices():
      if node.get_role() != Role.ROUTER:
          continue
      profile_tasks.append(ProfileUpdateTask(remote, ROUTER_PROFILE_PATH))

  update_result = xnet.update_nodes(profile_tasks)

  for task in tasks:
      res = update_result.get(str(task.xbee.get_64bit_addr()), None)
      res_msg = "OK"
      if res and res[1]:
          res_msg = "ERROR: %s" % str(res[1])
      print("%s: %s ---> %s" % (task.xbee, task.profile_path, res_msg))

  [...]

To receive the status of the update process per node, provide a callback using
the ``add_update_progress_callback()`` method. This callback receives three
arguments:

* The XBee being updated, local or remote.
* An ``UpdateProgressStatus`` with the current status.

**Register an update progress callback**

.. code:: python

  [...]

  xnet = xbee.get_network()

  [...]

  profile_tasks = ...

  # Define the update progress callback.
  def cb_update_progress(node, progress_status):
      print("%s %s - %s: %d%%" % (progress_status.type, node,
                                  progress_status.task, progress_status.percent))
      if progress_status.finished:
          print("---- %s finished for %s ----" % (progress_status.type, node))

  # Add the update progress callback.
  xnet.add_update_progress_callback(cb_network_modified)

  update_result = xnet.update_nodes(profile_tasks)

  [...]

To stop listening to update progress events, use the
``del_update_progress_callback()`` method to unsubscribe the already-registered
callback.

**Deregister an update progress callback**

.. code:: python

  [...]

  def cb_update_progress(node, task_str, percentage):
      [...]

  xbee.add_update_progress_callback(cb_update_progress)

  [...]

  # Delete the callback.
  xbee.del_update_progress_callback(cb_update_progress)

  [...]
