

from digi.xbee.devices import XBeeDevice


def main():

    device = XBeeDevice("COM6", 9600)
    device.open()
    print(device.get_parameter("NI").decode())
    device.close()
    device.open()
    print(device.get_parameter("NI").decode())
    device.close()
    device.open()
    print(device.get_parameter("NI").decode())
    device.close()
    device.open()
    print(device.get_parameter("NI").decode())
    device.close()
    device.open()
    print(device.get_parameter("NI").decode())
    device.close()


if __name__ == '__main__':
    main()
