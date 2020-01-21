# Copyright 2019, Digi International Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from digi.xbee.profile import XBeeProfile, ReadProfileException

# TODO: Replace with the location of the XBee profile file to read.
PROFILE_PATH = "<path_to_profile>"


def main():
    print(" +----------------------------------------------+")
    print(" | XBee Python Library Read XBee Profile Sample |")
    print(" +----------------------------------------------+\n")

    try:
        xbee_profile = XBeeProfile(PROFILE_PATH)
        print("Profile information\n-----------------------------------")
        print("  - Location: %s" % xbee_profile.profile_file)
        print("  - Version: %s" % xbee_profile.version)
        print("  - Firmware version: %s" % xbee_profile.firmware_version)
        print("  - Hardware version: %s" % xbee_profile.hardware_version)
        print("  - Protocol: %s" % xbee_profile.protocol.description)
        print("  - Flash firmware option: %s" % xbee_profile.flash_firmware_option.description)
        print("  - Description: %s" % xbee_profile.description)
        print("  - Reset settings: %s" % xbee_profile.reset_settings)
        print("  - Has filesystem: %s" % xbee_profile.has_filesystem)
        print("  - AT settings:")
        if not xbee_profile.profile_settings:
            print("    - None")
            return
        for profile_setting in xbee_profile.profile_settings:
            print("    - Setting '%s' - type: %s - format: %s - value: %s" %
                  (profile_setting.name, profile_setting.type.description,
                   profile_setting.format.description, profile_setting.value))

    except ReadProfileException as e:
        print(str(e))


if __name__ == '__main__':
    main()
