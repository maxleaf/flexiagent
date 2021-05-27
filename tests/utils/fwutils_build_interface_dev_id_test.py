import os
import sys
import pytest

CODE_ROOT = os.path.realpath(__file__).replace("\\", "/").split("/tests/")[0]
sys.path.append(CODE_ROOT)
import fwutils


class TestBuildInterfaceDevId:
    @pytest.mark.parametrize(
        "networking_devices,device_id,expected",
        [
            (
                "",
                None,
                "",
            ),
            (
                "",
                "",
                "",
            ),
            (
                "",
                "enp0s10",
                "",
            ),
            (
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s1 -> ../../devices/pci0000:00/0000:00:01.0/net/enp0s1\n"
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s10 -> ../../devices/pci0000:00/0000:00:0a.0/net/enp0s10\n",
                "vpp0",
                "",
            ),
            (
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s1 -> ../../devices/pci0000:00/0000:00:01.0/net/enp0s1\n"
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s10 -> ../../devices/pci0000:00/0000:00:0a.0/net/enp0s10\n",
                "",
                "",
            ),
            (
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s1 -> ../../devices/pci0000:00/0000:00:01.0/net/enp0s1\n"
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s10 -> ../../devices/pci0000:00/0000:00:0a.0/net/enp0s10\n",
                "enp0s10",
                "pci:0000:00:0a.00",
            ),
            (
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s1 -> ../../devices/pci0000:00/0000:00:01.0/net/enp0s1\n"
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s10 -> ../../devices/pci0000:00/0000:00:0a.0/net/enp0s10\n",
                "enp0s1",
                "pci:0000:00:01.00",
            ),
            (
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s10 -> ../../devices/pci0000:00/0000:00:0a.0/net/enp0s10\n"
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s1 -> ../../devices/pci0000:00/0000:00:01.0/net/enp0s1\n",
                "enp0s10",
                "pci:0000:00:0a.00",
            ),
            (
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s10 -> ../../devices/pci0000:00/0000:00:0a.0/net/enp0s10\n"
                "lrwxrwxrwx 1 root root 0 May 13 03:25 enp0s1 -> ../../devices/pci0000:00/0000:00:01.0/net/enp0s1\n",
                "enp0s1",
                "pci:0000:00:01.00",
            ),
        ],
    )
    def test_build_interface_dev_id(self, networking_devices, device_id, expected):
        response = fwutils.build_interface_dev_id(
            device_id, networking_devices.splitlines()
        )

        assert response == expected
