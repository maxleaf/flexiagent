the vpp-papi module located at https://pypi.org/project/vpp-papi/ is outdated.
Instead the one generated during vpp build should be installed.
The current vpp_papi-1.6.2-py3.6.egg stands for VPP 21.01 (May 2021)
==============================================================================
The easy way to do it just to install the outdated module and override
it's content with the latest egg.

pip3 install vpp-papi
pip3 uninstall enum34 -y
rm -rf  /usr/local/lib/python3.6/dist-packages/vpp_papi
unzip vpp_papi-1.6.2-py3.6.egg -d /usr/local/lib/python3.6/dist-packages/

Note the "enum34" is not needed with Python 3.6, as the enum is built-in now.
We have to remove it, as it causes dependencies issue.
==============================================================================

To run regressions with python3: python3 -m pytest