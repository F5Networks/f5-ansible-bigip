# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from unittest import TestCase

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.ipaddress import (
    is_valid_ip, is_valid_ip_network, is_valid_ip_interface
)


class TestIpAddress(TestCase):
    def test_is_valid_ip_address(self):
        valid_ip4 = is_valid_ip('192.168.1.1', type='ipv4')
        assert valid_ip4 is True

        valid_ip6 = is_valid_ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334', type='ipv6')
        assert valid_ip6 is True

        valid_ip = is_valid_ip('300.300.300.300')
        assert valid_ip is False

    def test_is_valid_ip_network(self):
        net = '192.168.1.0/24'
        no_net = '192.168.1.23/24'

        valid = is_valid_ip_network(net)
        assert valid is True

        valid = is_valid_ip_network(no_net)
        assert valid is False

    def test_is_valid_ip_interface(self):
        net = '192.168.1.23/32'
        err = '192.270.1.23/32'

        valid = is_valid_ip_interface(net)
        assert valid is True

        valid = is_valid_ip_interface(err)
        assert valid is False
