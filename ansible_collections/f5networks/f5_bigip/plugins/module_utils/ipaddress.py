# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    validate_ip_address, validate_ip_v6_address
)

from ipaddress import ip_interface, ip_network


def is_valid_ip(addr, type='all'):
    if type in ['all', 'ipv4']:
        if validate_ip_address(addr):
            return True
    if type in ['all', 'ipv6']:
        if validate_ip_v6_address(addr):
            return True
    return False


def is_valid_ip_network(address):
    try:
        ip_network(u'{0}'.format(address))
        return True
    except ValueError:
        return False


def is_valid_ip_interface(address):
    try:
        ip_interface(u'{0}'.format(address))
        return True
    except ValueError:
        return False
