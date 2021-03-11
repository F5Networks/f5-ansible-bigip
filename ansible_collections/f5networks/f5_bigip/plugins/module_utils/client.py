# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.urls import urlparse

from .common import F5ModuleError
from .teem import TeemClient
from ..module_utils.constants import BASE_HEADERS


class F5Client:
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.plugin = kwargs.get('client', None)

    def delete(self, url, headers=None, **kwargs):
        if headers:
            headers.update(BASE_HEADERS)
            return self.plugin.send_request(url, method='DELETE', headers=headers, **kwargs)
        return self.plugin.send_request(url, method='DELETE', headers=BASE_HEADERS, **kwargs)

    def get(self, url, headers=None, **kwargs):
        if headers:
            headers.update(BASE_HEADERS)
            return self.plugin.send_request(url, method='GET', headers=headers, **kwargs)
        return self.plugin.send_request(url, method='GET', headers=BASE_HEADERS, **kwargs)

    def patch(self, url, data=None, headers=None, **kwargs):
        if headers:
            headers.update(BASE_HEADERS)
            return self.plugin.send_request(url, method='PATCH', data=data, headers=headers, **kwargs)
        return self.plugin.send_request(url, method='PATCH', data=data, headers=BASE_HEADERS, **kwargs)

    def post(self, url, data=None, headers=None, **kwargs):
        if headers:
            headers.update(BASE_HEADERS)
            return self.plugin.send_request(url, method='POST', data=data, headers=headers, **kwargs)
        return self.plugin.send_request(url, method='POST', data=data, headers=BASE_HEADERS, **kwargs)

    def put(self, url, data=None, headers=None, **kwargs):
        if headers:
            headers.update(BASE_HEADERS)
            return self.plugin.send_request(url, method='PUT', data=data, headers=headers, **kwargs)
        return self.plugin.send_request(url, method='PUT', data=data, headers=BASE_HEADERS, **kwargs)

    @property
    def platform(self):
        network_os = self.plugin.network_os()
        if network_os.split('.')[2] == 'bigip':
            version = tmos_version(self)
        else:
            version = bigiq_version(self)
        return network_os.split('.')[2], version

    @property
    def ansible_version(self):
        return self.module.ansible_version

    @property
    def module_name(self):
        return self.module._name


def tmos_version(client):
    uri = "/mgmt/tm/sys/"
    response = client.get(uri)

    if response['code'] in [200, 201]:
        to_parse = urlparse(response['contents']['selfLink'])
        query = to_parse.query
        version = query.split('=')[1]
        return version

    raise F5ModuleError(response['contents'])


def bigiq_version(client):
    uri = "/mgmt/shared/resolver/device-groups/cm-shared-all-big-iqs/devices"
    query = "?$select=version"
    response = client.get(uri + query)
    if response['code'] in [200, 201]:
        if 'items' in response['contents']:
            version = response['contents']['items'][0]['version']
            return version
        raise F5ModuleError(
            'Failed to retrieve BIG-IQ version information.'
        )
    raise F5ModuleError(response['contents'])


def module_provisioned(client, module_name):
    provisioned = modules_provisioned(client)
    if module_name in provisioned:
        return True
    return False


def modules_provisioned(client):
    """Returns a list of all provisioned modules

    Args:
        client: Client connection to the BIG-IP

    Returns:
        A list of provisioned modules in their short name for.
        For example, ['afm', 'asm', 'ltm']
    """
    uri = "/mgmt/tm/sys/provision"
    response = client.get(uri)

    if response['code'] in [200, 201]:
        if 'items' not in response['contents']:
            return []
        return [x['name'] for x in response['contents']['items'] if x['level'] != 'none']

    raise F5ModuleError(response['contents'])


def send_teem(client, start_time):
    """ Sends Teem Data if allowed."""
    if client.plugin.telemetry():
        teem = TeemClient(client, start_time)
        teem.send()
    else:
        return False
