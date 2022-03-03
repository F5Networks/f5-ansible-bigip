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


def header(method):
    def wrap(self, *args, **kwargs):
        if 'headers' not in kwargs:
            if self.transact is not None:
                kwargs['headers'] = {'X-F5-REST-Coordination-Id': self.transact}
                kwargs['headers'].update(BASE_HEADERS)
                return method(self, *args, **kwargs)
            kwargs['headers'] = BASE_HEADERS
            return method(self, *args, **kwargs)
        else:
            if self.transact is not None:
                kwargs['headers'].update({'X-F5-REST-Coordination-Id': self.transact})
                kwargs['headers'].update(BASE_HEADERS)
                return method(self, *args, **kwargs)
            kwargs['headers'].update(BASE_HEADERS)
            return method(self, *args, **kwargs)
    return wrap


class F5Client:
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.plugin = kwargs.get('client', None)
        self.transact = None

    @header
    def delete(self, url, **kwargs):
        return self.plugin.send_request(url, method='DELETE', **kwargs)

    @header
    def get(self, url, **kwargs):
        return self.plugin.send_request(url, method='GET', **kwargs)

    @header
    def patch(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='PATCH', data=data, **kwargs)

    @header
    def post(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='POST', data=data, **kwargs)

    @header
    def put(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='PUT', data=data, **kwargs)

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


def sslo_version(client):
    uri = "/mgmt/shared/iapp/installed-packages"
    response = client.get(uri)
    if response['code'] in [200, 201, 202]:
        if response['contents']["items"]:
            for x in response['contents']["items"]:
                if x["appName"] == "f5-iappslx-ssl-orchestrator":
                    tmpversion = x["release"].split(".")
                    version = tmpversion[0] + "." + tmpversion[1]
                    return version
    raise F5ModuleError("SSL Orchestrator package does not appear to be installed. Aborting.")


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


def package_installed(client, package_name):
    provisioned = packages_installed(client)
    if package_name in provisioned:
        return True
    return False


def packages_installed(client):
    """Returns a list of installed ATC packages

    Args:
        client: Client connection to the BIG-IP

    Returns:
        A list of installed packages in their short name for.
        For example, ['as3', 'do', 'ts']
    """
    packages = {
        "f5-declarative-onboarding": "do",
        "f5-appsvcs": "as3",
        "f5-appsvcs-templates": "fast",
        "f5-cloud-failover": "cfe",
        "f5-telemetry": "ts",
        "f5-service-discovery": "sd"

    }

    uri = "/mgmt/shared/iapp/global-installed-packages"

    response = client.get(uri)

    if response['code'] == 404:
        return []

    if response['code'] in [200, 201]:
        if 'items' not in response['contents']:
            return []
        result = [packages[x['appName']] for x in response['contents']['items'] if x['appName'] in packages.keys()]
        return result
    raise F5ModuleError(response['contents'])


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


class TransactionContextManager(object):
    def __init__(self, client, validate_only=False):
        self.client = client
        self.validate_only = validate_only
        self.transid = None

    def __enter__(self):
        uri = "/mgmt/tm/transaction/"
        response = self.client.post(uri, data={})

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.transid = response['contents']['transId']
        self.client.transact = self.transid
        return self.client

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.client.transact = None
        if exc_tb is None:
            uri = "/mgmt/tm/transaction/{0}".format(self.transid)
            params = dict(
                state="VALIDATING",
                validateOnly=self.validate_only
            )
            response = self.client.patch(uri, data=params)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])
