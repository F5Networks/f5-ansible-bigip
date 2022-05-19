#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_config_resolver
short_description: Manage the SSL Orchestrator DNS resolver config
description:
  - Manage the SSL Orchestrator DNS resolver configuration.
version_added: "1.6.0"
options:
  fwd_name_servers:
    description:
      - Specifies the list of IP addresses for forwarding nameservers.
      - This parameter is mutually exclusive with C(fwd_zones).
    type: list
    elements: str
  fwd_zones:
    description:
      - Specifies the list of zone and servers key pairs.
      - This parameter is mutually exclusive with C(fwd_name_servers).
    type: list
    elements: dict
    suboptions:
      zone:
        description:
          - Defines the zone pattern.
          - The C(zone) and C(servers) parameters are required together when defining a zone.
        type: str
      servers:
        description:
          - Defines the list of nameserver IP addresses for this zone.
          - The C(zone) and C(servers) parameters are required together when defining a zone.
        type: list
        elements: str
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(yes), does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes to be made during
        C(MODIFY) on an existing service, no JSON output is generated.
    type: bool
    default: no
  timeout:
    description:
      - The amount of time to wait for the C(CREATE) or C(MODIFY) task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
author:
  - Wojciech Wypior (@wojtek0806)
  - Kevin Stewart (@kevingstewart)
'''


EXAMPLES = r'''
- hosts: all
  collections:
    - f5networks.f5_bigip
  connection: httpapi

  vars:
    ansible_host: "lb.mydomain.com"
    ansible_user: "admin"
    ansible_httpapi_password: "secret"
    ansible_network_os: f5networks.f5_bigip.bigip
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: SSLO dns resolver (forwarding nameservers)
      bigip_sslo_config_resolver:
        fwd_name_servers:
          - "10.1.20.1"
          - "10.1.20.2"
          - "fd66:2735:1533:46c1:68c8:0:0:7110"
          - "fd66:2735:1533:46c1:68c8:0:0:7111"

    - name: SSLO dns resolver (forwarding zones)
      bigip_sslo_config_resolver:
        fwd_zones:
          - zone: "."
            servers:
              - "10.1.20.1"
              - "10.1.20.5"
          - zone: "foo."
            servers:
              - "8.8.8.8"
              - "8.8.4.4"
              - "fd66:2735:1533:46c1:68c8:0:0:7113"
'''

RETURN = r'''
fwd_name_servers:
  description:
    - Changed list of nameserver IP addresses.
  type: str
  returned: changed
  sample: 8.8.8.8
fwd_zones:
  description:
    - Changed list of zone, server key pairs.
  type: complex
  returned: changed
  contains:
    zone:
       description: The zone pattern.
       type: str
       sample: "."
    servers:
       description: The list of nameserver IP addresses for this zone.
       type: str
       sample: 8.8.8.8
'''

import ipaddress
import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version,
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)
from ..module_utils.compare import (
    compare_complex_list, cmp_simple_list
)
from ..module_utils.constants import (
    min_sslo_version, max_sslo_version, resolver_logging_config
)
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.sslo_templates.sslo_resolver import create_modify


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'fwd_zones',
        'fwd_name_servers',
        'ip_family',
    ]

    updatables = [
        'fwd_zones',
        'fwd_name_servers',
        'ip_family'
    ]


class ApiParameters(Parameters):
    @property
    def fwd_name_servers(self):
        if self._values['dns'] is None:
            return None
        return self._values['dns'].get('localDnsNameservers', None)

    @property
    def fwd_zones(self):
        if self._values['dns'] is None:
            return None
        return self._values['dns'].get('localDnsZones', None)

    @property
    def ip_family(self):
        if self._values['ipFamily'] is None:
            return None
        return self._values['ipFamily']

    @property
    def dns_sec(self):
        if self._values['dns'] is None:
            return None
        return self._values['dns'].get('enableDnsSecurity', None)


class ModuleParameters(Parameters):
    @staticmethod
    def _process_servers(servers):
        version = list()
        for server in servers:
            if not is_valid_ip(server):
                raise F5ModuleError(f"A submitted IP address: {server} is not a valid IP address.")
            ip = ipaddress.ip_address(server)
            version.append(ip.version)
        return version

    def _set_version(self, versions):
        if all(version == 4 for version in versions):
            self.ip_family = 'ipv4'
        elif all(version == 6 for version in versions):
            self.ip_family = 'ipv6'
        else:
            self.ip_family = 'both'

    @property
    def fwd_name_servers(self):
        servers = self._values['fwd_name_servers']
        if servers:
            versions = self._process_servers(servers)
            self._set_version(versions)
            return servers

    @property
    def fwd_zones(self):
        if self._values['fwd_zones'] is None:
            return None
        versions = list()
        result = list()
        for zone in self._values['fwd_zones']:
            if not zone['zone']:
                raise F5ModuleError("A forwarding zone 'zone' key must contain a valid domain name entry.")
            element = dict()
            element['zone'] = zone['zone']
            if not zone['servers']:
                raise F5ModuleError("A forwarding zone 'servers' key must contain at least one IP address entry.")
            versions.extend(self._process_servers(zone['servers']))
            element['nameServerIps'] = zone['servers']
            result.append(element)
        self._set_version(versions)
        return result

    @property
    def ip_family(self):
        # the below covers an edge case where ip_family property is called before fwd_zones or fwd_name_servers
        # here we call fwd_zones or fwd_name_servers properties so they populate ip_family value as they normally would.
        if self._values['ip_family'] is None:
            if self._values['fwd_zones']:
                tmp = self.fwd_zones
            elif self._values['fwd_name_servers']:
                tmp = self.fwd_name_servers
        return self._values['ip_family']

    @ip_family.setter
    def ip_family(self, value):
        self._values['ip_family'] = value

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 10 and 1800 seconds."
            )
        if timeout > 99:
            divisor = 100
        delay = timeout / divisor

        return int(delay), divisor


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def fwd_zones(self):
        return compare_complex_list(self.want.fwd_zones, self.have.fwd_zones)

    @property
    def fwd_name_servers(self):
        return cmp_simple_list(self.want.fwd_name_servers, self.have.fwd_name_servers)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

        # define a set of common instance variables used during module execution
        self.block_id = None
        self.operation = None
        self.version = None
        self.json_dump = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        result = dict()
        self.check_sslo_version()
        changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        if self.json_dump:
            result.update(dict(json=self.json_dump))
        self._announce_deprecations(result)
        return result

    def check_sslo_version(self):
        self.version = sslo_version(self.client)
        if LooseVersion(self.version) > LooseVersion(max_sslo_version) or \
                LooseVersion(self.version) < LooseVersion(min_sslo_version):
            raise F5ModuleError(
                f"Unsupported SSL Orchestrator version, "
                f"requires a version between {min_sslo_version} and {max_sslo_version}"
            )
        return True

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.operation = 'MODIFY'
        task_id, output = self.update_on_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.operation = 'CREATE'
        task_id, output = self.create_on_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def add_missing_options(self, payload):
        # used during modify operation, to avoid overwriting the existing settings on device with the new template
        if self.changes.ip_family is None:
            payload['ip_family'] = self.have.ip_family
        if self.have.dns_sec:
            payload['dns_sec'] = self.have.dns_sec
        return payload

    def add_json_metadata(self, payload):
        payload['name'] = f"sslo_obj_GENERAL_SETTINGS_{self.operation}_ssloGS_global"
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if LooseVersion(self.version) < LooseVersion('6.0'):
            payload['log_conf'] = resolver_logging_config
        if self.operation == 'MODIFY':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        return payload

    def exists(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = "?$filter=name+eq+ssloGS_global"
        response = self.client.get(uri + query)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None):
            if response['contents']['items'][0]['name'] == 'ssloGS_global':
                self.block_id = response['contents']['items'][0]['id']
                return True
        return False

    def create_on_device(self):
        payload = self.changes.to_return()
        data = self.add_json_metadata(payload)

        output = process_json(data, create_modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def update_on_device(self):
        payload = self.changes.to_return()
        data = self.add_missing_options(self.add_json_metadata(payload))

        output = process_json(data, create_modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def read_current_from_device(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = "?$filter=name+eq+'ssloGS_global'"
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None) and response['contents']['items'][0]['name'] == 'ssloGS_global':
            returned_json = response['contents']['items'][0]['inputProperties'][0]['value']
            self.block_id = response['contents']['items'][0]['id']
            return ApiParameters(params=returned_json)
        raise F5ModuleError(response['contents'])

    def delete_failed_operation_on_device(self, task):
        # use this method to delete the operation that failed
        # if there are any http errors we ignore them
        uri = "/mgmt/shared/iapp/blocks/{0}".format(task)
        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202]:
            return True
        else:
            return False

    def wait_for_task(self, task_id):
        error = None
        delay, period = self.want.timeout
        for x in range(0, period):
            task = self._check_task_on_device(task_id)
            if task['state'] == 'BOUND':
                return True
            if task['state'] == 'ERROR':
                error = str(task['error'])
                break
            time.sleep(delay)
        if error:
            self.delete_failed_operation_on_device(task_id)
            raise F5ModuleError(f"{self.operation} operation error: {task_id} : {error}")
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _check_task_on_device(self, task_id):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=id+eq+'{task_id}'"
        response = self.client.get(uri + query)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['items'][0]


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            fwd_name_servers=dict(
                type='list',
                elements='str'
            ),
            fwd_zones=dict(
                type='list',
                elements='dict',
                options=dict(
                    zone=dict(),
                    servers=dict(
                        type='list',
                        elements='str',
                    )
                ),
                required_together=[
                    ['zone', 'servers']
                ],
                required_one_of=[
                    ['zone', 'servers']
                ]
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            dump_json=dict(
                type='bool',
                default='no'
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['fwd_name_servers', 'fwd_zones']
        ]
        self.required_one_of = [
            ['fwd_name_servers', 'fwd_zones']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
