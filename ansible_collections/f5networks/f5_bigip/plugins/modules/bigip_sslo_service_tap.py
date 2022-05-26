#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_service_tap
short_description: Manage an SSL Orchestrator TAP security device
description:
  - Manage an SSL Orchestrator TAP security device
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the TAP security service.
      - The configuration auto-prepends "ssloS_" to the service.
      - The service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  devices:
    description:
      - Specifies the network attachment for the TAP security device.
    type: dict
    suboptions:
      vlan:
        description:
          - Defines an existing VLAN to attach the TAP service to.
          - Mutually exclusive with C(tag) or C(interface) parameter.
        type: str
      interface:
        description:
          - Defines the interface on the to-service side.
          - Mutually exclusive with C(vlan).
        type: str
      tag:
        description:
          - Defines the VLAN tag on the to-service side.
          - Mutually exclusive with C(vlan).
        type: int
    required: True
  mac_address:
    description:
      - Specifies the MAC address to use for the TAP service clone pool (static ARP).
    type: str
  port_remap:
    description:
      - Specifies the port number to remap to for traffic to this TAP service.
    type: int
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
  state:
    description:
        - Specifies the present/absent state required.
    type: str
    choices:
        - absent
        - present
    default: present
author:
  - Ravinder Reddy (@chinthalapalli)
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
    - name: SSLO TAP service with interface
      bigip_sslo_service_tap:
        name: "tap_test_interface"
        devices:
          interface: "1.1"
          tag: 400
        mac_address: "xx:xx:xx:xx:xx:xx"
    - name: create TAP service VLAN
      bigip_vlan:
        name: TAPservice_vlan
        tagged_interface: 1.7
    - name: SSLO TAP service with vlan
      bigip_sslo_service_tap:
        name: "tap_test_vlan"
        devices:
          vlan: "/Common/TAPservice_vlan"
        mac_address: "xx:xx:xx:xx:xx:xx"
        port_remap: 8081
        state: "absent"
'''

RETURN = r'''
devices:
  description:
    - Network settings for TAP service configuration.
  returned: changed
  type: complex
  contains:
    vlan:
       description: Defines an existing TAP service VLAN.
       type: str
       sample: /Common/tapservice-vlan
    interface:
       description: Defines a TAP service interface.
       type: str
       sample: 1.3
    tag:
       description: Defines a TAG used VLAN in TAP service.
       type: int
       sample: 40
    ipv4_deviceip:
       description: Defines the to-service VLAN self IP.
       type: str
       sample: 198.19.64.7
    ipv6_deviceip:
       description: Defines the to-service VLAN self IP netmask.
       type: str
       sample: 255.255.255.128
mac_address:
  description:
    - Changed MAC address value of TAP services.
  returned: changed
  type: str
  sample: "12:12:12:12:12:12"
port_remap:
  description:
    - Port remap settings.
  returned: changed
  type: int
  sample: 8080
'''

import hashlib
import re
import time

from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json, flatten_boolean
)

from ..module_utils.constants import (
    min_sslo_version, max_sslo_version, json_enable_tls13
)

from ..module_utils.compare import compare_complex_list, compare_dictionary
from ..module_utils.sslo_templates.sslo_service_tap import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    updatables = [
        'devices',
        'mac_address',
        'port_remap',
        'service_down_action',
    ]
    returnables = [
        'devices',
        'mac_address',
        'port_remap',
        'service_down_action',
    ]


class ApiParameters(Parameters):

    @property
    def devices(self):
        result = dict()
        result['name'] = self._values['customService']['serviceSpecific']['vlan']['name']
        result['path'] = self._values['customService']['serviceSpecific']['vlan']['path']
        result['ipv4_selfip'] = self._values['customService']['managedNetwork']['ipv4']['serviceSelfIp']
        result['ipv4_subnet'] = self._values['customService']['managedNetwork']['ipv4']['serviceSubnet']
        result['ipv4_haselfip'] = self._values['customService']['managedNetwork']['ipv4']['serviceHASelfIp']
        result['ipv4_deviceip'] = self._values['customService']['managedNetwork']['ipv4']['deviceIp']

        result['ipv6_selfip'] = self._values['customService']['managedNetwork']['ipv6']['serviceSelfIp']
        result['ipv6_subnet'] = self._values['customService']['managedNetwork']['ipv6']['serviceSubnet']
        result['ipv6_haselfip'] = self._values['customService']['managedNetwork']['ipv6']['serviceHASelfIp']
        result['ipv6_deviceip'] = self._values['customService']['managedNetwork']['ipv6']['deviceIp']

        if self._values['useExistingNetworkObj']['path'] == "":
            result['interface'] = self._values['customService']['serviceSpecific']['vlan']['interface']
            if int(self._values['customService']['serviceSpecific']['vlan']['networkTag']) != 0:
                result['tag'] = int(self._values['customService']['serviceSpecific']['vlan']['networkTag'])
        else:
            result['vlan'] = self._values['useExistingNetworkObj']['path']
        return result

    @property
    def mac_address(self):
        return self._values['customService']['serviceSpecific']['macAddress']

    @property
    def port_remap(self):
        return self._values['customService']['httpPortRemapValue']

    @property
    def service_down_action(self):
        return self._values['customService']['serviceDownAction']


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


class ModuleParameters(Parameters):
    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloS_'):
            name = "ssloS_" + name
        return name

    @property
    def devices(self):
        devices = self._values['devices']
        if devices is None:
            return None
        result = dict()
        if 'vlan' in devices.keys() and devices['vlan']:
            result['name'] = ""
            result['path'] = devices['vlan']
            result['vlan'] = devices['vlan']
        else:
            result['name'] = f"ssloN_{self._values['name']}"
            result['path'] = f"/Common/ssloN_{self._values['name']}.app/ssloN_{self._values['name']}"
            result['interface'] = devices['interface']
        if 'tag' in devices.keys() and devices['tag']:
            result['tag'] = devices['tag']

        local_name = re.sub('ssloS_', '', self._values['name'])
        ipv4_random_octet = (int(hashlib.md5(local_name.encode()).hexdigest(), 16) % 252) + 1
        result['ipv4_subnet'] = f"198.19.{str(ipv4_random_octet)}.0"
        result['ipv4_selfip'] = f"198.19.{str(ipv4_random_octet)}.8"
        result['ipv4_haselfip'] = f"198.19.{str(ipv4_random_octet)}.9"
        result['ipv4_deviceip'] = f"198.19.{str(ipv4_random_octet)}.10"
        ipv6_random_octet = re.sub("0x", '', hex((int(hashlib.md5(local_name.encode()).hexdigest(), 16) % 65535) + 1))
        result['ipv6_subnet'] = f"2001:200:0:{str(ipv6_random_octet)}::"
        result['ipv6_selfip'] = f"2001:200:0:{str(ipv6_random_octet)}::8"
        result['ipv6_haselfip'] = f"2001:200:0:{str(ipv6_random_octet)}::9"
        result['ipv6_deviceip'] = f"2001:200:0:{str(ipv6_random_octet)}::a"
        return result

    @property
    def mac_address(self):
        mac_address = self._values['mac_address']
        if mac_address is None:
            mac_address = 'F5:F5:F5:F5:XX:YY'
        return mac_address

    @property
    def port_remap(self):
        port_remap = self._values['port_remap']
        return port_remap

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
    def devices(self):
        want = self.want.devices
        have = self.have.devices
        diff = compare_dictionary(want, have)
        if diff:
            return diff


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
        changed = False
        result = dict()
        state = self.want.state

        self.check_sslo_version()
        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

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

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def create(self):
        self.check_for_required_create_parameters()
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

    def check_for_required_create_parameters(self):
        if self.want.devices is None:
            raise F5ModuleError(
                "The devices parameter is not defined. Devices must be defined during CREATE operation."
            )

    def remove(self):
        if self.module.check_mode:
            return True
        self.operation = 'DELETE'
        task_id, output = self.remove_from_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def add_create_values(self, payload):
        # add create defaults for undefined values

        if self.changes.mac_address is None:
            payload['mac_address'] = None
        if self.changes.port_remap is None:
            payload['port_remap'] = 80
        if self.want.service_down_action is None:
            payload['service_down_action'] = 'ignore'

        return payload

    def add_missing_options(self, payload):
        # used during modify operation, to avoid repetition if missing some mandatory values we use in device config
        # to complete the input

        if self.changes.devices is None:
            payload['devices'] = self.have.devices
        if self.changes.mac_address is None:
            payload['mac_address'] = self.have.mac_address
        if self.changes.port_remap is None:
            payload['port_remap'] = self.have.port_remap
        if self.changes.service_down_action is None:
            payload['service_down_action'] = self.have.service_down_action

        return payload

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_SERVICE_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation == 'MODIFY' or self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        return payload

    def create_on_device(self):
        payload = self.changes.to_return()
        data = self.add_create_values(self.add_json_metadata(payload))
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

    def remove_from_device(self):
        data = self.add_json_metadata()
        output = process_json(data, delete)

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
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None) and response['contents']['items'][0]['name'] == self.want.name:
            returned_json = response['contents']['items'][0]['inputProperties'][0]['value']
            self.block_id = response['contents']['items'][0]['id']
            return ApiParameters(params=returned_json)
        raise F5ModuleError(response['contents'])

    def exists(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None):
            if response['contents']['items'][0]['name'] == self.want.name:
                self.block_id = response['contents']['items'][0]['id']
                return True
        return False

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
            name=dict(required=True),
            devices=dict(
                required=True,
                type='dict',
                options=dict(
                    vlan=dict(),
                    interface=dict(),
                    tag=dict(type='int'),
                ),
                mutually_exclusive=[
                    ['vlan', 'interface'],
                    ['vlan', 'tag']
                ],
                required_one_of=[
                    ('vlan', 'interface')
                ]
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            mac_address=dict(),
            port_remap=dict(
                type='int'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            dump_json=dict(
                type='bool',
                default='no'
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
