#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: velos_partition
short_description: Manage VELOS chassis partitions
description:
  - Manage VELOS chassis partitions.
version_added: "1.3.0"
options:
  name:
    description:
      - Name of the chassis partition.
    type: str
    required: True
  ipv4_mgmt_address:
    description:
      - Specifies the IPv4 address and subnet or subnet mask you use to access
        the chassis partition.
      - When creating a new chassis partition, if the CIDR notation is not used a default of C(/24) is appended to
        the address.
      - "The address must be specified in CIDR notation e.g. 192.168.1.1/24."
    type: str
  ipv4_mgmt_gateway:
    description:
      - Desired chassis partition management gateway.
      - The value C(none) can be used during an update to remove this value.
    type: str
  ipv6_mgmt_address:
    description:
      - Specifies the IPv6 address and subnet or subnet mask that you use to access
        the chassis partition.
      - When creating a new chassis partition, if the CIDR notation is not used a default of C(/96) is appended
        to the address.
      - "The address must be specified in CIDR notation e.g. 2002::1234:abcd:ffff:c0a8:101/64."
    type: str
  ipv6_mgmt_gateway:
    description:
      - Desired chassis partition management gateway.
      - The value C(none) can be used during an update to remove this value.
    type: str
  os_version:
    description:
      - Chassis partition F5OS-C OS version.
      - The value C(none) can be used during an update to remove this value.
    type: str
  slots:
    description:
      - List (integers), specifies which slots with which the chassis partition should associated.
      - By default, the chassis partition is not associated with any slots.
    type: list
    elements: int
  service_version:
    description:
      - Chassis partition F5OS-C Service version.
    type: str
  wait_time:
    description:
      - Max number of seconds to wait after creating a chassis partition for it to
        transition to the 'running' state.
    type: int
    default: 300
  state:
    description:
      - The chassis partition state. If C(absent), deletes the chassis partition
        if it exists. C(present) creates the chassis partition and enables it.
        If C(enabled), enables the chassis partition if it exists. If C(disabled),
        creates the chassis partition if needed, and sets state to C(disabled).
    type: str
    choices:
      - present
      - absent
      - enabled
      - disabled
    default: present
author:
  - Ravinder Reddy (@chinthalapalli)
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
    - name: Create partition 'foo'
      velos_partition:
        name: foo
        state: present
        os_version: 1.1.1-5046
        ipv4_mgmt_address: 10.144.140.124/24
        ipv4_mgmt_gateway: 10.144.140.254
        slots: [4,5]

    - name: Delete partition 'foo'
      velos_partition:
        name: foo
        state: absent
'''

RETURN = r'''
name:
  description: Specify the name of the partition.
  returned: changed
  type: str
  sample: foo
os_version:
  description: Partition OS version.
  returned: changed
  type: str
  sample: 1.1.1-5046
ipv4_mgmt_address:
  description: Specifies the IPv4 address and subnet or subnet mask that you use to access the partition.
  returned: changed
  type: str
  sample: 192.168.1.12/24
ipv4_mgmt_gateway:
  description: Desired partition management gateway.
  returned: changed
  type: str
  sample: 192.168.1.1
slots:
  description: Specifies which slots with which the partition should be associated.
  returned: changed
  type: list
  sample: [3, 4]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.ipaddress import is_valid_ip


class Parameters(AnsibleF5Parameters):
    api_map = {
        'iso-version': 'os_version',
        'mgmt-ip': 'mgmt_ip',
    }

    api_attributes = [
        'name',
        'enabled',
        'iso-version',
        'mgmt-ip',
        'slots',
    ]

    returnables = [
        'ipv4_mgmt_address',
        'ipv4_mgmt_gateway',
        'ipv6_mgmt_address',
        'ipv6_mgmt_gateway',
        'mgmt_ip',
        'enabled',
        'os_version',
        'slots',
    ]

    updatables = [
        'ipv4_mgmt_address',
        'ipv4_mgmt_gateway',
        'ipv6_mgmt_address',
        'ipv6_mgmt_gateway',
        'mgmt_ip',
        'enabled',
        'os_version',
        'slots',
    ]


class ApiParameters(Parameters):
    @property
    def ipv4_mgmt_address(self):
        local_mgmt_ip = self._values.get('mgmt_ip', None)
        if local_mgmt_ip is not None:
            if 'ipv4' in local_mgmt_ip and local_mgmt_ip['ipv4'] is not None:
                return "{0}/{1}".format(
                    local_mgmt_ip['ipv4']['address'], local_mgmt_ip['ipv4']['prefix-length']
                )
        return local_mgmt_ip

    @property
    def ipv4_mgmt_gateway(self):
        local_mgmt_ip = self._values.get('mgmt_ip', None)
        if local_mgmt_ip is not None:
            if 'ipv4' in local_mgmt_ip and local_mgmt_ip['ipv4'] is not None:
                return local_mgmt_ip['ipv4']['gateway']
        return local_mgmt_ip

    @property
    def ipv6_mgmt_address(self):
        local_mgmt_ip = self._values.get('mgmt_ip', None)
        if local_mgmt_ip is not None:
            if 'ipv6' in local_mgmt_ip and local_mgmt_ip['ipv6'] is not None:
                return "{0}/{1}".format(
                    local_mgmt_ip['ipv6']['address'], local_mgmt_ip['ipv6']['prefix-length']
                )
        return local_mgmt_ip

    @property
    def ipv6_mgmt_gateway(self):
        local_mgmt_ip = self._values.get('mgmt_ip', None)
        if local_mgmt_ip is not None:
            if 'ipv6' in local_mgmt_ip and local_mgmt_ip['ipv6'] is not None:
                return local_mgmt_ip['ipv6']['gateway']
        return local_mgmt_ip


class ModuleParameters(Parameters):

    @property
    def ipv4_mgmt_gateway(self):
        if self._values['ipv4_mgmt_gateway'] is None:
            return None
        elif self._values['ipv4_mgmt_gateway'] == 'none':
            return 'none'
        if is_valid_ip(self._values['ipv4_mgmt_gateway']):
            return self._values['ipv4_mgmt_gateway']
        else:
            raise F5ModuleError(
                "The specified 'ipv4_mgmt_gateway' is not a valid IP address."
            )

    @property
    def ipv4_mgmt_address(self):
        if self._values['ipv4_mgmt_address'] is None:
            return None
        if len(self._values['ipv4_mgmt_address'].split('/')) == 1:
            if is_valid_ip(self._values['ipv4_mgmt_address']):
                return self._values['ipv4_mgmt_address']
        else:
            if is_valid_ip(self._values['ipv4_mgmt_address'].split('/')[0]):
                return self._values['ipv4_mgmt_address']
        raise F5ModuleError(
            "The specified 'ipv4_mgmt_address' is not a valid IP address."
        )

    @property
    def ipv6_mgmt_gateway(self):
        if self._values['ipv6_mgmt_gateway'] is None:
            return None
        elif self._values['ipv6_mgmt_gateway'] == 'none':
            return 'none'
        if is_valid_ip(self._values['ipv6_mgmt_gateway']):
            return self._values['ipv6_mgmt_gateway']
        else:
            raise F5ModuleError(
                "The specified 'ipv6_mgmt_gateway' is not a valid IP address."
            )

    @property
    def ipv6_mgmt_address(self):
        if self._values['ipv6_mgmt_address'] is None:
            return None
        if len(self._values['ipv6_mgmt_address'].split('/')) == 1:
            if is_valid_ip(self._values['ipv6_mgmt_address']):
                return self._values['ipv6_mgmt_address']
        else:
            if is_valid_ip(self._values['ipv6_mgmt_address'].split('/')[0]):
                return self._values['ipv6_mgmt_address']
        raise F5ModuleError(
            "The specified 'ipv6_mgmt_address' is not a valid IP address."
        )

    @property
    def state(self):
        if self._values['state'] == 'present':
            return 'enabled'
        return self._values['state']

    @property
    def enabled(self):
        return self._values['state'] != 'disabled'

    @property
    def slots(self):
        if self._values['slots'] is None:
            return None
        if not self._values['slots']:
            return []
        result = [int(x) for x in self._values['slots']]
        result.sort()
        if min(result) < 0 or max(result) > 32:
            raise F5ModuleError(
                "Valid slot id's must be in range 0 - 32."
            )
        return result


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
    @property
    def mgmt_ip(self):
        result = {}
        if self._values['ipv4_mgmt_address'] is not None or self._values['ipv4_mgmt_gateway'] is not None:
            result['ipv4'] = dict()
            if self._values['ipv4_mgmt_address'] is not None:
                result['ipv4'].update(address=self._values['ipv4_mgmt_address'].split('/')[0])
                result['ipv4']['prefix-length'] = int(self._values['ipv4_mgmt_address'].split('/')[1])
            if self._values['ipv4_mgmt_gateway'] is not None:
                result['ipv4'].update(gateway=self._values['ipv4_mgmt_gateway'])
        if self._values['ipv6_mgmt_address'] is not None or self._values['ipv6_mgmt_gateway'] is not None:
            result['ipv6'] = dict()
            if self._values['ipv6_mgmt_address'] is not None:
                result['ipv6'].update(address=self._values['ipv6_mgmt_address'].split('/')[0])
                result['ipv6']['prefix-length'] = int(self._values['ipv6_mgmt_address'].split('/')[1])
            if self._values['ipv6_mgmt_gateway'] is not None:
                result['ipv6'].update(gateway=self._values['ipv6_mgmt_gateway'])
        return result


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
    def enabled(self):
        want_enabled = self.want.state != 'disabled'
        if want_enabled == self.have.enabled:
            return None
        return want_enabled


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

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
        if state in ['present', 'enabled', 'disabled']:
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

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

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def remove(self):
        self.have = self.read_current_from_device()
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        if self.want.ipv4_mgmt_address is not None and self.want.ipv4_mgmt_address.split('/')[1] is None:
            self.want.update(dict(
                ipv4_mgmt_address='{0}/24'.format(self.want.ipv4_mgmt_address.split('/', maxsplit=1)[0])
            ))
        if self.want.ipv6_mgmt_address is not None and self.want.ipv6_mgmt_address.split('/')[1] is None:
            self.want.update(dict(
                ipv6_mgmt_address='{0}/96'.format(self.want.ipv6_mgmt_address.split('/', maxsplit=1)[0])
            ))
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/f5-system-partition:partitions/partition={self.want.name}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        payload_config = params.copy()
        payload_config.pop('slots')
        payload = dict(partition=dict(name=self.want.name, config=payload_config))
        uri = "/f5-system-partition:partitions"
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        # Update slot assignment.
        slots = params.get('slots')
        if slots:
            self.set_slot_config(self.want.name, slots)
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        if not params.get('enabled'):
            params['enabled'] = self.want.enabled

        # Update slot assignment.
        slots = params.get('slots')
        # If you want to just dis-associates slots to partition by provides slots params as empty or not specifying.
        # ex: slots: []
        if not self.want.slots:
            self.remove_slot_from_partition()
        if slots:
            self.remove_slot_from_partition()
            self.set_slot_config(self.want.name, slots)
            params.pop('slots')

        if params.get('iso-version'):
            self._partition_iso_update()
            params.pop('iso-version')

        if params.get('mgmt-ip'):
            if params.get('mgmt-ip').get('ipv4') and params.get('mgmt-ip').get('ipv4').get('address') is None:
                params['mgmt-ip']['ipv4']['address'] = self.want.ipv4_mgmt_address.split('/', maxsplit=1)[0]
                params['mgmt-ip']['ipv4']['prefix-length'] = self.want.ipv4_mgmt_address.split('/')[1]
            if params.get('mgmt-ip').get('ipv4') and params.get('mgmt-ip').get('ipv4').get('gateway') is None:
                params['mgmt-ip']['ipv4']['gateway'] = self.want.ipv4_mgmt_gateway
            if params.get('mgmt-ip').get('ipv6') and params.get('mgmt-ip').get('ipv6').get('address') is None:
                params['mgmt-ip']['ipv6']['address'] = self.want.ipv6_mgmt_address.split('/', maxsplit=1)[0]
                params['mgmt-ip']['ipv6']['prefix-length'] = self.want.ipv6_mgmt_address.split('/')[1]
            if params.get('mgmt-ip').get('ipv6') and params.get('mgmt-ip').get('ipv6').get('gateway') is None:
                params['mgmt-ip']['ipv6']['gateway'] = self.want.ipv6_mgmt_gateway

        payload = dict(config=params)
        uri = f"/f5-system-partition:partitions/partition={self.want.name}/config"
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(
                "Failed to update Partition {0} with {1}".format(self.want.name, response['contents']))
        return True

    def _partition_iso_update(self):
        uri = f"/f5-system-partition:partitions/partition={self.want.name}/set-version"
        partition_data = {
            "f5-system-partition:set-version":
                {
                    "iso-version": self.want.os_version
                }
        }
        response = self.client.post(uri, data=partition_data)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        uri = f"/f5-system-partition:partitions/partition={self.want.name}"
        slots = self.get_slots_associated_with_partition(self.want.name)
        if len(slots) > 0:
            self.remove_slot_from_partition()
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def remove_slot_from_partition(self):
        slots_to_disassociate = list(set(self.have.slots) - set(self.want.slots))
        if self.want.state == "absent" and self.have.slots is not None:
            slots_to_disassociate = self.have.slots

        if len(slots_to_disassociate) > 0:
            self.set_slot_config("none", slots_to_disassociate)
        return True

    def read_current_from_device(self):
        uri = f"/f5-system-partition:partitions/partition={self.want.name}/config"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        response = response['contents']['f5-system-partition:config']
        slots = self.get_slots_associated_with_partition(self.want.name)
        response.update(slots=slots)
        return ApiParameters(params=response)

    def get_slots_associated_with_partition(self, name):
        uri = "/f5-system-slot:slots/slot"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        slot_config = response['contents']['f5-system-slot:slot']
        slots = [cfg['slot-num'] for cfg in slot_config
                 if cfg['partition'] == name]
        return slots

    def get_all_slots(self):
        uri = "/f5-system-slot:slots/slot"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-slot:slot']

    def set_slot_config(self, partition_name: str, slots: list):
        """
        Set the slot configuration
        :param partition_name: The partition to assign the slots to
        :param slots: list -  which slots to assign
        :return:
        """
        uri = "/f5-system-slot:slots"
        slot_data = {
            'f5-system-slot:slots': {
                'slot': [{'slot-num': slot, 'partition': partition_name}
                         for slot in slots]}}
        response = self.client.patch(uri, data=slot_data)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(
                "Failed to assign partition slot with {0}".format(response['contents']))
        return response


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            ipv4_mgmt_address=dict(),
            ipv4_mgmt_gateway=dict(),
            ipv6_mgmt_address=dict(),
            ipv6_mgmt_gateway=dict(),
            os_version=dict(),
            service_version=dict(),
            slots=dict(
                type='list',
                elements='int'
            ),
            wait_time=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['present', 'absent', 'enabled', 'disabled']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['os_version']],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
