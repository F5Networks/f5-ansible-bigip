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
short_description: Manage Velos chassis partitions
description:
  - Manage Velos partitions.
  - This module uses the controller API. The specified provider should be the IP of a VELOS system Controller.
version_added: 1.2.0
options:
  name:
    description:
      - Name of the partition
    type: str
    required: True
  ipv4_mgmt_address:
    description:
      - Specifies the IPv4 address, and subnet or subnet mask that you use to access
        the partition.
      - When creating a new partition, if you do not specify a network or network mask,
        a default of C(/24) will be assumed.
      - The value C(none) can be used during an update to remove this value.
    type: str
  ipv4_mgmt_gateway:
    description:
      - Desired partition management gateway.
      - The value C(none) can be used during an update to remove this value.
    type: str
  ipv6_mgmt_address:
    description:
      - Specifies the IPv6 address, and subnet or subnet mask that you use to access
        the partition.
      - When creating a new partition, if you do not specify a network or network mask,
        a default of C(/96) will be assumed.
      - The value C(none) can be used during an update to remove this value.
    type: str
  ipv6_mgmt_gateway:
    description:
      - Desired partition management gateway.
      - The value C(none) can be used during an update to remove this value.
    type: str
  os_version:
    description:
      - Partition OS version.
      - The value C(none) can be used during an update to remove this value.
    type: str
  slots:
    description:
      - list (integers), specify which slots with which the partition should associated.
      - By default, the partition is not associated with any slots.
    type: list
  wait_time:
    description:
      - Max number of seconds to wait after creating a partiton for it to
        transition to the 'running' state.
    type: int
    default: 300
  state:
    description:
      - The partition state. If C(absent), delete the partition
        if it exists. C(present) creates the partition and enables it.
        If C(enabled), enable the partition if it exists. If C(disabled),
        create the partition if needed, and set state to C(disabled).
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
  description: Specify Name of the partition
  returned: changed
  type: str
  sample: foo
  
os_version:
  description: Partition OS version.
  returned: changed
  type: str
  sample: 1.1.1-5046
  
ipv4_mgmt_address:
  description: Specifies the IPv4 address, and subnet or subnet mask that you use to access partition
  returned: changed
  type: str
  sample: 192.168.1.12/24
  
ipv4_mgmt_gateway:
  description: Desired partition management gateway
  returned: changed
  type: str
  sample: 192.168.1.1

slots:
  description: specify which slots with which the partition should associated
  returned: changed
  type: list
  sample: [3, 4]
'''

from ipaddress import ip_interface
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.ipaddress import (
    is_valid_ip,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'pxe-server': 'pxe_server',
        'service-version': 'service_version',
        'iso-version': 'os_version',
    }

    api_attributes = [
        'name',
        'enabled',
        'service-version',
        'iso-version',
        'pxe-server',
        'slots',
    ]

    returnables = [
        'name',
        'ipv4_mgmt_tuple',
        'ipv4_mgmt_address',
        'ipv4_mgmt_gateway',
        'ipv6_mgmt_tuple',
        'ipv6_mgmt_address',
        'ipv6_mgmt_gateway',
        'enabled',
        'os_version',
        'service_version',
        'pxe_server',
        'slots',
    ]

    updatables = [
        'ipv4_mgmt_tuple',
        'ipv4_mgmt_address',
        'ipv4_mgmt_gateway',
        'ipv6_mgmt_tuple',
        'ipv6_mgmt_address',
        'ipv6_mgmt_gateway',
        'enabled',
        'os_version',
        'service_version',
        'pxe_server',
        'slots',
    ]


class ApiParameters(Parameters):

    @property
    def ipv4_mgmt_address(self):
        if 'ipv4' in self._values['mgmt-ip'] and self._values['mgmt-ip']['ipv4'] is not None:
            return "{}/{}".format(self._values['mgmt-ip']['ipv4']['address'],
                                  self._values['mgmt-ip']['ipv4']['prefix-length'])
        return None

    @property
    def ipv4_mgmt_gateway(self):
        if 'ipv4' in self._values['mgmt-ip'] and self._values['mgmt-ip']['ipv4'] is not None:
            return self._values['mgmt-ip']['ipv4']['gateway']
        return None

    @property
    def ipv6_mgmt_address(self):
        if 'ipv6' in self._values['mgmt-ip'] and self._values['mgmt-ip']['ipv6'] is not None:
            return "{}/{}".format(self._values['mgmt-ip']['ipv6']['address'],
                                  self._values['mgmt-ip']['ipv6']['prefix-length'])
        return None

    @property
    def ipv6_mgmt_gateway(self):
        if 'ipv6' in self._values['mgmt-ip'] and self._values['mgmt-ip']['ipv6'] is not None:
            return self._values['mgmt-ip']['ipv6']['gateway']
        return None

    @property
    def enabled(self):
        return self._values['state'] != 'disabled'

    @property
    def slots(self):
        if self._values['slots'] is None:
            return None

        if len(self._values['slots']) == 0:
            return []

        result = [int(x) for x in self._values['slots']]
        result.sort()
        if min(result) < 0 or max(result) > 32:
            raise F5ModuleError(
                "Valid slot id's must be in range 0 - 32."
            )
        return result

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
        try:
            addr = ip_interface(u'%s' % str(self._values['ipv4_mgmt_address']))
            return str(addr.with_prefixlen)
        except ValueError:
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
        try:
            addr = ip_interface(u'%s' % str(self._values['ipv6_mgmt_address']))
            return str(addr.with_prefixlen)
        except ValueError:
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

        if len(self._values['slots']) == 0:
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
                change = getattr(self, returnable)
                if isinstance(change, dict):
                    result.update(change)
                else:
                    result[returnable] = change
            result = self._filter_params(result)
        except Exception:
            pass
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
    def enabled(self):
        want_enabled = self.want.state != 'disabled'
        if want_enabled == self.have.enabled:
            return None
        return want_enabled

    @property
    def slots(self):
        if self.want.slots is None:
            return None

        slots_differ = set(self.want.slots or []) != set(self.have.slots or [])
        if slots_differ:
            return self.want.slots

        return None


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
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.want.ipv4_mgmt_address.split('/')[1] is None:
            self.want.update(dict(
                ipv4_mgmt_address='{0}/24'.format(self.want.ipv4_mgmt_address.split('/')[0])
            ))
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
        # Note: we're avoiding the partition_api.create method here as it
        # requires deprecated key/value pairs and doesn't support passing the
        # pxe-server key/value.
        # So, marshal data into a structure suitable for the velos restconf API.
        partition_data = {
            "partition":
                {
                    "name": params['name'],
                    "config":
                        {
                            "enabled": params['enabled'],
                            "iso-version": params['iso-version'],
                            "mgmt-ip":
                                {
                                    "ipv4": {
                                        "address": self.want.ipv4_mgmt_address.split('/')[0],
                                        "prefix-length": self.want.ipv4_mgmt_address.split('/')[1],
                                        "gateway": self.want.ipv4_mgmt_gateway,
                                    },
                                },
                        },
                },
        }
        try:
            uri = "/f5-system-partition:partitions"
            response = self.client.post(uri, data=partition_data)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])
        except F5ModuleError as err:
            raise F5ModuleError('Failed to create the Partition {0} with err: {1}'.format(params['name'], err))

        # Update slot assignment.
        slots = params.get('slots')
        if slots:
            try:
                uri = f""
                res = self.set_slot_config(params['name'], slots)
                response = self.client.patch(uri, data=res)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(
                        "Failed to assign partition slot with {0}".format(response['contents']))
            except F5ModuleError as err:
                F5ModuleError("{0}".format(err))
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        partition_data = {
            "f5-system-partition:config":
                {
                    "enabled": self.want.enabled,
                    "mgmt-ip":
                        {
                            "ipv4": {
                                "address": self.want.ipv4_mgmt_address.split('/')[0],
                                "prefix-length": self.want.ipv4_mgmt_address.split('/')[1],
                                "gateway": self.want.ipv4_mgmt_gateway,
                            },
                        },
                },
        }
        try:
            uri = f"/f5-system-partition:partitions/partition={self.want.name}/config"
            response = self.client.patch(uri, data=partition_data)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(
                    "Failed to update Partition {0} with {1}".format(self.want.name, response['contents']))
        except F5ModuleError as err:
            F5ModuleError("{0}".format(err))

        if params.get('iso-version'):
            self._partition_iso_update()

        # Update slot assignment.
        slots = params.get('slots')
        if slots:
            self.remove_slot_from_partition()
            try:
                uri = f""
                res = self.set_slot_config(self.want.name, slots)
                response = self.client.patch(uri, data=res)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError(
                        "Failed to assign partition slot with {0}".format(response['contents']))
            except F5ModuleError as err:
                F5ModuleError("{0}".format(err))
        return True

    def _partition_iso_update(self):
        uri = f"/f5-system-partition:partitions/partition={self.want.name}/set-version"
        partition_data = {
            "f5-system-partition:set-version":
                {
                    "iso-version": self.want.os_version
                }
        }
        try:
            response = self.client.post(uri, data=partition_data)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])
        except F5ModuleError as err:
            raise F5ModuleError('Version update failed for Partition {0} with err: {1}'.format(self.want.name, err))

    def remove_from_device(self):
        uri = f"/f5-system-partition:partitions/partition={self.want.name}"
        self.remove_slot_from_partition()
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def remove_slot_from_partition(self):
        slots_to_disassociate = list(set(self.have.slots) - set(self.want.slots))
        if self.want.state == "absent":
            slots_to_disassociate = self.have.slots
        if len(slots_to_disassociate) > 0:
            slot_data = self.set_slot_config("none", slots_to_disassociate)
        try:
            uri = f""
            response = self.client.patch(uri, data=slot_data)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError(
                    "Failed to update Partition {0} with {1}".format(self.want.name, response['contents']))
        except F5ModuleError as err:
            F5ModuleError("{0}".format(err))
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
        uri = f"/f5-system-slot:slots/slot"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        slot_config = response['contents']['f5-system-slot:slot']
        slots = [cfg['slot-num'] for cfg in slot_config
                 if cfg['partition'] == name]
        return slots

    def get_all_slots(self):
        uri = f"/f5-system-slot:slots/slot"
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
        slot_data = {
            'f5-system-slot:slots': {
                'slot': [{'slot-num': slot, 'partition': partition_name}
                         for slot in slots]}}
        return slot_data


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
                default=[]
            ),
            wait_time=dict(
                type=int,
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
