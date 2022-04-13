#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_partition_vlan
short_description: Manage VLANs on VELOS chassis partitions
description:
  - Manage VLANs on VELOS chassis partitions.
version_added: "1.3.0"
options:
  name:
    description:
      - Specifies the name of the VLAN to configure on the chassis partition.
      - This parameter is optional, if it is not provided, the parameter name is derived from C(vlan_id).
    type: str
  vlan_id:
    description:
      - The ID for the VLAN.
      - Valid value range is from C(0) to C(4095).
    required: True
    type: int
  state:
    description:
      - The partition VLAN state.
      - If C(present), creates the specified VLAN if it does not exist, or updates the existing VLAN.
      - If C(absent), deletes the VLAN if it exists.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
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
    - name: Create a vlan on partition
      velos_partition_vlan:
        name: foo
        vlan_id: 3212

    - name: Update name of a vlan on partition
      velos_partition_vlan:
        name: changed_this
        vlan_id: 3212

    - name: Delete vlan on partition
      velos_partition_vlan:
        vlan_id: 3212
        state: absent
'''

RETURN = r'''
name:
  description: The name of the VLAN.
  returned: changed
  type: str
  sample: new_name
vlan_id:
  description: The ID of the VLAN.
  returned: changed
  type: int
  sample: 1234
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = [
        'vlan',
        'name',
    ]

    returnables = [
        'name',
        'vlan_id',
    ]

    updatables = [
        'name',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def vlan_id(self):
        result = self._values['vlan_id']
        if result < 0 or result > 4095:
            raise F5ModuleError(
                "Valid 'vlan_id' must be in range 0 - 4095."
            )
        return result

    @property
    def name(self):
        if self._values['name'] is None:
            return str(self._values['vlan_id'])
        return self._values['name']


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
    def vlan(self):
        if self._values['vlan_id'] is None:
            return None
        result = {
            'vlan-id': self._values['vlan_id'],
            'config': {
                'vlan-id': self._values['vlan_id'],
                'name': self._values['name'],
            }
        }
        return [result]


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

    def vlan_id(self):
        if self.want.vlan_id != self.have.vlan_id:
            raise F5ModuleError(
                "The C(vlan_id) cannot be updated once vlan is created."
            )


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

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

        if state == "present":
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
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/openconfig-vlan:vlans/vlan={self.want.vlan_id}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        # we only use name parameter separately in update
        params.pop('name', None)
        params = {'openconfig-vlan:vlans': params}
        uri = "/"
        response = self.client.patch(uri, data=params)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        for k, v in params.items():
            uri = f"/openconfig-vlan:vlans/vlan={self.want.vlan_id}/config/{k}"
            payload = {k: v}
            response = self.client.patch(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError("Failed to update vlan {0}, {1} to {2}".format(self.want.vlan_id, k, v))
        return True

    def remove_from_device(self):
        uri = f"/openconfig-vlan:vlans/vlan={self.want.vlan_id}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/openconfig-vlan:vlans/vlan={self.want.vlan_id}/config/"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents']['openconfig-vlan:config'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(),
            vlan_id=dict(
                required=True,
                type="int",
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
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
