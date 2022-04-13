#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_partition_interface
short_description: Manage network interfaces on VELOS chassis partitions
description:
  - Manage network interfaces on VELOS chassis partitions.
version_added: "1.4.0"
options:
  name:
    description:
      - Name of the chassis partition interface to configure.
    type: str
    required: true
  trunk_vlans:
    description:
      - Configures multiple VLAN IDs to associate with the interface.
      - The C(trunk_vlans) parameter is used for tagged traffic.
      - VLANs should not be assigned to interfaces if Link Aggregation Groups. In that case VLANs should be added to
        the the LAG configuration with C(velos_partition_lag) module instead.
      - The C(native_vlan) and C(trunk_vlans) parameters are mutually exclusive.
      - The order of these VLANs is ignored, the module orders the VLANs automatically.
    type: list
    elements: int
  native_vlan:
    description:
      - Configures the VLAN ID to associate with the interface.
      - The C(native_vlan) and C(trunk_vlans) parameters are mutually exclusive.
    type: int
  state:
    description:
      - If C(present), creates the specified object if it does not exist, or updates the existing object.
      - If C(absent), deletes the object if it exists.
    type: str
    choices:
      - present
      - absent
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
    - name: Creating VLAN444
      velos_partition_vlan:
        name: vlan-444
        vlan_id: 444

    - name: Creating VLAN555
      velos_partition_vlan:
        name: vlan-555
        vlan_id: 555

    - name: Attach Vlans to interface
      velos_partition_interface:
        name: "2/1.0"
        trunk_vlans: [444]
        state: present

    - name: modify Vlans to interface
      velos_partition_interface:
        name: "2/1.0"
        trunk_vlans: [444,555]
        state: present

    - name: Delete vlans on interface
      velos_partition_interface:
        name: "2/1.0"
        trunk_vlans: [444,555]
        state: absent
'''

RETURN = r'''
name:
  description: Name of the partition interface to configure.
  returned: changed
  type: str
  sample: new_name
trunk_vlans:
  description: trunk_vlans to attach to Interface.
  returned: changed
  type: int
  sample: [444,555]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
import re

from urllib.parse import quote


class Parameters(AnsibleF5Parameters):
    api_map = {
        'type': 'interface_type'
    }

    api_attributes = [
        'name',
        'type',
        'interface',
        'switched_vlan'
    ]

    returnables = [
        'interface_type',
        'switched_vlan'
    ]

    updatables = [
        'name',
        'interface_type',
        'switched_vlan'
    ]


class ApiParameters(Parameters):
    @property
    def interface_type(self):
        # Remove the 'iana-if-type:' prefix returned from the API.
        return re.sub(r'^{0}'.format(re.escape('iana-if-type:')), '', self._values['config']['type'])

    @property
    def switched_vlan(self):
        if self._values['name'] is None:
            return None
        iftype = 'openconfig-if-ethernet:ethernet'
        if self._values[iftype] is None:
            return None
        if 'openconfig-vlan:switched-vlan' not in self._values[iftype]:
            return None
        if 'trunk-vlans' in self._values[iftype]['openconfig-vlan:switched-vlan']['config']:
            return self._values[iftype]['openconfig-vlan:switched-vlan']['config']['trunk-vlans']
        if 'native-vlan' in self._values[iftype]['openconfig-vlan:switched-vlan']['config']:
            return self._values[iftype]['openconfig-vlan:switched-vlan']['config']['native-vlan']


class ModuleParameters(Parameters):
    @property
    def name(self):
        # Format: blade/port, or 1/1.0
        interface_format = re.compile(r'(?P<blade>\d+)\/(?P<port>\d+\.\d+)')
        match = interface_format.match(self._values['name'])
        if match is None:
            raise F5ModuleError(
                "Valid interface name must be formatted 'blade/port'. e.g. '1/1.0'"
            )

        return self._values['name']

    @property
    def switched_vlan(self):

        if self._values['native_vlan'] is not None:
            vlan = self._values['native_vlan']
            if vlan < 0 or vlan > 4095:
                raise F5ModuleError(
                    "Valid 'vlan_id' must be in range 0 - 4095."
                )
            return vlan

        if self._values['trunk_vlans'] is None:
            return None

        # Ensure valid vlan id's are passed in.
        vlans = self._values['trunk_vlans']
        if len(vlans) > 0:
            if min(vlans) < 0 or max(vlans) > 4095:
                raise F5ModuleError(
                    "Valid vlan id must be in range 0 - 4095."
                )
        if len(self._values['trunk_vlans']) > 1:
            self._values['trunk_vlans'].sort()
            return self._values['trunk_vlans']

        return self._values['trunk_vlans']


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
    def switched_vlan(self):
        if self._values['switched_vlan'] is None:
            return None
        if isinstance(self._values['switched_vlan'], list):
            result = {
                "openconfig-vlan:switched-vlan": {
                    "config": {
                        "trunk-vlans": self._values['switched_vlan'],
                    }
                }
            }
            return result
        if isinstance(self._values['switched_vlan'], int):
            result = {
                "openconfig-vlan:switched-vlan": {
                    "config": {
                        "native-vlan": self._values['switched_vlan'],
                    }
                }
            }
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
    def switched_vlan(self):
        if self.want.switched_vlan == self.have.switched_vlan:
            return None
        return self.want.switched_vlan


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

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
            # self._set_changed_options() <== remove ?
            return self.update()
        else:
            raise F5ModuleError(
                "Interface {0} does not exist. This module can only update existing interfaces".format(
                    self.want.name
                )
            )

    def absent(self):
        if self.exists() and self._get_switched_vlan():
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
        return True

    def exists(self):
        interface_encoded = self._encode_interface_name()
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        params = self.changes.api_params()
        payload = {
            'openconfig-interfaces:interfaces': {
                'interface': [
                    {
                        'name': self.want.name,
                        'openconfig-if-ethernet:ethernet': params.get('switched_vlan')
                    }
                ]
            }
        }

        uri = "/openconfig-interfaces:interfaces/"
        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(
                "Failed to update Vlans {0} to interface {1}".format(
                    self.want.switched_vlan, self.want.name
                )
            )
        return True

    def remove_from_device(self):
        if self._get_switched_vlan():
            self._update_switched_vlan(self.want.switched_vlan)
        return True

    def _remove_trunk_vlans(self, vlan):
        interface_encoded = self._encode_interface_name()
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/openconfig-vlan:switched-vlan/openconfig-vlan:config/openconfig-vlan:trunk-vlans={vlan}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def _remove_native_vlan(self):
        interface_encoded = self._encode_interface_name()
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/openconfig-vlan:switched-vlan/openconfig-vlan:config/openconfig-vlan:native-vlan"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        interface_encoded = self._encode_interface_name()
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents']['openconfig-interfaces:interface'][0])

    def _encode_interface_name(self):
        """
        Helper method -- Encode interface name (/ -> %2F).
        Use this method after confirming interface is
            valid using self.verify(interface: str)
        :return interface_encoded: str
        """
        return quote(self.want.name, safe='')

    def _update_switched_vlan(self, switched_vlan_want):
        if switched_vlan_want is None:
            # nothing to do.
            return

        if self.have.switched_vlan is not None:
            if isinstance(self.have.switched_vlan, list):
                for vlan in self.have.switched_vlan:
                    self._remove_trunk_vlans(vlan)
            if isinstance(self.have.switched_vlan, int):
                self._remove_native_vlan()
        return True

    def _get_switched_vlan(self):
        interface_encoded = self._encode_interface_name()
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/openconfig-vlan:switched-vlan"
        response = self.client.get(uri)
        if response['code'] in [200, 201, 202]:
            return True
        if response['code'] == 204:
            return False
        raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            trunk_vlans=dict(
                type='list',
                elements='int',
            ),
            native_vlan=dict(
                type="int",
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['trunk_vlans', 'native_vlan']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
