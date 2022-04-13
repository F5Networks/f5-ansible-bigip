#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: velos_partition_lag
short_description: Manage network interfaces on the VELOS chassis partitions
description:
  - Manage network interfaces on the VELOS chassis partitions.
version_added: "1.4.0"
options:
  name:
    description:
      - Name of the chassis partition interface to configure.
    type: str
    required: true
  trunk_vlans:
    description:
      - Configures multiple VLAN IDs to associate with the Link Aggregation Group.
      - The C(trunk_vlans) parameter is used for tagged traffic.
      - The C(native_vlan) and C(trunk_vlans) parameters are mutually exclusive.
      - The order of these VLANs is ignored, the module orders the VLANs automatically.
    type: list
    elements: int
  native_vlan:
    description:
      - Configures the VLAN ID to associate with the Link Aggregation Group.
      - The C(native_vlans) parameter is used for untagged traffic.
      - The C(native_vlan) and C(trunk_vlans) parameters are mutually exclusive.
    type: int
  lag_type:
    description:
      - The LAG type of the interface to be created.
    type: str
    choices:
      - LACP
      - STATIC
  config_members:
    description:
      - "Configures the list of interfaces to be grouped for the Link Aggregation Group (LAG)."
    type: list
    elements: str
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

    - name: Attach Trunk-vlans to LAG to interface
      velos_partition_lag:
        name: "Arista"
        trunk_vlans: [444]
        state: present

    - name: modify Vlans to LAG interface
      velos_partition_lag:
        name: "Arista"
        trunk_vlans: [444,555]
        state: present

    - name: Delete LAG on interface
      velos_partition_lag:
        name: "Arista"
        trunk_vlans: [444,555]
        state: absent
'''

RETURN = r'''
name:
  description: Name of the partition LAG interface to configure
  returned: changed
  type: str
  sample: new_name
trunk_vlans:
  description: trunk_vlans to attach to the interface
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
        'interface',
        'switched_vlan',
        'interface_type',
        'config_members',
        'lag_type'
    ]

    returnables = [
        'name',
        'switched_vlan',
        'interface_type',
        'config_members',
        'lag_type'
    ]

    updatables = [
        'switched_vlan',
        'interface',
        'config_members',
        'lag_type'
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
        iftype = 'openconfig-if-aggregate:aggregation'
        if self._values[iftype] is None:
            return None
        if 'openconfig-vlan:switched-vlan' not in self._values[iftype]:
            return None

        if 'trunk-vlans' in self._values[iftype]['openconfig-vlan:switched-vlan']['config']:
            return self._values[iftype]['openconfig-vlan:switched-vlan']['config']['trunk-vlans']
        if 'native-vlan' in self._values[iftype]['openconfig-vlan:switched-vlan']['config']:
            return self._values[iftype]['openconfig-vlan:switched-vlan']['config']['native-vlan']

    @property
    def lag_type(self):
        iftype = 'openconfig-if-aggregate:aggregation'
        if self._values[iftype] is None:
            return None
        return self._values[iftype]['config']['lag-type']

    @property
    def config_members(self):
        if self._values['config_members'] is None:
            return None
        return self._values['config_members']


class ModuleParameters(Parameters):

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

    @property
    def interface_type(self):
        return "{0}{1}".format('iana-if-type:', 'ieee8023adLag')

    @property
    def lag_type(self):
        if self._values['lag_type'] is None:
            return 'LACP'
        return self._values['lag_type']

    @property
    def config_members(self):
        # Format: blade/port, or 1/1.0
        if self._values['config_members'] is None:
            return None
        interface_format = re.compile(r'(?P<blade>\d+)\/(?P<port>\d+\.\d+)')
        intf_members = self._values['config_members']
        if len(intf_members) > 0:
            for intf in intf_members:
                match = interface_format.match(intf)
                if match is None:
                    raise F5ModuleError(
                        "Valid interface name must be formatted 'blade/port'. e.g. '1/1.0'"
                    )
        return intf_members


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

    @property
    def interface(self):
        result = {
            "name": self._values['name'],
            "config": {
                "name": self._values['name'],
                "type": self._values['interface_type'],
                "enabled": bool("true"),
            },
            "openconfig-if-aggregate:aggregation": {
                "config": {
                    "lag-type": self._values['lag_type'],
                    "f5-if-aggregate:distribution-hash": "src-dst-ipport",
                },
            }
        }
        if isinstance(self._values['switched_vlan'], list):
            vlan = {
                "trunk-vlans": self._values['switched_vlan'],
            }
            result['openconfig-if-aggregate:aggregation']['openconfig-vlan:switched-vlan'] = dict(config=vlan)
        if isinstance(self._values['switched_vlan'], int):
            vlan = {
                "native-vlan": self._values['switched_vlan'],
            }
            result['openconfig-if-aggregate:aggregation']['openconfig-vlan:switched-vlan'] = dict(config=vlan)
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

    @property
    def switched_vlan(self):
        if self.want.switched_vlan == self.have.switched_vlan:
            return None
        return self.want.switched_vlan

    @property
    def config_members(self):
        if self.want.config_members == self.have.config_members:
            return None
        return self.want.config_members


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
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        payload = {
            'openconfig-interfaces:interfaces': {
                'interface': params.get('interface')
            }
        }

        uri = "/"
        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        if params.get('config_members'):
            for intf in self.want.config_members:
                self._configure_member(intf)
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        if self.have.switched_vlan is not None:
            if isinstance(self.have.switched_vlan, list):
                for vlan in self.have.switched_vlan:
                    self._remove_trunk_vlans(vlan)
            if isinstance(self.have.switched_vlan, int):
                self._remove_native_vlan()
        for k, v in params.items():
            if k == 'switched_vlan':
                uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}" \
                      f"/openconfig-if-aggregate:aggregation/openconfig-vlan:switched-vlan/"
                response = self.client.patch(uri, data=v)
                if response['code'] not in [200, 201, 202, 204]:
                    raise F5ModuleError("Failed to update vlan {0}, {1} to {2}".format(self.want.switched_vlan, k, v))
            if k == 'config_members':
                intf_to_add = set(self.want.config_members) - set(self.have.config_members)
                intf_to_delete = set(self.have.config_members) - set(self.want.config_members)
                for intf in intf_to_add:
                    self._configure_member(intf)
                for intf in intf_to_delete:
                    self._delete_member(intf)
        return True

    def remove_from_device(self):
        self.have = self.read_current_from_device()
        if self.have.config_members is not None:
            for intf in self.have.config_members:
                self._delete_member(intf)
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def _remove_trunk_vlans(self, vlan):
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}" \
              f"/openconfig-if-aggregate:aggregation/openconfig-vlan:switched-vlan/openconfig-vlan:config/openconfig-vlan:trunk-vlans={vlan}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def _remove_native_vlan(self):
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}" \
              f"/openconfig-if-aggregate:aggregation/openconfig-vlan:switched-vlan/openconfig-vlan:config/openconfig-vlan:native-vlan"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/openconfig-interfaces:interfaces/interface={self.want.name}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        intf_list = []
        for intf in self._get_interfaces():
            if self._is_lag_member(intf):
                intf_list.append(intf)

        config = dict(response['contents']['openconfig-interfaces:interface'][0])
        config.update(config_members=intf_list)
        return ApiParameters(params=config)

    def _encode_interface(self, intfname):
        """
        Helper method -- Encode interface name (/ -> %2F).
        Use this method after confirming interface is
            valid using self.verify(interface: str)
        :return interface_encoded: str
        """
        return quote(intfname, safe='')

    def _get_interfaces(self):
        uri = "/openconfig-interfaces:interfaces"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        intf_list = []
        for intdict in response['contents']['openconfig-interfaces:interfaces']['interface']:
            if intdict['config']['type'] == 'iana-if-type:ethernetCsmacd':
                intf_list.append(intdict['name'])
        return intf_list

    def _configure_member(self, intf):
        uri = "/"
        payload = {
            'openconfig-interfaces:interfaces': {
                'interface': [
                    {
                        'name': intf,
                        'config': {
                            'name': intf
                        },
                        'openconfig-if-ethernet:ethernet': {
                            'config': {
                                'openconfig-if-aggregate:aggregate-id': self.want.name
                            }
                        }
                    }
                ]
            }
        }
        response = self.client.patch(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(
                "Failed to update LAG Interface {0} with {1}".format(self.want.name, intf))

    def _delete_member(self, intf):
        interface_encoded = self._encode_interface(intf)
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/config"

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(
                "Failed to delete LAG Interface {0} with {1}".format(self.want.name, intf)
            )

    def _is_lag_member(self, intf):
        interface_encoded = self._encode_interface(intf)
        iftype = 'openconfig-if-ethernet:ethernet'
        uri = f"/openconfig-interfaces:interfaces/interface={interface_encoded}" \
              f"/{iftype}/config"
        payload = {
            "openconfig-if-ethernet:config": {
                "openconfig-if-aggregate:aggregate-id": self.want.name
            }
        }
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(
                "Failed to update LAG Interface {0} with {1}".format(self.want.name, intf))
        if response['code'] == 204:
            return False
        if response['contents'] != payload:
            return False
        return True


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
            config_members=dict(
                type='list',
                elements='str',
            ),
            native_vlan=dict(
                type="int",
            ),
            lag_type=dict(
                choices=['LACP', 'STATIC']
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
