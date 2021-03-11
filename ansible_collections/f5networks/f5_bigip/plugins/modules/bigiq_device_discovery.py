#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigiq_device_discovery
short_description: Manage BIG-IP devices through BIG-IQ
description:
  - Discovers and imports BIG-IP device configuration on the BIG-IQ.
version_added: "1.0.0"
options:
  device_address:
    description:
      - The IP address of the BIG-IP device to be imported/managed.
    type: str
    required: True
  device_username:
    description:
      - The administrator username for the BIG-IP device.
      - This parameter is only required when adding a new BIG-IP device to be managed.
    type: str
  device_password:
    description:
      - The administrator password for the BIG-IP device.
      - This parameter is only required when adding a new BIG-IP device to be managed.
    type: str
  device_port:
    description:
      - The port on which a device trust setup between BIG-IQ and BIG-IP should happen.
    type: int
    default: 443
  ha_name:
    description:
      - DSC cluster name of the BIG-IP device to be managed.
      - This is optional if the managed device is not a part of a cluster group.
      - When C(use_bigiq_sync) is set to C(yes), this parameter is required.
    type: str
  use_bigiq_sync:
    description:
      - When set to true, BIG-IQ manually synchronizes configuration changes
        between members in a DSC cluster.
    type: bool
    default: no
  conflict_policy:
    description:
      - Sets the conflict resolution policy for shared objects across BIG-IP devices, except LTM profiles and monitors.
    type: str
    choices:
      - use_bigiq
      - use_bigip
    default: use_bigiq
  versioned_conflict_policy:
    description:
      - Sets the conflict resolution policy for LTM profile and monitor objects that are specific to a BIG-IP software
        version.
    type: str
    choices:
      - use_bigiq
      - use_bigip
      - keep_version
  device_conflict_policy:
    description:
      - Sets the conflict resolution policy for objects that are specific to a particular to a BIG-IP device
        and not shared among BIG-IP devices.
    type: str
    choices:
      - use_bigiq
      - use_bigip
    default: use_bigiq
  access_conflict_policy:
    description:
      - Sets the conflict resolution policy for Access module C(apm) objects. Only used when the C(apm) module is specified.
    type: str
    choices:
      - use_bigiq
      - use_bigip
      - keep_version
  access_group_name:
    description:
      - Access group name to import Access configuration for devices. Once set it cannot be changed.
    type: str
  access_group_first_device:
    description:
      - Specifies if the imported device is the first device in the access group to import shared configuration for that
        access group.
    type: bool
    default: yes
  force:
    description:
      - Forces rediscovery and import of existing modules on the managed BIG-IP.
    type: bool
    default: no
  modules:
    description:
      - List of modules to be discovered and imported into the device.
      - These modules must be provisioned on the target device, otherwise operation will fail.
      - The C(ltm) module must always be specified when performing discovery or re-discovery of the the device.
      - When C(asm) or C(afm) are specified, the C(shared_security) module also needs to be declared.
    type: list
    elements: str
    choices:
      - ltm
      - asm
      - apm
      - afm
      - dns
      - websafe
      - security_shared
  statistics:
    description:
      - Specify the statistics collection for discovered device.
    type: dict
    suboptions:
      enable:
        description:
          - Enables statistics collection on a device.
        type: bool
        default: no
      interval:
        description:
          - Specifies the interval the data is collected from the discovered device, in seconds.
        type: int
        default: 60
        choices:
          - 30
          - 60
          - 120
          - 500
      zone:
        description:
          - Specifies in which DCD zone is collecting the data from device.
        type: str
        default: default
      stat_modules:
        description:
          - Specifies for which modules the data is being collected.
        type: list
        elements: str
        default: ['device', 'ltm']
        choices:
          - device
          - ltm
          - dns
  state:
    description:
      - The state of the managed device on the system.
      - When C(present), enables new device addition as well as device rediscovery/import.
      - When C(absent), completely removes the device from the system.
    type: str
    choices:
      - absent
      - present
    default: present
notes:
  - BIG-IQ >= 6.1.0.
  - This module does not support atomic removal of discovered modules on the device.
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Discover a new device and import config, use default conflict policy.
  bigiq_device_discovery:
    device_address: 192.168.1.1
    device_username: bigipadmin
    device_password: bigipsecret
    modules:
      - ltm
      - afm
      - shared_security
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Discover a new device and import config, use non- default conflict policy.
  bigiq_device_discovery:
    device_address: 192.168.1.1
    modules:
      - ltm
      - dns
    conflict_policy: use_bigip
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Force full device rediscovery
  bigiq_device_discovery:
    device_address: 192.168.1.1
    modules:
      - ltm
      - afm
      - dns
      - shared_security
    force: yes
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove discovered device and its config
  bigiq_device_discovery:
    device_address: 192.168.1.1
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
device_address:
  description: The IP address of the BIG-IP device to be imported/managed.
  returned: changed
  type: str
  sample: 192.168.1.1
device_port:
  description: The port on which a device trust setup between BIG-IQ and BIG-IP should happen.
  returned: changed
  type: int
  sample: 10443
ha_name:
  description: DSC cluster name of the BIG-IP device to be managed.
  returned: changed
  type: str
  sample: GROUP_1
use_bigiq_sync:
  description: Indicates if BIG-IQ should manually synchronize DSC configuration.
  returned: changed
  type: bool
  sample: yes
conflict_policy:
  description: Sets the conflict resolution policy for shared objects across BIG-IP devices.
  returned: changed
  type: str
  sample: use_bigip
device_conflict_policy:
  description: Sets the conflict resolution policy for objects that are specific to a particular to a BIG-IP device.
  returned: changed
  type: str
  sample: use_bigip
versioned_conflict_policy:
  description: Sets the conflict resolution policy for LTM profile and monitor objects.
  returned: changed
  type: str
  sample: keep_version
access_conflict_policy:
  description: Sets the conflict resolution policy for Access module C(apm) objects.
  returned: changed
  type: str
  sample: keep_version
access_group_name:
  description: Access group name to import Access configuration for devices.
  returned: changed
  type: str
  sample: foo_group
access_group_first_device:
  description: First device in the access group to import shared configuration for that access group.
  returned: changed
  type: bool
  sample: yes
modules:
  description: List of modules to be discovered and imported into the device.
  returned: changed
  type: list
  sample: ['ltm', 'dns']

'''

import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)
from ..module_utils.client import F5Client, bigiq_version
from ..module_utils.ipaddress import is_valid_ip


class Parameters(AnsibleF5Parameters):
    api_map = {
        'address': 'device_address',
        'userName': 'device_username',
        'password': 'device_password',
        'httpsPort': 'device_port',
        'clusterName': 'ha_name',
        'useBigiqSync': 'use_bigiq_sync',
    }

    api_attributes = [
        'address',
        'userName',
        'password',
        'httpsPort',
        'clusterName',
        'useBigiqSync',
    ]

    returnables = [
        'device_address',
        'device_username',
        'device_password',
        'device_port',
        'ha_name',
        'use_bigiq_sync',
        'modules',
        'conflict_policy',
        'versioned_conflict_policy',
        'device_conflict_policy',
        'access_group_name',
        'access_group_first_device',
        'access_conflict_policy',
        'module_list',
        'apm_properties',
    ]

    updatables = [
        'modules',
        'access_group_name',
        'apm_properties',
        'module_list',
    ]


class ApiParameters(Parameters):
    module_map = {
        'cm-security-shared-allSharedDevices': 'security_shared',
        'cm-asm-allAsmDevices': 'asm',
        'cm-firewall-allFirewallDevices': 'firewall',
        'cm-websafe-allFpsDevices': 'fps',
        'cm-dns-allBigIpDevices': 'dns',
        'cm-adccore-allbigipDevices': 'adc_core',
        'cm-access-allBigIpDevices': 'access',
    }

    @property
    def modules(self):
        raw_data = self._values['properties']
        if raw_data is None:
            return None
        result = list()
        for item in raw_data.keys():
            if item in self.module_map:
                if raw_data[item]['discovered'] is True and raw_data[item]['imported'] is True:
                    result.append(self.module_map[item])
        return result

    @property
    def access_group_name(self):
        raw_data = self._values['properties']
        if raw_data is None:
            return None
        for item in raw_data.keys():
            if 'cm:access:access-group-name' in raw_data[item]:
                return raw_data[item]['cm:access:access-group-name']
        return None


class ModuleParameters(Parameters):
    module_map = {
        'ltm': 'adc_core',
        'afm': 'firewall',
        'websafe': 'fps',
        'apm': 'access',
    }

    @property
    def device_password(self):
        if self._values['device_password'] is None:
            return None
        return self._values['device_password']

    @property
    def device_username(self):
        if self._values['device_username'] is None:
            return None
        return self._values['device_username']

    @property
    def device_address(self):
        if is_valid_ip(self._values['device_address']):
            return self._values['device_address']
        raise F5ModuleError(
            'Provided device address: {0} is not a valid IP.'.format(self._values['device_address'])
        )

    @property
    def device_port(self):
        if self._values['device_port'] is None:
            return None
        return int(self._values['device_port'])

    @property
    def conflict_policy(self):
        return self._values['conflict_policy'].upper()

    @property
    def device_conflict_policy(self):
        return self._values['device_conflict_policy'].upper()

    @property
    def versioned_conflict_policy(self):
        if self._values['versioned_conflict_policy'] is None:
            return None
        return self._values['versioned_conflict_policy'].upper()

    @property
    def access_conflict_policy(self):
        if self._values['access_conflict_policy'] is None:
            return None
        return self._values['device_conflict_policy'].upper()

    @property
    def modules(self):
        if self._values['modules'] is None:
            return None
        result = list()
        if 'security_shared' not in self._values['modules']:
            if 'afm' in self._values['modules']:
                raise F5ModuleError(
                    "Module 'shared_security' required for 'afm' module."
                )
            if 'asm' in self._values['modules']:
                raise F5ModuleError(
                    "Module 'shared_security' required for 'asm' module."
                )
        if 'ltm' not in self._values['modules']:
            raise F5ModuleError(
                "LTM module must be specified for device discovery and import."
            )
        if 'apm' in self._values['modules']:
            if not self.access_group_name or not self.access_conflict_policy:
                raise F5ModuleError(
                    "When importing APM 'access_group_name' and 'access_conflict_policy' must be specified."
                )
        for item in self._values['modules']:
            if item in self.module_map:
                result.append(self.module_map[item])
            else:
                result.append(item)
        return result

    @property
    def apm_properties(self):
        if self._values['modules'] is None:
            return None
        if 'apm' in self._values['modules']:
            result = {
                'cm:access:conflict-resolution': self.access_conflict_policy,
                'cm:access:access-group-name': self.access_group_name,
                'cm:access:import-shared': self.access_group_first_device
            }
            return result

    @property
    def use_bigiq_sync(self):
        result = flatten_boolean(self._values['use_bigiq_sync'])
        if result:
            if result == 'yes':
                return True
            return False

    @property
    def access_group_first_device(self):
        result = flatten_boolean(self._values['access_group_first_device'])
        if result:
            if result == 'yes':
                return True
            return False

    @property
    def stats_enabled(self):
        if self._values['statistics'] is None:
            return None
        result = flatten_boolean(self._values['statistics']['enable'])
        if result:
            if result == 'yes':
                return True
            return False

    @property
    def interval(self):
        if self._values['statistics'] is None:
            return None
        return self._values['statistics']['interval']

    @property
    def zone(self):
        if self._values['statistics'] is None:
            return None
        return self._values['statistics']['zone']

    @property
    def stat_modules(self):
        if self._values['statistics'] is None:
            return None
        modules = self._values['statistics']['stat_modules']
        result = list()
        for module in modules:
            result.append((dict(module=module.upper())))
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
    def modules(self):
        if self._values['modules'] is None:
            return None
        result = list()
        for item in self._values['modules']:
            result.append(dict(module=item))
        return result

    @property
    def module_list(self):
        if self._values['modules'] is None:
            return None
        result = list()
        for item in self._values['modules']:
            if item == 'access':
                result.append(dict(module=item, properties=self._values['apm_properties']))
            else:
                result.append(dict(module=item))
        return result


class ReportableChanges(Changes):
    @property
    def module_list(self):
        return None

    @property
    def apm_properties(self):
        return None


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
    def modules(self):
        if self.want.modules is None:
            return None
        if self.have.modules is None:
            return self.want.modules
        if set(self.want.modules).issubset(self.have.modules):
            return None
        if set(self.want.modules) != set(self.have.modules):
            return self.want.modules

    @property
    def access_group_name(self):
        if self.want.access_group_name != self.have.access_group_name:
            raise F5ModuleError(
                'Access group name cannot be modified once it is set.'
            )

    @property
    def apm_properties(self):
        # This is required for idempotency and updates as we do not compare these properties
        return None


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()
        self.device_id = None
        self.task_id = None

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
            changed['apm_properties'] = self.want.apm_properties
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

    def check_bigiq_version(self, version):
        if LooseVersion(version) < LooseVersion('6.1.0'):
            raise F5ModuleError(
                'Module supports only BIGIQ version 6.1.x or higher.'
            )

    def exec_module(self):
        self.check_bigiq_version(bigiq_version(self.client))
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
        if not self.should_update() and not self.want.force:
            return False
        if self.module.check_mode:
            return True
        if self.want.force:
            self._set_changed_options()
        self.discover_on_device()
        self.import_modules_on_device()
        if self.want.stats_enabled:
            self.enable_stats_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_autority_from_device()
        self.remove_trust_from_device()
        return True

    def create(self):
        if self.want.modules is None:
            raise F5ModuleError(
                'List of modules cannot be empty if discovering a device.'
            )
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.set_trust_with_device()
        self.discover_on_device()
        self.import_modules_on_device()
        if self.want.stats_enabled:
            self.enable_stats_on_device()
        return True

    def exists(self):
        uri = "/mgmt/cm/system/machineid-resolver"
        query = "?$filter=address%20eq%20'{0}'".format(self.want.device_address)
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents']:
            if not response['contents']['items']:
                return False
            self.device_id = response['contents']['items'][0]['machineId']
            return True
        return False

    def set_trust_with_device(self):
        params = self.changes.api_params()
        params['name'] = 'trust_{0}'.format(self.want.device_address)
        uri = "/mgmt/cm/global/tasks/device-trust/"
        response = self.client.post(uri, data=params)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task = "/mgmt/cm/global/tasks/device-trust/{0}".format(response['contents']['id'])
        query = "?$select=status,currentStep,errorMessage"

        if self._wait_for_task(task + query):
            self._set_device_id(task)
        return True

    def _set_device_id(self, uri):
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.device_id = response['contents']['machineId']

    def _wait_for_task(self, uri):
        while True:
            response = self.client.get(uri)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['status'] in ['FINISHED', 'FAILED', 'CANCELLED']:
                break

            time.sleep(1)

        if response['contents']['status'] == 'FAILED':
            raise F5ModuleError(response['errorMessage'])
        if response['contents']['status'] == 'CANCELLED':
            raise F5ModuleError(
                'The task process has been cancelled.'
            )
        if response['contents']['status'] == 'FINISHED':
            return True

    def discover_on_device(self):
        tmp = self.changes.to_return()
        if self.reuse_task_on_device('discovery'):
            params = dict(
                moduleList=tmp['modules'],
                status='STARTED'
            )
            uri = "/mgmt/cm/global/tasks/device-discovery/{0}".format(self.task_id)
            response = self.client.patch(uri, data=params)

        else:
            params = dict(
                name='discovery_{0}'.format(self.want.device_address),
                moduleList=tmp['modules'],
                deviceReference=dict(link='https://localhost/mgmt/cm/system/machineid-resolver/{0}'.format(
                    self.device_id
                )
                ),
                status='STARTED'
            )
            uri = "/mgmt/cm/global/tasks/device-discovery"
            response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task = "/mgmt/cm/global/tasks/device-discovery/{0}".format(response['contents']['id'])
        query = "?$select=status,currentStep,errorMessage"

        self._wait_for_task(task + query)

        return True

    def import_modules_on_device(self):
        tmp = self.changes.to_return()
        if self.reuse_task_on_device('import'):
            params = dict(
                moduleList=tmp['module_list'],
                conflictPolicy=self.want.conflict_policy,
                deviceConflictPolicy=self.want.device_conflict_policy,
                status='STARTED'
            )

            if self.want.versioned_conflict_policy:
                params['versionedConflictPolicy'] = self.want.versioned_conflict_policy

            uri = "/mgmt/cm/global/tasks/device-import/{0}".format(self.task_id)
            response = self.client.patch(uri, data=params)

        else:
            params = dict(
                name='import_{0}'.format(self.want.device_address),
                moduleList=tmp['module_list'],
                conflictPolicy=self.want.conflict_policy,
                deviceConflictPolicy=self.want.device_conflict_policy,
                deviceReference=dict(link='https://localhost/mgmt/cm/system/machineid-resolver/{0}'.format(
                    self.device_id
                )
                ),
                status='STARTED'
            )

            if self.want.versioned_conflict_policy:
                params['versionedConflictPolicy'] = self.want.versioned_conflict_policy

            uri = "/mgmt/cm/global/tasks/device-import"
            response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task = "/mgmt/cm/global/tasks/device-import/{0}".format(response['contents']['id'])
        query = "?$select=status,currentStep,errorMessage"

        self._wait_for_task(task + query)

        return True

    def enable_stats_on_device(self):
        params = dict(
            enabled=self.want.stats_enabled,
            pushIntervalSecs=self.want.interval,
            zone=self.want.zone,
            modules=self.want.stat_modules,
            targetDeviceReference=dict(
                link='https://localhost/mgmt/cm/system/machineid-resolver/{0}'.format(
                    self.device_id
                )
            ),
        )

        uri = "/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task = "/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task/{0}".format(response['contents']['id'])
        query = "?$select=status,currentStep,errorMessage"

        self._wait_for_task(task + query)

        return True

    def reuse_task_on_device(self, task):
        if task == 'discovery':
            uri = "/mgmt/cm/global/tasks/device-discovery"
        else:
            uri = "/mgmt/cm/global/tasks/device-import"

        query = "?$filter=deviceReference/link%20eq%20'{0}'".format(self.device_id)
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents']:
            if response['contents']['items']:
                self.task_id = response['contents']['id']
                return True
        return False

    def remove_autority_from_device(self):
        # We can provide all of the modules for removal task, without ensuring they were discovered
        modules = [
            {'module': 'adc_core'},
            {'module': 'access'},
            {'module': 'asm'},
            {'module': 'fps'},
            {'module': 'firewall'},
            {'module': 'security_shared'},
            {'module': 'dns'}
        ]
        params = dict(
            moduleList=modules,
            deviceReference=dict(
                link="https://localhost/mgmt/cm/system/machineid-resolver/{0}".format(self.device_id)
            ),
            name='remove_auth_{0}'.format(self.want.device_address)

        )
        uri = "/mgmt/cm/global/tasks/device-remove-mgmt-authority/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task = "/mgmt/cm/global/tasks/device-remove-mgmt-authority/{0}".format(response['contents']['id'])
        query = "?$select=status,currentStep,errorMessage"

        self._wait_for_task(task + query)

    def remove_trust_from_device(self):
        params = dict(
            deviceReference=dict(
                link="https://localhost/mgmt/cm/system/machineid-resolver/{0}".format(self.device_id)
            ),
            name='remove_auth_{0}'.format(self.want.device_address)

        )
        uri = "/mgmt/cm/global/tasks/device-remove-trust/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task = "/mgmt/cm/global/tasks/device-remove-trust/{0}".format(response['contents']['id'])
        query = "?$select=status,currentStep,errorMessage"

        self._wait_for_task(task + query)

    def read_current_from_device(self):
        uri = "/mgmt/cm/system/machineid-resolver/{0}".format(self.device_id)
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.conflict = ['use_bigip', 'use_bigiq']
        argument_spec = dict(
            device_address=dict(
                required=True
            ),
            device_username=dict(
                no_log=True
            ),
            device_password=dict(
                no_log=True
            ),
            device_port=dict(
                type='int',
                default=443
            ),
            ha_name=dict(),
            use_bigiq_sync=dict(
                type='bool',
                default='no'
            ),
            conflict_policy=dict(
                choices=self.conflict,
                default='use_bigiq'
            ),
            versioned_conflict_policy=dict(
                choices=self.conflict + ['keep_version'],
            ),
            device_conflict_policy=dict(
                choices=self.conflict,
                default='use_bigiq'
            ),
            force=dict(
                type='bool',
                default='no'
            ),
            modules=dict(
                type='list',
                elements='str',
                choices=[
                    'ltm', 'asm', 'afm', 'dns', 'websafe', 'security_shared', 'apm'
                ]
            ),
            access_conflict_policy=dict(
                choices=self.conflict + ['keep_version']
            ),
            access_group_name=dict(),
            access_group_first_device=dict(
                type='bool',
                default='yes'
            ),
            statistics=dict(
                type='dict',
                options=dict(
                    enable=dict(
                        type='bool',
                        default='no'
                    ),
                    interval=dict(
                        type='int',
                        choices=[
                            30, 60, 120, 500
                        ],
                        default=60
                    ),
                    zone=dict(
                        type='str',
                        default='default'
                    ),
                    stat_modules=dict(
                        type='list',
                        elements='str',
                        choices=[
                            'device', 'ltm', 'dns'
                        ],
                        default=[
                            'device', 'ltm'
                        ]
                    )
                )

            ),
            state=dict(default='present', choices=['absent', 'present']),
        )
        self.required_if = [
            ['use_bigiq_sync', True, ['ha_name']]
        ]
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


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
