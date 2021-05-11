#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigiq_utility_license
short_description: Manage utility licenses on a BIG-IQ
description:
  - Manages utility licenses on a BIG-IQ. Utility licenses are one form of license
    that BIG-IQ can distribute. These licenses, unlike regkey licenses, do not require
    a pool to be created before creation. Additionally, when assigning them, you assign
    by offering instead of key.
version_added: "1.0.0"
options:
  license_key:
    description:
      - The license key to install and activate.
    type: str
    required: True
  accept_eula:
    description:
      - A key that signifies you accept the F5 EULA for this license.
      - A copy of the EULA can be found here https://askf5.f5.com/csp/article/K12902
      - This is required when C(state) is C(present).
    type: bool
  state:
    description:
      - The state of the utility license on the system.
      - When C(present), guarantees the license exists.
      - When C(absent), removes the license from the system.
    type: str
    choices:
      - absent
      - present
    default: present
requirements:
  - BIG-IQ >= 5.3.0
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
    ansible_network_os: f5networks.f5_bigip.bigiq
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Add a utility license to the system
      bigiq_utility_license:
        license_key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        accept_eula: yes
        state: present

    - name: Remove a utility license from the system
      bigiq_utility_license:
        license_key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        state: absent
'''

RETURN = r'''
# only common fields returned
'''

import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.urls import urlparse

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'regKey': 'license_key'
    }

    api_attributes = [
        'regKey'
    ]

    returnables = [
        'license_key'
    ]

    updatables = [
        'license_key'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    pass


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
    @property
    def license_key(self):
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

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def exec_module(self):
        start = datetime.now().isoformat()
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
        send_teem(self.client, start)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return False
        else:
            return self.create()

    def exists(self):
        uri = "/mgmt/cm/device/licensing/pool/utility/licenses/?$filter=regKey+eq+'{0}'".format(
            self.want.license_key
        )
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if response['code'] == 200 and response['contents']['totalItems'] == 0:
            return False
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        self.wait_for_removal()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.want.accept_eula is False:
            raise F5ModuleError(
                "To add a license, you must accept its EULA. Please see the module documentation for a link to this."
            )
        self.create_on_device()
        self.wait_for_initial_license_activation()
        self.wait_for_utility_license_activation()
        if not self.exists():
            raise F5ModuleError(
                "Failed to activate the license."
            )
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        uri = "/mgmt/cm/device/licensing/pool/initial-activation"

        params['name'] = self.want.license_key
        params['status'] = 'ACTIVATING_AUTOMATIC'

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def wait_for_removal(self):
        count = 0

        while count < 3:
            if not self.exists():
                count += 1
            else:
                count = 0
            time.sleep(1)

    def wait_for_initial_license_activation(self):
        count = 0
        uri = "/mgmt/cm/device/licensing/pool/initial-activation/{0}".format(self.want.license_key)

        while count < 3:
            response = self.client.get(uri)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['status'] == 'READY':
                count += 1
            elif response['contents']['status'] == 'ACTIVATING_AUTOMATIC_NEED_EULA_ACCEPT':
                uri = urlparse(response['contents']['selfLink']).path

                self.client.patch(uri, data=dict(
                    status='ACTIVATING_AUTOMATIC_EULA_ACCEPTED',
                    eulaText=response['contents']['eulaText']
                ))
            elif response['contents']['status'] == 'ACTIVATION_FAILED':
                raise F5ModuleError(str(response['contents']['message']))
            else:
                count = 0
            time.sleep(1)

    def wait_for_utility_license_activation(self):
        count = 0
        uri = "/mgmt/cm/device/licensing/pool/utility/licenses/{0}".format(self.want.license_key)

        while count < 3:
            response = self.client.get(uri)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['status'] == 'READY':
                count += 1
            elif response['contents']['status'] == 'ACTIVATION_FAILED':
                raise F5ModuleError(str(response['contents']['message']))
            else:
                count = 0
            time.sleep(1)

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/utility/licenses/{0}".format(self.want.license_key)

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            license_key=dict(required=True, no_log=True),
            accept_eula=dict(type='bool'),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['accept_eula']]
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
