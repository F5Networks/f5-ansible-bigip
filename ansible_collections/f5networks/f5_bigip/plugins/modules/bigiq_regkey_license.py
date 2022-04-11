#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigiq_regkey_license
short_description: Manages licenses in a BIG-IQ registration key pool
description:
  - Manages licenses in a BIG-IQ registration key pool.
version_added: "1.0.0"
options:
  regkey_pool:
    description:
      - The registration key pool in which you want to place the license.
      - You must give your registration pools unique names. While
        BIG-IQ does not require this, this module does. If you do not,
        the behavior of the module is undefined and you may end up putting
        licenses in the wrong registration key pool.
    type: str
    required: True
  license_key:
    description:
      - The license key to put in the pool.
    type: str
    required: True
  addon_keys:
    description:
      - The addon keys to put in the pool.
    type: list
    elements: str
    version_added: "1.7.0"
  description:
    description:
      - Description of the license.
    type: str
  accept_eula:
    description:
      - A key that signifies you accept the F5 EULA for this license.
      - A copy of the EULA can be found here https://askf5.f5.com/csp/article/K12902
      - This is required when C(state) is C(present).
    type: bool
  state:
    description:
      - The state of the regkey license in the pool on the system.
      - When C(present), guarantees the license exists in the pool.
      - When C(absent), removes the license from the pool.
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
    - name: Add a registration key license to a pool
      bigiq_regkey_license:
        regkey_pool: foo-pool
        license_key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        accept_eula: yes

    - name: Add a registration key license with addon keys to a pool
      bigiq_regkey_license:
        regkey_pool: foo-pool
        license_key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        addon_keys:
          - YYYY-YYY-YYY
          - ZZZZ-ZZZ-ZZZ
        accept_eula: yes

    - name: Remove a registration key license from a pool
      bigiq_regkey_license:
        regkey_pool: foo-pool
        license_key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        state: absent
'''

RETURN = r'''
description:
  description: The new description of the license key.
  returned: changed
  type: str
  sample: My license for BIG-IP 1
'''

import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'regKey': 'license_key',
        'addOnKeys': 'addon_keys'
    }

    api_attributes = [
        'regKey', 'description', 'addOnKeys'
    ]

    returnables = [
        'description'
    ]

    updatables = [
        'description'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def regkey_pool_uuid(self):
        if self._values['regkey_pool_uuid']:
            return self._values['regkey_pool_uuid']
        collection = self.read_current_from_device()
        resource = next((x for x in collection if x.name == self.regkey_pool), None)
        if resource is None:
            raise F5ModuleError("Could not find the specified regkey pool.")
        self._values['regkey_pool_uuid'] = resource.id
        return resource.id

    def read_current_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' not in response['contents']:
            return []
        result = [ApiParameters(params=r) for r in response['contents']['items']]
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


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(client=self.client, params=self.module.params)
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
            return self.update()
        else:
            return self.create()

    def exists(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}/offerings/{1}".format(
            self.want.regkey_pool_uuid,
            self.want.license_key
        )
        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

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
        if self.want.accept_eula is False:
            raise F5ModuleError(
                "To add a license, you must accept its EULA. Please see the module documentation for a link to this."
            )
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.want.api_params()
        params['name'] = self.want.name
        params['status'] = 'ACTIVATING_AUTOMATIC'
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}/offerings".format(
            self.want.regkey_pool_uuid,
        )
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        for x in range(60):
            resource = self.read_current_from_device()
            if resource.status == 'READY':
                break
            elif resource.status == 'ACTIVATING_AUTOMATIC_NEED_EULA_ACCEPT':
                params = dict(
                    status='ACTIVATING_AUTOMATIC_EULA_ACCEPTED',
                    eulaText=resource.eulaText
                )
                uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}/offerings/{1}".format(
                    self.want.regkey_pool_uuid,
                    self.want.license_key
                )
                response = self.client.patch(uri, data=params)

                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])

            elif resource.status == 'ACTIVATION_FAILED':
                raise F5ModuleError(str(resource.message))

            time.sleep(1)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}/offerings/{1}".format(
            self.want.regkey_pool_uuid,
            self.want.license_key
        )
        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}/offerings/{1}".format(
            self.want.regkey_pool_uuid,
            self.want.license_key
        )
        response = self.client.delete(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}/offerings/{1}".format(
            self.want.regkey_pool_uuid,
            self.want.license_key
        )
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            regkey_pool=dict(required=True),
            license_key=dict(required=True, no_log=True),
            addon_keys=dict(type='list', elements='str', no_log=True),
            description=dict(),
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
        required_if=spec.required_if,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
