#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_partition_change_password
short_description: Provides access to VELOS chassis partition user authentication methods
description:
  - Provides access to VELOS chassis partition user authentication change password methods.
version_added: "1.3.0"
options:
  user_name:
    description:
      - Name of the chassis partition user account.
    type: str
    required: True
  old_password:
    description:
      - Current password for the specified user account.
    type: str
    required: True
  new_password:
    description:
      - New password for the specified user account.
    type: str
    required: True
notes:
  - This module is not idempotent.
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
    ansible_network_os: f5networks.f5_bigip.velos
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Change password on partition
      velos_partition_change_password:
        user_name: foo
        old_password: admin
        new_password: abc123!@
'''

RETURN = r'''
# only common fields returned
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'old-password': 'old_password',
        'new-password': 'new_password',
        'confirm-password': 'confirm_pass',
    }

    api_attributes = [
        'old-password',
        'new-password',
        'confirm-password',
    ]

    returnables = [
        'old_password',
        'new_password',
        'confirm_pass',
    ]

    updatables = [

    ]


class ModuleParameters(Parameters):
    @property
    def confirm_pass(self):
        return self.new_password

    # We are enforcing the below as the VELOS api will return 400 error, when the passwords are the same,
    # without useful error message which will be confusing to the user

    @property
    def new_password(self):
        if self._values['old_password'] == self._values['new_password']:
            raise F5ModuleError("Old and new password cannot be the same.")
        return self._values['new_password']

    @property
    def old_password(self):
        if self._values['old_password'] == self._values['new_password']:
            raise F5ModuleError("Old and new password cannot be the same.")
        return self._values['old_password']


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
    returnables = []


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.scope = "/restconf/operations/openconfig-system:system/aaa"

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        result = dict()

        changed = self.execute()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def execute(self):
        self._set_changed_options()
        result = self.change_password_on_device()
        return result

    def change_password_on_device(self):
        params = self.changes.api_params()

        uri = f"/authentication/users/user={self.want.user_name}/config/change-password"

        response = self.client.post(uri, data=dict(input=[params]), scope=self.scope)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            user_name=dict(required=True),
            old_password=dict(required=True, no_log=True),
            new_password=dict(required=True, no_log=True)
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
