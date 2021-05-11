#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_ts_deploy
short_description: Manages TS declarations sent to BIG-IP
description:
  - Manages TS declarations sent to BIG-IP.
version_added: "1.0.0"
options:
  content:
    description:
      - Declaration to be configured on the system.
      - This parameter is most often used along with the C(file) or C(template) lookup plugins.
        Refer to the examples section for correct usage.
      - For anything advanced or with formatting consider using the C(template) lookup.
      - This can additionally be used for specifying application service configurations
        directly in YAML, however that is not an encouraged practice and, if used at all,
        should only be used for the absolute smallest of configurations to prevent your
        Playbooks from becoming too large.
      - If you C(content) includes encrypted values (such as ciphertexts, passphrases, etc),
        the returned C(changed) value will always be true.
      - If you are using the C(to_nice_json) filter, it will cause this module to fail because
        the purpose of that filter is to format the JSON to be human-readable and this process
        includes inserting "extra characters that break JSON validators.
    type: raw
  force:
    description:
      - If C(yes), the declaration is uploaded regardless if there is a change or not, option is useful when changing
        declaration's C(cipherText) key/pair.
      - If C(no), the declaration is only uploaded if there is a difference to what is on the device. The comparison is
        not performed on declaration's C(cipherText) key/pair as the paraphrases returned by device are encrypted.
    type: bool
    default: no
  state:
    description:
      - When C(state) is C(present), ensures the declaration is exists.
      - When C(state) is C(absent), ensures that the declaration is removed.
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
    - name: Declaration with 2 Tenants - AS3
      bigip_ts_deploy:
        content: "{{ lookup('file', 'ts_declaration.json') }}"

    - name: Upload declaration - force yes
      bigip_ts_deploy:
        content: "{{ lookup('file', 'ts_declaration.json') }}"
        force: yes
'''

RETURN = r'''
content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
'''

from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import string_types

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)
from ..module_utils.compare import nested_diff

try:
    import json
except ImportError:
    import simplejson as json


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'content',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def content(self):
        if self._values['content'] is None:
            return None
        if isinstance(self._values['content'], string_types):
            return json.loads(self._values['content'] or 'null')
        else:
            return self._values['content']


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


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

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
        start = datetime.now().isoformat()
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.module.check_mode:
            return True
        if self.exists():
            return self.remove_from_device()
        return False

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        return self.upsert_on_device()

    def update(self):
        if self.want.force:
            self._set_changed_options()
            if self.module.check_mode:
                return True
            return self.upsert_on_device()
        if self.needs_change():
            self._set_changed_options()
            if self.module.check_mode:
                return True
            return self.upsert_on_device()
        return False

    def needs_change(self):
        have = self.read_from_device()
        if nested_diff(self.want.content, have, ['cipherText']):
            return True
        return False

    def exists(self):
        have = self.read_from_device()
        if have is None:
            return False
        if len(have) == 2 and all(key in have for key in ['class', 'schemaVersion']):
            return False
        return True

    def read_from_device(self):
        uri = "/mgmt/shared/telemetry/declare"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['message'] == 'success':
            if 'declaration' in response['contents']:
                return response['contents']['declaration']
        return None

    def upsert_on_device(self):
        uri = "/mgmt/shared/telemetry/declare"
        response = self.client.post(uri, data=self.want.content)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['message'] == 'success':
            return True
        return False

    def remove_from_device(self):
        payload = {'class': 'Telemetry'}
        uri = "/mgmt/shared/telemetry/declare"
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['message'] == 'success':
            return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            force=dict(
                default='no',
                type='bool'
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['content']]
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
