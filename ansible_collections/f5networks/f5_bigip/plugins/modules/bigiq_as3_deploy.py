#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigiq_as3_deploy
short_description: Manages AS3 declarations sent to BIG-IQ
description:
  - Manages AS3 declarations sent to BIG-IQ.
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
  bigip_device:
    description:
      - The BIG-IP device on which to remove the declaration.
      - Parameter required when C(state) is absent, it is otherwise ignored.
    type: str
  tenant:
    description:
      - An AS3 tenant you wish to remove.
      - Parameter required when C(state) is absent, it is otherwise ignored.
    type: str
  timeout:
    description:
      - The amount of time in seconds to wait for the AS3 async interface to complete its task.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the declaration is exists.
      - When C(state) is C(absent), ensures that the declaration is removed.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - Due to limitations of the AS3 package on BIG-IQ, the module is not idempotent.
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
    - name: Declaration with 2 Tenants - AS3
      bigiq_as3_deploy:
        content: "{{ lookup('file', 'two_tenants.json') }}"
        service_type: "as3"
'''

RETURN = r'''
content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
tenant:
  description: The AS3 tenant to be managed.
  returned: changed
  type: str
  sample: foobar1
'''
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import string_types

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)

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

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 10 and 1800 seconds."
            )
        if timeout > 99:
            divisor = 100
        delay = timeout / divisor

        return delay, divisor


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
            changed = self.upsert()
        elif state == "absent":
            changed = self.remove_on_device()

        result.update(dict(changed=changed))
        send_teem(self.client, start)
        return result

    def upsert(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.upsert_on_device()
        return result

    def remove(self):
        return self.remove_on_device()

    def _get_errors_from_response(self, messages):
        results = []
        if 'results' not in messages:
            if 'message' in messages:
                results.append(messages['message'])
            if 'errors' in messages:
                results += messages['errors']
        else:
            for message in messages['results']:
                if 'message' in message and message['message'] in ['declaration failed', 'declaration is invalid']:
                    results.append(message['message'])
                if 'errors' in message:
                    results += message['errors']
        return results

    def _check_task_on_device(self, path):
        response = self.client.get(path)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']

    def upsert_on_device(self):
        delay, period = self.want.timeout
        if self.want.tenant:
            uri = "/mgmt/shared/appsvcs/declare/{0}?async=true".format(self.want.tenant)
        else:
            uri = "/mgmt/shared/appsvcs/declare?async=true"

        response = self.client.post(uri, data=self.want.content)
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/appsvcs/task/{0}".format(response['contents']['id']), delay, period)
        if task:
            return any(msg.get('message', None) != 'no change' for msg in task['results'])
        return False

    def wait_for_task(self, path, delay, period):
        for x in range(0, period):
            task = self._check_task_on_device(path)
            errors = self._get_errors_from_response(task)
            if errors:
                message = "{0}".format('. '.join(errors))
                raise F5ModuleError(message)
            if any(msg.get('message', None) != 'in progress' for msg in task['results']):
                return task
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def remove_on_device(self):
        delay, period = self.want.timeout
        payload = {
            "class": "AS3",
            "declaration": {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id": "fghijkl7890",
                "label": "Sample 1",
                "remark": "HTTP with custom persistence",
                'target': {
                    'address': str(self.want.bigip_device)
                },
                str(self.want.tenant): {
                    'class': 'Tenant'
                }
            }
        }

        uri = "/mgmt/shared/appsvcs/declare?async=true"

        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/appsvcs/task/{0}".format(response['contents']['id']), delay, period)
        if task:
            return any(msg.get('message', None) != 'no change' for msg in task['results'])
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            tenant=dict(),
            bigip_device=dict(),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'absent', ['tenant', 'bigip_device']]
        ]


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
