#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_as3_deploy
short_description: Manages AS3 declarations sent to BIG-IP
description:
  - Manages AS3 declarations sent to the BIG-IP.
version_added: "1.0.0"
options:
  content:
    description:
      - The declaration to be configured on the system.
      - This parameter is most often used with the C(file) or C(template) lookup plugins.
        Refer to the examples section for correct usage.
      - For anything advanced or with formatting, consider using the C(template) lookup.
      - Additionally, this can be used for specifying application service configurations
        directly in YAML. However that is not an encouraged practice and, if used at all,
        should only be used for the absolute smallest of configurations to prevent your
        Playbooks from becoming too large.
      - If your C(content) includes encrypted values (such as ciphertexts, passphrases, etc),
        the returned C(changed) value will always be true.
      - If you are using the C(to_nice_json) filter, it causes this module to fail because
        the purpose of that filter is to format the JSON to be human-readable and this process
        includes inserting extra characters that break JSON validators.
    type: raw
  tenant:
    description:
      - An AS3 tenant you want to manage.
      - A value of C(all) when C(state) is C(absent) removes all AS3 declarations from the device.
    type: str
  timeout:
    description:
      - The amount of time to wait for the AS3 async interface to complete its task, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the declaration is exists.
      - When C(state) is C(absent), ensures the declaration is removed.
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
      bigip_as3_deploy:
        content: "{{ lookup('file', 'two_tenants.json') }}"

    - name: Remove one tenant - AS3
      bigip_as3_deploy:
        as3_tenant: "Sample_01"
        state: absent
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
        'tenant',
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
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        result.update(dict(changed=changed))
        send_teem(self.client, start)
        return result

    def upsert(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.upsert_on_device()
        return result

    def present(self):
        if self.exists():
            return False
        return self.upsert()

    def absent(self):
        if self.resource_exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        result = self.remove_from_device()
        if self.resource_exists():
            raise F5ModuleError("Failed to delete the resource.")
        return result

    def exists(self):
        declaration = {}
        if self.want.content is None:
            raise F5ModuleError(
                "Empty content cannot be specified when 'state' is 'present'."
            )
        try:
            declaration.update(self.want.content)
        except ValueError:
            raise F5ModuleError(
                "The provided 'content' could not be converted into valid json. If you "
                "are using the 'to_nice_json' filter, please remove it."
            )
        declaration['action'] = 'dry-run'

        if self.want.tenant:
            uri = "/mgmt/shared/appsvcs/declare/{0}".format(self.want.tenant)
        else:
            uri = "/mgmt/shared/appsvcs/declare"

        response = self.client.post(uri, data=declaration)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        return all(msg.get('message', None) == 'no change' for msg in response['contents']['results'])

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
                if 'response' in message:
                    results.append(message['response'])
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

    def resource_exists(self):
        if self.want.tenant != 'all':
            uri = "/mgmt/shared/appsvcs/declare/{0}".format(self.want.tenant)
        else:
            uri = "/mgmt/shared/appsvcs/declare"

        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] == 204:
            return False
        return True

    def remove_from_device(self):
        delay, period = self.want.timeout
        if self.want.tenant == 'all':
            uri = "/mgmt/shared/appsvcs/declare?async=true"
        else:
            uri = "/mgmt/shared/appsvcs/declare/{0}?async=true".format(self.want.tenant)

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/appsvcs/task/{0}".format(response['contents']['id']), delay, period)
        if task:
            return any(msg.get('message', None) != 'no change' for msg in task['results'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            tenant=dict(),
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
            ['state', 'present', ['content']],
            ['state', 'absent', ['tenant']]
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
