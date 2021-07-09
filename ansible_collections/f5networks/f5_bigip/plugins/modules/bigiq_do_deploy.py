#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigiq_do_deploy
short_description: Manages DO declarations sent to BIG-IQ
description:
  - Manages DO declarations sent to BIG-IQ.
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
  task_id:
    description:
      - The ID of the async task as returned by the system in a previous module run.
      - Used to query the status of the task on the device, useful with longer running operations that require
        restarting services.
    type: str
  timeout:
    description:
      - The amount of time in seconds to wait for the DO async interface to complete its task.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
notes:
  - Due to limitations of the DO package, the module is not idempotent.
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
    - name: Start simple declaration task
      bigip_do_deploy:
        content: "{{ lookup('file', 'do_bigiq_declaration.json') }}"
      register: task

    - name: Check for simple declaration status
      bigiq_do_deploy:
        task_id: result.task_id
        timeout: 1000
'''

RETURN = r'''
content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
task_id:
  description: The task ID returned by the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
message:
  description: Informative message of the task status.
  returned: changed
  type: dict
  sample: hash/dictionary of values
'''
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types

from ansible.module_utils.connection import Connection

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
        divisor = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / divisor

        return delay, divisor


class Changes(Parameters):
    returnables = [
        'task_id',
        'content',
        'message',
    ]

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
        result = dict()

        changed = self.upsert()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def upsert(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.want.task_id:
            return self.query_task()
        task = self.upsert_on_device()
        self.changes.update({'task_id': task})
        self.changes.update({'message': 'DO async task started with id: {0}'.format(task)})
        return True

    def _get_errors_from_response(self, message):
        results = []
        if 'message' in message and message['message'] == 'invalid config - rolled back':
            results.append(message['message'])
        if 'errors' in message:
            results += message['errors']
        return results

    def upsert_on_device(self):
        uri = "/mgmt/shared/declarative-onboarding/declare"
        response = self.client.post(uri, data=self.want.content)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        return response['contents']['id']

    def query_task(self):
        delay, period = self.want.timeout
        task = self.wait_for_task(self.want.task_id, delay, period)
        if task:
            if 'message' in task['result'] and task['result']['message'] == 'success':
                return True
        return False

    def async_wait(self, task_id):
        delay, period = self.want.timeout
        task = self.wait_for_task(task_id, delay, period)
        if task:
            if 'message' in task['result'] and task['result']['message'] == 'success':
                return True
            return False
        return False

    def _check_task_on_device(self, task):
        uri = "/mgmt/shared/declarative-onboarding/task/{0}".format(task)
        response = self.client.get(uri)
        if response['code'] in [422, 424]:
            errors = self._get_errors_from_response(response['contents'])
            if errors:
                message = "{0}".format('. '.join(errors))
                raise F5ModuleError(message)
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        return response['code'], response['contents']

    def wait_for_task(self, task, delay, period):
        for x in range(0, period):
            code, response = self._check_task_on_device(task)
            if code in [200, 201, 202]:
                if response['result']['status'] != 'RUNNING':
                    return response
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            task_id=dict(),
            timeout=dict(
                type='int',
                default=300
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['task_id', 'content']
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
