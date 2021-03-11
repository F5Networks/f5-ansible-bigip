#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_do_deploy
short_description: Manages DO declarations sent to BIG-IP
description:
  - Manages DO declarations sent to BIG-IP.
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
  timeout:
    description:
      - The amount of time in seconds to wait for the DO async interface to complete its task.
      - The accepted value range is between C(300) and C(3600) seconds.
      - If the device needs to restart the defined timeout will be extended.
      - The hard timeout to wait for device reboot is 1800 seconds.
    type: int
    default: 150
notes:
  - Due to limitations of the DO package, the module is not idempotent.
extends_documentation_fragment: f5networks.f5_bigip.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- hosts: all
  collections:
    - f5networks.f5_bigip
  connection: local

  environment:
    F5_SERVER: "{{ ansible_host }}"
    F5_USER: "{{ ansible_user }}"
    F5_PASSWORD: "{{ ansible_httpapi_password }}"
    F5_SERVER_PORT: "{{ ansible_httpapi_port }}"
    F5_VALIDATE_CERTS: "{{ ansible_httpapi_validate_certs }}"

  tasks:
    - name: Simple declaration no restart
      bigip_do_deploy:
        content: "{{ lookup('file', 'do_simple_no_restart.json') }}"
'''

RETURN = r'''

content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values

'''
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types

from ..module_utils.bigip_local import F5RestClient
from ..module_utils.local import f5_argument_spec
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
        self.client = F5RestClient(**self.module.params)
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
        result = dict()

        changed = self.upsert()

        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def upsert(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        task = self.upsert_on_device()
        result = self.async_wait(task)
        return result

    def _get_errors_from_response(self, message):
        results = []
        if 'message' in message and message['message'] == 'invalid config - rolled back':
            results.append(message['message'])
        if 'errors' in message:
            results += message['errors']
        return results

    def upsert_on_device(self):
        uri = "https://{0}:{1}/mgmt/shared/declarative-onboarding/declare".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=self.want.content)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
            raise F5ModuleError(resp.content)
        return response['id']

    def async_wait(self, task_id):
        delay, period = self.want.timeout
        task = self.wait_for_task(task_id, delay, period)
        if task:
            if 'message' in task['result'] and task['result']['message'] == 'success':
                return True
            return False
        return False

    def _check_task_on_device(self, task):
        uri = "https://{0}:{1}/mgmt/shared/declarative-onboarding/task/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            task
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 422:
            errors = self._get_errors_from_response(response)
            if errors:
                message = "{0}".format('. '.join(errors))
                raise F5ModuleError(message)

        return resp.status, response

    def wait_for_task(self, task, delay, period):
        for x in range(0, period):
            code, response = self._check_task_on_device(task)
            if code not in [200, 201, 202]:
                ready = self.wait_for_device_reboot()
                if ready:
                    code, response = self._check_task_on_device(task)
            if code in [200, 201, 202]:
                if response['result']['status'] != 'RUNNING':
                    return response
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _check_if_device_is_ready(self):
        uri = "https://{0}:{1}/mgmt/shared/declarative-onboarding/available".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
            raise F5ModuleError(resp.content)

        return True

    def wait_for_device_reboot(self):
        for x in range(0, 360):
            time.sleep(5)
            try:
                self.client.reconnect()
                ready = self._check_if_device_is_ready()
                if ready is True:
                    return ready
            except F5ModuleError:
                # Handle all exceptions because if the system is offline (for a
                # reboot) the REST client will raise exceptions about
                # connections
                pass
        raise F5ModuleError('Reboot wait timeout limit exceeded 1800 seconds.')


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            timeout=dict(
                type='int',
                default=150
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
