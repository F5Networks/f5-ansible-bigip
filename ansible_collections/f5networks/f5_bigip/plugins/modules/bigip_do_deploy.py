#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
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
  task_id:
    description:
      - The ID of the async task as returned by the system in a previous module run.
      - Used to query the status of the task on the device, useful with longer running operations that require
        restarting services.
      - This option is mutually exclusive with C(dry_run).
    type: str
  dry_run:
    description:
      - Set this option to check what changes would be made on device if DO declaration was committed on device.
      - When C(true) the submitted DO declaration in C(content) is checked against existing configuration for any
        changes, with diff returned in results, without making any changes.
      - This option is mutually exclusive with C(task_id), and requires C(content) to be specified.
      - No changes are required in to be made by the user to DO declaration to perform a dry run.
      - While the operation is asynchronous, module does not require re-running to check for task status,
        for longer running tasks which would be with larger DO declarations, it is recommended to increase C(timeout)
        parameter from its default value.
    type: bool
    version_added: "2.0.0"
  timeout:
    description:
      - The amount of time in seconds to wait for the DO async interface to complete its task.
      - The accepted value range is between C(150) and C(3600) seconds.
      - If the device needs to restart the module will return with no change and an appropriate message. In such case,
        it is up to the user to pause task execution until device is ready, see C(EXAMPLES) section.
    type: int
    default: 300
notes:
  - While this module is not idempotent it offers a dry-run option to check for changes in configuration before they
    are committed, see Parameters section for details.
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Start complex declaration with restart
  bigip_do_deploy:
    content: "{{ lookup('file', 'do_provision_restart.json') }}"
  register: task

- name: Check for task that will reboot
  bigip_do_deploy:
    task_id: "{{ task.task_id }}"
  register: result

- name: Wait for 4 minutes if device is restarting services
  pause:
    minutes: 4
  when:
    - result.message == "Device is restarting services, unable to check task status."

- name: Check for task again after restart
  bigip_do_deploy:
    task_id: "{{ task.task_id }}"
  register: repeat
  when:
    - result.message == "Device is restarting services, unable to check task status."

- name: Dry run DO declaration
  bigip_do_deploy:
    content: "{{ lookup('file', 'do_provision.json') }}"
    dry_run: 'yes'
  register: result

- name: Assert Dry run DO declaration
  assert:
    that:
      - result is not changed
      - result is success
      - result.message is search("Dry run completed successfully")
      - result.diff | length > 0
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
  type: str
  sample: "9fe61ef703d0d3192016"
message:
  description: Informative message of the task status.
  returned: always
  type: str
  sample: 'task has been completed'
diff:
  description: Returns the detailed results of a diff from dry run operation.
  returned: when dry_run is yes
  type: list
  sample: [{'foo': 'bar'}, {'baz': 'bar'}]
'''
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import (
    Connection, ConnectionError
)
from ansible.module_utils.six import string_types

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)

try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'content'
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

    @property
    def dry_run(self):
        result = flatten_boolean(self._values['dry_run'])
        if result == 'yes':
            return True
        return False


class Changes(Parameters):
    returnables = [
        'task_id',
        'content',
        'message',
        'diff'
    ]

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:  # pragma: no cover
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

    def _announce_deprecations(self, result):  # pragma: no cover
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
        if self.module.check_mode:  # pragma: no cover
            return True
        if self.want.dry_run:
            return self.dry_run_on_device()
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

    def _set_dry_run_on_declaration(self):
        declaration = {}
        if self.want.content is None:
            raise F5ModuleError(
                "Empty content cannot be specified when 'dry_run' is 'yes'."
            )
        try:
            declaration.update(self.want.content)
        except ValueError:
            raise F5ModuleError(
                "The provided 'content' could not be converted into valid json. If you "
                "are using the 'to_nice_json' filter, please remove it."
            )
        set_dry_run = {
            'async': True,
            'controls': {
                'trace': True,
                'traceResponse': True,
                'dryRun': True
            }
        }
        declaration.update(set_dry_run)
        return declaration

    def _start_dry_run_on_device(self):
        declaration = self._set_dry_run_on_declaration()

        uri = "/mgmt/shared/declarative-onboarding/declare"
        response = self.client.post(uri, data=declaration)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        return response['contents']['id']

    def dry_run_on_device(self):
        delay, period = self.want.timeout
        task_id = self._start_dry_run_on_device()
        task = self.wait_for_task(task_id, delay, period)
        if task and task.get('traces'):
            self.changes.update({'message': 'Dry run completed successfully.'})
            self.changes.update({'diff': task['traces'].get('diff')})
        return False

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

    def _check_task_on_device(self, task):
        uri = "/mgmt/shared/declarative-onboarding/task/{0}".format(task)
        try:
            response = self.client.get(uri)
            if response['code'] == 422:
                errors = self._get_errors_from_response(response['contents'])
                if errors:
                    message = "{0}".format('. '.join(errors))
                    raise F5ModuleError(message)
            return response['code'], response['contents']
        except ConnectionError:
            return 400, None

    def check_task_exists_on_device(self, task):
        uri = "/mgmt/shared/declarative-onboarding/task/{0}".format(task)
        response = self.client.get(uri)
        if response['code'] in [200, 201, 202]:
            return True
        else:
            raise F5ModuleError("The task with the given task_id: {0} does not exist.".format(task))

    def wait_for_task(self, task, delay, period):
        for x in range(0, period):
            code, response = self._check_task_on_device(task)
            if code not in [200, 201, 202]:
                ready = self.device_is_ready()
                if not ready:
                    self.changes.update({'task_id': task})
                    self.changes.update({'message': 'Device is restarting services, unable to check task status.'})
                    return
                else:
                    self.check_task_exists_on_device(task)
                    code, response = self._check_task_on_device(task)
            if code in [200, 201, 202]:
                if response['result']['status'] != 'RUNNING':
                    return response
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def device_is_ready(self):
        uri = "/mgmt/shared/declarative-onboarding/available"
        try:
            response = self.client.get(uri)
            if response['code'] in [200, 201, 202]:
                return True
            return False
        except ConnectionError:
            return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            dry_run=dict(type='bool'),
            task_id=dict(),
            timeout=dict(
                type='int',
                default=300
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['task_id', 'content'],
            ['task_id', 'dry_run']
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


if __name__ == '__main__':  # pragma: no cover
    main()
