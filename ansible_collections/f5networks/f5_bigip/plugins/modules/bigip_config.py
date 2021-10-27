#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_config
short_description: Manage BIG-IP configuration sections
description:
  - Manages a BIG-IP configuration. Allows for merge of SCF formatted files into
    the running configuration.
version_added: "1.0.0"
options:
  save:
    description:
      - The C(save) argument instructs the module to save the
        running-config to startup-config.
    type: bool
    default: no
  reset:
    description:
      - Loads the default configuration on the device.
      - If this option is specified, the default configuration is loaded.
      - On TMOS v14.0.0 and up, resetting to the default configuration resets the admin and user password to the defaults.
        Restarts services, which leads to 503 server errors followed by 401 authorization errors during module
        execution. We recommend changing the C(ansible_httpapi_password) before checking for the reset
        task state.
    type: bool
    default: no
  merge_content:
    description:
      - The file that contains desired configuration to be merged.
      - Loads the specified configuration from a file to merge into
        the running configuration.
    type: path
  verify:
    description:
      - Validates the specified configuration to see whether it is
        valid to replace the running configuration.
      - The running configuration will not be changed.
      - When this parameter is set to C(yes), no change is reported
        by the module.
      - Verifies the operation is synchronous and does not require checking for task completion.
    type: bool
    default: no
  task_id:
    description:
      - The ID of the async task as returned by the system in a previous module run.
      - Used to query the status of the task on the device.
      - When this parameter is set, all other module parameters are ignored.
    type: str
  timeout:
    description:
      - The amount of time to wait for the DO async interface to complete its task, in seconds.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 150
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
    - name: Save the running configuration of the BIG-IP
      bigip_config:
        save: yes
      register: task

    - name: Check for task completion
      bigip_config:
        task_id: "{{ task.task_id }}"
        timeout: 150

    - name: Reset the BIG-IP configuration, for example, to RMA the device
      bigip_config:
        reset: yes
      register: task

    - name: Change connection password after config was reset
      set_fact:
        ansible_httpapi_password: "default"

    - name: Check for reset task completion
      bigip_config:
        task_id: "{{ task.task_id }}"
        timeout: 150

    - name: Save the running configuration of the BIG-IP after reset
      bigip_config:
        save: yes
      register: task

    - name: Check for save config task completion after reset
      bigip_config:
        task_id: "{{ task.task_id }}"
        timeout: 150

    - name: Load an SCF configuration
      bigip_config:
        merge_content: "{{ role_path }}/files/config.scf') }}"
      register: task

    - name: Check for merge config task completion
      bigip_config:
        task_id: "{{ task.task_id }}"
        timeout: 150

    - name: Verify an SCF configuration merge validity
      bigip_config:
        merge_content: "{{ role_path }}/files/config.scf') }}"
        validate: true
'''

RETURN = r'''
task_id:
  description: The task ID returned by the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
message:
  description: Informative message.
  returned: always
  type: dict
  sample: Verification is successful
'''

import os
import tempfile
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
    returnables = ['task_id', 'message']

    @property
    def timeout(self):
        divisor = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 150 and 1800 seconds."
            )

        delay = timeout / divisor

        return delay, divisor

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = Parameters(params=self.module.params)
        self.changes = Parameters()

    def exec_module(self):
        start = datetime.now().isoformat()
        result = {}

        changed = self.execute()

        result.update(**self.changes.to_return())
        result.update(dict(changed=changed))
        send_teem(self.client, start)
        return result

    def execute(self):
        if self.want.task_id:
            return self.check_task()
        if self.want.reset:
            task = self.reset()
            self._start_task_on_device(task)
            self.changes.update({'task_id': task})
            self.changes.update({'message': 'Load config defaults async task started with id: {0}'.format(task)})
            return True
        if self.want.merge_content:
            if self.module.check_mode:
                return True
            if self.want.verify:
                self.verify()
                self.changes.update({'message': 'Validating configuration process succeeded.'})
                return False
            else:
                task = self.merge()
                self._start_task_on_device(task)
                self.changes.update({'task_id': task})
                self.changes.update({'message': 'Merge config async task started with id: {0}'.format(task)})
                return True
        if self.want.save:
            task = self.save()
            self._start_task_on_device(task)
            self.changes.update({'task_id': task})
            self.changes.update({'message': 'Save config async task started with id: {0}'.format(task)})
            return True

    def reset(self):
        if self.module.check_mode:
            return True
        return self.reset_device()

    def check_task(self):
        ready = self.device_is_ready()
        if not ready:
            self.changes.update(
                {'message': 'Device is restarting services, unable to check task status.'}
            )
            return False
        self.async_wait(self.want.task_id)
        return True

    def reset_device(self):
        args = dict(
            command='load',
            options=[{"default": ""}]
        )
        response = self.client.post('/mgmt/tm/task/sys/config', data=args)

        if response['code'] in [200, 201, 202]:
            return response['contents']['_taskId']

        raise F5ModuleError(response['contents'])

    def verify(self):
        temp_name = next(tempfile._get_candidate_names())
        remote_path = "/var/config/rest/downloads/{0}".format(temp_name)
        temp_path = '/tmp/' + temp_name

        if self.module.check_mode:
            return True
        self.upload_to_device(temp_name)
        self.move_on_device(remote_path)
        result = self.verify_on_device(temp_path)
        self.remove_temporary_file(remote_path=temp_path)
        return result

    def merge(self):
        temp_name = next(tempfile._get_candidate_names())
        remote_path = "/var/config/rest/downloads/{0}".format(temp_name)
        temp_path = '/tmp/' + temp_name

        if self.module.check_mode:
            return True

        self.upload_to_device(temp_name)
        self.move_on_device(remote_path)
        task = self.merge_on_device(temp_path)
        return task

    def verify_on_device(self, remote_path):
        args = dict(
            command='load',
            options=[{"file": remote_path, "merge": "", "verify": ""}]
        )

        response = self.client.post('/mgmt/tm/sys/config', data=args)

        if response['code'] in [200, 201, 202]:
            return True

        raise F5ModuleError(response['contents'])

    def merge_on_device(self, remote_path):
        args = dict(
            command='load',
            options=[{"file": remote_path, "merge": ""}]
        )

        response = self.client.post('/mgmt/tm/task/sys/config', data=args)

        if response['code'] in [200, 201, 202]:
            return response['contents']['_taskId']

        raise F5ModuleError(response['contents'])

    def remove_temporary_file(self, remote_path):
        args = dict(
            command='run',
            utilCmdArgs=remote_path
        )
        response = self.client.post('/mgmt/tm/util/unix-rm', data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def move_on_device(self, remote_path):
        args = dict(
            command='run',
            utilCmdArgs='{0} /tmp/{1}'.format(
                remote_path, os.path.basename(remote_path)
            )
        )
        response = self.client.post('/mgmt/tm/util/unix-mv', data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def upload_to_device(self, temp_name):
        try:
            self.client.plugin.upload_file("/mgmt/shared/file-transfer/uploads", self.want.merge_content, temp_name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def save(self):
        if self.module.check_mode:
            return True
        return self.save_on_device()

    def save_on_device(self):
        args = dict(
            command='save'
        )
        response = self.client.post('/mgmt/tm/task/sys/config', data=args)
        if response['code'] in [200, 201, 202]:
            return response['contents']['_taskId']
        raise F5ModuleError(response['contents'])

    def _start_task_on_device(self, task):
        payload = {"_taskState": "VALIDATING"}
        uri = "/mgmt/tm/task/sys/config/{0}".format(task)
        response = self.client.put(uri, data=payload)

        if response['code'] in [200, 201, 202]:
            return True

        raise F5ModuleError(response['contents'])

    def check_task_exists_on_device(self, task):
        uri = "/mgmt/tm/task/sys/config/{0}".format(task)
        response = self.client.get(uri)
        if response['code'] in [200, 201, 202]:
            return True
        else:
            raise F5ModuleError("The task with the given task_id: {0} does not exist.".format(task))

    def async_wait(self, task):
        self.check_task_exists_on_device(task)
        delay, period = self.want.timeout
        uri = "/mgmt/tm/task/sys/config/{0}/result".format(task)
        for x in range(0, period):
            response = self.client.get(uri)
            if response['code'] in [200, 201, 202]:
                if response['contents']['_taskState'] == 'FAILED':
                    raise F5ModuleError("Task failed unexpectedly.")
                if response['contents']['_taskState'] == 'COMPLETED':
                    self.changes.update({'message': 'Task completed successfully.'})
                    return True
            if response['code'] not in [200, 201, 202]:
                if not self.device_is_ready():
                    self.changes.update(
                        {'message': 'Device is restarting services, unable to check task status.'}
                    )
                    return False
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def device_is_ready(self):
        uri = "/mgmt/tm/sys/available"
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
            reset=dict(
                type='bool',
                default=False
            ),
            merge_content=dict(type='path'),
            task_id=dict(),
            timeout=dict(
                type='int',
                default=150
            ),
            verify=dict(
                type='bool',
                default=False
            ),
            save=dict(
                type='bool',
                default=False
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
