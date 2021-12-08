#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ucs
short_description: Manage upload, installation, and removal of UCS files
description:
   - Manage upload, installation, and removal of UCS files on a BIG-IP system.
     A user configuration set (UCS) is a backup file that contains BIG-IP configuration
     data that can be used to fully restore a BIG-IP system in the event of a
     failure or RMA replacement.
version_added: "1.0.0"
options:
  include_chassis_level_config:
    description:
      - During restoration of the UCS file, includes chassis level configuration
        that is shared among boot volume sets. For example, the cluster default
        configuration.
    type: bool
  ucs:
    description:
      - The path to the UCS file to install. This parameter must be
        provided if the C(state) is either C(installed) or C(activated).
        When C(state) is C(absent), the full path for this parameter is
        ignored and only the filename is used to select a UCS for removal.
        Therefore you could specify C(/foo/bar/test.ucs) and this module
        would only look for C(test.ucs).
    type: str
    required: True
  force:
    description:
      - If C(yes), the system uploads the file every time and replaces the file on the
        device. If C(no), the file is only uploaded if it does not already
        exist. Generally it should only be C(yes) in cases where you believe
        the image was corrupted during upload.
    type: bool
    default: no
  no_license:
    description:
      - Performs a full restore of the UCS file and all the files it contains,
        with the exception of the license file. This option must be used to
        restore a UCS on RMA (Returned Materials Authorization) devices.
    type: bool
  no_platform_check:
    description:
      - Bypasses the platform check and allows installation of a UCS that was
        created using a different platform. By default (without this option),
        installation of a UCS created from a different platform is not allowed.
    type: bool
  passphrase:
    description:
      - Specifies the passphrase necessary to load the specified UCS file.
    type: str
  reset_trust:
    description:
      - When specified, the device and trust domain certificates and keys are not
        loaded from the UCS. Instead, a new set is generated.
    type: bool
  state:
    description:
      - When C(installed), ensures the UCS is uploaded and installed
        on the system. When C(present), ensures the UCS is uploaded.
        When C(absent), the UCS is removed from the system. When
        C(installed), the uploading of the UCS is idempotent, however the
        installation of that configuration is not idempotent.
    type: str
    choices:
      - absent
      - installed
      - present
    default: present
  task_id:
    description:
      - The ID of the async task as returned by the system in a previous module run.
      - Used to query the status of the task on the device, useful with longer running operations that require
        restarting services.
      - This parameter is only usable when C(state) is C(installed)
      - This parameter assumes a load ucs task has been started ond device,
        therefore it does not check for existence of the UCS file beforehand.
      - Adding this parameter incorrectly to a module run leads to confusing error messages. Refer to the examples
        section for correct usage of this parameter.
    type: str
    version_added: "1.4.0"
  timeout:
    description:
      - This parameter is used when installing uploaded UCS file on the device.
      - The amount of time to wait for the API async interface to complete its task, in seconds.
      - The accepted value range is between C(150) and C(1800) seconds.
    type: int
    default: 150
    version_added: "1.4.0"
notes:
   - Only the most basic checks are performed by this module. Other checks and
     considerations need to be taken into account. See
     https://support.f5.com/kb/en-us/solutions/public/11000/300/sol11318.html
   - This module does not handle devices with the FIPS 140 HSM.
   - This module does not handle BIG-IPs systems on the 6400, 6800, 8400, or
     8800 hardware platforms.
   - This module does not verify the new or replaced SSH keys from the
     UCS file are synchronized between the BIG-IP system and the SCCP.
   - This module does not support the 'rma' option.
   - This module does not support restoring a UCS archive on a BIG-IP 1500,
     3400, 4100, 6400, 6800, or 8400 hardware platforms other than the system
     from which the backup was created.
   - The UCS restore operation restores the full configuration only if the
     hostname of the target system matches the hostname on which the UCS
     archive was created. If the hostname does not match, only the shared
     configuration is restored.
   - This module does not support re-licensing a BIG-IP restored from a UCS.
   - This module does not support restoring encrypted archives on replacement
     RMA unit.
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
    - name: Upload UCS
      bigip_ucs:
        ucs: /root/bigip.localhost.localdomain.ucs
        state: present

    - name: Install (upload, install) UCS - start task
      bigip_ucs:
        ucs: /root/bigip.localhost.localdomain.ucs
        state: installed
        register: task

    - name: Install (upload, install) UCS - check task
      bigip_ucs:
        ucs: "{{ task.ucs }}"
        task_id: "{{ task.task_id }}"
        timeout: 300

    - name: Install (upload, install) UCS without installing the license portion - start task
      bigip_ucs:
        ucs: /root/bigip.localhost.localdomain.ucs
        no_license: yes
        state: installed
        register: task

    - name: Install (upload, install) UCS without installing the license portion - check task
      bigip_ucs:
        ucs: "{{ task.ucs }}"
        task_id: "{{ task.task_id }}"
        timeout: 300

    - name: Install (upload, install) UCS except the license, and bypassing the platform check - start task
      bigip_ucs:
        ucs: /root/bigip.localhost.localdomain.ucs
        no_license: yes
        no_platform_check: yes
        state: installed
        register: task

    - name: Install (upload, install) UCS except the license, and bypassing the platform check - check task
      bigip_ucs:
        ucs: "{{ task.ucs }}"
        task_id: "{{ task.task_id }}"
        timeout: 300

    - name: Install (upload, install) UCS using a passphrase necessary to load the UCS - start task
      bigip_ucs:
        ucs: /root/bigip.localhost.localdomain.ucs
        passphrase: MyPassphrase1234
        state: installed
        register: task

    - name: Install (upload, install) UCS using a passphrase necessary to load the UCS - check task
      bigip_ucs:
        ucs: "{{ task.ucs }}"
        task_id: "{{ task.task_id }}"
        timeout: 300

    - name: Remove uploaded UCS file
      bigip_ucs:
        ucs: bigip.localhost.localdomain.ucs
        state: absent
'''

RETURN = r'''
# only common fields returned
'''
import os
import re
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection, ConnectionError

from ..module_utils.client import (
    F5Client, send_teem
)

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    updatables = []
    returnables = [
        'ucs',
        'task_id',
        'message'
    ]
    api_attributes = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    def _check_required_if(self, parameter):
        if self._values[parameter] is not True:
            return self._values[parameter]
        if self.state != 'installed':
            raise F5ModuleError(
                '"{0}" parameters requires "installed" state'.format(parameter)
            )

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
    def basename(self):
        return os.path.basename(self.ucs)

    @property
    def options(self):
        tmp = {
            'include-chassis-level-config': self.include_chassis_level_config,
            'no-license': self.no_license,
            'no-platform-check': self.no_platform_check,
            'passphrase': self.passphrase,
            'reset-trust': self.reset_trust
        }
        result = self._filter_params(tmp)
        if result:
            return result

    @property
    def reset_trust(self):
        self._check_required_if('reset_trust')
        result = flatten_boolean(self._values['reset_trust'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def passphrase(self):
        self._check_required_if('passphrase')
        return self._values['passphrase']

    @property
    def no_platform_check(self):
        self._check_required_if('no_platform_check')
        result = flatten_boolean(self._values['no_platform_check'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def no_license(self):
        self._check_required_if('no_license')
        result = flatten_boolean(self._values['no_license'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def include_chassis_level_config(self):
        self._check_required_if('include_chassis_level_config')
        result = flatten_boolean(self._values['include_chassis_level_config'])
        if result == 'yes':
            return True
        if result == 'no':
            return False


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


class ReportableChanges(Changes):
    pass


class UsableChanges(Changes):
    pass


class Difference(object):
    pass


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

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

        if state in ['present', 'installed']:
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

    def present(self):
        if self.want.task_id:
            self.device_is_ready()
            self.async_wait(self.want.task_id)
            self.changes.update({'message': 'UCS loaded successfully'})
            return True
        if self.exists():
            return self.update()
        else:
            return self.create()

    def update(self):
        if self.module.check_mode:
            if self.want.force:
                return True
            return False
        elif self.want.force:
            self.remove()
            return self.create()
        elif self.want.state == 'installed':
            task = self.install_on_device()
            self._start_task_on_device(task)
            self.changes.update({'task_id': task})
            self.changes.update({'ucs': self.want.basename})
            self.changes.update({'message': 'UCS load async task started with id: {0}'.format(task)})
            return True
        else:
            return False

    def create(self):
        if self.module.check_mode:
            return True
        self.create_on_device()
        if not self.exists():
            raise F5ModuleError("Failed to upload the UCS file.")
        if self.want.state == 'installed':
            task = self.install_on_device()
            self._start_task_on_device(task)
            self.changes.update({'task_id': task})
            self.changes.update({'ucs': self.want.basename})
            self.changes.update({'message': 'UCS load async task started with id: {0}'.format(task)})
        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the UCS file.")
        return True

    def exists(self):
        collection = self.read_current_from_device()
        if self.want.basename in collection:
            return True
        return False

    def create_on_device(self):
        remote_path = "/var/local/ucs"
        tpath_name = '/var/config/rest/downloads'
        self.upload_file_to_device(self.want.ucs, self.want.basename)

        uri = "/mgmt/tm/util/unix-mv/"
        args = dict(
            command='run',
            utilCmdArgs='{0}/{2} {1}/{2}'.format(
                tpath_name, remote_path, self.want.basename
            )
        )
        response = self.client.post(uri, data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        params = dict(command="run",
                      utilCmdArgs='-c "tmsh delete sys ucs {0}"'.format(self.want.basename)
                      )
        uri = "/mgmt/tm/util/bash"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' in response['contents']:
            if '{0} is deleted'.format(self.want.basename) in response['contents']['commandResult']:
                return True
        return False

    def install_on_device(self):
        if self.want.options:
            params = dict(
                command="load",
                name=self.want.basename,
                options=[self.want.options]
            )
        else:
            params = dict(
                command="load",
                name=self.want.basename
            )
        uri = "/mgmt/tm/task/sys/ucs"

        response = self.client.post(uri, data=params)

        if response['code'] in [200, 201, 202]:
            return response['contents']['_taskId']

        raise F5ModuleError(response['contents'])

    def _start_task_on_device(self, task):
        payload = {"_taskState": "VALIDATING"}
        uri = "/mgmt/tm/task/sys/ucs/{0}".format(task)
        response = self.client.put(uri, data=payload)

        if response['code'] in [200, 201, 202]:
            return True

        raise F5ModuleError(response['contents'])

    def check_task_exists_on_device(self, task):
        uri = "/mgmt/tm/task/sys/ucs/{0}".format(task)
        response = self.client.get(uri)
        if response['code'] in [200, 201, 202]:
            return True
        if response['code'] == 404:
            return False
        raise F5ModuleError(response['contents'])

    def async_wait(self, task):
        delay, period = self.want.timeout
        # in most cases the task is no longer there after service restart, so instead for task we will check mcp state.
        if not self.check_task_exists_on_device(task):
            for x in range(0, period):
                params = dict(command="run",
                              utilCmdArgs='-c "tmsh show sys mcp-state"'
                              )
                uri = "/mgmt/tm/util/bash"

                response = self.client.post(uri, data=params)

                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])

                if 'commandResult' not in response['contents']:
                    continue

                result = response['contents']['commandResult']

                if self._is_config_reloading_failed_on_device(result):
                    raise F5ModuleError(
                        "Failed to reload the configuration. This may be due "
                        "to a cross-version incompatibility. {0}".format(result)
                    )
                if self._is_config_reloading_success_on_device(result):
                    return True
                time.sleep(delay)
            raise F5ModuleError(
                "Module timeout reached, state change is unknown, "
                "please increase the timeout parameter for long lived actions."
            )
        else:
            for x in range(0, period):
                uri = "/mgmt/tm/task/sys/ucs/{0}/result".format(task)
                response = self.client.get(uri)
                if response['code'] in [200, 201, 202]:
                    if response['contents']['_taskState'] == 'FAILED':
                        raise F5ModuleError("UCS load task has failed, please check device logs for more information.")
                    if response['contents']['_taskState'] == 'COMPLETED':
                        return True
                time.sleep(delay)
            raise F5ModuleError(
                "Module timeout reached, state change is unknown, "
                "please increase the timeout parameter for long lived actions."
            )

    def _is_config_reloading_success_on_device(self, output):
        succeed = r'Last Configuration Load Status\s+full-config-load-succeed'
        matches = re.search(succeed, output)
        if matches:
            return True
        return False

    def _is_config_reloading_failed_on_device(self, output):
        failed = r'Last Configuration Load Status\s+base-config-load-failed'
        matches = re.search(failed, output)
        if matches:
            return True
        return False

    def read_current_from_device(self):
        result = []
        uri = "/mgmt/tm/sys/ucs/"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        items = response['contents'].get('items', [])

        for item in items:
            result.append(os.path.basename(item['apiRawValues']['filename']))
        return result

    def device_is_ready(self):
        # we need to back off for a moment in case services are not restarting yet
        delay, period = self.want.timeout
        uri = "/mgmt/tm/sys/available"
        time.sleep(delay)
        for x in range(0, period):
            try:
                response = self.client.get(uri)
                if response['code'] in [200, 201, 202]:
                    return True
                time.sleep(delay)
            except ConnectionError:
                time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, unable to contact device, most likely due to restarting services, "
            "if this message persists check device logs."
        )

    def upload_file_to_device(self, content, name):
        try:
            self.client.plugin.upload_file("/mgmt/shared/file-transfer/uploads", content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            ucs=dict(required=True),
            force=dict(
                type='bool',
                default='no'
            ),
            include_chassis_level_config=dict(
                type='bool'
            ),
            no_license=dict(
                type='bool'
            ),
            no_platform_check=dict(
                type='bool'
            ),
            passphrase=dict(no_log=True),
            reset_trust=dict(type='bool'),
            task_id=dict(),
            state=dict(
                default='present',
                choices=['absent', 'installed', 'present']
            ),
            timeout=dict(
                type='int',
                default=150
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
