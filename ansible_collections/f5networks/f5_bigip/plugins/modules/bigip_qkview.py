#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_qkview
short_description: Manage QKviews on the device
description:
  - Manages creating and downloading QKviews from a BIG-IP. The qkview utility automatically
    collects configuration and diagnostic information from BIG-IP systems, and combines
    the data into a QKView file. F5 Support may request you send or upload this
    QKview to assist in troubleshooting.
version_added: "1.0.0"
options:
  filename:
    description:
      - Name of the QKview file to create on the remote BIG-IP.
    type: str
    default: "localhost.localdomain.qkview"
  dest:
    description:
      - Destination on your local filesystem where you want to save the QKview.
    type: path
    required: True
  asm_request_log:
    description:
      - When C(true), includes ASM request log data. When C(False),
        excludes ASM request log data.
    type: bool
    default: no
  max_file_size:
    description:
      - Maximum file size of the QKview file, in bytes. By default, no max
        file size is specified.
    type: int
    default: 0
  complete_information:
    description:
      - Include complete (all applicable) information in the QKview.
    type: bool
    default: no
  exclude_core:
    description:
      - Exclude core files from the QKview.
    type: bool
    default: no
  exclude:
    description:
      - Exclude various file from the QKview.
    type: list
    elements: str
    choices:
      - all
      - audit
      - secure
      - bash_history
  force:
    description:
      - If C(no), the file will only be transferred if the destination does not
        exist.
    type: bool
    default: yes
  timeout:
    description:
      - The amount of time in seconds to wait for the async interface to complete its task.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
notes:
  - This module does not include the "max time" or "restrict to blade" options.
  - If you are using this module with either Ansible Tower or Ansible AWX, you
    should be aware of how these Ansible products execute jobs in restricted
    environments. More information can be found here
    https://clouddocs.f5.com/products/orchestration/ansible/devel/usage/module-usage-with-tower.html
  - Some longer running tasks might cause the REST interface on BIG-IP to time out, to avoid this adjust the timers as
    per this KB article https://support.f5.com/csp/article/K94602685
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
    - name: Fetch a qkview from the remote device
      bigip_qkview:
        asm_request_log: yes
        exclude:
          - audit
          - secure
        dest: /tmp/localhost.localdomain.qkview
'''

RETURN = r'''
# only common fields returned
'''

import os
import re
import time

from datetime import datetime
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


from ..module_utils.client import (
    F5Client, tmos_version, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, fq_name
)


class Parameters(AnsibleF5Parameters):
    api_attributes = [
        'asm_request_log',
        'complete_information',
        'exclude',
        'exclude_core',
        'filename_cmd',
        'max_file_size',
    ]

    returnables = ['stdout', 'stdout_lines', 'warnings']

    @property
    def exclude(self):
        if self._values['exclude'] is None:
            return None
        exclude = ' '.join(self._values['exclude'])
        return "--exclude='{0}'".format(exclude)

    @property
    def exclude_raw(self):
        return self._values['exclude']

    @property
    def exclude_core(self):
        if self._values['exclude']:
            return '-C'
        else:
            return None

    @property
    def complete_information(self):
        if self._values['complete_information']:
            return '-c'
        return None

    @property
    def max_file_size(self):
        if self._values['max_file_size'] in [None]:
            return None
        return '-s {0}'.format(self._values['max_file_size'])

    @property
    def asm_request_log(self):
        if self._values['asm_request_log']:
            return '-o asm-request-log'
        return None

    @property
    def filename(self):
        pattern = r'^[\w\.]+$'
        filename = os.path.basename(self._values['filename'])
        if re.match(pattern, filename):
            return filename
        else:
            raise F5ModuleError(
                "The provided filename must contain word characters only."
            )

    @property
    def filename_cmd(self):
        return '-f {0}'.format(self.filename)

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

        return int(delay), divisor

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result

    def api_params(self):
        result = {}
        for api_attribute in self.api_attributes:
            if self.api_map is not None and api_attribute in self.api_map:
                result[api_attribute] = getattr(self, self.api_map[api_attribute])
            else:
                result[api_attribute] = getattr(self, api_attribute)
        result = self._filter_params(result)
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.kwargs = kwargs

    def exec_module(self):
        if self.is_version_less_than_14():
            manager = self.get_manager('madm')
        else:
            manager = self.get_manager('bulk')
        return manager.exec_module()

    def get_manager(self, type):
        if type == 'madm':
            return MadmLocationManager(**self.kwargs)
        elif type == 'bulk':
            return BulkLocationManager(**self.kwargs)

    def is_version_less_than_14(self):
        version = tmos_version(self.client)
        if LooseVersion(version) < LooseVersion('14.0.0'):
            return True
        else:
            return False


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.have = None
        self.want = Parameters(params=self.module.params)
        self.changes = Parameters()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = Parameters(params=changed)

    def exec_module(self):
        start = datetime.now().isoformat()
        result = dict()

        self.present()

        result.update(**self.changes.to_return())
        result.update(dict(changed=False))
        send_teem(self.client, start)
        return result

    def present(self):
        if os.path.exists(self.want.dest) and not self.want.force:
            raise F5ModuleError(
                "The specified 'dest' file already exists."
            )
        if not os.path.exists(os.path.dirname(self.want.dest)):
            raise F5ModuleError(
                "The directory of your 'dest' file does not exist."
            )
        if self.want.exclude:
            choices = ['all', 'audit', 'secure', 'bash_history']
            if not all(x in choices for x in self.want.exclude_raw):
                raise F5ModuleError(
                    "The specified excludes must be in the following list: "
                    "{0}".format(','.join(choices))
                )
        self.execute()

    def execute(self):
        response = self.execute_on_device()
        if not response:
            raise F5ModuleError(
                "Failed to create qkview on device."
            )

        result = self._move_qkview_to_download()
        if not result:
            raise F5ModuleError(
                "Failed to move the file to a downloadable location."
            )

        self._download_file()
        if not os.path.exists(self.want.dest):
            raise F5ModuleError(
                "Failed to save the qkview to local disk."
            )

        self._delete_qkview()

    def _delete_qkview(self):
        tpath_name = '{0}/{1}'.format(self.remote_dir, self.want.filename)
        params = dict(
            command='run',
            utilCmdArgs=tpath_name
        )
        uri = "/mgmt/tm/util/unix-rm"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def execute_on_device(self):
        self._upsert_temporary_cli_script_on_device()
        task_id = self._create_async_task_on_device()
        self._exec_async_task_on_device(task_id)
        self._wait_for_async_task_to_finish_on_device(task_id)
        self._remove_temporary_cli_script_from_device()
        return True

    def _upsert_temporary_cli_script_on_device(self):
        args = {
            "name": "__ansible_mkqkview",
            "apiAnonymous": """
                proc script::run {} {
                    set cmd [lreplace $tmsh::argv 0 0]; eval "exec $cmd 2> /dev/null"
                }
            """
        }
        result = self._create_temporary_cli_script_on_device(args)
        if result:
            return True
        return self._update_temporary_cli_script_on_device(args)

    def _create_temporary_cli_script_on_device(self, args):
        uri = "/mgmt/tm/cli/script"
        response = self.client.post(uri, data=args)
        if response['code'] in [404, 409]:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def _update_temporary_cli_script_on_device(self, args):
        uri = "/mgmt/tm/cli/script/{0}".format(transform_name('Common', '__ansible_mkqkview'))
        response = self.client.put(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def _create_async_task_on_device(self):
        """Creates an async cli script task in the REST API

        Returns:
            int: The ID of the task staged for running.

        :return:
        """
        command = ' '.join(self.want.api_params().values())
        args = {
            "command": "run",
            "name": "__ansible_mkqkview",
            "utilCmdArgs": "/usr/bin/qkview {0}".format(command)
        }
        uri = "/mgmt/tm/task/cli/script"

        response = self.client.post(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['_taskId']

    def _exec_async_task_on_device(self, task_id):
        args = {"_taskState": "VALIDATING"}
        uri = "/mgmt/tm/task/cli/script/{0}".format(task_id)
        response = self.client.put(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def _wait_for_async_task_to_finish_on_device(self, task_id):
        interval, period = self.want.timeout
        uri = "/mgmt/tm/task/cli/script/{0}/result".format(task_id)
        for x in range(0, period):
            response = self.client.get(uri)
            if response['code'] not in [200, 201, 202]:
                time.sleep(10)
                continue
            if response['contents']['_taskState'] == 'FAILED':
                raise F5ModuleError(
                    "qkview creation task failed unexpectedly."
                )
            if response['contents']['_taskState'] == 'COMPLETED':
                return True
            time.sleep(interval)
        raise F5ModuleError('Operation timed out.')

    def _remove_temporary_cli_script_from_device(self):
        command = 'tmsh delete cli script {0}'.format(fq_name('Common', '__ansible_mkqkview'))
        uri = "/mgmt/tm/util/bash"
        params = {
            "command": "run",
            "utilCmdArgs": '-c "{0}"'.format(command)
        }
        response = self.client.post(uri, data=params)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if 'commandResult' in response['contents']:
            raise F5ModuleError(
                "Attempt to remove the temporary script returned with: {0}".format(
                    response['contents']['commandResult']
                )
            )
        return True

    def _move_qkview_to_download(self):
        uri = "/mgmt/tm/util/unix-mv/"
        args = dict(
            command='run',
            utilCmdArgs='/var/tmp/{0} {1}/{0}'.format(self.want.filename, self.remote_dir)
        )
        response = self.client.post(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True


class BulkLocationManager(BaseManager):
    def __init__(self, *args, **kwargs):
        super(BulkLocationManager, self).__init__(**kwargs)
        self.remote_dir = '/var/config/rest/bulk'

    def _download_file(self):
        uri = "/mgmt/shared/file-transfer/bulk/{0}".format(self.want.filename)
        self.client.plugin.download_file(uri, self.want.dest)
        if os.path.exists(self.want.dest):
            return True
        return False


class MadmLocationManager(BaseManager):
    def __init__(self, *args, **kwargs):
        super(MadmLocationManager, self).__init__(**kwargs)
        self.remote_dir = '/var/config/rest/madm'

    def _download_file(self):
        uri = "/mgmt/shared/file-transfer/madm/{0}".format(self.want.filename)
        self.client.plugin.download_file(uri, self.want.dest)
        if os.path.exists(self.want.dest):
            return True
        return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            filename=dict(
                default='localhost.localdomain.qkview'
            ),
            asm_request_log=dict(
                type='bool',
                default='no',
            ),
            max_file_size=dict(
                type='int',
            ),
            complete_information=dict(
                default='no',
                type='bool'
            ),
            exclude_core=dict(
                default="no",
                type='bool'
            ),
            force=dict(
                default=True,
                type='bool'
            ),
            exclude=dict(
                type='list',
                elements='str',
                choices=[
                    'all', 'audit', 'secure', 'bash_history'
                ]
            ),
            dest=dict(
                type='path',
                required=True
            ),
            timeout=dict(
                type='int',
                default=300
            ),
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
