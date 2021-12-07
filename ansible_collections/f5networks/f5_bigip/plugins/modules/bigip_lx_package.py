#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_lx_package
short_description: Manages Javascript LX packages on a BIG-IP
description:
  - Manages Javascript LX packages on a BIG-IP. This module allows
    you to deploy LX packages to the BIG-IP and manage their lifecycle.
version_added: "1.0.0"
options:
  package:
    description:
      - The LX package that you want to upload or remove. When C(state) is C(present),
        and you intend to use this module in a C(role), it is recommended that you use
        the C({{ role_path }}) variable. An example is provided in the C(EXAMPLES) section.
      - When C(state) is C(absent), it is not necessary for the package to exist on the
        Ansible controller. If the full path to the package is provided, the filename is
        specifically cherry picked from it to properly remove the package.
    type: path
  state:
    description:
      - Whether the LX package should exist or not.
    type: str
    default: present
    choices:
      - present
      - absent
  retain_package_file:
    description:
      - Should the install file be deleted on successful installation of the package
    type: bool
    default: no
  timeout:
    description:
      - The amount of time to wait for the installation task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
    version_added: "1.4.0"
notes:
  - Requires the rpm tool be installed on the host. This can be accomplished through
    different ways on each platform.
  - On Debian based systems with C(apt); C(apt-get install rpm).
  - On Mac with C(brew); C(brew install rpm).
  - This command is already present on RedHat based systems.
requirements:
  - The 'rpm' tool installed on the Ansible controller
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
    - name: Install AS3
      bigip_lx_package:
        package: f5-appsvcs-3.5.0-3.noarch.rpm

    - name: Install AS3 with custom timeout
      bigip_lx_package:
        package: f5-appsvcs-3.5.0-3.noarch.rpm
        timeout: 100

    - name: Add an LX package stored in a role
      bigip_lx_package:
        package: "{{ roles_path }}/files/MyApp-0.1.0-0001.noarch.rpm'"

    - name: Remove an LX package
      bigip_lx_package:
        package: MyApp-0.1.0-0001.noarch.rpm
        state: absent

    - name: Install AS3 and don't delete package file
      bigip_lx_package:
        package: f5-appsvcs-3.5.0-3.noarch.rpm
        retain_package_file: yes
'''

RETURN = r'''
# only common fields returned
'''

import os
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import urlparse
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)


class Parameters(AnsibleF5Parameters):
    api_attributes = []
    returnables = []

    @property
    def package(self):
        if self._values['package'] is None:
            return None
        return self._values['package']

    @property
    def package_file(self):
        if self._values['package'] is None:
            return None
        return os.path.basename(self._values['package'])

    @property
    def package_name(self):
        """Return a valid name for the package

        BIG-IP determines the package name by the content of the RPM info.
        It does not use the filename. Therefore, we do the same. This method
        is only used though when the file actually exists on your Ansible
        controller.

        If the package does not exist, then we instead use the filename
        portion of the 'package' argument that is provided.

        Non-existence typically occurs when using 'state' = 'absent'

        :return:
        """
        cmd = ['rpm', '-qp', '--queryformat', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}', self.package]
        rc, out, err = self._module.run_command(cmd)
        if not out:
            return str(self.package_file)
        return out

    @property
    def package_root(self):
        if self._values['package'] is None:
            return None
        base = os.path.basename(self._values['package'])
        result = os.path.splitext(base)
        return result[0]

    @property
    def retain_package_file(self):
        return flatten_boolean(self._values['retain_package_file'])

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


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    pass


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
        self.want = ModuleParameters(module=self.module, params=self.module.params)
        self.changes = UsableChanges()

    def exec_module(self):
        start = datetime.now().isoformat()
        result = dict()
        changed = False
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        changes = self.changes.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        send_teem(self.client, start)
        return result

    def present(self):
        if self.exists():
            return False
        else:
            return self.create()

    def absent(self):
        changed = False
        if self.exists():
            changed = self.remove()
        return changed

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the LX package.")
        return True

    def create(self):
        if self.module.check_mode:
            return True
        if not os.path.exists(self.want.package):
            if self.want.package.startswith('/'):
                raise F5ModuleError(
                    "The specified LX package was not found at {0}.".format(self.want.package)
                )
            else:
                raise F5ModuleError(
                    "The specified LX package was not found in {0}.".format(os.getcwd())
                )
        if not self.check_file_exists_on_device():
            self.upload_to_device()
        self.create_on_device()
        self.enable_iapplx_on_device()
        if self.want.retain_package_file == 'no':
            self.remove_package_file_from_device()
        if self.exists():
            return True
        else:
            raise F5ModuleError("Failed to install LX package.")

    def exists(self):
        exists = False
        packages = self.get_installed_packages_on_device()
        if os.path.exists(self.want.package):
            exists = True
        for package in packages:
            if exists:
                if self.want.package_name == package['packageName']:
                    return True
            else:
                if self.want.package_root == package['packageName']:
                    return True
        return False

    def get_installed_packages_on_device(self):
        uri = "/mgmt/shared/iapp/package-management-tasks"
        params = {'operation': 'QUERY'}
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        path = urlparse(response['contents']['selfLink']).path
        task = self.wait_for_task(path)

        if task['status'] == 'FINISHED':
            return task['queryResponse']
        raise F5ModuleError(
            "Failed to find the installed packages on the device."
        )

    def wait_for_task(self, path):
        delay, period = self.want.timeout
        task = None
        for x in range(0, period):
            task = self._check_task_on_device(path)
            if task['status'] in ['FINISHED', 'FAILED']:
                return task
            time.sleep(delay)
        return task

    def _check_task_on_device(self, path):
        response = self.client.get(path)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']

    def upload_to_device(self):
        try:
            self.client.plugin.upload_file("/mgmt/shared/file-transfer/uploads", self.want.package)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def check_file_exists_on_device(self):
        params = dict(
            command="run",
            utilCmdArgs="/var/config/rest/downloads/{0}".format(self.want.package_file)
        )
        response = self.client.post('/mgmt/tm/util/unix-ls', data=params)
        if response['code'] in [200, 201]:
            if 'commandResult' in response['contents']:
                if self.want.package_file in response['contents']['commandResult'] and \
                        'No such file or directory' not in response['contents']['commandResult']:
                    return True
            return False
        raise F5ModuleError(response['contents'])

    def remove_package_file_from_device(self):
        params = dict(
            command="run",
            utilCmdArgs="/var/config/rest/downloads/{0}".format(self.want.package_file)
        )
        response = self.client.post('/mgmt/tm/util/unix-rm', data=params)
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def create_on_device(self):
        remote_path = "/var/config/rest/downloads/{0}".format(self.want.package_file)
        params = dict(
            operation='INSTALL', packageFilePath=remote_path
        )

        response = self.client.post('/mgmt/shared/iapp/package-management-tasks', data=params)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        path = urlparse(response['contents']["selfLink"]).path
        task = self.wait_for_task(path)

        if task['status'] == 'FINISHED':
            return True
        else:
            raise F5ModuleError(task['errorMessage'])

    def remove_from_device(self):
        params = dict(
            operation='UNINSTALL',
            packageName=self.want.package_root
        )

        response = self.client.post('/mgmt/shared/iapp/package-management-tasks', data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        path = urlparse(response['contents']["selfLink"]).path
        task = self.wait_for_task(path)

        if task['status'] == 'FINISHED':
            return True
        return False

    def enable_iapplx_on_device(self):
        params = dict(
            command="run",
            utilCmdArgs='-c "touch /var/config/rest/iapps/enable"'
        )
        response = self.client.post('/mgmt/tm/util/bash', data=params)

        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            package=dict(type='path'),
            retain_package_file=dict(
                default='no',
                type='bool'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['package']]
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
