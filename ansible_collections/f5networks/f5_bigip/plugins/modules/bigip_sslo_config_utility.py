#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_config_utility
short_description: Manage the set of SSL Orchestrator utility functions
description:
  - Manage the set of SSL Orchestrator utility functions.
version_added: "1.6.0"
options:
  package:
    description:
      - The SSLO package you want to upload.
      - Used when C(utility) is set to C(rpm-update).
      - Attempting to rerun the task with the same version of the RPM package is idempotent, which means no change operation
        is performed.
    type: path
  utility:
    description:
        - Specifies the utility function to perform.
        - When C(delete-all) is set, the utility removes all related SSL Orchestrator objects from the configuration.
        - The C(delete-all) mode is not idempotent.
        - When C(rpm-update) is set, the utility allows updating of existing SSLO RPM packages.
    type: str
    required: True
    choices:
      - delete-all
      - rpm-update
  timeout:
    description:
      - The amount of time to wait for the C(rpm-update) or C(delete-all) task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
notes:
  - Requires the RPM tool is installed on the host. This can be accomplished through
    different ways on each platform.
  - On Debian-based systems, use C(apt); C(apt-get install rpm).
  - On Mac, use C(brew); C(brew install rpm).
  - This command is already present on RedHat based systems.
requirements:
  - The 'rpm' tool installed on the Ansible controller.
author:
  - Wojciech Wypior (@wojtek0806)
  - Kevin Stewart (@kevingstewart)
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
    - name: Remove entire SSLO config
      bigip_sslo_config_utility:
        utility: delete-all
        timeout: 60

    - name: Update SSLO package
      bigip_sslo_config_utility:
        utility: update-rpm
        package: "{{ role_path }}/files/MyApp-0.1.0-0001.noarch.rpm"
        timeout: 60
'''

RETURN = r'''
# only common fields returned
'''

import os
import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import urlparse
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.constants import (
    min_sslo_version, max_sslo_version
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

        :return:
        """
        cmd = ['rpm', '-qp', '--queryformat', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}', self.package]
        rc, out, err = self._module.run_command(cmd)
        if not out:
            return str(self.package_file)
        return out

    @property
    def package_release(self):
        """To determine package release by the content of the RPM info,
        we use this to compare what is on device,
        as reinstalling same version will cause failure.
        """
        cmd = ['rpm', '-qp', '--queryformat', '%{RELEASE}', self.package]
        rc, out, err = self._module.run_command(cmd)
        if out:
            return out

    @property
    def package_root(self):
        if self._values['package'] is None:
            return None
        base = os.path.basename(self._values['package'])
        result = os.path.splitext(base)
        return result[0]

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


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1


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
        changed = False
        result = dict()
        utility = self.want.utility

        self.check_sslo_version()

        if utility == 'rpm-update':
            changed = self.create()
        if utility == 'delete-all':
            changed = self.delete()

        changes = self.changes.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def check_sslo_version(self):
        version = sslo_version(self.client)
        if LooseVersion(version) > LooseVersion(max_sslo_version) or \
                LooseVersion(version) < LooseVersion(min_sslo_version):
            raise F5ModuleError(
                f"Unsupported SSL Orchestrator version, requires a version between "
                f"{min_sslo_version} and {max_sslo_version}"
            )
        return True

    def create(self):
        if self.module.check_mode:
            return True
        if not os.path.exists(self.want.package):
            if self.want.package.startswith('/'):
                raise F5ModuleError(
                    "The specified SSLO package was not found at {0}.".format(self.want.package)
                )
            else:
                raise F5ModuleError(
                    "The specified SSLO package was not found in {0}.".format(os.getcwd())
                )
        if self.same_sslo_version():
            return False
        self.upload_to_device()
        self.create_on_device()
        return True

    def delete(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        return True

    def same_sslo_version(self):
        want_version = self.want.package_release
        have_version = self._get_sslo_release()

        # If we cannot determine version from provided RPM  or from device we do not install
        if not want_version or not have_version:
            return False
        if LooseVersion(want_version) == LooseVersion(have_version):
            return False
        return True

    def _get_sslo_release(self):
        uri = "/mgmt/shared/iapp/installed-packages"
        response = self.client.get(uri)
        if response['code'] in [200, 201, 202]:
            if response['contents']['items']:
                for x in response['contents']['items']:
                    if x['appName'] == 'f5-iappslx-ssl-orchestrator':
                        return x['release']

    def upload_to_device(self):
        try:
            self.client.plugin.upload_file("/mgmt/shared/file-transfer/uploads", self.want.package)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def create_on_device(self):
        remote_path = "/var/config/rest/downloads/{0}".format(self.want.package_file)
        params = dict(
            operation='INSTALL', packageFilePath=remote_path
        )

        response = self.client.post('/mgmt/shared/iapp/package-management-tasks', data=params)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        path = urlparse(response['contents']['selfLink']).path
        task = self.wait_for_task(path)

        if not task:
            raise F5ModuleError(
                "Module timeout reached, state change is unknown, "
                "please increase the timeout parameter for long lived actions."
            )

        if task['status'] == 'FINISHED':
            return True
        if 'errorMessage' in task:
            raise F5ModuleError(task['errorMessage'])
        else:
            raise F5ModuleError("SSL Orchestrator package update failed, check BIG-IP logs for root cause.")

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

    def remove_from_device(self):
        delay, period = self.want.timeout
        uri = "/mgmt/shared/iapp/f5-iappslx-ssl-orchestrator/appsCleanup"
        jsonstr = {'operationType': 'CLEAN_ALL_GC_APP'}
        response = self.client.post(uri, data=jsonstr)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        for x in range(0, period):
            response = self.client.get(uri)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['running'] is False \
                    and response['contents']['message'] == 'Cleanup process completed. Press ok to continue.':
                return True
            if response['contents']['running'] is False:
                if 'isCleanupSuccessful' in response['contents'] \
                        and response['contents']['isCleanupSuccessful'] is True:
                    return True
            elif response['contents']['running'] is False and len(response['contents']['successMessage']) > 0 and \
                    response['contents']['successMessage'][0]['type'] == 'error':
                raise F5ModuleError("Utility(delete-all) failed with the following message: {0}".format(
                    response['contents']['successMessage'][0]['message'])
                )
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            utility=dict(
                choices=['delete-all', 'rpm-update'],
                required=True
            ),
            package=dict(type='path'),
            timeout=dict(
                type='int',
                default=300
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['utility', 'rpm-update', ['package']]
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
