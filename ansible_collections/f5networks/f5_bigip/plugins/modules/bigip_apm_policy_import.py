#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_apm_policy_import
short_description: Manage BIG-IP APM policy or APM access profile imports
description:
   - Manage BIG-IP APM policy or APM access profile imports.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the APM policy or APM access profile to create or override.
    type: str
    required: True
  type:
    description:
      - Specifies the type of item to export from the device.
    type: str
    choices:
      - profile_access
      - access_policy
      - profile_api_protection
    default: profile_access
  source:
    description:
      - Full path to a file to be imported into the BIG-IP APM.
    type: path
  force:
    description:
      - When set to C(yes), any existing policy with the same name is overwritten by the new import.
      - If a policy does not exist, this setting is ignored.
    default: no
    type: bool
  partition:
    description:
      - Device partition on which to manage resources.
    type: str
    default: Common
  reuse_objects:
    description:
      - When set to C(yes) and objects referred within the policy exist on the BIG-IP,
        those are used instead of the objects defined in the policy.
      - Reusing existing objects reduces configuration size.
      - The configuration of existing objects might differ from the configuration of the objects defined in the policy!
    default: yes
    type: bool
notes:
  - Requires BIG-IP >= 14.0.0
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
    - name: Import APM profile
      bigip_apm_policy_import:
        name: new_apm_profile
        source: /root/apm_profile.tar.gz

    - name: Import APM policy
      bigip_apm_policy_import:
        name: new_apm_policy
        source: /root/apm_policy.tar.gz
        type: access_policy

    - name: Override existing APM policy
      bigip_asm_policy:
        name: new_apm_policy
        source: /root/apm_policy.tar.gz
        force: yes

    - name: Import APM profile without re-using existing configuration objects
      bigip_apm_policy_import:
        name: new_apm_profile
        source: /root/apm_profile.tar.gz
        reuse_objects: false
'''

RETURN = r'''
source:
  description: Local path to the APM policy file.
  returned: changed
  type: str
  sample: /root/some_policy.tar.gz
name:
  description: Name of the APM policy or APM access profile to be created/overwritten.
  returned: changed
  type: str
  sample: APM_policy_global
type:
  description: Set to specify the type of item to export.
  returned: changed
  type: str
  sample: access_policy
force:
  description: Set when overwriting an existing policy or profile.
  returned: changed
  type: bool
  sample: yes
reuse_objects:
  description: Set when reusing existing objects on the BIG-IP.
  returned: changed
  type: bool
  sample: yes
'''

import os
from datetime import datetime
from distutils.version import LooseVersion

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name
)
from ..module_utils.client import (
    F5Client, module_provisioned, tmos_version, send_teem
)


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [

    ]

    returnables = [
        'name',
        'source',
        'type',

    ]

    updatables = [

    ]


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
        if not module_provisioned(self.client, 'apm'):
            raise F5ModuleError(
                "APM must be provisioned to use this module."
            )

        if self.version_less_than_14():
            raise F5ModuleError('Due to bug ID685681 it is not possible to use this module on TMOS version below 14.x')

        result = dict()

        changed = self.policy_import()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

    def version_less_than_14(self):
        version = tmos_version(self.client)
        if LooseVersion(version) < LooseVersion('14.0.0'):
            return True
        return False

    def policy_import(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        if self.exists():
            if self.want.force is False:
                return False

        self.import_file_to_device()
        self.remove_temp_file_from_device()
        return True

    def exists(self):
        if self.want.type == 'access_policy':
            uri = "/mgmt/tm/apm/policy/access-policy/{0}".format(
                transform_name(self.want.partition, self.want.name)
            )
        else:
            uri = "/mgmt/tm/apm/profile/access/{0}".format(
                transform_name(self.want.partition, self.want.name)
            )
        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] in [200, 201, 202]:
            return True

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def upload_file_to_device(self, content, name):
        url = "/mgmt/shared/file-transfer/uploads"
        try:
            self.client.plugin.upload_file(url, content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def import_file_to_device(self):
        name = os.path.split(self.want.source)[1]
        self.upload_file_to_device(self.want.source, name)

        if self.want.reuse_objects is True:
            reuse_objects = "-s"
        else:
            reuse_objects = ""

        cmd = 'ng_import {0} /var/config/rest/downloads/{1} {2} -p {3} -t {4}'.format(
            reuse_objects, name, self.want.name, self.want.partition, self.want.type
        )

        uri = "/mgmt/tm/util/bash/"
        args = dict(
            command='run',
            utilCmdArgs='-c "{0}"'.format(cmd)
        )
        response = self.client.post(uri, data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' in response['contents']:
            raise F5ModuleError(response['contents']['commandResult'])

        return True

    def remove_temp_file_from_device(self):
        name = os.path.split(self.want.source)[1]
        tpath_name = '/var/config/rest/downloads/{0}'.format(name)
        uri = "/mgmt/tm/util/unix-rm/"
        args = dict(
            command='run',
            utilCmdArgs=tpath_name
        )
        response = self.client.post(uri, data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            source=dict(type='path'),
            force=dict(
                type='bool',
                default='no'
            ),
            type=dict(
                default='profile_access',
                choices=['profile_access', 'access_policy', 'profile_api_protection']
            ),
            reuse_objects=dict(
                type='bool',
                default='yes'
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
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
