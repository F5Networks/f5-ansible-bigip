#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_apm_policy_fetch
short_description: Exports the APM policy or APM access profile from remote nodes
description:
  - Exports the APM policy or APM access profile from remote nodes.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the APM policy or APM access profile exported to create a file on the remote device for downloading.
    type: str
    required: True
  dest:
    description:
      - A directory to save the file into.
    type: path
  file:
    description:
      - The name of the file to be created on the remote device for downloading.
    type: str
  type:
    description:
      - Specifies the type of item to export from the device.
    type: str
    choices:
      - profile_access
      - access_policy
    default: profile_access
  force:
    description:
      - If C(no), the file will only be transferred if it does not exist in the the destination.
    type: bool
    default: yes
  partition:
    description:
      - Device partition which contains the APM policy or APM access profile to export.
    type: str
    default: Common
notes:
  - Due to ID685681 it is not possible to execute ng_* tools via REST API on v12.x and 13.x, once this is fixed
    this restriction will be removed.
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
    - name: Export APM access profile
      bigip_apm_policy_fetch:
        name: foobar
        file: export_foo
        dest: /root/download

    - name: Export APM access policy
      bigip_apm_policy_fetch:
        name: foobar
        file: export_foo
        dest: /root/download
        type: access_policy

    - name: Export APM access profile, autogenerate name
      bigip_apm_policy_fetch:
        name: foobar
        dest: /root/download
'''

RETURN = r'''
name:
  description: Name of the APM policy or APM access profile to be exported.
  returned: changed
  type: str
  sample: APM_policy_global
file:
  description:
    - Name of the exported file on the remote BIG-IP to download. If not
      specified, then this will be a randomly generated filename.
  returned: changed
  type: str
  sample: foobar_file
dest:
  description: Local path to download the exported APM policy.
  returned: changed
  type: str
  sample: /root/downloads/profile-foobar_file.conf.tar.gz
type:
  description: Set to specify the type of item to export.
  returned: changed
  type: str
  sample: access_policy
'''

import os
import tempfile
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
    api_map = {}

    api_attributes = []

    returnables = [
        'name',
        'file',
        'dest',
        'type',
        'force',
    ]

    updatables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def file(self):
        if self._values['file'] is not None:
            return self._values['file']
        result = next(tempfile._get_candidate_names()) + '.tar.gz'
        self._values['file'] = result
        return result

    @property
    def fulldest(self):
        if os.path.isdir(self.dest):
            result = os.path.join(self.dest, self.file)
        else:
            if os.path.exists(os.path.dirname(self.dest)):
                result = self.dest
            else:
                try:
                    # os.path.exists() can return false in some
                    # circumstances where the directory does not have
                    # the execute bit for the current user set, in
                    # which case the stat() call will raise an OSError
                    result = self.dest
                    os.stat(os.path.dirname(result))
                except OSError as e:
                    if "permission denied" in str(e).lower():
                        raise F5ModuleError(
                            "Destination directory {0} is not accessible".format(os.path.dirname(self.dest))
                        )
                    raise F5ModuleError(
                        "Destination directory {0} does not exist".format(os.path.dirname(self.dest))
                    )

        if not os.access(os.path.dirname(result), os.W_OK):
            raise F5ModuleError(
                "Destination {0} not writable".format(os.path.dirname(result))
            )
        return result


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
        if not module_provisioned(self.client, 'apm'):
            raise F5ModuleError(
                "APM must be provisioned to use this module."
            )

        if self.version_less_than_14():
            raise F5ModuleError('Due to bug ID685681 it is not possible to use this module on TMOS version below 14.x')

        result = dict()

        self.export()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=True))
        send_teem(self.client, start)
        return result

    def version_less_than_14(self):
        version = tmos_version(self.client)
        if LooseVersion(version) < LooseVersion('14.0.0'):
            return True
        return False

    def export(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def update(self):
        if not self.want.force:
            raise F5ModuleError(
                "File '{0}' already exists.".format(self.want.fulldest)
            )
        self.create()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        self.execute()
        return True

    def download(self):
        self.download_from_device(self.want.fulldest)
        if os.path.exists(self.want.fulldest):
            return True
        raise F5ModuleError(
            "Failed to download the remote file."
        )

    def execute(self):
        self.download()
        self.remove_temp_file_from_device()
        return True

    def exists(self):
        self.policy_exists()
        if os.path.exists(self.want.fulldest):
            return True
        return False

    def policy_exists(self):
        if self.want.type == 'access_policy':
            uri = "/mgmt/tm/apm/policy/access-policy/{0}".format(transform_name(self.want.partition, self.want.name))
        else:
            uri = "/mgmt/tm/apm/profile/access/{0}".format(transform_name(self.want.partition, self.want.name))

        response = self.client.get(uri)

        if response['code'] == 404:
            raise F5ModuleError('The provided {0} with the name {1} does not exist on device.'.format(
                self.want.type, self.want.name)
            )
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        cmd = 'ng_export -t {0} {1} {1} -p {2}'.format(
            self.want.type, self.want.name, self.want.partition
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
            raise F5ModuleError('Item export command failed with the error: {0}'.format(
                response['contents']['commandResult']
            )
            )

        self._move_file_to_download()
        return True

    def _move_file_to_download(self):
        if self.want.type == 'access_policy':
            item = 'policy'
        else:
            item = 'profile'

        name = '{0}-{1}.conf.tar.gz'.format(item, self.want.name)
        move_path = '/shared/tmp/{0} {1}/{2}'.format(
            name,
            '/shared/images',
            self.want.file
        )
        params = dict(
            command='run',
            utilCmdArgs=move_path
        )

        uri = "/mgmt/tm/util/unix-mv/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' in response['contents']:
            if 'cannot stat' in response['contents']['commandResult']:
                raise F5ModuleError(response['contents']['commandResult'])
        return True

    def download_from_device(self, dest):
        url = "/mgmt/cm/autodeploy/software-image-downloads/{0}".format(self.want.file)
        self.client.plugin.download_file(url, dest)
        if os.path.exists(self.want.dest):
            return True
        return False

    def remove_temp_file_from_device(self):
        tpath_name = '/shared/images/{0}'.format(self.want.file)
        uri = "/mgmt/tm/util/unix-rm/"
        args = dict(
            command='run',
            utilCmdArgs=tpath_name
        )
        response = self.client.post(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True,
            ),
            dest=dict(
                type='path'
            ),
            type=dict(
                default='profile_access',
                choices=['profile_access', 'access_policy']
            ),
            file=dict(),
            force=dict(
                default='yes',
                type='bool'
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
