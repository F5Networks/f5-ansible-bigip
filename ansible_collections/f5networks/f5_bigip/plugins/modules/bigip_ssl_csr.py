#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ssl_csr
short_description: Create SSL CSR files on the BIG-IP
description:
  - This module will create SSL CSR files on a BIG-IP. CSRs
    require an associated SSL key to pre-exist on the BIG-IP.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the CSR file.
    type: str
    required: True
  common_name:
    description:
      - The certificate common name.
    type: str
  key_name:
    description:
      - The SSL key to be used to generate the CSR.
    type: str
  state:
    description:
      - When C(present), ensures the resource exists.
      - When C(absent), ensures the resource does not exist.
    type: str
    choices:
      - present
      - absent
    default: present
  dest:
    description:
      - Destination on your local filesystem when you want to save the CSR file.
    type: path
    required: True
  force:
    description:
      - If C(no), the file will only be transferred if the destination does not
        exist.
    type: bool
    default: yes
author:
  - Nitin Khanna (@nitinthewiz)
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

- name: Create an SSL csr
  bigip_ssl_csr:
    name: csr-name
    key_name: key-name
    common_name: csr-name
    dest: /tmp/csr-name
'''

RETURN = r'''
csr_name:
  description: The name of the CSR file.
  returned: created
  type: str
  sample: csr-name
common_name:
  description: The common name of the CSR file.
  returned: created
  type: str
  sample: csr-name
'''

import os

from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, tmos_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'commonName': 'common_name',
        'key': 'key_name'
    }

    api_attributes = [
        'commonName',
        'key'
    ]

    returnables = [
        'csr_name',
        'common_name'
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
        self.have = ApiParameters()
        self.changes = UsableChanges()
        self.remote_dir = '/var/config/rest/bulk'

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
        if self.version_is_less_than_14():
            raise F5ModuleError(
                "This module requires TMOS version 14.x and above."
            )
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def version_is_less_than_14(self):
        version = tmos_version(self.client)
        if LooseVersion(version) < LooseVersion('14.0.0'):
            return True
        else:
            return False

    def present(self):
        if os.path.exists(self.want.dest) and not self.want.force:
            raise F5ModuleError(
                "The specified 'dest' file already exists."
            )
        if not os.path.exists(os.path.dirname(self.want.dest)):
            raise F5ModuleError(
                "The directory of your 'dest' file does not exist."
            )
        if self.exists():
            return False
        else:
            return self.execute()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def execute(self):
        response = self.create()
        if not response:
            raise F5ModuleError(
                "Failed to create csr on device."
            )

        result = self._move_csr_to_download()
        if not result:
            raise F5ModuleError(
                "Failed to move the csr file to a downloadable location"
            )

        self._download_file()
        if not os.path.exists(self.want.dest):
            raise F5ModuleError(
                "Failed to save the csr file to local disk"
            )

        self._delete_csr()
        result = self.file_exists()
        if result:
            raise F5ModuleError(
                "Failed to remove the remote csr file"
            )
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "/mgmt/tm/sys/crypto/csr/{0}".format(self.want.name)
        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        params['key'] = self.want.key_name

        uri = "/mgmt/tm/sys/crypto/csr/"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        uri = "/mgmt/tm/sys/crypto/csr/{0}".format(self.want.name)

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def file_exists(self):
        tpath_name = '{0}/{1}'.format(self.remote_dir, self.want.name)
        params = dict(
            command='run',
            utilCmdArgs=tpath_name
        )

        uri = "/mgmt/tm/util/unix-ls"

        response = self.client.post(uri, data=params)

        if response['code'] == 404:
            return False
        try:
            if "No such file or directory" in response['contents']['commandResult']:
                return False
            if self.want.name in response['contents']['commandResult']:
                return True
        except KeyError:
            return False

    def _download_file(self):
        url = "/mgmt/shared/file-transfer/bulk/{0}".format(self.want.name)
        self.client.plugin.download_file(url, self.want.dest)
        if os.path.exists(self.want.dest):
            return True
        return False

    def _delete_csr(self):
        tpath_name = '{0}/{1}'.format(self.remote_dir, self.want.name)
        params = dict(
            command='run',
            utilCmdArgs=tpath_name
        )
        uri = "/mgmt/tm/util/unix-rm"
        response = self.client.post(uri, data=params)
        if response['code'] == 404:
            return False

    def _move_csr_to_download(self):
        uri = "/mgmt/tm/util/unix-mv/"
        args = dict(
            command='run',
            utilCmdArgs='/config/ssl/ssl.csr/{0} {1}/{0}'.format(self.want.name, self.remote_dir)
        )
        self.client.post(uri, data=args)
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                required=True
            ),
            common_name=dict(),
            key_name=dict(),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            dest=dict(
                type='path',
                required=True
            ),
            force=dict(
                default=True,
                type='bool'
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)

        self.required_if = [
            ['state', 'present', ['common_name', 'key_name']]
        ]


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
