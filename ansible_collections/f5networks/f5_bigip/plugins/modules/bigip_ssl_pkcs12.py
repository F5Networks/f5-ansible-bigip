#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_ssl_pkcs12
short_description: Manage BIG-IP PKCS12 certificates/keys
description:
  - Installs, updates and removes PKCS12 certificates/keys on/from the BIG-IP.
version_added: 1.0.0
options:
  name:
    description:
      - The name of the PKCS12 certificate and key to create or override.
      - This parameter is mandatory when C(state) is C(absent).
      - When C(state) is C(present) and the parameter is not given, the certificate and key name is derived from the
        C(source) parameter.
    type: str
  source:
    description:
      - Full path to a PKCS12 file to be imported into the BIG-IP.
      - Parameter is mandatory when C(state) is C(present)
    type: path
  cert_pass:
    description:
      - Passphrase that the PKCS12 file is encrypted with.
    type: str
  force:
    description:
      - When set to C(yes) any existing certificate/key with the same name will be overwritten by the new import.
    default: no
    type: bool
  partition:
    description:
      - Used to check for existence and removal of installed PKCS12 keys and certs.
    type: str
    default: Common
  state:
    description:
      - Certificate and key state. This determines if the provided certificate
        and key is to be made C(present) on the device or C(absent).
    type: str
    choices:
      - present
      - absent
    default: present
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
    - name: Install PKCS12 cert and key
      bigip_ssl_pkcs12:
        source: /root/baz.p12
        state: present

    - name: Install PKCS12 cert and key - force
      bigip_ssl_pkcs12:
        name: foo
        source: /root/baz.p12
        state: present
        force: yes

    - name: Remove PKCS12 cert and key
      bigip_ssl_pkcs12:
        name: foo
        state: absent
'''

RETURN = r'''
source:
  description: Local path to PKCS12 file.
  returned: changed
  type: str
  sample: /root/some_cert.p12
name:
  description: Name of the PKCS12 cert and key to be created/overwritten.
  returned: changed
  type: str
  sample: some_cert
'''
import os
from datetime import datetime
from pathlib import Path

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'passphrase': 'cert_pass'
    }

    api_attributes = [
        'name'
        'passphrase'
    ]

    returnables = [
        'name',
        'source',
    ]
    updatables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def name(self):
        if self._values['name'] is None:
            return Path(self._values['source']).stem
        else:
            return self._values['name']

    @property
    def filename(self):
        if self._values['source'] is None:
            return None
        name = os.path.basename(self.source)
        return name


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
        self.have = ApiParameters()

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
        send_teem(self.client, start)
        return result

    def present(self):
        if self.exists():
            if self.want.force is False:
                return False
        return self.create()

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

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.install_on_device()
        self.remove_temp_file_from_device()
        return True

    def exists(self):
        uri_crt = "/mgmt/tm/sys/file/ssl-cert/{0}".format(transform_name(self.want.partition, self.want.name))
        uri_key = "/mgmt/tm/sys/file/ssl-key/{0}".format(transform_name(self.want.partition, self.want.name))
        cert = self.client.get(uri_crt)
        key = self.client.get(uri_key)

        if cert['code'] == 404 or key['code'] == 404:
            return False

        if cert['code'] not in [200, 201, 202]:
            raise F5ModuleError(cert['contents'])

        if key['code'] not in [200, 201, 202]:
            raise F5ModuleError(key['contents'])

        return True

    def upload_file_to_device(self, content, name):
        url = "/mgmt/shared/file-transfer/uploads"
        try:
            self.client.plugin.upload_file(url, content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def install_on_device(self):
        self.upload_file_to_device(self.want.source, self.want.filename)
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['command'] = "install"
        params["from-local-file"] = "/var/config/rest/downloads/{0}".format(self.want.filename)
        uri = "/mgmt/tm/sys/crypto/pkcs12"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        uri_crt = "/mgmt/tm/sys/file/ssl-cert/{0}".format(transform_name(self.want.partition, self.want.name))
        uri_key = "/mgmt/tm/sys/file/ssl-key/{0}".format(transform_name(self.want.partition, self.want.name))

        cert = self.client.delete(uri_crt)
        key = self.client.delete(uri_key)

        if cert['code'] not in [200, 201, 202]:
            raise F5ModuleError(cert['contents'])
        if key['code'] not in [200, 201, 202]:
            raise F5ModuleError(key['contents'])

        return True

    def remove_temp_file_from_device(self):
        tpath_name = '/var/config/rest/downloads/{0}'.format(self.want.filename)
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
            name=dict(),
            source=dict(
                type='path'
            ),
            cert_pass=dict(
                no_log=True
            ),
            force=dict(
                default='no',
                type='bool'
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.add_file_common_args = True
        self.required_if = [
            ['state', 'present', ['source']],
            ['state', 'absent', ['name']]
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        add_file_common_args=spec.add_file_common_args
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
