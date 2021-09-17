#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_fast_template
short_description: Manages FAST template sets on BIG-IP
description:
  - Uploads and manages FAST template sets on the BIG-IP.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the FAST template set to create or remove.
      - When C(present) the name must correspond to the basename of the uploaded zip file without the file extension.
      - Parameter is optional when C(state) is C(present), the name will be derived from the basename of the uploaded
        zip file.
      - Parameter is mandatory when C(state) is C(absent), and disregarded when C(state) is C(purge).
    type: str
  source:
    description:
      - Full path to a template set file to be imported into the BIG-IP.
      - File must be in a zip format, other formats will raise an error when attempting to activate the template sets.
      - Parameter is required when C(state) is C(present)
    type: path
  force:
    description:
      - When set to C(yes) any existing template with the same name will be overwritten by the new import.
    default: no
    type: bool
  state:
    description:
      - When C(state) is C(present), the FAST template set is uploaded and created on the device.
      - When C(state) is C(absent), ensures the existing FAST template set is removed.
      - When C(state) is C(purge), ensures all the FAST templates are removed from the device.
    type: str
    choices:
      - present
      - absent
      - purge
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
    - name: Upload and create FAST template set
      bigip_fast_template:
        name: new_template_set
        source: /root/new_template_set.zip
        state: "present"

    - name: Upload and create FAST template set, name not given - force overwrite
      bigip_fast_template:
        source: /root/new_template_set.zip
        state: "present"
        force: yes

    - name: Remove existing FAST template set
      bigip_fast_template:
        name: new_template_set
        state: "absent"

    - name: Remove all existing FAST template sets
      bigip_fast_template:
        state: "purge"
'''

RETURN = r'''
source:
  description: Local path to FAST template set file.
  returned: changed
  type: str
  sample: /root/some_template.zip
name:
  description: Name of the template set to be created/overwritten.
  returned: changed
  type: str
  sample: some_template
'''
from datetime import datetime
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    returnables = [
        'name',
        'source',
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def name(self):
        if self._values['name'] is None:
            if self._values['state'] == 'purge':
                return None
            if self._values['state'] == 'present':
                return Path(self._values['source']).stem
        return self._values['name']


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
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()
        elif state == "purge":
            changed = self.purge()

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
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.create_on_device()
        self.remove_temp_file_from_device()
        return result

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return result

    def purge(self):
        if not self.exists(sets=True):
            return False
        if self.module.check_mode:
            return True
        result = self.purge_from_device()
        return result

    def exists(self, sets=False):
        if sets:
            uri = "/mgmt/shared/fast/templatesets/"
            verify = self.client.get(uri)

            if verify['code'] not in [200, 201, 202, 204, 207]:
                raise F5ModuleError(verify['contents'])
            if not verify['contents']:
                return False
            return True
        else:
            uri = "/mgmt/shared/fast/templatesets/{0}".format(self.want.name)
            response = self.client.get(uri)
            if response['code'] == 200:
                return True
            if response['code'] == 404:
                return False

    def create_on_device(self):
        name = Path(self.want.source).name
        self.upload_file_to_device(self.want.source, name)

        args = dict(name=self.want.name)
        uri = "/mgmt/shared/fast/templatesets/"
        response = self.client.post(uri, data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def upload_file_to_device(self, content, name):
        url = "/mgmt/shared/file-transfer/uploads"
        try:
            self.client.plugin.upload_file(url, content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def remove_temp_file_from_device(self):
        name = Path(self.want.source).name
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

    def remove_from_device(self):
        uri = "/mgmt/shared/fast/templatesets/{0}".format(self.want.name)
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        return True

    def purge_from_device(self):
        uri = "/mgmt/shared/fast/templatesets/"

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(),
            source=dict(type='path'),
            force=dict(
                type='bool',
                default='no'
            ),
            state=dict(
                default='present',
                choices=['present', 'absent', 'purge']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['source']],
            ['state', 'absent', ['name']]
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
