#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_awaf_custom_attack_signatures
short_description: Imports/Exports custom attack signatures for AWAF.
description:
  - Imports/Exports custom attack signatures for AWAF.
version_added: "1.0.0"
options:
  names:
    description:
      - The names of the Custom attack signatures file on the remote BIG-IP to be Exported.
      - The name is required in state C(export) and ignored for state C(import).
    type: list
    elements: str
  source:
    description:
      - Full path to a file to be imported as Custom attack signatures.
      - Only XML file is supported for import.
      - Source file is required in state C(import).
    type: path
  dest:
    description:
      - A directory to save the file into.
      - Destination is required for state C(export).
    type: path
  force:
    description:
      - If C(true) a file of the same name on the remote device will be overwritten.
    type: bool
    default: false
  state:
    description:
      - State specifies whether the attack signatures should be imported or exported.
      - Export of only one custom attack signature at a time is supported.
    choices:
      - export
      - import
    type: str
    required: True
notes:
  - Imports/Exports are supported in XML format only.
author:
  - Prateek Ramani (@ramani)
'''

EXAMPLES = r'''
- name: Export custom attack signatures file from remote BIG-IP
  bigip_awaf_custom_attack_signatures:
    names:
      - test
    dest: /root/download
    state: export

- name: Import custom attack signatures file into BIG-IP
  bigip_awaf_custom_attack_signatures:
    source: /root/foobar.xml
    state: import
'''

RETURN = r'''
names:
  description: Name of the custom attack signatures file to be imported or exported.
  returned: changed
  type: list
  sample: APM_policy_global
source:
  description: Local path to a file to import Custom attack signatures into BIG-IP.
  returned: changed
  type: str
  sample: /root/some_attack_signatures.xml
dest:
  description: Local path to download the exported custom attack signatures file.
  returned: changed
  type: str
  sample: /root/downloads/profile-foobar_file.conf.tar.gz
state:
  description: State specifies whether the custom attack signatures file was imported or exported.
  returned: changed
  type: str
  sample: import
'''

import os
from datetime import datetime
import time
import xml.etree.ElementTree as ET

from ansible.module_utils.basic import (
    AnsibleModule
)
from ansible.module_utils.connection import Connection

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)
from ..module_utils.client import (
    F5Client, send_teem
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'names',
        'source',
        'dest',
        'force',
        'state'
    ]

    updatables = []


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
        except Exception:  # pragma: no cover
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

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        start = datetime.now().isoformat()
        state = self.want.state
        result = dict()

        if state == "export":
            changed = self.export()
        elif state == "import":
            changed = self.import_custom_attack_signatures()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))

        send_teem(self.client, start)
        return result

    def export(self):
        exists, ids = self.signature_exists(','.join(self.want.names))
        if not exists:
            raise F5ModuleError(
                f"Custom Attack Signature Policy '{self.want.names}' was not found."
            )
        return self.export_file(ids)

    def export_file(self, ids):
        uri = "/mgmt/tm/asm/tasks/export-signatures/"
        timestamp = str(int(time.time()))
        filename = f"sigfile_{timestamp}.xml"
        ids = "'" + "','".join(ids) + "'"
        filter = f"id in ({ids})"
        args = dict(
            filename=filename,
            signaturesFilter=filter
        )
        response = self.client.post(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        self.wait_for_task("/mgmt/tm/asm/tasks/export-signatures/", response['contents']['id'])
        return self.download(filename)

    def download(self, filename):
        self.download_from_device(filename)
        if os.path.exists(self.want.dest):
            return True
        raise F5ModuleError(
            "Failed to download the remote file."
        )

    def download_from_device(self, filename):
        url = "/mgmt/tm/asm/file-transfer/downloads/{0}".format(filename)
        self.client.plugin.download_asm_file(url, self.want.dest + "/" + filename, 413)
        if os.path.exists(self.want.dest):
            return True
        return False

    def upload_file_to_device(self, content, name):
        url = "/mgmt/tm/asm/file-transfer/uploads/"
        try:
            self.client.plugin.upload_file(url, content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def import_file_to_device(self):
        name = os.path.split(self.want.source)[1]
        self.upload_file_to_device(self.want.source, name)
        uri = "/mgmt/tm/asm/tasks/update-signatures"
        args = dict(
            filename=name,
            isUserDefined=True
        )
        response = self.client.post(uri, data=args)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        self.wait_for_task("/mgmt/tm/asm/tasks/update-signatures/", response['contents']['id'])

        return True

    def wait_for_task(self, url, task_id):
        while True:
            response = self.client.get(url + task_id)

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['status'] in ['COMPLETED', 'FAILURE']:
                break
            time.sleep(1)
        if response['contents']['status'] == 'FAILURE':
            raise F5ModuleError(
                'Failed to import Custom Signatures Attack file.'
            )
        if response['contents']['status'] == 'COMPLETED':
            return True

    def import_custom_attack_signatures(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        sig_names = set()
        tree = ET.parse(self.want.source)
        root = tree.getroot()

        for sig in root.findall('sig'):
            for rev in sig.findall('rev'):
                sig_name = rev.find('sig_name').text
                sig_names.add(sig_name)

        names = ','.join(sig_names)
        self.want.names = names
        exists, ids = self.signature_exists(names)
        if exists:
            if self.want.force is False:
                return False
        self.import_file_to_device()
        return True

    def signature_exists(self, names):
        uri = "/mgmt/tm/asm/signatures?$filter=name%20IN%20({0})".format(names)
        response = self.client.get(uri)
        if response['code'] == 404:
            return False, None
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if len(response['contents']['items']) == 0:
            return False, None
        if response['contents']['totalItems'] != len(names.split(',')):
            return False, None
        ids = [sig['id'] for sig in response['contents']['items']]
        return True, ids


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            names=dict(
                type='list',
                elements='str',
            ),
            source=dict(type='path'),
            dest=dict(
                type='path'
            ),
            force=dict(
                default=False,
                type='bool'
            ),
            state=dict(
                required=True,
                choices=['export', 'import']
            )
        )
        self.argument_spec = {}
        self.required_if = [['state', "export", ['names', 'dest']], ['state', "import", ['source']]]
        self.argument_spec.update(argument_spec)


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


if __name__ == '__main__':  # pragma: no cover
    main()
