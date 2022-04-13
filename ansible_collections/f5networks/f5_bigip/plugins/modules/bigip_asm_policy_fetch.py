#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_asm_policy_fetch
short_description: Exports the ASM policy from remote nodes.
description:
  - Exports the BIG-IP ASM policy from remote nodes.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the policy exported to create a file on the remote device for downloading.
    type: str
    required: True
  dest:
    description:
      - A directory where you want to save the policy file.
      - This option is ignored when C(inline) is set to c(yes).
    type: path
  file:
    description:
      - The name of the file to be created on the remote device for downloading.
      - When C(binary) is set to C(no), the ASM policy will be in XML format.
    type: str
  inline:
    description:
      - If C(yes), the ASM policy will be exported C(inline) as a string instead of a file.
      - The policy can be be retrieved in the playbook C(result) dictionary under the C(inline_policy) key.
    type: bool
  compact:
    description:
      - If C(yes), only the ASM policy custom settings will be exported.
      - Only applies to XML type ASM policy exports.
    type: bool
  base64:
    description:
      - If C(yes), the returned C(inline) ASM policy content will be Base64 encoded.
      - Only applies to C(inline) ASM policy exports.
    type: bool
  binary:
    description:
      - If C(yes), the exported ASM policy will be in binary format.
      - Only applies to C(file) ASM policy exports.
    type: bool
  force:
    description:
      - If C(no), the file will only be transferred if it does not exist in the the destination.
    default: yes
    type: bool
  partition:
    description:
      - Device partition which contains the ASM policy to export.
    type: str
    default: Common
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
    - name: Export policy in binary format
      bigip_asm_policy_fetch:
        name: foobar
        file: export_foo
        dest: /root/download
        binary: yes

    - name: Export policy inline base64 encoded format
      bigip_asm_policy_fetch:
        name: foobar
        inline: yes
        base64: yes

    - name: Export policy in XML format
      bigip_asm_policy_fetch:
        name: foobar
        file: export_foo
        dest: /root/download

    - name: Export compact policy in XML format
      bigip_asm_policy_fetch:
        name: foobar
        file: export_foo.xml
        dest: /root/download/
        compact: yes

    - name: Export policy in binary format, autogenerate name
      bigip_asm_policy_fetch:
        name: foobar
        dest: /root/download/
        binary: yes
'''

RETURN = r'''
name:
  description: Name of the ASM policy to be exported.
  returned: changed
  type: str
  sample: Asm_APP1_Transparent
dest:
  description: Local path to download the exported ASM policy.
  returned: changed
  type: str
  sample: /root/downloads/foobar.xml
file:
  description:
    - Name of the policy file on the remote BIG-IP to download. If not
      specified, this will be a randomly generated filename.
  returned: changed
  type: str
  sample: foobar.xml
inline:
  description: Set when the ASM policy to be exported is inline
  returned: changed
  type: bool
  sample: yes
compact:
  description: Set only to export custom ASM policy settings.
  returned: changed
  type: bool
  sample: no
base64:
  description: Set to encode inline export in Base64 format.
  returned: changed
  type: bool
  sample: no
binary:
  description: Set to export the ASM policy in binary format.
  returned: changed
  type: bool
  sample: yes
'''

import os
import tempfile
import time
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean, fq_name
)
from ..module_utils.client import (
    F5Client, module_provisioned, send_teem
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'filename': 'file',
        'minimal': 'compact',
        'isBase64': 'base64',
    }

    api_attributes = [
        'inline',
        'minimal',
        'isBase64',
        'policyReference',
        'filename',
    ]

    returnables = [
        'file',
        'compact',
        'base64',
        'inline',
        'force',
        'binary',
        'dest',
        'name',
        'inline_policy',
    ]

    updatables = [

    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def file(self):
        if self._values['file'] is not None:
            return self._values['file']
        if self.binary:
            result = next(tempfile._get_candidate_names()) + '.plc'
        else:
            result = next(tempfile._get_candidate_names()) + '.xml'
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

    @property
    def inline(self):
        result = flatten_boolean(self._values['inline'])
        if result == 'yes':
            return True
        elif result == 'no':
            return False

    @property
    def compact(self):
        result = flatten_boolean(self._values['compact'])
        if result == 'yes':
            return True
        elif result == 'no':
            return False

    @property
    def base64(self):
        result = flatten_boolean(self._values['base64'])
        if result == 'yes':
            return True
        elif result == 'no':
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
        if not module_provisioned(self.client, 'asm'):
            raise F5ModuleError(
                "ASM must be provisioned to use this module."
            )

        result = dict()

        self.export()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=True))
        send_teem(self.client, start)
        return result

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
        if self.want.binary:
            self.export_binary()
            return True
        self.create_on_device()
        if not self.want.inline:
            self.execute()
        return True

    def export_binary(self):
        self.export_binary_on_device()
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
        self.remove_temp_policy_from_device()
        return True

    def exists(self):
        self.policy_exists()
        if not self.want.inline:
            if os.path.exists(self.want.fulldest):
                return True
        return False

    def policy_exists(self):
        uri = "/mgmt/tm/asm/policies/"
        query = "?$filter=contains(name,'{0}')+and+contains(partition,'{1}')&$select=name,partition".format(
            self.want.name, self.want.partition
        )
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents'] and response['contents']['items'] != []:
            # because api filter on ASM is broken when names contain numbers at the end we need to work around it
            for policy in response['contents']['items']:
                if policy['name'] == self.want.name and policy['partition'] == self.want.partition:
                    return True

        raise F5ModuleError(
            "The specified ASM policy {0} on partition {1} does not exist on device.".format(
                self.want.name, self.want.partition
            )
        )

    def create_on_device(self):
        self._set_policy_link()
        params = self.changes.api_params()
        uri = "/mgmt/tm/asm/tasks/export-policy/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        result, output, file_size = self.wait_for_task(response['contents']['id'])
        if result and output:
            if 'file' in output:
                self.changes.update(dict(inline_policy=output['file']))
        if result:
            self.want.file_size = file_size
            return True

    def wait_for_task(self, task_id):
        uri = "/mgmt/tm/asm/tasks/export-policy/{0}".format(task_id)
        while True:
            response = self.client.get(uri)

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['status'] in ['COMPLETED', 'FAILURE']:
                break
            time.sleep(1)

        if response['contents']['status'] == 'FAILURE':
            raise F5ModuleError(
                'Failed to export ASM policy.'
            )
        if response['contents']['status'] == 'COMPLETED':
            if not self.want.inline:
                return True, None, response['contents']['result']['fileSize']
            else:
                return True, response['contents']['result'], response['contents']['result']['fileSize']

    def _set_policy_link(self):
        policy_link = None
        uri = "/mgmt/tm/asm/policies/"
        query = "?$filter=name+eq+{0}+and+partition+eq+{1}&$select=name,partition".format(
            self.want.name, self.want.partition
        )
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents'] and response['contents']['items'] != []:
            if len(response['contents']['items']) == 1:
                policy_link = response['contents']['items'][0]['selfLink']
            else:
                for item in response['contents']['items']:
                    if item['name'] == self.want.name:
                        policy_link = item['selfLink']

        if not policy_link:
            raise F5ModuleError("The policy was not found")

        self.changes.update(dict(policyReference={'link': policy_link}))
        return True

    def export_binary_on_device(self):
        full_name = fq_name(self.want.partition, self.want.name)
        cmd = 'tmsh save asm policy {0} bin-file {1}'.format(full_name, self.want.file)
        uri = "/mgmt/tm/util/bash/"
        args = dict(
            command='run',
            utilCmdArgs='-c "{0}"'.format(cmd)
        )
        response = self.client.post(uri, data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' in response['contents']:
            if 'Error' in response['contents']['commandResult'] or 'error' in response['contents']['commandResult']:
                raise F5ModuleError(response['contents']['commandResult'])

        self._stat_binary_on_device()
        self._move_binary_to_download()

        return True

    def _stat_binary_on_device(self):
        params = dict(
            command='run',
            utilCmdArgs='/var/tmp/{0} -l'.format(self.want.file)
        )
        uri = "/mgmt/tm/util/unix-ls/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' not in response['contents']:
            raise F5ModuleError("Failed to obtain file information, aborting.")

        if 'Error' in response['contents']['commandResult'] or 'error' in response['contents']['commandResult']:
            raise F5ModuleError(response['contents']['commandResult'])

        if '/var/tmp/{0}'.format(self.want.file) not in response['contents']['commandResult']:
            raise F5ModuleError("Cannot get size of exported binary file, aborting")

        size = response['contents']['commandResult']

        self.want.file_size = int(size.split()[4])
        return True

    def _move_binary_to_download(self):
        name = '{0}~{1}'.format(self.client.plugin.get_user(), self.want.file)
        move_path = '/var/tmp/{0} {1}/{2}'.format(
            self.want.file,
            '/ts/var/rest',
            name
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
        url = "/mgmt/tm/asm/file-transfer/downloads/{0}".format(self.want.file)
        self.client.plugin.download_asm_file(url, dest, self.want.file_size)
        if os.path.exists(self.want.dest):
            return True
        return False

    def remove_temp_policy_from_device(self):
        name = '{0}~{1}'.format(self.client.plugin.user, self.want.file)
        tpath_name = '/ts/var/rest/{0}'.format(name)
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
            file=dict(),
            inline=dict(
                type='bool'
            ),
            compact=dict(
                type='bool'
            ),
            base64=dict(
                type='bool'
            ),
            binary=dict(
                type='bool'
            ),
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
        self.mutually_exclusive = [
            ['binary', 'inline'],
            ['binary', 'compact'],
            ['dest', 'inline'],
            ['file', 'inline']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
