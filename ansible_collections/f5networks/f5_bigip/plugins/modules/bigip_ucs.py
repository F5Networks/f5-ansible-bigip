#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ucs
short_description: Manage upload, installation, and removal of UCS files
description:
   - Manage upload, installation, and removal of UCS files on a BIG-IP system.
     A user configuration set (UCS) is a backup file that contains BIG-IP configuration
     data that can be used to fully restore a BIG-IP system in the event of a
     failure or RMA replacement.
version_added: "1.0.0"
options:
  include_chassis_level_config:
    description:
      - During restoration of the UCS file, includes chassis level configuration
        that is shared among boot volume sets. For example, the cluster default
        configuration.
    type: bool
  ucs:
    description:
      - The path to the UCS file to install. The parameter must be
        provided if the C(state) is either C(installed) or C(activated).
        When C(state) is C(absent), the full path for this parameter is
        ignored and only the filename is used to select a UCS for removal.
        Therefore you could specify C(/foo/bar/test.ucs) and this module
        would only look for C(test.ucs).
    type: str
    required: True
  force:
    description:
      - If C(yes), the system uploads the file every time and replaces the file on the
        device. If C(no), the file is only uploaded if it does not already
        exist. Generally should only be C(yes) in cases where you believe
        the image was corrupted during upload.
    type: bool
    default: no
  no_license:
    description:
      - Performs a full restore of the UCS file and all the files it contains,
        with the exception of the license file. The option must be used to
        restore a UCS on RMA (Returned Materials Authorization) devices.
    type: bool
  no_platform_check:
    description:
      - Bypasses the platform check and allows installation of a UCS that was
        created using a different platform. By default (without this option),
        installation of a UCS created from a different platform is not allowed.
    type: bool
  passphrase:
    description:
      - Specifies the passphrase that is necessary to load the specified UCS file.
    type: str
  reset_trust:
    description:
      - When specified, the device and trust domain certs and keys are not
        loaded from the UCS. Instead, a new set is generated.
    type: bool
  state:
    description:
      - When C(installed), ensures the UCS is uploaded and installed
        on the system. When C(present), ensures the UCS is uploaded.
        When C(absent), the UCS is removed from the system. When
        C(installed), the uploading of the UCS is idempotent, however the
        installation of that configuration is not idempotent.
    type: str
    choices:
      - absent
      - installed
      - present
    default: present
notes:
   - Only the most basic checks are performed by this module. Other checks and
     considerations need to be taken into account. See
     https://support.f5.com/kb/en-us/solutions/public/11000/300/sol11318.html
   - This module does not handle devices with the FIPS 140 HSM.
   - This module does not handle BIG-IPs systems on the 6400, 6800, 8400, or
     8800 hardware platforms.
   - This module does not verify the new or replaced SSH keys from the
     UCS file are synchronized between the BIG-IP system and the SCCP.
   - This module does not support the 'rma' option.
   - This module does not support restoring a UCS archive on a BIG-IP 1500,
     3400, 4100, 6400, 6800, or 8400 hardware platforms other than the system
     from which the backup was created.
   - The UCS restore operation restores the full configuration only if the
     hostname of the target system matches the hostname on which the UCS
     archive was created. If the hostname does not match, only the shared
     configuration is restored.
   - This module does not support re-licensing a BIG-IP restored from a UCS.
   - This module does not support restoring encrypted archives on replacement
     RMA unit.
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

- name: Upload UCS
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: present

- name: Install (upload, install) UCS.
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed

- name: Install (upload, install) UCS without installing the license portion
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    no_license: yes

- name: Install (upload, install) UCS except the license, and bypassing the platform check
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    no_license: yes
    no_platform_check: yes

- name: Install (upload, install) UCS using a passphrase necessary to load the UCS
  bigip_ucs:
    ucs: /root/bigip.localhost.localdomain.ucs
    state: installed
    passphrase: MyPassphrase1234

- name: Remove uploaded UCS file
  bigip_ucs:
    ucs: bigip.localhost.localdomain.ucs
    state: absent
'''

RETURN = r'''
# only common fields returned
'''

import os
import re
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


try:
    from collections import OrderedDict
except ImportError:
    try:
        from ordereddict import OrderedDict
    except ImportError:
        pass


class Parameters(AnsibleF5Parameters):
    api_map = {}
    updatables = []
    returnables = []
    api_attributes = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    def _check_required_if(self, parameter):
        if self._values[parameter] is not True:
            return self._values[parameter]
        if self.state != 'installed':
            raise F5ModuleError(
                '"{0}" parameters requires "installed" state'.format(parameter)
            )

    @property
    def basename(self):
        return os.path.basename(self.ucs)

    @property
    def options(self):
        return {
            'include-chassis-level-config': self.include_chassis_level_config,
            'no-license': self.no_license,
            'no-platform-check': self.no_platform_check,
            'passphrase': self.passphrase,
            'reset-trust': self.reset_trust
        }

    @property
    def reset_trust(self):
        self._check_required_if('reset_trust')
        return self._values['reset_trust']

    @property
    def passphrase(self):
        self._check_required_if('passphrase')
        return self._values['passphrase']

    @property
    def no_platform_check(self):
        self._check_required_if('no_platform_check')
        return self._values['no_platform_check']

    @property
    def no_license(self):
        self._check_required_if('no_license')
        return self._values['no_license']

    @property
    def include_chassis_level_config(self):
        self._check_required_if('include_chassis_level_config')
        return self._values['include_chassis_level_config']

    @property
    def install_command(self):
        cmd = 'tmsh load sys ucs /var/local/ucs/{0}'.format(self.basename)
        # Append any options that might be specified
        options = OrderedDict(sorted(self.options.items(), key=lambda t: t[0]))
        for k, v in options.items():
            if v is False or v is None:
                continue
            elif k == 'passphrase':
                cmd += ' %s %s' % (k, v)
            else:
                cmd += ' %s' % (k)
        return cmd


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


class ReportableChanges(Changes):
    pass


class UsableChanges(Changes):
    pass


class Difference(object):
    pass


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
        state = self.want.state

        if state in ['present', 'installed']:
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def update(self):
        if self.module.check_mode:
            if self.want.force:
                return True
            return False
        elif self.want.force:
            self.remove()
            return self.create()
        elif self.want.state == 'installed':
            return self.install_on_device()
        else:
            return False

    def create(self):
        if self.module.check_mode:
            return True
        self.create_on_device()
        if not self.exists():
            raise F5ModuleError("Failed to upload the UCS file")
        if self.want.state == 'installed':
            self.install_on_device()
        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the UCS file")
        return True

    def exists(self):
        collection = self.read_current_from_device()
        if self.want.basename in collection:
            return True
        return False

    def wait_for_rest_api_restart(self):
        for x in range(0, 20):
            time.sleep(10)
            try:
                response = self.client.get('/mgmt/tm/util/available')
                if response['code'] == 200:
                    break
            except Exception:
                raise

    def wait_for_configuration_reload(self):
        noops = 0
        while noops < 4:
            time.sleep(3)
            params = dict(command="run",
                          utilCmdArgs='-c "tmsh show sys mcp-state"'
                          )
            uri = "/mgmt/tm/util/bash"

            response = self.client.post(uri, data=params)

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if 'commandResult' not in response['contents']:
                continue

            result = response['contents']['commandResult']

            if self._is_config_reloading_failed_on_device(result):
                raise F5ModuleError(
                    "Failed to reload the configuration. This may be due "
                    "to a cross-version incompatibility. {0}".format(result)
                )
            if self._is_config_reloading_success_on_device(result):
                if self._is_config_reloading_running_on_device(result):
                    noops += 1
                    continue
            noops = 0

    def _is_config_reloading_success_on_device(self, output):
        succeed = r'Last Configuration Load Status\s+full-config-load-succeed'
        matches = re.search(succeed, output)
        if matches:
            return True
        return False

    def _is_config_reloading_running_on_device(self, output):
        running = r'Running Phase\s+running'
        matches = re.search(running, output)
        if matches:
            return True
        return False

    def _is_config_reloading_failed_on_device(self, output):
        failed = r'Last Configuration Load Status\s+base-config-load-failed'
        matches = re.search(failed, output)
        if matches:
            return True
        return False

    def upload_file_to_device(self, content, name):
        try:
            self.client.plugin.upload_file("/mgmt/shared/file-transfer/uploads", content, name)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def create_on_device(self):
        remote_path = "/var/local/ucs"
        tpath_name = '/var/config/rest/downloads'
        self.upload_file_to_device(self.want.ucs, self.want.basename)

        uri = "/mgmt/tm/util/unix-mv/"
        args = dict(
            command='run',
            utilCmdArgs='{0}/{2} {1}/{2}'.format(
                tpath_name, remote_path, self.want.basename
            )
        )
        response = self.client.post(uri, data=args)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def remove_from_device(self):
        params = dict(command="run",
                      utilCmdArgs='-c "tmsh delete sys ucs {0}"'.format(self.want.basename)
                      )
        uri = "/mgmt/tm/util/bash"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'commandResult' in response['contents']:
            if '{0} is deleted'.format(self.want.basename) in response['contents']['commandResult']:
                return True
        return False

    def install_on_device(self):
        params = dict(command="run", utilCmdArgs='-c "{0}"'.format(self.want.install_command))
        uri = "/mgmt/tm/util/bash"

        response = self.client.post(uri, data=params)

        if response['code'] in [400, 403]:
            raise F5ModuleError(response['contents'])

        if response['code'] in [401, 404, 503]:
            # services might start to restart immediately so its better to catch the error and move on
            pass
        self.wait_for_rest_api_restart()
        self.wait_for_configuration_reload()
        return True

    def read_current_from_device(self):
        result = []
        uri = "/mgmt/tm/sys/ucs/"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        items = response['contents'].get('items', [])

        for item in items:
            result.append(os.path.basename(item['apiRawValues']['filename']))
        return result


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            force=dict(
                type='bool',
                default='no'
            ),
            include_chassis_level_config=dict(
                type='bool'
            ),
            no_license=dict(
                type='bool'
            ),
            no_platform_check=dict(
                type='bool'
            ),
            passphrase=dict(no_log=True),
            reset_trust=dict(type='bool'),
            state=dict(
                default='present',
                choices=['absent', 'installed', 'present']
            ),
            ucs=dict(required=True)
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
