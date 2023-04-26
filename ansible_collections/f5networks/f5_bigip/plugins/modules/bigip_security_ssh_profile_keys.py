#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_security_ssh_profile_keys
short_description: Manage SSH proxy security key management on a BIG-IP
description:
  - Manage SSH proxy security profile private and public keys for SSH proxy on a BIG-IP.
version_added: 1.13.0
options:
  name:
    description:
      - Specifies the name of object to hold key information on the SSH security profile.
    type: str
    required: True
  profile_name:
    description:
      - Specifies the name of the SSH security profile to which this rule applies.
    type: str
    required: True
  proxy_client_public_key:
    description:
      - Proxy client authentication public key.
    type: str
  proxy_client_private_key:
    description:
      - Proxy client authentication private key.
      - To update this key the C(force) option must be set to C(true).
    type: str
  proxy_server_public_key:
    description:
      - Proxy server authentication public key.
    type: str
  proxy_server_private_key:
    description:
      - Proxy server authentication private key.
      - To update this key the C(force) option must be set to C(true).
    type: str
  real_server_public_key:
    description:
      - Real server public key.
    type: str
  force:
    description:
      - Set this option to C(true) when updating existing private keys, as private keys are encrypted on the device
        there is no other way to update them while keeping the module idempotent.
    type: bool
    default: false
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the SSH proxy security authentication is created.
      - When C(absent), ensures the SSH proxy security authentication is removed.
    type: str
    choices:
      - absent
      - present
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
    - name: Add SSH keys to ssh proxy security profile
      bigip_security_ssh_profile_keys:
        name: auth1
        profile_name: ssh_test
        proxy_client_private_key: "XXXXXXXXXXXXXXXXXX"
        proxy_client_public_key: "YYYYYYYYYYYYYYYYYYY"
        proxy_server_public_key: "CCCCCCCCCCCCCCCCCCC"
        proxy_server_private_key: "BBBBBBBBBBBBBBBBBB"
        real_server_public_key: "AAAAAAAAAAAAAAAAAAAA"

    - name: Modify SSH private keys on ssh proxy security profile - force on
      bigip_security_ssh_profile_keys:
        name: auth1
        profile_name: ssh_test
        proxy_client_private_key: "XXXXXXXXXXXXXXXXXX"
        proxy_server_private_key: "BBBBBBBBBBBBBBBBBB"
        force: yes

    - name: Remove SSH keys from ssh proxy security profile
      bigip_security_ssh_profile_keys:
        name: auth1
        profile_name: ssh_test
        state: absent
'''

RETURN = r'''
proxy_client_private_key:
  description: Proxy client authentication private key.
  returned: changed
  type: str
  sample: "XXXXXXXXXXXX"
proxy_client_public_key:
  description: Proxy client authentication private key.
  returned: changed
  type: str
  sample: "XXXXXXXXXXXX"
proxy_server_public_key:
  description: Proxy server authentication public key.
  returned: changed
  type: str
  sample: "XXXXXXXXXXXX"
proxy_server_private_key:
  description: Proxy server authentication private key.
  returned: changed
  type: str
  sample: "XXXXXXXXXXXX"
real_server_public_key:
  description: Real server public key.
  returned: changed
  type: str
  sample: "XXXXXXXXXXXX"
'''

from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean, transform_name
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'proxyClientAuth': 'proxy_client_auth',
        'proxyServerAuth': 'proxy_server_auth',
        'realServerAuth': 'real_server_auth'
    }

    api_attributes = [
        'proxyClientAuth',
        'proxyServerAuth',
        'realServerAuth'
    ]

    returnables = [
        'proxy_client_public_key',
        'proxy_client_private_key',
        'proxy_server_public_key',
        'proxy_server_private_key',
        'real_server_public_key'
    ]

    updatables = [
        'proxy_client_public_key',
        'proxy_client_private_key',
        'proxy_server_public_key',
        'proxy_server_private_key',
        'real_server_public_key'
    ]


class ApiParameters(Parameters):
    @property
    def proxy_client_public_key(self):
        if not self._values['proxy_client_auth']:
            return None
        return self._values['proxy_client_auth'].get('publicKey')

    @property
    def proxy_client_private_key(self):
        if not self._values['proxy_client_auth']:
            return None
        return self._values['proxy_client_auth'].get('privateKey')

    @property
    def proxy_server_public_key(self):
        if not self._values['proxy_server_auth']:
            return None
        return self._values['proxy_server_auth'].get('publicKey')

    @property
    def proxy_server_private_key(self):
        if not self._values['proxy_client_auth']:
            return None
        return self._values['proxy_server_auth'].get('privateKey')

    @property
    def real_server_public_key(self):
        if not self._values['real_server_auth']:
            return None
        return self._values['real_server_auth'].get('publicKey')


class ModuleParameters(Parameters):
    @property
    def force(self):
        result = flatten_boolean(self._values['force'])
        if result == 'yes':
            return True
        return False


class Changes(Parameters):
    def to_return(self):  # pragma: no cover
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    @property
    def proxy_client_auth(self):
        result = self._filter_params(dict(
            privateKey=self._values['proxy_client_private_key'],
            publicKey=self._values['proxy_client_public_key']
        ))
        if result:
            return result

    @property
    def proxy_server_auth(self):
        result = self._filter_params(dict(
            privateKey=self._values['proxy_server_private_key'],
            publicKey=self._values['proxy_server_public_key']
        ))
        if result:
            return result

    @property
    def real_server_auth(self):
        result = self._filter_params(dict(
            publicKey=self._values['real_server_public_key']
        ))
        if result:
            return result


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
        except AttributeError:  # pragma: no cover
            return attr1

    @property
    def proxy_client_private_key(self):
        if self.want.proxy_client_private_key is None:
            return None
        if self.have.proxy_client_private_key is None:
            return self.want.proxy_client_private_key
        if self.want.proxy_client_private_key != self.have.proxy_client_private_key:
            if self.want.force:
                return self.want.proxy_client_private_key
            return None

    @property
    def proxy_server_private_key(self):
        if self.want.proxy_server_private_key is None:
            return None
        if self.have.proxy_server_private_key is None:
            return self.want.proxy_server_private_key
        if self.want.proxy_server_private_key != self.have.proxy_server_private_key:
            if self.want.force:
                return self.want.proxy_server_private_key
            return None


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

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):  # pragma: no cover
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):  # pragma: no cover
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
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def profile_exists(self):
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(self.want.partition, self.want.profile_name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            raise F5ModuleError(
                f"The ssh profile {self.want.profile_name} does not exist in {self.want.partition} partition."
            )
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def exists(self):
        self.profile_exists()
        ssh_profile = transform_name(self.want.partition, self.want.profile_name)
        uri = f"/mgmt/tm/security/ssh/profile/{ssh_profile}/auth-info/{self.want.name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        ssh_profile = transform_name(self.want.partition, self.want.profile_name)

        uri = f"/mgmt/tm/security/ssh/profile/{ssh_profile}/auth-info"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        ssh_profile = transform_name(self.want.partition, self.want.profile_name)
        uri = f"/mgmt/tm/security/ssh/profile/{ssh_profile}/auth-info/{self.want.name}"

        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        ssh_profile = transform_name(self.want.partition, self.want.profile_name)
        uri = f"/mgmt/tm/security/ssh/profile/{ssh_profile}/auth-info/{self.want.name}"

        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        ssh_profile = transform_name(self.want.partition, self.want.profile_name)
        uri = f"/mgmt/tm/security/ssh/profile/{ssh_profile}/auth-info/{self.want.name}"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            profile_name=dict(required=True),
            proxy_client_public_key=dict(),
            proxy_client_private_key=dict(no_log=True),
            proxy_server_public_key=dict(),
            proxy_server_private_key=dict(no_log=True),
            real_server_public_key=dict(),
            force=dict(
                type='bool',
                default=False
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
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


if __name__ == '__main__':  # pragma: no cover
    main()
