#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigiq_regkey_pool
short_description: Manages registration key pools on BIG-IQ
description:
  - Manages registration key (regkey) pools on a BIG-IQ. These pools function as
    a container in-which you will add lists of registration keys. To add registration
    keys, use the C(bigiq_regkey_license) module.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the registration key pool.
      - You must be mindful to name your registration pools unique names. While
        BIG-IQ does not require this, this module does. If you do not do this,
        the behavior of the module is undefined and you may end up putting
        licenses in the wrong registration key pool.
    type: str
    required: True
  description:
    description:
      - A description to attach to the pool.
    type: str
  state:
    description:
      - The state of the regkey pool on the system.
      - When C(present), guarantees that the pool exists.
      - When C(absent), removes the pool, and the licenses it contains, from the
        system.
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
    ansible_network_os: f5networks.f5_bigip.bigiq
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Create a registration key (regkey) pool to hold individual device licenses
      bigiq_regkey_pool:
        name: foo-pool
        state: present
'''

RETURN = r'''
description:
  description: New description of the regkey pool.
  returned: changed
  type: str
  sample: My description
'''
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        'description'
    ]

    returnables = [
        'description'
    ]

    updatables = [
        'description'
    ]

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class ModuleParameters(Parameters):
    @property
    def uuid(self):
        """Returns UUID of a given name

        Will search for a given name and return the first one returned to us. If no name,
        and therefore no ID, is found, will return the string "none". The string "none"
        is returned because if we were to return the None value, it would cause the
        license loading code to append a None string to the URI; essentially asking the
        remote device for its collection (which we dont want and which would cause the SDK
        to return an False error.

        :return:
        """
        collection = self.read_current_from_device()
        resource = next((x for x in collection if x.name == self._values['name']), None)
        if resource:
            return resource.id
        else:
            return "none"

    def read_current_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if 'items' not in response['contents']:
            return []

        result = [ApiParameters(params=r) for r in response['contents']['items']]

        return result


class ApiParameters(Parameters):
    @property
    def uuid(self):
        return self._values['id']


class Changes(Parameters):
    pass


class ReportableChanges(Changes):
    pass


class UsableChanges(Changes):
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
        self.want = ModuleParameters(client=self.client, params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

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
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = Changes(params=changed)
            return True
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

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

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def exists(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}".format(self.want.uuid)
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

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
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.want.api_params()
        params['name'] = self.want.name
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}".format(self.want.uuid)
        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}".format(self.want.uuid)
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = "/mgmt/cm/device/licensing/pool/regkey/licenses/{0}".format(self.want.uuid)
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            description=dict(),
            state=dict(
                default='present',
                choices=['absent', 'present']
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
