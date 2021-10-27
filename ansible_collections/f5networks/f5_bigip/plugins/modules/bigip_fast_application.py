#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_fast_application
short_description: Manages FAST application declarations sent to BIG-IP
description:
  - Manages FAST application declarations sent to the BIG-IP.
version_added: "1.0.0"
options:
  content:
    description:
      - Declaration to be configured on the system.
      - This parameter is most often used along with the C(file) or C(template) lookup plugins.
        Refer to the examples section for correct usage.
      - For anything advanced or with formatting, consider using the C(template) lookup.
      - Additionally, this can be used for specifying application service configurations
        directly in YAML, however that is not an encouraged practice and, if used at all,
        should only be used for the absolute smallest of configurations to prevent your
        Playbooks from becoming too large.
      - If your C(content) includes encrypted values (such as ciphertexts, passphrases, etc),
        the returned C(changed) value is always true.
      - If you are using the C(to_nice_json) filter, it causes this module to fail because
        the purpose of that filter is to format the JSON to be human-readable and this process
        includes inserting extra characters that break JSON validators.
      - This parameter is required when C(state) is C(create) or C(present).
    type: raw
  tenant:
    description:
      - A FAST tenant name on which you want to manage the application.
      - This parameter is required when C(state) is C(present) or C(absent).
    type: str
  application:
    description:
      - A FAST application name you want to update or remove.
      - This parameter is required when C(tenant) is specified.
    type: str
  template:
    description:
      - Name of installed FAST template used to create the FAST application.
      - This parameter is only used when creating a new application, when C(state) is C(create).
    type: str
  timeout:
    description:
      - The amount of time to wait for the FAST async interface to complete its task, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(create), the declaration is used to create a new FAST application.
      - When C(state) is C(present), the existing FAST application is updated.
      - When C(state) is C(absent), ensures the existing FAST application is removed.
      - When C(state) is C(purge), ensures all FAST applications are removed from device.
    type: str
    choices:
      - create
      - present
      - absent
      - purge
    default: create
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
    - name: Create FAST application
      bigip_fast_application:
        template: "examples/simple_http"
        content: "{{ lookup('file', 'simple_http.json') }}"
        state: "create"

    - name: Update existing FAST application
      bigip_fast_application:
        tenant: "sample_tenant"
        application: "sample_app"
        content: "{{ lookup('file', 'simple_http_update.json') }}"
        state: "present"

    - name: Remove existing FAST application
      bigip_fast_application:
        tenant: "sample_tenant"
        application: "sample_app"
        state: "absent"

    - name: Remove all existing FAST applications on device
      bigip_fast_application:
        state: "purge"
'''

RETURN = r'''
content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
tenant:
  description: A FAST tenant name on which you want to manage application.
  returned: changed
  type: str
  sample: example_tenant
application:
  description: A FAST application name you want to update or remove.
  returned: changed
  type: str
  sample: simple_http
template:
  description: Name of the installed FAST template used to create the FAST application.
  returned: changed
  type: str
  sample: examples/simple_http
'''
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import string_types

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.version import CURRENT_COLL_VERSION

try:
    import json
except ImportError:
    import simplejson as json


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'content',
        'tenant',
        'application',
        'template'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def content(self):
        if self._values['content'] is None:
            return None
        if isinstance(self._values['content'], string_types):
            return json.loads(self._values['content'] or 'null')
        else:
            return self._values['content']

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 10 and 1800 seconds."
            )
        if timeout > 99:
            divisor = 100
        interval = timeout / divisor
        return interval, divisor


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

        if state == "create":
            changed = self.create()
        elif state == "present":
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

    def create(self):
        self.template_exists()
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.create_on_device()
        return result

    def present(self):
        if self.exists():
            return self.update()
        raise F5ModuleError(
            "The specified FAST Application: {0} in tenant: {1} has not been found.".format(
                self.want.application, self.want.tenant
            )
        )

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def update(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.upsert_on_device()
        return result

    def remove(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        result = self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return result

    def purge(self):
        if self.module.check_mode:
            return True
        result = self.purge_from_device()
        return result

    def create_on_device(self):
        interval, period = self.want.timeout
        declaration = {}
        try:
            declaration.update(self.want.content)
        except ValueError:
            raise F5ModuleError(
                "The provided 'content' could not be converted into valid json. If you "
                "are using the 'to_nice_json' filter, please remove it."
            )
        payload = dict(
            name=self.want.template,
            parameters=declaration
        )

        uri = "/mgmt/shared/fast/applications?userAgent=F5_BIGIP/{0}/{1}".format(
            CURRENT_COLL_VERSION, self.want.template
        )

        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/fast/tasks/{0}".format(
            response['contents']['message'][0]['id']), interval, period
        )
        if task:
            if task['message'] == 'no change':
                return False
            if task['message'] == 'success':
                return True

    def template_exists(self):
        uri = "/mgmt/shared/fast/templates"
        response = self.client.get(uri)

        if response['code'] == 200:
            if any(self.want.template == name for name in response['contents']):
                return True
            raise F5ModuleError(
                "The specified FAST template: {0} has not been found.".format(self.want.template)
            )
        # we need to handle 404 errors individually due to exists() method functionality
        # remaining errors are handled by connection plugin
        if response['code'] == 404:
            raise F5ModuleError(response['contents'])

    def exists(self):
        uri = "/mgmt/shared/fast/applications/{0}/{1}".format(self.want.tenant, self.want.application)
        response = self.client.get(uri)
        if response['code'] == 200:
            return True
        if response['code'] == 404:
            return False

    def _check_for_errors_in_response(self, response):
        if 'declaration failed' in response['message'] or 'declaration is invalid' in response['message']:
            raise F5ModuleError(response['message'])

    def _check_task_on_device(self, path):
        response = self.client.get(path)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']

    def upsert_on_device(self):
        interval, period = self.want.timeout
        uri = "/mgmt/shared/fast/applications/{0}/{1}".format(self.want.tenant, self.want.application)
        declaration = {}
        try:
            declaration.update(self.want.content)
        except ValueError:
            raise F5ModuleError(
                "The provided 'content' could not be converted into valid json. If you "
                "are using the 'to_nice_json' filter, please remove it."
            )

        payload = dict(parameters=declaration)
        response = self.client.patch(uri, data=payload)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/fast/tasks/{0}".format(
            response['contents']['message']['message'][0]['id']), interval, period
        )
        if task:
            if task['message'] == 'no change':
                return False
            if task['message'] == 'success':
                return True

    def wait_for_task(self, path, interval, period):
        for x in range(0, period):
            task = self._check_task_on_device(path)
            self._check_for_errors_in_response(task)
            if task['message'] != 'in progress':
                return task
            time.sleep(interval)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def remove_from_device(self):
        interval, period = self.want.timeout
        uri = "/mgmt/shared/fast/applications/{0}/{1}".format(self.want.tenant, self.want.application)

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/fast/tasks/{0}".format(response['contents']['id']), interval, period)
        if task:
            if task['message'] == 'success':
                return True

    def purge_from_device(self):
        interval, period = self.want.timeout
        uri = "/mgmt/shared/fast/applications/"

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/fast/tasks/{0}".format(response['contents']['id']), interval, period)
        if task:
            if task['message'] == 'success':
                return True
            if task['message'] == 'no change':
                return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            tenant=dict(),
            application=dict(),
            template=dict(),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='create',
                choices=['present', 'absent', 'purge', 'create']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'create', ['template', 'content']],
            ['state', 'present', ['tenant', 'content']],
            ['state', 'absent', ['tenant']]
        ]
        self.required_together = [
            ['tenant', 'application']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
        required_together=spec.required_together
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
