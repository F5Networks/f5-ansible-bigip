#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_service_swg
short_description: Manage an SSL Orchestrator SWG service
description:
  - Manage an SSL Orchestrator Secure Web Gateway service.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the SWG service object.
      - The configuration auto-prepends C(ssloS_) to the object.
      - Names should be less than 14 characters and not contain dashes C(-).
    type: str
    required: True
  swg_policy:
    description:
      - Specifies the name of the SWG per-request policy to attach to the service configuration.
      - This parameter is required when creating a new service.
    type: str
  profile_scope:
    description:
      - Specifies the level of information sharing. When using named scope, an authentication access profile
        attached to the topology can share its user identity information with the SWG policy.
    type: str
    choices:
      - profile
      - named
  named_scope:
    description:
      - Required when C(profile_scope) is C(named), and specifies a name string the authentication
        and SWG policies share to allow access to identity information.
      - This parameter is ignored when C(profile_scope) is C(profile).
    type: str
  access_profile:
    description:
      - Specifies a custom SWG-Transparent access profile to apply to the SWG service.
      - During creation of a new SWG service, when the parameter is not specified, the configuration auto generates
        the access profile.
    type: str
  service_down_action:
    description:
      - Specifies the action taken if the SWG service fails.
    type: str
    choices:
      - ignore
      - reset
      - drop
  log_settings:
    description:
      - Specifies a custom log setting for the SWG service.
    type: list
    elements: str
  rules:
    description:
      - Specifies custom iRules to apply to the SWG service.
    type: list
    elements: str
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(yes) does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes to be made during
        C(MODIFY) on an existing service, no JSON output is generated.
    type: bool
    default: no
  timeout:
    description:
      - The amount of time to wait for the C(CREATE), C(MODIFY) or C(DELETE) task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the object is created or modified.
      - When C(state) is C(absent), ensures the service is removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
  - Kevin Stewart (@kevingstewart)
notes:
  - Requires SSLO >= 9.0
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
    - name: Create SSLO SWG service with defaults
      bigip_sslo_service_swg:
        name: "swg2"
        swg_policy: "/Common/test-swg"

    - name: Modify SSLO SWG service
      bigip_sslo_service_swg:
        name: "swg2"
        profile_scope: "named"
        named_scope: "SSLO"
        access_profile: "/Common/test-access"
        log_settings:
          - "/Common/default-log-setting1"
          - "/Common/default-log-setting2"
        rules:
          - "/Common/test-rule"

    - name: Delete SSLO SWG service
      bigip_sslo_service_swg:
        name: "swg2"
        state: "absent"
'''

RETURN = r'''
swg_policy:
  description:
    - The name of the SWG per-request policy attached to the service configuration.
  returned: changed
  type: str
  sample: /Common/my-swg-policy
profile_scope:
  description:
    - The the level of information sharing.
  returned: changed
  type: str
  sample: named
named_scope:
  description:
    - The name string the authentication and SWG policies share to allow access to identity information.
  returned: changed
  type: str
  sample: SSLO
access_profile:
  description:
    - A custom SWG-Transparent access profile to apply to the SWG service.
  returned: changed
  type: str
  sample: /Common/my-access-profile
service_down_action:
  description:
    - The action taken if the SWG service fails.
  returned: changed
  type: str
  sample: reset
log_settings:
  description:
    - The custom log setting for the SWG service.
  returned: changed
  type: str
  sample: /Common/my-log-settings
rules:
  description:
    - The custom iRules to apply to the SWG service.
  returned: changed
  type: str
  sample: /Common/my-swg-rule1
'''

import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)

from ..module_utils.compare import (
    compare_complex_list
)

from ..module_utils.sslo_templates.sslo_service_swg import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    returnables = [
        'swg_policy',
        'profile_scope',
        'named_scope',
        'access_profile',
        'service_down_action',
        'log_settings',
        'rules'
    ]

    updatables = [
        'swg_policy',
        'profile_scope',
        'named_scope',
        'access_profile',
        'service_down_action',
        'log_settings',
        'rules'
    ]


class ApiParameters(Parameters):
    @property
    def swg_policy(self):
        return self._values['customService']['serviceSpecific']['perReqPolicy']

    @property
    def profile_scope(self):
        return self._values['customService']['serviceSpecific']['accessProfileScope']

    @property
    def named_scope(self):
        return self._values['customService']['serviceSpecific']['accessProfileNameScopeValue']

    @property
    def access_profile(self):
        return self._values['customService']['serviceSpecific']['accessProfile']

    @property
    def service_down_action(self):
        return self._values['customService']['serviceDownAction']

    @property
    def log_settings(self):
        return self._values['customService']['serviceSpecific']['logSettings']

    @property
    def rules(self):
        return self._values['customService']['serviceSpecific']['iRuleList']


class ModuleParameters(Parameters):
    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloS_'):
            name = "ssloS_" + name
        return name

    @property
    def rules(self):
        if self._values['rules'] is None:
            return None
        if not any(self.name in rule for rule in self._values['rules']):
            rules = list()
            rules.append(f"/Common/{self.name}.app/{self.name}-swg")
            rules.extend(self._values['rules'])
        else:
            rules = self._values['rules']
        result = list()
        for rule in rules:
            element = dict()
            element['name'] = rule
            element['value'] = rule
            result.append(element)
        return result

    @property
    def log_settings(self):
        if self._values['log_settings'] is None:
            return None
        result = list()
        for item in self._values['log_settings']:
            element = dict()
            element['name'] = item
            element['value'] = item
            result.append(element)
        return result

    @property
    def named_scope(self):
        if self._values['named_scope'] is None:
            return None
        # we ignore this setting if the profile scope is set to profile
        if self.want.profile_scope == 'profile' and self._values['named_scope'] != "":
            return None
        return self._values['named_scope']

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
        delay = timeout / divisor

        return int(delay), divisor


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

    @property
    def log_settings(self):
        return compare_complex_list(self.want.log_settings, self.have.log_settings)

    @property
    def rules(self):
        return compare_complex_list(self.want.rules, self.have.rules)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

        # define a set of common instance variables used during module execution
        self.block_id = None
        self.operation = None
        self.version = None
        self.json_dump = None

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
            self.changes = UsableChanges(params=changed)
            return True
        return False

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

        self.check_sslo_version()

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        if self.json_dump:
            result.update(dict(json=self.json_dump))
        self._announce_deprecations(result)
        return result

    def check_sslo_version(self):
        self.version = sslo_version(self.client)
        if LooseVersion(self.version) > LooseVersion("9.9") or \
                LooseVersion(self.version) < LooseVersion("9.0"):
            raise F5ModuleError(
                "Unsupported SSL Orchestrator version, requires a version between 9.0 and 9.9"
            )
        return True

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
        if self.module.check_mode:
            return True
        self.operation = 'MODIFY'
        task_id, output = self.update_on_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.operation = 'DELETE'
        task_id, output = self.remove_from_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def create(self):
        self.check_for_required_create_parameters()
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.operation = 'CREATE'
        task_id, output = self.create_on_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def exists(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None):
            if response['contents']['items'][0]['name'] == self.want.name:
                self.block_id = response['contents']['items'][0]['id']
                return True
        return False

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_SERVICE_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation == 'MODIFY' or self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        return payload

    def check_for_required_create_parameters(self):
        if self.want.swg_policy is None:
            raise F5ModuleError(
                "The swg_policy parameter is not defined. "
                "Existing SWG per-request policy must be defined for CREATE operation."
            )

    def add_create_defaults(self, payload):
        # add create defaults for undefined values
        if self.want.access_profile is None:
            payload['access_profile'] = f"/Common/{self.want.name}.app/{self.want.name}_M_accessProfile"
        if self.want.rules is None:
            default_rule = f"/Common/{self.want.name}.app/{self.want.name}-swg"
            payload['rules'] = [dict(name=default_rule, value=default_rule)]
        if self.want.log_settings is None:
            payload['log_settings'] = [dict(name="/Common/default-log-setting", value="/Common/default-log-setting")]
        if self.want.service_down_action is None:
            payload['service_down_action'] = 'reset'
        if self.want.profile_scope is None:
            payload['profile_scope'] = 'profile'
        return payload

    def add_missing_options(self, payload):
        # used during modify operation, to avoid repetition if missing some mandatory values we use in device config
        # to complete the input
        if self.changes.access_profile is None:
            payload['access_profile'] = self.have.access_profile
        if self.changes.swg_policy is None:
            payload['swg_policy'] = self.have.swg_policy
        if self.changes.profile_scope is None:
            payload['profile_scope'] = self.have.profile_scope
        if self.changes.named_scope is None:
            payload['named_scope'] = self.have.named_scope
        if self.changes.service_down_action is None:
            payload['service_down_action'] = self.have.service_down_action
        if self.changes.log_settings is None:
            payload['log_settings'] = self.have.log_settings
        if self.changes.rules is None:
            payload['rules'] = self.have.rules
        return payload

    def create_on_device(self):
        payload = self.changes.to_return()
        data = self.add_create_defaults(self.add_json_metadata(payload))

        output = process_json(data, create_modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def update_on_device(self):
        payload = self.changes.to_return()
        data = self.add_missing_options(self.add_json_metadata(payload))

        output = process_json(data, create_modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def remove_from_device(self):
        data = self.add_json_metadata()

        output = process_json(data, delete)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def read_current_from_device(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('items', None) and response['contents']['items'][0]['name'] == self.want.name:
            returned_json = response['contents']['items'][0]['inputProperties'][0]['value']
            self.block_id = response['contents']['items'][0]['id']
            return ApiParameters(params=returned_json)
        raise F5ModuleError(response['contents'])

    def delete_failed_operation_on_device(self, task):
        # use this method to delete the operation that failed
        # if there are any http errors we ignore them
        uri = "/mgmt/shared/iapp/blocks/{0}".format(task)
        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202]:
            return True
        else:
            return False

    def wait_for_task(self, task_id):
        error = None
        delay, period = self.want.timeout
        for x in range(0, period):
            task = self._check_task_on_device(task_id)
            if task['state'] == 'BOUND':
                return True
            if task['state'] == 'ERROR':
                error = str(task['error'])
                break
            time.sleep(delay)
        if error:
            self.delete_failed_operation_on_device(task_id)
            raise F5ModuleError(f"{self.operation} operation error: {task_id} : {error}")
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _check_task_on_device(self, task_id):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=id+eq+'{task_id}'"
        response = self.client.get(uri + query)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['items'][0]


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            swg_policy=dict(),
            profile_scope=dict(
                choices=["profile", "named"]
            ),
            named_scope=dict(),
            access_profile=dict(),
            service_down_action=dict(
                choices=["ignore", "reset", "drop"]
            ),
            log_settings=dict(
                type='list',
                elements='str'
            ),
            rules=dict(
                type='list',
                elements='str'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            dump_json=dict(
                type='bool',
                default='no'
            )
        )
        self.required_if = [
            ['profile_scope', 'named', ['named_scope']]
        ]
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
