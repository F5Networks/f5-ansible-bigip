#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_service_o365_tr
short_description: Manage an SSL Orchestrator O365 Tenant Restriction security device
description:
  - Manage an SSL Orchestrator O365 Tenant Restriction security device
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the O365 Tenant Restriction security service.
      - The configuration auto-prepends "ssloS_" to the service.
      - The service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  restrict_access_to_tenant:
    description:
      - Specifies the tenant to restrict access to for the O365 Tenant Restriction service.
    type: str
  restrict_access_context:
    description:
      - Specifies the vendor-specific o365 tenant restrictions service used. The default is C(Generic o365 tenant restrictions Service).
    type: str
  rules:
    description:
      - Defines a list of iRules to attach to the service entry (ingress side).
      - Also known as "iRules on Service Entry".
    type: list
    elements: str
  service_down_action:
    description:
        - The action to take on monitor failure.
    type: str
    choices:
      - ignore
      - reset
      - drop
    default: ignore
  sub_type:
    description:
        - The action to take on o365 module type.
    type: str
    default: o365
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(true), does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes to be made during
        C(MODIFY) on an existing service, no JSON output is generated.
    type: bool
    default: false
  timeout:
    description:
      - The number of seconds to wait for the C(CREATE) or C(MODIFY) task to complete.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
        - Specifies the present/absent state required.
    type: str
    choices:
        - absent
        - present
    default: present
author:
  - Shweta Bakliwal (@bakliwal)
'''

EXAMPLES = r'''
- name: SSLO o365 tenant restriction service
  bigip_sslo_service_o365_tr:
    name: "o365_tr_test"
    restrict_access_to_tenant: "example_tenant"
    restrict_access_context: "Generic o365 tenant restrictions Service"
    rules:
      - "iRule1"
      - "iRule2"
'''

RETURN = r'''

restrict_access_to_tenant:
  description:
    - Specifies the tenant to restrict access to for the O365 Tenant Restriction service.
  returned: changed
  type: str
  sample: "example_tenant"
restrict_access_context:
  description:
    - Specifies the vendor-specific o365 tenant restrictions service used. The default is C(Generic o365 tenant restrictions Service).
  returned: changed
  type: str
  sample: "Generic o365 tenant restrictions Service"
rules:
  description:
    - Defines a list of iRules to attach to the service entry (ingress side).
    - Also known as "iRules on Service Entry".
  returned: changed
  type: list
  elements: str
  sample: ["/Common/test-rule-1", "/Common/test-rule-2"]
'''

import time
import traceback

try:
    from packaging.version import Version
except ImportError:
    HAS_PACKAGING = False
    Version = None
    PACKAGING_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_PACKAGING = True
    PACKAGING_IMPORT_ERROR = None

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)

from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version, check_sslo_provisioned
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)

from ..module_utils.constants import (
    min_sslo_version, max_sslo_version
)

from ..module_utils.compare import compare_dictionary, compare_complex_list_ordered
from ..module_utils.sslo_templates.sslo_service_o365_tr import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    updatables = [
        'restrict_access_to_tenant',
        'restrict_access_context',
        'rules',
        'sub_type',
        'service_down_action',
    ]
    returnables = [
        'restrict_access_to_tenant',
        'restrict_access_context',
        'rules',
        'sub_type',
        'service_down_action',
    ]


class ApiParameters(Parameters):

    @property
    def restrict_access_to_tenant(self):
        return self._values.get('customService', {}).get('serviceSpecific', {}).get('restrictAccessToTenant')

    @property
    def restrict_access_context(self):
        return self._values.get('customService', {}).get('serviceSpecific', {}).get('restrictAccessContext')

    @property
    def rules(self):
        irules = self._values.get('customService', {}).get('iRuleList', [])
        # Filter out the system-added default iRule that is automatically added by the device
        # The system iRule has a name that ends with '-f5-tenant-restrictions' and is in the service's app folder
        # This allows idempotent checks to work correctly without requiring users to include it
        filtered = [
            rule for rule in irules
            if not (isinstance(rule, dict) and rule.get('name', '').endswith('-f5-tenant-restrictions'))
        ]
        return filtered

    @property
    def sub_type(self):
        if 'subType' not in self._values.get('customService', {}).get('serviceSpecific', {}):
            return 'o365'
        return self._values['customService']['serviceSpecific']['subType']

    @property
    def service_down_action(self):
        return self._values.get('customService', {}).get('serviceDownAction')


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
    @property
    def rules(self):
        rules = self._values.get('rules')
        if rules is None:
            return None
        # Unwrap internal {name, value} dict form back to plain iRule names for user-facing output
        return [rule['name'] for rule in rules]


class ModuleParameters(Parameters):
    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloS_'):
            name = "ssloS_" + name
        return name

    @property
    def restrict_access_to_tenant(self):
        if self._values['restrict_access_to_tenant'] is None:
            return None
        return self._values['restrict_access_to_tenant']

    @property
    def restrict_access_context(self):
        if self._values['restrict_access_context'] is None:
            return "Generic o365 tenant restrictions Service"
        return self._values['restrict_access_context']

    @property
    def rules(self):
        rules = self._values['rules']
        if rules is None:
            return []
        # Convert plain iRule names to the {name, value} form the device API expects
        return [{'name': rule, 'value': rule} for rule in rules]

    @property
    def service_down_action(self):
        if self._values['service_down_action'] is None:
            return 'ignore'
        return self._values['service_down_action']

    @property
    def sub_type(self):
        if self._values['sub_type'] is None:
            return 'o365'
        return self._values['sub_type']

    @property
    def state(self):
        return self._values['state']

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 1800:
            raise F5ModuleError('Timeout must be between 10 and 1800 seconds')
        if timeout > 99:
            divisor = 100
        delay = timeout / divisor
        return int(delay), divisor

    @property
    def dump_json(self):
        return self._values['dump_json']


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
    def devices(self):
        want = self.want.devices
        have = self.have.devices
        diff = compare_dictionary(want, have)
        if diff:
            return diff

    @property
    def restrict_access_to_tenant(self):
        want = self.want.restrict_access_to_tenant
        have = self.have.restrict_access_to_tenant
        if want != have:
            return want
        return None

    @property
    def restrict_access_context(self):
        want = self.want.restrict_access_context
        have = self.have.restrict_access_context
        if want != have:
            return want
        return None

    @property
    def sub_type(self):
        want = self.want.sub_type
        have = self.have.sub_type
        if want != have:
            return want
        return None

    @property
    def rules(self):
        return compare_complex_list_ordered(self.want.rules, self.have.rules)


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

        check_sslo_provisioned(self.client)
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
        if Version(self.version) >= Version(max_sslo_version) or \
                Version(self.version) < Version(min_sslo_version):
            raise F5ModuleError(
                f"Unsupported SSL Orchestrator version, "
                f"requires a version between {min_sslo_version} and {max_sslo_version}"
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

    def check_for_required_create_parameters(self):
        if self.want.name is None:
            raise F5ModuleError(
                "The name parameter is required during CREATE operation."
            )

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

    def add_create_values(self, payload):
        # add create defaults for undefined values

        if self.changes.rules is None:
            payload['rules'] = None
        return payload

    def add_missing_options(self, payload):
        # used during modify operation, to avoid repetition if missing some mandatory values we use in device config
        # to complete the input

        if self.changes.restrict_access_to_tenant is None:
            payload['restrict_access_to_tenant'] = self.have.restrict_access_to_tenant
        if self.changes.restrict_access_context is None:
            payload['restrict_access_context'] = self.have.restrict_access_context
        if self.changes.rules is None:
            payload['rules'] = self.have.rules
        if self.changes.sub_type is None:
            payload['sub_type'] = self.have.sub_type
        if self.changes.service_down_action is None:
            payload['service_down_action'] = self.have.service_down_action
        # Ensure restrict_access_to_tenant is always in payload for MODIFY operations
        # This is needed to properly derive the subtype on the device
        if 'restrict_access_to_tenant' not in payload:
            if self.have.restrict_access_to_tenant:
                payload['restrict_access_to_tenant'] = self.have.restrict_access_to_tenant
            else:
                payload['restrict_access_to_tenant'] = "example_tenant"
        # Ensure restrict_access_context is always in payload for MODIFY operations
        # This is needed to properly derive the subtype on the device
        if 'restrict_access_context' not in payload:
            if self.have.restrict_access_context:
                payload['restrict_access_context'] = self.have.restrict_access_context
            else:
                payload['restrict_access_context'] = "Generic o365 tenant restrictions Service"
        # Ensure sub_type is always in payload for MODIFY operations
        if 'sub_type' not in payload:
            if self.have.sub_type:
                payload['sub_type'] = self.have.sub_type
            else:
                payload['sub_type'] = 'o365'
        return payload

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

    def create_on_device(self):
        payload = self.changes.to_return()
        data = self.add_create_values(self.add_json_metadata(payload))
        output = process_json(data, create_modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'] or 'id' not in response['contents']:
            raise F5ModuleError(f"Invalid response from device: {response['contents']}")

        task_id = str(response['contents']['id'])
        return task_id, None

    def update_on_device(self):
        payload = self.changes.to_return()
        data = self.add_missing_options(self.add_json_metadata(payload))

        output = process_json(data, create_modify)
        output['operation'] = 'MODIFY'

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'] or 'id' not in response['contents']:
            raise F5ModuleError(f"Invalid response from device: {response['contents']}")

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

        if not response['contents']:
            raise F5ModuleError("Invalid response from device: empty contents")

        if response['contents'].get('items', None) and response['contents']['items'][0]['name'] == self.want.name:
            returned_json = response['contents']['items'][0]['inputProperties'][0]['value']
            self.block_id = response['contents']['items'][0]['id']
            return ApiParameters(params=returned_json)
        raise F5ModuleError(response['contents'])

    def exists(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = f"?$filter=name+eq+'{self.want.name}'"
        response = self.client.get(uri + query)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents']:
            return False

        if response['contents'].get('items', None):
            if response['contents']['items'][0]['name'] == self.want.name:
                self.block_id = response['contents']['items'][0]['id']
                return True
        return False

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
        max_retries = 3
        for x in range(0, period):
            retries = 0
            task = None
            while retries < max_retries:
                try:
                    task = self._check_task_on_device(task_id)
                    break
                except F5ModuleError as ex:
                    if retries < max_retries - 1:
                        retries += 1
                        time.sleep(delay)
                    else:
                        raise
            if task and task['state'] == 'BOUND':
                return True
            if task and task['state'] == 'ERROR':
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
        try:
            response = self.client.get(uri + query)
        except Exception as ex:
            raise F5ModuleError(f"Failed to check task status: {str(ex)}")
        if response is None:
            raise F5ModuleError(f"No response from device when checking task {task_id}")
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if not response['contents'].get('items'):
            raise F5ModuleError(f"Task {task_id} not found on device")
        return response['contents']['items'][0]


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            restrict_access_to_tenant=dict(),
            restrict_access_context=dict(),
            rules=dict(type='list', elements='str'),
            sub_type=dict(default='o365'),
            service_down_action=dict(default='ignore', choices=['ignore', 'reset', 'drop']),
            state=dict(default='present', choices=['present', 'absent']),
            timeout=dict(type='int', default=300),
            dump_json=dict(type='bool', default=False),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    if not HAS_PACKAGING:
        module.fail_json(
            msg=missing_required_lib('packaging'),
            exception=PACKAGING_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
