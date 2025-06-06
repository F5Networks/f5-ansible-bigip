#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: bigip_as3_deploy
short_description: Manages AS3 declarations sent to BIG-IP
description:
  - Manages AS3 declarations sent to the BIG-IP.
version_added: "1.0.0"
options:
  content:
    description:
      - The declaration to be configured on the system.
      - This parameter is most often used with the C(file) or C(template) lookup plugins.
        Refer to the examples section for correct usage.
      - For anything advanced or with formatting, consider using the C(template) lookup.
      - Additionally, this can be used for specifying application service configurations
        directly in YAML. However that is not an encouraged practice and, if used at all,
        should only be used for the absolute smallest of configurations to prevent your
        Playbooks from becoming too large.
      - If your C(content) includes encrypted values (such as ciphertexts, passphrases, etc),
        the returned C(changed) value will always be true.
      - If you are using the C(to_nice_json) filter, it causes this module to fail because
        the purpose of that filter is to format the JSON to be human-readable and this process
        includes inserting extra characters that break JSON validators.
    type: raw
  tenant:
    description:
      - tenant is mandatory for Per-Application Deployment
      - An AS3 tenant you want to manage.
      - A value of C(all) when C(state) is C(absent) removes all AS3 declarations from the device.
    type: str
  as3_apps_delete:
    description:
      - A list of AS3 application names to be deleted from a tenant.
      - This parameter is only relevant when I(state) is C(absent).
      - When provided, only the specified applications will be removed from the tenant instead of the entire tenant.
      - This parameter is ignored if I(tenant) is set to C(all).
    type: list
    elements: str
    version_added: "3.13.0"
  timeout:
    description:
      - The amount of time to wait for the AS3 async interface to complete its task, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  controls:
    version_added: "3.9.0"
    description:
      - Optional controls configuration.
      - The controls options can also be specified in the as3 declaration itself.
      - Do not specify the controls options in both the as3 declaration and the module parameters, as this will raise an error.
    type: dict
    suboptions:
      dry_run:
        description:
          - If C(true), the declaration is not deployed to the device.
        type: bool
      log_level:
        description:
          - Controls the amount of detail in logs produced while configuring the tenant.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - error
          - warning
          - notice
          - info
          - debug
      trace:
        description:
          - If C(true), BIG-IP AS3 creates a detailed trace of the configuration process for this Tenant for subsequent analysis.
        type: bool
      trace_response:
        description:
          - If set to C(true), the response will contain the trace files.
        type: bool
      user_agent:
        description:
          - User Agent information to include in TEEM report.
        type: str
  state:
    description:
      - When C(state) is C(present), ensures the declaration is exists.
      - When C(state) is C(absent), ensures the declaration is removed.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - For Traditional Deployment should contian the Tenant information inside it.
    Traditional Deployment dosen't depend on C(perAppDeploymentAllowed) value.
  - For Per-Application Deployment C(perAppDeploymentAllowed) should be set to true.
    Per-Application declaration shouldn't contain Tenant information inside it.
    Per-Application deployments is supported from AS3 versions>=3.50.0
    Tenant parameter is mandatory for Per-Application Deployments
    More infotmation can be found here https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/per-app-declarations.html
  - Applications must exist in the specified tenant for deletion to succeed.
  - Each application will be deleted individually via a separate API call.
  - If any application in the list doesn't exist, it will be skipped without causing an error.
  - When using this parameter, the tenant itself will remain after the specified applications are deleted.
  - Regarding the controls parameter, in this document,
    https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/refguide/as3-api.html#query-parameters-for-controls-objects,
    it is mentioned that controls parameters specified in the url as query parameters will override the controls parameters specified in the declaration,
    but due to a bug that behaviour is not seen, so it is recommended that the user should specify controls options either in the module parameters or in
    the AS3 declaration. Note that using the controls parameter in this module uses url query parameters behind the scenes.

author:
  - Ravinder Reddy (@chinthalalalli)
  - Wojciech Wypior (@wojtek0806)
  - Prateek Ramani (@ramani)
"""

EXAMPLES = r"""
- name: Declaration with 2 Tenants - AS3
  bigip_as3_deploy:
    content: |
      {
        "class": "AS3",
        "action": "deploy",
        "persist": true,
        "declaration": {
          "class": "ADC",
          "schemaVersion": "3.0.0",
          "id": "urn:uuid:33045210-3ab8-4636-9b2a-c98d22ab915d",
          "label": "Sample 1",
          "remark": "Simple HTTP application with RR pool",
          "Sample_01": {
            "class": "Tenant",
            "A1": {
              "class": "Application",
              "template": "http",
              "serviceMain": {
                "class": "Service_HTTP",
                "virtualAddresses": [
                  "10.0.1.10"
                ],
                "pool": "web_pool"
              },
              "web_pool": {
                "class": "Pool",
                "monitors": [
                  "http"
                ],
                "members": [{
                  "servicePort": 80,
                  "serverAddresses": [
                    "192.0.1.10",
                    "192.0.1.11"
                  ]
                }]
              }
            }
          },
          "Sample_02": {
            "class": "Tenant",
            "A1": {
              "class": "Application",
              "template": "http",
              "serviceMain": {
                "class": "Service_HTTP",
                "virtualAddresses": [
                  "10.0.1.11"
                ],
                "pool": "web_pool2"
              },
              "web_pool2": {
                "class": "Pool",
                "monitors": [
                  "http"
                ],
                "members": [{
                  "servicePort": 80,
                  "serverAddresses": [
                    "192.0.1.12",
                    "192.0.1.13"
                  ]
                }]
              }
            }
          }
        }
      }

- name: Deploying Per-App Declaration
  bigip_as3_deploy:
    content: |
      {
        "schemaVersion": "3.48.0",
        "Application1": {
          "class": "Application",
          "service": {
            "class": "Service_HTTP",
            "virtualAddresses": [
              "192.0.10.1"
            ],
            "pool": "pool"
          },
          "pool": {
            "class": "Pool",
            "members": [
              {
                "servicePort": 80,
                "serverAddresses": [
                  "192.0.10.1",
                  "192.0.10.2"
                ]
              }
            ]
          }
        }
      }
    tenant: sample

- name: Deleting AS3 Application using as3_apps_delete
  bigip_as3_deploy:
    content: "{{ lookup('file', '<path_of_as3>/as3_2apps.json') }}"
    tenant: "as3-tenant"
    as3_apps_delete:
      - A2
      - A2
    state: absent

- name: Declaration with 2 Tenants with controls parameters - AS3
  bigip_as3_deploy:
    content: |
      {
        "class": "AS3",
        "action": "deploy",
        "persist": true,
        "declaration": {
          "class": "ADC",
          "schemaVersion": "3.0.0",
          "id": "urn:uuid:33045210-3ab8-4636-9b2a-c98d22ab915d",
          "label": "Sample 1",
          "remark": "Simple HTTP application with RR pool",
          "Sample_01": {
            "class": "Tenant",
            "A1": {
              "class": "Application",
              "template": "http",
              "serviceMain": {
                "class": "Service_HTTP",
                "virtualAddresses": [
                  "10.0.1.10"
                ],
                "pool": "web_pool"
              },
              "web_pool": {
                "class": "Pool",
                "monitors": [
                  "http"
                ],
                "members": [{
                  "servicePort": 80,
                  "serverAddresses": [
                    "192.0.1.10",
                    "192.0.1.11"
                  ]
                }]
              }
            }
          },
          "Sample_02": {
            "class": "Tenant",
            "A1": {
              "class": "Application",
              "template": "http",
              "serviceMain": {
                "class": "Service_HTTP",
                "virtualAddresses": [
                  "10.0.1.11"
                ],
                "pool": "web_pool2"
              },
              "web_pool2": {
                "class": "Pool",
                "monitors": [
                  "http"
                ],
                "members": [{
                  "servicePort": 80,
                  "serverAddresses": [
                    "192.0.1.12",
                    "192.0.1.13"
                  ]
                }]
              }
            }
          }
        }
      }
    controls:
      log_level: debug
      trace: true
      trace_response: true

- name: Controls parameter in declaration as well as module parameters will result in error, NOT RECOMMENDED
  bigip_as3_deploy:
    controls:
      dry_run: true
    content: |
      {
        "action": "deploy",
        "class": "AS3",
        "declaration": {
          "Sample_xyz": {
            "A1": {
              "class": "Application",
              "serviceMain": {
                "class": "Service_HTTP",
                "pool": "web_pool",
                "virtualAddresses": [
                  "10.0.1.10"
                ]
              },
              "template": "http",
              "web_pool": {
                "class": "Pool",
                "members": [
                  {
                    "serverAddresses": [
                      "192.0.1.10",
                      "192.0.1.11"
                    ],
                    "servicePort": 80
                  }
                ],
                "monitors": [
                  "http"
                ]
              }
            },
            "class": "Tenant"
          },
          "class": "ADC",
          "id": "urn:uuid:33045210-3ab8-4636-9b2a-c98d22ab915d",
          "label": "Sample 1",
          "remark": "Simple HTTP application with RR pool",
          "schemaVersion": "3.0.0",
          "controls": {
            "class": "Controls",
            "dryRun": false
          }
        },
        "persist": true
      }
  ignore_errors: true
  register: result

- name: Assert expect error due to controls parameter conflict
  assert:
    that:
      - result is failed
      - >
        "'Controls parameters provided in both, the AS3 declaration
        and module parameters. Please provide the controls parameters
        in only one place.' in result.msg"

- name: Remove one tenant - AS3
  bigip_as3_deploy:
    tenant: "Sample_01"
    state: absent
"""

RETURN = r"""
content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
tenant:
  description: The AS3 tenant to be managed.
  returned: changed
  type: str
  sample: foobar1
"""
import time
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import string_types

from ..module_utils.client import F5Client, send_teem
from ..module_utils.common import (
    F5ModuleError,
    AnsibleF5Parameters,
    check_for_atc_errors,
    F5ATCError,
    flatten_boolean,
)

try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        "content",
        "tenant",
        "as3_apps_delete",
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
        delay = timeout / divisor

        return delay, divisor


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
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        result.update(dict(changed=changed))
        send_teem(self.client, start)
        return result

    def upsert(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        result = self.upsert_on_device()
        return result

    def present(self):
        if self.exists():
            return False
        return self.upsert()

    def absent(self):
        if self.resource_exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        result = self.remove_from_device()
        if self.resource_exists():
            raise F5ModuleError("Failed to delete the resource.")
        return result

    def exists(self):
        declaration = {}
        if self.want.content is None:
            raise F5ModuleError(
                "Empty content cannot be specified when 'state' is 'present'."
            )
        try:
            declaration.update(self.want.content)
        except ValueError:
            raise F5ModuleError(
                "The provided 'content' could not be converted into valid json. If you "
                "are using the 'to_nice_json' filter, please remove it."
            )

        perAppDeploymentAllowed = self.check_settings()
        tenantList = self.get_tenant_list()

        if perAppDeploymentAllowed and len(tenantList) == 0:
            return False
        else:
            self._check_control_queries_conflict()

            if declaration.get('class') != 'AS3':
                declaration = {
                    'class': 'AS3',
                    'persist': False,
                    'declaration': declaration,
                }

            if self.want.tenant:
                uri = "/mgmt/shared/appsvcs/declare/{0}?controls.dryRun=true".format(self.want.tenant)
            else:
                uri = "/mgmt/shared/appsvcs/declare?controls.dryRun=true"

        response = self.client.post(uri, data=declaration)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        return all(
            msg.get("message", None) == "no change"
            for msg in response["contents"]["results"]
        )

    def _check_task_on_device(self, path):
        response = self.client.get(path)
        if response["code"] not in [200, 201, 202]:
            raise F5ModuleError(response["contents"])
        return response["contents"]

    def get_control_queries(self):
        control_queries = ""

        if self.want.controls is not None:
            log_level = self.want.controls.get("log_level")
            user_agent = self.want.controls.get("user_agent")
            trace = (
                "true"
                if flatten_boolean(self.want.controls.get("trace")) == "yes"
                else "false"
            )
            trace_response = (
                "true"
                if flatten_boolean(self.want.controls.get("trace_response")) == "yes"
                else "false"
            )
            dry_run = (
                "true"
                if flatten_boolean(self.want.controls.get("dry_run")) == "yes"
                else "false"
            )

            control_queries += (
                f"&controls.dryRun={dry_run}" if dry_run == "true" else ""
            )
            control_queries += (
                f"&controls.logLevel={log_level}" if log_level is not None else ""
            )
            control_queries += f"&controls.trace={trace}" if trace == "true" else ""
            control_queries += (
                f"&controls.traceResponse={trace_response}"
                if trace_response == "true"
                else ""
            )
            control_queries += (
                f"&controls.userAgent={user_agent}" if user_agent is not None else ""
            )

        return control_queries

    def _check_control_queries_conflict(self):
        as3json = self.want.content
        if as3json.get("declaration") is not None:
            declaration = as3json["declaration"]
            if declaration.get("controls") is not None and self.want.controls is not None:
                raise F5ModuleError(
                    "Controls parameters provided in both, the AS3 declaration and module parameters. "
                    "Please provide the controls parameters in only one place."
                )

    def upsert_on_device(self):
        delay, period = self.want.timeout

        perAppDeploymentAllowed = self.check_settings()

        tenantList = self.get_tenant_list()

        self._check_control_queries_conflict()

        control_queries = self.get_control_queries()
        if perAppDeploymentAllowed and len(tenantList) == 0:
            if not self.want.tenant:
                raise F5ModuleError(
                    "tenant parameter is mandatory for Per-Application Deployment"
                )
            else:
                tenant = self.want.tenant
            uri = f"/mgmt/shared/appsvcs/declare/{tenant}/applications?async=true{control_queries}"
        else:
            if self.want.tenant:
                uri = f"/mgmt/shared/appsvcs/declare/{self.want.tenant}?async=true{control_queries}"
            else:
                uri = f"/mgmt/shared/appsvcs/declare?async=true{control_queries}"

        response = self.client.post(uri, data=self.want.content)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/appsvcs/task/{0}".format(response['contents']['id']), delay, period)
        if task and all(msg.get("dryRun", None) is True for msg in task["results"]):
            return False
        if task:
            return any(msg.get("message", None) != "no change" for msg in task["results"])

    def wait_for_task(self, path, delay, period):
        for x in range(0, period):
            task = self._check_task_on_device(path)
            errors = check_for_atc_errors(task)
            if errors:
                raise F5ATCError(errors)
            if any(msg.get('message', None) != 'in progress' for msg in task['results']):
                return task
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def resource_exists(self):
        if self.want.tenant != 'all':
            uri = "/mgmt/shared/appsvcs/declare/{0}".format(self.want.tenant)
        else:
            uri = "/mgmt/shared/appsvcs/declare"

        if self.want.tenant != 'all' and self.want.as3_apps_delete is not None:
            for app in self.want.as3_apps_delete:
                uri = "/mgmt/shared/appsvcs/declare/{0}/applications/{1}".format(self.want.tenant, app)
                response = self.client.get(uri)
                if response['code'] in [200]:
                    return True
                if response['code'] in [404, 204]:
                    pass
            return False

        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] == 204:
            return False
        return True

    def remove_from_device(self):
        delay, period = self.want.timeout
        uri = "/mgmt/shared/appsvcs/declare?async=true"
        if self.want.tenant != 'all':
            uri = "/mgmt/shared/appsvcs/declare/{0}?async=true".format(self.want.tenant)
            if self.want.as3_apps_delete is not None:
                for app in self.want.as3_apps_delete:
                    uri = "/mgmt/shared/appsvcs/declare/{0}/applications/{1}".format(self.want.tenant, app)
                    response = self.client.delete(uri)
                    if response['code'] not in [200, 201, 202, 204, 207, 500]:
                        raise F5ModuleError("Failed to delete application '{0}' in tenant '{1}'. Response code: {2}, Message: {3}".format(app, self.want.tenant, response.get('code', 'N/A'), response.get('contents', 'No response content')))  # noqa: E501
                    self.module.log("Application '{0}' successfully deleted.".format(app))
                return True

        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        task = self.wait_for_task("/mgmt/shared/appsvcs/task/{0}".format(response['contents']['id']), delay, period)
        if task:
            return any(msg.get('message', None) != 'no change' for msg in task['results'])

    def check_settings(self):
        response = self.client.get("/mgmt/shared/appsvcs/settings")
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])

        if 'betaOptions' in response['contents']:  # for AS3 version < 3.50.0
            return response['contents']['betaOptions']['perAppDeploymentAllowed']
        elif 'perAppDeploymentAllowed' in response['contents']:  # for As3 version 3.50.0
            return response['contents']['perAppDeploymentAllowed']
        else:
            return False

    def get_tenant_list(self):
        tenant_list = []
        content = self.want.content
        if isinstance(content, dict):
            if 'declaration' in content:
                declaration = content['declaration']
                if isinstance(declaration, dict):
                    for key, value in declaration.items():
                        if isinstance(value, dict) and value.get('class') == 'Tenant':
                            tenant_list.append(key)

        return tenant_list

    # def generate_random_string(self, length):
    #     charset = string.ascii_letters + string.digits
    #     random_string = random.choice(string.ascii_letters)
    #     for _ in range(length - 1):
    #         random_string += random.choice(charset)
    #     return random_string


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw'),
            tenant=dict(),
            as3_apps_delete=dict(type="list", elements="str"),
            controls=dict(
                type="dict",
                options=dict(
                    dry_run=dict(
                        type="bool",
                    ),
                    log_level=dict(
                        type="str",
                        choices=[
                            "emergency",
                            "alert",
                            "critical",
                            "error",
                            "warning",
                            "notice",
                            "info",
                            "debug",
                        ],
                    ),
                    trace=dict(
                        type="bool",
                    ),
                    trace_response=dict(
                        type="bool",
                    ),
                    user_agent=dict(
                        type="str",
                    ),
                ),
            ),
            timeout=dict(type="int", default=300),
            state=dict(default="present", choices=["present", "absent"]),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ["state", "present", ["content"]],
            ["state", "absent", ["tenant"]],
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


if __name__ == "__main__":  # pragma: no cover
    main()
