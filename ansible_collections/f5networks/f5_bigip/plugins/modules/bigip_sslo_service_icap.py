#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_service_icap
short_description: Manage an SSL Orchestrator ICAP security device
description:
  - Manage an SSL Orchestrator ICAP security device.
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the ICAP service object.
      - The configuration auto-prepends C(ssloS_) to the object.
      - Names should be less than 14 characters and not contain dashes C(-).
    type: str
    required: True
  devices:
    description:
      - Specifies a list of listening IP:ports for each ICAP security device.
      - This parameter is required when creating a new ICAP service object.
    type: list
    elements: dict
    suboptions:
      ip:
        description:
          - Specifies the IP address for the ICAP security device.
        type: str
      port:
        description:
          - Specifies the port for the ICAP security device.
          - Valid value range is from C(0) to C(65535).
        type: int
  ip_family:
    description:
      - Specifies the IP family used for attaching ICAP security devices.
      - When creating an ICAP service, if the parameter is not provided a default of C(ipv4)
        is assumed.
    type: str
    choices:
      - ipv4
      - ipv6
      - both
  monitor:
    description:
      - Specifies the monitor attached the ICAP security device pool. The monitor must already exist on the BIG-IP.
      - When creating an ICAP service, if the parameter is not provided a default of C(/Common/tcp) is
        assumed.
    type: str
  headers:
    description:
      - Settings related to custom headers to be inserted to the ICAP server.
    type: dict
    suboptions:
      enable:
        description:
          - Enables or disables custom headers to be inserted to the ICAP server.
          - If C(yes), the C(referrer), C(host), C(user_agent) and C(h_from) parameters are mandatory when creating a
            new service object.
          - When creating an ICAP service, if the parameter is not provided a default of value C(no) is assumed.
        type: bool
      referrer:
        description:
          - Specifies a Referrer header to pass to the ICAP service.
          - Required when creating a new service object with C(enable) value set to C(yes).
        type: str
      host:
        description:
          - Specifies a Host header to pass to the ICAP service.
          - Required when creating a new service object with C(enable) value set to C(yes).
        type: str
      user_agent:
        description:
          - Specifies a User-Agent header to pass to the ICAP service.
          - Required when creating a new service object with C(enable) value set to C(yes).
        type: str
      h_from:
        description:
          - Specifies a From header to pass to the ICAP service.
          - Required when creating a new service object with C(enable) value set to C(yes).
        type: str
  enable_one_connect:
    description:
      - Enables or disables OneConnect optimization to the ICAP server.
      - When creating an ICAP service, if the parameter is not provided a default value of C(yes) is assumed.
    type: bool
  request_uri:
    description:
      - Specifies the ICAP request URI. This URI must always start with a forward slash C(/) e.g. C(/avscan).
      - When creating an ICAP service, if the parameter is not provided a default value of C(/) is assumed.
    type: str
  response_uri:
    description:
      - Specifies the ICAP response URI. This URI must always start with a forward slash C(/) e.g. C(/avscan).
      - When creating an ICAP service, if the parameter is not provided a default value of C(/) is assumed.
    type: str
  preview_length:
    description:
      - Specifies the ICAP preview length value, in bytes.
      - Valid value range is from C(0) to C(51200) bytes.
      - When creating an ICAP service, if the parameter is not provided a default value of C(1024) is assumed.
    type: int
  service_down_action:
    description:
      - Specifies the action to take on monitor failure.
      - Setting to C(ignore) bypasses the security device in the service chain.
      - Setting to C(reset) or C(drop) resets or drops the connection, respectively, if the service monitor fails.
      - When creating an ICAP service, if the parameter is not provided a default value of C(ignore) is assumed.
    type: str
    choices:
      - ignore
      - reset
      - drop
  allow_http10:
    description:
      - Enables or disables HTTP/1.0 support to ICAP.
      - When creating an ICAP service, if the parameter is not provided a default value of C(no) is assumed.
    type: bool
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(yes), does not make any changes on the device and always returns C(changed=False).
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
    - name: Create SSLO ICAP service
      bigip_sslo_service_icap:
        name: "icap1"
        ip_family: "ipv4"
        devices:
          - ip: "1.1.1.1"
            port: 1344
          - ip: "2.2.2.2"
            port: 1348
        headers:
          enable: yes
          h_from: "foo_from"
          host: "foo_host"
          user_agent: "foo_ua"
          referrer: "foo_referrer"
        enable_one_connect: no
        preview_length: 2048
        service_down_action: "drop"
        allow_http10: yes

    - name: Modify SSLO ICAP service
      bigip_sslo_service_icap:
        name: "icap1"
        request_uri: "/avscan"
        response_uri: "/avscan"
        preview_length: 1024
        headers:
          enable: no

    - name: Delete SSLO ICAP service
      bigip_sslo_service_icap:
        name: "icap1"
        state: "absent"
'''

RETURN = r'''
devices:
  description:
    - A list of listening IP:ports for each ICAP security device.
  type: complex
  returned: changed
  contains:
    ip:
      description: The IP address for the ICAP security device.
      returned: changed
      type: str
      sample: 1.1.1.1
    port:
      description: The port for the ICAP security device.
      returned: changed
      type: int
      sample: 1344
ip_family:
  description:
    - The IP family used for attached ICAP security devices.
  returned: changed
  type: str
  sample: ipv4
monitor:
  description:
    - The monitor attached the ICAP security device pool.
  returned: changed
  type: str
  sample: /Common/tcp
headers:
  description:
    - Settings related to custom headers to be inserted to the ICAP server.
  type: complex
  returned: changed
  contains:
    enable:
      description: Enables or disables custom headers to be inserted to the ICAP server.
      returned: changed
      type: bool
      sample: True
    referrer:
      description: The Referrer header to pass to the ICAP service.
      returned: changed
      type: str
      sample: my_referrer
    host:
      description: The Host header to pass to the ICAP service.
      returned: changed
      type: str
      sample: my_host
    user_agent:
      description: The User-Agent header to pass to the ICAP service
      returned: changed
      type: str
      sample: my_user_agent
    h_from:
      description: The From header to pass to the ICAP service.
      returned: changed
      type: str
      sample: my_from
enable_one_connect:
  description:
    - Enables or disables OneConnect optimization to the ICAP server.
  returned: changed
  type: bool
  sample: True
request_uri:
  description:
    - The ICAP request URI.
  returned: changed
  type: str
  sample: /avscan
response_uri:
  description:
    - The ICAP response URI.
  returned: changed
  type: str
  sample: /avscan
preview_length:
  description:
    - The ICAP preview length value, in bytes.
  returned: changed
  type: int
  sample: 1024
service_down_action:
  description:
    - The action to take on monitor failure.
  returned: changed
  type: str
  sample: ignore
allow_http10:
  description:
    - Enables or disables HTTP/1.0 support to ICAP.
  returned: changed
  type: bool
  sample: True
'''

import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json, flatten_boolean
)
from ..module_utils.constants import (
    min_sslo_version, max_sslo_version
)
from ..module_utils.compare import compare_complex_list
from ..module_utils.sslo_templates.sslo_service_icap import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'allow_http10',
        'devices',
        'enable_one_connect',
        'header_enable',
        'header_referrer',
        'header_host',
        'header_user_agent',
        'header_from',
        'ip_family',
        'monitor',
        'preview_length',
        'request_uri',
        'response_uri',
        'service_down_action'
    ]

    updatables = [
        'allow_http10',
        'devices',
        'enable_one_connect',
        'header_enable',
        'header_referrer',
        'header_host',
        'header_user_agent',
        'header_from',
        'ip_family',
        'monitor',
        'preview_length',
        'request_uri',
        'response_uri'
        'service_down_action'
    ]


class ApiParameters(Parameters):
    @property
    def allow_http10(self):
        return self._values['customService']['serviceSpecific']['allowHttp10']

    @property
    def devices(self):
        devices = self._values['customService']['loadBalancing']['devices']
        result = list()
        for item in devices:
            tmp = dict()
            tmp['port'] = int(item['port'])
            tmp['ip'] = item['ip']
            result.append(tmp)
        if result:
            return result

    @property
    def enable_one_connect(self):
        return self._values['customService']['serviceSpecific']['enableOneConnect']

    @property
    def header_enable(self):
        return self._values['customService']['serviceSpecific']['headers']['mode']

    @property
    def header_referrer(self):
        if not self._values['customService']['serviceSpecific']['headers']['headerConfig']:
            return None
        return self._values['customService']['serviceSpecific']['headers']['headerConfig']['referrer']

    @property
    def header_host(self):
        if not self._values['customService']['serviceSpecific']['headers']['headerConfig']:
            return None
        return self._values['customService']['serviceSpecific']['headers']['headerConfig']['host']

    @property
    def header_user_agent(self):
        if not self._values['customService']['serviceSpecific']['headers']['headerConfig']:
            return None
        return self._values['customService']['serviceSpecific']['headers']['headerConfig']['userAgent']

    @property
    def header_from(self):
        if not self._values['customService']['serviceSpecific']['headers']['headerConfig']:
            return None
        return self._values['customService']['serviceSpecific']['headers']['headerConfig']['from']

    @property
    def ip_family(self):
        return self._values['customService']['ipFamily']

    @property
    def monitor(self):
        return self._values['customService']['loadBalancing']['monitor']['fromSystem']

    @property
    def preview_length(self):
        return int(self._values['customService']['serviceSpecific']['previewLength'])

    @property
    def request_uri(self):
        return self._values['customService']['serviceSpecific']['requestUri']

    @property
    def response_uri(self):
        return self._values['customService']['serviceSpecific']['responseUri']

    @property
    def service_down_action(self):
        return self._values['customService']['serviceDownAction']


class ModuleParameters(Parameters):
    @staticmethod
    def _port_check(item):
        if 0 <= item <= 65535:
            return item
        raise F5ModuleError(
            "Valid ports must be in range 0 - 65535."
        )

    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloS_'):
            name = "ssloS_" + name
        return name

    @property
    def allow_http10(self):
        result = flatten_boolean(self._values['allow_http10'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def devices(self):
        result = list()
        if self._values['devices'] is None:
            return None
        for item in self._values['devices']:
            tmp = dict()
            tmp['port'] = self._port_check(item['port'])
            tmp['ip'] = item['ip']
            result.append(tmp)

        if result:
            return result

    @property
    def enable_one_connect(self):
        result = flatten_boolean(self._values['enable_one_connect'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def header_enable(self):
        result = flatten_boolean(self._values['headers'].get('enable', None))
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def header_referrer(self):
        if self._values['headers'] is None:
            return None
        return self._values['headers'].get('referrer', None)

    @property
    def header_host(self):
        if self._values['headers'] is None:
            return None
        return self._values['headers'].get('host', None)

    @property
    def header_user_agent(self):
        if self._values['headers'] is None:
            return None
        return self._values['headers'].get('user_agent', None)

    @property
    def header_from(self):
        if self._values['headers'] is None:
            return None
        return self._values['headers'].get('h_from', None)

    @property
    def request_uri(self):
        link = self._values['request_uri']
        if link is None:
            return None
        return "icap://${SERVER_IP}:${SERVER_PORT}" + link

    @property
    def response_uri(self):
        link = self._values['response_uri']
        if link is None:
            return None
        return "icap://${SERVER_IP}:${SERVER_PORT}" + link

    @property
    def preview_length(self):
        preview = self._values['preview_length']
        if preview is None:
            return None
        if 0 <= preview <= 51200:
            return preview
        raise F5ModuleError(
            f"Invalid preview_length value got: {preview} bytes, "
            "valid value range is between 0 and 51200 bytes."
        )

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
    returnables = [
        'allow_http10',
        'devices',
        'enable_one_connect',
        'headers',
        'ip_family',
        'monitor',
        'preview_length',
        'request_uri',
        'response_uri',
        'service_down_action'
    ]

    @property
    def headers(self):
        tmp = dict()
        tmp['enable'] = self.header_enable
        tmp['referrer'] = self.header_referrer
        tmp['host'] = self.header_host
        tmp['user_agent'] = self.header_user_agent
        tmp['h_from'] = self.header_from
        result = self._filter_params(tmp)
        if result:
            return result


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
        result = compare_complex_list(self.want.devices, self.have.devices)
        return result


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
        if LooseVersion(self.version) > LooseVersion(max_sslo_version) or \
                LooseVersion(self.version) < LooseVersion(min_sslo_version):
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

    def check_for_required_create_parameters(self):
        if self.want.devices is None:
            raise F5ModuleError(
                "The devices parameter is not defined. Devices must be defined during CREATE operation."
            )
        if self.want.header_referrer is None and self.want.header_enable is True:
            raise F5ModuleError(
                "The referrer parameter is not defined. Custom header configuration requires the "
                "'referrer', 'host', 'user_agent' and 'h_from' values to be defined during CREATE operation when"
                "'enable' parameter is set to 'True'."
            )

        if self.want.header_host is None and self.want.header_enable is True:
            raise F5ModuleError(
                "The host parameter is not defined. Custom header configuration requires the "
                "'referrer', 'host', 'user_agent' and 'h_from' values to be defined during CREATE operation when"
                "'enable' parameter is set to 'True'."
            )

        if self.want.header_user_agent is None and self.want.header_enable is True:
            raise F5ModuleError(
                "The user_agent parameter is not defined. Custom header configuration requires the "
                "'referrer', 'host', 'user_agent' and 'h_from' values to be defined during CREATE operation when"
                "'enable' parameter is set to 'True'."
            )

        if self.want.header_from is None and self.want.header_enable is True:
            raise F5ModuleError(
                "The h_from parameter is not defined. Custom header configuration requires the "
                "'referrer', 'host', 'user_agent' and 'h_from' values to be defined during CREATE operation when"
                "'enable' parameter is set to 'True'."
            )

    def add_create_values(self, payload):
        # add create defaults for undefined values
        if self.want.allow_http10 is None:
            payload['allow_http10'] = False
        if self.want.ip_family is None:
            payload['ip_family'] = 'ipv4'
        if self.want.monitor is None:
            payload['monitor'] = '/Common/tcp'
        if self.want.header_enable is None:
            payload['header_enable'] = False
        if self.want.enable_one_connect is None:
            payload['enable_one_connect'] = True
        if self.want.request_uri is None:
            payload['request_uri'] = '/'
        if self.want.response_uri is None:
            payload['response_uri'] = '/'
        if self.want.preview_length is None:
            payload['preview_length'] = 1024
        if self.want.service_down_action is None:
            payload['service_down_action'] = 'ignore'
        # build header dictionary out of parameters
        if self.want.header_enable is True:
            tmp = dict()
            tmp['from'] = self.want.header_from
            tmp['host'] = self.want.header_host
            tmp['referrer'] = self.want.header_referrer
            tmp['userAgent'] = self.want.header_user_agent
            payload['header_config'] = tmp
        return payload

    def add_missing_options(self, payload):
        # used during modify operation, to avoid repetition if missing some mandatory values we use in device config
        # to complete the input
        if self.changes.allow_http10 is None:
            payload['allow_http10'] = self.have.allow_http10
        if self.changes.devices is None:
            payload['devices'] = self.have.devices
        if self.changes.enable_one_connect is None:
            payload['enable_one_connect'] = self.have.enable_one_connect
        if self.changes.ip_family is None:
            payload['ip_family'] = self.have.ip_family
        if self.changes.monitor is None:
            payload['monitor'] = self.have.monitor
        if self.changes.preview_length is None:
            payload['preview_length'] = self.have.preview_length
        if self.changes.request_uri is None:
            payload['request_uri'] = self.have.request_uri
        if self.changes.response_uri is None:
            payload['response_uri'] = self.have.response_uri
        if self.changes.service_down_action is None:
            payload['service_down_action'] = self.have.service_down_action
        if self.changes.header_enable is None:
            if self.have.header_enable is False:
                payload['header_enable'] = self.have.header_enable
            if self.have.header_enable is True:
                payload['header_enable'] = self.have.header_enable
                payload['header_config'] = self._add_header_config()
        if self.changes.header_enable is True:
            payload['header_config'] = self._add_header_config()

        return payload

    def _add_header_config(self):
        tmp = dict()
        tmp['from'] = self.changes.header_from if self.changes.header_from else self.have.header_from
        tmp['host'] = self.changes.header_host if self.changes.header_host else self.have.header_host
        tmp['referrer'] = self.changes.header_referrer if self.changes.header_referrer else self.have.header_referrer
        tmp['userAgent'] = self.changes.header_user_agent if self.changes.header_user_agent else \
            self.have.header_user_agent
        return tmp

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
            devices=dict(
                type='list',
                elements='dict',
                options=dict(
                    ip=dict(),
                    port=dict(type='int'),
                ),
                required_together=[['ip', 'port']],
                required_one_of=[['ip', 'port']]
            ),
            ip_family=dict(
                choices=['ipv4', 'ipv6', 'both']
            ),
            monitor=dict(),
            headers=dict(
                type='dict',
                options=dict(
                    enable=dict(type='bool'),
                    referrer=dict(),
                    host=dict(),
                    user_agent=dict(),
                    h_from=dict()
                )
            ),
            enable_one_connect=dict(
                type='bool'
            ),
            request_uri=dict(),
            response_uri=dict(),
            preview_length=dict(
                type='int'
            ),
            service_down_action=dict(
                choices=['ignore', 'reset', 'drop']
            ),
            allow_http10=dict(
                type='bool'
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
