#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_authentication
short_description: Manage an SSL Orchestrator authentication object
description:
  - Manage an SSL Orchestrator authentication object.
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the authentication object.
      - The configuration auto-prepends C(ssloA_) to the object.
      - Names should be less than 14 characters and not contain dashes C(-).
    type: str
    required: True
  ocsp:
    description:
      - Specifies an OCSP type authentication object
    type: dict
    suboptions:
      fqdn:
        description:
          - Defines the fully qualified name of the OCSP authentication service.
          - This parameter is required when creating a new OCSP authentication service.
        type: str
      dest:
        description:
          - Defines the OCSP authentication service destination IP address. The address must be valid
            and provided in CIDR notation.
          - If a route domain is not indicated in the address, a default C(%0) is inserted into the address.
          - This parameter is required when creating new OCSP authentication service.
        type: str
      ssl_profile:
        description:
          - Defines the existing SSL settings object to reference in the OCSP authentication.
          - The configuration auto-prepends C(ssloT_) to the object.
          - This parameter is required when creating new OCSP authentication service.
        type: str
      vlans:
        description:
          - Defines the list of client-facing VLANs for the OCSP authentication service.
          - The names of VLANs must be provided in the C(full_path) format e.g. C(/Common/vlan1).
          - This parameter is required when creating new OCSP authentication service.
        type: list
        elements: str
      port:
        description:
          - A custom port for the authentication service.
        type: int
      source:
        description:
          - Defines a source IP address filter, the address must be valid and provided in CIDR notation.
          - If a route domain is not indicated in the address, a default C(%0) is inserted into the address.
          - When creating an OCSP authentication service, if the parameter is not provided a default of C(0.0.0.0%0/0) is
            assumed.
        type: str
      http_profile:
        description:
          - Defines a custom HTTP profile to apply to the OCSP authentication service virtual server.
          - The name of profile must be provided in the C(full_path) format, for example C(/Common/http).
          - When creating the OCSP authentication service, if the parameter is not provided a default of C(/Common/http) is
            assumed.
        type: str
      tcp_settings_client:
        description:
          - Defines a custom client TCP profile.
          - The name of profile must be provided in the C(full_path) format e.g. C(/Common/f5-tcp-wan).
          - When creating an OCSP authentication service, if the parameter is not provided a default of
            C(/Common/f5-tcp-wan) is assumed.
        type: str
      tcp_settings_server:
        description:
          - Defines a custom server TCP profile.
          - The name of profile must be provided in the C(full_path) format e.g. C(/Common/f5-tcp-lan).
          - When creating an OCSP authentication service, if the parameter is not provided a default of
            C(/Common/f5-tcp-lan) is assumed.
        type: str
      existing_ocsp:
        description:
          - Defines an existing OCSP profile to use. Otherwise the OCSP profile is created automatically.
          - The name of profile must be provided in the C(full_path) format e.g. C(/Common/my_ocsp).
        type: str
      ocsp_max_age:
        description:
          - Defines a maximum age value for the OCSP profile (if not using an existing OCSP profile).
          - When creating an OCSP authentication service, if the parameter is not provided a default of
            C(604800) is assumed.
        type: int
      ocsp_nonce:
        description:
          - Enables or disables OCSP nonce (if not using an existing OCSP profile).
          - When creating an OCSP authentication service, if the parameter is not provided and C(existing_ocsp)
            is not set, the default of C(True) is assumed.
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
    - name: Create an SSLO authentication service
      bigip_sslo_config_authentication:
        name: "example_service"
        ocsp:
          fqdn: "foo.example.com"
          dest: "192.168.1.1/32"
          source: "10.10.10.0/24"
          ssl_profile: "example_sslo"
          vlans:
            - "/Common/vlan1"
            - "/Common/vlan2"

    - name: Modify an SSLO authentication service
      bigip_sslo_config_authentication:
        name: "example_service"
        ocsp:
          ssl_profile: "example_sslo"
          vlans:
            - "/Common/client-vlan"
            - "/Common/dlp-vlan"
          source: "0.0.0.0%0/0"

    - name: Create an SSLO authentication service - output json only
      bigip_sslo_config_authentication:
        name: "example_service"
        ocsp:
          fqdn: "foo.example.com"
          dest: "192.168.1.1/32"
          source: "10.10.10.0/24"
          ssl_profile: "example_sslo"
          vlans:
            - "/Common/vlan1"
            - "/Common/vlan2"
        dump_json: yes

    - name: Delete an SSLO authentication service
      bigip_sslo_config_authentication:
        name: "example_service"
        state: absent
'''

RETURN = r'''
ocsp:
  description: Settings used to define an OCP authentication object.
  type: complex
  returned: changed
  contains:
    fqdn:
      description: The fully qualified name clients use to access the OCSP authentication service.
      type: str
      sample: ocsp.f5labs.com
    dest:
      description: The destination IP address.
      type: str
      sample: 10.1.10.150/32
    ssl_profile:
      description: The SSL settings object the OCSP authentication service monitors for revocation states.
      type: str
      sample: ssl_settings_1
    vlans:
      description: The list of client-facing VLANs to listen on.
      type: str
      sample: /Common/client-vlan
    source:
      description: The source IP address filter.
      type: str
      sample: 0.0.0.0%0/0
    port:
      description: A custom port for the authentication service.
      type: int
      sample: 80
    http_profile:
      description: A custom HTTP profile to use for the authentication service.
      type: str
      sample: /Common/http
    tcp_settings_client:
      description: A custom client TCP profile to use for the authentication service.
      type: str
      sample: /Common/f5-tcp-wan
    tcp_settings_Server:
      description: A custom server TCP profile to use for the authentication service.
      type: str
      sample: /Common/f5-tcp-lan
    existing_ocsp:
      description: An existing OCSP profile to use for the authentication service.
      type: str
      sample: /Common/my-ocsp
    ocsp_max_age:
      description: A max age value for the OCSP profile (if not using an existing OCSP profile).
      type: int
      sample: 604800
    ocsp_nonce:
      description: Enables or disables nonce in the OCSP profile (if not using an existing OCSP profile).
      type: bool
      sample: True
'''

import re
import time
from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, sslo_version
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean, process_json
)
from ..module_utils.compare import compare_complex_list
from ..module_utils.sslo_templates.sslo_auth import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'ocsp_fqdn',
        'ocsp_dest',
        'ocsp_source',
        'ocsp_ssl_profile',
        'ocsp_vlans',
        'ocsp_port',
        'ocsp_http_profile',
        'ocsp_tcp_settings_client',
        'ocsp_tcp_settings_server',
        'existing_ocsp',
        'ocsp_max_age',
        'ocsp_nonce',
        'use_existing',
    ]

    updatables = [
        'ocsp_fqdn',
        'ocsp_dest',
        'ocsp_source',
        'ocsp_ssl_profile',
        'ocsp_vlans',
        'ocsp_port',
        'ocsp_http_profile',
        'ocsp_tcp_settings_client',
        'ocsp_tcp_settings_server',
        'existing_ocsp',
        'ocsp_max_age',
        'ocsp_nonce',
    ]


class ApiParameters(Parameters):
    @property
    def ocsp_fqdn(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp']['fqdn']

    @property
    def ocsp_dest(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['destination']['address']

    @property
    def ocsp_port(self):
        if self._values['serverDef'] is None:
            return None
        result = self._values['serverDef']['destination']['port']
        if result:
            return int(result)

    @property
    def ocsp_source(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['source']

    @property
    def ocsp_ssl_profile(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['sslSettingReference']

    @property
    def ocsp_vlans(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['vlans']

    @property
    def ocsp_http_profile(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['httpProfile']

    @property
    def ocsp_tcp_settings_client(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['serverTcpProfile']

    @property
    def ocsp_tcp_settings_server(self):
        if self._values['serverDef'] is None:
            return None
        return self._values['serverDef']['clientTcpProfile']

    @property
    def existing_ocsp(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp']['ocspProfile']

    @property
    def ocsp_max_age(self):
        if self._values['ocsp'] is None:
            return None
        result = self._values['ocsp']['maxAge']
        if result:
            return int(result)

    @property
    def ocsp_nonce(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp']['nonce']

    @property
    def use_existing(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp']['useExisting']


class ModuleParameters(Parameters):
    @staticmethod
    def _add_rd(addr):
        match = re.search(r'^.*%(\d+).*$', addr)
        if match:
            return addr
        tmp = addr.split('/')
        result = tmp[0] + '%0/' + tmp[1]
        return result

    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloA_'):
            name = "ssloA_" + name
        return name

    @property
    def ocsp_fqdn(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp'].get('fqdn', None)

    @property
    def ocsp_dest(self):
        if self._values['ocsp'] is None:
            return None
        dest = self._values['ocsp'].get('dest', None)
        if dest is None:
            return None
        try:
            m = re.search(r'^.*/(\d+)$', dest)
            if int(m.group(1)) > 32:
                raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
        except AttributeError:
            raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
        return self._add_rd(dest)

    @property
    def ocsp_source(self):
        if self._values['ocsp'] is None:
            return None
        src = self._values['ocsp'].get('source', None)
        if src is None:
            return None
        try:
            m = re.search(r'^.*/(\d+)$', src)
            if int(m.group(1)) > 32:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
        except AttributeError:
            raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
        return self._add_rd(src)

    @property
    def ocsp_port(self):
        if self._values['ocsp'] is None:
            return None
        port = self._values['ocsp'].get('port', None)
        if port is None:
            return None
        if 0 < port > 65535:
            raise F5ModuleError("A defined port must be an integer between 0 and 65535.")
        return port

    @property
    def ocsp_vlans(self):
        if self._values['ocsp'] is None:
            return None
        vlans = self._values['ocsp'].get('vlans', None)
        if vlans is None:
            return None
        result = list()
        for vlan in vlans:
            element = dict()
            element['name'] = vlan
            element['value'] = vlan
            result.append(element)
        return result

    @property
    def ocsp_ssl_profile(self):
        if self._values['ocsp'] is None:
            return None
        ssl = self._values['ocsp'].get('ssl_profile', None)
        if ssl is None:
            return None
        if not ssl.startswith('ssloT_'):
            result = 'ssloT_' + ssl
            return result
        else:
            return ssl

    @property
    def ocsp_http_profile(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp'].get('http_profile', None)

    @property
    def ocsp_tcp_settings_client(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp'].get('tcp_settings_client', None)

    @property
    def ocsp_tcp_settings_server(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp'].get('tcp_settings_server', None)

    @property
    def existing_ocsp(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp'].get('existing_ocsp', None)

    @property
    def ocsp_max_age(self):
        if self._values['ocsp'] is None:
            return None
        return self._values['ocsp'].get('ocsp_max_age', None)

    @property
    def ocsp_nonce(self):
        if self._values['ocsp'] is None:
            return None
        result = flatten_boolean(self._values['ocsp'].get('ocsp_nonce', None))
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

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
        'ocsp'
    ]

    @property
    def ocsp(self):
        result = dict()
        if self.ocsp_fqdn:
            result['fqdn'] = self.ocsp_fqdn
        if self.ocsp_dest:
            result['dest'] = self.ocsp_dest
        if self.ocsp_ssl_profile:
            name = self.ocsp_ssl_profile
            result['ssl_profile'] = name.lstrip('ssloT_')
        if self.ocsp_vlans:
            result['vlans'] = self.ocsp_vlans
        if self.ocsp_port:
            result['port'] = self.ocsp_port
        if self.ocsp_http_profile:
            result['http_profile'] = self.ocsp_http_profile
        if self.ocsp_tcp_settings_client:
            result['tcp_settings_client'] = self.ocsp_tcp_settings_client
        if self.ocsp_tcp_settings_server:
            result['tcp_settings_server'] = self.ocsp_tcp_settings_server
        if self.existing_ocsp:
            result['existing_ocsp'] = self.existing_ocsp
        if self.ocsp_max_age:
            result['ocsp_max_age'] = self.ocsp_max_age
        if self.ocsp_nonce:
            result['ocsp_nonce'] = self.ocsp_nonce
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
    def ocsp_vlans(self):
        result = compare_complex_list(self.want.ocsp_vlans, self.have.ocsp_vlans)
        return result

    @property
    def existing_ocsp(self):
        if self.want.existing_ocsp is None:
            return None
        if self.want.existing_ocsp != self.have.existing_ocsp:
            return self.want.existing_ocsp


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
        if LooseVersion(self.version) > LooseVersion('9.9') or \
                LooseVersion(self.version) < LooseVersion('9.0'):
            raise F5ModuleError("Unsupported SSL Orchestrator version, requires a version between '9.0' and '9.9'")
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

    def check_for_required_create_parameters(self):
        if self.want.ocsp_fqdn is None:
            raise F5ModuleError(
                "FQDN not defined. OCSP Authentication minimally requires the "
                "'fqdn', 'dest', 'ssl_profile' and 'vlans' values to be defined during CREATE operation."
            )

        if self.want.ocsp_dest is None:
            raise F5ModuleError(
                "Dest not defined. OCSP Authentication minimally requires the "
                "'fqdn', 'dest', 'ssl_profile' and 'vlans' values to be defined during CREATE operation."
            )

        if self.want.ocsp_ssl_profile is None:
            raise F5ModuleError(
                "Ssl_profile not defined. OCSP Authentication minimally requires the "
                "'fqdn', 'dest', 'ssl_profile' and 'vlans' values to be defined during CREATE operation."
            )

        if self.want.ocsp_vlans is None:
            raise F5ModuleError(
                "Vlans not defined. OCSP Authentication minimally requires the "
                "'fqdn', 'dest', 'ssl_profile' and 'vlans' values to be defined during CREATE operation."
            )

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_AUTHENTICATION_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation == 'MODIFY' or self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        return payload

    def add_create_defaults(self, payload):
        # adds default values for undefined settings during create operation
        if self.want.ocsp_source is None:
            payload['ocsp_source'] = '0.0.0.0%0/0'
        if self.want.ocsp_port is None:
            payload['ocsp_port'] = 80
        if self.want.ocsp_http_profile is None:
            payload['ocsp_http_profile'] = '/Common/http'
        if self.want.ocsp_tcp_settings_client is None:
            payload['ocsp_tcp_settings_client'] = '/Common/f5-tcp-wan'
        if self.want.ocsp_tcp_settings_server is None:
            payload['ocsp_tcp_settings_server'] = '/Common/f5-tcp-lan'
        if self.want.ocsp_max_age is None and self.want.existing_ocsp is None:
            payload['ocsp_max_age'] = 604800
        if self.want.ocsp_nonce is None and self.want.existing_ocsp is None:
            payload['ocsp_nonce'] = 'enabled'
        if self.want.existing_ocsp is None:
            payload['use_existing'] = False
        if self.want.existing_ocsp is not None:
            payload['use_existing'] = True
        return payload

    def add_missing_options(self, payload):
        # used during modify operation, to avoid repetition if missing some mandatory values we use in device config
        # to complete the input
        if self.changes.ocsp_fqdn is None:
            payload['ocsp_fqdn'] = self.have.ocsp_fqdn
        if self.changes.ocsp_dest is None:
            payload['ocsp_dest'] = self.have.ocsp_dest
        if self.changes.ocsp_source is None:
            payload['ocsp_source'] = self.have.ocsp_source
        if self.changes.ocsp_vlans is None:
            payload['ocsp_vlans'] = self.have.ocsp_vlans
        if self.changes.ocsp_port is None:
            payload['ocsp_port'] = self.have.ocsp_port
        if self.changes.ocsp_http_profile is None:
            payload['ocsp_http_profile'] = self.have.ocsp_http_profile
        if self.changes.ocsp_tcp_settings_client is None:
            payload['ocsp_tcp_settings_client'] = self.have.ocsp_tcp_settings_client
        if self.changes.ocsp_tcp_settings_server is None:
            payload['ocsp_tcp_settings_server'] = self.have.ocsp_tcp_settings_server
        if self.changes.ocsp_max_age is None:
            payload['ocsp_max_age'] = self.have.ocsp_max_age
        if self.changes.ocsp_nonce is None:
            payload['ocsp_nonce'] = self.have.ocsp_nonce
        if self.changes.existing_ocsp is None:
            payload['existing_ocsp'] = self.have.existing_ocsp
            payload['use_existing'] = self.have.use_existing
        if self.changes.existing_ocsp is not None and self.changes.existing_ocsp != '':
            payload['use_existing'] = True
        if self.changes.existing_ocsp is not None and self.changes.existing_ocsp == '':
            payload['use_existing'] = False
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
            name=dict(
                required=True
            ),
            ocsp=dict(
                type='dict',
                options=dict(
                    fqdn=dict(),
                    dest=dict(),
                    ssl_profile=dict(),
                    vlans=dict(
                        type='list',
                        elements='str'
                    ),
                    source=dict(),
                    port=dict(
                        type='int'
                    ),
                    http_profile=dict(),
                    tcp_settings_client=dict(),
                    tcp_settings_server=dict(),
                    existing_ocsp=dict(),
                    ocsp_max_age=dict(
                        type='int'
                    ),
                    ocsp_nonce=dict(
                        type='bool'
                    )
                ),
                mutually_exclusive=[
                    ['existing_ocsp', 'ocsp_nonce'],
                    ['existing_ocsp', 'ocsp_max_age']
                ]
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
