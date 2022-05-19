#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_service_http
short_description: Manage an SSL Orchestrator HTTP security device
description:
  - Manage an SSL Orchestrator HTTP security device.
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the HTTP service object.
      - The configuration auto-prepends C(ssloS_) to the object.
      - Names should be less than 14 characters and not contain dashes C(-).
    type: str
    required: True
  devices_to:
    description:
      - Specifies the set of network settings for traffic going to the service from the BIG-IP.
    type: dict
    suboptions:
      vlan:
        description:
          - Defines an existing VLAN to attach on the to-service side.
          - Mutually exclusive with C(tag) or C(interface) parameter.
        type: str
      interface:
        description:
          - Defines the interface on the to-service side.
          - Mutually exclusive with C(vlan).
        type: str
      tag:
        description:
          - Defines the VLAN tag on the to-service side.
          - Mutually exclusive with C(vlan).
        type: int
      self_ip:
        description:
          - Defines the to-service self IP.
        type: str
      netmask:
        description:
          - Defines the to-service self IP netmask.
        type: str
  devices_from:
    description:
      - Specifies the set of network settings for traffic going to the BIG-IP from the service.
    type: dict
    suboptions:
      vlan:
        description:
          - Defines an existing VLAN to attach on the from-service side.
          - Mutually exclusive with the C(tag) or C(interface) parameters.
        type: str
      interface:
        description:
          - Defines the interface on the from-service side.
          - Mutually exclusive with C(vlan).
        type: str
      tag:
        description:
          - Defines the VLAN tag on the from-service side.
          - Mutually exclusive with C(vlan).
        type: int
      self_ip:
        description:
          - Defines the from-service self IP.
        type: str
      netmask:
        description:
          - Defines the from-service self IP netmask.
        type: str
  devices:
    description:
      - Defines a list of service IP addresses and ports.
      - Use IP only for transparent proxy, and IP and port for explicit proxy.
    type: list
    elements: dict
    suboptions:
      ip:
        description:
          - The nominal IP address for this service.
        type: str
      port:
        description:
          - The port for this service.
          - Required when C(proxy_type) is explicit.
        type: int
  proxy_type:
    description:
      - Specifies the HTTP service as explicit or transparent.
      - When creating an HTTP service, if the parameter is not provided a default of C(transparent) is
        assumed.
    type: str
    choices:
      - explicit
      - transparent
  auth_offload:
    description:
       - Enables or disables authentication offload to the HTTP service.
       - When creating an HTTP service, if the parameter is not provided a default of C(no) is
         assumed.
    type: bool
  monitor:
    description:
      - Specifies the monitor attached to the HTTP security device pool.
      - The monitor must already exist on the BIG-IP.
      - "When creating an HTTP service, if the parameter is not provided a default of C(/Common/gateway_icmp) is assumed."
    type: str
  port_remap:
    description:
      - Defines the port to remap decrypted traffic to.
    type: int
  snat:
    description:
      - Defines if and how a SNAT configuration is deployed.
      - When C(none) no SNAT configuration is performed. This is the default choice when creating HTTP service
        if the parameter is not provided.
      - When C(automap), SNAT automap is configured.
      - When C(snatpool), the SNAT configuration points to an existing SNAT Pool defined by the C(snatpool) parameter.
      - When C(snatlist), a new SNAT Pool is created from the provided C(snatlist).
    type: str
    choices:
      - none
      - automap
      - snatpool
      - snatlist
  snat_pool:
    description:
      - Defines an existing SNAT pool.
      - This parameter is required when C(snat) set to C(snatpool).
    type: str
  snat_list:
    description:
      - Defines a list of IP addresses to use in a SNAT pool configuration.
      - This parameter required when C(snat) set to C(snatlist).
    type: list
    elements: str
  rules:
    description:
      - Defines a list of iRules to attach to the service.
    type: list
    elements: str
  ip_family:
    description:
      - Specifies the IP family used for attached HTTP security devices.
      - When creating an ICAP service, if the parameter is not provided a default of C(ipv4) is
        assumed.
    type: str
    choices:
      - ipv4
      - ipv6
  service_down_action:
    description:
      - Specifies the action to take on monitor failure.
      - Setting to C(ignore) bypasses the security device in the service chain.
      - Setting to C(reset) or C(drop) resets or drops the connection, respectively if the service monitor fails.
      - When creating an ICAP service, if the parameter is not provided a default value of C(ignore) is assumed.
    type: str
    choices:
      - ignore
      - reset
      - drop
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
      - The amount of time to wait for the C(CREATE) or C(MODIFY) task to complete, in seconds.
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
    - name: Create a HTTP service
      bigip_sslo_service_http:
        name: "proxy1a"
        devices_to:
            vlan: "/Common/proxy1a-in-vlan"
            self_ip: "198.19.96.7"
            netmask: "255.255.255.128"
        devices_from:
            interface: "1.1"
            tag: 50
            self_ip: "198.19.96.245"
            netmask: "255.255.255.128"
        devices:
          - ip: "198.19.96.30"
          - ip: "198.19.96.31"
        snat: snatpool
        snat_pool: "/Common/proxy1a-snatpool"
        proxy_type: "transparent"
        auth_offload: true
        ip_family: "ipv4"
        service_down_action: "reset"
        port_remap: 8080

    - name: Modify a HTTP service
      bigip_sslo_service_http:
        name: "proxy1a"
        snat: "snatlist"
        snat_list:
          - "198.19.64.10"
          - "198.19.64.11"

    - name: Delete SSLO HTTP service
      bigip_sslo_service_http:
        name: "proxy1a"
        state: "absent"
'''

RETURN = r'''
devices_to:
  description:
    - Network settings for to-service configuration.
  returned: changed
  type: complex
  contains:
    vlan:
       description: Defines an existing to-service VLAN.
       type: str
       sample: /Common/proxy1a-to-vlan
    interface:
       description: Defines a to-service interface.
       type: str
       sample: 1.3
    tag:
       description: Defines a to-service VLAN tag.
       type: int
       sample: 40
    self_ip:
       description: Defines the to-service VLAN self IP.
       type: str
       sample: 198.19.64.7
    netmask:
       description: Defines the to-service VLAN self IP netmask.
       type: str
       sample: 255.255.255.128
devices_from:
  description:
    - Network settings for for-service configuration.
  returned: changed
  type: complex
  contains:
    vlan:
       description: Defines an existing for-service VLAN.
       type: str
       sample: /Common/proxy1a-from-vlan
    interface:
       description: Defines a from-service interface.
       type: str
       sample: 1.3
    tag:
       description: Defines a from-service VLAN tag.
       type: int
       sample: 50
    self_ip:
       description: Defines the from-service VLAN self IP.
       type: str
       sample: 198.19.64.245
    netmask:
       description: Defines the from-service VLAN self IP netmask.
       type: str
       sample: 255.255.255.128
devices:
  description:
    - The list of service IP addresses and ports.
  returned: changed
  type: complex
  contains:
    ip:
       description: The nominal IP address for this service.
       type: str
       sample: "192.168.1.1"
    port:
       description: The port for this service.
       type: str
       sample: 8455
proxy_type:
  description:
    - The HTTP service proxy type.
  returned: changed
  type: str
  sample: "transparent"
auth_offload:
  description:
    - Enables or disables authentication offload to the HTTP service.
  returned: changed
  type: bool
  sample: true
ip_family:
  description:
    - The IP family used for attached HTTP security devices.
  returned: changed
  type: str
  sample: ipv4
monitor:
  description:
    - The monitor attached to the HTTP security device pool.
  returned: changed
  type: str
  sample: /Common/gateway_icmp
service_down_action:
  description:
    - The action to take on monitor failure.
  returned: changed
  type: str
  sample: ignore
port_remap:
  description:
    - Port remap settings.
  returned: changed
  type: int
  sample: 8080
snat:
  description:
    - SNAT configuration type.
  returned: changed
  type: str
  sample: none
snat_pool:
  description:
    - The name of the existing SNAT pool.
  returned: changed
  type: str
  sample: /Common/test-snat-pool
snatlist:
  description:
    - The list of SNAT pool members.
  returned: changed
  type: list
  sample: ["198.19.64.10" , "198.19.64.11"]
rules:
  description:
    - List of iRules attached to the service.
  returned: changed
  type: list
  sample: ["/Common/test-rule-1", "/Common/test-rule-2"]
'''

import re
import ipaddress
import time
import traceback
from distutils.version import LooseVersion


try:
    from netaddr import IPAddress
except ImportError:
    HAS_NETADDR = False
    IPAddress = None
    NETADDR_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_NETADDR = True

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
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
from ..module_utils.compare import compare_complex_list, compare_dictionary
from ..module_utils.sslo_templates.sslo_service_http import (
    create_modify
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'devices_to',
        'devices_from',
        'devices',
        'ip_family',
        'monitor',
        'service_down_action',
        'port_remap',
        'snat',
        'snat_list',
        'snat_pool',
        'rules',
        'proxy_type',
        'auth_offload'
    ]

    updatables = [
        'devices_to',
        'devices_from',
        'devices',
        'ip_family',
        'monitor',
        'service_down_action',
        'port_remap',
        'snat',
        'snat_list',
        'snat_pool',
        'rules',
        'proxy_type',
        'auth_offload'
    ]


class ApiParameters(Parameters):
    @property
    def devices_to(self):
        ipfamily = self.ip_family
        result = dict()
        result['name'] = self._values['fromNetworkObj']['name']
        result['path'] = self._values['fromNetworkObj']['vlan']['path']
        result['self_ip'] = self._values['customService']['managedNetwork'][ipfamily]['toServiceSelfIp']
        result['netmask'] = self._values['customService']['managedNetwork'][ipfamily]['toServiceMask']
        result['network'] = self._values['customService']['managedNetwork'][ipfamily]['toServiceNetwork']
        if self._values['fromNetworkObj']['vlan']['create']:
            if isinstance(self._values['fromNetworkObj']['vlan']['interface'], list):
                result['interface'] = self._values['fromNetworkObj']['vlan']['interface'][0]
            else:
                result['interface'] = self._values['fromNetworkObj']['vlan']['interface']
            if int(self._values['fromNetworkObj']['vlan']['tag']) != 0:
                result['tag'] = int(self._values['fromNetworkObj']['vlan']['tag'])
        else:
            result['vlan'] = self._values['fromNetworkObj']['vlan']['path']
        return result

    @property
    def devices_from(self):
        ipfamily = self.ip_family
        result = dict()
        result['name'] = self._values['toNetworkObj']['name']
        result['path'] = self._values['toNetworkObj']['vlan']['path']
        result['self_ip'] = self._values['customService']['managedNetwork'][ipfamily]['fromServiceSelfIp']
        result['netmask'] = self._values['customService']['managedNetwork'][ipfamily]['fromServiceMask']
        result['network'] = self._values['customService']['managedNetwork'][ipfamily]['fromServiceNetwork']
        if self._values['toNetworkObj']['vlan']['create']:
            if isinstance(self._values['toNetworkObj']['vlan']['interface'], list):
                result['interface'] = self._values['toNetworkObj']['vlan']['interface'][0]
            else:
                result['interface'] = self._values['toNetworkObj']['vlan']['interface']
            if int(self._values['toNetworkObj']['vlan']['tag']) != 0:
                result['tag'] = int(self._values['toNetworkObj']['vlan']['tag'])
        else:
            result['vlan'] = self._values['toNetworkObj']['vlan']['path']
        return result

    @property
    def devices(self):
        devices = self._values['customService']['loadBalancing']['devices']
        result = list()
        for device in devices:
            element = dict()
            element['ip'] = device['ip']
            element['port'] = int(device['port'])
            result.append(element)
        return result

    @property
    def ip_family(self):
        return self._values['customService']['ipFamily']

    @property
    def monitor(self):
        return self._values['customService']['loadBalancing']['monitor']['fromSystem']

    @property
    def service_down_action(self):
        return self._values['customService']['serviceDownAction']

    @property
    def port_remap(self):
        return int(self._values['customService']['httpPortRemapValue'])

    @property
    def snat(self):
        return self._values['customService']['snatConfiguration']['clientSnat']

    @property
    def snat_list(self):
        ipfamily = self.ip_family
        if ipfamily == 'ipv6':
            return self._values['customService']['snatConfiguration']['snat']['ipv6SnatAddresses']
        else:
            return self._values['customService']['snatConfiguration']['snat']['ipv4SnatAddresses']

    @property
    def snat_pool(self):
        if self.snat == 'existingSNAT':
            return self._values['customService']['snatConfiguration']['snat']['referredObj']

    @property
    def rules(self):
        return self._values['iRuleList']

    @property
    def proxy_type(self):
        return self._values['customService']['serviceSpecific']['proxyType']

    @property
    def auth_offload(self):
        return self._values['customService']['serviceSpecific']['authOffload']

    @property
    def from_net_id(self):
        block_id = self._values['customService']['connectionInformation']['fromBigipNetwork']['networkBlockId']
        if block_id:
            return block_id

    @property
    def to_net_id(self):
        block_id = self._values['customService']['connectionInformation']['toBigipNetwork']['networkBlockId']
        if block_id:
            return block_id

    @property
    def snat_ref_id(self):
        if self.snat == 'SNAT':
            return self._values['customService']['snatConfiguration']['snat']['referredObj']


class ModuleParameters(Parameters):
    @staticmethod
    def _port_check(item):
        if 0 <= item <= 65535:
            return item
        raise F5ModuleError(
            "Valid ports must be in range 0 - 65535."
        )

    @staticmethod
    def _process_network(item):
        cidr = IPAddress(item['netmask']).netmask_bits()
        ip = f"{item['self_ip']}/{cidr}"
        network = re.sub('/[0-9]+', '', str(ipaddress.ip_network(ip, strict=False)))
        return network

    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloS_'):
            name = "ssloS_" + name
        return name

    @property
    def devices_to(self):
        devices = self._values['devices_to']
        if devices is None:
            return None
        result = dict()
        result['name'] = f"ssloN_{self._values['name']}_in"
        if 'vlan' in devices.keys() and devices['vlan']:
            result['path'] = devices['vlan']
            result['vlan'] = devices['vlan']
        else:
            result['path'] = f"/Common/ssloN_{self._values['name']}_in.app/ssloN_{self._values['name']}_in"
            result['interface'] = devices['interface']
        if 'tag' in devices.keys() and devices['tag']:
            result['tag'] = devices['tag']
        result['self_ip'] = devices['self_ip']
        result['netmask'] = devices['netmask']
        result['network'] = self._process_network(devices)
        return result

    @property
    def devices_from(self):
        devices = self._values['devices_from']
        if devices is None:
            return None
        result = dict()
        result['name'] = f"ssloN_{self._values['name']}_out"
        if 'vlan' in devices.keys() and devices['vlan']:
            result['path'] = devices['vlan']
            result['vlan'] = devices['vlan']
        else:
            result['path'] = f"/Common/ssloN_{self._values['name']}_out.app/ssloN_{self._values['name']}_out"
            result['interface'] = devices['interface']
        if 'tag' in devices.keys() and devices['tag']:
            result['tag'] = devices['tag']
        result['self_ip'] = devices['self_ip']
        result['netmask'] = devices['netmask']
        result['network'] = self._process_network(devices)
        return result

    @property
    def devices(self):
        proxy = self.proxy_type
        result = list()
        if self._values['devices'] is None:
            return None
        for device in self._values['devices']:
            tmp = dict()
            tmp['ip'] = device['ip']
            if 'port' not in device.keys() or not device['port']:
                if proxy == 'explicit':
                    raise F5ModuleError('Explicit proxy requires an IP and port specified for devices.')
                tmp['port'] = 80
            else:
                tmp['port'] = self._port_check(device['port'])
            result.append(tmp)
        if result:
            return result

    @property
    def port_remap(self):
        if self._values['port_remap'] is None:
            return None
        if self.proxy_type == 'explicit':
            raise F5ModuleError('Port remap cannot be used with explicit proxy.')
        return self._values['port_remap']

    @property
    def rules(self):
        if self._values['rules'] is None:
            return None
        result = list()
        for rule in self._values['rules']:
            element = dict()
            element['name'] = rule
            element['value'] = rule
            result.append(element)
        return result

    @property
    def proxy_type(self):
        proxy = self._values['proxy_type']
        if proxy is None:
            return None
        elif proxy == 'explicit':
            return 'Explicit'
        elif proxy == 'transparent':
            return 'Transparent'

    @property
    def auth_offload(self):
        result = flatten_boolean(self._values['auth_offload'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def snat_list(self):
        snats = self._values['snat_list']
        if snats is None:
            return None
        result = list()
        for snat in snats:
            element = dict(ip=None)
            element['ip'] = snat
            result.append(element)
        return result

    @property
    def snat(self):
        snat = self._values['snat']
        if snat is None:
            return None
        if snat == 'none':
            return 'None'
        elif snat == 'automap':
            return 'AutoMap'
        elif snat == 'snatlist':
            return 'SNAT'
        elif snat == 'snatpool':
            return 'existingSNAT'

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


class RemovalChanges(Changes):
    returnables = [
        'devices_to',
        'devices_from',
        'devices',
        'ip_family',
        'monitor',
        'service_down_action',
        'port_remap',
        'snat',
        'snat_list',
        'snat_pool',
        'rules',
        'proxy_type',
        'auth_offload',
        'snat_ref_id'
    ]


class ReportableChanges(Changes):
    @staticmethod
    def _normalize_devices(devices):
        result = dict()
        if 'vlan' in devices.keys() and devices['vlan']:
            result['vlan'] = devices['vlan']
        if 'interface' in devices.keys() and devices['interface']:
            result['interface'] = devices['interface']
        if 'tag' in devices.keys() and devices['tag']:
            result['tag'] = devices['tag']
        result['self_ip'] = devices['self_ip']
        result['netmask'] = devices['netmask']
        return result

    @property
    def devices_to(self):
        devices = self._values['devices_to']
        if devices is None:
            return None
        result = self._normalize_devices(devices)
        return result

    @property
    def devices_from(self):
        devices = self._values['devices_from']
        if devices is None:
            return None
        result = self._normalize_devices(devices)
        return result

    @property
    def rules(self):
        rules = self._values['rules']
        if rules is None:
            return None
        result = list()
        for rule in rules:
            result.append(rule['name'])
        return result

    @property
    def proxy_type(self):
        proxy = self._values['proxy_type']
        if proxy is None:
            return None
        return proxy.lower()

    @property
    def auth_offload(self):
        return flatten_boolean(self._values['auth_offload'])

    @property
    def snat_list(self):
        snats = self._values['snat_list']
        if snats is None:
            return None
        result = list()
        for snat in snats:
            result.append(snat['ip'])
        return result

    @property
    def snat(self):
        snat = self._values['snat']
        if snat is None:
            return None
        if snat == 'None':
            return 'none'
        elif snat == 'AutoMap':
            return 'autoMap'
        elif snat == 'SNAT':
            return 'snatlist'
        elif snat == 'existingSNAT':
            return 'snatpool'


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
    def devices_to(self):
        want = self.want.devices_to
        have = self.have.devices_to
        diff = compare_dictionary(want, have)
        if diff:
            if want['self_ip'] != have['self_ip'] or want['netmask'] != have['netmask']:
                raise F5ModuleError(
                    'Self-IPs are immutable. You must delete and recreate the service to change the self-IPs.'
                )
            return diff

    @property
    def devices_from(self):
        want = self.want.devices_from
        have = self.have.devices_from
        diff = compare_dictionary(want, have)
        if diff:
            if want['self_ip'] != have['self_ip'] or want['netmask'] != have['netmask']:
                raise F5ModuleError(
                    'Self-IPs are immutable. You must delete and recreate the service to change the self-IPs.'
                )
            return diff

    @property
    def devices(self):
        return compare_complex_list(self.want.devices, self.have.devices)

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
        self.removals = RemovalChanges()
        self.have = ApiParameters()

        # define a set of common instance variables used during module execution
        self.block_id = None
        self.operation = None
        self.version = None
        self.json_dump = None

    def _set_options_to_remove(self):
        changed = {}
        for key in RemovalChanges.returnables:
            if getattr(self.have, key) is not None:
                changed[key] = getattr(self.have, key)
        if changed:
            self.removals = RemovalChanges(params=changed)

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

    def remove(self):
        if self.module.check_mode:
            return True
        self.operation = 'DELETE'
        self.have = self.read_current_from_device()
        self._set_options_to_remove()
        task_id, output = self.remove_from_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def check_for_required_create_parameters(self):
        if self.want.devices_to is None or self.want.devices_from is None or self.want.devices is None:
            raise F5ModuleError(
                "Creating SSLO HTTP service requires 'devices_to', 'devices_from' and 'devices'"
                " parameters to be specified."
            )

    def add_create_values(self, params):
        if self.want.proxy_type is None:
            params['proxy_type'] = 'Explicit'
        if self.want.monitor is None:
            params['monitor'] = '/Common/gateway_icmp'
        if self.want.service_down_action is None:
            params['service_down_action'] = 'ignore'
        if self.want.snat is None:
            params['snat'] = 'None'
        if self.want.ip_family is None:
            params['ip_family'] = 'ipv4'
        if self.want.snat == 'existingSNAT':
            params['snat_ref_id'] = self.want.snat_pool
        if self.want.auth_offload is None:
            params['auth_offload'] = False
        return params

    def add_missing_options(self, params):
        if self.changes.devices_to is None:
            params['devices_to'] = self.have.devices_to
        if self.changes.devices_from is None:
            params['devices_from'] = self.have.devices_from
        if self.changes.devices is None:
            params['devices'] = self.have.devices
        if self.changes.ip_family is None:
            params['ip_family'] = self.have.ip_family
        if self.changes.monitor is None:
            params['monitor'] = self.have.monitor
        if self.changes.service_down_action is None:
            params['service_down_action'] = self.have.service_down_action
        if self.changes.port_remap is None:
            params['port_remap'] = self.have.port_remap
        if self.changes.rules is None:
            params['rules'] = self.have.rules
        if self.changes.proxy_type is None:
            params['proxy_type'] = self.have.proxy_type
        if self.changes.auth_offload is None:
            params['auth_offload'] = self.have.auth_offload
        if self.changes.snat is None:
            params['snat'] = self.have.snat
            if self.have.snat == 'SNAT':
                params['snat_ref_id'] = self.have.snat_ref_id
                if self.changes.snat_list is None:
                    params['snat_list'] = self.have.snat_list
            if self.have.snat == 'existingSNAT':
                if self.changes.snat_pool is None:
                    params['snat_ref_id'] = self.have.snat_pool
                else:
                    params['snat_ref_id'] = self.changes.snat_pool
        if self.changes.snat == 'existingSNAT':
            params['snat_ref_id'] = self.changes.snat_pool
        return params

    def add_json_metadata(self, payload):
        payload['name'] = f"sslo_obj_SERVICE_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation == 'MODIFY' or self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
        if self.operation == 'MODIFY':
            if self.have.to_net_id:
                payload['to_net_id'] = self.have.to_net_id
            if self.have.from_net_id:
                payload['from_net_id'] = self.have.from_net_id
        return payload

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
        payload = self.removals.to_return()
        data = self.add_json_metadata(payload)

        output = process_json(data, create_modify)

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
            devices_to=dict(
                type='dict',
                options=dict(
                    vlan=dict(),
                    interface=dict(),
                    tag=dict(type='int'),
                    self_ip=dict(),
                    netmask=dict()
                ),
                required_together=[
                    ['self_ip', 'netmask']
                ],
                mutually_exclusive=[
                    ['vlan', 'interface'],
                    ['vlan', 'tag']
                ],
                required_one_of=[
                    ['vlan', 'interface'],
                    ['self_ip', 'netmask']
                ]
            ),
            devices_from=dict(
                type='dict',
                options=dict(
                    vlan=dict(),
                    interface=dict(),
                    tag=dict(type='int'),
                    self_ip=dict(),
                    netmask=dict()
                ),
                required_together=[
                    ['self_ip', 'netmask']
                ],
                mutually_exclusive=[
                    ['vlan', 'interface'],
                    ['vlan', 'tag']
                ],
                required_one_of=[
                    ['vlan', 'interface'],
                    ['self_ip', 'netmask']
                ]
            ),
            devices=dict(
                type='list',
                elements='dict',
                options=dict(
                    ip=dict(),
                    port=dict(type='int')
                )
            ),
            ip_family=dict(
                choices=['ipv4', 'ipv6']
            ),
            monitor=dict(),
            service_down_action=dict(
                choices=['ignore', 'reset', 'drop']
            ),
            port_remap=dict(
                type='int'
            ),
            snat=dict(
                choices=['none', 'automap', 'snatlist', 'snatpool']
            ),
            snat_list=dict(
                type='list',
                elements='str'
            ),
            snat_pool=dict(),
            rules=dict(
                type='list',
                elements='str'
            ),
            proxy_type=dict(
                choices=['explicit', 'transparent']
            ),
            auth_offload=dict(
                type='bool'
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            dump_json=dict(
                type='bool',
                default='no'
            )
        )
        self.required_if = [
            ['snat', 'snatlist', ['snat_list']],
            ['snat', 'snatpool', ['snat_pool']]
        ]
        self.mutually_exclusive = [
            ['snat_list', 'snat_pool']
        ]
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    if not HAS_NETADDR:
        module.fail_json(
            msg=missing_required_lib('netaddr'),
            exception=NETADDR_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
