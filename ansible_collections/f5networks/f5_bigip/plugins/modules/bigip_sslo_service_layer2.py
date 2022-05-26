#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_service_layer2
short_description: Manage an SSL Orchestrator Layer 2 security device
description:
  - Manage an SSL Orchestrator Layer 2 security device.
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name of the Layer 2 security service.
      - The configuration auto-prepends "ssloS_" to the service.
      - The service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  devices:
    description:
      - Specifies the set of network settings for traffic going to the service from the BIG-IP.
      - Multiple devices are defined as separate list items.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Defines the name of this specific device.
        type: str
        required: True
      ratio:
        description:
          - Defines a load balancing ratio setting for this device.
        type: int
        required: True
      vlan_in:
        description:
          - Defines an existing VLAN to attach on the to-service side.
          - The C(vlan_in) and C(interface_in) and C(tag_in) options are mutually exclusive.
        type: str
      interface_in:
        description:
          - Defines the interface on the to-service side.
          - The C(vlan_in) and C(interface_in) and C(tag_in) options are mutually exclusive.
        type: str
      tag_in:
        description:
          - Defines the VLAN tag on the to-service side.
        type: int
      vlan_out:
        description:
          - Defines an existing VLAN to attach on the from-service side.
          - The C(vlan_out) and C(interface_out) and C(tag_out) options are mutually exclusive.
        type: str
      interface_out:
        description:
          - Defines the interface on the from-service side.
          - The C(vlan_out) and C(interface_out) and C(tag_out) options are mutually exclusive.
        type: str
      tag_out:
        description:
          - Defines the VLAN tag on the from-service side (as required).
        type: int
  monitor:
    description:
      - Specifies the monitor attached to the L2 security device pool.
      - The monitor must already exist on the BIG-IP.
      - When creating a L2 service, if the parameter is not provided a default of C(/Common/gateway_icmp) is assumed.
    type: str
  ip_offset:
    description:
      - Defines an IP offset integer to be used in the internal IP addressing.
      - This parameter is required when creating a new L2 service.
      - Accepted values are in the range of C(0) to C(30).
      - This is typically used in a tiered architecture, where a Layer 2 service is shared between multiple
        standalone SSL Orchestrator instances.
    type: int
  port_remap:
    description:
      - Defines the port to remap decrypted traffic to.
    type: int
  rules:
    description:
      - Defines a list of iRules to attach to the service.
    type: list
    elements: str
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
        C(MODIFY) on an existing service no JSON output is generated.
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
    - name: Create SSLO L2 service
      bigip_sslo_service_layer2:
        name: "layer2a"
        devices:
          - name: "FEYE1"
            ratio: 1
            interface_in: "1.1"
            tag_in: 100
            interface_out: "1.1"
            tag_out: 101
        ip_offset: 1
        port_remap: 8283

    - name: Modify SSLO L2 service
      bigip_sslo_service_layer2:
        name: "layer2a"
        devices:
          - name: "FEYE1"
            ratio: 1
            vlan_in: "/Common/L2service_vlan_in"
            interface_out: "1.1"
            tag_out: 101

    - name: Delete SSLO L2 service
      bigip_sslo_service_layer2:
        name: "layer2a"
        state: "absent"
'''

RETURN = r'''
interfaces:
  description:
    - The list of interfaces created for each specified device.
  returned: changed
  type: list
  sample: [hash/dictionary of values]
networks:
  description:
    - The list of networks created for each specified device.
  returned: changed
  type: list
  sample: [hash/dictionary of values]
devices_ips:
  description:
    - The list of IP addresses created for each specified device.
  returned: changed
  type: list
  sample: [hash/dictionary of values]
service_subnet:
  description:
    - The service subnet created for L2 inline service
  returned: changed
  type: dict
  sample: [hash/dictionary of values]
monitor:
  description:
    - The monitor attached to the L2 security device pool.
  returned: changed
  type: str
  sample: /Common/gateway_icmp
service_down_action:
  description:
    - The action to take on monitor failure.
  type: str
  returned: changed
  sample: ignore
port_remap:
  description:
    - Port remap settings.
  type: int
  returned: changed
  sample: 8080
rules:
  description:
    - List of iRules attached to the service.
  returned: changed
  type: list
  sample: ["/Common/test-rule-1", "/Common/test-rule-2"]
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
from ..module_utils.constants import (
    min_sslo_version, max_sslo_version
)
from ..module_utils.compare import compare_complex_list
from ..module_utils.sslo_templates.sslo_service_layer2 import (
    create, modify
)


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []

    returnables = [
        'interfaces',
        'networks',
        'devices_ips',
        'monitor',
        'service_down_action',
        'port_remap',
        'service_subnet',
        'rules'
    ]

    updatables = [
        'interfaces',
        'networks',
        'devices_ips',
        'monitor',
        'service_down_action',
        'port_remap',
        'service_subnet',
        'rules'
    ]


class ApiParameters(Parameters):
    @property
    def interfaces(self):
        devices = self._values['customService']['connectionInformation']['interfaces']
        if not devices:
            return None
        result = list()
        for device in devices:
            dev = dict(from_vlan=dict(), to_vlan=dict())
            dev['from_vlan']['name'] = device['fromBigipVlan']['name']
            dev['from_vlan']['path'] = device['fromBigipVlan']['path']
            if device['fromBigipVlan'].get('interface', None):
                dev['from_vlan']['interface'] = device['fromBigipVlan']['interface'][0]
            if device['fromBigipVlan'].get('tag', None):
                dev['from_vlan']['tag'] = int(device['fromBigipVlan']['tag'])
            dev['to_vlan']['name'] = device['toBigipVlan']['name']
            dev['to_vlan']['path'] = device['toBigipVlan']['path']
            if device['toBigipVlan'].get('interface', None):
                dev['to_vlan']['interface'] = device['toBigipVlan']['interface'][0]
            if device['toBigipVlan'].get('tag', None):
                dev['to_vlan']['tag'] = int(device['toBigipVlan']['tag'])
            result.append(dev)
        return result

    @property
    def network_ids(self):
        devices = self._values['customService']['connectionInformation']['interfaces']
        if not devices:
            return None
        result = dict()
        for device in devices:
            if 'networkBlockId' in device['fromBigipVlan'].keys():
                result[device['fromBigipVlan']['name']] = device['fromBigipVlan']['networkBlockId']
            if 'networkBlockId' in device['toBigipVlan'].keys():
                result[device['toBigipVlan']['name']] = device['toBigipVlan']['networkBlockId']
        if result:
            return result

    @property
    def networks(self):
        networks = self._values['networkObjects']
        if not networks:
            # check modifiedNetworkObjects list and return None if empty
            networks = self._values['modifiedNetworkObjects']
            if not networks:
                return None
        result = list()
        for network in networks:
            element = dict()
            element['name'] = network['name']
            element['path'] = network['vlan']['path']
            element['interface'] = network['vlan']['interface'][0]
            element['tag'] = int(network['vlan']['tag'])
            result.append(element)
        return result

    @property
    def devices_ips(self):
        devices = self._values['customService']['loadBalancing']['devices']
        if not devices:
            return None
        result = list()
        for device in devices:
            dev = dict(ratio=None, ip=list())
            dev['ratio'] = device['ratio']
            dev['ip'] = device['ip']
            result.append(dev)
        return result

    @property
    def service_subnet(self):
        result = dict()
        result['ipv4'] = self._values['customService']['managedNetwork']['ipv4']['serviceSubnet']
        result['ipv6'] = self._values['customService']['managedNetwork']['ipv6']['serviceSubnet']
        return result

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
    def rules(self):
        return self._values['customService']['iRuleList']


class ModuleParameters(Parameters):
    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('ssloS_'):
            name = "ssloS_" + name
        return name

    @property
    def networks(self):
        if self._values['devices'] is None:
            return None
        result = list()
        for device in self._values['devices']:
            if 'interface_in' in device.keys() and device['interface_in']:
                element = dict()
                element['name'] = f"ssloN_{device['name']}_in"
                element['path'] = f"/Common/ssloN_{device['name']}_in.app/ssloN_{device['name']}_in"
                element['interface'] = device['interface_in']
                element['tag'] = device.get('tag_in', None)
                result.append(element)
            if 'interface_out' in device.keys() and device['interface_out']:
                element = dict()
                element['name'] = f"ssloN_{device['name']}_out"
                element['path'] = f"/Common/ssloN_{device['name']}_out.app/ssloN_{device['name']}_out"
                element['interface'] = device['interface_out']
                element['tag'] = device.get('tag_out', None)
                result.append(element)
        return result

    @property
    def interfaces(self):
        if self._values['devices'] is None:
            return None
        result = list()
        for device in self._values['devices']:
            dev = dict(from_vlan=dict(), to_vlan=dict())
            if 'interface_in' in device.keys() and device['interface_in']:
                dev['from_vlan']['name'] = f"ssloN_{device['name']}_in"
                dev['from_vlan']['path'] = f"/Common/ssloN_{device['name']}_in.app/ssloN_{device['name']}_in"
                dev['from_vlan']['interface'] = device['interface_in']
                dev['from_vlan']['tag'] = device.get('tag_in', None)
            if 'interface_out' in device.keys() and device['interface_out']:
                dev['to_vlan']['name'] = f"ssloN_{device['name']}_out"
                dev['to_vlan']['path'] = f"/Common/ssloN_{device['name']}_out.app/ssloN_{device['name']}_out"
                dev['to_vlan']['interface'] = device['interface_out']
                dev['to_vlan']['tag'] = device.get('tag_out', None)
            if 'vlan_in' in device.keys() and device['vlan_in']:
                dev['from_vlan']['name'] = f"ssloN_{device['name']}_in"
                dev['from_vlan']['path'] = device['vlan_in']
            if 'vlan_out' in device.keys() and device['vlan_out']:
                dev['to_vlan']['name'] = f"ssloN_{device['name']}_out"
                dev['to_vlan']['path'] = device['vlan_out']
            result.append(dev)
        return result

    @property
    def devices_ips(self):
        if self._values['devices'] is None:
            return None
        if not self.ip_offset:
            return None
        services_ip4_list = {1: 30, 2: 62, 3: 95, 4: 126, 5: 158, 6: 190, 7: 222, 8: 255}
        services_ip6_list = {1: "1e", 2: "3e", 3: "5e", 4: "7e", 5: "9e", 6: "ae", 7: "ce", 8: "ee"}
        service_cnt = 1
        result = list()
        ip4_offset_octet = 32 + self.ip_offset
        ip6_offset_octet = 200 + self.ip_offset
        for device in self._values['devices']:
            dev = dict(ratio=None, ip=list())
            dev['ratio'] = self._ratio_check(device.get('ratio', None))
            dev['ip'].append(f"198.19.{str(ip4_offset_octet)}.{str(services_ip4_list[service_cnt])}")
            dev['ip'].append(f"2001:0200:0:{str(ip6_offset_octet)}::{str(services_ip6_list[service_cnt])}")
            service_cnt += service_cnt
            result.append(dev)
        return result

    @property
    def service_subnet(self):
        if not self.ip_offset:
            return None
        result = dict()
        ip4_offset_octet = 32 + self.ip_offset
        ip6_offset_octet = 200 + self.ip_offset
        result['ipv4'] = f"198.19.{str(ip4_offset_octet)}.0"
        result['ipv6'] = f"2001:0200:0:{str(ip6_offset_octet)}::"
        return result

    @property
    def ip_offset(self):
        if self._values['ip_offset'] is None:
            return None
        if 0 <= self._values['ip_offset'] <= 30:
            return self._values['ip_offset']
        raise F5ModuleError(
            "IP Offset value must be in range 0 - 30."
        )

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

    @staticmethod
    def _ratio_check(item):
        if item is None:
            return None
        if 1 <= item <= 65535:
            return str(item)
        raise F5ModuleError(
            "Ratio value must be in range 1 - 65535."
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
    @property
    def networks(self):
        networks = self._values['networks']
        net_ids = self._values['network_ids']
        result = list()
        if networks is None:
            return networks
        if net_ids is None:
            return networks
        for network in networks:
            net_id = net_ids.get(network['name'], None)
            if net_id:
                network['block_id'] = net_id
            result.append(network)
        return result

    @property
    def interfaces(self):
        interfaces = self._values['interfaces']
        net_ids = self._values['network_ids']
        result = list()
        if interfaces is None:
            return interfaces
        for intf in interfaces:
            if 'from_vlan' in intf.keys() and 'interface' in intf['from_vlan'].keys():
                if net_ids:
                    net_id = net_ids.get(intf['from_vlan']['name'], None)
                    if net_id:
                        intf['from_vlan']['create'] = False
                        intf['from_vlan']['block_id'] = net_id
                    else:
                        intf['from_vlan']['create'] = True
                else:
                    intf['from_vlan']['create'] = True
            else:
                intf['from_vlan']['create'] = False
            if 'to_vlan' in intf.keys() and 'interface' in intf['to_vlan'].keys():
                if net_ids:
                    net_id = net_ids.get(intf['to_vlan']['name'], None)
                    if net_id:
                        intf['to_vlan']['create'] = False
                        intf['to_vlan']['block_id'] = net_id
                    else:
                        intf['to_vlan']['create'] = True
                else:
                    intf['to_vlan']['create'] = True
            else:
                intf['to_vlan']['create'] = False
            result.append(intf)
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
        except AttributeError:
            return attr1

    @property
    def networks(self):
        return compare_complex_list(self.want.networks, self.have.networks)

    @property
    def interfaces(self):
        return compare_complex_list(self.want.interfaces, self.have.interfaces)

    @property
    def rules(self):
        return compare_complex_list(self.want.rules, self.have.rules)

    @property
    def devices(self):
        return compare_complex_list(self.want.devices, self.have.devices)

    @property
    def service_subnet(self):
        return compare_complex_list(self.want.service_subnet, self.have.service_subnet)


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
            changed['network_ids'] = None
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
            changed['network_ids'] = self.have.network_ids
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
        self.have = self.read_current_from_device()
        task_id, output = self.remove_from_device()
        if task_id:
            self.wait_for_task(task_id)
        if output:
            self.json_dump = output
            return False
        return True

    def create(self):
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

    def _populate_intf_ids(self):
        interfaces = self.have.interfaces
        net_ids = self.have.network_ids
        result = list()
        for intf in interfaces:
            intf['from_vlan']['create'] = False
            intf['to_vlan']['create'] = False
            if 'interface' in intf['from_vlan'].keys():
                net_id = net_ids.get(intf['from_vlan']['name'], None)
                if net_id:
                    intf['from_vlan']['block_id'] = net_id
            if 'interface' in intf['to_vlan'].keys():
                net_id = net_ids.get(intf['to_vlan']['name'], None)
                if net_id:
                    intf['to_vlan']['block_id'] = net_id
            result.append(intf)
        return result

    def _populate_net_ids(self):
        networks = self.have.networks
        net_ids = self.have.network_ids
        result = list()
        for network in networks:
            net_id = net_ids.get(network['name'], None)
            if net_id:
                network['block_id'] = net_id
            result.append(network)
        return result

    def check_for_required_creation_parameters(self):
        if self.want.ip_offset is None:
            raise F5ModuleError('The ip_offset parameter is required when creating a new layer2 SSLO service')

    def add_create_values(self, payload):
        if self.want.monitor is None:
            payload['monitor'] = '/Common/gateway_icmp'
        if self.want.service_down_action is None:
            payload['service_down_action'] = 'ignore'
        return payload

    def add_missing_options(self, payload):
        if self.changes.interfaces is None and self.have.interfaces:
            payload['interfaces'] = self._populate_intf_ids()
        if self.changes.networks is None and self.have.networks:
            payload['networks'] = self._populate_net_ids()
        if self.changes.devices_ips is None:
            payload['devices_ips'] = self.have.devices_ips
        if self.changes.monitor is None:
            payload['monitor'] = self.have.monitor
        if self.changes.service_down_action is None:
            payload['service_down_action'] = self.have.service_down_action
        if self.changes.port_remap is None:
            payload['port_remap'] = self.have.port_remap
        if self.changes.service_subnet is None:
            payload['service_subnet'] = self.have.service_subnet
        if self.changes.rules is None:
            payload['rules'] = self.have.rules
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

        output = process_json(data, create)

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

        output = process_json(data, modify)

        if self.want.dump_json:
            return None, output

        uri = "/mgmt/shared/iapp/blocks/"
        response = self.client.post(uri, data=output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = str(response['contents']['id'])
        return task_id, None

    def remove_from_device(self):
        data = self.add_missing_options(self.add_json_metadata())

        output = process_json(data, modify)

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
                    name=dict(required=True),
                    ratio=dict(required=True, type='int'),
                    vlan_in=dict(),
                    vlan_out=dict(),
                    interface_in=dict(),
                    interface_out=dict(),
                    tag_in=dict(type='int'),
                    tag_out=dict(type='int')
                ),
                mutually_exclusive=[
                    ['vlan_in', 'interface_in'],
                    ['vlan_out', 'interface_out'],
                    ['vlan_in', 'tag_in'],
                    ['vlan_out', 'tag_out']
                ],
                required_one_of=[
                    ['vlan_in', 'interface_in'],
                    ['vlan_out', 'interface_out']
                ]
            ),
            monitor=dict(),
            service_down_action=dict(
                choices=['ignore', 'reset', 'drop']
            ),
            port_remap=dict(
                type='int'
            ),
            ip_offset=dict(
                type='int',
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
