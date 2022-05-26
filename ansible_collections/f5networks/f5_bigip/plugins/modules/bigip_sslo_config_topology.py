#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_sslo_config_topology
short_description: Manage an SSL Orchestrator Topology
description:
  - Manage an SSL Orchestrator topology
version_added: "1.7.0"
options:
  name:
    description:
      - Specifies the name of the topology.
      - Configuration auto-prepends "sslo_" to the topology.
      - Topology name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  topology_type:
    description:
      - Defines the type of topology to create.
    type: str
    required: True
    choices:
      - outbound_l3
      - inbound_l3
      - outbound_explicit
      - outbound_l2
      - inbound_l2
  protocol:
    description:
      - "Defines the topology protocol, either TCP, UDP, or other (non-tcp/non-udp)."
      - When creating a new topology object, if protocol is not specified, a value of C(tcp) is assumed.
    type: str
    choices:
      - tcp
      - udp
      - other
  ip_family:
    description:
      - Defines the IP family for the topology.
      - When creating a new topology object, if ip_family is not specified, a value of C(ipv4) is assumed.
    type: str
    choices:
      - ipv4
      - ipv6
  source:
    description:
      - Defines the source address filter and optional route domain for the topology listener.
      - The address must be specified in CIDR notation, with subnet mask not exceeding 32 bits.
      - When creating a new topology object, if source is not specified, a value of C(0.0.0.0%0/0) is assumed.
    type: str
  dest:
    description:
      - Defines the destination address filter and optional route domain for the topology listener.
      - The address must be specified in CIDR notation, with subnet mask not exceeding 32 bits.
      - When creating a new topology object, if dest is not specified, a value of C(0.0.0.0%0/0) is assumed.
    type: str
  port:
    description:
      - Defines the port filter for the topology listener.
      - When creating a new topology object, if port is not specified, a value of C(0) is assumed.
      - Valid value range is from C(0) to C(65535).
    type: int
  snat:
    description:
      - Defines the type egress source NAT used.
      - When C(none), no outbound SNAT configuration is configured. This is the default choice when creating a topology
        object if the parameter is not provided.
      - When C(topology_type) is either set to C(l2_outbound) or C(l2_inbound), a C(snat) is automatically
        set to C(none).
      - When C(automap), SNAT auto map is configured.
      - When C(snatpool), the SNAT configuration points to an existing SNAT pool defined by the C(snatpool) parameter.
      - When C(snatlist), a new SNAT pool is created from the provided C(snatlist).
    type: str
    choices:
      - none
      - automap
      - snatpool
      - snatlist
  snat_pool:
    description:
      - Defines an existing SNAT pool.
      - This parameter required when C(snat) is set to C(snatpool).
    type: str
  snat_list:
    description:
      - Defines a list of IP addresses to use in a SNAT pool configuration.
      - This parameter is required when C(snat) is set to C(snatlist).
    type: list
    elements: str
  vlans:
    description:
      - Defines the list of listening VLANs for the topology listener.
      - This parameter is required when creating new topology object.
    type: list
    elements: str
  gateway:
    description:
      - Defines the type of egress gateway to use for egress traffic.
      - When C(system) is set, a system-defined gateway route is used. This is the default choice when a creating topology
        object if the parameter is not provided.
      - When C(topology_type) is either set to C(l2_outbound) or C(l2_inbound), a C(gateway) is automatically
        set to C(system).
      - When C(pool), the gateway configuration points to an existing gateway pool defined by the C(gateway_pool) parameter.
      - When C(iplist), a new gateway pool is created from the provided C(gateway_list).
    type: str
    choices:
      - system
      - pool
      - iplist
  gateway_pool:
    description:
      - Defines an existing gateway pool to use for egress traffic.
      - This parameter is required when C(gateway) is set to C(pool).
    type: str
  gateway_list:
    description:
      - Defines a list of IP addresses to use in a gateway pool configuration.
      - This parameter is required when C(gateway) is set to C(iplist).
    type: list
    elements: dict
    suboptions:
      ip:
        description:
          - The IP address of the gateway in pool.
        type: str
        required: True
      ratio:
        description:
          - The ratio used for load balancing egress traffic in the gateway pool.
          - When creating a new topology object, if ratio is not specified, a value of C(1) is assumed.
          - Valid value range is from C(1) to C(65535).
        type: int
  tcp_settings_client:
    description:
      - Defines a custom client side TCP profile to use.
      - This parameter is ignored when C(topology_type) is set to C(outbound_explicit).
      - When not specified, the default creation value is set depending on the C(topology_type). If C(topology_type)
        is either set to C(l2_inbound) or C(l3_inbound), the value is set to C(/Common/f5-tcp-wan). If C(topology_type)
        is either set to C(l2_outbound or C(l3_outbound), the value is set to C(/Common/f5-tcp-lan).
    type: str
  tcp_settings_server:
    description:
      - Defines a custom server side TCP profile to use.
      - This parameter is ignored when C(topology_type) is set to C(outbound_explicit).
      - When not specified, the default creation value is set depending on the C(topology_type). If C(topology_type)
        is either set to C(l2_inbound) or C(l3_inbound) the value is set to C(/Common/f5-tcp-lan). If C(topology_type)
        is either set to C(l2_outbound or C(l3_outbound) the value is set to C(/Common/f5-tcp-wan).
    type: str
  l7_profile_type:
    description:
      - Defines the L7 protocol type, and can either be C(none) for all protocols, or C(http).
      - When creating a new topology object, if l7_profile_type is not specified, a value of C(http) is assumed.
    type: str
    choices:
      - none
      - http
  l7_profile:
    description:
      - Defines the specific HTTP profile if the C(l7_profile_type) is set to C(http).
      - When creating a new topology object, if l7_profile is not specified, a value of C(/Common/http) is assumed.
    type: str
  additional_protocols:
    description:
      - Defines a list of additional protocols to create listeners for.
      - This parameter is only valid when C(protocol) is set to C(tcp).
      - "Accepted values of this list are: C(ftp), C(imap), C(pop3), C(smtps)."
    type: list
    elements: str
  access_profile:
    description:
      - Defines a custom access profile to use.
      - When not specified, a topology-defined access profile is created.
      - This parameter is mandatory when C(topology_type) is C(outbound_explicit) or when C(security_policy) is set.
    type: str
  profile_scope:
    description:
      - Defines the access profile scope.
      - This parameter applies to SSLO version 8.2 and later.
    type: str
    choices:
      - public
      - named
  profile_scope_value:
    description:
      - Defines a string name shared between the transparent proxy SSL Orchestrator profile and the captive
        portal authentication access profile.
      - This parameter applies to SSLO version 8.2 and later.
      - Required when the C(profile_scope) option is C(named).
    type: str
  primary_auth_uri:
    description:
      - "Defines the authentication service (ie. captive portal) to redirect new users to."
      - "This setting should contain a fully-qualified domain name (ex. https://auth.f5labs.com)."
      - This parameter applies to SSLO version 8.2 and later.
      - Required when the C(profile_scope) option is C(named).
    type: str
  verify_accept:
    description:
      - Enables TCP Verify Accept proxy through an outbound topology.
      - This parameter is available in SSLO version 9.0 and later.
    type: bool
  ocsp_auth:
    description:
      - This setting defines an OCSP Authentication profile.
      - This parameter is available in SSLO version 9.0 and later.
    type: str
  proxy_ip:
    description:
      - Defines the explicit proxy listener IP address.
      - This parameter is required when C(topology_type) is is C(outbound_explicit).
      - This parameter is mutually exclusive with C(dest) and C(port).
      - This parameter must be specified together with C(proxy_port).
    type: str
  proxy_port:
    description:
      - Defines the explicit proxy listener port.
      - This parameter is required when C(topology_type) is is C(outbound_explicit).
      - This parameter is mutually exclusive with C(dest) and C(port).
      - This parameter must be specified together with C(proxy_ip).
    type: int
  auth_profile:
    description:
      - Defines an access profile to use for explicit proxy authentication.
    type: str
  dns_resolver:
    description:
      - Defines a per-topology DNS resolver configuration object.
      - This parameter is available in SSLO version 9.0 and above.
    type: str
  pool:
    description:
      - Defines a server pool to use in an application mode inbound topology.
    type: str
  logging:
    description:
      - Defines the setting of logging characteristics for an SSL Orchestrator topology.
    type: dict
    suboptions:
      sslo:
        description:
          - Defines the logging facility used for the SSL Orchestrator summary logging.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - warning
          - error
          - notice
          - information
          - debug
      per_request_policy:
        description:
          - Defines the logging facility used for the SSL Orchestrator security policy logging.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - warning
          - error
          - notice
          - information
          - debug
      ftp:
        description:
          - Defines the logging facility used for the SSL Orchestrator FTP listener logging.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - warning
          - error
          - notice
          - information
          - debug
      imap:
        description:
          - Defines the logging facility used for the SSL Orchestrator IMAP listener logging.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - warning
          - error
          - notice
          - information
          - debug
      pop3:
        description:
          - Defines the logging facility used for the SSL Orchestrator POP3 listener logging.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - warning
          - error
          - notice
          - information
          - debug
      smtps:
        description:
          - Defines the logging facility used for the SSL Orchestrator SMTPS listener logging.
        type: str
        choices:
          - emergency
          - alert
          - critical
          - warning
          - error
          - notice
          - information
          - debug
  ssl_settings:
    description:
      - Defines the name of the SSL settings object already created.
      - Configuration auto-prepends "ssloT_" to provided name if not present.
    type: str
  security_policy:
    description:
      - Defines the name of the security policy object already created.
      - Configuration auto-prepends "ssloP_" to provided name if not present.
      - This parameter is mandatory when C(proxy_type) is C(outbound_explicit).
    type: str
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
      - When C(state) is C(absent), ensures the object is removed.
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
    - name: Create SSLO Topology
      bigip_sslo_topology:
        name: "l3_topo_out"
        topology_type: "outbound_l3"
        dest: "192.168.1.4%0/32"
        port: 8080
        ip_family: "ipv4"
        ssl_settings: "foobar"
        vlans:
          - "/Common/fake1"

    - name: Delete SSLO Topology
      bigip_sslo_topology:
        name: "l3_topo_out"
        topology_type: "outbound_l3"
        state: "absent"
'''

RETURN = r'''
# only common fields returned
'''

import re
import ipaddress
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
    min_sslo_version, max_sslo_version, json_template_gs
)
from ..module_utils.sslo_templates.sslo_config_topology import (
    create_modify, delete
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'topology',
        'ip_family',
        'rule',
        'proxy_type',
        'dep_net',
        'dest',
        'proxy_ip',
        'pool',
        'source',
        'port',
        'proxy_port',
        'tcp_settings_client',
        'tcp_settings_server',
        'vlans',
        'protocol',
        'additional_protocols',
        'profile_scope',
        'profile_scope_value',
        'primary_auth_uri',
        'ocsp_auth',
        'snat_list',
        'snat',
        'gateway',
        'gateway_list',
        'logging',
        'ssl_settings',
        'security_policy',
        'verify_accept'
    ]

    updatables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @staticmethod
    def _port_check(item):
        if item is None:
            return None
        if 0 <= item <= 65535:
            return item
        raise F5ModuleError(
            "Valid ports must be in range 0 - 65535."
        )

    @staticmethod
    def _ratio_check(item):
        if not 1 <= item <= 65535:
            raise F5ModuleError(
                "Ratio value must be in range 1 - 65535."
            )

    @staticmethod
    def _add_zero_rd(item):
        ip = re.search(r'^.*%(\d+).*$', item)
        if ip:
            return item
        iplist = item.split('/')
        iplist[0] = re.sub('%.*', '', iplist[0])
        result = iplist[0] + "%0/" + iplist[1]
        return result

    @staticmethod
    def _check_for_subnet(item):
        net = re.search(r'^.*/(\d+)$', item)
        if net is None:
            raise F5ModuleError('Address must contain a subnet (CIDR) value <= 32.')
        if int(net.group(1)) > 32:
            raise F5ModuleError('Address must contain a subnet (CIDR) value <= 32.')

    @property
    def name(self):
        name = self._values['name']
        if not name.startswith('sslo_'):
            if len(name) > 15:
                raise F5ModuleError('Maximum allowed name length is 15 characters.')
            name = "sslo_" + name
        return name

    @property
    def topology(self):
        api_values = {
            'outbound_l3': 'topology_l3_outbound',
            'inbound_l3': 'topology_l3_inbound',
            'outbound_explicit': 'topology_l3_explicit_proxy',
            'outbound_l2': 'topology_l2_outbound',
            'inbound_l2': 'topology_l2_inbound'
        }
        return api_values[self._values['topology_type']]

    @property
    def rule(self):
        topology = self.topology
        if topology in ['topology_l2_outbound', 'topology_l3_outbound', 'topology_l3_explicit_proxy']:
            return 'Outbound'
        if topology in ['topology_l2_inbound', 'topology_l3_inbound']:
            return 'Inbound'

    @property
    def proxy_type(self):
        topology = self.topology
        if topology in ['topology_l2_outbound', 'topology_l3_outbound']:
            return 'transparent'
        if topology == 'topology_l3_explicit_proxy':
            return 'explicit'

    @property
    def dep_net(self):
        topology = self.topology
        if topology in ['topology_l2_inbound', 'topology_l2_outbound']:
            return 'l2_network'

    @property
    def dest(self):
        if self._values['dest'] is None:
            return None
        self._check_for_subnet(self._values['dest'])
        return self._add_zero_rd(self._values['dest'])

    @property
    def source(self):
        if self._values['source'] is None:
            return None
        self._check_for_subnet(self._values['source'])
        return self._add_zero_rd(self._values['source'])

    @property
    def port(self):
        return self._port_check(self._values['port'])

    @property
    def proxy_port(self):
        return self._port_check(self._values['proxy_port'])

    @property
    def tcp_settings_client(self):
        topology = self.topology
        if self._values['tcp_settings_client'] is None:
            return None
        if topology == 'topology_l3_explicit_proxy':
            return None
        return self._values['tcp_settings_client']

    @property
    def tcp_settings_server(self):
        topology = self.topology
        if self._values['tcp_settings_server'] is None:
            return None
        if topology == 'topology_l3_explicit_proxy':
            return None
        return self._values['tcp_settings_server']

    @property
    def vlans(self):
        if self._values['vlans'] is None:
            return None
        result = list()
        for vlan in self._values['vlans']:
            element = dict()
            element['name'] = vlan
            element['value'] = vlan
            result.append(element)
        return result

    @property
    def additional_protocols(self):
        add_prot = self._values['additional_protocols']
        protocol = self._values['protocol']
        if add_prot is None:
            return None
        if protocol is not None and protocol != 'tcp':
            raise F5ModuleError("The 'additional_protocols' parameter can only be used with TCP traffic.")
        else:
            result = list()
            for proto in add_prot:
                element = dict()
                if proto not in ['ftp', 'imap', 'pop3', 'smtps']:
                    raise F5ModuleError(
                        f"Acceptable values for the 'additional_protocols' parameter are 'ftp', 'imap', 'pop3', "
                        f"and 'smtps'. Received: '{proto}'.")
                element['name'] = proto.upper()
                element['value'] = proto
                result.append(element)
            return result

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
        if self.topology in ['topology_l2_outbound', 'topology_l2_inbound'] or snat == 'none':
            return 'None'
        elif snat == 'automap':
            return 'AutoMap'
        elif snat == 'snatlist':
            return 'SNAT'
        elif snat == 'snatpool':
            return 'existingSNAT'

    @property
    def gateway(self):
        gateway = self._values['gateway']
        if gateway is None:
            return None
        if self.topology in ['topology_l2_outbound', 'topology_l2_inbound'] or gateway == 'system':
            return 'useDefault'
        elif gateway == 'pool':
            return 'existingGatewayPool'
        elif gateway == 'iplist':
            return 'newGatewayPool'

    @property
    def gateway_list(self):
        result = list()
        gateways = self._values['gateway_list']
        if gateways is None:
            return None
        for gw in gateways:
            if 'ratio' in gw.keys() and gw['ratio']:
                self._ratio_check(gw['ratio'])
            else:
                gw['ratio'] = 1
            result.append(gw)
        return result

    @property
    def logging(self):
        log_map = {
            'emergency': 'emerg',
            'alert': 'alert',
            'critical': 'crit',
            'warning': 'warn',
            'error': 'err',
            'notice': 'notice',
            'information': 'info',
            'debug': 'debug'
        }
        logging = self._values['logging']
        if logging is None:
            return None
        result = dict()
        for key in logging.keys():
            if logging.get(key):
                result[key] = log_map[logging.get(key)]
        if result:
            return result

    @property
    def ssl_settings(self):
        name = self._values['ssl_settings']
        if not name.startswith('ssloT_'):
            name = "ssloT_" + name
        return name

    @property
    def security_policy(self):
        name = self._values['security_policy']
        if not name.startswith('ssloP_'):
            name = "ssloP_" + name
        return name

    @property
    def verify_accept(self):
        result = flatten_boolean(self._values['verify_accept'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

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

    def return_sslo_global(self):
        uri = "/mgmt/shared/iapp/blocks/"
        query = "?$filter=name+eq+'ssloGS_global'"
        response = self.client.get(uri + query)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if len(response['contents']["items"]) > 0:
            response = response['contents']["items"][0]["inputProperties"][0]["value"]
            return response
        else:
            gs = json_template_gs
            gs["version"] = self.version
            gs["previousVersion"] = self.version
            return gs

    def present(self):
        if self.exists():
            return False
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

    @staticmethod
    def _same_ip_family(ip1, ip2):
        tmp1 = re.sub('/.*', '', re.sub('%.*', '', ip1))
        tmp2 = re.sub('/.*', '', re.sub('%.*', '', ip2))
        add1 = ipaddress.ip_address(tmp1)
        add2 = ipaddress.ip_address(tmp2)
        return add1.version == add2.version

    def validate_parameters(self, params):
        if not params.get('vlans'):
            raise F5ModuleError('At least one VLAN must be defined.')
        if params.get('source'):
            if params.get('dest'):
                if not self._same_ip_family(params['source'], params['dest']):
                    raise F5ModuleError('Source and destination addresses must be in the same IP family.')
            if params.get('proxy_ip'):
                if not self._same_ip_family(params['source'], params['proxy_ip']):
                    raise F5ModuleError('Source and proxy addresses must be in the same IP family.')
        if LooseVersion(self.version) < LooseVersion('8.2'):
            if params.get('primary_auth_uri') or params.get('profile_scope_value') or params.get('profile_scope'):
                raise F5ModuleError(
                    f"The 'primary_auth_uri', 'profile_scope_value' or 'profile_scope' are supported on "
                    f"SSLO version 8.2 and above, your SSLO version is {self.version}."
                )
        if LooseVersion(self.version) < LooseVersion('9.0'):
            if params.get('ocsp_auth'):
                raise F5ModuleError(
                    f"The 'ocsp_auth' key is supported on "
                    f"SSLO version 9.0 and above, your SSLO version is {self.version}."
                )
            if params.get('verify_accept') or params.get('verify_accept') is False:
                raise F5ModuleError(
                    f"The 'verify_accept' key is supported on "
                    f"SSLO version 9.0 and above, your SSLO version is {self.version}."
                )
        if params['topology'] == 'topology_l3_outbound':
            if params.get('protocol') == 'tcp':
                if not params.get('ssl_settings'):
                    raise F5ModuleError('The Outbound L3 topology for TCP traffic requires an ssl_settings key.')
            if params.get('protocol') == 'udp':
                if params.get('ssl_settings'):
                    raise F5ModuleError('The Outbound L3 topology for UDP traffic cannot contain an ssl_settings key.')
            if params.get('protocol') == 'other':
                if params.get('ssl_settings'):
                    raise F5ModuleError(
                        'The Outbound L3 topology for non-TCP/non-UDP traffic cannot contain an ssl_settings key.'
                    )
                if params.get('security_policy'):
                    raise F5ModuleError(
                        'The Outbound L3 topology for non-TCP/non-UDP traffic cannot contain a security_policy key.'
                    )
            if LooseVersion(self.version) >= LooseVersion('8.2'):
                if params.get('protocol'):
                    if params['protocol'] != 'tcp':
                        if params.get('primary_auth_uri'):
                            raise F5ModuleError(
                                "The 'primary_auth_uri' key can only be used with an outbound L3 TCP topology."
                            )
                        if params.get('profile_scope_value'):
                            raise F5ModuleError(
                                "The 'profile_scope_value' key can only be used with an outbound L3 TCP topology."
                            )
        if params['topology'] == 'topology_l2_outbound':
            if params.get('protocol') == 'tcp':
                if not params.get('ssl_settings'):
                    raise F5ModuleError('The Outbound L2 topology for TCP traffic requires an ssl_settings key.')
            if params.get('protocol') == 'udp':
                if params.get('ssl_settings'):
                    raise F5ModuleError('The Outbound L2 topology for UDP traffic cannot contain an ssl_settings key.')
            if params.get('protocol') == 'other':
                if params.get('ssl_settings'):
                    raise F5ModuleError(
                        'The Outbound L2 topology for non-TCP/non-UDP traffic cannot contain an ssl_settings key.'
                    )
                if params.get('security_policy'):
                    raise F5ModuleError(
                        'The Outbound L2 topology for non-TCP/non-UDP traffic cannot contain a security_policy key.'
                    )
            if LooseVersion(self.version) >= LooseVersion('8.2'):
                if params.get('protocol'):
                    if params['protocol'] != 'tcp':
                        if params.get('primary_auth_uri'):
                            raise F5ModuleError(
                                "The 'primary_auth_uri' key can only be used with an outbound L2 TCP topology."
                            )
                        if params.get('profile_scope_value'):
                            raise F5ModuleError(
                                "The 'profile_scope_value' key can only be used with an outbound L2 TCP topology."
                            )
        if params['topology'] == 'topology_l3_explicit_proxy':
            if not params.get('proxy_ip'):
                raise F5ModuleError(
                    "The 'proxy_ip' is required when creating explicit proxy type topology."
                )
            if not params.get('security_policy'):
                raise F5ModuleError(
                    "The 'security_policy' is required when creating explicit proxy type topology."
                )
        if params['topology'] != 'topology_l3_explicit_proxy':
            if params.get('proxy_ip'):
                raise F5ModuleError(
                    "The 'proxy_ip' key is only to be used with explicit proxy type, use 'dest' key instead."
                )

    def add_create_values(self, params):
        if self.want.protocol is None:
            params['protocol'] = 'tcp'
        if self.want.ip_family is None:
            params['ip_family'] = 'ipv4'
        if self.want.topology != 'topology_l3_explicit_proxy':
            if self.want.dest is None:
                params['dest'] = '0.0.0.0%0/0'
            if self.want.port is None:
                params['port'] = 0
        if self.want.topology == 'topology_l3_explicit_proxy':
            if self.want.proxy_port is None:
                params['port'] = 0
        if self.want.topology in ['topology_l2_inbound', 'topology_l3_inbound']:
            if self.want.tcp_settings_client is None:
                params['tcp_settings_client'] = '/Common/f5-tcp-wan'
            if self.want.tcp_settings_server is None:
                params['tcp_settings_server'] = '/Common/f5-tcp-lan'
        if self.want.topology in ['topology_l2_outbound', 'topology_l3_outbound']:
            if self.want.tcp_settings_client is None:
                params['tcp_settings_client'] = '/Common/f5-tcp-lan'
            if self.want.tcp_settings_server is None:
                params['tcp_settings_server'] = '/Common/f5-tcp-wan'
        if self.want.source is None:
            params['source'] = '0.0.0.0%0/0'
        if self.want.snat == 'existingSNAT':
            params['snat_ref_id'] = self.want.snat_pool
        if self.want.gateway == 'existingGatewayPool':
            params['gw_ref_id'] = self.want.gateway_pool
        if self.want.access_profile is None:
            if self.want.security_policy is not None:
                params['access_profile'] = f'/Common/{self.want.name}.app/{self.want.name}_accessProfile'
        if self.want.l7_profile_type is None:
            params['l7_profile_type'] = 'http'
        if self.want.l7_profile is None:
            params['l7_profile'] = '/Common/http'
        return params

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_TOPOLOGY_{self.operation}_{self.want.name}"
        payload['deployment_name'] = self.want.name
        payload['operation'] = self.operation
        payload['sslo_version'] = float(self.version)
        if self.operation != 'DELETE':
            payload['resolver'] = self.return_sslo_global()
        if self.operation == 'DELETE':
            payload['dep_ref'] = f"https://localhost/mgmt/shared/iapp/blocks/{self.block_id}"
            payload['block_id'] = self.block_id
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
        self.validate_parameters(data)

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
        self.logging = ['emergency', 'alert', 'critical', 'warning', 'error', 'notice', 'information', 'debug']
        argument_spec = dict(
            name=dict(required=True),
            topology_type=dict(
                required=True,
                choices=['outbound_l3', 'inbound_l3', 'outbound_explicit', 'outbound_l2', 'inbound_l2']
            ),
            protocol=dict(
                choices=['tcp', 'udp', 'other']
            ),
            ip_family=dict(
                choices=['ipv4', 'ipv6'],
            ),
            source=dict(),
            dest=dict(),
            port=dict(
                type='int'
            ),
            snat=dict(
                choices=['none', 'automap', 'snatpool', 'snatlist'],
            ),
            snat_list=dict(
                type='list',
                elements='str',
            ),
            vlans=dict(
                type='list',
                elements='str'
            ),
            snat_pool=dict(),
            gateway=dict(
                choices=['system', 'pool', 'iplist']
            ),
            gateway_list=dict(
                type='list',
                elements='dict',
                options=dict(
                    ip=dict(required=True),
                    ratio=dict(type='int')
                )
            ),
            gateway_pool=dict(),
            tcp_settings_client=dict(),
            tcp_settings_server=dict(),
            l7_profile_type=dict(
                choices=['none', 'http']
            ),
            l7_profile=dict(),
            additional_protocols=dict(
                type='list',
                elements='str'
            ),
            access_profile=dict(),
            profile_scope=dict(
                choices=['public', 'named']
            ),
            profile_scope_value=dict(),
            primary_auth_uri=dict(),
            verify_accept=dict(type='bool'),
            ocsp_auth=dict(),
            proxy_ip=dict(),
            proxy_port=dict(type='int'),
            auth_profile=dict(),
            dns_resolver=dict(),
            pool=dict(),
            logging=dict(
                type='dict',
                options=dict(
                    sslo=dict(choices=self.logging),
                    per_request_policy=dict(choices=self.logging),
                    ftp=dict(choices=self.logging),
                    imap=dict(choices=self.logging),
                    pop3=dict(choices=self.logging),
                    smtps=dict(choices=self.logging),
                )
            ),
            ssl_settings=dict(),
            security_policy=dict(),
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
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['snat', 'snatlist', ['snat_list']],
            ['snat', 'snatpool', ['snat_pool']],
            ['gateway', 'pool', ['gateway_pool']],
            ['gateway', 'iplist', ['gateway_list']],
            ['profile_scope', 'named', ['profile_scope_value', 'primary_auth_uri']],
        ]
        self.required_together = [
            ['dest', 'port'],
            ['proxy_ip', 'proxy_port']
        ]
        self.mutually_exclusive = [
            ['snat_list', 'snat_pool'],
            ['gateway_list', 'gateway_pool'],
            ['dest', 'proxy_ip'],
            ['dest', 'proxy_port'],
            ['port', 'proxy_ip'],
            ['port', 'proxy_port']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
        required_together=spec.required_together,
        required_if=spec.required_if
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
