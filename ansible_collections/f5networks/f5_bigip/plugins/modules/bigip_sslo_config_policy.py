#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_policy
short_description: Manage an SSL Orchestrator security policy
description:
  - Manage an SSL Orchestrator security policy
version_added: "1.7.0"
options:
  name:
    description:
      - Specifies the name of the security policy.
      - Configuration auto-prepends "ssloP_" to the policy.
      - The policy name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  policy_consumer:
    description:
      - Specifies the type of policy, either "outbound" or "inbound".
    type: str
    choices:
      - outbound
      - inbound
  proxy_connect:
    description:
      - Specifies the proxy-connect settings, as required, to establish an upstream proxy chain egress.
    type: dict
    suboptions:
      pool_members:
        description:
          - Defines Pools members which we want to associate for new pool
          - Mutually exclusive with the C(pool_name) parameter.
        type: list
        elements: dict
        suboptions:
           ip:
             description:
               - IP address of the pool member to be added
             type: str
             required: True
           port:
             description:
               - Port number to be associated with the pool member IP address.
             type: int
      pool_name:
        description:
          - Defines an existing pool to be used for proxy connection.
          - Mutually exclusive with C(pool_members).
        type: str
      username:
        description:
          - Defines username to be used for proxy connection.
        type: str
      password:
        description:
          - Defines password pool to be used for proxy connection.
        type: str
  servercert_check:
    description:
      - Enables or disables server certificate validation.
    type: bool
  policy_rules:
    description:
      - Defines the policy rules to apply to the security policy, in defined order.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Defines the name of the policy rule.
        type: str
      match_type:
        description:
          - Defines the match type when multiple conditions are applied to a single rule.
        type: str
        choices:
          - match_any
          - match_all
      conditions:
        description:
          - Defines the list of conditions within this rule.
        type: list
        elements: dict
        suboptions:
          condition_type:
            description:
              - Defines the name of the policy rule.
            type: str
            choices:
              - category_lookup_all
              - category_lookup_sni
              - category_lookup_httpconnect
              - ssl_check
              - client_port_match
              - server_port_match
              - client_ip_subnet_match
              - server_ip_subnet_match
              - tcp_l7_protocol_lookup
              - client_ip_geolocation
              - server_ip_geolocation
          condition_option_category:
            description:
              - A list of URL categories (ex. "Financial and Data Services").
              - Should be used when c(condition_type) matches c(category_lookup_all) or c(category_lookup_sni).
            type: list
            elements: str
          geolocations:
            description:
              - A list of 'type' and 'value' keys, where type can be 'countryCode', 'countryName', 'continent', or 'state'.
              - Should be used when c(condition_type) matches c(client_ip_geolocation) or c(server_ip_geolocation).
            type: list
            elements: dict
          condition_option_ports:
            description:
              - Defines a list of ports.
              - Should be used when c(condition_type) matches c(client_port_match) or c(server_port_match).
            type: list
            elements: str
          condition_option_subnet:
            description:
              - Defines a list of IP subnets.
              - Should be used with when c(condition_type) matches c(client_ip_subnet_match) or c(server_ip_subnet_match)
            type: list
            elements: str
          condition_option_protocol:
            description:
              - Defines the protocols.
            type: list
            elements: str
      policy_action:
        description:
          - Defines the policy action to be applied for this rule.
        type: str
        choices:
          - allow
          - reject
          - abort
      ssl_forwardproxy_action:
        description:
          - Defines the TLS intercept/bypass behavior for this rule
        type: str
        choices:
          - bypass
          - intercept
      service_chain:
        description:
          - Defines the service chain to attach to this rule.
        type: str
  dump_json:
    description:
      - Sets the module to output a JSON blob for further consumption.
      - When C(yes) does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes to be made during
        C(MODIFY) on an existing service, no JSON output will be generated.
    type: bool
    default: no
  timeout:
    description:
      - The amount of time, to wait for the C(CREATE) or C(MODIFY) task to complete, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the policy is created or modified.
      - When C(state) is C(absent), ensures the policy is removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy(@chinthalapalli)
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
    - name: SSLO config policy
      bigip_sslo_config_policy:
        name: "testpolicy"
        servercert_check: true
        proxy_connect:
          username: "testuser"
          password: ""
          pool_members:
            - ip: "192.168.30.10"
              port: 100
        policy_rules:
          - name: "testrule"
            match_type: "match_any"
            policy_action: "reject"
            conditions:
              - condition_type: "category_lookup_all"
                condition_option_category:
                  - "Financial Data and Services"
                  - "General Email"
              - condition_type: "client_port_match"
                condition_option_ports:
                  - "80"
                  - "90"
              - condition_type: "client_ip_geolocation"
                geolocations:
                  - type: "countryCode"
                    value: "US"
                  - type: "countryCode"
                    value: "UK"
          - name: "testrule2"
            match_type: "match_all"
            policy_action: "reject"
            conditions:
              - condition_type: "category_lookup_all"
                condition_option_category:
                  - "Financial Data and Services"
                  - "General Email"
              - condition_type: "client_port_match"
                condition_option_ports:
                  - "80"
                  - "90"
      delegate_to: localhost
'''

RETURN = r'''

'''

import re
import time
import ipaddress
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
from ..module_utils.sslo_templates.sslo_config_policy import (
    create_modify, delete
)

condition_type = {'category_lookup_all': 'Category Lookup',
                  'category_lookup_sni': "SNI Category Lookup",
                  'category_lookup_httpconnect': "HTTP Connect Category Lookup",
                  'ssl_check': "SSL Check",
                  'client_port_match': "Client Port Match",
                  'server_port_match': "Server Port Match",
                  'client_ip_subnet_match': "Client IP Subnet Match",
                  'server_ip_subnet_match': "Server IP Subnet Match",
                  'tcp_l7_protocol_lookup': "TCP L7 Protocol Lookup",
                  'client_ip_geolocation': "Client IP Geolocation",
                  'server_ip_geolocation': "Server IP Geolocation"
                  }

condition_type_list = ['category_lookup_all', 'category_lookup_sni', 'category_lookup_httpconnect', 'ssl_check',
                       'client_port_match', 'server_port_match', 'client_ip_subnet_match', 'server_ip_subnet_match',
                       'tcp_l7_protocol_lookup', 'client_ip_geolocation', 'server_ip_geolocation']

category_list = ['category_lookup_all', 'category_lookup_sni', 'category_lookup_httpconnect']
port_list = ['client_port_match', 'server_port_match']
subnet_list = ['client_ip_subnet_match', 'server_ip_subnet_match']
protocol_list = ['tcp_l7_protocol_lookup', 'udp_l7_protocol_lookup']
geolocation_list = ['client_ip_geolocation', 'server_ip_geolocation']

condition_category = {'general_mail': "General Email",
                      'financial_data_and_services': "Financial Data and Services"
                      }

condition_category_list = [
    "Files Containing Passwords",
    "File Download Servers",
    "Facebook Video Upload",
    "Facebook Questions",
    "Abortion",
    "Abused Drugs",
    "Adult Content",
    "Adult Material",
    "Advanced Malware Command and Control",
    "Advanced Malware Payloads",
    "Advertisements",
    "Advocacy Groups",
    "Alcohol and Tobacco",
    "Alternative Journals",
    "Application and Software Download",
    "Bandwidth",
    "Blog Commenting",
    "Blog Posting",
    "Blogs and Personal Sites",
    "Bot Networks",
    "Business and Economy",
    "Classifieds Posting",
    "Collaboration - Office",
    "Compromised Websites",
    "Computer Security",
    "Content Delivery Networks",
    "Cultural Institutions",
    "Custom-Encrypted Uploads",
    "Drugs",
    "Dynamic Content",
    "Dynamic DNS",
    "Education",
    "Educational Institutions",
    "Educational Materials",
    "Educational Video",
    "Elevated Exposure",
    "Emerging Exploits",
    "Entertainment",
    "Entertainment Video",
    "Extended Protection",
    "Facebook Apps",
    "Facebook Chat",
    "Facebook Commenting",
    "Facebook Events",
    "Facebook Friends",
    "Facebook Games",
    "Facebook Groups",
    "Facebook Mail",
    "Facebook Photo Upload",
    "Facebook Posting",
    "Financial Data and Services",
    "Gambling",
    "Games",
    "Gay or Lesbian or Bisexual Interest",
    "General Email",
    "Government",
    "Hacking",
    "Health and Medicine",
    "Hosted Business Applications",
    "Illegal or Questionable",
    "Information Technology",
    "Instant Messaging",
    "Internet Auctions",
    "Internet Communication",
    "Internet Radio and TV",
    "Internet Telephony",
    "Intolerance",
    "Job Search",
    "Keyloggers and Monitoring",
    "Lingerie and Swimsuit",
    "LinkedIn Connections",
    "LinkedIn Jobs",
    "LinkedIn Mail",
    "LinkedIn Updates",
    "Malicious Embedded Link",
    "Malicious Embedded iFrame",
    "Malicious Web Sites",
    "Marijuana",
    "Media File Download",
    "Message Boards and Forums",
    "Militancy and Extremist",
    "Military",
    "Miscellaneous",
    "Mobile Malware",
    "Network Errors",
    "Newly Registered Websites",
    "News and Media",
    "Non-Traditional Religions",
    "Nudity",
    "Nutrition",
    "Office - Apps",
    "Office - Documents",
    "Office - Drive",
    "Office - Mail",
    "Online Brokerage and Trading",
    "Organizational Email",
    "Parked Domain",
    "Pay to Surf",
    "Peer-to-Peer File Sharing",
    "Personal Network Storage and Backup",
    "Personals and Dating",
    "Phishing and Other Frauds",
    "Political Organizations",
    "Potentially Exploited Documents",
    "Potentially Unwanted Software",
    "Prescribed Medications",
    "Private IP Addresses",
    "Pro-Choice",
    "Pro-Life",
    "Productivity",
    "Professional and Worker Organizations",
    "Proxy Avoidance",
    "Real Estate",
    "Recreation and Hobbies",
    "Reference and Research",
    "Religion",
    "Restaurants and Dining",
    "Search Engines and Portals",
    "Security",
    "Service and Philanthropic Organizations",
    "Sex",
    "Sex Education",
    "Shopping",
    "Social Networking",
    "Social Organizations",
    "Social Web - Facebook",
    "Social Web - LinkedIn",
    "Social Web - Twitter",
    "Social Web - Various",
    "Social Web - YouTube",
    "Social and Affiliation Organizations",
    "Society and Lifestyles",
    "Special Events",
    "Sport Hunting and Gun Clubs",
    "Sports",
    "Spyware and Adware",
    "Streaming Media",
    "Surveillance",
    "Suspicious Content",
    "Suspicious Embedded Link",
    "Tasteless",
    "Text and Media Messaging",
    "Traditional Religions",
    "Travel",
    "Twitter Follow",
    "Twitter Mail",
    "Twitter Posting",
    "Unauthorized Mobile Marketplaces",
    "Uncategorized",
    "Vehicles",
    "Violence",
    "Viral Video",
    "Weapons",
    "Web Analytics",
    "Web Chat",
    "Web Collaboration",
    "Web Hosting",
    "Web Images",
    "Web Infrastructure",
    "Web and Email Marketing",
    "Web and Email Spam",
    "Website Translation",
    "YouTube Commenting",
    "YouTube Sharing",
    "YouTube Video Upload",
    "Pinners"
]


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = []
    updatables = [
        'proxy_connect',
        'pools',
        'policy_consumer'
        'policy_rules',
        'servercert_check',
    ]
    returnables = [
        'proxy_connect',
        'pools',
        'policy_consumer',
        'policy_rules',
        'servercert_check',
    ]


class ApiParameters(Parameters):
    @property
    def policy_consumer(self):
        return self._values['policyConsumer']['type']

    @property
    def policy_rules(self):
        return self._values['rules']

    @property
    def servercert_check(self):
        return self._values['serverCertStatusCheck']

    @property
    def proxy_connect(self):
        return self._values['proxyConfigurations']

    @property
    def pools(self):
        return self._values['pools']


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
        if not name.startswith('ssloP_'):
            name = "ssloP_" + name
        return name

    @property
    def policy_consumer(self):
        policy_consumer = self._values['policy_consumer']
        if policy_consumer is None:
            return "Outbound"
        return policy_consumer

    @property
    def servercert_check(self):
        if self._values['servercert_check'] is None:
            return False
        return True

    @property
    def proxy_connect(self):
        if self._values['proxy_connect'] is None:
            return {}
        proxy_config = dict()
        proxy_config['isProxyChainEnabled'] = True
        proxy_config['username'] = self._values['proxy_connect']['username']
        proxy_config['password'] = self._values['proxy_connect']['password']
        proxy_config_pool = dict()
        if 'pool_members' in self._values['proxy_connect'] and \
                self._values['proxy_connect']['pool_members'] is not None:
            proxy_config_pool['create'] = True
            pool_members = list()
            for mem in self._values['proxy_connect']['pool_members']:
                tmpdict = dict()
                tmpdict['ip'] = mem['ip']
                if 'port' not in mem.keys() or not mem['port']:
                    tmpdict['port'] = 80
                else:
                    tmpdict['port'] = self._port_check(int(mem['port']))
                # tmpdict['port'] = str(mem['port'])
                # # self._port_check(mem['port'])
                pool_members.append(tmpdict)
            proxy_config_pool['members'] = pool_members
            proxy_config_pool[
                'name'] = f"/Common/ssloP_{self._values['name']}.app/ssloP_{self._values['name']}_proxyChainPool"

        if 'pool_name' in self._values['proxy_connect'] and self._values['proxy_connect']['pool_name'] is not None:
            proxy_config_pool['create'] = False
            proxy_config_pool['name'] = self._values['proxy_connect']['pool_name']

        proxy_config['pool'] = proxy_config_pool
        return proxy_config

    @property
    def pools(self):
        if self._values['proxy_connect'] is None:
            return {}
        pools = dict()
        pool_detail = dict()
        pool_detail['name'] = f"ssloP_{self._values['name']}_proxyChainPool"
        pool_detail['loadBalancingMode'] = "predictive-node"
        pool_detail['monitors'] = {"names": ["/Common/gateway_icmp"]}
        pool_detail['unhandledPool'] = True
        pool_detail['callerContext'] = "policyConfigProcessor"

        if 'pool_members' in self._values['proxy_connect'] and \
                self._values['proxy_connect']['pool_members'] is not None:
            pool_members = list()
            for mem in self._values['proxy_connect']['pool_members']:
                tmpdict = dict()
                tmpdict['ip'] = mem['ip']
                if 'port' not in mem.keys() or not mem['port']:
                    tmpdict['port'] = 80
                else:
                    tmpdict['port'] = self._port_check(int(mem['port']))
                pool_members.append(tmpdict)
            pool_detail['members'] = pool_members

        pools[f"ssloP_{self._values['name']}_proxyChainPool"] = pool_detail
        return pools

    @property
    def policy_rules(self):
        if self._values['policy_rules'] is None:
            return {}
        result = list()
        for rule in self._values['policy_rules']:
            policy_rule = dict()
            policy_rule['name'] = rule['name']
            policy_rule['operation'] = 'AND' if rule['match_type'] == 'match_all' else 'OR'
            policy_rule['mode'] = "edit"
            policy_rule['action'] = "reject"
            if rule['policy_action'] is not None:
                policy_rule['action'] = rule['policy_action']
            action_option = dict()
            action_option['ssl'] = ""
            action_option['serviceChain'] = ""
            if rule['policy_action'] == 'allow':
                action_option['ssl'] = "" if rule['ssl_forwardproxy_action'] is None else rule[
                    'ssl_forwardproxy_action']
                action_option['serviceChain'] = "" if rule['service_chain'] is None else rule['service_chain']

            policy_rule['actionOptions'] = action_option
            condtns = rule['conditions'] if 'conditions' in rule else []

            policy_rule['conditions'] = condtns
            condition_result = list()
            for cond in condtns:
                if cond['condition_type'] is None:
                    raise F5ModuleError(
                        "condition_type must be specified for each policy condition"
                    )
                if cond['condition_type'] in category_list:
                    cla = dict()
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    for opt in cond['condition_option_category']:
                        if opt in condition_category_list:
                            r1.append(opt)
                        else:
                            raise F5ModuleError(f"condition_option_category '{opt}' must be one of : {condition_category_list}")
                    cla['options'] = {
                        "category": r1
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in port_list:
                    cla = dict()
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    for opt in cond['condition_option_ports']:
                        r1.append(opt)
                    cla['options'] = {
                        "port": r1
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in subnet_list:
                    cla = dict()
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    for opt in cond['condition_option_subnet']:
                        r1.append(opt)
                    cla['options'] = {
                        "subnet": r1
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in protocol_list:
                    cla = dict()
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    for opt in cond['condition_option_protocol']:
                        r1.append(opt)
                    cla['options'] = {
                        "subnet": r1
                    }
                    condition_result.append(cla)

                if cond['condition_type'] in geolocation_list:
                    cla = dict()
                    cla['type'] = condition_type[cond['condition_type']]
                    r1 = list()
                    for opt in cond['geolocations']:
                        tmp = dict()
                        tmp['matchType'] = opt['type']
                        tmp['value'] = opt['value']
                        r1.append(tmp)
                    cla['options'] = {
                        "geolocations": r1
                    }
                    condition_result.append(cla)

            policy_rule['conditions'] = condition_result
            result.append(policy_rule)
        default_rule = dict()
        default_rule['name'] = "All Traffic"
        default_rule['action'] = "allow"
        default_rule['mode'] = "edit"
        default_rule['actionOptions'] = {"ssl": "", "serviceChain": ""}
        default_rule['isDefault'] = True
        result.append(default_rule)
        return result

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
    def policy_rules(self):
        return compare_complex_list(self.want.policy_rules, self.have.policy_rules)

    @property
    def proxy_connect(self):
        return compare_complex_list(self.want.proxy_connect, self.have.proxy_connect)

    @property
    def pools(self):
        return compare_complex_list(self.want.pools, self.have.pools)


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
                # if isinstance(change, dict):
                #     changed.update(change)
                # else:
                changed[k] = change
        del changed['pools']
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

    def check_for_required_create_parameters(self):
        pass

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

    def add_create_values(self, params):
        if self.want.policy_consumer is None:
            params['policy_consumer'] = 'Outbound'
        if self.want.servercert_check is None:
            params['servercert_check'] = False

        return params

    def add_missing_options(self, params):
        if self.changes.policy_consumer is None:
            params['policy_consumer'] = self.have.policy_consumer
        if self.changes.proxy_connect is None:
            params['proxy_connect'] = self.have.proxy_connect
        if self.changes.policy_rules is None:
            params['policy_rules'] = self.have.policy_rules
        if self.changes.pools is None:
            params['pools'] = self.have.pools
        if self.changes.servercert_check is None:
            params['servercert_check'] = self.have.servercert_check
        return params

    def add_json_metadata(self, payload=None):
        if not payload:
            payload = dict()
        payload['name'] = f"sslo_obj_SECURITY_POLICY_{self.operation}_{self.want.name}"
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


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            policy_consumer=dict(
                choices=['outbound', 'inbound'],
            ),
            policy_rules=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(),
                    match_type=dict(
                        choices=['match_any', 'match_all']
                    ),
                    conditions=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            condition_type=dict(
                                choices=['category_lookup_all', 'category_lookup_sni', 'category_lookup_httpconnect',
                                         'ssl_check', 'client_port_match', 'server_port_match',
                                         'client_ip_subnet_match', 'server_ip_subnet_match', 'tcp_l7_protocol_lookup',
                                         'client_ip_geolocation', 'server_ip_geolocation']
                            ),
                            condition_option_category=dict(
                                type='list',
                                elements='str'
                            ),
                            geolocations=dict(type='list', elements='dict'),
                            condition_option_ports=dict(type='list', elements='str'),
                            condition_option_subnet=dict(type='list', elements='str'),
                            condition_option_protocol=dict(type='list', elements='str'),
                        ),
                        required_if=[
                            ('condition_type', 'client_port_match', ['condition_option_ports'], True),
                            ('condition_type', 'client_port_match', ['condition_option_ports'], True),
                            ('condition_type', 'category_lookup_all', ['condition_option_category'], True),
                            ('condition_type', 'category_lookup_sni', ['condition_option_category'], True),
                            ('condition_type', 'category_lookup_httpconnect', ['condition_option_category'], True),
                            ('condition_type', 'client_ip_subnet_match', ['condition_option_subnet'], True),
                            ('condition_type', 'server_ip_subnet_match', ['condition_option_subnet'], True),
                            ('condition_type', 'tcp_l7_protocol_lookup', ['condition_option_protocol'], True),
                            ('condition_type', 'udp_l7_protocol_lookup', ['condition_option_protocol'], True),
                            ('condition_type', 'client_ip_geolocation', ['geolocations'], True),
                            ('condition_type', 'server_ip_geolocation', ['geolocations'], True)
                        ]

                    ),
                    policy_action=dict(
                        choices=['allow', 'reject', 'abort']
                    ),
                    ssl_forwardproxy_action=dict(
                        choices=['bypass', 'intercept']
                    ),
                    service_chain=dict(),
                ),
                required_if=[
                    ('policy_action', 'allow', ('ssl_forwardproxy_action', 'service_chain'), True)]
            ),
            proxy_connect=dict(
                type='dict',
                options=dict(
                    pool_members=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            ip=dict(required=True),
                            port=dict(type='int')
                        )
                    ),
                    pool_name=dict(),
                    username=dict(),
                    password=dict(
                        no_log=True
                    )
                ),
                mutually_exclusive=[
                    ['pool_members', 'pool_name']]
            ),
            servercert_check=dict(type='bool'),
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
        # required_if=spec.required_if
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
