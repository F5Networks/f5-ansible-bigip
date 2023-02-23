#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_awaf_policy
short_description: Manage WAF policy with input parameters
description:
  - Manage WAF policy with input parameters.
version_added: 2.0.0
options:
  name:
    description:
      - The unique user-given name of the policy. Policy names cannot contain spaces or special characters.
      - Parameter mutually exclusive with C(policy_id).
      - Parameter is mandatory when creating a new WAF policy.
    type: str
  policy_id:
    description:
      - The device generated id of existing WAF policy.
      - Parameter mutually exclusive with C(name).
    type: str
  template:
    description:
      - Specifies the name of the template used for WAF policy creation.
      - Parameter is required when creating a new WAF policy.
    type: str
  language:
    description:
      - The character encoding for the web application.
      - The character encoding determines how the policy processes the character sets.
      - When unspecified the parameter is set to C(auto-detect) when creating a new WAF policy.
    type: str
    choices:
      - auto-detect
      - big5
      - euc-jp
      - euc-kr
      - gb18030
      - gb2312
      - gbk
      - iso-8859-1
      - iso-8859-10
      - iso-8859-13
      - iso-8859-15
      - iso-8859-16
      - iso-8859-2
      - iso-8859-3
      - iso-8859-4
      - iso-8859-5
      - iso-8859-6
      - iso-8859-7
      - iso-8859-8
      - iso-8859-9
      - koi8-r
      - shift_jis
      - utf-8
      - windows-1250
      - windows-1251
      - windows-1252
      - windows-1253
      - windows-1255
      - windows-1256
      - windows-1257
      - windows-874
  case_insensitive:
    description:
      - Specifies whether the security policy treats microservice URLs, file types, URLs, and parameters as case
        sensitive or not.
      - When C(yes), the system stores these security policy elements in lowercase in the security policy configuration.
      - When unspecified parameter is set to C(no) when creating a new WAF policy.
    type: bool
  enable_passive_mode:
    description:
      - When C(yes), the policy can be associated with a Performance L4 Virtual Server.
      - When unspecified parameter is set to C(no) when creating a new WAF policy.
    type: bool
  protocol_independent:
    description:
      - When C(yes), the security policy differentiates between HTTP and HTTPS.
      - When C(not), the security policy configures URLs without specifying a specific protocol.
      - When unspecified parameter is set to C(no) when creating a new WAF policy.
    type: bool
  enforcement_mode:
    description:
      - Defines how the system processes a request that triggers a security policy violation.
      - When C(blocking), the traffic is blocked if it causes a violation.
      - When C(transparent), the traffic is not blocked even if a violation is triggered.
      - When unspecified parameter is set to C(transparent) when creating a new WAF policy.
    type: str
    choices:
      - blocking
      - transparent
  type:
    description:
      - The type of policy to be created.
      - Whem C(parent), the policy can be used as a basis for similar child policies. Parent policy settings can be
        inherited to its child policies. A parent policy cannot be applied to Virtual Servers.
      - When C(security), the policy can be created from a parent policy or as a stand-alone policy.
        Changes to a security policy do not affect other security policies.
        A security policy can be applied to a virtual server.
      - When unspecified parameter is set to C(security) when creating a new WAF policy.
    type: str
    choices:
     - parent
     - security
  server_technologies:
    description:
      - The server technology is a server-side application, framework, web server or operating system type that is
        configured in the policy in order to adapt the policy to the checks needed for the respective technology.
      - Parameter must be specified when creating new WAF policy.
      - "The valid elements that can be specified in the list are: ASP, ASP.NET, AngularJS, Apache Struts,
        Apache Tomcat, Apache/NCSA HTTP Server, BEA Systems WebLogic Server, Backbone.js, CGI, Cisco, Citrix,
        CodeIgniter, CouchDB, Django, Elasticsearch, Ember.js, Express.js, Front Page Server Extensions (FPSE),
        Google Web Toolkit, GraphQL, Handlebars, IBM DB2, IIS, JBoss, Java Servlets/JSP, JavaScript,
        JavaServer Faces (JSF), Jenkins, Jetty, Joomla, Laravel, Lotus Domino, Macromedia ColdFusion, Macromedia JRun,
        Microsoft SQL Server, Microsoft Windows, MongoDB, MooTools, Mustache, MySQL, Nginx, Node.js, Novell, Oracle,
        Oracle Application Server, Oracle Identity Manager, Outlook Web Access, PHP, PostgreSQL, Prototype,
        Proxy Servers, Python, React, Redis, RequireJS, Ruby, SQLite, SSI (Server Side Includes), SharePoint,
        Spring Boot, Sybase/ASE, TYPO3 CMS, UIKit, Underscore.js, Unix/Linux, Vue.js, WebDAV, WordPress, XML,
        ZURB Foundation, Zend, ef.js, jQuery."
    type: list
    elements: str
  pb_learning_mode:
    description:
      - Learning setting for Policy Builder.
      - When unspecified parameter is set to C(manual) when creating a new WAF policy.
    type: str
    choices:
      - automatic
      - disabled
      - manual
  allowed_file_types:
    description:
      - List of allowed file types.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Defines the name of the file.
        type: str
        required: True
      type:
        description:
          - Defines if the value provided in C(name) is to be treated as C(explicit) or a C(wildcard).
        type: str
        required: True
        choices:
          - explicit
          - wildcard
  disallowed_file_types:
    description:
      - List of disallowed file types.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Defines the name of the file.
          - The type of this file is always explicit.
        type: str
        required: True
  open_api_files:
    description:
      - List of links for open api files on the policy.
    type: list
    elements: str
  policy_in_json:
    description:
      - User provided JSON for a WAF policy, normally used as a end user template for rapid policy deployments.
      - The parameters in this module, when specified take precedence over parameters defined in C(policy_in_json), and
        will overwrite then when a new WAF policy is created.
      - When using C(policy_in_json) to modify an existing WAF policy, the C(force) parameter must C(yes) in order
        to apply the C(policy_in_json) in its entirety as each WAF contains parameters not covered by the parameters
        in this module, therefore there is no comparison operation run on them, and they remain unchanged on the device.
    type: raw
  force:
    description:
      - If C(yes), the C(policy_in_json) will be applied in its entirety over the existing WAF policy.
      - When C(yes) module operations are not idempotent.
    type: bool
    default: no
  dump_json:
    description:
      - Sets the module to output a WAF policy JSON for further consumption.
      - When C(yes), does not make any changes on the device and always returns C(changed=False).
      - The output provided is idempotent in nature, meaning if there are no changes to be made the output will not be
        generated except when C(force) is set to C(yes).
      - Parameter mutually exclusive with C(apply_policy).
    type: bool
    default: no
  apply_policy:
    description:
      - When C(yes) after applies WAF policy after creating or modifying.
      - Parameter mutually exclusive with C(dump_json).
    type: bool
    default: no
  description:
    description:
      - Specifies descriptive text that identifies WAF policy.
    type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the security WAF policy is created/modified.
      - When C(absent), ensures the security WAF policy is removed.
    type: str
    choices:
      - absent
      - present
    default: present
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
    - name: Create aWAF policy with json template
      bigip_awaf_policy:
        name: "foobar_awaf"
        policy_in_json: "{{ lookup('file', 'awaf_big_policy.json') }}"
        server_technologies:
          - "Apache Tomcat"
        apply_policy: "yes"

    - name: Create aWAF policy without json
      bigip_awaf_policy:
        name: "custom_awaf"
        server_technologies:
          - "AngularJS"
          - "Apache Struts"
          - "Apache Tomcat"
        template: "POLICY_TEMPLATE_RAPID_DEPLOYMENT"
        pb_learning_mode: "disabled"
        allowed_file_types:
          - name: "js"
            type: "explicit"
          - name: "jpg"
            type: "explicit"
        disallowed_file_types:
          - name: "php"
        apply_policy: "yes"

    - name: Modify aWAF policy using policy_id
      bigip_awaf_policy:
        policy_id: "{{ policy_id }}"
        language: "utf-8"
        pb_learning_mode: "manual"
        apply_policy: 'yes'

    - name: Overwrite existing aWAF policy with json template
      bigip_awaf_policy:
        name: "foobar_awaf"
        policy_in_json: "{{ lookup('file', 'awaf_new_policy.json') }}"
        server_technologies:
          - "AngularJS"
        allowed_file_types:
          - name: "php"
            type: "explicit"
          - name: "jpg"
            type: "explicit"
          - name: "js"
            type: "explicit"
        disallowed_file_types:
          - name: "*"
        apply_policy: "yes"
        force: "yes"

    - name: Remove aWAF policies
      bigip_awaf_policy:
        name: "foobar_awaf"
        state: absent
'''

RETURN = r'''
policy_id:
  description:
    - The device generated id of existing or created WAF policy.
  returned: changed
  type: str
  sample: "yE48MEYUzFoeevnd8UjAoQ"
json_string:
  description:
    - Policy JSON in an escaped string format.
  returned: changed
  type: str
  sample: "\n{\n   \"policy\" : {\n      \"name\": \"foobar_awaf\",\n      \"fullPath\": \"/Common/foobar_awaf\"\n"
description:
  description:
    - Specifies descriptive text that identifies WAF policy.
  returned: changed
  type: str
  sample: this is a new policy
template:
  description:
    - Specifies the name of the template used for WAF policy creation.
  returned: changed
  type: str
  sample: POLICY_TEMPLATE_RAPID_DEPLOYMENT
language:
  description:
    - The character encoding for the web application.
  returned: changed
  type: str
  sample: utf-8
case_insensitive:
  description:
    - Specifies whether the security policy treats microservice URLs, file types, URLs, and parameters as case
      sensitive or not.
  returned: changed
  type: bool
  sample: no
enable_passive_mode:
  description:
    - Specifies whether the security policy can be associated with a Performance L4 Virtual Server.
  returned: changed
  type: bool
  sample: no
protocol_independent:
  description:
    - Specifies whether the security policy differentiates between HTTP and HTTPS.
  returned: changed
  type: bool
  sample: no
enforcement_mode:
  description:
    - Defines how the system processes a request that triggers a security policy violation.
  returned: changed
  type: str
  sample: blocking
type:
  description:
    - The type of policy to be created.
  returned: changed
  type: str
  sample: security
server_technologies:
  description:
    - The list of server technologies applied on the WAF policy.
  returned: changed
  type: list
  sample: ['ef.js', 'jQuery']
pb_learning_mode:
  description:
    - Learning setting for Policy Builder.
  returned: changed
  type: str
  sample: manual
allowed_file_types:
  description:
    - List of allowed file types.
  returned: changed
  type: complex
  contains:
    name:
      description:
        - Defines the name of the file.
      type: str
      returned: changed
      sample: php
    type:
      description:
        - Defines if the value provided in name is to be treated as explicit) or a wildcard.
      type: str
      returned: changed
      sample: explicit
disallowed_file_types:
  description:
    - List of disallowed file types.
  returned: changed
  type: complex
  contains:
    name:
      description:
        - Defines the name of the file.
      type: str
      returned: changed
      sample: php
open_api_files:
  description:
    - List of links for open api files on the policy.
  returned: changed
  type: list
  sample: ['http://foobar.com/file/api/foo.txt']
'''

import json
import os
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import (
    string_types, iteritems
)

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean, fq_name, process_json
)
from ..module_utils.compare import compare_complex_list
from ..module_utils.awaf_templates.awaf_policy import create_modify


class Parameters(AnsibleF5Parameters):
    api_map = {
        'applicationLanguage': 'language',
        'caseInsensitive': 'case_insensitive',
        'fullPath': 'full_path',
        'enablePassiveMode': 'enable_passive_mode',
        'enforcementMode': 'enforcement_mode',
        'filetypes': 'file_types',
        'open-api-files': 'open_api_files',
        'server-technologies': 'server_technologies',
        'policy-builder': 'policy_builder',
        'protocolIndependent': 'protocol_independent'
    }

    api_attributes = []

    returnables = [
        'description',
        'template',
        'language',
        'case_insensitive',
        'enable_passive_mode',
        'protocol_independent',
        'enforcement_mode',
        'type',
        'server_technologies',
        'policy_builder',
        'file_types',
        'open_api_files'
    ]

    updatables = [
        'description',
        'template',
        'language',
        'case_insensitive',
        'enable_passive_mode',
        'protocol_independent',
        'enforcement_mode',
        'type',
        'server_technologies',
        'policy_builder',
        'file_types',
        'open_api_files'
    ]


class ApiParameters(Parameters):
    api_map = {
        'applicationLanguage': 'language',
        'caseInsensitive': 'case_insensitive',
        'enablePassiveMode': 'enable_passive_mode',
        'enforcementMode': 'enforcement_mode',
        'filetypes': 'file_types',
        'open-api-files': 'open_api_files',
        'server-technologies': 'server_technologies',
        'protocolIndependent': 'protocol_independent',
        'policy-builder': 'policy_builder',
        'ip-intelligence': 'ip_intel',
        'policy-builder-central-configuration': 'pb_central_config',
        'policy-builder-cookie': 'pb_cookie',
        'policy-builder-filetype': 'pb_filetype',
        'policy-builder-header': 'pb_header',
        'policy-builder-parameter': 'pb_param',
        'policy-builder-redirection-protection': 'pb_redirect_prot',
        'policy-builder-server-technologies': 'pb_server_tech',
        'policy-builder-sessions-and-logins': 'pb_sess_and_logins',
        'policy-builder-url': 'pb_url',
        'signature-sets': 'signature_sets',
        'signature-settings': 'signature_settings',
        'behavioral-enforcement': 'behavioral_enforce',
        'blocking-settings': 'blocking_settings',
        'brute-force-attack-preventions': 'brute_force_atck_prev',
        'character-sets': 'character_sets',
        'cookie-settings': 'cookie_settings',
        'csrf-protection': 'csrf_protection',
        'csrf-urls': 'csrf_urls',
        'data-guard': 'data_guard',
        'database-protection': 'database_protection',
        'deception-settings': 'deception_settings',
        'graphql-profiles': 'graphql_profiles',
        'gwt-profiles': 'gwt_profiles',
        'header-settings': 'header_settings',
        'json-profiles': 'json_profiles',
        'login-enforcement': 'login_enforcement',
        'plain-text-profiles': 'plain_text_profiles',
        'redirection-protection-domains': 'redir_prot_dom',
        'response-pages': 'resp_pages',
        'sensitive-parameters': 'sens_params',
        'session-tracking': 'sess_tracking',
        'threat-campaign-settings': 'threat_camp_sett',
        'websocket-urls': 'websock_urls',
        'xml-profiles': 'xml_profiles'
    }

    @property
    def template(self):
        return self._values['template'].get('name')

    @property
    def policy_builder(self):
        if self._values['policy_builder'] is None:
            return None
        return self._values['policy_builder'].get('learningMode')

    @property
    def file_types(self):
        if self._values['file_types'] is None:
            return None
        result = list()
        for filetype in self._values['file_types']:
            element = dict(name=filetype['name'], allowed=filetype['allowed'])
            if filetype['allowed']:
                element['type'] = filetype['type']
            result.append(element)
        return result


class JsonParameters(ApiParameters):
    pass


class ModuleParameters(Parameters):
    @staticmethod
    def _handle_server_tech(server):
        tech_list = ['ASP', 'ASP.NET', 'AngularJS', 'Apache Struts', 'Apache Tomcat', 'Apache/NCSA HTTP Server',
                     'BEA Systems WebLogic Server', 'Backbone.js', 'CGI', 'Cisco', 'Citrix', 'CodeIgniter', 'CouchDB',
                     'Django', 'Elasticsearch', 'Ember.js', 'Express.js', 'Front Page Server Extensions (FPSE)',
                     'Google Web Toolkit', 'GraphQL', 'Handlebars', 'IBM DB2', 'IIS', 'JBoss', 'Java Servlets/JSP',
                     'JavaScript', 'JavaServer Faces (JSF)', 'Jenkins', 'Jetty', 'Joomla', 'Laravel', 'Lotus Domino',
                     'Macromedia ColdFusion', 'Macromedia JRun', 'Microsoft SQL Server', 'Microsoft Windows', 'MongoDB',
                     'MooTools', 'Mustache', 'MySQL', 'Nginx', 'Node.js', 'Novell', 'Oracle',
                     'Oracle Application Server', 'Oracle Identity Manager', 'Outlook Web Access', 'PHP', 'PostgreSQL',
                     'Prototype', 'Proxy Servers', 'Python', 'React', 'Redis', 'RequireJS', 'Ruby', 'SQLite',
                     'SSI (Server Side Includes)', 'SharePoint', 'Spring Boot', 'Sybase/ASE', 'TYPO3 CMS', 'UIKit',
                     'Underscore.js', 'Unix/Linux', 'Vue.js', 'WebDAV', 'WordPress', 'XML', 'ZURB Foundation', 'Zend',
                     'ef.js', 'jQuery']
        if server not in tech_list:
            raise F5ModuleError(f'Invalid entry for server technology: {server}, should be one of {tech_list}')
        return server

    @staticmethod
    def _handle_booleans(value):
        result = flatten_boolean(value)
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def case_insensitive(self):
        return self._handle_booleans(self._values['case_insensitive'])

    @property
    def enable_passive_mode(self):
        return self._handle_booleans(self._values['enable_passive_mode'])

    @property
    def protocol_independent(self):
        return self._handle_booleans(self._values['protocol_independent'])

    @property
    def apply_policy(self):
        return self._handle_booleans(self._values['apply_policy'])

    @property
    def server_technologies(self):
        if self._values['server_technologies'] is None:
            return None
        result = [
            dict(serverTechnologyName=self._handle_server_tech(server))
            for server in self._values['server_technologies']
        ]
        return result

    @property
    def file_types(self):
        allowed = self._values['allowed_file_types']
        disallowed = self._values['disallowed_file_types']
        result = list()
        if allowed:
            for allow in allowed:
                result.append(dict(allowed=True, name=allow['name'], type=allow['type']))
        if disallowed:
            for disallow in disallowed:
                result.append(dict(allowed=False, name=disallow['name']))
        if result:
            return result

    @property
    def open_api_files(self):
        if not self._values['open_api_files']:
            return None
        result = [dict(link=file) for file in self._values['open_api_files']]
        return result

    @property
    def policy_builder(self):
        if self._values['pb_learning_mode'] is None:
            return None
        return self._values['pb_learning_mode']

    @property
    def policy_in_json(self):
        if self._values['policy_in_json'] is None:
            return None
        if isinstance(self._values['policy_in_json'], string_types):
            try:
                template = json.loads(self._values['policy_in_json'] or 'null')
            except json.JSONDecodeError:
                raise F5ModuleError(
                    "The provided 'policy_in_json' could not be converted into valid json. If you "
                    "are using the 'to_nice_json' filter, please remove it."
                )
        else:
            template = dict()
            try:
                template.update(self._values['policy_in_json'])
            except ValueError:
                raise F5ModuleError(
                    "The provided 'policy_in_json' could not be converted into valid json. If you "
                    "are using the 'to_nice_json' filter, please remove it."
                )
        if template:
            return template


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
    @property
    def policy_builder(self):
        if self._values['policy_builder'] is None:
            return None
        return dict(learningMode=self._values['policy_builder'])

    @property
    def template(self):
        if self._values['template'] is None:
            return None
        return dict(name=self._values['template'])


class ReportableChanges(Changes):
    returnables = [
        'description',
        'template',
        'language',
        'case_insensitive',
        'enable_passive_mode',
        'protocol_independent',
        'enforcement_mode',
        'type',
        'server_technologies',
        'pb_learning_mode',
        'allowed_file_types',
        'disallowed_file_types',
        'open_api_files'
    ]

    @property
    def allowed_file_types(self):
        if self._values['file_types'] is None:
            return None
        result = [dict(name=item['name'], type=item['type'])
                  for item in self._values['file_types'] if item['allowed'] is True]
        if result:
            return result

    @property
    def disallowed_file_types(self):
        if self._values['file_types'] is None:
            return None
        result = [dict(name=item['name'])
                  for item in self._values['file_types'] if item['allowed'] is False]
        if result:
            return result

    @property
    def template(self):
        if self._values['template'] is None:
            return None
        return self._values['template']['name']

    @property
    def server_technologies(self):
        if self._values['server_technologies'] is None:
            return None
        result = [item['serverTechnologyName'] for item in self._values['server_technologies']]
        if result:
            return result

    @property
    def pb_learning_mode(self):
        if self._values['policy_builder'] is None:
            return None
        return self._values['policy_builder']['learningMode']

    @property
    def open_api_files(self):
        if self._values['open_api_files'] is None:
            return None
        result = [file['link'] for file in self._values['open_api_files']]
        if result:
            return result


class Difference(object):
    def __init__(self, want, have=None, in_json=None):
        self.want = want
        self.have = have
        self.in_json = in_json

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = self.__in_json_attr(param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:  # pragma: no cover
            return attr1

    def __in_json_attr(self, param):
        attr1 = getattr(self.want, param)
        if attr1:
            return attr1
        try:
            attr2 = getattr(self.in_json, param)
            return attr2
        except AttributeError:
            return attr1

    def to_tuple(self, items):
        result = []
        for x in items:
            tmp = [(str(k), str(v)) for k, v in iteritems(x)]
            result += tmp
        return result

    def _diff_complex_items(self, want, have):
        if want == [] and have is None:
            return None
        if want is None:
            return None
        if have is None:
            return want
        w = self.to_tuple(want)
        h = self.to_tuple(have)
        if set(w).issubset(set(h)):
            return None
        else:
            return want

    @property
    def file_types(self):
        if self.want.file_types:
            return self._diff_complex_items(self.want.file_types, self.have.file_types)
        if self.in_json:
            return self._diff_complex_items(self.in_json.file_types, self.have.file_types)

    @property
    def server_technologies(self):
        if self.want.server_technologies is not None:
            return compare_complex_list(self.want.server_technologies, self.have.server_technologies)
        if self.in_json:
            return compare_complex_list(self.in_json.server_technologies, self.have.server_technologies)

    @property
    def open_api_files(self):
        if self.want.open_api_files is not None:
            return compare_complex_list(self.want.open_api_files, self.have.open_api_files)
        if self.in_json:
            return compare_complex_list(self.in_json.open_api_files, self.have.open_api_files)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

        # define a set of common instance variables used during module execution
        self.in_json = None
        self.policy_id = None
        self.json_dump = None
        self.json_string = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
            elif self.in_json:
                if getattr(self.in_json, key) is not None:
                    changed[key] = getattr(self.in_json, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have, self.in_json)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):  # pragma: no cover
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _set_policy_in_json(self):
        policy = self.want.policy_in_json
        if policy:
            return JsonParameters(params=policy['policy'])

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

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        if self.json_dump:
            result.update(dict(json=self.json_dump))
        else:
            result.update(dict(policy_id=self.policy_id))
            result.update(dict(json_string=self.json_string))
        self._announce_deprecations(result)
        send_teem(self.client, start)
        return result

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
        self.in_json = self._set_policy_in_json()
        self.have = self.read_current_from_device()
        if not self.should_update() and not self.want.force:
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        changed, output = self.update_on_device()
        if not changed and output:
            self.json_dump = output
            return False
        if self.want.apply_policy is True:
            self.apply_policy(update=True)
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        if self.want.policy_id:
            raise F5ModuleError("The 'name' and 'partition' parameters must be used when creating a new policy.")
        self.in_json = self._set_policy_in_json()
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        changed, output = self.create_on_device()
        if not changed and output:
            self.json_dump = output
            return False
        if self.want.apply_policy is True:
            self.apply_policy()
        return True

    def exists(self):
        if self.want.policy_id:
            return self._check_by_policy_id()
        else:
            return self._check_by_policy_name()

    def _check_by_policy_id(self):
        uri = f"/mgmt/tm/asm/policies/{self.want.policy_id}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['id'] == self.want.policy_id:
            self.policy_id = self.want.policy_id

        return True

    def _check_by_policy_name(self):
        uri = "/mgmt/tm/asm/policies/"
        query = "?$filter=contains(name,'{0}')+and+contains(partition,'{1}')&$select=name,partition,id".format(
            self.want.name, self.want.partition
        )
        response = self.client.get(uri + query)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents'] and response['contents']['items'] != []:
            # because api filter on ASM is broken when names contain numbers at the end we need to work around it
            for policy in response['contents']['items']:
                if policy['name'] == self.want.name and policy['partition'] == self.want.partition:
                    self.policy_id = policy['id']
                    return True
        return False

    def create_on_device(self):
        content, json_string = self.generate_policy_json()
        if self.want.dump_json:
            return False, content
        task = self.import_policy(content)
        result = self.wait_for_task(task)
        self.policy_id = Path(urlparse(result['policyReference']['link']).path).name
        self.json_string = json_string
        return True, None

    def update_on_device(self):
        content, json_string = self.generate_policy_json(update=True)
        if self.want.dump_json:
            return False, content
        task = self.import_policy(content, update=True)
        result = self.wait_for_task(task)
        self.policy_id = Path(urlparse(result['policyReference']['link']).path).name
        self.json_string = json_string
        return True, None

    def import_policy(self, content, update=False):
        params = dict(
            format='json',
            file=content,
            policy=dict(fullPath=fq_name(self.want.partition, self.want.name) if not update else self.have.full_path)
        )
        if update:
            params.update(dict(policyReference={'link': f"https://localhost/mgmt/tm/asm/policies/{self.policy_id}"}))

        uri = "/mgmt/tm/asm/tasks/import-policy/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']['id']

    def apply_policy(self, update=False):
        params = dict(policy=dict(
            fullPath=fq_name(self.want.partition, self.want.name) if not update else self.have.full_path)
        )
        if update:
            params.update(dict(policyReference={'link': f"https://localhost/mgmt/tm/asm/policies/{self.policy_id}"}))

        uri = "/mgmt/tm/asm/tasks/apply-policy/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return self.wait_for_task(response['contents']['id'], apply=True)

    def generate_policy_json(self, update=False):
        params = self.changes.to_return()
        params['name'] = self.want.name if not update else self.have.name
        params['fullPath'] = fq_name(self.want.partition, self.want.name) if not update else self.have.full_path
        if update:
            if self.want.force:
                data = self.add_extra_params_from_in_json(self.add_params_on_update(params))
            else:
                data = self.add_extra_params_from_device(self.add_params_on_update(params))
        else:
            self.check_for_required_create_params()
            if self.in_json:
                data = self.add_extra_params_from_in_json(self.add_create_defaults(params))
            else:
                data = self.add_create_defaults(params)

        output = process_json(data, create_modify, raw=True)
        json_string = json.dumps(output)
        return output, json_string

    def add_create_defaults(self, params):
        if self.changes.language is None:
            params['language'] = 'auto-detect'
        if self.changes.case_insensitive is None:
            params['case_insensitive'] = False
        if self.changes.enable_passive_mode is None:
            params['enable_passive_mode'] = False
        if self.changes.protocol_independent is None:
            params['protocol_independent'] = False
        if self.changes.enforcement_mode is None:
            params['enforcement_mode'] = 'transparent'
        if self.changes.type is None:
            params['type'] = 'security'
        if self.changes.policy_builder is None:
            params['policy_builder'] = dict(learningMode='manual')
        return params

    def check_for_required_create_params(self):
        if self.changes.server_technologies is None:
            raise F5ModuleError("The 'server_technologies' parameter must be provided when creating new policy.")
        if self.changes.template is None:
            raise F5ModuleError("The 'template' parameter must be provided when creating new policy.")

    def add_params_on_update(self, params):
        if self.changes.server_technologies is None:
            params['server_technologies'] = self.have.server_technologies
        if self.changes.template is None:
            params['template'] = dict(name=self.have.template)
        if self.changes.language is None:
            params['language'] = self.have.language
        if self.changes.case_insensitive is None:
            params['case_insensitive'] = self.have.case_insensitive
        if self.changes.enable_passive_mode is None:
            params['enable_passive_mode'] = self.have.enable_passive_mode
        if self.changes.protocol_independent is None:
            params['protocol_independent'] = self.have.protocol_independent
        if self.changes.enforcement_mode is None:
            params['enforcement_mode'] = self.have.enforcement_mode
        if self.changes.type is None:
            params['type'] = self.have.type
        if self.changes.description is None and self.have.description:
            params['description'] = self.have.description
        if self.changes.policy_builder is None and self.have.policy_builder:
            params['policy_builder'] = dict(learningMode=self.have.policy_builder)
        if self.changes.file_types is None and self.have.file_types:
            params['file_types'] = self.have.file_types
        if self.changes.open_api_files is None and self.have.open_api_files:
            params['open_api_files'] = self.have.open_api_files
        return params

    def add_extra_params_from_device(self, params):
        if self.have.urls:
            params['urls'] = self.have.urls
        if self.have.cookies:
            params['cookies'] = self.have.cookies
        if self.have.general:
            params['general'] = self.have.general
        if self.have.headers:
            params['headers'] = self.have.headers
        if self.have.methods:
            params['methods'] = self.have.methods
        if self.have.ip_intel:
            params['ip_intel'] = self.have.ip_intel
        if self.have.parameters:
            params['parameters'] = self.have.parameters
        if self.have.pb_central_config:
            params['pb_central_config'] = self.have.pb_central_config
        if self.have.pb_cookie:
            params['pb_cookie'] = self.have.pb_cookie
        if self.have.pb_filetype:
            params['pb_filetype'] = self.have.pb_filetype
        if self.have.pb_header:
            params['pb_header'] = self.have.pb_header
        if self.have.pb_param:
            params['pb_param'] = self.have.pb_param
        if self.have.pb_redirect_prot:
            params['pb_redirect_prot'] = self.have.pb_redirect_prot
        if self.have.pb_server_tech:
            params['pb_server_tech'] = self.have.pb_server_tech
        if self.have.pb_sess_and_logins:
            params['pb_sess_and_logins'] = self.have.pb_sess_and_logins
        if self.have.pb_url:
            params['pb_url'] = self.have.pb_url
        if self.have.signature_sets:
            params['signature_sets'] = self.have.signature_sets
        if self.have.signature_settings:
            params['signature_settings'] = self.have.signature_settings
        if self.have.behavioral_enforce:
            params['behavioral_enforce'] = self.have.behavioral_enforce
        if self.have.blocking_settings:
            params['blocking_settings'] = self.have.blocking_settings
        if self.have.brute_force_atck_prev:
            params['brute_force_atck_prev'] = self.have.brute_force_atck_prev
        if self.have.character_sets:
            params['character_sets'] = self.have.character_sets
        if self.have.signature_settings:
            params['cookie_settings'] = self.have.cookie_settings
        if self.have.csrf_protection:
            params['csrf_protection'] = self.have.csrf_protection
        if self.have.csrf_urls:
            params['csrf_urls'] = self.have.csrf_urls
        if self.have.data_guard:
            params['data_guard'] = self.have.data_guard
        if self.have.database_protection:
            params['database_protection'] = self.have.database_protection
        if self.have.deception_settings:
            params['deception_settings'] = self.have.deception_settings
        if self.have.graphql_profiles:
            params['graphql_profiles'] = self.have.graphql_profiles
        if self.have.gwt_profiles:
            params['gwt_profiles'] = self.have.gwt_profiles
        if self.have.header_settings:
            params['header_settings'] = self.have.header_settings
        if self.have.json_profiles:
            params['json_profiles'] = self.have.json_profiles
        if self.have.login_enforcement:
            params['login_enforcement'] = self.have.login_enforcement
        if self.have.plain_text_profiles:
            params['plain_text_profiles'] = self.have.plain_text_profiles
        if self.have.login_enforcement:
            params['login_enforcement'] = self.have.login_enforcement
        if self.have.redir_prot_dom:
            params['redir_prot_dom'] = self.have.redir_prot_dom
        if self.have.resp_pages:
            params['resp_pages'] = self.have.resp_pages
        if self.have.sens_params:
            params['sens_params'] = self.have.sens_params
        if self.have.sess_tracking:
            params['sess_tracking'] = self.have.sess_tracking
        if self.have.threat_camp_sett:
            params['threat_camp_sett'] = self.have.threat_camp_sett
        if self.have.websock_urls:
            params['websock_urls'] = self.have.websock_urls
        if self.have.xml_profiles:
            params['xml_profiles'] = self.have.xml_profiles
        return params

    def add_extra_params_from_in_json(self, params):
        if self.in_json.urls:
            params['urls'] = self.in_json.urls
        if self.in_json.cookies:
            params['cookies'] = self.in_json.cookies
        if self.in_json.general:
            params['general'] = self.in_json.general
        if self.in_json.headers:
            params['headers'] = self.in_json.headers
        if self.in_json.methods:
            params['methods'] = self.in_json.methods
        if self.in_json.ip_intel:
            params['ip_intel'] = self.in_json.ip_intel
        if self.in_json.parameters:
            params['parameters'] = self.in_json.parameters
        if self.in_json.pb_central_config:
            params['pb_central_config'] = self.in_json.pb_central_config
        if self.in_json.pb_cookie:
            params['pb_cookie'] = self.in_json.pb_cookie
        if self.in_json.pb_filetype:
            params['pb_filetype'] = self.in_json.pb_filetype
        if self.in_json.pb_header:
            params['pb_header'] = self.in_json.pb_header
        if self.in_json.pb_param:
            params['pb_param'] = self.in_json.pb_param
        if self.in_json.pb_redirect_prot:
            params['pb_redirect_prot'] = self.in_json.pb_redirect_prot
        if self.in_json.pb_server_tech:
            params['pb_server_tech'] = self.in_json.pb_server_tech
        if self.in_json.pb_sess_and_logins:
            params['pb_sess_and_logins'] = self.in_json.pb_sess_and_logins
        if self.in_json.pb_url:
            params['pb_url'] = self.in_json.pb_url
        if self.in_json.signature_sets:
            params['signature_sets'] = self.in_json.signature_sets
        if self.in_json.signature_settings:
            params['signature_settings'] = self.in_json.signature_settings
        if self.in_json.behavioral_enforce:
            params['behavioral_enforce'] = self.in_json.behavioral_enforce
        if self.in_json.blocking_settings:
            params['blocking_settings'] = self.in_json.blocking_settings
        if self.in_json.brute_force_atck_prev:
            params['brute_force_atck_prev'] = self.in_json.brute_force_atck_prev
        if self.in_json.character_sets:
            params['character_sets'] = self.in_json.character_sets
        if self.in_json.signature_settings:
            params['cookie_settings'] = self.in_json.cookie_settings
        if self.in_json.csrf_protection:
            params['csrf_protection'] = self.in_json.csrf_protection
        if self.in_json.csrf_urls:
            params['csrf_urls'] = self.in_json.csrf_urls
        if self.in_json.data_guard:
            params['data_guard'] = self.in_json.data_guard
        if self.in_json.database_protection:
            params['database_protection'] = self.in_json.database_protection
        if self.in_json.deception_settings:
            params['deception_settings'] = self.in_json.deception_settings
        if self.in_json.graphql_profiles:
            params['graphql_profiles'] = self.in_json.graphql_profiles
        if self.in_json.gwt_profiles:
            params['gwt_profiles'] = self.in_json.gwt_profiles
        if self.in_json.header_settings:
            params['header_settings'] = self.in_json.header_settings
        if self.in_json.json_profiles:
            params['json_profiles'] = self.in_json.json_profiles
        if self.in_json.login_enforcement:
            params['login_enforcement'] = self.in_json.login_enforcement
        if self.in_json.plain_text_profiles:
            params['plain_text_profiles'] = self.in_json.plain_text_profiles
        if self.in_json.login_enforcement:
            params['login_enforcement'] = self.in_json.login_enforcement
        if self.in_json.redir_prot_dom:
            params['redir_prot_dom'] = self.in_json.redir_prot_dom
        if self.in_json.resp_pages:
            params['resp_pages'] = self.in_json.resp_pages
        if self.in_json.sens_params:
            params['sens_params'] = self.in_json.sens_params
        if self.in_json.sess_tracking:
            params['sess_tracking'] = self.in_json.sess_tracking
        if self.in_json.threat_camp_sett:
            params['threat_camp_sett'] = self.in_json.threat_camp_sett
        if self.in_json.websock_urls:
            params['websock_urls'] = self.in_json.websock_urls
        if self.in_json.xml_profiles:
            params['xml_profiles'] = self.in_json.xml_profiles
        return params

    def wait_for_task(self, task_id, export=False, apply=False):
        if export:
            uri = f"/mgmt/tm/asm/tasks/export-policy/{task_id}"
        elif apply:
            uri = f"/mgmt/tm/asm/tasks/apply-policy/{task_id}"
        else:
            uri = f"/mgmt/tm/asm/tasks/import-policy/{task_id}"
        while True:
            response = self.client.get(uri)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            if response['contents']['status'] in ['COMPLETED', 'FAILURE']:
                break
            time.sleep(1)

        if response['contents']['status'] == 'FAILURE':
            if export:
                raise F5ModuleError(
                    f"Failed to export aWAF policy with the following message: "
                    f"{response['contents']['result']['message']}"
                )
            elif apply:
                raise F5ModuleError(
                    f"Failed to apply aWAF policy with the following message: "
                    f"{response['contents']['result']['message']}"
                )
            else:
                raise F5ModuleError(
                    f"Failed to import aWAF policy with the following message: "
                    f"{response['contents']['result']['message']}"
                )
        if response['contents']['status'] == 'COMPLETED':
            if apply:
                return True
            else:
                return response['contents']['result']

    def remove_from_device(self):
        uri = f"/mgmt/tm/asm/policies/{self.policy_id}"
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        params = dict(
            filename=os.path.basename(tempfile.NamedTemporaryFile().name),
            format='json',
            inline=True,
            policyReference=dict(link=f"https://localhost/mgmt/tm/asm/policies/{self.policy_id}")
        )
        uri = "/mgmt/tm/asm/tasks/export-policy/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        output = self.wait_for_task(response['contents']['id'], export=True)

        if output.get('file'):
            result = json.loads(output.get('file'))
            return ApiParameters(params=result['policy'])

        raise F5ModuleError('Failed to read exported aWAF policy.')


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(),
            policy_id=dict(),
            apply_policy=dict(
                type='bool',
                default='no'
            ),
            description=dict(),
            template=dict(),
            language=dict(
                choices=[
                    'auto-detect', 'big5', 'euc-jp', 'euc-kr', 'gb18030', 'gb2312', 'gbk', 'iso-8859-1', 'iso-8859-10',
                    'iso-8859-13', 'iso-8859-15', 'iso-8859-16', 'iso-8859-2', 'iso-8859-3', 'iso-8859-4', 'iso-8859-5',
                    'iso-8859-6', 'iso-8859-7', 'iso-8859-8', 'iso-8859-9', 'koi8-r', 'shift_jis', 'utf-8',
                    'windows-1250', 'windows-1251', 'windows-1252', 'windows-1253', 'windows-1255', 'windows-1256',
                    'windows-1257', 'windows-874'
                ]
            ),
            case_insensitive=dict(type='bool'),
            enable_passive_mode=dict(type='bool'),
            protocol_independent=dict(type='bool'),
            enforcement_mode=dict(
                choices=['blocking', 'transparent']
            ),
            type=dict(
                choices=['parent', 'security']
            ),
            server_technologies=dict(
                type='list',
                elements='str'
            ),
            pb_learning_mode=dict(
                choices=['automatic', 'disabled', 'manual']
            ),
            allowed_file_types=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    type=dict(
                        required=True,
                        choices=['explicit', 'wildcard']
                    )
                )
            ),
            disallowed_file_types=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True)
                )
            ),
            open_api_files=dict(
                type='list',
                elements='str'
            ),
            policy_in_json=dict(type='raw'),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            dump_json=dict(
                type='bool',
                default='no'
            ),
            force=dict(
                type='bool',
                default='no'
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [['force', 'yes', ['policy_in_json']]]
        self.required_one_of = [['name', 'policy_id']]
        self.mutually_exclusive = [
            ['apply_policy', 'dump_json'],
            ['name', 'policy_id']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
        mutually_exclusive=spec.mutually_exclusive,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
