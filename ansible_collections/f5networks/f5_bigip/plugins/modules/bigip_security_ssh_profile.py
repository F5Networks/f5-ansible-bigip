#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_security_ssh_profile
short_description: Manage SSH proxy security profiles on a BIG-IP
description:
  - Manage SSH proxy security profiles on a BIG-IP.
version_added: 1.13.0
options:
  name:
    description:
      - Specifies the name of the SSH proxy security profile to manage.
    type: str
    required: true
  default_action:
    description:
      - Specifies the default action rule for SSH proxy security profile.
      - When creating a new policy, this parameter must be specified otherwise
        failure will occur.
    type: dict
    suboptions:
      name:
        description:
          - Name of the C(default_action) rule to be created or modified.
        type: str
        required: true
      shell:
        description:
          - Defines use of the C(shell) command to open an SSH shell channel
            type.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      sub_system:
        description:
          - Defines the use of the C(subsystem) command, to invoke remote
            commands that are defined on the server over the SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      sftp_up:
        description:
          - Defines the use of Secure File Transfer Protocol to upload files
            over the SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      sftp_down:
        description:
          - Defines the use of Secure File Transfer Protocol to download files
            over the SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      scp_up:
        description:
          - Defines the use of Secure Copy to copy files from a local directory
            to a remote directory over the SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      scp_down:
        description:
          - Defines the use of Secure Copy to copy files from a remote directory
            to a local directory over the SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      rexec:
        description:
          - Defines the use of C(rexec) remote execution commands over the SSH
            tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      forward_local:
        description:
          - Defines the use of the C(-L) to do local port forwarding over the
            SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      forward_remote:
        description:
          - Defines the use of the C(-R) to do remote port forwarding over the
            SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      forward_x11:
        description:
          - Defines the use of X11 forwarding over the SSH tunnel.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      agent:
        description:
          - Defines the use of ssh-agent over the SSH tunnel.
          - Agent forwarding specifies that the chain of SSH connections
            forwards key challenges back to the original agent, removing the
            need for passwords or private keys on intermediate machines.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
      other:
        description:
          - Defines the use of other SSH commands on SSH connection.
        type: dict
        suboptions:
          control:
            description:
              - When set to C(allow) allows setup of the session for the
                selected SSH channel action.
              - When set to C(disallow), SSH channel action is denied and a
                I(command not accepted) message is sent.
              - When set to C(terminate) SSH connection is terminated with reset
                message when selected channel action is received.
            type: str
            choices:
              - allow
              - disallow
              - terminate
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
  description:
    description:
      - Specifies descriptive text that identifies the SSH proxy profile.
    type: str
  lang_env_tolerance:
    description:
      - Determines which connections with LANG environment variables set are
        allowed to pass through if the SSH Proxy profile has the C(other)
        channel type action set.
      - When set to C(any) allows connections with any LANG environment value
        set.
      - When set to C(none) disallows all connections with the LANG environment
        variable set.
      - When set to C(common) allows only connections with the LANG environment
        value set to C(en_US.UTF-8) to pass through the C(other) restrictions.
      - This setting is in effect only if C(other) action is set to C(disallow)
        or C(terminate).
    type: str
    choices:
      - any
      - none
      - common
  timeout:
    description:
      - Specifies a timeout for the SSH proxy, in seconds.
    type: int
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the SSH proxy security profile is created.
      - When C(absent), ensures the SSH proxy security profile is removed.
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
    - name: Create an ssh proxy profile
      bigip_security_ssh_profile:
        name: test_profile
        default_action:
          name: default_rule
          shell:
            control: disallow
            log: True
          sub_system:
            control: disallow
            log: True
          agent:
            control: terminate
            log: True
          other:
            control: terminate
            log: True
        lang_env_tolerance: common
        description: "this is a new profile"
        timeout: 180
        state: present

    - name: Modify an ssh proxy profile
      bigip_security_ssh_profile:
        name: test_profile
        default_action:
          name: default_rule
          shell:
            control: allow
            log: False
        timeout: 200
        state: present

    - name: Remove ssh proxy profile
      bigip_security_ssh_profile:
        name: test_profile
        state: absent
'''

RETURN = r'''
default_action:
  description: The default action rule for SSH proxy security profile.
  returned: changed
  type: dict
  sample: hash/dictionary of values
lang_env_tolerance:
  description: Determines which connections with LANG environment variables set are allowed to pass through.
  returned: changed
  type: str
  sample: any
description:
  description: Descriptive text that identifies the SSH proxy profile.
  returned: changed
  type: str
  sample: 'this is a profile'
timeout:
  description: The timeout for the SSH proxy.
  returned: changed
  type: int
  sample: 200
'''

from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean, transform_name
)
from ..module_utils.compare import compare_key_values


class Parameters(AnsibleF5Parameters):
    api_map = {
        'langEnvTolerance': 'lang_env_tolerance',
        'actions': 'default_action',
    }

    api_attributes = [
        'timeout',
        'actions',
        'langEnvTolerance',
        'description'
    ]

    returnables = [
        'lang_env_tolerance',
        'timeout',
        'description',
        'default_action_name',
        'default_action_shell',
        'default_action_sub_system',
        'default_action_sftp_up',
        'default_action_sftp_down',
        'default_action_scp_up',
        'default_action_scp_down',
        'default_action_rexec',
        'default_action_forward_local',
        'default_action_forward_remote',
        'default_action_forward_x11',
        'default_action_agent',
        'default_action_other'
    ]

    updatables = [
        'lang_env_tolerance',
        'timeout',
        'description',
        'default_action_name',
        'default_action_shell',
        'default_action_sub_system',
        'default_action_sftp_up',
        'default_action_sftp_down',
        'default_action_scp_up',
        'default_action_scp_down',
        'default_action_rexec',
        'default_action_forward_local',
        'default_action_forward_remote',
        'default_action_forward_x11',
        'default_action_agent',
        'default_action_other'
    ]


class ApiParameters(Parameters):
    @property
    def default_action_name(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('name')

    @property
    def default_action_shell(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('shellAction')

    @property
    def default_action_sub_system(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('subSystemAction')

    @property
    def default_action_sftp_up(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('sftpUpAction')

    @property
    def default_action_sftp_down(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('sftpDownAction')

    @property
    def default_action_scp_up(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('scpUpAction')

    @property
    def default_action_scp_down(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('scpDownAction')

    @property
    def default_action_rexec(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('rexecAction')

    @property
    def default_action_forward_local(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('localForwardAction')

    @property
    def default_action_forward_remote(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('remoteForwardAction')

    @property
    def default_action_forward_x11(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('x11ForwardAction')

    @property
    def default_action_agent(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('agentAction')

    @property
    def default_action_other(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'][0].get('otherAction')


class ModuleParameters(Parameters):
    def _handle_action(self, action):
        if action:
            tmp = dict()
            tmp['control'] = action.get('control')
            tmp['log'] = flatten_boolean(action.get('log'))
            result = self._filter_params(tmp)
            if result:
                return result

    @property
    def default_action_name(self):
        if self._values['default_action'] is None:
            return None
        return self._values['default_action'].get('name')

    @property
    def default_action_shell(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('shell'))

    @property
    def default_action_sub_system(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('sub_system'))

    @property
    def default_action_sftp_up(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('sftp_up'))

    @property
    def default_action_sftp_down(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('sftp_down'))

    @property
    def default_action_scp_up(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('scp_up'))

    @property
    def default_action_scp_down(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('scp_down'))

    @property
    def default_action_rexec(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('rexec'))

    @property
    def default_action_forward_local(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('forward_local'))

    @property
    def default_action_forward_remote(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('forward_remote'))

    @property
    def default_action_forward_x11(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('forward_x11'))

    @property
    def default_action_agent(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('agent'))

    @property
    def default_action_other(self):
        if self._values['default_action'] is None:
            return None
        return self._handle_action(self._values['default_action'].get('other'))


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
    def default_action(self):
        result = list()
        tmp = dict()
        tmp['name'] = self._values['default_action_name']
        tmp['shellAction'] = self._values['default_action_shell']
        tmp['subSystemAction'] = self._values['default_action_sub_system']
        tmp['sftpUpAction'] = self._values['default_action_sftp_up']
        tmp['sftpDownAction'] = self._values['default_action_sftp_down']
        tmp['scpUpAction'] = self._values['default_action_scp_up']
        tmp['scpDownAction'] = self._values['default_action_scp_down']
        tmp['rexecAction'] = self._values['default_action_rexec']
        tmp['localForwardAction'] = self._values['default_action_forward_local']
        tmp['remoteForwardAction'] = self._values['default_action_forward_remote']
        tmp['x11ForwardAction'] = self._values['default_action_forward_x11']
        tmp['agentAction'] = self._values['default_action_agent']
        tmp['otherAction'] = self._values['default_action_other']
        element = self._filter_params(tmp)
        if element:
            result.append(element)
            return result


class ReportableChanges(Changes):
    returnables = [
        'lang_env_tolerance',
        'timeout',
        'description',
        'default_action'
    ]

    @property
    def default_action(self):
        tmp = dict()
        tmp['name'] = self._values['default_action_name']
        tmp['shell'] = self._values['default_action_shell']
        tmp['sub_system'] = self._values['default_action_sub_system']
        tmp['sftp_up'] = self._values['default_action_sftp_up']
        tmp['sftp_down'] = self._values['default_action_sftp_down']
        tmp['scp_up'] = self._values['default_action_scp_up']
        tmp['scp_down'] = self._values['default_action_scp_down']
        tmp['rexec'] = self._values['default_action_rexec']
        tmp['forward_local'] = self._values['default_action_forward_local']
        tmp['forward_remote'] = self._values['default_action_forward_remote']
        tmp['forward_x11'] = self._values['default_action_forward_x11']
        tmp['agent'] = self._values['default_action_agent']
        tmp['other'] = self._values['default_action_other']
        return self._filter_params(tmp)


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
        except AttributeError:  # pragma: no cover
            return attr1

    @property
    def default_action_shell(self):
        return compare_key_values(self.want.default_action_shell, self.have.default_action_shell)

    @property
    def default_action_sub_system(self):
        return compare_key_values(self.want.default_action_sub_system, self.have.default_action_sub_system)

    @property
    def default_action_sftp_up(self):
        return compare_key_values(self.want.default_action_sftp_up, self.have.default_action_sftp_up)

    @property
    def default_action_sftp_down(self):
        return compare_key_values(self.want.default_action_sftp_down, self.have.default_action_sftp_down)

    @property
    def default_action_scp_up(self):
        return compare_key_values(self.want.default_action_scp_up, self.have.default_action_scp_up)

    @property
    def default_action_scp_down(self):
        return compare_key_values(self.want.default_action_scp_down, self.have.default_action_scp_down)

    @property
    def default_action_rexec(self):
        return compare_key_values(self.want.default_action_rexec, self.have.default_action_rexec)

    @property
    def default_action_forward_local(self):
        return compare_key_values(self.want.default_action_forward_local, self.have.default_action_forward_local)

    @property
    def default_action_forward_remote(self):
        return compare_key_values(self.want.default_action_forward_remote, self.have.default_action_forward_remote)

    @property
    def default_action_forward_x11(self):
        return compare_key_values(self.want.default_action_forward_x11, self.have.default_action_forward_x11)

    @property
    def default_action_agent(self):
        return compare_key_values(self.want.default_action_agent, self.have.default_action_agent)

    @property
    def default_action_other(self):
        return compare_key_values(self.want.default_action_other, self.have.default_action_other)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()

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
                changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

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
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "/mgmt/tm/security/ssh/profile/"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(self.want.partition, self.want.name)}"

        # name parameter is required when updating actions, in case there was no change in name
        # it won't be passed to UsableChanges class therefore we must add existing action name parameter
        # or api call will fail
        if 'actions' in params:
            if not params['actions'][0].get('name'):
                params['actions'][0]['name'] = self.want.default_action_name

        response = self.client.patch(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(self.want.partition, self.want.name)}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            default_action=dict(
                type='dict',
                options=dict(
                    name=dict(required=True),
                    shell=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    sub_system=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    sftp_up=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    sftp_down=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    scp_up=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    scp_down=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    rexec=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    forward_local=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    forward_remote=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    forward_x11=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    agent=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    ),
                    other=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    )
                )
            ),
            lang_env_tolerance=dict(
                choices=['any', 'none', 'common']
            ),
            description=dict(),
            timeout=dict(
                type='int'
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
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


if __name__ == '__main__':  # pragma: no cover
    main()
