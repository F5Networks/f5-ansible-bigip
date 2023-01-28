#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_security_profile_ssh_rules
short_description: Manage SSH proxy security profile rules on a BIG-IP
description:
  - Manage SSH proxy security profile rules on a BIG-IP.
version_added: 1.13.0
options:
  name:
    description:
      - Specifies the name of the rule that will be applied to ssh security profile.
    type: str
    required: True
  profile_name:
    description:
      - Specifies the name of the SSH security profile to which this rule applies to.
    type: str
    required: True
  users:
    description:
      - Specifies the list of users to be added to SSH proxy permissions list.
    type: list
    elements: str
  action:
    description:
      - Species the action of the rule which is to be applied to the SSH security profile
    type: dict
    suboptions:
      name:
        description:
          - Name of the C(action) to be created or modified.
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
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
              - When set to C(unspecified), no action is taken.
            type: str
            choices:
              - allow
              - disallow
              - terminate
              - unspecified
          log:
            description:
              - Specifies if logging should be enabled for the selected SSH
                action.
            type: bool
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
  - Rohit Upadhyay (@urohit011)
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
    - name: Create ssh profile rule
      bigip_security_profile_ssh_rules:
        name: test_rule_1
        users:
          - test_user_1
          - test_user_2
        profile_name: test_ssh
        action:
          name: test_action
          shell:
            control: allow
            log: yes
          forward_x11:
            control: terminate
            log: yes

    - name: Modify ssh profile rule, add action
      bigip_security_profile_ssh_rules:
        name: test_rule_1
        users:
          - test_user_1
          - test_user_2
        profile_name: test_ssh
        action:
          name: test_action
          shell:
            control: allow
            log: yes
          forward_x11:
            control: terminate
            log: yes
          other:
            control: terminate
            log: yes

    - name: Delete ssh profile rule
      bigip_security_profile_ssh_rules:
        name: test_rule_1
        profile_name: test_ssh
        state: absent
'''

RETURN = r'''
action:
  description: The action rule that is applied to the SSH security profile.
  returned: changed
  type: dict
  sample: hash/dictionary of values
users:
  description: The list of users to be added to SSH proxy permissions list.
  returned: changed
  type: list
  sample: ['...', '...']
'''

from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, flatten_boolean
)
from ..module_utils.compare import compare_key_values


class Parameters(AnsibleF5Parameters):
    api_map = {
        'identityUsers': 'users',
        'actions': 'action'
    }

    api_attributes = [
        'identityUsers',
        'actions',
    ]

    returnables = [
        'name',
        'profile_name',
        'users',
        'action_name',
        'action_shell',
        'action_sub_system',
        'action_sftp_up',
        'action_sftp_down',
        'action_scp_up',
        'action_scp_down',
        'action_rexec',
        'action_forward_local',
        'action_forward_remote',
        'action_forward_x11',
        'action_agent',
        'action_other'
    ]

    updatables = [
        'users',
        'action_name',
        'action_shell',
        'action_sub_system',
        'action_sftp_up',
        'action_sftp_down',
        'action_scp_up',
        'action_scp_down',
        'action_rexec',
        'action_forward_local',
        'action_forward_remote',
        'action_forward_x11',
        'action_agent',
        'action_other'
    ]


class ApiParameters(Parameters):
    @property
    def action_name(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('name')

    @property
    def action_shell(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('shellAction')

    @property
    def action_sub_system(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('subSystemAction')

    @property
    def action_sftp_up(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('sftpUpAction')

    @property
    def action_sftp_down(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('sftpDownAction')

    @property
    def action_scp_up(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('scpUpAction')

    @property
    def action_scp_down(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('scpDownAction')

    @property
    def action_rexec(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('rexecAction')

    @property
    def action_forward_local(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('localForwardAction')

    @property
    def action_forward_remote(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('remoteForwardAction')

    @property
    def action_forward_x11(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('x11ForwardAction')

    @property
    def action_agent(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('agentAction')

    @property
    def action_other(self):
        if self._values['action'] is None:
            return None
        return self._values['action'][0].get('otherAction')


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
    def action_name(self):
        if self._values['action'] is None:
            return None
        name = self._values['action'].get('name')
        if name:
            return name
        else:
            raise F5ModuleError('action name cannot be None')

    @property
    def action_shell(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('shell'))

    @property
    def action_sub_system(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('sub_system'))

    @property
    def action_sftp_up(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('sftp_up'))

    @property
    def action_sftp_down(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('sftp_down'))

    @property
    def action_scp_up(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('scp_up'))

    @property
    def action_scp_down(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('scp_down'))

    @property
    def action_rexec(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('rexec'))

    @property
    def action_forward_local(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('forward_local'))

    @property
    def action_forward_remote(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('forward_remote'))

    @property
    def action_forward_x11(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('forward_x11'))

    @property
    def action_agent(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('agent'))

    @property
    def action_other(self):
        if self._values['action'] is None:
            return None
        return self._handle_action(self._values['action'].get('other'))


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
    def action(self):
        result = list()
        tmp = dict()
        tmp['name'] = self._values['action_name']
        tmp['shellAction'] = self._values['action_shell']
        tmp['subSystemAction'] = self._values['action_sub_system']
        tmp['sftpUpAction'] = self._values['action_sftp_up']
        tmp['sftpDownAction'] = self._values['action_sftp_down']
        tmp['scpUpAction'] = self._values['action_scp_up']
        tmp['scpDownAction'] = self._values['action_scp_down']
        tmp['rexecAction'] = self._values['action_rexec']
        tmp['localForwardAction'] = self._values['action_forward_local']
        tmp['remoteForwardAction'] = self._values['action_forward_remote']
        tmp['x11ForwardAction'] = self._values['action_forward_x11']
        tmp['agentAction'] = self._values['action_agent']
        tmp['otherAction'] = self._values['action_other']
        element = self._filter_params(tmp)
        if element:
            result.append(element)
            return result


class ReportableChanges(Changes):
    returnables = [
        'timeout',
        'users',
        'action'
    ]

    @property
    def action(self):
        tmp = dict()
        tmp['name'] = self._values['action_name']
        tmp['shell'] = self._values['action_shell']
        tmp['sub_system'] = self._values['action_sub_system']
        tmp['sftp_up'] = self._values['action_sftp_up']
        tmp['sftp_down'] = self._values['action_sftp_down']
        tmp['scp_up'] = self._values['action_scp_up']
        tmp['scp_down'] = self._values['action_scp_down']
        tmp['rexec'] = self._values['action_rexec']
        tmp['forward_local'] = self._values['action_forward_local']
        tmp['forward_remote'] = self._values['action_forward_remote']
        tmp['forward_x11'] = self._values['action_forward_x11']
        tmp['agent'] = self._values['action_agent']
        tmp['other'] = self._values['action_other']
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
                return attr1  # pragma: no cover
        except AttributeError:  # pragma: no cover
            return attr1

    @property
    def users(self):
        have = set(self.have.users) if bool(self.have.users) else None
        want = set(self.want.users) if bool(self.want.users) else None
        return self.want.users if want != have else None

    @property
    def action_name(self):
        return compare_key_values(self.want.action_name, self.have.action_name)

    @property
    def action_shell(self):
        return compare_key_values(self.want.action_shell, self.have.action_shell)

    @property
    def action_sub_system(self):
        return compare_key_values(self.want.action_sub_system, self.have.action_sub_system)

    @property
    def action_sftp_up(self):
        return compare_key_values(self.want.action_sftp_up, self.have.action_sftp_up)

    @property
    def action_sftp_down(self):
        return compare_key_values(self.want.action_sftp_down, self.have.action_sftp_down)

    @property
    def action_scp_up(self):
        return compare_key_values(self.want.action_scp_up, self.have.action_scp_up)

    @property
    def action_scp_down(self):
        return compare_key_values(self.want.action_scp_down, self.have.ction_scp_down)

    @property
    def action_rexec(self):
        return compare_key_values(self.want.action_rexec, self.have.action_rexec)

    @property
    def action_forward_local(self):
        return compare_key_values(self.want.action_forward_local, self.have.action_forward_local)

    @property
    def action_forward_remote(self):
        return compare_key_values(self.want.action_forward_remote, self.have.action_forward_remote)

    @property
    def action_forward_x11(self):
        return compare_key_values(self.want.action_forward_x11, self.have.action_forward_x11)

    @property
    def action_agent(self):
        return compare_key_values(self.want.action_agent, self.have.action_agent)

    @property
    def action_other(self):
        return compare_key_values(self.want.action_other, self.have.action_other)


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
        self.profile_exists()
        name = self.want.name
        partition = self.want.partition
        ssh_profile = self.want.profile_name
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(partition, ssh_profile)}/rules/{name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def _add_missing_options(self, params):
        if 'shellAction' not in params['actions'][0]:
            params['actions'][0]['shellAction'] = self.want.action_shell
        if 'subSystemAction' not in params['actions'][0]:
            params['actions'][0]['subSystemAction'] = self.want.action_sub_system
        if 'sftpUpAction' not in params['actions'][0]:
            params['actions'][0]['sftpUpAction'] = self.want.action_sftp_up
        if 'sftpDownAction' not in params['actions'][0]:
            params['actions'][0]['sftpDownAction'] = self.want.action_sftp_down
        if 'scpUpAction' not in params['actions'][0]:
            params['actions'][0]['scpUpAction'] = self.want.action_scp_up
        if 'scpDownAction' not in params['actions'][0]:
            params['actions'][0]['scpDownAction'] = self.want.action_scp_down
        if 'rexecAction' not in params['actions'][0]:
            params['actions'][0]['rexecAction'] = self.want.action_rexec
        if 'localForwardAction' not in params['actions'][0]:
            params['actions'][0]['localForwardAction'] = self.want.action_forward_local
        if 'remoteForwardAction' not in params['actions'][0]:
            params['actions'][0]['remoteForwardAction'] = self.want.action_forward_remote
        if 'x11ForwardAction' not in params['actions'][0]:
            params['actions'][0]['x11ForwardAction'] = self.want.action_forward_x11
        if 'agentAction' not in params['actions'][0]:
            params['actions'][0]['agentAction'] = self.want.action_agent
        if 'otherAction' not in params['actions'][0]:
            params['actions'][0]['otherAction'] = self.want.action_other

        return params

    def profile_exists(self):
        partition = self.want.partition
        ssh_profile = self.want.profile_name
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(partition, ssh_profile)}"
        response = self.client.get(uri)

        if response['code'] == 404:
            raise F5ModuleError(
                f"The profile {self.want.profile_name} does not exist in {self.want.partition} partition."
            )
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition

        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(self.want.partition, self.want.profile_name)}/rules"
        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        name = self.want.name
        partition = self.want.partition
        ssh_profile = self.want.profile_name
        params = self._add_missing_options(self.changes.api_params())
        params['name'] = name
        params['partition'] = partition
        params['identityUsers'] = self.have.users if params.get('identityUsers') is None else self.want.users

        if 'actions' in params:
            if not params['actions'][0].get('name'):
                params['actions'][0]['name'] = self.want.action_name

        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(partition, ssh_profile)}/rules/{name}"
        response = self.client.patch(uri, data=params)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        name = self.want.name
        partition = self.want.partition
        ssh_profile = self.want.profile_name
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(partition, ssh_profile)}/rules/{name}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        name = self.want.name
        partition = self.want.partition
        ssh_profile = self.want.profile_name
        uri = f"/mgmt/tm/security/ssh/profile/{transform_name(partition, ssh_profile)}/rules/{name}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            users=dict(
                type='list',
                elements='str'
            ),
            profile_name=dict(required=True),
            action=dict(
                type='dict',
                options=dict(
                    name=dict(type='str', required=True),
                    shell=dict(
                        type='dict',
                        options=dict(
                            control=dict(
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
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
                                choices=['allow', 'disallow', 'terminate', 'unspecified']
                            ),
                            log=dict(type='bool')
                        ),
                        required_one_of=[
                            ['control', 'log']
                        ]
                    )
                )
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
        self.required_if = [
            ['state', 'present', ['users']]
        ]
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
