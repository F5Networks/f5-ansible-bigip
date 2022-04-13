#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_partition_wait
short_description: Wait for a VELOS chassis partition to match a condition before continuing
description:
  - Wait for VELOS chassis partition to match a condition before continuing.
version_added: "1.3.0"
options:
  name:
    description:
      - Name of the chassis partition.
    type: str
    required: True
  state:
    description:
      - The condition for which the system is waiting.
      - Defaults to C(running), which verifies the specified chassis partition has been created with
        a status of 'running'.
      - C(ssh-ready) waits for a deployed tenant to be reachable via SSH.
    type: str
    default: running
    choices:
      - running
      - ssh-ready
  timeout:
    description:
      - Maximum number of seconds to wait for the desired state.
    type: int
    default: 600
  delay:
    description:
      - Number of seconds to wait before starting to poll.
    type: int
    default: 0
  sleep:
    description:
      - Number of seconds to sleep between checks.
    type: int
    default: 1
  msg:
    description:
      - This overrides the normal error message from a failure to meet the required conditions.
    type: str
author:
  - Ravinder Reddy (@chinthalapalli)
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
    - name: Wait for the specified partition to be in the running state.
      velos_partition_wait:
        name: partition1
    - name: Wait a maximum of 300 seconds specified partition to be in the api_available state.
      velos_partition_wait:
        name: partition1
        state: ssh-ready
        timeout: 300
    - name: Wait 30 seconds before verifying the specified partition to be in the running state.
      velos_partition_wait:
        name: partition1
        state: running
        delay: 30
'''
RETURN = r'''
elapsed:
  description: Seconds spent waiting for the requested state.
  returned: always
  type: int
  example: 600
partition_state:
  description: State data for the specified partition.
  returned: always
  type: complex
  contains:
    controllers:
      description: State of controllers
      returned: always
      type: str
      example: '
      {
        "controllers": {
            "controller": [
                {
                    "controller": 1,
                    "partition-id": 2,
                    "partition-status": "running-active"
                },
                {
                    "controller": 2,
                    "partition-id": 2,
                    "partition-status": "running-standby"
                }
            ]
        }'
'''

import datetime
import json
import logging
import signal
import time
import traceback

try:
    import paramiko
except ImportError:
    IMPORT_ERROR = traceback.format_exc()
    HAS_SSH = False
else:
    HAS_SSH = True

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
from ansible.module_utils.connection import Connection
from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)

# paramiko.transport is too chatty - it logs exceptions raised while attempting
# to connect to ssh servers before they are ready.
paramiko_logger = logging.getLogger("paramiko.transport")
setattr(paramiko_logger, 'disabled', True)


def hard_timeout(module, want, start):
    elapsed = datetime.datetime.utcnow() - start
    module.fail_json(
        msg=want.msg or "Timeout when waiting for Velos Partition", elapsed=elapsed.seconds
    )


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [

    ]
    returnables = [
        'elapsed'
        'partition_state'
    ]

    updatables = [

    ]

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            pass
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = Parameters(params=self.module.params)
        self.changes = Parameters()
        self.have = None

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        result = dict()

        changed = self.execute()

        changes = self.changes.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def execute(self):
        if self.want.delay >= self.want.timeout:
            raise F5ModuleError(
                "The delay should not be greater than or equal to the timeout."
            )
        if self.want.delay + self.want.sleep >= self.want.timeout:
            raise F5ModuleError(
                "The combined delay and sleep should not be greater than or equal to the timeout."
            )
        signal.signal(
            signal.SIGALRM,
            lambda sig, frame: hard_timeout(self.module, self.want, start)
        )
        # setup handler before scheduling signal, to eliminate a race
        # signal.alarm(int(self.want.timeout))

        start = datetime.datetime.utcnow()
        # partition_state = {}
        if self.want.delay:
            time.sleep(float(self.want.delay))
        end = start + datetime.timedelta(seconds=int(self.want.timeout))

        partition_state = self.wait_for_partition(start, end)
        elapsed = datetime.datetime.utcnow() - start
        self.changes.update({'elapsed': elapsed.seconds,
                             'partition_state': partition_state})
        return False

    def wait_for_partition(self, start, end):
        partition_state = {}
        while datetime.datetime.utcnow() < end:
            time.sleep(int(self.want.sleep))
            try:
                # The first test verifies that the tenant exists on the specified
                # partition, indirectly verifying the partition API is reachable.
                if not self.partition_exists():
                    partition_state.update(status='Partition Not Found')
                    continue

                partition_data = self.read_partition_from_device()
                partition_state = partition_data.get('state', {})

                if self.want.state == 'running' and self.partition_is_running(partition_state):
                    break

                # elif self.want.state == 'removed' and self.partition_is_removed(partition_state):
                #     break

                elif self.want.state == 'ssh-ready' and self.partition_ssh_ready(partition_data):
                    break

                # No match - log state data
                self.module.debug(json.dumps(partition_data))

            except Exception as ex:
                self.module.debug(str(ex))
                continue
        else:
            elapsed = datetime.datetime.utcnow() - start
            self.module.fail_json(
                msg=self.want.msg or "Timeout waiting for desired parition state", elapsed=elapsed.seconds,
                partition_state=partition_state
            )
        return partition_state

    def partition_exists(self):
        """ Determine if specified partition exists.
        """
        uri = f"/f5-system-partition:partitions/partition={self.want.name}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def read_partition_from_device(self):
        """ Read Specified Partition from device
        """
        uri = f"/f5-system-partition:partitions/partition={self.want.name}"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-system-partition:partition'][0]

    def partition_is_running(self, partition):
        """ Determine if specified partition status is 'running'
        """
        partition_status = [p['partition-status'] for p in partition['controllers']['controller']]
        is_running = all(
            status.lower() in ['running', 'running-active', 'running-standby'] for status in partition_status)
        return is_running

    def partition_is_removed(self):
        """ Determine if specified partition is (not) present in controller status output.
        """
        return not self.partition_exists()

    def partition_ssh_ready(self, partition_data):
        """ Return True if the partition is ready to accept ssh connections.
        """
        ssh_ready = False
        host = ""
        if 'ipv4' in partition_data['config']['mgmt-ip']:
            host = partition_data['config']['mgmt-ip']['ipv4']['address']
        if 'ipv6' in partition_data['config']['mgmt-ip']:
            host = partition_data['config']['mgmt-ip']['ipv6']['address']
        port = partition_data['config'].get('port', 22)

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.load_system_host_keys()
            ssh_client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            # We don't expect or need these credentials to work. Just want to wait
            # for the ssh server to accept connections.
            ssh_client.connect(host, port, 'admin', 'foo')
            # Successful connection?
            ssh_ready = True

        except paramiko.ssh_exception.AuthenticationException:
            # SSH Server is up.
            ssh_ready = True

        except Exception:
            # ssh server must not be ready.
            pass

        finally:
            try:
                ssh_client.close()
            except Exception:
                pass

        return ssh_ready


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            state=dict(
                choices=['running', 'ssh-ready'],
                default='running'
            ),
            timeout=dict(default=600, type='int'),
            delay=dict(default=0, type='int'),
            sleep=dict(default=1, type='int'),
            msg=dict()
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )
    if not HAS_SSH:
        module.fail_json(msg=missing_required_lib('another_library'), exception=IMPORT_ERROR)

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
