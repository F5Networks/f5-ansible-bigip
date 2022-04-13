#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_tenant_wait
short_description: Wait for a VELOS condition before continuing
description:
  - Wait for a VELOS tenant to be C(configured), C(provisioned) or C(deployed).
version_added: "1.1.0"
options:
  name:
    description:
      - Name of the tenant.
    type: str
    required: True
  state:
    description:
      - The condition for which the system is waiting.
      - Defaults to C(configured), which verifies the specified tenant has been created on
        the partition and is in the configured run-state.
      - C(provisioned) waits for the tenant running-state and status "provisioned".
      - C(deployed) waits for the tenant running-state "deployed", status "running", and phase "running".
      - C(ssh-ready) waits for a deployed tenant to be reachable via SSH.
    type: str
    default: configured
    choices:
      - configured
      - provisioned
      - deployed
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
    ansible_network_os: f5networks.f5_bigip.velos
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Wait for the specified tenant to be in the configured state.
      velos_tenant_wait:
        name: bigip_tenant1

    - name: Wait a maximum of 300 seconds specified tenant to be in the provisioned state.
      velos_tenant_wait:
        name: bigip_tenant1
        state: provisioned
        timeout: 300

    - name: Wait 30 seconds before verifying the specified tenant to be in the deployed state.
      velos_tenant_wait:
        name: bigip_tenant1
        state: deployed
        delay: 30
'''

RETURN = r'''
elapsed:
  description: Seconds spent waiting for the requested state.
  returned: always
  type: int
  example: 600
tenant_state:
  description: State data for the specified tenant.
  returned: always
  type: complex
  contains:
    name:
      description: Name of the tenant.
      returned: always
      type: str
      example: 'defaultbip'
    type:
      description: Tenant type.
      returned: always
      type: str
      example: 'BIG-IP'
    blades:
      description: Blades allocated to tenant.
      returned: always
      type: int
      example: 1
    cryptos:
      description: Tenant crypto state. Enabled or Disabled.
      returned: always
      type: str
      example: 'disabled'
    cpu-cores:
      description: CPU Cores allocated to the tenant.
      returned: always
      type: str
      example: '1'
    memory:
      description: Memory allocated to the tenant.
      returned: always
      type: str
      example: '4092'
    running-state:
      description: Tenant running state.
      returned: always
      type: str
      example: 'defaultbip'
    mac-data:
      description: Tenant MAC pool details.
      returned: always
      type: dict
      example: hash/dictionary of values
    status:
      description: Tenant Running state.
      returned: always
      type: str
      example: 'Running'
    instances:
      description: Tenant instance details.
      returned: always
      type: dict
      example: hash/dictionary of values
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
        msg=want.msg or "Timeout when waiting for Velos Tenant", elapsed=elapsed.seconds
    )


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [

    ]

    returnables = [
        'elapsed',
        'tenant_state'
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
            raise
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
        start = datetime.datetime.utcnow()
        if self.want.delay:
            time.sleep(float(self.want.delay))
        end = start + datetime.timedelta(seconds=int(self.want.timeout))

        tenant_state = self.wait_for_tenant(start, end)
        elapsed = datetime.datetime.utcnow() - start
        self.changes.update({'elapsed': elapsed.seconds,
                             'tenant_state': tenant_state})
        return False

    def wait_for_tenant(self, start, end):
        tenant_state = {}
        while datetime.datetime.utcnow() < end:
            time.sleep(int(self.want.sleep))
            try:
                # The first test verifies that the tenant exists on the specified
                # partition, indirectly verifying the partition API is reachable.
                if not self.tenant_exists():
                    tenant_state.update(status='Tenant Not Found')
                    continue

                tenant_data = self.read_tenant_from_device()
                tenant_state = tenant_data.get('state', {})

                if self.want.state == 'configured' and self.tenant_is_configured(tenant_state):
                    break

                elif self.want.state == 'provisioned' and self.tenant_is_provisioned(tenant_state):
                    break

                elif self.want.state == 'deployed' and self.tenant_is_deployed(tenant_state):
                    break

                elif self.want.state == 'ssh-ready' and self.tenant_ssh_ready(tenant_data):
                    break

                # No match - log state data
                self.module.debug(json.dumps(tenant_data))

            except Exception as ex:
                self.module.debug(str(ex))
                continue
        else:
            elapsed = datetime.datetime.utcnow() - start
            self.module.fail_json(
                msg=self.want.msg or "Timeout waiting for desired tenant state", elapsed=elapsed.seconds,
                tenant_state=tenant_state
            )
        return tenant_state

    def tenant_exists(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def read_tenant_from_device(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['f5-tenants:tenant'][0]

    def tenant_is_configured(self, tenant_state):
        # example tenant_data when tenant is configured.
        #  {
        #   "name": "defaultbip",
        #   "type": "BIG-IP",
        #   "mgmt-ip": "10.146.97.29",
        #   "prefix-length": 19,
        #   "gateway": "10.146.127.254",
        #   "mac-ndi-set": [
        #     {
        #       "ndi": "default",
        #       "mac": "00:94:a1:8e:7c:0b"
        #     }
        #   ],
        #   "vlans": [
        #     104
        #   ],
        #   "cryptos": "disabled",
        #   "vcpu-cores-per-node": "2",
        #   "memory": "8192",
        #   "running-state": "configured",
        #   "mac-data": {
        #     "mgmt-mac": "00:94:a1:8e:7c:09",
        #     "base-mac": "00:94:a1:8e:7c:0a",
        #     "mac-pool-size": 1
        #   },
        #   "appliance-mode": {
        #     "enabled": false
        #   },
        #   "status": "Configured"
        # }
        run_state = tenant_state.get('running-state', '').lower() == 'configured'
        if tenant_state.get('status') is not None:
            return all([run_state, tenant_state.get('status')])
        return run_state

    def tenant_is_provisioned(self, tenant_state):
        # example tenant_data when tenant is provisioned.
        #  {
        #   "name": "defaultbip",
        #   "type": "BIG-IP",
        #   "mgmt-ip": "10.146.97.29",
        #   "prefix-length": 19,
        #   "gateway": "10.146.127.254",
        #   "mac-ndi-set": [
        #     {
        #       "ndi": "default",
        #       "mac": "00:94:a1:8e:7c:0b"
        #     }
        #   ],
        #   "vlans": [
        #     104
        #   ],
        #   "cryptos": "disabled",
        #   "vcpu-cores-per-node": "2",
        #   "memory": "8192",
        #   "running-state": "provisioned",
        #   "mac-data": {
        #     "mgmt-mac": "00:94:a1:8e:7c:09",
        #     "base-mac": "00:94:a1:8e:7c:0a",
        #     "mac-pool-size": 1
        #   },
        #   "appliance-mode": {
        #     "enabled": false
        #   },
        #   "status": "Provisioned",
        #   "primary-slot": 1,
        #   "image-version": "BIG-IP 14.1.2.8 0.0.477",
        #   "instances": {
        #     "instance": [
        #       {
        #         "node": 1,
        #         "instance-id": 1,
        #         "phase": "Ready to deploy",
        #         "image-name": "BIGIP-bigip14.1.x-miro-14.1.2.8-0.0.477.ALL-VELOS.qcow2.zip.bundle",
        #         "creation-time": "",
        #         "ready-time": "",
        #         "status": " "
        #       }
        #     ]
        #   }
        # }
        run_state = tenant_state.get('running-state', '').lower() == 'provisioned'
        run_status = tenant_state.get('status', '').lower() == 'provisioned'
        is_provisioned = all([run_state, run_status])
        return is_provisioned

    def tenant_is_deployed(self, tenant_state):
        # example tenant_data when tenant is deployed.
        # {
        #   "name": "defaultbip",
        #   "type": "BIG-IP",
        #   "mgmt-ip": "10.146.97.29",
        #   "prefix-length": 19,
        #   "gateway": "10.146.127.254",
        #   "mac-ndi-set": [
        #     {
        #       "ndi": "default",
        #       "mac": "00:94:a1:8e:7c:0b"
        #     }
        #   ],
        #   "vlans": [
        #     104
        #   ],
        #   "cryptos": "disabled",
        #   "vcpu-cores-per-node": "2",
        #   "memory": "8192",
        #   "running-state": "deployed",
        #   "mac-data": {
        #     "mgmt-mac": "00:94:a1:8e:7c:09",
        #     "base-mac": "00:94:a1:8e:7c:0a",
        #     "mac-pool-size": 1
        #   },
        #   "appliance-mode": {
        #     "enabled": false
        #   },
        #   "status": "Running",
        #   "primary-slot": 1,
        #   "image-version": "BIG-IP 14.1.2.8 0.0.477",
        #   "instances": {
        #     "instance": [
        #       {
        #         "node": 1,
        #         "instance-id": 1,
        #         "phase": "Running",
        #         "image-name": "BIGIP-bigip14.1.x-miro-14.1.2.8-0.0.477.ALL-VELOS.qcow2.zip.bundle",
        #         "creation-time": "2020-10-13T18:56:40Z",
        #         "ready-time": "2020-10-13T18:56:38Z",
        #         "status": "Started tenant instance"
        #       }
        #     ]
        #   }
        # }
        run_phase = []
        for instance in tenant_state.get('instances', {}).get('instance', []):
            run_phase.append(instance.get('phase', '').lower() == 'running')

        running = all(run_phase)
        run_state = tenant_state.get('running-state', '').lower() == 'deployed'
        run_status = tenant_state.get('status', '').lower() == 'running'
        is_deployed = all([run_state, run_status, running])
        return is_deployed

    def tenant_ssh_ready(self, tenant_data):
        """ Return True if the tenant is ready to accept ssh connections.
        """
        ssh_ready = False
        host = tenant_data['config']['mgmt-ip']
        port = tenant_data['config'].get('port', 22)

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.load_system_host_keys()
            ssh_client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            # We don't expect or need these credentials to work. Just want to wait
            # for the ssh server to accept connections.
            ssh_client.connect(host, port, 'root', 'foo')
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
                choices=['configured', 'provisioned', 'deployed', 'ssh-ready'],
                default='configured'
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
