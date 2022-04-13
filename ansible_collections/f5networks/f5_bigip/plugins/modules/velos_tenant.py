#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: velos_tenant
short_description: Manage VELOS tenants
description:
  - Manage VELOS tenants.
version_added: "1.1.0"
options:
  name:
    description:
      - Name of the tenant.
    type: str
    required: True
  image_name:
    description:
      - Name of the tenant image to be used. Must be present on the chassis partition.
      - Required for create operations.
    type: str
  nodes:
    description:
      - List of integers. Specifies which blades C(nodes) the tenant are deployed on.
      - Required for create operations.
    type: list
    elements: int
  mgmt_ip:
    description:
      - IP address which is used to connect to the deployed tenant.
      - Required for create operations.
    type: str
  mgmt_prefix:
    description:
      - Tenant management CIDR prefix.
    type: int
  mgmt_gateway:
    description:
      - Tenant management gateway.
    type: str
  vlans:
    description:
      - The existing VLAN IDs in the chassis partition that should be added to the tenant.
      - The order of these VLANs is ignored.
      - This module orders the VLANs automatically, therefore, if you deliberately re-order them in subsequent tasks,
        this module will B(not) register a change.
      - Required for create operations.
    type: list
    elements: int
  cpu_cores:
    description:
      - The number of vCPUs that should be added to the Tenant.
      - Required for create operations.
    type: int
    choices:
      - 1
      - 2
      - 4
      - 6
      - 8
      - 10
      - 12
      - 14
      - 16
      - 18
      - 20
      - 22
  memory:
    description:
      - The amount of memory that should be provided to the tenant, in KB.
      - Required for create operations.
    type: int
  cryptos:
    description:
      - Should crypto and compression hardware offload be enabled on the tenant.
      - The recommendation is to have this enabled, otherwise crypto and compression may be processed in CPU.
    type: str
    choices:
      - enabled
      - disabled
  running_state:
    description:
      - Desired C(running_state) of the tenant.
    type: str
    choices:
      - configured
      - provisioned
      - deployed
  state:
    description:
      - The tenant state. If C(absent), deletes the tenant if it exists.
      - If C(present) the tenant is created and enabled.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
notes:
  - The module will create configurations of the tenants, it does not assume actual state of the running tenant.
  - As deployment of tenants is a lengthy process, the module C(velos_tenant_wait) should be used in concert with
    this module to achieve desired results.
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
    - name: Create tenant 'foo'
      velos_tenant:
        name: foo
        image_name: BIGIP-bigip14.1.x-miro-14.1.2.3-0.0.182.ALL-VELOS.qcow2.zip
        nodes:
          - 1
        mgmt_ip: 10.144.3.17
        mgmt_prefix: 19
        mgmt_gateway: 10.146.127.254
        vlans: [245]
        cpu_cores: 2
        memory: 4096
        cryptos: disabled
        running_state: configured

    - name: Deploy tenant 'foo'
      velos_tenant:
        name: foo
        running_state: deployed

    - name: Delete tenant 'foo'
      velos_tenant:
        name: foo
        state: absent
'''

RETURN = r'''
image_name:
  description: Name of the tenant image.
  returned: changed
  type: str
  sample: BIGIP-bigip.TMOS-VEL.qcow2.zip
nodes:
  description: Specify on which blades the tenant is configured.
  returned: changed
  type: list
  sample: [1]
mgmt_ip:
  description: IP address used to connect to the deployed tenant.
  returned: changed
  type: str
  sample: 192.168.1.1
mgmt_prefix:
  description: Tenant management CIDR prefix.
  returned: changed
  type: int
  sample: 24
mgmt_gateway:
  description: Tenant management gateway.
  returned: changed
  type: str
  sample: 192.168.1.254
vlans:
  description: Existing VLAN IDs in the chassis partition to be added to the tenant.
  returned: changed
  type: list
  sample: [444, 333]
cpu_cores:
  description: The number of vCPUs added to tenant.
  returned: changed
  type: int
  sample: 4
memory:
  description: The amount of memory in KB provided to the tenant.
  returned: changed
  type: int
  sample: 4096
cryptos:
  description: Specify if crypto and compression hardware offload is enabled for the tenant.
  returned: changed
  type: str
  sample: enabled
running_state:
  description: The running_state of tenant.
  returned: changed
  type: str
  sample: provisioned
'''

from ipaddress import ip_interface

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.velos_client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'image': 'image_name',
        'mgmt-ip': 'mgmt_ip',
        'prefix-length': 'mgmt_prefix',
        'gateway': 'mgmt_gateway',
        'running-state': 'running_state',
        'vcpu-cores-per-node': 'cpu_cores',
        'cpu-cores': 'cpu_cores'
    }

    api_attributes = [
        'image',
        'nodes',
        'mgmt-ip',
        'prefix-length',
        'gateway',
        'vlans',
        'vcpu-cores-per-node',
        'memory',
        'cryptos',
        'running-state',
    ]

    returnables = [
        'image_name',
        'nodes',
        'mgmt_ip',
        'mgmt_prefix',
        'mgmt_gateway',
        'vlans',
        'cpu_cores',
        'memory',
        'cryptos',
        'running_state'
    ]

    updatables = [
        'image_name',
        'nodes',
        'mgmt_ip',
        'mgmt_prefix',
        'mgmt_gateway',
        'vlans',
        'cpu_cores',
        'memory',
        'cryptos',
        'running_state'
    ]


class ApiParameters(Parameters):
    @property
    def cpu_cores(self):
        try:
            cpu_cores = self._values.get('vcpu-cores-per-node') or self._values.get('cpu_cores')
            return int(cpu_cores)
        except (TypeError, ValueError):
            return None

    @property
    def memory(self):
        try:
            return int(self._values.get('memory'))
        except (TypeError, ValueError):
            return None


class ModuleParameters(Parameters):
    @property
    def nodes(self):
        if self._values['nodes'] is None:
            return None
        result = [int(x) for x in self._values['nodes']]
        result.sort()
        if min(result) < 0 or max(result) > 32:
            raise F5ModuleError(
                "Valid node id's must be in range 0 - 32."
            )
        return result

    @property
    def mgmt_ip(self):
        if self._values['mgmt_ip'] is None:
            return None
        try:
            addr = ip_interface(u'{0}'.format(self._values['mgmt_ip']))
            return str(addr.ip)
        except ValueError:
            raise F5ModuleError(
                "The specified 'mgmt_ip' is not a valid IP address."
            )

    @property
    def mgmt_gateway(self):
        if self._values['mgmt_gateway'] is None:
            return None
        try:
            addr = ip_interface(u'{0}'.format(self._values['mgmt_gateway']))
            return str(addr.ip)
        except ValueError:
            raise F5ModuleError(
                "The specified 'mgmt_gateway' is not a valid IP address."
            )

    @property
    def memory(self):
        if self._values['memory'] is None:
            return None
        elif self._values['memory'] < 1 or self._values['memory'] > 8388608:
            raise F5ModuleError(
                "Valid 'memory' must be in range 1 - 8388608"
            )
        return self._values['memory']

    @property
    def vlans(self):
        if self._values['vlans'] is None:
            return None
        result = [int(x) for x in self._values['vlans']]
        result.sort()
        if min(result) < 0 or max(result) > 4095:
            raise F5ModuleError(
                "Valid 'vlan' id must be in range 0 - 4095."
            )
        return result


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

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
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
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def create_on_device(self):
        params = self.changes.api_params()
        payload = dict(tenant=[dict(name=self.want.name, config=params)])

        uri = "/f5-tenants:tenants"
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        for k, v in params.items():
            uri = f"/f5-tenants:tenants/tenant={self.want.name}/config/{k}"
            payload = {k: v}
            response = self.client.patch(uri, data=payload)
            if response['code'] not in [200, 201, 202, 204]:
                raise F5ModuleError("Failed to update tenant {0}, {1} to {2}".format(self.want.name, k, v))
        return True

    def remove_from_device(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}"
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202, 204]:
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/f5-tenants:tenants/tenant={self.want.name}/config"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return ApiParameters(params=response['contents']['f5-tenants:config'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            image_name=dict(),
            nodes=dict(type='list', elements='int'),
            mgmt_ip=dict(),
            mgmt_prefix=dict(type='int'),
            mgmt_gateway=dict(),
            vlans=dict(type='list', elements='int'),
            cpu_cores=dict(
                type='int',
                choices=[1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]
            ),
            memory=dict(type='int'),
            cryptos=dict(
                choices=['enabled', 'disabled']
            ),
            running_state=dict(
                choices=['configured', 'provisioned', 'deployed']
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


if __name__ == '__main__':
    main()
