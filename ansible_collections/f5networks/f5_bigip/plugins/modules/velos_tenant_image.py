#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: velos_tenant_image
short_description: Manage VELOS tenant images
description:
  - Manage VELOS tenant images.
version_added: "1.1.0"
options:
  image_name:
    description:
      - Name of the tenant image.
    type: str
    required: True
  remote_host:
    description:
      - The hostname or IP address of the remote server on which the tenant image is
        stored.
      - The server must make the image accessible via the specified C(protocol).
    type: str
  remote_port:
    description:
      - The port on the remote host to which you want to connect.
      - If the port is not provided, a default port for the selected C(protocol) is used.
    type: int
  protocol:
    description:
      - Protocol for image transfer.
    type: str
    default: scp
    choices:
      - scp
      - sftp
      - https
  remote_user:
    description:
      - User name for the remote server on which the tenant image is stored.
    type: str
  remote_password:
    description:
      - Password for the user on the remote server on which the tenant image is stored.
    type: str
  remote_path:
    description:
      - The path to the tenant image on the remote server.
    type: path
  timeout:
    description:
      - The amount of time to wait for image import to finish, in seconds.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  state:
    description:
      - The tenant image state.
      - If C(import), starts the image import task if the image does not exist.
      - If C(present), checks for the status of the import task if the image does not exist.
      - If C(absent), deletes the tenant image if it exists.
    type: str
    choices:
      - import
      - present
      - absent
    default: import
notes:
  - Repeating the same image import task immediately after the previous is not idempotent
    if the image has not finished downloading.
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
    - name: Import tenant image 'foo' onto the VELOS provider
      velos_tenant_image:
        image_name: foo
        remote_host: builds.mydomain.com
        remote_user: admin
        remote_password: secret
        remote_path: /images/
        state: import

    - name: Check the status of the image import onto the VELOS provider
      velos_tenant_image:
        image_name: foo
        timeout: 600
        state: present

    - name: Remove tenant image 'foo'
      velos_tenant_image:
        name: foo
        state: absent
'''
RETURN = r'''
image_name:
  description: Name of the tenant image.
  returned: changed
  type: str
  example: BIGIP-bigip14.1.x-miro-14.1.2.5-0.0.336.ALL-VELOS.qcow2.zip
remote_host:
  description: The hostname or IP address of the remote server.
  returned: changed
  type: str
  example: foo.bar.baz.net
remote_port:
  description: The port on the remote host to which you want to connect.
  returned: changed
  type: int
  example: 443
remote_path:
  description: The path to the tenant image on the remote server.
  returned: changed
  type: str
  example: /foo/bar/
message:
  description: Informative message of the image import status.
  returned: changed
  type: dict
  sample: Import success
'''
import time
from ipaddress import ip_interface

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.velos_client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'remote-host': 'remote_host',
        'remote-port': 'remote_port',
        'remote-file': 'remote_path',
        'username': 'remote_user',
        'password': 'remote_password',
    }
    api_attributes = [
        'protocol',
        'remote-host',
        'remote-port',
        'remote-file',
        'username',
        'password',
    ]

    returnables = [
        'protocol',
        'remote_host',
        'remote_port',
        'remote_path',
        'image_name',
        'remote_user',
        'remote_password',
        'message',
    ]

    updatables = []


class ModuleParameters(Parameters):
    @property
    def timeout(self):
        divisor = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / divisor

        return delay, divisor

    @property
    def remote_host(self):
        if self._values['remote_host'] is None:
            return None
        try:
            addr = ip_interface(u'{0}'.format(self._values['remote_host']))
            return str(addr.ip)
        except ValueError:
            # Assume hostname was passed in.
            return self._values['remote_host']

    @property
    def remote_path(self):
        if self._values['remote_path'] is None:
            return None
        if not self._values['remote_path'].endswith(self._values['image_name']):
            # API seems to require server_remote_path include the image name.
            return "{0}/{1}".format(self._values['remote_path'].rstrip('/'), self._values['image_name'])

        return self._values['remote_path']


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
    returnables = [
        'remote_host',
        'remote_port',
        'remote_path',
        'image_name',
        'remote_user',
        'message',
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.image_is_valid = False

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

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

        if state == "import":
            changed = self.import_image()
        elif state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def import_image(self):
        if self.exists() and self.image_is_valid:
            return False
        else:
            return self.create()

    def present(self):
        if self.exists() and self.image_is_valid:
            return False
        else:
            return self.check_progress()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

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
        uri = f"/f5-tenant-images:images/image={self.want.image_name}/status"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        if response['contents']['f5-tenant-images:status'] == 'replicated':
            self.image_is_valid = True
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        uri = "/f5-utils-file-transfer:file/import"
        params['local-file'] = "images"
        params['insecure'] = ""
        payload = dict(input=[params])
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to import tenant image: {self.want.image_name}")

        self.changes.update({"message": f"Image {self.want.image_name} import started."})
        return True

    def check_progress(self):
        delay, period = self.want.timeout
        for x in range(0, period):
            if self.is_imported():
                if not self.changes.message:
                    self.changes.update({"message": f"Image {self.want.image_name} import successful."})
                return True
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def is_imported(self):
        uri = f"/f5-tenant-images:images/image={self.want.image_name}/status"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] == 204:
            return False
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        status = response['contents']['f5-tenant-images:status']
        if 'replicated' in status:
            return True
        if 'verification-failed' in status:
            raise F5ModuleError(f"The image: {self.want.image_name} was imported, but it failed signature verification,"
                                f" remove the image and try again.")
        return False

    def remove_from_device(self):
        uri = "/f5-tenant-images:images/remove"
        payload = dict(input=[{"name": self.want.image_name}])
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to remove tenant image: {self.want.image_name} {response['contents']}")
        result = response['contents']["f5-tenant-images:output"]["result"]
        if result == "Successful.":
            return True
        raise F5ModuleError(f"Failed to remove tenant image: {self.want.image_name} {result}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            image_name=dict(required=True),
            remote_host=dict(),
            remote_port=dict(type='int'),
            remote_user=dict(),
            remote_password=dict(no_log=True),
            remote_path=dict(type='path'),
            protocol=dict(
                default='scp',
                choices=['scp', 'sftp', 'https']
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='import',
                choices=['import', 'present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'import', ['image_name', 'remote_host', 'remote_path']]]


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


if __name__ == '__main__':
    main()
