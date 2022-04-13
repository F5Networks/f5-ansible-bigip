#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: velos_partition_image
short_description: Manage VELOS chassis partition images
description:
  - Manage VELOS chassis partition images.
version_added: "1.1.0"
options:
  image_name:
    description:
      - Name of the partition image.
      - "The value must follow original F5 ISO naming pattern: C(F5OS-C-) if C(iso_version) is not provided."
    type: str
    required: True
  iso_version:
    description:
      - The F5OS-C OS version.
      - When not provided, the value is extracted from the provided C(image_name).
    type: str
  remote_host:
    description:
      - The hostname or IP address of the remote server on which the partition image is
        stored.
      - The server must make the image accessible via the specified C(protocol).
    type: str
  remote_port:
    description:
      - The port to connect to on the remote host.
      - If the port is not provided, a default port for the selected C(protocol) is used.
    type: int
  protocol:
    description:
      - Protocol to be used for image transfer.
    type: str
    default: scp
    choices:
      - scp
      - sftp
      - https
  remote_user:
    description:
      - User name for the remote server on which the partition image is stored.
    type: str
  remote_password:
    description:
      - Password for the user on the remote server on which the partition image is stored.
    type: str
  remote_path:
    description:
      - The path to the partition image on the remote server.
    type: path
  timeout:
    description:
      - The amount of time to wait for image import to finish, in seconds.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  state:
    description:
      - The partition image state.
      - If C(import), starts the image import task if the image does not exist.
      - If C(present), checks for the status of the import task if the image does not exist.
      - If C(absent), deletes the partition image if it exists.
    type: str
    choices:
      - import
      - present
      - absent
    default: import
notes:
  - It can take up to 20 minutes for the image to register on the device after successful upload.
  - As there is no way to check the internal ISO import progress yet, users should assume if the image ISO
    has not been found by this module when running the module with C(state) set to C(present) and 20 minutes has
    passed since it was uploaded, the internal import failed. The most common reason for this failure is ISO
    image corruption.
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
    - name: Import partition image onto the Velos controller
      velos_partition_image:
        image_name: F5OS-C-1.1.0-3198.PARTITION.iso
        remote_host: builds.mydomain.com
        remote_user: admin
        remote_password: secret
        remote_path: /images/
        state: import

    - name: Check for presence of the imported ISO on the Velos controller
      velos_partition_image:
        image_name: F5OS-C-1.1.0-3198.PARTITION.iso
        timeout: 600
        state: present

    - name: Remove partition image from the Velos controller
      velos_partition_image:
        image_name: F5OS-C-1.1.0-3198.PARTITION.iso
        state: absent
'''
RETURN = r'''
image_name:
  description: Name of the partition image.
  returned: changed
  type: str
  example: F5OS-C-1.1.0-3198.PARTITION.iso
remote_host:
  description: The hostname or IP address of the remote server.
  returned: changed
  type: str
  example: foo.bar.baz.net
remote_port:
  description: The port to connect to on the remote host.
  returned: changed
  type: int
  example: 443
remote_path:
  description: The path to the partition image on the remote server.
  returned: changed
  type: str
  example: /foo/bar/
message:
  description: Informative message of the image import status.
  returned: changed
  type: dict
  sample: Import success
iso_version:
  description: Version of the ISO image.
  returned: changed
  type: dict
  sample: 1.1.0-3198
'''
import re
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
        'iso_version',
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
    def iso_version(self):
        # attempt to extract iso_version if not provided
        if self._values['iso_version'] is None:
            pattern = r"\d\.\d\.\d\-\d*"
            value = re.search(pattern, self._values['image_name'])
            if value:
                return value.group(0)
            raise F5ModuleError(
                f"Could not derive iso_version from provided image_name {self._values['image_name']}."
                f"If the image name has been changed from the original 'F5OS-C-' "
                f"format, iso_version parameter must be provided."
            )
        return self._values['iso_version']

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
        'message',
        'iso_version'
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()

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
        if self.exists():
            return False
        else:
            return self.create()

    def present(self):
        if self.exists():
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
        uri = f"/f5-system-image:image/partition/config/iso/iso={self.want.iso_version}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        uri = "/f5-utils-file-transfer:file/import"
        params['local-file'] = "/var/import/staging/",
        params['insecure'] = ""
        payload = dict(input=[params])
        response = self.client.post(uri, data=payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to import partition image: {self.want.image_name}")

        self.changes.update({"message": f"Image {self.want.image_name} import started."})
        return True

    def check_progress(self):
        delay, period = self.want.timeout
        for x in range(0, period):
            if self.is_imported():
                if not self.changes.message:
                    self.changes.update({"message": f"Image {self.want.image_name} import successful."})
                return True
            self.check_file_transfer_status()
            time.sleep(delay)
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def check_file_transfer_status(self):
        uri = "/f5-utils-file-transfer:file/transfer-status"
        payload = {"f5-utils-file-transfer:file-name": f"/var/import/staging/{self.want.image_name}"}
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        r = response['contents']['f5-utils-file-transfer:output']['result']
        result = r.split('\n')[2].split('|')[-1]
        if not any(s in result for s in ['Completed', 'File Transfer Initiated']):
            raise F5ModuleError(f"Error uploading image: {result}")

    def is_imported(self):
        uri = f"/f5-system-image:image/partition/config/iso/iso={self.want.iso_version}"
        response = self.client.get(uri)
        if response['code'] == 404:
            return False
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        uri = "/f5-system-image:image/partition/remove"
        payload = {"f5-system-image:iso": self.want.iso_version}
        response = self.client.post(uri, data=payload)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(f"Failed to remove partition ISO: {self.want.iso_version} {response['contents']}")
        result = response['contents']["f5-system-image:output"]["response"]
        if result == "specified images removed":
            return True
        raise F5ModuleError(f"Failed to remove partition ISO: {self.want.iso_version} {result}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            iso_version=dict(),
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
            ['state', 'import', ['image_name', 'remote_host', 'remote_path']]
        ]


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
