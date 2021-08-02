#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_software_image
short_description: Manage software images on a BIG-IP
description:
  - Manages software images on a BIG-IP. These images may include both base images
    and hotfix images.
version_added: "1.1.0"
options:
  force:
    description:
      - When C(yes), uploads the file every time and replaces the file on the
        device.
      - When C(no), the file is only uploaded if it does not already
        exist.
      - Generally should be C(yes) only in cases where you have reason
        to believe the image was corrupted during upload.
    type: bool
    default: no
  state:
    description:
      - When C(present), ensures the image is uploaded.
      - When C(absent), ensures the image is removed.
    type: str
    choices:
      - absent
      - present
    default: present
  image:
    description:
      - The image to put on the remote device.
      - This may be an absolute or relative location on the Ansible controller.
      - Image names, whether they are base ISOs or hotfix ISOs, B(must) be unique.
    type: str
    required: True
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
    - name: Upload relative image to the BIG-IP
      bigip_software_image:
        image: BIGIP-13.0.0.0.0.1645.iso

    - name: Upload absolute image to the BIG-IP
      bigip_software_image:
        image: /path/to/images/BIGIP-13.0.0.0.0.1645.iso

    - name: Upload image in a role to the BIG-IP
      bigip_software_image:
        image: "{{ role_path }}/files/BIGIP-13.0.0.0.0.1645.iso"
'''

RETURN = r'''
image_type:
  description: Whether the image is a release or hotfix image.
  returned: changed
  type: str
  sample: release
version:
  description: Version of the software contained in the image.
  returned: changed
  type: str
  sample: 13.1.0.8
build:
  description: Build version of the software contained in the image.
  returned: changed
  type: str
  sample: 0.0.3
checksum:
  description: MD5 checksum of the ISO.
  returned: changed
  type: str
  sample: 8cdbd094195fab4b2b47ff4285577b70
file_size:
  description: Size of the uploaded image in MB.
  returned: changed
  type: int
  sample: 1948
'''

import os
import time
from datetime import datetime

from ansible.module_utils.urls import urlparse
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        'fileSize': 'file_size'
    }

    api_attributes = [

    ]

    returnables = [
        'image_type',
        'version',
        'build',
        'checksum',
        'file_size',
    ]

    updatables = [

    ]


class ApiParameters(Parameters):
    @property
    def file_size(self):
        if self._values['file_size'] is None:
            return None
        tmp = self._values['file_size'].split(' ')
        return int(tmp[0])


class ModuleParameters(Parameters):
    @property
    def filename(self):
        return os.path.basename(self.image)


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
        self.have = ApiParameters()
        self.changes = UsableChanges()
        self.image_type = None
        self.image_url = None

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

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

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

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def exists(self):
        if self.image_exists() or self.hotfix_exists():
            return True
        return False

    def _set_image_url(self, item):
        self.image_url = urlparse(item['selfLink']).path

    def image_exists(self):
        result = False
        uri = "/mgmt/tm/sys/software/image/"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents']:
            for item in response['contents']['items']:
                if item['name'].startswith(self.want.filename):
                    self._set_image_url(item)
                    self.image_type = 'release'
                    result = True
                    break
        return result

    def hotfix_exists(self):
        result = False
        uri = "/mgmt/tm/sys/software/hotfix/"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if 'items' in response['contents']:
            for item in response['contents']['items']:
                if item['name'].startswith(self.want.filename):
                    self._set_image_url(item)
                    self.image_type = 'hotfix'
                    result = True
                    break
        return result

    def update(self):
        if self.module.check_mode:
            return True
        if self.want.force:
            # The process of updating is a forced re-creation.
            self.remove_from_device()
            self.create_on_device()
            return True
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()

        # Deleting images involves a short period of inconsistency in the REST
        # API due to needing to remove files from disk and update MCPD.
        #
        # This should not (realistically) take more than 30 seconds.
        for x in range(0, 30):
            if not self.exists():
                return True
            time.sleep(1)
        raise F5ModuleError("Failed to delete the resource.")

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True

        self.create_on_device()

        # Creating images involves a short period of inconsistency in the REST
        # API likely due to having to move files into appropriate places on disk
        # and update MCPD with information.
        #
        # This should not (realistically) take more than 30 seconds.
        for x in range(0, 30):
            if self.exists():
                # We want to return some information about the image that was just uploaded
                #
                # This must appear after the creation process because the information
                # does not exist on the device (has been parsed by BIG-IP) until the
                # ISO is uploaded.
                self.want = self.read_current_from_device()
                self._set_changed_options()
                return True
            time.sleep(1)
        raise F5ModuleError("Failed to create the resource.")

    def create_on_device(self):
        url = "/mgmt/cm/autodeploy/software-image-uploads"
        try:
            self.client.plugin.upload_file(url, self.want.image)
        except F5ModuleError:
            raise

    def read_current_from_device(self):
        response = self.client.get(self.image_url)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        result = ApiParameters(params=response['contents'])
        result.update({'image_type': self.image_type})
        return result

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        if self.image_exists():
            self.remove_iso_from_device('image')
        elif self.hotfix_exists():
            self.remove_iso_from_device('hotfix')

    def remove_iso_from_device(self, type):
        uri = "/mgmt/tm/sys/software/{0}/{1}".format(type, self.want.filename)
        response = self.client.delete(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            force=dict(type='bool', default='no'),
            image=dict(required=True),
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
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
