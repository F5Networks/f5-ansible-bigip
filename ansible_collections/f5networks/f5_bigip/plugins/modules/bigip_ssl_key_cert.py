#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ssl_key_cert
short_description: Import/Delete SSL keys and certs from BIG-IP
description:
  - This module imports/deletes SSL keys and certificates on a BIG-IP.
    Keys can be imported from key files on the local disk, in PEM format.
    Certificates can be imported from certificate and key files on the local
    disk, in PEM format.
version_added: "1.0.0"
options:
  key_content:
    description:
      - Sets the contents of a key directly to the specified value, used with lookup plugins,
        or for anything with formatting or templating.
      - Parameter must be provided when C(state) is C(present).
    type: str
  state:
    description:
      - When C(present), ensures the key and/or cert is uploaded to the
        device.
      - When C(absent), ensures the key and/or cert is removed from the device.
        If the key and/or cert is currently in use, the module will not be able to remove the key.
    type: str
    choices:
      - present
      - absent
    default: present
  key_name:
    description:
      - The name of the key.
    type: str
  passphrase:
    description:
      - Passphrase on key.
    type: str
  cert_content:
    description:
      - Sets the contents of a certificate directly to the specified value, used with lookup plugins,
        or for anything with formatting or templating.
      - Parameter must be provided when C(state) is C(present).
    type: str
  cert_name:
    description:
      - SSL Certificate Name. This is the cert name used when importing a certificate
        into the BIG-IP. It also determines the filenames of the objects on the LTM.
    type: str
  issuer_cert:
    description:
      - Issuer certificate used for OCSP monitoring.
      - This parameter is only valid on versions of BIG-IP 13.0.0 or above.
    type: str
  true_names:
    description:
      - If C(true), then the module does not append the C(.crt) and C(.key) extensions to the given certificate and key names.
      - If C(false), then the module appends the C(.crt) and C(.key) extensions to the given certificate and key names.
    type: bool
    default: false
    version_added: "2.1.0"
  partition:
    description:
      - Device partition on which to manage resources.
    type: str
    default: Common
author:
  - Nitin Khanna (@nitinthewiz)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Import both key and cert
  bigip_ssl_key_cert:
    key_content: "{{ lookup('file', 'key.pem') }}"
    key_name: cert1
    cert_content: "{{ lookup('file', 'cert.pem') }}"
    cert_name: cert1
    state: present

- name: Import cert and key without appending .crt and .key extensions
  bigip_ssl_key_cert:
    key_content: "{{ lookup('file', 'key.pem') }}"
    key_name: key1
    cert_content: "{{ lookup('file', 'cert.pem') }}"
    cert_name: cert1
    true_names: true
    state: present
'''

RETURN = r'''
# only common fields returned
'''

import hashlib
import os
import re
from datetime import datetime
from io import StringIO

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.connection import Connection

from ..module_utils.client import (
    F5Client, send_teem, TransactionContextManager
)
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, flatten_boolean, fq_name
)


class Parameters(AnsibleF5Parameters):
    download_path = '/var/config/rest/downloads'

    api_map = {
        'sourcePath': 'source_path',
        'issuerCert': 'issuer_cert',
    }

    api_attributes = [
        'passphrase',
        'sourcePath',
        'issuerCert',
    ]

    returnables = [
        'key_checksum',
        'cert_checksum',
        'key_source_path',
        'cert_source_path',
        'issuer_cert',
    ]

    updatables = [
        'key_checksum',
        'cert_checksum',
        'cert_content',
        'issuer_cert',
        'key_source_path',
        'cert_source_path',
    ]


class ApiParameters(Parameters):
    @property
    def key_filename(self):
        if self._values['key_name'] is None:
            return None
        return self._values['key_name']

    @property
    def key_source_path(self):
        if self.key_filename is None:
            return None
        if self._values['key_source_path'] is None:
            return None
        else:
            return self._values['key_source_path']

    @property
    def cert_filename(self):
        if self._values['cert_name'] is None:
            return None
        return self._values['cert_name']

    @property
    def cert_source_path(self):
        if self.cert_filename is None:
            return None
        if self._values['cert_source_path'] is None:
            return None
        else:
            return self._values['cert_source_path']

    @property
    def key_checksum(self):
        if self._values['key_checksum'] is None:
            return None
        pattern = r'SHA1:\d+:(?P<value>[\w+]{40})'
        matches = re.match(pattern, self._values['key_checksum'])
        if matches:
            return matches.group('value')

    @property
    def cert_checksum(self):
        if self._values['cert_checksum'] is None:
            return None
        pattern = r'SHA1:\d+:(?P<value>[\w+]{40})'
        matches = re.match(pattern, self._values['cert_checksum'])
        if matches:
            return matches.group('value')


class ModuleParameters(Parameters):
    def _get_hash(self, content):
        k = hashlib.sha1()
        s = StringIO(content)
        while True:
            data = s.read(1024)
            if not data:
                break
            k.update(data.encode('utf-8'))
        return k.hexdigest()

    @property
    def issuer_cert(self):
        if self._values['issuer_cert'] is None:
            return None
        name = fq_name(self.partition, self._values['issuer_cert'])
        true_name = flatten_boolean(self.true_names)
        if true_name == 'yes':
            return name
        else:
            if name.endswith('.crt'):
                return name
            else:
                return name + '.crt'

    @property
    def key_filename(self):
        if self.key_name is None:
            return None
        true_name = flatten_boolean(self.true_names)
        if true_name == 'yes':
            return self.key_name
        else:
            if self.key_name.endswith('.key'):
                return self.key_name
            else:
                return self.key_name + '.key'

    @property
    def cert_filename(self):
        if self.cert_name is None:
            return None
        true_name = flatten_boolean(self.true_names)
        if true_name == 'yes':
            return self.cert_name
        else:
            if self.cert_name.endswith('.crt'):
                return self.cert_name
            else:
                return self.cert_name + '.crt'

    @property
    def key_checksum(self):
        if self.key_content is None:
            return None
        return self._get_hash(self.key_content)

    @property
    def cert_checksum(self):
        if self.cert_content is None:
            return None
        return self._get_hash(self.cert_content)

    @property
    def key_source_path(self):
        if self.key_filename is None:
            return None
        true_name = flatten_boolean(self.true_names)
        result = 'file://' + os.path.join(
            self.download_path,
            self.key_filename
        )
        if true_name == 'yes':
            result = result + "_key"
        return result

    @property
    def cert_source_path(self):
        if self.cert_filename is None:
            return None
        true_name = flatten_boolean(self.true_names)
        result = 'file://' + os.path.join(
            self.download_path,
            self.cert_filename
        )
        if true_name == 'yes':
            result = result + "_cert"
        return result


class Changes(Parameters):  # pragma: no cover
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
        except AttributeError:  # pragma: no cover
            return attr1

    @property
    def key_checksum(self):
        if self.want.key_checksum is None:
            return None
        if self.want.key_checksum != self.have.key_checksum:
            return self.want.key_checksum

    @property
    def key_source_path(self):
        if self.want.key_source_path is None:
            return None
        if self.want.key_source_path == self.have.key_source_path:
            if self.key_checksum:
                return self.want.key_source_path
        if self.want.key_source_path != self.have.key_source_path:
            return self.want.key_source_path

    @property
    def cert_source_path(self):
        if self.want.cert_source_path is None:
            return None
        if self.want.cert_source_path == self.have.cert_source_path:
            if self.cert_content:
                return self.want.cert_source_path
        if self.want.cert_source_path != self.have.cert_source_path:
            return self.want.cert_source_path

    @property
    def cert_content(self):
        if self.want.cert_checksum != self.have.cert_checksum:
            result = dict(
                checksum=self.want.cert_checksum,
                content=self.want.cert_content
            )
            return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

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
        if self.want.key_filename:
            self.remove_uploaded_file_from_device(os.path.basename(self.want.key_source_path))
        if self.want.cert_filename:
            self.remove_uploaded_file_from_device(os.path.basename(self.want.cert_source_path))
        return True

    def remove_uploaded_file_from_device(self, name):
        filepath = '/var/config/rest/downloads/{0}'.format(name)
        params = {
            "command": "run",
            "utilCmdArgs": filepath
        }
        uri = "/mgmt/tm/util/unix-rm"

        response = self.client.post(uri, data=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def exists(self):
        if self.want.key_name:
            uri = "/mgmt/tm/sys/file/ssl-key/{0}".format(transform_name(self.want.partition, self.want.key_filename))
            response = self.client.get(uri)

            if response['code'] == 404:
                return False

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

        if self.want.cert_name:
            uri = "/mgmt/tm/sys/file/ssl-cert/{0}".format(transform_name(self.want.partition, self.want.cert_filename))
            response = self.client.get(uri)

            if response['code'] == 404:
                return False

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

        return True

    def upload_file_to_device(self, content, name):
        url = "/mgmt/shared/file-transfer/uploads"
        try:
            self.client.plugin.upload_file(url, content, name, true_path=False)
        except F5ModuleError:
            raise F5ModuleError(
                "Failed to upload the file."
            )

    def _prepare_links(self):
        # this is to ensure no duplicates are in the provided collection
        links = list()

        if self.want.key_name:
            key_link = "/mgmt/tm/sys/file/ssl-key/{0}".format(
                transform_name(self.want.partition, self.want.key_filename)
            )
            links.append(key_link)

        if self.want.cert_name:
            cert_link = "/mgmt/tm/sys/file/ssl-cert/{0}".format(
                transform_name(self.want.partition, self.want.cert_filename)
            )
            links.append(cert_link)

        return links

    def _prepare_links_for_update(self, params_dict):
        # this is to ensure no duplicates are in the provided collection
        links_and_params = list()

        if self.want.key_name:
            key_link = "/mgmt/tm/sys/file/ssl-key/{0}".format(
                transform_name(self.want.partition, self.want.key_filename)
            )
            key_params_dict = params_dict.copy()
            key_params_dict['sourcePath'] = self.want.key_source_path
            links_and_params.append({'link': key_link, 'params': key_params_dict})

        if self.want.cert_name:
            cert_link = "/mgmt/tm/sys/file/ssl-cert/{0}".format(
                transform_name(self.want.partition, self.want.cert_filename)
            )
            cert_params_dict = params_dict.copy()
            cert_params_dict['sourcePath'] = self.want.cert_source_path

            links_and_params.append({'link': cert_link, 'params': cert_params_dict})

        return links_and_params

    def _prepare_links_for_create(self, params_dict):
        # this is to ensure no duplicates are in the provided collection
        links_and_params = list()

        if self.want.key_name:
            key_link = "/mgmt/tm/sys/file/ssl-key/"
            key_params_dict = params_dict.copy()
            key_params_dict['name'] = self.want.key_filename
            key_params_dict['sourcePath'] = self.want.key_source_path
            links_and_params.append({'link': key_link, 'params': key_params_dict})

        if self.want.cert_name:
            cert_link = "/mgmt/tm/sys/file/ssl-cert/"
            cert_params_dict = params_dict.copy()
            cert_params_dict['name'] = self.want.cert_filename
            cert_params_dict['sourcePath'] = self.want.cert_source_path

            links_and_params.append({'link': cert_link, 'params': cert_params_dict})

        return links_and_params

    def create_on_device(self):
        params = self.changes.api_params()
        params['partition'] = self.want.partition

        links_and_params = self._prepare_links_for_create(params)

        if self.want.key_name:
            self.upload_file_to_device(self.want.key_content, os.path.basename(self.want.key_source_path))

        if self.want.cert_name:
            self.upload_file_to_device(self.want.cert_content, os.path.basename(self.want.cert_source_path))

        with TransactionContextManager(self.client) as transact:
            for link in links_and_params:
                response = transact.post(link['link'], data=link['params'])

                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        # update remaining parameter after certificate has been uploaded and created
        if self.want.cert_name:
            params = self.want.api_params()
            if params:
                uri = "/mgmt/tm/sys/file/ssl-cert/{0}".format(
                    transform_name(self.want.partition, self.want.cert_filename)
                )
                response = self.client.put(uri, data=params)

                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])

        return True

    def update_on_device(self):
        params = self.changes.api_params()

        if self.want.key_name:
            self.upload_file_to_device(self.want.key_content, os.path.basename(self.want.key_source_path))

        if self.want.cert_name:
            self.upload_file_to_device(self.want.cert_content, os.path.basename(self.want.cert_source_path))

        links_and_params = self._prepare_links_for_update(params)
        with TransactionContextManager(self.client) as transact:
            for link in links_and_params:
                response = transact.patch(link['link'], data=link['params'])
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        links = self._prepare_links()
        with TransactionContextManager(self.client) as transact:
            for link in links:
                response = transact.delete(link)
                if response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(response['contents'])
        return True

    def read_current_from_device(self):
        final_response = {}
        if self.want.key_name:
            uri = "/mgmt/tm/sys/file/ssl-key/{0}".format(transform_name(self.want.partition, self.want.key_filename))
            response = self.client.get(uri)

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            final_response['key_name'] = response['contents'].get('name')
            final_response['key_checksum'] = response['contents'].get('checksum')
            final_response['key_source_path'] = response['contents'].get('sourcePath')

        if self.want.cert_name:
            uri = "/mgmt/tm/sys/file/ssl-cert/{0}".format(transform_name(self.want.partition, self.want.cert_filename))

            query = '?expandSubcollections=true'
            response = self.client.get(uri + query)

            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

            final_response['cert_name'] = response['contents'].get('name')
            final_response['cert_checksum'] = response['contents'].get('checksum')
            final_response['cert_source_path'] = response['contents'].get('sourcePath')
            final_response['issuer_cert'] = response['contents'].get('issuerCert')

        return ApiParameters(params=final_response)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            key_name=dict(),
            key_content=dict(
                no_log=True
            ),
            passphrase=dict(
                no_log=True
            ),
            cert_name=dict(),
            cert_content=dict(),
            issuer_cert=dict(),
            true_names=dict(
                type='bool',
                default=False
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
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


if __name__ == '__main__':  # pragma: no cover
    main()
