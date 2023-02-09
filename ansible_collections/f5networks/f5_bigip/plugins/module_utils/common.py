# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json

try:
    from jinja2 import Environment
except ImportError as imp_exc:
    JINA2_IMPORT_ERROR = imp_exc
    Environment = None
else:
    JINA2_IMPORT_ERROR = None

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import exec_command
from ansible.module_utils.six import (
    iteritems, raise_from
)
from ansible.module_utils.parsing.convert_bool import (
    BOOLEANS_TRUE, BOOLEANS_FALSE
)
from collections import (
    defaultdict, namedtuple
)

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.config import (
    NetworkConfig, ConfigLine, ignore_line
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list, ComplexList
)


def process_json(data, template):
    if JINA2_IMPORT_ERROR:
        raise_from(F5ModuleError('jinja2 package must be installed to use this collection'),
                   JINA2_IMPORT_ERROR
                   )
    jinja_env = Environment()
    template = jinja_env.from_string(template)
    content = template.render(params=data)
    my_json = json.loads(content)
    return my_json


def check_for_atc_errors(task):
    result = list()
    AtcError = namedtuple('AtcError', ['code', 'status', 'tenant', 'err'])
    if task.get('results'):
        for msg in task.get('results'):
            if msg['code'] != 200 and msg['message'] != 'in progress':
                error = AtcError(
                    code=msg['code'], status=msg['response'] if msg.get('response') else msg['message'],
                    tenant=msg.get('tenant'), err=msg.get('errors')
                )
                result.append(error)
    return result


def fq_name(partition, value, sub_path=''):
    """Returns a 'Fully Qualified' name

    A BIG-IP expects most names of resources to be in a fully-qualified
    form. This means that both the simple name, and the partition need
    to be combined.

    The Ansible modules, however, can accept (as names for several
    resources) their name in the FQ format. This becomes an issue when
    the FQ name and the partition are both specified as separate values.

    Consider the following examples.

        # Name not FQ
        name: foo
        partition: Common

        # Name FQ
        name: /Common/foo
        partition: Common

    This method will rectify the above situation and will, in both cases,
    return the following for name.

        /Common/foo

    Args:
        partition (string): The partition that you would want attached to
            the name if the name has no partition.
        value (string): The name that you want to attach a partition to.
            This value will be returned unchanged if it has a partition
            attached to it already.
        sub_path (string): The sub path element. If defined the sub_path
            will be inserted between partition and value.
            This will also work on FQ names.
    Returns:
        string: The fully qualified name, given the input parameters.
    """
    if value is not None and sub_path == '':
        try:
            int(value)
            return '/{0}/{1}'.format(partition, value)
        except (ValueError, TypeError):
            if not value.startswith('/'):
                return '/{0}/{1}'.format(partition, value)
    if value is not None and sub_path != '':
        try:
            int(value)
            return '/{0}/{1}/{2}'.format(partition, sub_path, value)
        except (ValueError, TypeError):
            if value.startswith('/'):
                dummy, partition, name = value.split('/')
                return '/{0}/{1}/{2}'.format(partition, sub_path, name)
            if not value.startswith('/'):
                return '/{0}/{1}/{2}'.format(partition, sub_path, value)
    return value


def to_commands(module, commands):
    spec = {
        'command': dict(key=True),
        'prompt': dict(),
        'answer': dict()
    }
    transform = ComplexList(spec, module)
    return transform(commands)


def run_commands(module, commands, check_rc=True):
    responses = list()
    commands = to_commands(module, to_list(commands))
    for cmd in commands:
        cmd = module.jsonify(cmd)
        rc, out, err = exec_command(module, cmd)
        if check_rc and rc != 0:
            raise F5ModuleError(to_text(err, errors='surrogate_then_replace'))
        result = to_text(out, errors='surrogate_then_replace')
        responses.append(result)
    return responses


def flatten_boolean(value):
    truthy = list(BOOLEANS_TRUE) + ['enabled', 'True', 'true']
    falsey = list(BOOLEANS_FALSE) + ['disabled', 'False', 'false']
    if value is None:
        return None
    elif value in truthy:
        return 'yes'
    elif value in falsey:
        return 'no'


def merge_two_dicts(x, y):
    """ Merge any two dicts passed to the function
        This does not do a deep copy, just a shallow
        copy. However, it does create a new object,
        so there's that.
    """
    z = x.copy()
    z.update(y)
    return z


def transform_name(partition='', name='', sub_path=''):
    if partition != '':
        if name.startswith(partition + '/'):
            name = name.replace(partition + '/', '')
        if name.startswith('/' + partition + '/'):
            name = name.replace('/' + partition + '/', '')

    if name:
        name = name.replace('/', '~')
        name = name.replace('%', '%25')

    if partition:
        partition = partition.replace('/', '~')
        if not partition.startswith('~'):
            partition = '~' + partition
    else:
        if sub_path:
            raise F5ModuleError(
                'When giving the subPath component include partition as well.'
            )

    if sub_path and partition:
        sub_path = '~' + sub_path

    if name and partition:
        name = '~' + name

    result = partition + sub_path + name
    return result


class AnsibleF5Parameters:
    def __init__(self, *args, **kwargs):
        self._values = defaultdict(lambda: None)
        self._values['__warnings'] = []
        self.client = kwargs.pop('client', None)
        self._module = kwargs.pop('module', None)
        self._params = {}

        params = kwargs.pop('params', None)
        if params:
            self.update(params=params)
            self._params.update(params)

    def update(self, params=None):
        if params:
            self._params.update(params)
            for k, v in iteritems(params):
                # Adding this here because ``username`` is a connection parameter
                # and in cases where it is also an API parameter, we run the risk
                # of overriding the specified parameter with the connection parameter.
                #
                # Since this is a problem, and since "username" is never a valid
                # parameter outside its usage in connection params (where we do not
                # use the ApiParameter or ModuleParameters classes) it is safe to
                # skip over it if it is provided.
                if k == 'password':
                    continue
                if self.api_map is not None and k in self.api_map:
                    map_key = self.api_map[k]
                else:
                    map_key = k

                # Handle weird API parameters like `dns.proxy.__iter__` by
                # using a map provided by the module developer
                class_attr = getattr(type(self), map_key, None)
                if isinstance(class_attr, property):
                    # There is a mapped value for the api_map key
                    if class_attr.fset is None:
                        # If the mapped value does not have
                        # an associated setter
                        self._values[map_key] = v
                    else:
                        # The mapped value has a setter
                        setattr(self, map_key, v)
                else:
                    # If the mapped value is not a @property
                    self._values[map_key] = v

    def api_params(self):
        result = {}
        for api_attribute in self.api_attributes:
            if self.api_map is not None and api_attribute in self.api_map:
                result[api_attribute] = getattr(self, self.api_map[api_attribute])
            else:
                result[api_attribute] = getattr(self, api_attribute)
        result = self._filter_params(result)
        return result

    def __getattr__(self, item):
        # Ensures that properties that weren't defined, and therefore stashed
        # in the `_values` dict, will be retrievable.
        return self._values[item]

    @property
    def partition(self):
        if self._values['partition'] is None:
            return 'Common'
        return self._values['partition'].strip('/')

    @partition.setter
    def partition(self, value):
        self._values['partition'] = value

    def _filter_params(self, params):
        return dict((k, v) for k, v in iteritems(params) if v is not None)


class ImishConfig(NetworkConfig):
    def add(self, lines, parents=None, duplicates=False):
        ancestors = list()

        # global config command
        if not parents:
            for line in lines:
                # handle ignore lines
                if ignore_line(line):
                    continue

                item = ConfigLine(line)
                item.raw = line
                if item not in self.items:
                    self.items.append(item)

        else:
            for index, p in enumerate(parents):
                try:
                    i = index + 1
                    obj = self.get_block(parents[:i])[0]
                    ancestors.append(obj)

                except ValueError:
                    # add parent to config
                    offset = index * self._indent
                    obj = ConfigLine(p)
                    obj.raw = p.rjust(len(p) + offset)
                    if ancestors:
                        obj._parents = list(ancestors)
                        ancestors[-1]._children.append(obj)
                    self.items.append(obj)
                    ancestors.append(obj)

            # add child objects
            for line in lines:
                # handle ignore lines
                if ignore_line(line):
                    continue

                # check if child already exists
                for child in ancestors[-1]._children:
                    if child.text == line and not duplicates:
                        break
                else:
                    offset = len(parents) * self._indent
                    item = ConfigLine(line)
                    item.raw = line.rjust(len(line) + offset)
                    item._parents = ancestors
                    ancestors[-1]._children.append(item)
                    self.items.append(item)


class F5ModuleError(Exception):
    pass


class F5ATCError(F5ModuleError):
    """Detailed error for ATC declarative operations."""
    def __init__(self, errors):
        results = list()
        for error in errors:
            if error.tenant:
                err = f"The operation for {error.tenant} has returned code: {error.code} with the following " \
                      f"message: {error.status}"
            elif error.err:
                err_string = '\n'.join(e for e in error.err)
                err = f"The operation has returned code: {error.code} with the following errors: {err_string}"

            else:
                err = f"The operation has returned code: {error.code} with the following message: {error.status}"
            results.append(err)

        self.msg = '\n'.join(response for response in results)
        self.errors = errors
        super().__init__(self.msg)
