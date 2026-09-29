# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import ansible_collections.f5networks.f5_bigip.plugins.module_utils.common as comm
from unittest import TestCase
from unittest.mock import MagicMock, patch


class TestFunctions(TestCase):
    def test_process_json_raises(self):
        comm.JINA2_IMPORT_ERROR = ImportError('Something bad happened during j2 import.')
        with self.assertRaises(comm.F5ModuleError) as err:
            comm.process_json('foodata', 'footemplate')

        assert 'jinja2 package must be installed to use this collection' in str(err.exception)
        comm.JINA2_IMPORT_ERROR = None

    def test_fq_name(self):
        res1 = comm.fq_name('Foo', '100',)
        assert res1 == '/Foo/100'

        res2 = comm.fq_name('Foo', '1.1')
        assert res2 == '/Foo/1.1'

        res3 = comm.fq_name('Foo', '100', 'Bar')
        assert res3 == '/Foo/Bar/100'

        res4 = comm.fq_name('Foo', '/Baz/Resource', 'Bar')
        assert res4 == '/Baz/Bar/Resource'

        res5 = comm.fq_name('Foo', 'Resource', 'Bar')
        assert res5 == '/Foo/Bar/Resource'

        res6 = comm.fq_name('Foo', None)
        assert res6 is None

    def test_to_commands(self):
        fake_module = MagicMock()
        result = comm.to_commands(fake_module, ['command1', 'command2'])
        assert result == [
            {'command': 'command1', 'prompt': None, 'answer': None},
            {'command': 'command2', 'prompt': None, 'answer': None}
        ]

    @patch('ansible_collections.f5networks.f5_bigip.plugins.module_utils.common.exec_command', new_callable=MagicMock())
    def test_run_commands(self, patched):
        fake_module = MagicMock()
        command = ['command1']
        patched.side_effect = [(0, b'some command response', None), (1, None, b'bad command')]
        result = comm.run_commands(fake_module, command)

        with self.assertRaises(comm.F5ModuleError) as err:
            comm.run_commands(fake_module, command)

        assert result == ['some command response']
        assert 'bad command' in str(err.exception)

    def test_flatten_boolean(self):
        true = 'enabled'
        false = 'disabled'

        res1 = comm.flatten_boolean(true)
        res2 = comm.flatten_boolean(false)
        res3 = comm.flatten_boolean(None)

        assert res1 == 'yes'
        assert res2 == 'no'
        assert res3 is None

    def test_merge_two_dics(self):
        first = dict(foo=1, bar=2)
        second = dict(baz=3)
        result = comm.merge_two_dicts(first, second)

        assert result == {'foo': 1, 'bar': 2, 'baz': 3}

    def test_transform_name(self):
        res1 = comm.transform_name('/this%isaname')
        res2 = comm.transform_name('Common', 'Common/Foo')
        res3 = comm.transform_name('Common', '/Common/Foo')
        res4 = comm.transform_name('Common', 'Common/Foo', 'Baz')

        with self.assertRaises(comm.F5ModuleError) as err:
            comm.transform_name(name='/Common/foo', sub_path='Baz')

        assert res1 == '~this%isaname'
        assert res2 == '~Common~Foo'
        assert res3 == '~Common~Foo'
        assert res4 == '~Common~Baz~Foo'
        assert 'When giving the subPath component include partition as well.' in str(err.exception)


class TestAnsibleF5ParametersInit(TestCase):
    """Test AnsibleF5Parameters initialization"""

    def test_init_with_no_params(self):
        """Test initialization with no parameters"""
        params = comm.AnsibleF5Parameters()
        assert params._values is not None
        assert params._values['__warnings'] == []
        assert params.client is None
        assert params._module is None

    def test_init_with_params(self):
        """Test initialization with parameters"""
        test_params = {'name': 'test_resource', 'description': 'test desc'}
        params = comm.AnsibleF5Parameters(params=test_params)
        assert params._params == test_params
        assert params._values['name'] == 'test_resource'
        assert params._values['description'] == 'test desc'

    def test_init_with_client_and_module(self):
        """Test initialization with client and module kwargs"""
        mock_client = MagicMock()
        mock_module = MagicMock()
        params = comm.AnsibleF5Parameters(client=mock_client, module=mock_module)
        assert params.client is mock_client
        assert params._module is mock_module

    def test_init_skips_password_parameter(self):
        """Test that password parameter is skipped during update"""
        test_params = {'name': 'test', 'password': 'secret123'}
        params = comm.AnsibleF5Parameters(params=test_params)
        assert params._values['name'] == 'test'
        assert 'password' not in params._values or params._values['password'] is None


class TestAnsibleF5ParametersUpdate(TestCase):
    """Test AnsibleF5Parameters update method"""

    def test_update_simple_values(self):
        """Test update with simple parameter values"""
        params = comm.AnsibleF5Parameters()
        params.update(params={'name': 'foo', 'state': 'present'})
        assert params._values['name'] == 'foo'
        assert params._values['state'] == 'present'

    def test_update_with_none_values(self):
        """Test update with None values"""
        params = comm.AnsibleF5Parameters()
        params.update(params={'name': None, 'description': 'test'})
        assert params._values['name'] is None
        assert params._values['description'] == 'test'

    def test_update_multiple_times(self):
        """Test multiple sequential updates"""
        params = comm.AnsibleF5Parameters()
        params.update(params={'name': 'foo'})
        assert params._values['name'] == 'foo'
        params.update(params={'name': 'bar', 'state': 'absent'})
        assert params._values['name'] == 'bar'
        assert params._values['state'] == 'absent'

    def test_update_with_api_map(self):
        """Test update using api_map for parameter transformation"""

        class TestParameters(comm.AnsibleF5Parameters):
            api_map = {'full_name': 'name', 'current_state': 'state'}
            api_attributes = ['name', 'state']

        params = TestParameters()
        params.update(params={'full_name': 'test_resource', 'current_state': 'present'})
        assert params._values['name'] == 'test_resource'
        assert params._values['state'] == 'present'

    def test_update_skips_password(self):
        """Test that update skips password parameter"""
        params = comm.AnsibleF5Parameters()
        params.update(params={'name': 'test', 'password': 'should_not_set'})
        assert params._values['name'] == 'test'
        assert 'password' not in params._values or params._values['password'] is None


class TestAnsibleF5ParametersProperties(TestCase):
    """Test AnsibleF5Parameters property handling"""

    def test_partition_default_value(self):
        """Test partition property returns Common by default"""
        params = comm.AnsibleF5Parameters()
        assert params.partition == 'Common'

    def test_partition_setter_and_getter(self):
        """Test partition setter and getter"""
        params = comm.AnsibleF5Parameters()
        params.partition = 'MyPartition'
        assert params.partition == 'MyPartition'

    def test_partition_strips_leading_slash(self):
        """Test partition strips leading slash"""
        params = comm.AnsibleF5Parameters()
        params.partition = '/MyPartition'
        assert params.partition == 'MyPartition'

    def test_partition_with_explicit_value(self):
        """Test partition with value set in init"""
        params = comm.AnsibleF5Parameters(params={'partition': 'TestPart'})
        assert params.partition == 'TestPart'

    def test_getattr_returns_values_dict(self):
        """Test __getattr__ retrieves values from _values dict"""
        params = comm.AnsibleF5Parameters(params={'custom_attr': 'custom_value'})
        assert params.custom_attr == 'custom_value'

    def test_getattr_returns_none_for_missing_key(self):
        """Test __getattr__ returns None for missing keys"""
        params = comm.AnsibleF5Parameters()
        assert params.nonexistent_key is None


class TestAnsibleF5ParametersApiParams(TestCase):
    """Test AnsibleF5Parameters api_params method"""

    def test_api_params_filters_none_values(self):
        """Test api_params filters out None values"""

        class TestParameters(comm.AnsibleF5Parameters):
            api_attributes = ['name', 'description', 'state']
            api_map = None

        params = TestParameters(params={'name': 'test', 'description': None, 'state': 'present'})
        result = params.api_params()
        assert result == {'name': 'test', 'state': 'present'}
        assert 'description' not in result

    def test_api_params_with_api_map(self):
        """Test api_params with api_map transformation"""

        class TestParameters(comm.AnsibleF5Parameters):
            api_attributes = ['full_name', 'current_state']
            api_map = {'full_name': 'name', 'current_state': 'state'}

        params = TestParameters(params={'name': 'resource', 'state': 'present'})
        result = params.api_params()
        assert 'full_name' in result or 'name' in result

    def test_api_params_with_no_api_map(self):
        """Test api_params without api_map"""

        class TestParameters(comm.AnsibleF5Parameters):
            api_attributes = ['name', 'state']
            api_map = None

        params = TestParameters(params={'name': 'test', 'state': 'present'})
        result = params.api_params()
        assert result == {'name': 'test', 'state': 'present'}

    def test_api_params_empty_attributes(self):
        """Test api_params with no api_attributes"""

        class TestParameters(comm.AnsibleF5Parameters):
            api_attributes = []
            api_map = None

        params = TestParameters(params={'name': 'test'})
        result = params.api_params()
        assert result == {}


class TestFilterParams(TestCase):
    """Test _filter_params method"""

    def test_filter_params_removes_none_values(self):
        """Test _filter_params removes None values"""
        params = comm.AnsibleF5Parameters()
        input_dict = {'name': 'test', 'description': None, 'state': 'present'}
        result = params._filter_params(input_dict)
        assert result == {'name': 'test', 'state': 'present'}

    def test_filter_params_preserves_false_values(self):
        """Test _filter_params preserves False values"""
        params = comm.AnsibleF5Parameters()
        input_dict = {'enabled': False, 'name': 'test', 'description': None}
        result = params._filter_params(input_dict)
        assert result == {'enabled': False, 'name': 'test'}

    def test_filter_params_preserves_empty_strings(self):
        """Test _filter_params preserves empty strings"""
        params = comm.AnsibleF5Parameters()
        input_dict = {'description': '', 'name': 'test', 'value': None}
        result = params._filter_params(input_dict)
        assert result == {'description': '', 'name': 'test'}

    def test_filter_params_preserves_zero(self):
        """Test _filter_params preserves 0 values"""
        params = comm.AnsibleF5Parameters()
        input_dict = {'timeout': 0, 'name': 'test', 'count': None}
        result = params._filter_params(input_dict)
        assert result == {'timeout': 0, 'name': 'test'}


class TestCheckForAtcErrors(TestCase):
    """Test check_for_atc_errors function"""

    def test_check_for_atc_errors_empty_results(self):
        """Test with empty results"""
        task = {'results': []}
        result = comm.check_for_atc_errors(task)
        assert result == []

    def test_check_for_atc_errors_no_results_key(self):
        """Test with no results key"""
        task = {}
        result = comm.check_for_atc_errors(task)
        assert result == []

    def test_check_for_atc_errors_successful_responses(self):
        """Test with successful responses (code 200)"""
        task = {
            'results': [
                {'code': 200, 'message': 'success'},
                {'code': 200, 'message': 'in progress'}
            ]
        }
        result = comm.check_for_atc_errors(task)
        assert result == []

    def test_check_for_atc_errors_with_error_codes(self):
        """Test with various error codes"""
        task = {
            'results': [
                {'code': 400, 'message': 'Bad Request', 'tenant': 'tenant1', 'errors': None},
                {'code': 500, 'message': 'Internal Error', 'tenant': None, 'errors': ['error1', 'error2']},
                {'code': 403, 'message': 'Forbidden', 'tenant': 'tenant2', 'errors': None}
            ]
        }
        result = comm.check_for_atc_errors(task)
        assert len(result) == 3
        assert result[0].code == 400
        assert result[1].code == 500
        assert result[2].code == 403

    def test_check_for_atc_errors_in_progress_ignored(self):
        """Test that 'in progress' messages are ignored"""
        task = {
            'results': [
                {'code': 202, 'message': 'in progress'},
                {'code': 400, 'message': 'Bad Request', 'tenant': None, 'errors': None}
            ]
        }
        result = comm.check_for_atc_errors(task)
        assert len(result) == 1
        assert result[0].code == 400

    def test_check_for_atc_errors_with_response_field(self):
        """Test error with response field used as status"""
        task = {
            'results': [
                {'code': 500, 'message': 'Processing', 'response': 'Server Error', 'tenant': None, 'errors': None}
            ]
        }
        result = comm.check_for_atc_errors(task)
        assert len(result) == 1
        assert result[0].code == 500


class TestImishConfigAdd(TestCase):
    """Test ImishConfig.add method"""

    def test_add_global_config_single_line(self):
        """Test adding single global config line"""
        config = comm.ImishConfig()
        config.add(['interface eth0'])
        assert len(config.items) == 1
        assert config.items[0].text == 'interface eth0'

    def test_add_global_config_multiple_lines(self):
        """Test adding multiple global config lines"""
        config = comm.ImishConfig()
        config.add(['interface eth0', 'ip address 192.168.1.1 255.255.255.0'])
        assert len(config.items) == 2

    def test_add_global_config_no_duplicates(self):
        """Test that duplicate lines are not added by default"""
        config = comm.ImishConfig()
        config.add(['interface eth0'])
        config.add(['interface eth0'])
        assert len(config.items) == 1

    def test_add_global_config_with_duplicates_flag(self):
        """Test duplicates flag behavior with child configs"""
        config = comm.ImishConfig()
        # Add a parent config
        config.add(['interface eth0'])
        # Add child without duplicates (default)
        config.add(['ip address 192.168.1.1'], parents=['interface eth0'])
        # Try adding same child again without duplicates flag
        config.add(['ip address 192.168.1.1'], parents=['interface eth0'])
        # Should not add duplicate child
        child_count = sum(1 for item in config.items if item.text == 'ip address 192.168.1.1')
        assert child_count == 1

    def test_add_child_config_to_parent(self):
        """Test adding child config under parent"""
        config = comm.ImishConfig()
        config.add(['ip address 192.168.1.1 255.255.255.0'], parents=['interface eth0'])
        assert len(config.items) >= 2

    def test_add_nested_child_config(self):
        """Test adding nested child config"""
        config = comm.ImishConfig()
        parents = ['interface eth0', 'description test']
        config.add(['ip address 192.168.1.1'], parents=parents)
        assert len(config.items) >= 3

    def test_add_child_to_existing_parent(self):
        """Test adding child to already-existing parent"""
        config = comm.ImishConfig()
        config.add(['interface eth0'])
        config.add(['description test'], parents=['interface eth0'])
        assert any(item.text == 'description test' for item in config.items)

    def test_add_ignores_empty_lines(self):
        """Test that empty lines are ignored"""
        config = comm.ImishConfig()
        config.add(['', 'interface eth0', '!'])
        # Empty lines and comments should be ignored or handled gracefully
        assert any(item.text == 'interface eth0' for item in config.items)


class TestF5ModuleError(TestCase):
    """Test F5ModuleError exception"""

    def test_f5_module_error_instantiation(self):
        """Test F5ModuleError can be instantiated"""
        error = comm.F5ModuleError('Test error message')
        assert str(error) == 'Test error message'

    def test_f5_module_error_is_exception(self):
        """Test F5ModuleError is an Exception"""
        error = comm.F5ModuleError('Test error')
        assert isinstance(error, Exception)

    def test_f5_module_error_with_empty_message(self):
        """Test F5ModuleError with empty message"""
        error = comm.F5ModuleError('')
        assert str(error) == ''

    def test_f5_module_error_raise_and_catch(self):
        """Test raising and catching F5ModuleError"""
        with self.assertRaises(comm.F5ModuleError) as context:
            raise comm.F5ModuleError('Custom error')
        assert 'Custom error' in str(context.exception)


class TestF5ATCError(TestCase):
    """Test F5ATCError exception"""

    def test_f5_atc_error_with_tenant(self):
        """Test F5ATCError with tenant information"""
        from collections import namedtuple
        AtcError = namedtuple('AtcError', ['code', 'status', 'tenant', 'err'])
        error = AtcError(code=400, status='Bad Request', tenant='tenant1', err=None)
        exc = comm.F5ATCError([error])
        assert 'tenant1' in exc.msg
        assert '400' in exc.msg

    def test_f5_atc_error_with_errors_field(self):
        """Test F5ATCError with errors field"""
        from collections import namedtuple
        AtcError = namedtuple('AtcError', ['code', 'status', 'tenant', 'err'])
        error = AtcError(code=500, status='Server Error', tenant=None, err=['error1', 'error2'])
        exc = comm.F5ATCError([error])
        assert 'error1' in exc.msg
        assert 'error2' in exc.msg
        assert '500' in exc.msg

    def test_f5_atc_error_without_tenant_or_errors(self):
        """Test F5ATCError without tenant or errors"""
        from collections import namedtuple
        AtcError = namedtuple('AtcError', ['code', 'status', 'tenant', 'err'])
        error = AtcError(code=403, status='Forbidden', tenant=None, err=None)
        exc = comm.F5ATCError([error])
        assert 'Forbidden' in exc.msg
        assert '403' in exc.msg

    def test_f5_atc_error_multiple_errors(self):
        """Test F5ATCError with multiple errors"""
        from collections import namedtuple
        AtcError = namedtuple('AtcError', ['code', 'status', 'tenant', 'err'])
        errors = [
            AtcError(code=400, status='Bad Request', tenant='tenant1', err=None),
            AtcError(code=500, status='Server Error', tenant='tenant2', err=None)
        ]
        exc = comm.F5ATCError(errors)
        assert 'tenant1' in exc.msg
        assert 'tenant2' in exc.msg
        assert len(exc.errors) == 2

    def test_f5_atc_error_is_f5_module_error(self):
        """Test F5ATCError is a F5ModuleError"""
        from collections import namedtuple
        AtcError = namedtuple('AtcError', ['code', 'status', 'tenant', 'err'])
        error = AtcError(code=400, status='Bad Request', tenant=None, err=None)
        exc = comm.F5ATCError([error])
        assert isinstance(exc, comm.F5ModuleError)
