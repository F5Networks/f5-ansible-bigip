# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from unittest import TestCase

from ansible_collections.f5networks.f5_bigip.plugins.module_utils.compare import (
    cmp_simple_list, cmp_str_with_none, compare_dictionary, compare_complex_list,
    nested_diff, recursive_sort, compare_key_values
)


class TestCompareFunctions(TestCase):
    def test_cmp_simple_list(self):
        res1 = cmp_simple_list(None, ['something'])
        res2 = cmp_simple_list('none', None)
        res3 = cmp_simple_list('', ['something'])
        res4 = cmp_simple_list(['want'], None)
        res5 = cmp_simple_list(['want'], ['have'])
        res6 = cmp_simple_list(['want'], ['want'])

        assert res1 is None and res2 is None and res6 is None
        assert res3 == []
        assert res4 == res5 == ['want']

    def test_cmp_str_with_none(self):
        res1 = cmp_str_with_none(None, 'something')
        res2 = cmp_str_with_none('', None)
        res3 = cmp_str_with_none('want', 'have')

        assert res1 is None and res2 is None
        assert res3 == 'want'

    def test_compare_complex_list(self):
        res1 = compare_complex_list([], None)
        res2 = compare_complex_list(None, ['foo'])
        res3 = compare_complex_list([dict(baz=1, bar=2)], [dict(foo=1)])
        res4 = compare_complex_list([dict(baz=1, bar=2)], [dict(baz=1, bar=2)])

        assert res1 is None and res2 is None and res4 is None
        assert res3 == [dict(baz=1, bar=2)]

    def test_compare_dictionary(self):
        res1 = compare_dictionary({}, None)
        res2 = compare_dictionary(None, dict(foo=1))
        res3 = compare_dictionary(dict(baz=1, bar=2), dict(foo=1))
        res4 = compare_dictionary(dict(baz=1, bar=2), dict(baz=1, bar=2))

        assert res1 is None and res2 is None and res4 is None
        assert res3 == dict(baz=1, bar=2)

    def test_nested_diff(self):
        res1 = nested_diff(dict(foo=1), None, [])
        res2 = nested_diff(None, dict(foo=1), [])
        res3 = nested_diff(dict(foo=dict(baz=1, bar=2)), dict(baz=1), ['bar'])
        res4 = nested_diff(dict(foo=dict(baz=1, bar=2)), dict(foo=dict(baz=2, bar=3)), ['bar'])
        res5 = nested_diff(dict(foo=dict(baz=1, bar=2)), dict(foo=dict(baz=1, bar=3)), ['bar'])

        assert res1 is True and res3 is True and res4 is True
        assert res2 is False and res5 is False


class TestRecursiveSort(TestCase):
    """Test recursive_sort function"""

    def test_recursive_sort_simple_list(self):
        """Test sorting a simple list"""
        result = recursive_sort([3, 1, 2])
        assert result == [3, 1, 2]  # Lists maintain order

    def test_recursive_sort_dict(self):
        """Test sorting dictionary keys"""
        input_dict = {'z': 1, 'a': 2, 'm': 3}
        result = recursive_sort(input_dict)
        assert list(result.keys()) == ['a', 'm', 'z']

    def test_recursive_sort_nested_dict(self):
        """Test sorting nested dictionaries"""
        input_dict = {'z': {'b': 1, 'a': 2}, 'a': {'y': 3, 'x': 4}}
        result = recursive_sort(input_dict)
        assert list(result.keys()) == ['a', 'z']
        assert list(result['a'].keys()) == ['x', 'y']

    def test_recursive_sort_list_of_dicts(self):
        """Test sorting list of dictionaries"""
        input_list = [{'z': 1, 'a': 2}, {'b': 3, 'x': 4}]
        result = recursive_sort(input_list)
        assert list(result[0].keys()) == ['a', 'z']
        assert list(result[1].keys()) == ['b', 'x']

    def test_recursive_sort_empty_dict(self):
        """Test sorting empty dictionary"""
        result = recursive_sort({})
        assert result == {}

    def test_recursive_sort_empty_list(self):
        """Test sorting empty list"""
        result = recursive_sort([])
        assert result == []

    def test_recursive_sort_scalar_values(self):
        """Test recursive_sort with scalar values"""
        assert recursive_sort(42) == 42
        assert recursive_sort('string') == 'string'
        assert recursive_sort(None) is None

    def test_recursive_sort_tuple(self):
        """Test sorting tuples"""
        result = recursive_sort((3, 1, 2))
        assert isinstance(result, tuple)

    def test_recursive_sort_tuple_with_dicts(self):
        """Test recursive_sort with tuple containing dicts"""
        input_tuple = ({'z': 1, 'a': 2}, {'b': 3, 'x': 4})
        result = recursive_sort(input_tuple)
        assert isinstance(result, tuple)
        assert list(result[0].keys()) == ['a', 'z']


class TestCompareKeyValues(TestCase):
    """Test compare_key_values function"""

    def test_compare_key_values_none_want(self):
        """Test with None want parameter"""
        result = compare_key_values(None, {'a': 1})
        assert result is None

    def test_compare_key_values_none_have(self):
        """Test with None have parameter"""
        result = compare_key_values({'a': 1}, None)
        assert result == {'a': 1}

    def test_compare_key_values_identical(self):
        """Test with identical dictionaries"""
        want = {'a': 1, 'b': 2, 'c': 3}
        have = {'a': 1, 'b': 2, 'c': 3}
        result = compare_key_values(want, have)
        assert result is None

    def test_compare_key_values_different_values(self):
        """Test with different values for same keys"""
        want = {'a': 1, 'b': 2, 'c': 3}
        have = {'a': 10, 'b': 2, 'c': 3}
        result = compare_key_values(want, have)
        assert result == want

    def test_compare_key_values_have_extra_keys(self):
        """Test when have has extra keys not in want"""
        want = {'a': 1, 'b': 2}
        have = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
        result = compare_key_values(want, have)
        assert result is None

    def test_compare_key_values_empty_want(self):
        """Test with empty want dictionary"""
        result = compare_key_values({}, {'a': 1})
        assert result is None

    def test_compare_key_values_empty_have(self):
        """Test with empty have dictionary"""
        want = {'a': 1}
        result = compare_key_values(want, {})
        assert result is None

    def test_compare_key_values_nested_values(self):
        """Test with nested dictionary values"""
        want = {'a': {'x': 1, 'y': 2}, 'b': 2}
        have = {'a': {'x': 1, 'y': 2}, 'b': 2}
        result = compare_key_values(want, have)
        assert result is None

    def test_compare_key_values_nested_values_different(self):
        """Test with different nested dictionary values"""
        want = {'a': {'x': 1, 'y': 2}, 'b': 2}
        have = {'a': {'x': 1, 'y': 3}, 'b': 2}
        result = compare_key_values(want, have)
        assert result == want


class TestCmpSimpleListEdgeCases(TestCase):
    """Test edge cases for cmp_simple_list"""

    def test_cmp_simple_list_empty_want(self):
        """Test with empty want list"""
        result = cmp_simple_list([], ['something'])
        assert result is None or result == []

    def test_cmp_simple_list_empty_have(self):
        """Test with empty have list"""
        result = cmp_simple_list(['something'], [])
        assert result == ['something']

    def test_cmp_simple_list_order_matters(self):
        """Test with cmp_order=True for order-sensitive comparison"""
        result = cmp_simple_list(['a', 'b', 'c'], ['c', 'b', 'a'], cmp_order=True)
        assert result == ['a', 'b', 'c']


class TestCompareDictionaryEdgeCases(TestCase):
    """Test edge cases for compare_dictionary"""

    def test_compare_dictionary_both_empty(self):
        """Test with both empty dictionaries"""
        result = compare_dictionary({}, {})
        assert result is None

    def test_compare_dictionary_single_key_difference(self):
        """Test with single key value difference"""
        want = {'key': 'value1'}
        have = {'key': 'value2'}
        result = compare_dictionary(want, have)
        assert result == want


class TestCompareComplexListEdgeCases(TestCase):
    """Test edge cases for compare_complex_list"""

    def test_compare_complex_list_both_empty(self):
        """Test with both empty lists"""
        result = compare_complex_list([], [])
        assert result is None

    def test_compare_complex_list_nested_dicts(self):
        """Test with nested dictionary items"""
        want = [{'a': {'b': 1}}]
        have = [{'a': {'b': 1}}]
        result = compare_complex_list(want, have)
        assert result is None

    def test_compare_complex_list_multiple_items(self):
        """Test with multiple items in list"""
        want = [{'a': 1}, {'b': 2}, {'c': 3}]
        have = [{'c': 3}, {'a': 1}, {'b': 2}]
        result = compare_complex_list(want, have)
        assert result is None
