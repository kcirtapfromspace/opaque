"""Source-discovery guards, including syntax that must not broaden production."""
from pathlib import Path
import tempfile
import unittest

from rust_coverage_scope import ScopeError, runtime_sources


class RuntimeSourceScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def write(self, name, code):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
        return path

    def graph(self, code):
        self.write('crate/src/lib.rs', code)
        return runtime_sources(self.root, ['crate/src/lib.rs'])

    def test_comments_strings_raw_strings_chars_and_macro_definitions_are_not_source_edges(self):
        graph = self.graph('''
// #[path="missing.rs"] mod comment;
/* outer /* nested */ include!("missing.rs"); */
const S: &str = "#[path=\\\"missing.rs\\\"] mod ordinary;";
const R: &str = r###"include!("missing.rs"); #[path="missing.rs"] mod raw;"###;
const B: &[u8] = br##"include!("missing.rs");"##;
const C: char = '{';
macro_rules! unexpanded { () => { mod absent; } }
pub fn value<'a>(v: &'a str) -> &'a str { v }
''')
        self.assertEqual(graph['sources'], {'crate/src/lib.rs'})
        self.assertEqual(graph['required'], {'crate/src/lib.rs'})

    def test_test_only_inline_modules_and_functions_do_not_follow_missing_paths(self):
        graph = self.graph('''
#[cfg(test)] mod tests { #[path="missing.rs"] mod missing; }
#[cfg(all(unix, test))] pub(crate) fn fixture() { include!("missing.rs"); }
#[cfg(test)] #[path="missing.rs"] mod outside;
#[cfg(not(test))] pub fn runtime() {}
''')
        self.assertEqual(graph['sources'], {'crate/src/lib.rs'})
        self.assertEqual(graph['required'], {'crate/src/lib.rs'})

    def test_conditional_native_module_is_in_scope_without_forged_unconditional_mapping(self):
        self.write('shared/native.rs', 'pub fn native() {}')
        graph = self.graph('#[cfg(any(test, target_os="linux"))] #[path="../../shared/native.rs"] mod native;')
        self.assertIn('shared/native.rs', graph['sources'])
        self.assertNotIn('shared/native.rs', graph['required'])

    def test_nested_inline_module_paths_and_path_override_children_match_rustc_rules(self):
        self.write('crate/src/ordinary.rs', '''mod nested {
    #[path="../../../shared/selected.rs"] pub mod selected;
}''')
        self.write('crate/shared/selected.rs', 'pub mod child;')
        self.write('crate/shared/child.rs', 'pub fn value() {}')
        graph = self.graph('mod ordinary;')
        self.assertEqual(graph['sources'], {'crate/src/lib.rs', 'crate/src/ordinary.rs',
                                           'crate/shared/selected.rs', 'crate/shared/child.rs'})
        self.assertEqual(graph['required'], {'crate/shared/child.rs'})

    def test_literal_include_recurses_but_unreferenced_neighbor_does_not_enter_scope(self):
        self.write('shared/first.rs', 'include!(r"second.rs");')
        self.write('shared/second.rs', 'pub fn second() {}')
        self.write('shared/unrelated.rs', 'pub fn should_not_be_in_scope() {}')
        graph = self.graph('include!("../../shared/first.rs",);')
        self.assertEqual(graph['sources'], {'crate/src/lib.rs', 'shared/first.rs', 'shared/second.rs'})
        self.assertEqual(graph['required'], {'shared/second.rs'})

    def test_inner_test_cfg_does_not_turn_fixture_functions_into_runtime_mappings(self):
        self.write('shared/test.rs', '#![cfg(test)] include!("missing.rs"); pub fn fixture() {}')
        graph = self.graph('#[path="../../shared/test.rs"] mod test;')
        self.assertEqual(graph['required'], set())
        self.assertEqual(graph['sources'], {'crate/src/lib.rs'})

    def test_cfg_attr_cannot_disguise_a_test_only_source_as_production(self):
        self.write('shared/test.rs', 'pub fn fixture() {}')
        graph = self.graph('#[cfg_attr(not(test), cfg(any()))] #[path="../../shared/test.rs"] mod test;')
        self.assertEqual(graph['sources'], {'crate/src/lib.rs'})
        self.assertEqual(graph['required'], set())
        self.write('shared/test.rs', '#![cfg_attr(not(test), cfg(any()))] pub fn fixture() {}')
        graph = self.graph('#[path="../../shared/test.rs"] mod test;')
        self.assertEqual(graph['sources'], {'crate/src/lib.rs'})

    def test_array_type_semicolons_do_not_hide_unconditional_function_bodies(self):
        self.write('shared/array.rs', 'pub fn value(input: [u8; 4]) -> [u8; 4] { input }')
        graph = self.graph('#[path="../../shared/array.rs"] mod array;')
        self.assertIn('shared/array.rs', graph['required'])

    def test_dynamic_generated_and_macro_defined_source_inputs_fail_closed(self):
        for code in ('include!(concat!(env!("OUT_DIR"), "/generated.rs"));',
                     'macro_rules! generated { () => { include!("file.rs"); } }',
                     '#[cfg_attr(unix, path="selected.rs")] mod selected;',
                     '#[path="../../target/generated.rs"] mod generated;'):
            self.write('target/generated.rs', 'pub fn generated() {}')
            with self.subTest(code=code), self.assertRaises(ScopeError):
                self.graph(code)

    def test_missing_ambiguous_symlink_and_escaping_paths_fail_closed(self):
        self.write('crate/src/duplicate.rs', '')
        self.write('crate/src/duplicate/mod.rs', '')
        outside = self.write('shared/actual.rs', 'pub fn value() {}')
        (self.root / 'shared/link.rs').symlink_to(outside)
        for code in ('mod absent;', 'mod duplicate;', '#[path="../../shared/link.rs"] mod link;',
                     '#[path="../../../outside.rs"] mod outside;'):
            with self.subTest(code=code), self.assertRaises(ScopeError):
                self.graph(code)

    def test_real_brand_module_is_exactly_owned_and_requires_executable_mapping(self):
        root = Path(__file__).resolve().parents[1]
        graph = runtime_sources(root, ['crates/opaque-web/src/lib.rs'])
        external = {name for name in graph['sources'] if not name.startswith('crates/opaque-web/')}
        self.assertEqual(external, {'assets/brand/embedded.rs'})
        self.assertIn('assets/brand/embedded.rs', graph['required'])
        self.assertFalse(any('/tests/' in name for name in graph['sources']))


if __name__ == '__main__':
    unittest.main()
