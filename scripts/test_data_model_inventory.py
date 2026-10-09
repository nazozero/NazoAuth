import unittest

from data_model_inventory import rust_models


class ModelInventoryTest(unittest.TestCase):
    def test_named_tuple_unit_enum_and_alias_members(self):
        source = '''
        pub struct Record<'a, T> {
            #[serde(default)]
            pub id: u64,
            values: Vec<Result<T, &'a str>>,
            callback: fn(u8, u8) -> bool,
            bytes: [u8; 32],
        }
        struct Tuple(pub String, [u8; 32]);
        struct Empty;
        enum State { Ready, Pending { id: u64, names: Vec<String> }, Failed(String) }
        type Digest = [u8; 32];
        trait Port { type Error; }
        '''
        rows = {row['id'].split('::')[-1]: row for row in rust_models(source, 'test.rs')}
        self.assertEqual(set(rows), {'Record', 'Tuple', 'Empty', 'State', 'Digest'})
        self.assertEqual([f['name'] for f in rows['Record']['fields']], ['id', 'values', 'callback', 'bytes'])
        self.assertEqual([f['name'] for f in rows['Tuple']['fields']], ['0', '1'])
        self.assertEqual(rows['Empty']['fields'], [])
        self.assertEqual([f['name'] for f in rows['State']['fields']], ['Ready', 'Pending.id', 'Pending.names', 'Failed.0'])
        self.assertEqual(rows['Digest']['fields'], [{'name': 'target', 'type': '[u8; 32]'}])

    def test_private_field_starting_with_pub_is_not_visibility(self):
        rows = rust_models('struct Key { public_key: String, pub(crate) published: bool }', 'test.rs')
        self.assertEqual([f['name'] for f in rows[0]['fields']], ['public_key', 'published'])

    def test_where_fn_bounds_do_not_become_tuple_fields(self):
        rows = rust_models('struct Callback<F> where F: Fn(u8) -> bool { callback: F }', 'test.rs')
        self.assertEqual(rows[0]['fields'], [{'name': 'callback', 'type': 'F'}])

    def test_literals_and_comments_do_not_create_fake_types(self):
        source = '''
        const DOC: &str = r#"struct Fake { secret: String }"#;
        // enum Other { Nope }
        struct Real { id: u64 }
        '''
        self.assertEqual([row['id'] for row in rust_models(source, 'test.rs')], ['test.rs::Real'])

    def test_all_cfg_definitions_are_retained_for_explicit_classification(self):
        rows = rust_models('#[cfg(test)] struct Example { id: u64 }\n#[cfg(feature = "x")] struct Feature(u8);', 'test.rs')
        self.assertEqual(len(rows), 2)

    def test_macros_are_reported_not_silently_treated_as_expanded(self):
        rows = rust_models('macro_rules! identity_id { ($name:ident) => { struct $name(u64); }; }', 'test.rs')
        self.assertEqual(rows[0]['kind'], 'macro-definition')
        self.assertEqual(rows[0]['review'], 'inspect expansions')

    def test_duplicate_local_names_have_distinct_inventory_keys(self):
        rows = rust_models('fn a() { struct Row { id: u64 } } fn b() { struct Row { count: i64 } }', 'test.rs')
        self.assertEqual([row['id'] for row in rows], ['test.rs::Row', 'test.rs::Row#2'])


if __name__ == '__main__':
    unittest.main()
