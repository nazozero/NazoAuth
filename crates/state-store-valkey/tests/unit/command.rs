use super::COMPARE_DELETE_SCRIPT;

#[test]
fn compare_delete_checks_the_opaque_value_before_deleting() {
    let get = COMPARE_DELETE_SCRIPT.find("redis.call('GET'").unwrap();
    let compare = COMPARE_DELETE_SCRIPT.find("current ~= ARGV[1]").unwrap();
    let delete = COMPARE_DELETE_SCRIPT.find("redis.call('DEL'").unwrap();

    assert!(get < compare && compare < delete);
    assert!(COMPARE_DELETE_SCRIPT.contains("return 'changed'"));
    assert!(COMPARE_DELETE_SCRIPT.contains("return 'deleted'"));
}
