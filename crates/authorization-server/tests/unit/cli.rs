use super::*;

fn parse(args: &[&str]) -> anyhow::Result<Command> {
    Command::parse(args.iter().map(|value| (*value).to_owned()))
}

#[test]
fn requires_an_explicit_command() {
    assert_eq!(parse(&["nazoauth"]).unwrap_err().to_string(), USAGE);
}

#[test]
fn parses_all_product_commands() {
    assert_eq!(parse(&["nazoauth", "server"]).unwrap(), Command::Server);
    assert_eq!(parse(&["nazoauth", "migrate"]).unwrap(), Command::Migrate);
    assert_eq!(
        parse(&["nazoauth", "keyctl", "validate"]).unwrap(),
        Command::Keyctl(vec!["validate".to_owned()])
    );
}

#[test]
fn help_is_available_without_starting_a_runtime() {
    assert_eq!(parse(&["nazoauth", "--help"]).unwrap(), Command::Help);
}

#[test]
fn server_and_migrate_reject_accidental_arguments() {
    assert_eq!(
        parse(&["nazoauth", "server", "--detach"])
            .unwrap_err()
            .to_string(),
        "server does not accept argument --detach"
    );
    assert_eq!(
        parse(&["nazoauth", "migrate", "now"])
            .unwrap_err()
            .to_string(),
        "migrate does not accept argument now"
    );
}

#[test]
fn unknown_command_reports_usage() {
    assert_eq!(
        parse(&["nazoauth", "serve"]).unwrap_err().to_string(),
        format!("unknown command serve\n{USAGE}")
    );
}
