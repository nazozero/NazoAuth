use fred::prelude::{Expiration, KeysInterface, SetOptions};

use crate::{Error, ValkeyConnection};

const COMPARE_DELETE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return 'missing'
end
if current ~= ARGV[1] then
  return 'changed'
end
redis.call('DEL', KEYS[1])
return 'deleted'
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompareDelete {
    Deleted,
    MissingOrChanged,
}

pub(crate) async fn set_ex_nx(
    connection: &ValkeyConnection,
    key: String,
    value: &'static str,
    ttl_seconds: u64,
) -> Result<bool, Error> {
    let reply = connection
        .client
        .set::<Option<String>, _, _>(
            connection.state_key(key),
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await
        .map_err(Error::from_fred)?;
    match reply.as_deref() {
        Some("OK") => Ok(true),
        None => Ok(false),
        Some(other) => Err(Error::unexpected(format!(
            "unexpected SET NX reply {other:?}"
        ))),
    }
}

pub(crate) async fn set_ex_nx_string(
    connection: &ValkeyConnection,
    key: String,
    value: String,
    ttl_seconds: u64,
) -> Result<bool, Error> {
    let reply = connection
        .client
        .set::<Option<String>, _, _>(
            connection.state_key(key),
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await
        .map_err(Error::from_fred)?;
    match reply.as_deref() {
        Some("OK") => Ok(true),
        None => Ok(false),
        Some(other) => Err(Error::unexpected(format!(
            "unexpected SET NX reply {other:?}"
        ))),
    }
}

pub(crate) async fn set_ex(
    connection: &ValkeyConnection,
    key: String,
    value: &'static str,
    ttl_seconds: u64,
) -> Result<(), Error> {
    connection
        .client
        .set::<(), _, _>(
            connection.state_key(key),
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            None,
            false,
        )
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn take(
    connection: &ValkeyConnection,
    key: String,
) -> Result<Option<String>, Error> {
    connection
        .client
        .getdel(connection.state_key(key))
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn set_ex_string(
    connection: &ValkeyConnection,
    key: String,
    value: String,
    ttl_seconds: u64,
) -> Result<(), Error> {
    connection
        .client
        .set::<(), _, _>(
            connection.state_key(key),
            value,
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            None,
            false,
        )
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn get(
    connection: &ValkeyConnection,
    key: String,
) -> Result<Option<String>, Error> {
    connection
        .client
        .get(connection.state_key(key))
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn get_many(
    connection: &ValkeyConnection,
    keys: Vec<String>,
) -> Result<Vec<Option<String>>, Error> {
    connection
        .client
        .mget(connection.state_keys(keys))
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn delete(connection: &ValkeyConnection, key: String) -> Result<i64, Error> {
    connection
        .client
        .del(connection.state_key(key))
        .await
        .map_err(Error::from_fred)
}

pub(crate) async fn compare_delete(
    connection: &ValkeyConnection,
    key: String,
    expected: &str,
) -> Result<CompareDelete, Error> {
    match eval_string(
        connection,
        COMPARE_DELETE_SCRIPT,
        vec![key],
        vec![expected.to_owned()],
    )
    .await?
    .as_str()
    {
        "deleted" => Ok(CompareDelete::Deleted),
        "missing" | "changed" => Ok(CompareDelete::MissingOrChanged),
        reply => Err(Error::unexpected(format!(
            "unexpected compare-delete reply {reply:?}"
        ))),
    }
}

pub(crate) async fn eval_string(
    connection: &ValkeyConnection,
    script: &'static str,
    keys: Vec<String>,
    args: Vec<String>,
) -> Result<String, Error> {
    use fred::prelude::LuaInterface;

    connection
        .client
        .eval(script, connection.state_keys(keys), args)
        .await
        .map_err(Error::from_fred)
}

#[cfg(test)]
#[path = "../tests/unit/command.rs"]
mod tests;
