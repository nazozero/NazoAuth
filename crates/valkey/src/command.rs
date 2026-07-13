use fred::prelude::{Expiration, KeysInterface, SetOptions};

use crate::{Error, ValkeyConnection};

pub(crate) async fn set_ex_nx(
    connection: &ValkeyConnection,
    key: String,
    value: &'static str,
    ttl_seconds: u64,
) -> Result<bool, Error> {
    let reply = connection
        .client
        .set::<Option<String>, _, _>(
            key,
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
            key,
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
        .getdel(key)
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
            key,
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
    connection.client.get(key).await.map_err(Error::from_fred)
}

pub(crate) async fn get_many(
    connection: &ValkeyConnection,
    keys: Vec<String>,
) -> Result<Vec<Option<String>>, Error> {
    connection.client.mget(keys).await.map_err(Error::from_fred)
}

pub(crate) async fn delete(connection: &ValkeyConnection, key: String) -> Result<i64, Error> {
    connection.client.del(key).await.map_err(Error::from_fred)
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
        .eval(script, keys, args)
        .await
        .map_err(Error::from_fred)
}
