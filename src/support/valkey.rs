//! Valkey 缓存命令封装。
// 这里保留最小 Redis 协议操作，业务 key 仍由调用方决定。

use super::prelude::*;
use fred::prelude::LuaInterface;

pub(crate) async fn valkey_set_ex(
    valkey: &ValkeyClient,
    key: impl Into<String>,
    value: impl Into<String>,
    ttl_seconds: u64,
) -> Result<(), ValkeyError> {
    valkey
        .set::<(), _, _>(
            key.into(),
            value.into(),
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            None,
            false,
        )
        .await
}

pub(crate) async fn valkey_set_ex_nx(
    valkey: &ValkeyClient,
    key: impl Into<String>,
    value: impl Into<String>,
    ttl_seconds: u64,
) -> Result<bool, ValkeyError> {
    let response = valkey
        .set::<Option<String>, _, _>(
            key.into(),
            value.into(),
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await?;
    Ok(response.is_some())
}

pub(crate) async fn valkey_get(
    valkey: &ValkeyClient,
    key: impl Into<String>,
) -> Result<Option<String>, ValkeyError> {
    valkey.get::<Option<String>, _>(key.into()).await
}

pub(crate) async fn valkey_getdel(
    valkey: &ValkeyClient,
    key: impl Into<String>,
) -> Result<Option<String>, ValkeyError> {
    valkey.getdel::<Option<String>, _>(key.into()).await
}

pub(crate) async fn valkey_del(
    valkey: &ValkeyClient,
    key: impl Into<String>,
) -> Result<i64, ValkeyError> {
    valkey.del::<i64, _>(key.into()).await
}

pub(crate) async fn valkey_eval_string(
    valkey: &ValkeyClient,
    script: &'static str,
    keys: Vec<String>,
    args: Vec<String>,
) -> Result<String, ValkeyError> {
    valkey.eval::<String, _, _, _>(script, keys, args).await
}
