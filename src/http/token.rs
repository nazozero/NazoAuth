//! OAuth/OIDC token 相关 HTTP handler 聚合模块。
// 子模块按 grant type 或端点职责拆分，路由层通过本模块 re-export。
mod authorization_code;
mod client_auth;
mod client_credentials;
mod dispatch;
mod forms;
mod introspect;
mod issue;
mod refresh;
mod revoke;
mod userinfo;

pub(crate) use authorization_code::*;
pub(crate) use client_auth::*;
pub(crate) use client_credentials::*;
pub(crate) use dispatch::*;
pub(crate) use forms::*;
pub(crate) use introspect::*;
pub(crate) use issue::*;
pub(crate) use refresh::*;
pub(crate) use revoke::*;
pub(crate) use userinfo::*;
