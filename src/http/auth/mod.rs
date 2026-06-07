//! 登录、注册与 CSRF 相关 HTTP handler 聚合模块。
// 子模块按端点拆分，路由层只依赖本模块 re-export 的 handler 名称。
mod csrf;
mod email_code;
mod login;
mod passkey;
mod register;

pub(crate) use csrf::*;
pub(crate) use email_code::*;
pub(crate) use login::*;
pub(crate) use passkey::*;
pub(crate) use register::*;
