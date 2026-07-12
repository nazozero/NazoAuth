//! OAuth 授权码流程 HTTP handler 聚合模块。
// 三个端点分别负责发起授权、读取授权确认页数据、提交授权决策。
mod consent;
mod decision;
mod jar;
mod par;
mod request;

pub(crate) const BASELINE_ACR_VALUE: &str = "1";

pub(crate) use consent::*;
pub(crate) use decision::*;
pub(crate) use jar::*;
pub(crate) use par::*;
pub(crate) use request::*;
