//! OAuth 授权码流程 HTTP handler 聚合模块。
// 三个端点分别负责发起授权、读取授权确认页数据、提交授权决策。
pub(crate) mod consent;
pub(crate) mod decision;
pub(crate) mod jar;
pub(crate) mod par;
pub(crate) mod request;

pub(crate) const BASELINE_ACR_VALUE: &str = "1";

pub(crate) use jar::{apply_request_object, unverified_signed_request_object_client_id};
pub(crate) use par::is_pushed_authorization_request_uri;
pub(crate) use request::{
    AuthorizationResponseRedirect, PushedAuthorizationRequestConsumeError,
    authorization_response_redirect, consume_pushed_authorization_request,
};
