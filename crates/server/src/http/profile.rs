//! 当前用户 HTTP handler 聚合模块。
// 子模块按 /auth/me 下的资源职责拆分，路由层通过显式模块路径调用。
pub(crate) mod access_requests;
#[cfg(test)]
pub(crate) mod account;
#[cfg(test)]
pub(crate) mod applications;
pub(crate) mod avatar;
pub(crate) mod delivery;
pub(crate) mod federation_links;
pub(crate) mod passkeys;
pub(crate) mod session_management;
