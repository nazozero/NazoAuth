//! 当前用户 HTTP handler 聚合模块。
// 子模块按 /auth/me 下的资源职责拆分，路由层通过显式模块路径调用。
pub mod access_requests;
pub mod avatar;
pub mod delivery;
pub mod federation_links;
pub mod mtls_trust;

pub mod multipart;
