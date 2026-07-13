//! 管理端 OAuth 客户端 handler 聚合模块。
// 列表、创建、详情和更新分别位于独立文件，便于按端点维护。
pub(crate) mod create;
pub(crate) mod detail;
pub(crate) mod list;
pub(crate) mod update;

pub(crate) use create::{
    CreateClientRequest, insert_client_error_response, prepare_client_insert_with_secret_pepper,
};
