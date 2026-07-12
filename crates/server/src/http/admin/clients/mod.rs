//! 管理端 OAuth 客户端 handler 聚合模块。
// 列表、创建、详情和更新分别位于独立文件，便于按端点维护。
mod create;
mod detail;
mod list;
mod update;

pub(crate) use create::*;
pub(crate) use detail::*;
pub(crate) use list::*;
pub(crate) use update::*;
