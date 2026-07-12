//! 领域类型聚合模块。
// 每个子模块只描述一种领域概念，本模块只负责向 crate 内部 re-export。
mod oauth;
mod rows;
mod state;
mod status;

pub(crate) use nazo_key_management::KeySnapshot as Keyset;
pub(crate) use oauth::*;
pub(crate) use rows::*;
pub(crate) use state::*;
pub(crate) use status::*;
