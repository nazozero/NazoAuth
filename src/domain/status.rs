//! 数据库内访问申请状态码。
// 全链路使用 smallint/int 传输，服务端只在边界处解析为强类型枚举。

/// oauth_access_requests.status 的合法取值。
#[derive(Clone, Copy)]
#[repr(i16)]
pub(crate) enum AccessRequestStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
}

impl AccessRequestStatus {
    /// 返回数据库和 HTTP JSON 中使用的数字状态码。
    pub(crate) const fn code(self) -> i16 {
        self as i16
    }

    /// 将外部输入的数字状态转换为内部枚举。
    pub(crate) const fn from_code(code: i16) -> Option<Self> {
        match code {
            0 => Some(Self::Pending),
            1 => Some(Self::Approved),
            2 => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/domain/tests/status.rs"]
mod tests;
