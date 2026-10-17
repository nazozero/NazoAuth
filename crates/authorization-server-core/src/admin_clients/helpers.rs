use super::errors::AdminClientError;

pub(super) fn validate_subject_type(value: &str) -> Result<(), AdminClientError> {
    if matches!(value, "public" | "pairwise") {
        Ok(())
    } else {
        Err(AdminClientError::InvalidRequest(
            "subject_type 必须是 public 或 pairwise".to_owned(),
        ))
    }
}

pub(super) fn trim_optional_string(value: Option<String>) -> Option<String> {
    let mut value = value?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let length = trimmed.len();
    let start = value.len() - value.trim_start().len();
    value.truncate(start + length);
    if start != 0 {
        value.drain(..start);
    }
    Some(value)
}

pub(super) fn trim_string_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| trim_optional_string(Some(value)))
        .collect()
}

pub(super) fn all_same_host(uris: &[String]) -> Option<String> {
    let mut urls = uris
        .iter()
        .filter_map(|uri| url::Url::parse(uri).ok())
        .filter(|url| url.host_str().is_some());
    let first = urls.next()?;
    let host = first.host_str()?;
    urls.all(|url| url.host_str() == Some(host))
        .then(|| host.to_owned())
}

pub(super) fn sector_identifier_host_for_redirects(
    uri: &str,
    redirect_uris: &[String],
    sector_uris: &[String],
) -> Result<String, AdminClientError> {
    for redirect_uri in redirect_uris {
        if !sector_uris.contains(redirect_uri) {
            return Err(AdminClientError::InvalidRequest(format!(
                "redirect_uri {redirect_uri} 不在 sector_identifier_uri 返回列表中"
            )));
        }
    }
    url::Url::parse(uri)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            AdminClientError::InvalidRequest(
                "sector_identifier_uri host 解析失败: InvalidUri".to_owned(),
            )
        })
}
