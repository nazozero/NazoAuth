use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceIndicatorError {
    Invalid,
    Duplicate,
}

pub fn parse_resource_indicators(values: &[String]) -> Result<Vec<String>, ResourceIndicatorError> {
    let mut seen = HashSet::new();
    let mut resources = Vec::with_capacity(values.len());
    for value in values {
        let parsed = url::Url::parse(value).map_err(|_| ResourceIndicatorError::Invalid)?;
        if parsed.fragment().is_some() {
            return Err(ResourceIndicatorError::Invalid);
        }
        if !seen.insert(value.clone()) {
            return Err(ResourceIndicatorError::Duplicate);
        }
        resources.push(value.clone());
    }
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_indicators_require_absolute_unique_fragmentless_uris() {
        assert_eq!(
            parse_resource_indicators(&["https://api.example".to_owned()]).unwrap(),
            ["https://api.example"]
        );
        assert_eq!(
            parse_resource_indicators(&["relative".to_owned()]),
            Err(ResourceIndicatorError::Invalid)
        );
        assert_eq!(
            parse_resource_indicators(&["https://api.example#fragment".to_owned()]),
            Err(ResourceIndicatorError::Invalid)
        );
    }
}
