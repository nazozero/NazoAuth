use http::{HeaderMap, header};

use super::{
    AccessTokenScheme, ResourceServerRequestError, VerifiedAccessToken,
    VerifiedSenderConstraintProof,
};

pub(super) fn http_authorization_headers(
    headers: &HeaderMap,
) -> Result<Vec<&str>, ResourceServerRequestError> {
    headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResourceServerRequestError::InvalidRequest)
        })
        .collect()
}

pub(super) fn http_dpop_headers(
    headers: &HeaderMap,
) -> Result<Vec<&str>, ResourceServerRequestError> {
    headers
        .get_all("dpop")
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResourceServerRequestError::InvalidRequest)
        })
        .collect()
}

pub(super) fn single_dpop_header<'a>(
    values: &'a [&'a str],
) -> Result<&'a str, ResourceServerRequestError> {
    if values.is_empty() {
        return Err(ResourceServerRequestError::MissingSenderConstraint);
    }
    if values.len() != 1 {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    if values[0].trim().is_empty() {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    Ok(values[0])
}

pub(super) fn query_has_access_token(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "access_token")
    })
}

pub(super) fn presented_authorization_token<'a>(
    values: &'a [&'a str],
) -> Result<(AccessTokenScheme, &'a str), ResourceServerRequestError> {
    if values.is_empty() {
        return Err(ResourceServerRequestError::MissingToken);
    }
    if values.len() != 1 {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let mut parts = values[0].split_whitespace();
    let Some(scheme) = parts.next() else {
        return Err(ResourceServerRequestError::MissingToken);
    };
    let Some(token) = parts.next().filter(|token| !token.trim().is_empty()) else {
        return Err(ResourceServerRequestError::MissingToken);
    };
    if parts.next().is_some() {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        AccessTokenScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("dpop") {
        AccessTokenScheme::Dpop
    } else {
        return Err(ResourceServerRequestError::MissingToken);
    };
    Ok((scheme, token))
}

pub(super) fn validate_presented_sender_constraint(
    scheme: AccessTokenScheme,
    verified: &VerifiedAccessToken,
    proof: &VerifiedSenderConstraintProof,
) -> Result<(), ResourceServerRequestError> {
    let Some(cnf) = verified.cnf.as_ref() else {
        return if scheme == AccessTokenScheme::Dpop {
            Err(ResourceServerRequestError::MissingSenderConstraint)
        } else {
            Ok(())
        };
    };
    if let Some(expected) = cnf.jkt.as_ref() {
        if scheme != AccessTokenScheme::Dpop {
            return Err(ResourceServerRequestError::MissingSenderConstraint);
        }
        return match proof.dpop_jkt.as_ref() {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => Err(ResourceServerRequestError::DpopBindingMismatch),
            None => Err(ResourceServerRequestError::MissingSenderConstraint),
        };
    }
    if scheme == AccessTokenScheme::Dpop {
        return Err(ResourceServerRequestError::MissingSenderConstraint);
    }
    if let Some(expected) = cnf.x5t_s256.as_ref() {
        return match proof.mtls_x5t_s256.as_ref() {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => Err(ResourceServerRequestError::MtlsBindingMismatch),
            None => Err(ResourceServerRequestError::MissingSenderConstraint),
        };
    }
    Err(ResourceServerRequestError::MissingSenderConstraint)
}

#[cfg(test)]
#[path = "../tests/unit/presentation.rs"]
mod tests;
