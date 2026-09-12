use actix_web::{HttpRequest, http::header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_oauth_server::contracts::token_client_auth::{
    BasicAuthorizationCredentials, TokenClientAuthTransportFacts,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct TokenClientAuthForm<'a> {
    pub client_id: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

#[must_use]
pub fn token_client_auth_transport_facts(
    request: &HttpRequest,
    form: TokenClientAuthForm<'_>,
) -> TokenClientAuthTransportFacts {
    TokenClientAuthTransportFacts::from_parts(
        basic_authorization_credentials(request),
        form.client_id.map(str::to_owned),
        form.client_secret.map(str::to_owned),
        form.client_assertion_type.map(str::to_owned),
        form.client_assertion.map(str::to_owned),
    )
}

fn basic_authorization_credentials(request: &HttpRequest) -> BasicAuthorizationCredentials {
    let Some(raw) = request.headers().get(header::AUTHORIZATION) else {
        return BasicAuthorizationCredentials::Absent;
    };
    let bytes = raw.as_bytes();
    let start = bytes
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(bytes.len());
    if !bytes[start..end].eq_ignore_ascii_case(b"Basic") {
        return BasicAuthorizationCredentials::Absent;
    }
    let Some(encoded) = raw.to_str().ok().and_then(|value| {
        let mut parts = value.trim_start().splitn(2, char::is_whitespace);
        parts.next()?;
        let credentials = parts.next()?.trim();
        (!credentials.is_empty() && credentials.split_whitespace().count() == 1)
            .then_some(credentials)
    }) else {
        return BasicAuthorizationCredentials::Malformed;
    };
    let Some((client_id, client_secret)) = STANDARD.decode(encoded).ok().and_then(|decoded| {
        let separator = decoded.iter().position(|byte| *byte == b':')?;
        let client_id = form_urlencoded_component(&decoded[..separator])?;
        let client_secret = form_urlencoded_component(&decoded[separator + 1..])?;
        Some((client_id, client_secret))
    }) else {
        return BasicAuthorizationCredentials::Malformed;
    };
    BasicAuthorizationCredentials::Present {
        client_id,
        client_secret,
    }
}

fn form_urlencoded_component(input: &[u8]) -> Option<String> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        match input[cursor] {
            b'+' => {
                decoded.push(b' ');
                cursor += 1;
            }
            b'%' => {
                let high = input.get(cursor + 1).and_then(|byte| hex_value(*byte))?;
                let low = input.get(cursor + 2).and_then(|byte| hex_value(*byte))?;
                decoded.push((high << 4) | low);
                cursor += 3;
            }
            byte => {
                decoded.push(byte);
                cursor += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
