use crate::adapters::security::blake3_hex;

use serde_json::json;

pub(super) fn oidc_state_key(state: &str) -> String {
    format!("oauth:federation:oidc:state:{}", blake3_hex(state))
}
