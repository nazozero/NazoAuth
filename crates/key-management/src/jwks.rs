use serde_json::{Value, json};

use crate::VerificationKey;

pub(crate) fn public_jwks(keys: &[VerificationKey]) -> Value {
    json!({
        "keys": keys.iter().map(|key| {
            let mut public = key.public_jwk.clone();
            if let Some(object) = public.as_object_mut() {
                for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                    object.remove(member);
                }
            }
            public
        }).collect::<Vec<_>>()
    })
}

#[cfg(test)]
#[path = "../tests/unit/jwks.rs"]
mod tests;
