"""Instrument a disposable build to time the client snapshot and remaining grant on the same requests."""
import sys
from pathlib import Path

path = Path(sys.argv[1]) / "crates/authorization-server/src/token/dispatch/mod.rs"
text = path.read_text()
def replace_once(before, after):
    global text
    assert text.count(before) == 1, before
    text = text.replace(before, after)

lookup = "        let (mut client, secret_digest, client_epoch) = match authorization_service"
replace_once(lookup, """        static MACHINE_SAMPLES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sampled_at = (form.grant_type == "client_credentials" &&
            MACHINE_SAMPLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 32 == 0)
            .then(std::time::Instant::now);
""" + lookup)
next_check = "        if form.grant_type == nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT {\n            if !client.is_active"
replace_once(next_check, "        let snapshot_time = sampled_at.map(|t| t.elapsed());\n" + next_check)
call = '            "client_credentials" => {\n                token_client_credentials_with_service('
replace_once(call, call.replace("                token_", "                let result = token_"))
end = "                .await\n            }\n            JWT_BEARER_GRANT_TYPE"
replace_once(end, """                .await;
                if result.is_ok() && let (Some(t), Some(snapshot)) = (sampled_at, snapshot_time) {
                    eprintln!("BENCH_MACHINE_SNAPSHOT {} {}", snapshot.as_nanos(), t.elapsed().as_nanos());
                }
                result
            }
            JWT_BEARER_GRANT_TYPE""")
path.write_text(text)
