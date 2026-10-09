from pathlib import Path
import subprocess,json,time
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009'
p=R/'crates/persistence-postgres/tests/unit/convert/identity.rs'
p.write_text(p.read_text()+'''
fn passkey_row() -> PasskeyCredentialRow {
    PasskeyCredentialRow {
        id: Uuid::now_v7(), tenant_id: Uuid::now_v7(), user_id: Uuid::now_v7(),
        credential_id: "AQID".into(), label: "Laptop".into(), sign_count: 12,
        credential: serde_json::json!({"id": [1,2,3], "counter": 12,
          "public_key_cose": [164,1,1,3,39,32,6,33], "transports": ["internal"], "aaguid": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}),
        last_used_at: None, created_at: Utc::now(), updated_at: Utc::now(),
    }
}

#[test]
fn passkey_adapter_rejects_conflicting_credential_authorities() {
    assert!(passkey(passkey_row()).is_ok());
    let mut row = passkey_row(); row.sign_count = 13;
    assert!(passkey(row).is_err(), "legacy JSON counter must agree with CAS column");
    let mut row = passkey_row(); row.credential_id = "BAUG".into();
    assert!(passkey(row).is_err(), "legacy JSON ID must agree with lookup column");
}
''')
cmd=['cargo','test','-p','nazo-postgres','--lib','--all-features','--locked','passkey_adapter_rejects_conflicting_credential_authorities']
t=time.monotonic()
with (E/'passkey-negative.log').open('w') as f:r=subprocess.run(['docker','exec','-w','/src','nazoauth-perf-runner-20261009',*cmd],stdout=f,stderr=subprocess.STDOUT)
(E/'passkey-negative-exit.json').write_text(json.dumps(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-t)))
print((E/'passkey-negative.log').read_text()[-5000:]);print('EXIT',r.returncode)
