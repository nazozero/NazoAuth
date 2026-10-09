# One-off, branch-local refactoring input. Removed from the resulting source tree.
from pathlib import Path
import re
from tree_sitter import Language, Parser
import tree_sitter_rust
R = Path.cwd()
def edit(path, fn):
    p=R/path; old=p.read_text(); new=fn(old); assert new!=old,path; p.write_text(new)
def sub(s,a,b,count=1):
    assert s.count(a)==count,(a,s.count(a),count)
    return s.replace(a,b)
def identity_model(s):
    start=s.index('#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]\npub enum AuthMethod')
    end=s.index('#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]\npub struct PostalAddress',start)
    s=s[:start]+s[end:]
    for variant in ['InvalidAuthenticationTime','FutureAuthenticationTime','EmptyAuthenticationMethods','EmptyOidcSid']:
        s=re.sub(r'^    '+variant+r',\n','',s,flags=re.M)
        s=re.sub(r'^            Self::'+variant+r' => [^\n]*\n','',s,flags=re.M)
    return s
edit('crates/identity/src/model.rs',identity_model)
edit('crates/identity/src/lib.rs',lambda s:sub(s,'AccountIdentity, AuthMethod, AuthenticationContext, AuthenticationIdentity, IdentityModelError,','AccountIdentity, AuthenticationIdentity, IdentityModelError,'))
def model_tests(s):
    s=sub(s,'    AuthMethod, AuthenticationContext, IdentityModelError, OrganizationId, PostalAddress,\n','    IdentityModelError, OrganizationId, PostalAddress,\n')
    a=s.index('#[test]\nfn authentication_context_has_ordered_deduplicated_amr_and_mfa()')
    z=s.index('#[test]\nfn subject_claims_are_framework_and_storage_independent()',a)
    return s[:a]+'''#[test]
fn session_metadata_has_one_amr_source_and_rejects_invalid_time_or_sid() {
    use nazo_identity::session::{SessionRecord, valid_authentication_metadata};
    let mut session = SessionRecord::new(
        UserId::new(id(4)).unwrap(), 1_000, vec!["password".to_owned()], false,
        Some("sid-1".to_owned()),
    );
    session.add_amr("otp");
    session.add_amr("mfa");
    session.add_amr("otp");
    assert_eq!(session.amr(), ["password", "otp", "mfa"]);
    assert!(valid_authentication_metadata(session.auth_time(), session.amr(), session.oidc_sid(), 1_001));
    assert!(!valid_authentication_metadata(0, session.amr(), session.oidc_sid(), 1_001));
    assert!(!valid_authentication_metadata(1_032, session.amr(), session.oidc_sid(), 1_001));
    assert!(!valid_authentication_metadata(1_000, &[], session.oidc_sid(), 1_001));
    assert!(!valid_authentication_metadata(1_000, session.amr(), Some(" "), 1_001));
}

'''+s[z:]
edit('crates/identity/tests/model.rs',model_tests)
def rows(s):
    a=s.index('#[allow(dead_code)]'); z=s.index('/// Focused account read model.',a)
    return s[:a]+s[z:]
edit('crates/persistence-postgres/src/rows/identity.rs',rows)
def convert(s):
    s=sub(s,'    SubjectClaimsRow, UserRow,','    SubjectClaimsRow,')
    a=s.index('impl TryFrom<UserRow> for Principal {'); z=s.index('fn principal_parts(',a); s=s[:a]+s[z:]
    a=s.index('fn account(row: &UserRow)'); z=s.index('pub(crate) fn authentication_identity(',a); s=s[:a]+s[z:]
    a=s.index('impl TryFrom<UserRow> for PublicAccount {'); z=s.index('pub(crate) fn passkey(',a)
    return s[:a]+s[z:]
edit('crates/persistence-postgres/src/convert/identity.rs',convert)
edit('crates/persistence-postgres/src/lib.rs',lambda s:sub(s,'//! use nazo_postgres::rows::identity::UserRow;','//! use nazo_postgres::rows::identity::PublicAccountRow;'))
def conversion_tests(s):
    s=s.replace('UserRow','PublicAccountRow')
    s=sub(s,'        password_hash: "hash".into(),\n','')
    s=sub(s,'        password_hash: row.password_hash,','        password_hash: "hash".into(),')
    return sub(s,'''    let mut row = user_row();
    row.password_hash = "   ".to_owned();

    let error = authentication_identity(authentication_row(row)).unwrap_err();''','''    let mut row = authentication_row(user_row());
    row.password_hash = "   ".to_owned();

    let error = authentication_identity(row).unwrap_err();''')
edit('crates/persistence-postgres/tests/unit/convert/identity.rs',conversion_tests)
parser=Parser(Language(tree_sitter_rust.language()))
targets={'ValidatedClientRegistration','PreparedDynamicClientRegistration'}
for p in R.glob('crates/**/*.rs'):
    b=p.read_bytes(); root=parser.parse(b).root_node; patches=[]; stack=[root]
    while stack:
        n=stack.pop();stack.extend(n.named_children)
        if n.type not in {'struct_item','struct_expression'}:continue
        nn=n.child_by_field_name('name');name=b[nn.start_byte:nn.end_byte].decode().split('::')[-1] if nn else ''
        if name not in targets:continue
        body=n.child_by_field_name('body')
        if not body:continue
        for f in body.named_children:
            if f.type not in {'field_declaration','field_initializer'}:continue
            fn=f.child_by_field_name('name') or f.child_by_field_name('field')
            if not fn or b[fn.start_byte:fn.end_byte]!=b'backchannel_user_code_parameter':continue
            a=b.rfind(b'\n',0,f.start_byte)+1;z=b.find(b'\n',f.end_byte)+1
            prev=f.prev_named_sibling
            while prev and prev.type in {'line_comment','attribute_item'}:
                a=b.rfind(b'\n',0,prev.start_byte)+1;prev=prev.prev_named_sibling
            patches.append((a,z,b''))
    if patches:
        for a,z,new in sorted(patches,reverse=True):b=b[:a]+new+b[z:]
        p.write_bytes(b)
def replace(path,a,b):
    edit(path,lambda s:sub(s,a,b))
replace('crates/authorization-server-core/src/admin_clients/patch.rs',
'''    if let Some(value) = request.backchannel_user_code_parameter {
        client.backchannel_user_code_parameter = value;
    }
''','')
replace('crates/authorization-server-core/src/admin_clients/patch.rs',
'    if let Some(security_policy) = request.security_policy.as_ref() {',
'''    if request.backchannel_user_code_parameter == Some(true) {
        return Err(AdminClientError::InvalidRequest(
            "backchannel_user_code_parameter=true 不受支持".to_owned(),
        ));
    }
    if let Some(security_policy) = request.security_policy.as_ref() {''')
replace('crates/authorization-server-core/src/admin_clients/validation.rs','backchannel_user_code_parameter: client.backchannel_user_code_parameter,','backchannel_user_code_parameter: false,')
replace('crates/authorization-server-core/src/dynamic_client_registration/request.rs','backchannel_user_code_parameter: self.backchannel_user_code_parameter,','backchannel_user_code_parameter: false,')
replace('crates/http-actix/src/dynamic_client_registration/response.rs','"backchannel_user_code_parameter": client.backchannel_user_code_parameter,','"backchannel_user_code_parameter": false,')
replace('crates/authorization-server-core/tests/ciba_registration_contract.rs','        assert!(!prepared.backchannel_user_code_parameter);','        assert!(!prepared.into_create_client_request().backchannel_user_code_parameter);')
replace('crates/authorization-server-core/tests/admin_client_types.rs',
'''            assert!(
                !created
                    .unwrap()
                    .registration
                    .backchannel_user_code_parameter
            );
            assert!(!patched.unwrap().backchannel_user_code_parameter);''',
'''            let registration = serde_json::to_value(created.unwrap().registration).unwrap();
            let patched = serde_json::to_value(patched.unwrap().registration).unwrap();
            assert!(registration.get("backchannel_user_code_parameter").is_none());
            assert!(patched.get("backchannel_user_code_parameter").is_none());''')
p=R/'crates/nazoauth/src/http/views.rs';s=p.read_text();s=re.sub(r'^\s*let backchannel_user_code_parameter = client\.backchannel_user_code_parameter;\n','\n',s,flags=re.M);s=s.replace('json!(backchannel_user_code_parameter)','json!(false)');p.write_text(s)
p=R/'crates/nazoauth/tests/support/macros.rs';s=p.read_text();s=re.sub(r'^\s*backchannel_user_code_parameter: false,\n','\n',s,flags=re.M);p.write_text(s)
p=R/'crates/persistence-postgres/tests/oauth_client_dcr.rs';s=p.read_text()
for receiver in ['persisted','replaced']:
    s=s.replace(f'assert!(!{receiver}.backchannel_user_code_parameter);',f'assert!(serde_json::to_value(&{receiver}.registration).unwrap().get("backchannel_user_code_parameter").is_none());')
p.write_text(s)
