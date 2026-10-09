# One-off AST-assisted transformation; deleted from the resulting source tree.
from pathlib import Path
import re
from tree_sitter import Parser, Language
import tree_sitter_rust
R=Path.cwd(); parser=Parser(Language(tree_sitter_rust.language()))
owned={'ConsentPayload','CodePayload','RefreshTokenAuthenticationContext','Claims','TokenIssue'}
borrowed={'AccessTokenClaimsInput','AccessTokenSignInput','AccessTokenJwtInput'}
names={'userinfo_claims':'userinfo_claim_requests','id_token_claims':'id_token_claim_requests'}
def walk(n):
    yield n
    for c in n.named_children:yield from walk(c)
def text(n,b):return b[n.start_byte:n.end_byte].decode() if n else ''
def attrstart(n):
    s=n.start_byte;c=n.prev_named_sibling
    while c and c.type=='attribute_item':s=c.start_byte;c=c.prev_named_sibling
    return s
for f in R.glob('crates/**/*.rs'):
    b=f.read_bytes();ed=[]
    for n in walk(parser.parse(b).root_node):
        if n.type=='struct_item':
            name=text(n.child_by_field_name('name'),b)
            if name not in owned|borrowed:continue
            for ch in n.child_by_field_name('body').named_children:
                if ch.type!='field_declaration':continue
                field=text(ch.child_by_field_name('name'),b)
                if field in names:
                    e=ch.end_byte
                    if b[e:e+1]==b',':e+=1
                    if b[e:e+1]==b'\n':e+=1
                    ed.append((attrstart(ch),e,''))
                elif field in names.values() and name in owned:
                    ft=ch.child_by_field_name('type')
                    prefix='crate::' if f.parts[f.parts.index('crates')+1]=='authorization-server-core' else 'nazo_auth::'
                    wrapper='UserinfoClaimRequests' if field.startswith('userinfo') else 'IdTokenClaimRequests'
                    ed.append((ft.start_byte,ft.end_byte,prefix+wrapper))
                    if name!='TokenIssue':ed.append((attrstart(ch),ch.start_byte,'#[serde(flatten)]\n    '))
        elif n.type=='struct_expression':
            name=text(n.child_by_field_name('name'),b).split('::')[-1]
            if name not in owned|borrowed:continue
            fields={}
            for ch in n.child_by_field_name('body').named_children:
                if ch.type=='field_initializer':
                    fn=ch.child_by_field_name('field');v=ch.child_by_field_name('value');fields[text(fn,b)]=(ch,v,text(v,b))
                elif ch.type=='shorthand_field_initializer':
                    key=text(ch,b);fields[key]=(ch,ch,key)
            for old,new in names.items():
                if old not in fields:continue
                ch,oldv,oldtxt=fields[old];e=ch.end_byte
                if b[e:e+1]==b',':e+=1
                if b[e:e+1]==b'\n':e+=1
                ed.append((ch.start_byte,e,''))
                assert new in fields,(f,name,new)
                full,fv,ftxt=fields[new]
                empty=oldtxt in {'Vec::new()','vec![]','&[]'}
                full_empty=ftxt in {'Vec::new()','vec![]','&[]'}
                if not empty and '/tests/' in str(f) and full_empty:
                    vals=oldtxt.removeprefix('&')
                    ftxt=f'({vals}).into_iter().map(nazo_auth::OidcClaimRequest::named).collect::<Vec<_>>()'
                    if name in borrowed:ftxt='&'+ftxt
                if name in owned:ftxt=f'({ftxt}).into()'
                if full.type=='shorthand_field_initializer':ed.append((full.start_byte,full.end_byte,new+': '+ftxt))
                else:ed.append((fv.start_byte,fv.end_byte,ftxt))
    for a,z,s in sorted(ed,reverse=True):b=b[:a]+s.encode()+b[z:]
    if ed:f.write_bytes(b)
# Turn the builders into consumers of one full request sequence.
for f in R.glob('crates/**/*.rs'):
    b=f.read_bytes();ed=[]
    for n in walk(parser.parse(b).root_node):
        if n.type!='call_expression':continue
        fn=text(n.child_by_field_name('function'),b).split('::')[-1]
        if fn not in {'oidc_user_claims','oidc_id_token_user_claims'}:continue
        args=n.child_by_field_name('arguments')
        a=[x for x in args.named_children if x.type not in {'line_comment','block_comment'}]
        assert len(a)==6,(f,n.start_point,len(a))
        vals=[text(x,b) for x in a];bare,full=vals[3:5]
        if '/tests/' in str(f) and bare!='&[]' and full=='&[]':
            full=f'&({bare.removeprefix("&")}).into_iter().map(nazo_auth::OidcClaimRequest::named).collect::<Vec<_>>()'
        ed.append((args.start_byte,args.end_byte,'('+', '.join(vals[:3]+[full])+')'))
    for a,z,s in sorted(ed,reverse=True):b=b[:a]+s.encode()+b[z:]
    if ed:f.write_bytes(b)
f=R/'crates/authorization-server/src/domain/oidc_claims.rs';s=f.read_text()
s=s.replace('requested_claims: &[String]', 'requested_claims: &[OidcClaimRequest]',1).replace('&claim.as_str()', '&claim.name.as_str()')
s=s.replace('    requested_claims: &[String],\n','').replace('    _sector_identifier_host: Option<&str>,\n','').replace('    sector_identifier_host: Option<&str>,\n','')
s=s.replace('        requested_claims,\n','').replace('            requested_claims,\n','')
a=s.index('fn requested_claim(');z=s.index('fn claim_allowed(',a)
s=s[:a]+'''fn claim_requested(requests: &[OidcClaimRequest], name: &str) -> bool {
    requests.iter().any(|request| request.name == name)
}

'''+s[z:]
s=s.replace('    if requested_claim(requested_claims, name) {\n        return true;\n    }\n    scope_allowed && !claim_requested(requested_claims, requested_claim_requests, name)', '    scope_allowed')
s=s.replace('claim_requested(requested_claims, requested_claim_requests,', 'claim_requested(requested_claim_requests,');f.write_text(s)
for f in R.glob('crates/**/*.rs'):
    if f.name=='claim_selection.rs':continue
    s=f.read_text()
    if f.as_posix().endswith('src/token/issue/refresh_persistence.rs'):
        s=re.sub(r'^\s*&& context\.(?:userinfo_claims|id_token_claims) == issue\.(?:userinfo_claims|id_token_claims)\n','\n',s,flags=re.M)
    if f.as_posix().endswith('src/token/issue.rs'):
        s=s.replace('let requested = issue.id_token_claims.iter().any(|claim| claim == "sid")\n        || issue','let requested = issue')
    s=re.sub(r'\b(\w+)\.(userinfo_claims|id_token_claims)\b',lambda m:m[1]+'.'+m[2].replace('_claims','_claim_requests')+'.names()',s)
    if f.name=='flow.rs':
        s=s.replace('&payload.userinfo_claim_requests.names()', '&payload.userinfo_claim_requests').replace('&payload.id_token_claim_requests.names()', '&payload.id_token_claim_requests')
    if f.name=='claims_contract.rs':
        s=s.replace('    let userinfo_claims = vec!["email".to_owned()];\n','').replace('                "userinfo_claims": ["email"],\n','')
    if f.name in {'transaction.rs','claims.rs'}:s=s.replace('#[serde(flatten)]','#[serde(flatten, skip_serializing_if = "Vec::is_empty")]')
    f.write_text(s)
f=R/'crates/authorization-server/src/authorization/request/parameters.rs';s=f.read_text()
s=re.sub(r'pub\(super\) fn claim_request_names\([^\n]*\) -> Vec<String> \{.*?\n\}\n','',s,flags=re.S).replace('use nazo_auth::OidcClaimRequest;\n','');f.write_text(s)
for rel in ['crates/authorization-server/src/authorization/request/flow.rs','crates/authorization-server/src/authorization/request/mod.rs']:
    f=R/rel;s=f.read_text().replace(', claim_request_names','').replace('claim_request_names, ','');f.write_text(s)
for f in R.glob('crates/**/tests/**/*.rs'):
    s=f.read_text()
    s=re.sub(r'claim_request_names\(&(requested\.userinfo|requested\.id_token|requests)\)',r'nazo_auth::UserinfoClaimRequests::from(\1.clone()).names()',s)
    s=s.replace('claim_request_names(&[])','nazo_auth::UserinfoClaimRequests::default().names()');f.write_text(s)
f=R/'crates/authorization-server/tests/unit/token/issue/refresh_persistence.rs';s=f.read_text().replace('context.userinfo_claim_requests.names().push("profile".into())','context.userinfo_claim_requests.push(nazo_auth::OidcClaimRequest::named("profile"))').replace('context.id_token_claim_requests.names().push("profile".into())','context.id_token_claim_requests.push(nazo_auth::OidcClaimRequest::named("profile"))');f.write_text(s)
f=R/'crates/nazoauth/tests/unit/http/token/authorization_code/issuance.rs';s=f.read_text()
s=s.replace('    payload.userinfo_claim_requests.names() = vec!["name".to_owned(), "email".to_owned()];\n','').replace('    payload.id_token_claim_requests.names() = vec!["auth_time".to_owned(), "sid".to_owned()];\n','')
s=s.replace('payload.userinfo_claim_requests = vec![OidcClaimRequest {','payload.userinfo_claim_requests = vec![OidcClaimRequest::named("name"), OidcClaimRequest {',1)
s=s.replace('payload.id_token_claim_requests = vec![OidcClaimRequest {','payload.id_token_claim_requests = vec![OidcClaimRequest::named("auth_time"), OidcClaimRequest::named("sid"), OidcClaimRequest {',1)
s=s.replace('vec!["auth_time", "sid"]','vec!["auth_time", "sid", "acr"]')
s=s.replace('issue.userinfo_claim_requests.len(), 1','issue.userinfo_claim_requests.len(), 2').replace('issue.userinfo_claim_requests[0]','issue.userinfo_claim_requests[1]').replace('issue.id_token_claim_requests.len(), 1','issue.id_token_claim_requests.len(), 3').replace('issue.id_token_claim_requests[0]','issue.id_token_claim_requests[2]');f.write_text(s)
for f in R.glob('crates/**/*.rs'):
    if f.name=='claim_selection.rs':continue
    b=f.read_bytes();ed=[]
    for n in walk(parser.parse(b).root_node):
        if n.type!='assignment_expression':continue
        a=n.child_by_field_name('left');v=n.child_by_field_name('right')
        if a.type=='field_expression' and text(a.child_by_field_name('field'),b) in names.values():
            s=text(v,b)
            if s.startswith('vec!') or s=='Vec::new()':ed.append((v.start_byte,v.end_byte,'('+s+').into()'))
    for a,z,s in sorted(ed,reverse=True):b=b[:a]+s.encode()+b[z:]
    if ed:f.write_bytes(b)
f=R/'crates/authorization-server/tests/unit/domain/oidc_claims.rs';s=f.read_text();a=s.index('fn prompt_none_claims_require_their_authorizing_scope()');z=s.index('\nfn user()',a);part=s[a:z]
part=re.sub(r'"([a-z_]+)"\.to_owned\(\)',lambda m:'OidcClaimRequest::named("'+m[1]+'")' if m[1] in {'birthdate','email_verified','phone_number','unknown_claim'} else m[0],part)
part=part.replace('&["email".to_owned()]','&[OidcClaimRequest::named("email")]').replace('            "address".to_owned(),','            OidcClaimRequest::named("address"),');f.write_text(s[:a]+part+s[z:])
for rel in ['crates/authorization-server-core/src/transaction.rs','crates/authorization-server-core/src/token.rs','crates/authorization-server/src/domain/oauth.rs']:
    f=R/rel;s=f.read_text()
    if s.count('OidcClaimRequest')==1:s=s.replace('use crate::OidcClaimRequest;\n','').replace('OidcClaimRequest, ','').replace(', OidcClaimRequest','')
    f.write_text(s)
for f in R.glob('crates/authorization-server-core/tests/unit/**/*.rs'):
    s=f.read_text().replace('nazo_auth::OidcClaimRequest::named','crate::OidcClaimRequest::named');f.write_text(s)
f=R/'crates/authorization-server-core/src/lib.rs';s=f.read_text().replace('mod claims;','mod claim_selection;\nmod claims;\npub use claim_selection::{IdTokenClaimRequests, UserinfoClaimRequests};');f.write_text(s)
f=R/'crates/authorization-server-core/src/claims.rs';s=f.read_text();at=s.index('\n#[derive(Clone, Debug, Deserialize, Serialize)]\npub struct Claims');s=s[:at]+'''
impl OidcClaimRequest {
    /// An explicit request with no additional value constraint.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self { name: name.into(), essential: false, value: None, values: Vec::new() }
    }
}
'''+s[at:];f.write_text(s)
f=R/'crates/authorization-server-core/src/token.rs';s=f.read_text().replace('pub const CURRENT_VERSION: u16 = 1;', '/// Version 2 encodes each authorized claim exactly once. Version 1 is read-only legacy.\n    pub const CURRENT_VERSION: u16 = 2;').replace('self.version == Self::CURRENT_VERSION','matches!(self.version, 1 | Self::CURRENT_VERSION)');f.write_text(s)
f=R/'crates/authorization-server-core/tests/unit/token.rs';s=f.read_text().replace('authentication_context_accepts_only_the_current_version','authentication_context_accepts_current_and_retained_legacy_versions').replace('    assert!(context.is_well_formed());','    assert!(context.is_well_formed());\n    let legacy = RefreshTokenAuthenticationContext { version: 1, ..context.clone() };\n    assert!(legacy.is_well_formed());',1);f.write_text(s)
f=R/'crates/persistence-postgres/tests/unit/repositories/token_issuance.rs';s=f.read_text().replace('version: 1,','version: nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION,');f.write_text(s)
