"""Create benchmark accounts and clients through published application surfaces."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from api import Api,ApiError,compact,totp

import os
os.umask(0o077)
root=Path('/tmp')
actor=json.loads((root/'api-bench-admin.json').read_text())
service=Api()
service.login(actor)
document,_,_=service.call('POST','/auth/me/mfa/totp/begin')
actor['totp']={k:document[k] for k in ('secret_base32','period','digits')}
service.call('POST','/auth/me/mfa/totp/confirm',{'code':totp(actor['totp'])})
(root/'actor.json').write_text(compact(actor))
enabled=[]
modules,_,_=service.call('GET','/admin/runtime-modules')
for module in modules['items']:
    name=module['module_id']
    if name not in ('native_sso','dynamic_client_registration','device_authorization','jwt_bearer_grant'):
        continue
    if module['desired_state']!='enabled':
        service.call('PATCH','/admin/runtime-modules/'+name,{'desired_state':'enabled','expected_revision':module['revision'],'reason':'Isolated API benchmark'},(200,202))
    enabled.append(name)

users=[]
for i in range(128):
    account={'email':f'audit-user-{i:03d}@example.test','password':secrets.token_urlsafe(22)}
    created,_,_=service.call('POST','/admin/users',account,(201,))
    assert created['email']==account['email']
    users.append(account)
(root/'api-users.json').write_text(compact(users))

def encode(n):
    data=n.to_bytes(max(1,(n.bit_length()+7)//8),'big')
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def rsajwk(n,kid,alg):
    p=n.public_numbers
    return {'kty':'RSA','kid':kid,'alg':alg,'use':'sig','n':encode(p.n),'e':encode(p.e),
            'd':encode(n.d),'p':encode(n.p),'q':encode(n.q),'dp':encode(n.dmp1),'dq':encode(n.dmq1),'qi':encode(n.iqmp)}

def public(key):
    return {k:v for k,v in key.items() if k not in ('d','p','q','dp','dq','qi')}

rsa_key=rsa.generate_private_key(public_exponent=65537,key_size=2048).private_numbers()
rs=rsajwk(rsa_key,'audit-rs','RS256')
ps=rsajwk(rsa_key,'audit-ps','PS256')
ec_key=ec.generate_private_key(ec.SECP256R1()).private_numbers()
def ec_coord(n):
    return base64.urlsafe_b64encode(n.to_bytes(32,'big')).decode().rstrip('=')
ec_public={'kty':'EC','crv':'P-256','x':ec_coord(ec_key.public_numbers.x),'y':ec_coord(ec_key.public_numbers.y)}
thumb=base64.urlsafe_b64encode(hashlib.sha256(json.dumps(ec_public,sort_keys=True,separators=(',',':')).encode()).digest()).decode().rstrip('=')
dpop={**ec_public,'d':ec_coord(ec_key.private_value),'kid':'audit-dpop','alg':'ES256'}
redirect='https://client.example.test/callback'
scopes=['openid','profile','offline_access','device_sso']
grants=['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange',
        'urn:ietf:params:oauth:grant-type:jwt-bearer']
keys={'keys':[public(rs),public(ps)]}
policy={'version':1,'assurance':'baseline','require_signed_authorization_request':False,
        'require_signed_authorization_response':False,'require_signed_introspection_response':False,
        'session_management':True,'allow_cross_device_flows':False,'allow_confidential_oidc_without_pkce':False}
clients={}; issued={}; errors={}
def client(tag, auth, access, flows, **extra):
    body={'client_name':'API audit '+tag,'client_type':'confidential','redirect_uris':[redirect],
          'allowed_audiences':['resource://default'],'scopes':access,'grant_types':flows,'token_endpoint_auth_method':auth,**extra}
    try:
        record,_,_=service.call('POST','/admin/clients',body,(201,))
    except ApiError as err:
        errors[tag]=str(err)
        return
    clients[tag]=record['client_id']
    if 'client_secret' in record:
        issued[record['client_id']]=record['client_secret']

client('client_credentials','client_secret_post',['profile'],['client_credentials'])
client('machine_basic','client_secret_basic',['profile'],['client_credentials'])
client('oidc','client_secret_post',scopes,grants,jwks=keys,security_policy=policy)
client('device','client_secret_post',['openid','profile'],['urn:ietf:params:oauth:grant-type:device_code'],
       security_policy={**policy,'allow_cross_device_flows':True})
client('fapi','private_key_jwt',['openid','profile','offline_access'],['authorization_code','refresh_token'],
       jwks=keys,security_policy={**policy,'assurance':'fapi2'},require_dpop_bound_tokens=True,
       require_par_request_object=True,request_object_signing_alg='PS256',id_token_signed_response_alg='PS256')
client('fapi_machine','private_key_jwt',['profile'],['client_credentials'],
       jwks=keys,security_policy={**policy,'assurance':'fapi2'},require_dpop_bound_tokens=True)
client('ciba','private_key_jwt',['openid','profile'],['urn:openid:params:grant-type:ciba'],jwks=keys,
       security_policy={**policy,'assurance':'fapi2','allow_cross_device_flows':True},require_dpop_bound_tokens=True,
       id_token_signed_response_alg='PS256')
state={'issuer':'http://localhost:8080','redirect_uri':redirect,'user':users[0],'users':users,
       'admin':actor,'logged_in_sessions':[],'oidc_refresh_tokens':[],
       'clients':clients,'client_secrets':issued,'private_jwk':rs,'ps256_private_jwk':ps,
       'dpop_private_jwk':dpop,'dpop_public_jwk':ec_public,'dpop_jkt':thumb,
       'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'}
(root/'state.json').write_text(compact(state))
(root/'provenance.json').write_text(compact({'real_users_created':len(users),'oauth_client_classes':sorted(clients),
       'runtime_modules':sorted(enabled),'client_creation_diagnostics':errors,
       'interfaces':['nazoauth admin-provision','POST /admin/users','POST /admin/clients','PATCH /admin/runtime-modules/{module_id}']}))
assert {'client_credentials','machine_basic','oidc'} <= clients.keys(),errors
print('API provisioning completed',len(users),'users',len(clients),'clients')
