"""Prepare isolated test clients through Keycloak or Hydra administrative HTTP APIs."""
import json,os,sys
from pathlib import Path
from urllib.parse import quote
from api import Api,compact

os.umask(0o077)
root=Path('/tmp')
peer=sys.argv[1]
source=json.loads((root/'state.json').read_text())
users=source['users']
redirect=source['redirect_uri']
clients={}; secrets={}
if peer=='keycloak':
    kc=Api('oidc-bench-keycloak')
    bootstrap=json.loads((root/'peer-bootstrap.json').read_text())
    credential,_,_=kc.form('POST','/realms/master/protocol/openid-connect/token',
        {'client_id':bootstrap['client_id'],'grant_type':'client_credentials','client_secret':bootstrap['secret']})
    headers={'Authorization':'Bearer '+credential['access_token']}
    kc.call('POST','/admin/realms',{'realm':'api-audit','enabled':True,'sslRequired':'none',
      'revokeRefreshToken':True,'refreshTokenMaxReuse':0,'accessTokenLifespan':300},(201,409),headers=headers)
    base='/admin/realms/api-audit'
    first=None
    for user in users:
        _,location,status=kc.call('POST',base+'/users',
          {'username':user['email'],'email':user['email'],'enabled':True,'firstName':'Benchmark','lastName':'User',
           'emailVerified':True,'credentials':[{'type':'password','temporary':False,'value':user['password']}]},
          (201,409),headers=headers)
        if first is None:
            if location:
                first=location.rstrip('/').rsplit('/',1)[1]
            else:
                found,_,_=kc.call('GET',base+'/users?exact=true&username='+quote(user['email']),headers=headers)
                first=found[0]['id']
    for alias in ('machine','oidc'):
        cid='api-audit-'+alias
        client={'clientId':cid,'protocol':'openid-connect','enabled':True,'publicClient':False,
                'consentRequired':False,'clientAuthenticatorType':'client-secret','redirectUris':[redirect],
                'standardFlowEnabled':alias=='oidc','directAccessGrantsEnabled':False,
                'serviceAccountsEnabled':alias=='machine','attributes':{'pkce.code.challenge.method':'S256'} if alias=='oidc' else {}}
        _,url,_=kc.call('POST',base+'/clients',client,(201,409),headers=headers)
        if url:
            internal=url.rstrip('/').rsplit('/',1)[1]
        else:
            found,_,_=kc.call('GET',base+'/clients?clientId='+quote(cid),headers=headers)
            internal=next(x['id'] for x in found if x['clientId']==cid)
        if alias=='machine':
            path=base+'/clients/'+internal+'/protocol-mappers/models'
            current,_,_=kc.call('GET',path,headers=headers)
            if not any(mapper['name']=='machine token audience' for mapper in current):
                kc.call('POST',path,{'name':'machine token audience','protocol':'openid-connect',
                  'protocolMapper':'oidc-audience-mapper','config':{'included.client.audience':cid,
                  'access.token.claim':'true','introspection.token.claim':'true','id.token.claim':'false'}},
                  (201,),headers=headers)
            current,_,_=kc.call('GET',path,headers=headers)
            assert any(mapper['config'].get('included.client.audience')==cid for mapper in current)
        out,_,_=kc.call('GET',base+'/clients/'+internal+'/client-secret',headers=headers)
        clients[alias]=cid
        secrets[cid]=out['value']
    parameters={}
    if first:
        out,_,_=kc.call('GET',base+'/users/'+first+'/credentials',headers=headers)
        config=json.loads(next(row['credentialData'] for row in out if row['type']=='password'))
        parameters={'algorithm':config.get('algorithm'),'iterations':config.get('hashIterations'),
                    'memory_kib':config.get('additionalParameters',{}).get('memory'),
                    'parallelism':config.get('additionalParameters',{}).get('parallelism')}
    proof={'product':'Keycloak','users_via_admin_api':len(users),'clients_via_admin_api':2,'password_policy':parameters,'realm':'api-audit','machine_audience_mapper':True}
    issuer='http://localhost:8080/realms/api-audit'
elif peer=='hydra':
    hydra=Api('oidc-bench-hydra',8081)
    for alias in ('machine','oidc'):
        data={'client_name':'API audit '+alias,'token_endpoint_auth_method':'client_secret_basic' if alias=='machine' else 'client_secret_post',
              'grant_types':['client_credentials'] if alias=='machine' else ['authorization_code','refresh_token'],
              'scope':'profile' if alias=='machine' else 'openid profile offline_access',
              'redirect_uris':[redirect],'response_types':['code'] if alias=='oidc' else []}
        created,_,_=hydra.call('POST','/admin/clients',data,(201,))
        clients[alias]=created['client_id']
        secrets[created['client_id']]=created['client_secret']
    proof={'product':'Ory Hydra','clients_via_admin_api':2,'login_fixture':'delegated identity through Hydra login/consent callbacks'}
    issuer='http://localhost:8080'
else:
    raise ValueError(peer)

fixture={'issuer':issuer,'redirect_uri':redirect,'users':users,'user':users[0],'clients':clients,'client_secrets':secrets}
(root/'peer-state.json').write_text(compact(fixture))
(root/'peer-provenance.json').write_text(compact(proof))
print(compact(proof))
