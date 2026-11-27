"""Private benchmark HTTP driver. Payloads and response bodies stay local."""
import base64
from hashlib import sha1
import hmac
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
from pathlib import Path
import re
import time
from urllib.parse import urlencode

def compact(value):
    return json.dumps(value,separators=(",",":"))

class ApiError(RuntimeError):
    def __init__(self, method, path, status, code):
        self.status=status
        super().__init__(f'{method} {path.split("?")[0]} returned {status} {code}')

class Api:
    def __init__(self, host="oidc-bench-nazo", port=8080):
        self.host=host
        self.cookies={}
        self.conn=HTTPConnection(host,port,timeout=8)

    def call(self, method, path, payload=None, expected=(200,), headers=None):
        opts={'Host':'localhost:8080','Accept':'application/json'}
        if self.cookies:
            opts['Cookie']='; '.join(f'{k}={v}' for k,v in self.cookies.items())
        if csrf:=self.cookies.get('nazo_oauth_csrf'):
            opts['X-CSRF-Token']=csrf
        if isinstance(payload,(dict,list)):
            opts['Content-Type']='application/json'
            payload=compact(payload)
        opts.update(headers or {})
        self.conn.request(method,path,body=payload,headers=opts)
        response=self.conn.getresponse()
        body=response.read()
        self.last_body=body
        for name,value in response.getheaders():
            if name.lower()=='set-cookie':
                parsed=SimpleCookie()
                parsed.load(value)
                for key,cookie in parsed.items():
                    if cookie.value:
                        self.cookies[key]=cookie.value
                    else:
                        self.cookies.pop(key,None)
        try:
            data=json.loads(body)
        except (UnicodeError,ValueError):
            data=None
        if response.status not in expected:
            code=(data or {}).get('error','') if isinstance(data,dict) else ''
            code=code if isinstance(code,str) and re.fullmatch(r'[A-Za-z0-9_\-]+',code) else ''
            raise ApiError(method,path,response.status,code)
        return data,response.getheader('Location'),response.status

    def login(self, account):
        data,_,_=self.call('POST','/auth/login',{'email':account['email'],'password':account['password']})
        if (data or {}).get('mfa_required'):
            self.call('POST','/auth/mfa/verify',{'code':totp(account['totp'])})
        if not self.cookies.get('nazo_oauth_csrf'):
            raise RuntimeError('login did not establish CSRF state')

    def form(self, method, path, fields, expected=(200,), headers=None):
        return self.call(method,path,urlencode(fields),expected,{'Content-Type':'application/x-www-form-urlencoded',**(headers or {})})

def totp(binding):
    period=int(binding['period'])
    if time.time() % period >= period-2:
        time.sleep(2)
    secret=binding['secret_base32'].upper()
    key=base64.b32decode(secret+'='*((-len(secret))%8))
    counter=int(time.time())//period
    mac=hmac.new(key,counter.to_bytes(8,'big'),sha1).digest()
    offset=mac[-1]&15
    n=int.from_bytes(mac[offset:offset+4],'big')&0x7fffffff
    digits=int(binding['digits'])
    return f'{n%10**digits:0{digits}d}'
