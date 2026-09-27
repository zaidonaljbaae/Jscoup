# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
import asyncio,json,time,types,threading
import pytest
from jscoup import JSCoup,MemoryStorage,JSCoupConfig
from jscoup.context import current_context,all_contexts,reset
from jscoup.models import EventRecord
@pytest.fixture(autouse=True)
def isolate(tmp_path,monkeypatch):
 monkeypatch.chdir(tmp_path);reset();yield;reset()
def bl(**kw):return JSCoup(storage=MemoryStorage(),dashboard_local_dev=True,capture_success=True,**kw)
def payload(x):return json.dumps(x.storage.list()[0].to_dict())
@pytest.mark.parametrize('channel',['positional_sql','sql_literal','custom_sql_key','custom_body','raw_preview','azure_url','culprit'])
def test_privacy_boundary(channel):
 x=bl(sensitive_keys=['password','token','api_key','iban']);marker='SYNTHETIC_7fb_secret'
 if channel=='azure_url':
  @x.watch_azure_function()
  def handler(req):return 'ok'
  handler(types.SimpleNamespace(url='https://local/test?token='+marker,method='GET',headers={},params={'token':marker},get_body=lambda:b''))
 elif channel=='culprit':
  try:raise ValueError('password=SYNTHETIC_7fb_secret')
  except Exception as e:x.record_exception(e)
 else:
  with x.capture(name='case') as ctx:
   if channel=='positional_sql':x.record_query('INSERT INTO users(password) VALUES (?)',(marker,))
   if channel=='sql_literal':x.record_query("INSERT INTO users(password) VALUES ('"+marker+"')")
   if channel=='custom_sql_key':x.record_query('SELECT :iban',{'iban':marker})
   if channel=='custom_body':ctx.body_preview=json.dumps({'iban':marker})
   if channel=='raw_preview':ctx.result_preview=json.dumps({'password':marker})
 assert marker not in payload(x)
def test_sessions_reject_other_application():
 a=JSCoup(storage=MemoryStorage(),service_name='a',dashboard_username='alice',dashboard_password='alpha')
 b=JSCoup(storage=MemoryStorage(),service_name='b',dashboard_username='bob',dashboard_password='bravo')
 r=a.dashboard.handle('/api/login',method='POST',body=json.dumps({'username':'alice','password':'alpha'}).encode())
 cookie=r.headers['Set-Cookie'].split(';')[0]
 assert b.dashboard.handle('/api/health',headers={'Cookie':cookie}).status==401
def test_bad_argument_repr_preserves_host_call():
 class Bad:
  def __repr__(self):raise RuntimeError('repr broke')
 x=bl()
 @x.watch()
 def f(arg):return 7
 assert f(Bad())==7
def test_azure_async_capture_waits_for_completion():
 x=bl()
 @x.watch_azure_function()
 async def handler(req):
  assert current_context() is not None
  raise ValueError('async Azure failure')
 async def run():
  with pytest.raises(ValueError):await handler(types.SimpleNamespace(headers={},params={},get_body=lambda:b''))
 asyncio.run(run());assert x.storage.list()[0].error_type=='ValueError'
def test_simulator_refuses_watched_functions_of_every_kind():
 x=bl()
 ran=[]
 @x.watch_azure_function(name='az')
 def handler(req=None):ran.append(1);return 'ok'
 @x.watch(name='plain')
 async def plain():ran.append(2);return 1
 r=x.invoke('service:az');assert r['ok'] is False and 'not an HTTP API' in r['error']
 async def run():return await x.ainvoke('service:plain')
 r=asyncio.run(run());assert r['ok'] is False and 'not an HTTP API' in r['error']
 assert ran==[] and all_contexts()==()
def test_query_overflow_keeps_failure():
 x=bl(max_queries=1)
 with x.capture():
  x.record_query('SELECT 1',duration_ms=2);x.record_query('SELECT broken',duration_ms=3,error='missing column')
 e=x.storage.list()[0];assert any(q.error for q in e.queries);assert e.query_count==2
def test_legacy_crypto_read():
 from jscoup.crypto import EncryptingStorage,generate_key,encrypt_text
 k=generate_key();s=MemoryStorage();e=EventRecord(params={'name':encrypt_text('Alice',k)});s.save(e)
 assert EncryptingStorage(s,k).get(e.id).params=={'name':'Alice'}
@pytest.mark.parametrize('kind',['timeout','column'])
def test_diagnosis_specificity(kind):
 from jscoup.analyzers import AnalyzerEngine,AnalysisInput
 if kind=='timeout':
  d=AnalyzerEngine().analyze(AnalysisInput(exception=TimeoutError('network operation timed out'),error_type='TimeoutError',error_module='builtins',error_message='network operation timed out'));assert d.category!='database'
 else:
  d=AnalyzerEngine().analyze(AnalysisInput(error_type='UndefinedColumn',error_module='psycopg.errors',error_message='column "foo" does not exist'));assert d.subtype!='missing_table'
def test_storage_issue_grouping(tmp_path):
 from jscoup.storage.sql import SqlStorage
 from jscoup.storage.sqlite import SQLiteStorage
 stores=[MemoryStorage(),SQLiteStorage(str(tmp_path/'s.db')),SqlStorage('sqlite:///:memory:')]
 for s in stores:
  for i in range(2):s.save(EventRecord(status='error',fingerprint='same',name='f'+str(i),path='/'+str(i),error_type='ValueError',error_message='x'))
 assert [len(s.issues()) for s in stores]==[1,1,1]
@pytest.fixture
def mongo(monkeypatch):
 import pymongo,mongomock
 monkeypatch.setattr(pymongo,'MongoClient',mongomock.MongoClient)
 from jscoup.storage.mongo import MongoStorage
 return MongoStorage()
def test_mongo_zero_limit(mongo):
 mongo.save(EventRecord(name='one'));assert mongo.list(limit=0)==[]
def test_mongo_search_is_literal(mongo):
 mongo.save(EventRecord(name='abc'));mongo.save(EventRecord(name='a.b'));assert mongo.count(search='.')==1
def test_mongo_invalid_regex_safe(mongo):
 mongo.save(EventRecord(name='abc'));assert mongo.count(search='[')==0
def test_ssh_real_constructor_compatible():
 from jscoup.storage.connections import SSHTunnel
 t=SSHTunnel(ssh_host='127.0.0.1',ssh_username='synthetic',ssh_password='synthetic',remote_bind_host='127.0.0.1',remote_bind_port=5432);t.stop()
def test_ssh_binds_loopback(monkeypatch):
 from jscoup.storage.ssh import SSHTunnel
 import paramiko
 class Client:
  def load_system_host_keys(self):pass
  def set_missing_host_key_policy(self,p):assert isinstance(p,paramiko.RejectPolicy)
  def connect(self,**kw):pass
  def get_transport(self):return self
  def close(self):pass
 monkeypatch.setattr(paramiko,'SSHClient',Client)
 t=SSHTunnel(ssh_host='bastion',remote_bind_host='db',remote_bind_port=5432)
 try:
  t.start();assert t._server.server_address[0]=='127.0.0.1'
 finally:t.stop()
def test_connection_ini_percent_password(tmp_path):
 from jscoup.storage.connections import load_connection_file
 p=tmp_path/'db.ini';p.write_text('[connection]\npassword = abc%def\n');assert load_connection_file(str(p))['password']=='abc%def'
def test_usage_guide_config_example():assert JSCoup(storage=MemoryStorage(),dashboard_username='admin',dashboard_password='synthetic')
@pytest.mark.parametrize('path',['/api/events','/api/issues','/api/summary'])
def test_window_validation_complete(path):assert bl().dashboard.handle(path,query={'window':'garbage'}).status==400
def test_gateway_logs_rate_limit(tmp_path):
 x=bl(gateway_enabled=True,gateway_db_path=str(tmp_path/'gw.db'),gateway_rate_limit=1)
 x.gateway.create_user('test','test','synthetic',allowed_target_ids='*');token=x.gateway.login('test','synthetic')['token'];h={'Authorization':'Bearer '+token}
 assert x.dashboard.handle('/gw/my-logs',headers=h).status==200
 assert x.dashboard.handle('/gw/my-logs',headers=h).status==429
@pytest.mark.parametrize('style',['flask','fastapi'])
def test_real_http_replay(style):
 import http.server
 class H(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   self.send_response(200 if self.path=='/users/7' else 404);self.end_headers();self.wfile.write(b'{}')
  def do_POST(self):
   obj=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
   self.send_response(200 if self.path=='/items?limit=2' and obj=={'name':'sample'} else 422);self.end_headers();self.wfile.write(b'{}')
  def log_message(self,*a):pass
 server=http.server.HTTPServer(('127.0.0.1',0),H);t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
 try:
  x=bl(base_url='http://127.0.0.1:'+str(server.server_port))
  if style=='flask':
   from flask import Flask
   app=Flask('test')
   @app.get('/users/<int:user_id>')
   def user(user_id):return {'id':user_id}
   x.install(app);target='http:GET:/users/<int:user_id>';params={'user_id':7}
  else:
   from fastapi import FastAPI
   from pydantic import BaseModel
   app=FastAPI()
   class Item(BaseModel):name:str
   @app.post('/items')
   def item(item:Item,limit:int=1):return {'ok':True}
   x.install(app);target='http:POST:/items';params={'name':'sample','limit':2}
  r=x.invoke(target,params=params);assert r['status_code']==200,r
 finally:server.shutdown();server.server_close();t.join()
def test_fixed_core_boundaries(tmp_path):
 from jscoup.gateway import GatewayStore
 x=bl()
 with x.capture() as c:c.headers={'X-Api-Key':'SYNTHETIC_HEADER'}
 assert 'SYNTHETIC_HEADER' not in payload(x)
 @x.watch(name='cancel')
 async def f():raise asyncio.CancelledError()
 async def run():
  try:await f()
  except asyncio.CancelledError:pass
  assert all_contexts()==()
 asyncio.run(run())
 a=GatewayStore(str(tmp_path/'g.db'));b=GatewayStore(str(tmp_path/'g.db'));u=a.create_user('test','test','pw','*');token=a.login('test','pw')['token']
 assert b.authenticate(token);a.revoke(u.id);assert b.authenticate(token) is None
def test_missing_encryption_env_fails_closed(monkeypatch):
 from jscoup.projectconfig import ProjectConfig
 monkeypatch.delenv('JSCOUP_REVIEW_MISSING',raising=False)
 with pytest.raises(ValueError):ProjectConfig.from_dict({'encryption_key':'env:JSCOUP_REVIEW_MISSING'})
def test_secret_reference_survives_config_save(tmp_path,monkeypatch):
 from jscoup.projectconfig import ProjectConfig,save
 monkeypatch.setenv('JSCOUP_REVIEW_SECRET','SYNTHETIC_ENV_SECRET')
 c=ProjectConfig.from_dict({'dashboard_password':'env:JSCOUP_REVIEW_SECRET'});p=tmp_path/'cfg.json';save(c,str(p))
 assert 'SYNTHETIC_ENV_SECRET' not in p.read_text()
def test_startup_lock_timeout_never_writes(tmp_path,monkeypatch):
 import jscoup.projectconfig as p
 monkeypatch.setattr(p,'_acquire_startup_lock',lambda *a:False)
 with pytest.raises((TimeoutError,RuntimeError)):p.load_or_create(str(tmp_path/'cfg.json'))
def test_gateway_put_reachable_through_flask(tmp_path):
 from flask import Flask
 app=Flask('gw')
 @app.put('/resource')
 def resource():return {'ok':True}
 x=bl(gateway_enabled=True,gateway_db_path=str(tmp_path/'g.db'));x.install(app)
 x.gateway.set_public('http:PUT:/resource',True)
 # No actual replay needed: test integration forwards supported verb to policy layer.
 x.simulator.invoke=lambda *a,**k:{'ok':True,'status_code':200,'response':{}}
 assert app.test_client().put('/__jscoup/gw/http:PUT:/resource').status_code==200
def test_standalone_http_lifecycle(tmp_path):
 import urllib.request,urllib.error,http.cookiejar
 x=JSCoup(storage=MemoryStorage(),dashboard_username='admin',dashboard_password='synthetic',dashboard_session_db_path=str(tmp_path/'sessions.db'))
 s=x.run_dashboard(port=0)
 base='http://127.0.0.1:'+str(s.server_port)
 op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 try:
  assert op.open(base+'/').status==200
  with pytest.raises(urllib.error.HTTPError) as ex:op.open(base+'/api/health')
  assert ex.value.code==401
  req=urllib.request.Request(base+'/api/login',data=json.dumps({'username':'admin','password':'synthetic'}).encode(),headers={'Content-Type':'application/json'})
  assert op.open(req).status==200
  assert op.open(base+'/api/health').status==200
  assert op.open(urllib.request.Request(base+'/api/logout',data=b'{}')).status==200
  with pytest.raises(urllib.error.HTTPError):op.open(base+'/api/health')
 finally:s.shutdown();s.server_close()
@pytest.mark.parametrize('feature,path,method',[('code_audit','/api/audit','audit_code')])
def test_feature_flag_disables_capability(feature,path,method,tmp_path):
 from jscoup.projectconfig import ProjectConfig,save
 p=tmp_path/'cfg.json';save(ProjectConfig(dashboard_password='synthetic',features={feature:False}),str(p))
 x=JSCoup.from_config_file(path=str(p),storage=MemoryStorage(),encryption_key=None,dashboard_local_dev=True,dashboard_username=None)
 called=[]
 setattr(x,method,lambda **kw:called.append(True) or [])
 response=x.dashboard.handle(path,method='POST',body=b'{}')
 assert not called
