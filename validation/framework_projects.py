import os,sys,json,time,threading,statistics,urllib.request,urllib.error,tempfile,pathlib
from wsgiref.simple_server import make_server,WSGIRequestHandler
framework=sys.argv[1]; mode=sys.argv[2]
from jscoup import JSCoup,SQLiteStorage
root=pathlib.Path(tempfile.mkdtemp(prefix='project_',dir=str(pathlib.Path(__file__).parent)))
os.chdir(root)
x=JSCoup(storage=SQLiteStorage(str(root/'events.db')),dashboard_username='review',dashboard_password='test-only-password',capture_success=mode=='all') if mode!='baseline' else None
if framework=='flask':
 from flask import Flask,request,jsonify
 import sqlite3
 if x:x.watch_sqlite()
 app=Flask(__name__)
 def db():return sqlite3.connect(str(root/'app.db'))
 with db() as c:c.execute('create table items(id integer primary key,name text)')
 @app.route('/items',methods=['POST'])
 def create():
  with db() as c:
   cur=c.execute('insert into items(name) values(?)',(request.json['name'],)); ident=cur.lastrowid
  return jsonify(id=ident),201
 @app.route('/items/<int:item_id>')
 def get(item_id):
  with db() as c:row=c.execute('select name from items where id=?',(item_id,)).fetchone()
  return jsonify(id=item_id,name=row[0]) if row else (jsonify(error='missing'),404)
 @app.route('/fail')
 def fail():raise ValueError('intentional project failure')
 if x:x.install(app)
else:
 from django.conf import settings
 settings.configure(SECRET_KEY='test-only',DEBUG=False,ALLOWED_HOSTS=['127.0.0.1'],ROOT_URLCONF=__name__,MIDDLEWARE=['jscoup.integrations.django.JSCoupMiddleware'] if x else [],DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':str(root/'app.db')}},INSTALLED_APPS=[],JSCOUP=x)
 import django;django.setup()
 from django.db import models,connection
 class Item(models.Model):
  name=models.CharField(max_length=100)
  class Meta:app_label='review'
 with connection.schema_editor() as editor:editor.create_model(Item)
 from django.http import JsonResponse
 from django.urls import path
 def create(request):return JsonResponse({'id':Item.objects.create(name=json.loads(request.body)['name']).pk},status=201)
 def get(request,item_id):
  item=Item.objects.filter(pk=item_id).first()
  return JsonResponse({'id':item.pk,'name':item.name}) if item else JsonResponse({'error':'missing'},status=404)
 def fail(request):raise ValueError('intentional project failure')
 urlpatterns=[path('items',create),path('items/<int:item_id>',get),path('fail',fail)]
 if x:
  from jscoup.integrations.django import jscoup_urls
  urlpatterns+=jscoup_urls(x)
 from django.core.checks import run_checks
 assert not run_checks()
 from django.core.wsgi import get_wsgi_application
 app=get_wsgi_application()
class Quiet(WSGIRequestHandler):
 def log_message(self,*args):pass
server=make_server('127.0.0.1',0,app,handler_class=Quiet)
def serve():
 if framework=='django' and os.environ.get('WRAP_IN_WORKER'):
  from jscoup.dbwatch import instrument_django
  instrument_django()
 server.serve_forever()
threading.Thread(target=serve,daemon=True).start();base='http://127.0.0.1:'+str(server.server_port)
def req(path,data=None,headers=None):
 r=urllib.request.Request(base+path,data=json.dumps(data).encode() if data else None,headers={'Content-Type':'application/json',**(headers or {})})
 try:
  with urllib.request.urlopen(r) as s:return s.status,s.read(),dict(s.headers)
 except urllib.error.HTTPError as s:return s.code,s.read(),dict(s.headers)
checks={};checks['create']=req('/items',{'name':'widget'})[0]==201;checks['read']=json.loads(req('/items/1')[1])=={'id':1,'name':'widget'};checks['missing']=req('/items/999')[0]==404;checks['exception']=req('/fail')[0]==500
if x:
 checks['dashboard_protected']=req('/__jscoup/api/health')[0]==401
 login=req('/__jscoup/api/login',{'username':'review','password':'test-only-password'});cookie=login[2].get('Set-Cookie','').split(';')[0]
 checks['login']=login[0]==200;checks['authenticated']=req('/__jscoup/api/health',headers={'Cookie':cookie})[0]==200
 targets=x.registry.all();target=next((t for t in targets if t.path and 'item_id' in t.path),None)
 if target:
  replay=x.invoke(target.id,{'item_id':1},base_url=base);checks['replay']=bool(replay.get('ok'));checks['replay_detail']=replay
 events=x.storage.list(limit=100);checks['captured_exception']=any(e.error_type=='ValueError' for e in events);checks['sql_captured']=any(e.queries for e in events)
for i in range(10):req('/items/1')
times=[]
for i in range(150):
 t=time.perf_counter();assert req('/items/1')[0]==200;times.append((time.perf_counter()-t)*1000)
server.shutdown()
print(json.dumps({'framework':framework,'mode':mode,'checks':checks,'median_ms':statistics.median(times),'p95_ms':sorted(times)[142],'samples':150,'project_dir':str(root)},default=str))
