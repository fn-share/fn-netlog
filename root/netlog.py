# root/netlog.py

import os, time, base64, json, traceback
from binascii import hexlify, unhexlify
from email.utils import formatdate

import logging
logger = logging.getLogger(__name__)

from . import app
from flask import request, render_template

from nbc import wallet
from nbc.util import base36
from .ssi_login import verify_auth, ripemd_hash, refresh_periods, WEBSITE_REALM, ssi_login_init

_data_dir = os.environ.get('LOCAL_DIR','./data')
os.makedirs(_data_dir,exist_ok=True)

#---- wrap files

_sample_md_txt = '样例文件\n=======\n\n&nbsp;\n\n### 1. 章标题\n\n#### 1.1 节标题\n\n这是正文\n'
_sample_md_txt = _sample_md_txt.encode('utf-8')

use_s3_file = os.environ.get('ENV_cloud') == 'AWS'

if use_s3_file:
  from io import BytesIO
  import boto3, botocore
  
  _bucket_name = 'fns-netlog'
  _aws_region = os.environ.get('AWS_REGION','ap-east-1')
  s3Client = boto3.client('s3',region_name=_aws_region)
  # s3Disk = boto3.resource('s3',region_name=_aws_region)
  # s3Bucket = s3Disk.Bucket(_bucket_name)

def md_base_dir(login_sess):
  s = os.path.join(_data_dir,'netlog',login_sess)
  os.makedirs(s,exist_ok=True)
  return s

def ensure_md_edt_file(edt_file, cfg_file):
  if not os.path.isfile(edt_file):
    with open(edt_file,'wb') as f:
      f.write(_sample_md_txt)
  if not os.path.isfile(cfg_file):
    with open(cfg_file,'wb') as f:
      f.write(b'{}')

# def is_s3_404(e):
#   return str(e).find('(404)') >= 0  # 'An error occurred (404) when calling ...'

def read_file_from_s3(path, modiTmAlso=False):
  try:
    res = s3Client.get_object(Bucket=_bucket_name,Key=path)
    metadata = res.get('ResponseMetadata',{})
    if metadata.get('HTTPStatusCode') == 200:
      modi = 0
      if modiTmAlso:
        dt = res.get('LastModified')
        if dt: modi = int(time.mktime(dt.timetuple()))
      return (modi,res.Body.read())
    else: raise Exception('read s3 failed')
  
  except s3Client.exceptions.NoSuchKey:
    return (0,None)
  
  '''
  try:
    s3file = s3Disk.Object(_bucket_name,path)
    payload = BytesIO()
    s3file.download_fileobj(payload)  # maybe error, 404
    payload.seek(0,0)
    
    modi = 0
    if modiTmAlso and s3file.last_modified:
      tupleDate = tuple(s3file.last_modified.timetuple())
      modi = int(time.mktime(tupleDate))
    return (modi,payload.read())
  
  except botocore.exceptions.ClientError as e:
    if is_s3_404(e):
      return (0,None)
    else: raise  '''

def read_cfg_from_s3(cfg_path):
  try:
    res = s3Client.get_object(Bucket=_bucket_name,Key=cfg_path)
    metadata = res.get('ResponseMetadata',{})
    if metadata.get('HTTPStatusCode') == 200:
      return json.load(res.Body.read().decode('utf-8'))
    else: raise Exception('read s3 failed')
  
  except s3Client.exceptions.NoSuchKey:
    return None
  '''
  try:
    s3file = s3Disk.Object(_bucket_name,cfg_path)
    payload = BytesIO()
    s3file.download_fileobj(payload)  # maybe error, 404
    payload.seek(0,0)
    return json.load(payload)
  except botocore.exceptions.ClientError as e:
    if is_s3_404(e):
      return None
    else: raise  '''

def get_publish_info(login_sess):
  info = { 'login_session':login_sess, 'content':'', 'modify_at':0 }
  
  if use_s3_file:
    idx_path = login_sess + os.path.sep + 'index.md'
    last_modi,buf = read_file_from_s3(idx_path,True)
    if buf is None: buf = b''
    
    info['content'] = base64.b64encode(buf).decode('utf-8')
    info['file_size'] = len(buf)
    info['modify_at'] = last_modi
  
  else:
    base_dir = md_base_dir(login_sess)
    idx_file = os.path.join(base_dir,'index.md')
    
    if os.path.isdir(base_dir) and os.path.isfile(idx_file):
      st = os.stat(idx_file)
      with open(idx_file,'rb') as f:
        info['content'] = base64.b64encode(f.read()).decode('utf-8')
        info['modify_at'] = int(st.st_mtime)
        info['file_size'] = st.st_size
  
  return info

def desc_editing_state(cfg, tz=0):
  if cfg is None:
    return (False,'尚未开始编辑。\n')
  
  opened = bool(cfg.get('opened',0))
  last_archive = cfg.get('archive_time',0)
  last_editing = cfg.get('editing_time',0)
  if not last_archive:
    desc = '本文尚未发布。\n\n'
  else:
    desc = '本文在 %s 最后发布。\n\n' % time.strftime('%y-%m-%d %H:%M:%S',tuple(time.gmtime(last_archive-tz)))
  
  if not last_editing:
    desc += '本文尚未提交更新。\n'
  else:
    desc += '用户（指纹 %s）于 %s 最后更新。\n' % (cfg.get('last_editor',''),time.strftime('%y-%m-%d %H:%M:%S',tuple(time.gmtime(last_editing-tz))))
  
  curr_opener = cfg.get('locker_opener','')
  curr_open_tm = cfg.get('last_open',0)
  if opened and curr_opener and int(time.time()) - curr_open_tm < _locker_expired:
    tm_desc = time.strftime('%y-%m-%d %H:%M:%S',tuple(time.gmtime(curr_open_tm-tz)))
    desc += '\n用户（指纹 %s）于 %s 开锁，正在编辑中 ...\n' % (int(curr_opener,16),tm_desc)
  
  return (opened,desc)

def get_editing_info(login_sess, tz=0):
  if use_s3_file:
    cfg_path = login_sess + os.path.sep + 'editing.cfg'
    cfg = read_cfg_from_s3(cfg_path)
    
    if cfg is None:  # inexistent yet
      edt_path = login_sess + os.path.sep + 'editing.md'
      s3Client.put_object(Bucket=_bucket_name,Key=edt_path,Body=_sample_md_txt)
      # s3Bucket.put_object(Key=edt_path,Body=_sample_md_txt)
      s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=b'{}')
      # s3Bucket.put_object(Key=cfg_path,Body=b'{}')
  
  else:
    base_dir = md_base_dir(login_sess)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = None
    if os.path.isfile(cfg_file):
      with open(cfg_file,'rb') as f:
        cfg = json.load(f)
  
  return desc_editing_state(cfg,tz)

def get_editing_text(login_sess):
  if use_s3_file:
    edt_path = login_sess + os.path.sep + 'editing.md'
    last_modi,buf = read_file_from_s3(edt_path,False)
    
    if buf is None:
      buf = _sample_md_txt
      cfg_path = login_sess + os.path.sep + 'editing.cfg'
      s3Client.put_object(Bucket=_bucket_name,Key=edt_path,Body=buf)
      # s3Bucket.put_object(Key=edt_path,Body=buf)
      s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=b'{}')
      # s3Bucket.put_object(Key=cfg_path,Body=b'{}')
    return buf
  
  else:
    base_dir = md_base_dir(login_sess)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    with open(edt_file,'rb') as f:
      return f.read()

def put_editing_text(login_sess, by_gncd, figerprint, ctx, now):
  if use_s3_file:
    cfg_path = login_sess + os.path.sep + 'editing.cfg'
    cfg = read_cfg_from_s3(cfg_path) or {}
    
    # when current login by green card, and not same unlock operator, and still before _locker_expired
    if by_gncd and cfg.get('locker_opener') != figerprint and (now - cfg.get('last_open',0)) < _locker_expired:
      return 'UNLOCK_BY_OTHER'
    
    cfg['last_editor'] = int(figerprint,16)
    cfg['editing_time'] = now
    
    edt_path = login_sess + os.path.sep + 'editing.md'
    s3Client.put_object(Bucket=_bucket_name,Key=edt_path,Body=ctx)
    # s3Bucket.put_object(Key=edt_path,Body=ctx)
    s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
    # s3Bucket.put_object(Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
    return 'OK'
  
  else:
    base_dir = md_base_dir(login_sess)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    if os.path.isfile(cfg_file):
      with open(cfg_file,'rb') as f:
        cfg = json.load(f)
    else: cfg = {}
    
    # when current login by green card, and not same unlock operator, and still before _locker_expired
    if by_gncd and cfg.get('locker_opener') != figerprint and (now - cfg.get('last_open',0)) < _locker_expired:
      return 'UNLOCK_BY_OTHER'
    
    with open(edt_file,'wb') as f:
      with open(cfg_file,'wt') as f2:
        cfg['last_editor'] = int(figerprint,16)
        cfg['editing_time'] = now
        json.dump(cfg,f2)
      f.write(ctx)
    return 'OK'

def modify_locker(action, login_sess, by_gncd, figerprint, now, tz=0):
  if use_s3_file:
    need_save = False
    cfg_path = login_sess + os.path.sep + 'editing.cfg'
    cfg = read_cfg_from_s3(cfg_path)
    if cfg is None:
      cfg = {}
      need_save = True
    
    if cfg.get('opened'):  # already opened
      if by_gncd and cfg.get('locker_opener') != figerprint and (now-cfg.get('last_open',0)) < _locker_expired:
        return 'UNLOCK_BY_OTHER'   # login by green card, and not same unlock operator, and still before _locker_expired
    
    if action == 'open_locker':
      if not cfg.get('opened',False):
        cfg['opened'] = True   # open it
        cfg['locker_opener'] = figerprint
        cfg['last_open'] = now
        need_save = True
      # else, already unlocked
    else:   # 'close_locker'
      if cfg.get('opened',False):
        cfg['opened'] = False  # close it
        need_save = True
      # else, already locked
    
    if need_save:
      s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
      # s3Bucket.put_object(Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
    
    return desc_editing_state(cfg,tz)
  
  else:
    base_dir = md_base_dir(login_sess)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = None; need_save = False
    with open(cfg_file,'rt') as f:
      cfg = json.load(f)
      if cfg.get('opened'):  # already opened
        if by_gncd and cfg.get('locker_opener') != figerprint and (now-cfg.get('last_open',0)) < _locker_expired:
          return 'UNLOCK_BY_OTHER'   # login by green card, and not same unlock operator, and still before _locker_expired
      
      if action == 'open_locker':
        if not cfg.get('opened'):
          cfg['opened'] = True   # open it
          cfg['locker_opener'] = figerprint
          cfg['last_open'] = now
          need_save = True
        # else, already unlocked
      else:   # 'close_locker'
        if cfg.get('opened'):
          cfg['opened'] = False  # close it
          need_save = True
        # else, already locked
    
    if need_save:
      with open(cfg_file,'wt') as f:
        json.dump(cfg,f)
    
    return desc_editing_state(cfg,tz)

def publish_editing_text(login_sess, now, tz=0):
  if use_s3_file:
    cfg_path = login_sess + os.path.sep + 'editing.cfg'
    cfg = read_cfg_from_s3(cfg_path) or {}
    
    if cfg.get('archive_time',0) > cfg.get('editing_time',now):
      return 'NO_CHANGE'
    
    edt_file = login_sess + os.path.sep + 'editing.md'
    last_modi,buf = read_file_from_s3(edt_file,False)
    if buf is None:
      return 'NO_EDITING'
    
    idx_path = login_sess + os.path.sep + 'index.md'
    s3Client.put_object(Bucket=_bucket_name,Key=idx_path,Body=buf)
    # s3Bucket.put_object(Key=idx_path,Body=buf)
    
    cfg['archive_time'] = now
    s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
    # s3Bucket.put_object(Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
  
  else:
    base_dir = md_base_dir(login_sess)
    idx_file = os.path.join(base_dir,'index.md')
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = json.load(open(cfg_file,'rt'))
    if cfg.get('archive_time',0) > cfg.get('editing_time',now):
      return 'NO_CHANGE'
    
    with open(edt_file,'rb') as f:
      with open(idx_file,'wb') as f2:
        f2.write(f.read())
    
    cfg['archive_time'] = now
    with open(cfg_file,'wt') as f:
      json.dump(cfg,f)
  
  return desc_editing_state(cfg,tz)

#--

MAX_IMAGE_FILE = 36

_img_ext = set(['gif','png','jpg','svg','webp'])
_img_types = { 'gif':'image/gif', 'png':'image/png',
  'jpg':'image/jpeg', 'svg':'image/svg+xml', 'webp':'image/webp' }

def list_s3_img_files(login_sess, max_files=MAX_IMAGE_FILE):
  img_path = login_sess + '/res'
  resp = s3Client.list_objects(Bucket=_bucket_name,Delimiter='/',Prefix=img_path,MaxKeys=max_files)
  bFiles = resp.get('Contents') or []
  img_path += '/'
  
  ret = []
  for aFile in bFiles:  # aFile is {Key,LastModified,ETag,Size,StorageClass,Owner}
    fname = aFile['Key'].replace(img_path,'')
    if os.path.splitext(fname)[-1] in _img_types:
      ret.append(fname)
  return ret

def read_img_from_s3(path, headers):
  try:
    kwarg = { 'Bucket':_bucket_name, 'Key':path }
    none_match = headers.get('If-None-Match',None)
    if none_match is not None:
      kwarg['IfNoneMatch'] = none_match
    modi_since = headers.get('If-Modified-Since',None)
    if modi_since is not None:
      kwarg['IfModifiedSince'] = modi_since
    
    res = s3Client.get_object(**kwarg)
    metadata = res.get('ResponseMetadata',{})
    status = metadata.get('HTTPStatusCode')
    if status == 304:
      return ('NOT_MODIFIED',304)
    elif status == 200:
      s3_headers = res.get('HTTPHeaders',{})
      ctx_len = s3_headers.get('content-length')
      if ctx_len: headers['Content-Length'] = ctx_len
      etag = s3_headers.get('etag')
      if etag: headers['ETag'] = etag
      last_modi = s3_headers.get('last-modified')
      if last_modi: headers['Last-Modified'] = last_modi
      
      return (res.Body,200,headers)
    else: return ('',status)  # meet error
  
  except s3Client.exceptions.NoSuchKey:
    return ('INEXISTENT',404)

def write_s3_file(login_sess, img_file, ctx, ctx_type):
  b = list_s3_img_files(login_sess)
  if len(b) >= MAX_IMAGE_FILE and img_file in b:
    return ('EXCEED_IMAGE_FILE_NUM',400)
  
  path = login_sess + '/' + img_file
  s3Client.put_object(Bucket=_bucket_name,Key=path,Body=ctx,ContentType=ctx_type)
  return 'OK'

def get_img_files(login_sess):
  if use_s3_file:
    ret = list_s3_img_files(login_sess)
  
  else:
    ret = []
    img_dir = md_base_dir(login_sess + os.path.sep + 'res')
    files = os.listdir(img_dir)
    for item in files:
      if item[:1] == '.': continue
      if os.path.splitext(item)[-1] in _img_ext and os.path.isfile(os.path.join(img_dir,item)):
        ret.append(item)
  
  return json.dumps(ret)

def read_img_file(login_sess, img_file, mime_type):
  if use_s3_file:
    img_path = login_sess + '/res/' + img_file
    return read_img_from_s3(img_path,{'Content-Type':mime_type})
  else:
    img_dir = md_base_dir(login_sess + os.path.sep + 'res')
    img_file = os.path.join(img_dir,img_file)    
    if not os.path.isfile(img_file):
      return ('INEXISTENT',404)
    
    # st = os.stat(img_file)
    # modi_tm = formatdate(st.st_mtime,usegmt=True)
    # headers = {'Content-Type':mine_type,'Last-Modified':modi_tm}
    with open(img_file,'rb') as f:
      # for local image file, we not process 304, since image file may changing
      return (f.read(),200,{'Content-Type':mine_type})

def write_img_file(login_sess, img_file, ctx):
  if len(ctx) > 0x19000:  # more than 100k
    return ('EXCEED_SIZE',400)
  
  ext = os.path.splitext(img_file)[-1]
  mime_type = None
  if ext:
    mime_type = _img_types.get(ext[1:])
  if not mime_type: return ('UNKNOWN_FORMAT',400)
  
  if use_s3_file:
    return write_s3_file(login_sess,img_file,ctx,mime_type)
  
  else:
    img_dir = md_base_dir(login_sess + os.path.sep + 'res')
    img_file = os.path.join(img_dir,img_file)    
    
    if os.path.isfile(img_file):  # just overwrite
      pass
    else:
      b = os.listdir(img_dir); b2 = []
      for item in b:
        if item[:1] == '.': continue
        tmp = item.split('.')
        if len(tmp) >= 2 and tmp[-1] in _img_ext:
          if os.path.isfile(img_dir + os.path.sep + item):
            b2.append(item)
      
      if len(b2) >= MAX_IMAGE_FILE:
        return ('EXCEED_IMAGE_FILE_NUM',400)
    
    with open(img_file,'wb') as f:
      f.write(ctx)
    return 'OK'

#----

_route_prefix = os.environ.get('ROUTE_PREFIX','')

_real_website = ''
_app_admin_pubkey = ''
_app_strategy_str = '{}'

_locker_expired = 86400    # default is 1 day, would config as: refresh_period*(session_limit+1)

@app.route(_route_prefix+'/')
@app.route(_route_prefix+'/index.html')
def netlog_index_page():
  info = { 'real_website': _real_website,
    'app_admin_pubkey': _app_admin_pubkey,
    'app_strategy': _app_strategy_str }
  return render_template('netlog_index.html',info=info)

@app.route(_route_prefix+'/md/<login_sess>')
def get_netlog_md(login_sess):
  try:
    info = get_publish_info(login_sess)
    return render_template('netlog_show_md.html',info=info)
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route(_route_prefix+'/visa/<card_hash>')
def get_netlog_visa(card_hash):
  return render_template('netlog_fetch_visa.html',info={'hash':card_hash})

@app.route(_route_prefix+'/stat')
def get_netlog_stat():
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    # step 2: get login_sess and stat resource
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    tz = int(request.args.get('tz','-480')) * 60
    opened, desc = get_editing_info(login_sess2,tz)
    
    return { 'path':'md/'+login_sess2, 'opened':opened, 'desc':desc }
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route(_route_prefix+'/editing', methods=['GET','POST'])
def do_netlog_editing():
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    # step 2: get login_sess and locate resource
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    if request.method == 'GET':
      return get_editing_text(login_sess2)
    
    else:  # request.method == 'POST'
      if role != b'editor' and role != b'manager':
        return ('NOT_SUPPORT',400)
      
      data = request.get_json(force=True,silent=True)
      ctx = base64.b64decode(data['content'])  # ctx can be '' that means reset content
      if len(ctx) > 0x100000:  # 0x100000 is 1M
        return ('LARGE_THAN_1M',400)
      
      now = int(time.time())
      ret = put_editing_text(login_sess2,ord(sdat[:1]) < 0x80,sid[:4].hex(),ctx,now)
      
      if ret == 'UNLOCK_BY_OTHER':
        return (ret,400)
      else: return {'result':ret}
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route(_route_prefix+'/locker', methods=['POST'])
def post_netlog_locker():
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    if role != b'editor' and role != b'manager':
      return ('NOT_SUPPORT',400)
    
    # step 2: get and check parameter
    data = request.get_json(force=True,silent=True)
    tm = int(data.get('time',0))
    tz = int(data.get('tz',-480)) * 60
    action = data.get('action','')
    pubkey = unhexlify(data.get('pubkey',''))
    self_sign = unhexlify(data.get('signature',''))
    if not tm or (action != 'open_locker' and action != 'close_locker') or len(pubkey) != 33 or ord(pubkey[:1]) not in (2,3) or len(self_sign) < 64:
      return ('INVALID_PARAMTER',400)
    
    if ripemd_hash(pubkey) != sid[:20]:
      return ('INVALID_ACCOUNT',400)
    
    now = int(time.time())
    if abs(now - tm) > 90:   # should be nearby in 1.5 minutes
      return ('INVALID_TIME',400)
    
    # step 3: verify signature
    wa = wallet.Address(pub_key=pubkey)
    s = b'%s+%s+%s:%i' % (WEBSITE_REALM,role,action.encode('utf-8'),tm)
    if not wa.verify_ex(s,self_sign,single=True):
      return ('INVALID_SIGNATURE',401)
    
    # step 4: process unlock or lock and return
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    ret = modify_locker(action,login_sess2,ord(sdat[:1]) < 0x80,sid[:4].hex(),now,tz)
    if isinstance(ret,tuple):
      opened, desc = ret
      return { 'result':'OK', 'path':'md/'+login_sess2, 'opened':opened, 'desc':desc }
    else: return (ret,400)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route(_route_prefix+'/publish', methods=['POST'])
def post_netlog_publish():
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    if role != b'manager':
      return ('NOT_SUPPORT',400)
    
    # step 2: get and check parameter
    data = request.get_json(force=True,silent=True)
    tm = int(data.get('time',0))
    tz = int(data.get('tz',-480)) * 60
    pubkey = unhexlify(data.get('pubkey',''))
    self_sign = unhexlify(data.get('signature',''))
    if not tm or len(pubkey) != 33 or ord(pubkey[:1]) not in (2,3) or len(self_sign) < 64:
      return ('INVALID_PARAMTER',400)
    
    if ripemd_hash(pubkey) != sid[:20]:
      return ('INVALID_ACCOUNT',400)
    
    now = int(time.time())
    if abs(now - tm) > 90:   # should be nearby in 1.5 minutes
      return ('INVALID_TIME',400)
    
    # step 3: verify signature
    wa = wallet.Address(pub_key=pubkey)
    s = b'%s+%s+%s:%i' % (WEBSITE_REALM,role,b'archive',tm)
    if not wa.verify_ex(s,self_sign,single=True):
      return ('INVALID_SIGNATURE',401)
    
    # step 4: locate resource and publish new version
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    ret = publish_editing_text(login_sess2,now,tz)
    if isinstance(ret,tuple):
      opened, desc = ret
      return { 'result':'OK', 'path':'md/'+login_sess2, 'opened':opened, 'desc':desc }
    else: return (ret,400)  # 'NO_CHANGE' 'NO_EDITING'
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

#----

@app.route(_route_prefix+'/images')
def get_netlog_images():
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    # step 2: list image files
    return get_img_files(login_sess2)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route(_route_prefix+'/image/<img_file>', methods=['GET','POST'])
def get_post_netlog_image(img_file):
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    # step 2: get image file
    img_ext = img_file.rsplit('.',maxsplit=1)[-1]
    if img_ext not in _img_ext:
      return ('UNSUPPORT_IMG_FORMAT',400)
    mime_type = _img_types[img_ext]
    
    if request.method == 'GET':
      return read_img_file(login_sess2,img_file,mime_type)
    
    else:  # 'POST'
      img_data = request.get_data(as_text=True)  # data:image/png;bas64,...
      if img_data[:5] == 'data:':
        b = img_data.split(';base64,',maxsplit=1)
        if len(b) == 2:
          ctx = base64.b64decode(img_data[1])
          return write_img_file(login_sess2,img_file,ctx)
      return ('INVALID_IMAGE_DATA',400)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

#----

def netlog_init(config):
  global _real_website, _app_admin_pubkey, _app_strategy_str
  
  _real_website = config['real_website']
  _app_admin_pubkey = wallet.Address(priv_key=config['app_admin_wif'].encode('utf-8')).publicKey().hex()
  _app_strategy_str = json.dumps(config['strategy'],indent=None,separators=(',',':'))
  
  global _locker_expired
  stg = config['strategy']
  _locker_expired = refresh_periods[stg.get('session_type',1)&0x07] * (stg.get('session_limit',14)+1)
  
  ssi_login_init(config)
