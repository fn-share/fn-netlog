# root/netlog.py

import os, time, base64, json, traceback
from binascii import unhexlify
from email.utils import formatdate
from urllib.parse import quote

import logging
logger = logging.getLogger(__name__)

from . import app
from flask import request, render_template

from nbc import wallet
from nbc.util import base36

from .ssi_login import verify_auth, ripemd_hash, refresh_periods, WEBSITE_REALM

_data_dir = os.environ.get('LOCAL_DIR','./data')
os.makedirs(_data_dir,exist_ok=True)

#---- wrap files

_sample_md_txt = '样例文件\n=======\n\n&nbsp;\n\n### 1. 章标题\n\n#### 1.1 节标题\n\n这是正文\n'
_sample_md_txt = _sample_md_txt.encode('utf-8')

use_s3_file = os.environ.get('ENV_cloud') == 'AWS'

if use_s3_file:
  from io import BytesIO
  import boto3
  
  _bucket_name = os.environ.get('NETLOG_BUCKET','fns-netlog')
  s3Client = boto3.client('s3',region_name=os.environ.get('AWS_REGION','ap-east-1'))

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

def read_file_from_s3(path, modiTmAlso=False):
  try:
    res = s3Client.get_object(Bucket=_bucket_name,Key=path)
    metadata = res.get('ResponseMetadata',{})
    if metadata.get('HTTPStatusCode') == 200:
      modi = 0
      if modiTmAlso:
        dt = res.get('LastModified')
        # if dt: modi = int(time.mktime(dt.timetuple()))  # dt.timetuple() convert to localtime
        if dt: modi = int(dt.timestamp())
      return (modi,res['Body'].read())
    else: raise Exception('read s3 failed')
  
  except s3Client.exceptions.NoSuchKey:
    return (0,None)

def read_cfg_from_s3(cfg_path):
  try:
    res = s3Client.get_object(Bucket=_bucket_name,Key=cfg_path)
    metadata = res.get('ResponseMetadata',{})
    if metadata.get('HTTPStatusCode') == 200:
      return json.load(res['Body'])
    else: raise Exception('read s3 failed')
  
  except s3Client.exceptions.NoSuchKey:
    return None

def get_publish_info(login_sess, use_base64=True):
  info = { 'login_session':login_sess, 'content':'', 'modify_at':0 }
  
  if use_s3_file:
    idx_path = login_sess + os.path.sep + 'index.md'
    last_modi,buf = read_file_from_s3(idx_path,True)
    if buf is None: buf = b''
    
    if use_base64:
      info['content'] = base64.b64encode(buf).decode('utf-8')
    else: info['content'] = buf.decode('utf-8')
    info['file_size'] = len(buf)
    info['modify_at'] = last_modi
  
  else:
    base_dir = md_base_dir(login_sess)
    idx_file = os.path.join(base_dir,'index.md')
    
    if os.path.isdir(base_dir) and os.path.isfile(idx_file):
      st = os.stat(idx_file)
      with open(idx_file,'rb') as f:
        if use_base64:
          info['content'] = base64.b64encode(f.read()).decode('utf-8')
        else: info['content'] = f.read().decode('utf-8')
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
  
  auto_publish = bool(cfg.get('auto_publish',0))
  return (opened,desc,auto_publish)

def get_editing_info(login_sess, tz=0):
  if use_s3_file:
    cfg_path = login_sess + os.path.sep + 'editing.cfg'
    cfg = read_cfg_from_s3(cfg_path)
    
    if cfg is None:  # inexistent yet
      edt_path = login_sess + os.path.sep + 'editing.md'
      s3Client.put_object(Bucket=_bucket_name,Key=edt_path,Body=_sample_md_txt)
      s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=b'{}')
  
  else:
    base_dir = md_base_dir(login_sess)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = None
    if os.path.isfile(cfg_file):
      with open(cfg_file,'rt') as f:
        cfg = json.load(f)
  
  return desc_editing_state(cfg,tz)

def get_editing_text(login_sess):
  if use_s3_file:
    edt_path = login_sess + os.path.sep + 'editing.md'
    _, buf = read_file_from_s3(edt_path,False)
    
    if buf is None:
      buf = _sample_md_txt
      cfg_path = login_sess + os.path.sep + 'editing.cfg'
      s3Client.put_object(Bucket=_bucket_name,Key=edt_path,Body=buf)
      s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=b'{}')
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
    auto_pub = bool(cfg.get('auto_publish',0))
    
    # when current login by green card, and not same unlock operator, and still before _locker_expired
    if by_gncd and cfg.get('locker_opener') != figerprint and (now - cfg.get('last_open',0)) < _locker_expired:
      return 'UNLOCK_BY_OTHER'
    
    cfg['last_editor'] = int(figerprint,16)
    cfg['editing_time'] = now
    
    # save editor
    edt_path = login_sess + '/editing.md'
    s3Client.put_object(Bucket=_bucket_name,Key=edt_path,Body=ctx)
    
    # try publish
    if auto_pub:
      cfg['archive_time'] = now
      idx_path = login_sess + '/index.md'
      # s3Client.put_object(Bucket=_bucket_name,Key=idx_path,Body=ctx)
      s3Client.copy_object(Bucket=_bucket_name,Key=idx_path,CopySource={'Bucket':_bucket_name,'Key':edt_path})
    
    # save config
    s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
    return 'OK'
  
  else:
    base_dir = md_base_dir(login_sess)
    edt_file = os.path.join(base_dir,'editing.md')
    idx_file = os.path.join(base_dir,'index.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    if os.path.isfile(cfg_file):
      with open(cfg_file,'rt') as f:
        cfg = json.load(f)
    else: cfg = {}
    auto_pub = bool(cfg.get('auto_publish',0))
    
    # when current login by green card, and not same unlock operator, and still before _locker_expired
    if by_gncd and cfg.get('locker_opener') != figerprint and (now - cfg.get('last_open',0)) < _locker_expired:
      return 'UNLOCK_BY_OTHER'
    
    with open(edt_file,'wb') as f:
      f.write(ctx)
      if auto_pub:
        with open(idx_file,'wb') as f2:
          f2.write(ctx)
      
      with open(cfg_file,'wt') as f3:
        cfg['last_editor'] = int(figerprint,16)
        cfg['editing_time'] = now
        if auto_pub: cfg['archive_time'] = now
        json.dump(cfg,f3)
    
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

def set_auto_publish(auto_pub, login_sess, tz=0):
  if use_s3_file:
    cfg_path = login_sess + '/editing.cfg'
    cfg = read_cfg_from_s3(cfg_path) or {}
    
    old = cfg.get('auto_publish',False)
    if old != auto_pub:   # config changed
      cfg['auto_publish'] = auto_pub
      s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
  
  else:
    base_dir = md_base_dir(login_sess)
    idx_file = os.path.join(base_dir,'index.md')
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = json.load(open(cfg_file,'rt'))
    old = cfg.get('auto_publish',False)
    if old != auto_pub:   # config changed
      cfg['auto_publish'] = auto_pub
      with open(cfg_file,'wt') as f:
        json.dump(cfg,f)
  
  return desc_editing_state(cfg,tz)

def publish_editing_text(login_sess, now, tz=0):
  if use_s3_file:
    cfg_path = login_sess + '/editing.cfg'
    cfg = read_cfg_from_s3(cfg_path) or {}
    
    if cfg.get('archive_time',0) > cfg.get('editing_time',now):
      return 'NO_CHANGE'
    
    edt_file = login_sess + '/editing.md'
    _, buf = read_file_from_s3(edt_file,False)
    if buf is None:
      return 'NO_EDITING'
    
    idx_path = login_sess + '/index.md'
    s3Client.put_object(Bucket=_bucket_name,Key=idx_path,Body=buf)
    
    cfg['archive_time'] = now
    s3Client.put_object(Bucket=_bucket_name,Key=cfg_path,Body=json.dumps(cfg).encode('utf-8'))
  
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

_img_types = { '.gif':'image/gif', '.png':'image/png',
  '.jpg':'image/jpeg', '.svg':'image/svg+xml', '.webp':'image/webp' }

def list_s3_img_files(login_sess, max_files=MAX_IMAGE_FILE):
  img_path = login_sess + '/res/'
  resp = s3Client.list_objects(Bucket=_bucket_name,Delimiter='/',Prefix=img_path,MaxKeys=max_files)
  bFiles = resp.get('Contents') or []
  
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
      headers.pop('If-None-Match',None)      # reuse in reply
    modi_since = headers.get('If-Modified-Since',None)
    if modi_since is not None:
      kwarg['IfModifiedSince'] = modi_since
      headers.pop('If-Modified-Since',None)  # reuse in reply
    
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
      
      return (res['Body'],200,headers)
    else: return ('',status)  # meet error
  
  except s3Client.exceptions.NoSuchKey:
    return ('INEXISTENT',404)

def write_img_to_s3(login_sess, img_file, ctx, ctx_type):
  b = list_s3_img_files(login_sess)
  if len(b) >= MAX_IMAGE_FILE and img_file in b:
    return ('EXCEED_IMAGE_FILE_NUM',400)
  
  path = login_sess + '/res/' + img_file
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
      if os.path.splitext(item)[-1] in _img_types and os.path.isfile(os.path.join(img_dir,item)):
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
    # headers = {'Content-Type':mime_type,'Last-Modified':modi_tm}
    with open(img_file,'rb') as f:
      # for local image file, we not process 304, since image file may changing
      return (f.read(),200,{'Content-Type':mime_type})

def write_img_file(login_sess, img_file, ctx):
  if len(ctx) > 0x32000:  # more than 200k
    return ('EXCEED_SIZE',400)
  
  mime_type = _img_types.get(os.path.splitext(img_file)[-1],None)
  if not mime_type: return ('UNSUPPORT_IMG_FORMAT',400)
  
  if use_s3_file:
    return write_img_to_s3(login_sess,img_file,ctx,mime_type)
  
  else:
    img_dir = md_base_dir(login_sess + os.path.sep + 'res')
    img_file = os.path.join(img_dir,img_file)    
    
    if os.path.isfile(img_file):  # just overwrite
      pass
    else:
      b = os.listdir(img_dir); b2 = []
      for item in b:
        if item[:1] == '.': continue
        if os.path.splitext(item)[-1] in _img_types and os.path.isfile(img_dir + os.path.sep + item):
          b2.append(item)
      
      if len(b2) >= MAX_IMAGE_FILE:
        return ('EXCEED_IMAGE_FILE_NUM',400)
    
    with open(img_file,'wb') as f:
      f.write(ctx)
    return 'OK'

def rmv_img_file(login_sess, img_file):
  try:
    if use_s3_file:
      path = login_sess + '/res/' + img_file
      s3Client.delete_object(Bucket=_bucket_name,Key=path)
      return 'OK'
    
    else:
      img_dir = md_base_dir(login_sess + os.path.sep + 'res')
      img_file = os.path.join(img_dir,img_file)    
      
      if os.path.isfile(img_file):  # just overwrite
        os.remove(img_file)
      return 'OK'
  
  except:
    logger.warning(traceback.format_exc())
    return ('WRITE_FILE_ERROR',400)

#----

_rsp_website = ''
_app_admin_pubkey = ''
_app_strategy = {}

_locker_expired = 86400    # default is 1 day, would config as: refresh_period*(session_limit+1)

@app.route('/netlog/app_info')
def netlog_info():
  return {'rsp_website':_rsp_website,'app_admin_pubkey':_app_admin_pubkey,'app_strategy':_app_strategy}

@app.route('/netlog/')
@app.route('/netlog/index.html')
def netlog_index_page():
  return ('',302,{'Location':'/www/netlog_index.html'})

@app.route('/netlog/md/<login_sess>/res/<img_file>')
def get_netlog_md_img(login_sess, img_file):
  try:
    mime_type = _img_types.get(os.path.splitext(img_file)[-1],'')
    
    if use_s3_file:
      headers2 = {}
      none_match = request.headers.get('If-None-Match',None)
      if none_match is not None:
        headers2['IfNoneMatch'] = none_match
      modi_since = request.headers.get('If-Modified-Since',None)
      if modi_since is not None:
        headers2['IfModifiedSince'] = modi_since
      
      if mime_type: headers2['Content-Type'] = mime_type
      img_path = login_sess + '/res/' + img_file
      return read_img_from_s3(img_path,headers2)
    
    else:
      base_dir = md_base_dir(login_sess + os.path.sep + 'res')
      a_file = os.path.join(base_dir,img_file)
      
      if os.path.isdir(base_dir) and os.path.isfile(a_file):
        st = os.stat(a_file)
        
        headers = {}
        if mime_type: headers['Content-Type'] = mime_type
        headers['Last-Modified'] = formatdate(st.st_mtime,usegmt=True)
        with open(a_file,'rb') as f:
          return (f.read(),200,headers)
      
      else: return ('NOT_FOUND',404)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/netlog/md/<login_sess>/')
@app.route('/netlog/md/<login_sess>/index.html')
def get_netlog_md(login_sess):
  try:
    info = get_publish_info(login_sess)
    return render_template('netlog_show_md.html',info=info)
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

_cors_headers =  [ ('Access-Control-Allow-Origin','*'),
  ('Access-Control-Allow-Methods','GET,POST,OPTIONS'),
  ('Access-Control-Allow-Headers','*'),
  ('Access-Control-Allow-Credentials','true') ]

@app.route('/netlog/md/<login_sess>/index.md')
def get_netlog_raw(login_sess):
  try:
    info = get_publish_info(login_sess,False)
    return (info['content'],200,_cors_headers)
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400,_cors_headers)

@app.route('/netlog/visa/<card_hash>')
def get_netlog_visa(card_hash):
  return render_template('netlog_fetch_visa.html',info={'hash':card_hash})

@app.route('/netlog/stat')
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
    opened, desc, auto_pub = get_editing_info(login_sess2,tz)
    
    return { 'path':'/netlog/md/'+login_sess2, 'opened':opened, 'desc':desc, 'auto_publish':auto_pub }
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/netlog/editing', methods=['GET','POST'])
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

@app.route('/netlog/locker', methods=['POST'])
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
      opened, desc, auto_pub = ret
      return { 'result':'OK', 'path':'/netlog/md/'+login_sess2, 
        'opened':opened, 'desc':desc, 'auto_publish':auto_pub }
    else: return (ret,400)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/netlog/auto_publish', methods=['POST'])
def post_netlog_auto_publish():
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
    auto_pub = bool(data.get('auto_publish',0))
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
    act_name = b'set_auto' if auto_pub else b'clear_auto'
    wa = wallet.Address(pub_key=pubkey)
    s = b'%s+%s+%s:%i' % (WEBSITE_REALM,role,act_name,tm)
    if not wa.verify_ex(s,self_sign,single=True):
      return ('INVALID_SIGNATURE',401)
    
    # step 4: locate resource and publish new version
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    ret = set_auto_publish(auto_pub,login_sess2,tz)
    if isinstance(ret,tuple):
      opened, desc, auto_pub = ret
      return { 'result':'OK', 'path':'/netlog/md/'+login_sess2,
        'opened':opened, 'desc':desc, 'auto_publish':auto_pub }
    else: return (ret,400)  # 'NO_CHANGE' 'NO_EDITING'
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/netlog/publish', methods=['POST'])
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
      opened, desc, auto_pub = ret
      return { 'result':'OK', 'path':'/netlog/md/'+login_sess2,
        'opened':opened, 'desc':desc, 'auto_publish':auto_pub }
    else: return (ret,400)  # 'NO_CHANGE' 'NO_EDITING'
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

#----

@app.route('/netlog/images')
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

@app.route('/netlog/res/<img_file>', methods=['GET','POST','DELETE'])
def get_post_netlog_image(img_file):
  try:
    mime_type = _img_types.get(os.path.splitext(img_file)[-1],None)
    if not mime_type: return ('UNSUPPORT_IMG_FORMAT',400)
    
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) < 2 or not role:
      return ('NEED_LOGIN',400)
    
    login_sess = sdat[2:2+ord(sdat[1:2])]
    assert len(login_sess) == 20
    login_sess2 = base36.b36encode(login_sess).decode('utf-8')
    
    # step 2: get image file, no check authority
    if request.method == 'GET':
      return read_img_file(login_sess2,img_file,mime_type)
    
    # step 3: check authority
    auth = request.headers.get('X-Authority','')
    if not auth: auth = request.args.get('token','')
    if not verify_auth(sid,sdat,auth):
      return ('AUTHORIZE_FAIL',401)
    
    # step 4: process POST or DELETE
    if request.method == 'POST':
      img_data = request.get_data(as_text=True)  # data:image/png;bas64,...
      if img_data[:5] == 'data:':
        b = img_data.split(';base64,',maxsplit=1)
        if len(b) == 2:
          ctx = base64.b64decode(b[1])
          return write_img_file(login_sess2,img_file,ctx)
      return ('INVALID_IMAGE_DATA',400)
    
    else:  # 'DELETE'
      return rmv_img_file(login_sess2,img_file)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

#----

def netlog_init(config):
  global _rsp_website, _app_admin_pubkey, _app_strategy
  
  _rsp_website = config['rsp_website']
  _app_admin_pubkey = wallet.Address(priv_key=config['app_admin_wif'].encode('utf-8')).publicKey().hex()
  _app_strategy = config['strategy']
  
  global _locker_expired
  stg = config['strategy']
  _locker_expired = refresh_periods[stg.get('session_type',1)&0x07] * (stg.get('session_limit',14)+1)
  
  from .ssi_login import ssi_login_init
  ssi_login_init(config)
