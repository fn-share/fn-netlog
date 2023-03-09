# root/netlog.py

import os, time, hashlib, base64, json, traceback
from binascii import hexlify, unhexlify

import logging
logger = logging.getLogger(__name__)

from . import app
from flask import request, render_template

from nbc import wallet
from nbc.util import base36
from .ssi_login import verify_auth, ripemd_hash, refresh_periods, WEBSITE_REALM, ssi_login_init

_real_website = ''
_app_admin_pubkey = ''
_app_strategy_str = '{}'

_locker_expired = 86400    # default is 1 day, would config as: refresh_period*(session_limit+1)

def md_base_dir(login_sess):
  file_dir = os.path.split(__file__)[0]
  file_dir = os.path.split(file_dir)[0]
  return os.path.join(file_dir,'data',login_sess)

@app.route('/')
@app.route('/index.html')
def index_page():
  info = { 'real_website': _real_website,
    'app_admin_pubkey': _app_admin_pubkey,
    'app_strategy': _app_strategy_str }
  return render_template('index.html',info=info)

@app.route('/md/<login_sess>')
def get_markdown(login_sess):
  try:
    info = { 'login_session':login_sess, 'content':'', 'modify_at':0 }
    base_dir = md_base_dir(login_sess)
    idx_file = os.path.join(base_dir,'index.md')
    
    if os.path.isdir(base_dir) and os.path.isfile(idx_file):
      st = os.stat(idx_file)
      with open(idx_file,'rb') as f:
        info['content'] = base64.b64encode(f.read()).decode('utf-8')
        info['modify_at'] = int(st.st_mtime)
        info['file_size'] = st.st_size
    
    return render_template('show_md.html',info=info)
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/visa/<card_hash>')
def fetch_visa(card_hash):
  return render_template('fetch_visa.html',info={'hash':card_hash})

def ensure_md_edt_file(edt_file, cfg_file):
  if not os.path.isfile(edt_file):
    with open(edt_file,'wt') as f:
      f.write('样例文件\n=======\n\n&nbsp;\n\n### 1. 章标题\n\n#### 1.1 节标题\n\n这是正文\n')
  if not os.path.isfile(cfg_file):
    with open(cfg_file,'wt') as f:
      f.write('{}')

@app.route('/stat')
def get_stat():
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
    
    base_dir = md_base_dir(login_sess2)
    if not os.path.isdir(base_dir): os.makedirs(base_dir,exist_ok=True)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    desc = ''; cfg = None; opened = False
    if os.path.isfile(cfg_file):
      with open(cfg_file,'rb') as f:
        cfg = json.load(f)
    if cfg is not None:
      opened = bool(cfg.get('opened',0))
      last_archive = cfg.get('archive_time',0)
      last_editing = cfg.get('editing_time',0)
      if not last_archive:
        desc += '本文尚未发布。\n\n'
      else:
        desc += '本文在 %s 最后发布。\n\n' % time.strftime('%y-%m-%d %H:%M:%S',tuple(time.localtime(last_archive)))
      
      if not last_editing:
        desc += '本文尚未提交更新。\n'
      else:
        desc += '用户（指纹 %s）于 %s 最后更新。\n' % (cfg.get('last_editor',''),time.strftime('%y-%m-%d %H:%M:%S',tuple(time.localtime(last_editing))))
      
      curr_opener = cfg.get('locker_opener','')
      curr_open_tm = cfg.get('last_open',0)
      if opened and curr_opener and int(time.time()) - curr_open_tm < _locker_expired:
        tm_desc = time.strftime('%y-%m-%d %H:%M:%S',tuple(time.localtime(curr_open_tm)))
        desc += '\n用户（指纹 %s）于 %s 开锁，正在编辑中 ...\n' % (int(curr_opener,16),tm_desc)
    
    return { 'desc':desc, 'path':'/md/'+login_sess2, 'opened':opened }
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/editing', methods=['GET','POST'])
def do_editing():
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
    
    base_dir = md_base_dir(login_sess2)
    if not os.path.isdir(base_dir): os.makedirs(base_dir,exist_ok=True)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    if request.method == 'GET':
      with open(edt_file,'rb') as f:
        return f.read()
    
    else:  # request.method == 'POST'
      if role != b'editor' and role != b'manager':
        return ('NOT_SUPPORT',400)
      
      if os.path.isfile(cfg_file):
        with open(cfg_file,'rb') as f:
          cfg = json.load(f)
      else: cfg = {}
      
      # when current login by green card, and not same unlock operator, and still before _locker_expired
      if ord(sdat[:1]) < 0x80 and cfg.get('locker_opener') != sid[:4].hex() and (now - cfg.get('last_open',0)) < _locker_expired:
        return ('UNLOCK_BY_OTHER',400)
      
      data = request.get_json(force=True,silent=True)
      ctx = base64.b64decode(data['content'])  # ctx can be '' that means reset content
      
      with open(edt_file,'wb') as f:
        with open(cfg_file,'wt') as f2:
          cfg['last_editor'] = int(sid[:4].hex(),16)  # figerprint
          cfg['editing_time'] = int(time.time())
          json.dump(cfg,f2)
        f.write(ctx)
      
      return {'result':'OK'}
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/locker', methods=['POST'])
def post_locker():
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
    
    base_dir = md_base_dir(login_sess2)
    if not os.path.isdir(base_dir): os.makedirs(base_dir,exist_ok=True)
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = None; need_save = False
    with open(cfg_file,'rt') as f:
      cfg = json.load(f)
      if cfg.get('opened'):  # already opened
        # less than 0x80 means not login by meta-passport
        if ord(sdat[:1]) < 0x80 and cfg.get('locker_opener') != sid[:4].hex() and (now-cfg.get('last_open',0)) < _locker_expired:
          return ('UNLOCK_BY_OTHER',400)   # login by green card, and not same unlock operator, and still before _locker_expired
      
      if action == 'open_locker':
        if not cfg.get('opened'):
          cfg['opened'] = True   # open it
          cfg['locker_opener'] = sid[:4].hex()  # hex figerprint
          cfg['last_open'] = int(time.time())
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
    
    return {'result':'OK'}
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/publish', methods=['POST'])
def post_publish():
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
    
    base_dir = md_base_dir(login_sess2)
    if not os.path.isdir(base_dir): os.makedirs(base_dir,exist_ok=True)
    idx_file = os.path.join(base_dir,'index.md')
    edt_file = os.path.join(base_dir,'editing.md')
    cfg_file = os.path.join(base_dir,'editing.cfg')
    ensure_md_edt_file(edt_file,cfg_file)
    
    cfg = json.load(open(cfg_file,'rt'))
    if cfg.get('archive_time',0) > cfg.get('editing_time',now):
      return ('NO_CHANGE',400)
    
    with open(edt_file,'rb') as f:
      with open(idx_file,'wb') as f2:
        f2.write(f.read())
    
    cfg['archive_time'] = int(time.time())
    with open(cfg_file,'wt') as f:
      json.dump(cfg,f)
    
    return {'result':'OK'}
  
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
