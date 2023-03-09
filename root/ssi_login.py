# root/ssi_login.py

import logging
logger = logging.getLogger(__name__)

import os, traceback
import time, random, hashlib, base64, hmac, re, struct
from binascii import hexlify, unhexlify
from flask import request, make_response

from . import app

from nbc import wallet
from nbc.util import base36
from nbc.util.ecdsa import SECP256k1 as curve
from nbc.util.ecdsa.util import number_to_string, string_to_number
from nbc.wallet.hdwallet import point_decompress
from nbc.util.pyaes.aes import AESModeOfOperationCBC as AES

_platform_pubkey = b''
_product_pubkey  = b''

def ripemd_hash(s):
  return hashlib.new('ripemd160',hashlib.sha256(s).digest()).digest()

def ber_encode(tag, b):  # tag should be 0xc0~0xdf, b should be bytes
  i = len(b)             # len(b) must less than 65536
  if i > 255:
    hi,lo = divmod(i,256)
    return bytes((tag,0x82,hi,lo)) + b
  elif i > 127:
    return bytes((tag,0x81,i)) + b
  else: return bytes((tag,i)) + b

def ber_decode(b):       # b should be bytes
  ret = []
  
  i = 0; iLen = len(b)   # len(b) must less than 65536
  while i < iLen:
    tag = ord(b[i:i+1])
    i += 1
    if i >= iLen:
      raise Exception('BER out of range')
    
    i2 = ord(b[i:i+1])
    if i2 == 0x82:
      subLen = (ord(b[i+1:i+2]) << 8) + ord(b[i+2:i+3])
      i += 3
    elif i2 == 0x81:
      subLen = ord(b[i+1:i+2])
      i += 2
    else:
      if i2 > 0x80: raise Exception('BER format error')
      subLen = i2
      i += 1
    
    if i + subLen > iLen:
      raise Exception('BER out of range')
    ret.append((tag,b[i:i+subLen]))
    i += subLen
  
  return ret

def gen_ecdh_key(pubkey33, priv32=None):
  if priv32 is None:
    secexp = random.randrange(curve.order>>16,curve.order)
  elif isinstance(priv32,int):
    secexp = priv32 % curve.order
  else: secexp = string_to_number(priv32) % curve.order
  
  point_nonce = curve.generator * secexp
  nonce_x = number_to_string(point_nonce.x(),curve.order)
  nonce_y = number_to_string(point_nonce.y(),curve.order)
  flag = ord(nonce_y[-1:]) & 0x01
  
  peer_point = point_decompress(curve.curve,pubkey33)
  point_targ = peer_point * secexp
  targ_x = number_to_string(point_targ.x(),curve.order)
  
  return (flag,nonce_x,targ_x)  # temporary pub_key33: bytes((2+flag,)) + nonce_x

def encrypt_arg(data, k_iv):  
  n = len(data)
  m = n % 16
  if m > 0:      # align to 16 * n
    n2 = 16 - m
    data += b'\x00' * n2
    n += n2
  
  aes = AES(k_iv[:16],k_iv[16:32])
  return b''.join(aes.encrypt(data[i:i+16]) for i in range(0,n,16))

def decrypt_arg(data, k_iv):
  n = len(data)
  if (n & 0x0f) != 0:
    raise ValueError('decrypt data not align to 16 bytes')
  
  aes = AES(k_iv[:16],k_iv[16:32])
  return b''.join(aes.decrypt(data[i:i+16]) for i in range(0,n,16))

_last_mono_priv = 0

def mono_encrypt(msg16):
  global _last_mono_priv
  
  if not _last_mono_priv:
    while True:
      temp_priv = random.randrange(curve.order>>16,curve.order)
      flag,_,_ = gen_ecdh_key(_platform_pubkey,temp_priv)
      if flag == 0:  # we only choose flag==0, ignore flag==1
        _last_mono_priv = temp_priv
        break
  
  _,nonce_x,k_iv_plt = gen_ecdh_key(_platform_pubkey,_last_mono_priv)
  _,_,k_iv_pdt = gen_ecdh_key(_product_pubkey,_last_mono_priv)
  return nonce_x + encrypt_arg(encrypt_arg(msg16,k_iv_plt),k_iv_pdt)

#----

WEBSITE_REALM = os.environ.get('WEB_REALM','localhost:3000').encode('utf-8')
WEBSITE_NONCE = os.environ.get('WEB_NONCE','WEBSITE_SECRET').encode('utf-8')  # for session control

# 6m, 15m, 30m, 1h, 3h, 8h, 1d, 7d
session_periods = (360,900,1800,3600,10800,28800,86400,604800)
# 30m, 90m, 5h, 10h, 24h, 3d, 7d, 63d
refresh_periods = (1800,5400,18000,36000,86400,259200,604800,5443200)

DEFAULT_SESS_TYPE = 1
DEFAULT_PERIOD    = session_periods[DEFAULT_SESS_TYPE]  # 30m, session_periods[1]
DEFAULT_REFRESH   = refresh_periods[DEFAULT_SESS_TYPE]  # 90m, refresh_periods[1]

TAG_ACCOUNT       = 0xc1
TAG_ROOTCODE      = 0xc2
TAG_LOGIN_SESSION = 0xc3
TAG_TARGET        = 0xc5
TAG_REALM         = 0xc8
TAG_SESSION_DATA  = 0xc9
TAG_ADMIN_FP      = 0xca
TAG_CERT_EXPIRED  = 0xcb
TAG_NOW_TIME      = 0xcc
TAG_SEED_SECRET   = 0xce
TAG_MAX_AUTH_TIME = 0xcf
TAG_SIGNATURE     = 0xdf

MAX_SESS_CACHE_NUM    = 8192

MIN_VISA_MINUTES      = 1440      # 1440 is 1 day
MAX_VISA_MINUTES      = 10512000  # 10512000 is 20 years
MAX_VISA_AUTH_MINUTES = 20160     # 20160 is 14 days

_config   = {}
_strategy = {}

passport_tags = ( TAG_ACCOUNT, TAG_ROOTCODE, TAG_LOGIN_SESSION,
  TAG_REALM, TAG_ADMIN_FP, TAG_CERT_EXPIRED, TAG_NOW_TIME )
greencard_tags = ( TAG_ROOTCODE, TAG_LOGIN_SESSION, TAG_REALM,
  TAG_SESSION_DATA, TAG_ADMIN_FP, TAG_CERT_EXPIRED, TAG_NOW_TIME )

app_server_secret = os.environ.get('APP_SECRET','change_it_please').encode('utf-8')  # for green card authority

pspt_admin_acc = None
pspt_admin_fp  = b''

app_admin_acc = None
app_admin_fp  = b''

nbc_platform_acc = None
nbc_platform_fp  = b''

nbc_product_acc = None
nbc_product_fp  = b''

session_cache = {}  # { acc20:[time,mutable_num4,last_refresh_seg,last_nonce_crc3,last_token,session_data]}

def set_sess_cache(acc, mutable_num, refresh_seg, nonce_crc, tok, sess_data):
  now = int(time.time())
  tmp = [now,mutable_num,refresh_seg,nonce_crc,tok,sess_data]
  info = session_cache.get(acc)
  if not info:
    session_cache[acc] = info = tmp
  else: info[:] = tmp
  
  if len(session_cache) > MAX_SESS_CACHE_NUM:   # too many cached items
    try:
      kv = list(session_cache.items())
      one_hour_ago = now - 3600
      half_hour_ago = one_hour_ago + 1800
      
      b = []
      for k,v in kv:
        t = v[0]
        if t < one_hour_ago:  # remove all old item that cached at one hour ago
          session_cache.pop(k,None)
        elif t < half_hour_ago:
          b.append(k)
      
      if len(session_cache) > MAX_SESS_CACHE_NUM:  # remove more if still too many
        for k in b: session_cache.pop(k,None)
    
    except:
      logger.warning(traceback.format_exc())

@app.route('/login/nonce', methods=['POST'])
def post_login_nonce():
  try:
    # step 1: parse parameters
    data = request.get_json(force=True,silent=True)
    card_ctx = unhexlify(data.get('card',''))
    role = data.get('role','')
    client_nonce_crc = unhexlify(data.get('nonce_crc',''))
    tm = int(data.get('time',0))
    self_sign = unhexlify(data.get('signature',''))
    
    if (not role) or (role not in _strategy['roles']) or len(client_nonce_crc) != 3 or len(card_ctx) <= 64 or len(self_sign) < 64:
      return ('INVALID_PARAMTER',400)
    
    if abs(time.time() - tm) > 90:   # should be nearby in 1.5 minutes
      return ('INVALID_TIME',400)
    
    # step 2: parse and verify card
    role2 = role.encode('utf-8')
    card_dict = {}; card_tags = ()
    by_passport = False
    card_flag = card_ctx[:4]
    if card_flag == b'pspt' or card_flag == b'gncd':
      succ = True
      card_dict = dict(ber_decode(card_ctx[4:]))
      if card_flag == b'pspt':
        by_passport = True
        card_tags = passport_tags 
      else: card_tags = greencard_tags
      
      for tag in card_tags:
        if tag not in card_dict:
          succ = False
          break
    else: succ = False
    
    sig = card_dict.get(TAG_SIGNATURE)
    if sig:
      del card_dict[TAG_SIGNATURE]
    else: succ = False
    
    if not succ or len(card_dict) != len(card_tags):  # extractly no unknown fields
      return ('INVALID_CARD',400)
    
    # step 3: verify account and pub33
    sess_type,card_tm = struct.unpack('>BI',card_dict[TAG_NOW_TIME])
    if by_passport:
      acc = card_dict[TAG_ACCOUNT]
      if len(acc) == 20:  # pubkey also needed if account20 passed
        pub33 = unhexlify(data.get('pubkey',''))
        if ripemd_hash(pub33) != acc: pub33 = b''   # failed
      else:
        pub33 = acc
        acc = ripemd_hash(pub33)
      
      if card_tm != 0:
        return ('NOT_META_PSPT',400)   # only meta passport supports direct login
    else:  # by green card
      pub33 = unhexlify(data.get('pubkey',''))
      acc = ripemd_hash(pub33)
    
    if len(pub33) != 33 or ord(pub33[:1]) not in (2,3):
      return ('UNKNOWN_PUBKEY',400)
    
    # step 4: verify card signature
    card = card_ctx[:-2-len(sig)]
    if by_passport:
      if card_dict[TAG_ADMIN_FP] != pspt_admin_fp or not pspt_admin_acc.verify_ex(card,sig,single=True,no_der=True):
        return ('INVALID_CARD',400)
    else:
      fp = card_dict[TAG_ADMIN_FP]
      if fp == nbc_platform_fp:
        if not nbc_platform_acc.verify_ex(card,sig,single=True,no_der=True):
          return ('INVALID_CARD',400)
      elif fp == nbc_product_fp:
        if not nbc_product_acc.verify_ex(card,sig,single=True,no_der=True):
          return ('INVALID_CARD',400)
      else: return ('INVALID_CARD',400)
    
    # step 5: check card time
    now_min = tm // 60
    expired = struct.unpack('>I',card_dict[TAG_CERT_EXPIRED])[0]
    if now_min + (session_periods[sess_type&0x07] // 60) > expired:
      return ('EXPIRE_OUT_RANGE',400)  # not enough for one period
    
    # step 6: get realm, sess_data
    realm = card_dict[TAG_REALM]
    if by_passport:
      # highest bit of first byte: 1 for by meta-passport
      # other bits of first byte: re_authority_level=0~127
      sess_data = b'\xff\x14' + card_dict[TAG_LOGIN_SESSION]  # re-authority level, len1+resourceId
      if realm != WEBSITE_REALM:
        return ('MISMATCH_REALM',400)
    else:  # by green card
      sess_data = card_dict[TAG_SESSION_DATA]
      if len(sess_data) < ord(sess_data[1:2] or b'\x00')+2:
        return ('INVALID_SESS_DATA',400)
      host_role = WEBSITE_REALM + b'+' + role2
      if realm != host_role and realm.find(host_role+b'+') != 0:
        return ('MISMATCH_REALM',400)   # not start with host+role
      
      # step 7: check loginSession for green card
      server_secret = b'%s:%s:%s' % (app_server_secret,realm,sess_data)
      server_secret = hashlib.sha256(hashlib.sha256(server_secret).digest()).digest()[:16]
      
      ha1 = ripemd_hash(b'%s:%i:%i' % (pub33,card_tm,expired))
      ha2 = ripemd_hash(b'%s:%s' % (realm,sess_data))
      ha3 = bytes([ha1[i] ^ ha2[i] for i in range(20)])
      if card_dict[TAG_LOGIN_SESSION] != ripemd_hash(server_secret + ha3):
        return ('AUTHORIZE_ERROR',401)
    
    # step 8: check self signature
    wa = wallet.Address(pub_key=pub33)
    s = b'%s+%s+login:%s:%s:%i' % (WEBSITE_REALM,role2,hashlib.sha256(card_ctx).digest(),client_nonce_crc,tm)
    if not wa.verify_ex(s,self_sign,single=True):
      return ('INVALID_SIGNATURE',401)
    
    # step 9: setup sess_id, and cookie var _sid_
    cookie_age = 5 * DEFAULT_REFRESH    # fixed to sessType=2 (5 hours), max (0x04+1)* 5h
    refresh_seg = tm // DEFAULT_REFRESH
    mutable_num = 0x04000000 + refresh_seg
    sess_id = acc + struct.pack('>I',mutable_num)   # acc is account20, current login account
    server_nonce = hashlib.sha256(b'%s:%s:%s:%s' % (WEBSITE_REALM,WEBSITE_NONCE,role2,sess_id)).digest()
    
    # step 10: caculate access token, and save cache item
    h = hmac.new(server_nonce,digestmod='sha256')
    h.update(b':%i' % refresh_seg)
    tok = ripemd_hash(b'%s:%s:%s:%i' % (h.digest(),client_nonce_crc,sess_data,tm // DEFAULT_PERIOD))
    set_sess_cache(acc,sess_id[20:24],refresh_seg,client_nonce_crc,tok,sess_data)
    
    # step 11: set cookie and return
    # _sid_ = account20+mutable_num4+nonce_crc3+role, 36 bytes in base64 format
    resp = make_response({'nonce':server_nonce.hex(),'session_data':sess_data.hex()})
    sess_id = base64.b64encode(sess_id+client_nonce_crc+role2).decode('utf-8')
    resp.set_cookie( '_sid_', sess_id, max_age=cookie_age, path='/',
          # domain=THIS_DOMAIN,         # THIS_DOMAIN='.nb-chain.cn'
          secure=True, httponly=True)   # only for https, samesite=None # not all browser support samesite 
    resp.set_cookie( '_sdat_', base64.b64encode(sess_data).decode('utf-8'),
          max_age=cookie_age, path='/', # domain=THIS_DOMAIN,
          secure=True, httponly=True)   # sess_data[2:22] is unique resource id
    return resp
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

_re_whites  = re.compile(r'\s+')

def _split_assign(s):
  i = s.find('=')
  if i > 0:
    return (s[:i],s[i+1:])
  else: return (s,'')

def verify_auth(sid, sdat, auth):
  # step 1: parse X-Authority
  b = _re_whites.split(auth.strip())  # SSI-SIGN realm=nbc-kanban,period=1200,token=xxx
  if len(b) != 2 or b[0] != 'SSI-SIGN': return False
  
  b = b[1].split(',')
  d = dict([_split_assign(item) for item in b])
  
  period = int(d.get('period',DEFAULT_PERIOD))
  realm = d.get('realm',WEBSITE_REALM)
  token = base64.b64decode(d.get('token',''))
  if period != DEFAULT_PERIOD or realm != WEBSITE_REALM or len(token) != 20:
    return False
  
  # step 2: check expired or not
  acc20 = sid[:20]
  mutable_num4 = sid[20:24]
  limit_num = ord(mutable_num4[:1])
  now = int(time.time())
  refresh_beg = int(hexlify(mutable_num4[1:]),16)
  refresh_end = now // DEFAULT_REFRESH
  if refresh_end - refresh_beg > limit_num: return False  # login expired
  
  # step 3: compare to last cached item and try return quickly
  cache_info = session_cache.get(acc20)
  if cache_info and cache_info[1] == mutable_num4:  # cache item matched, mutable_num should be same too
    if cache_info[4] == token and cache_info[2] == refresh_end:  # in same refresh period
      return True        # token is matched to the last one, return quickly
    old_sdat = cache_info[5]   # not None, means exists matched old cache
  else: old_sdat = None  # means no matched old cache item
  
  # step 4: full caculate access token and verify it
  nonce_crc = sid[24:27]
  n,m = divmod(now,DEFAULT_PERIOD)
  server_nonce = hashlib.sha256(b'%s:%s:%s:%s' % (WEBSITE_REALM,WEBSITE_NONCE,sid[27:],sid[:24])).digest()
  
  h = hmac.new(server_nonce,digestmod='sha256')
  for i in range(refresh_beg,refresh_end+1):  # max loop 256 times
    h.update(b':%i' % i)
  
  access_token = ripemd_hash(b'%s:%s:%s:%i' % (h.digest(),nonce_crc,sdat,n))
  if access_token != token:
    if m <= 120:
      n -= 1        # 2 minutes from period starting, try perious period
    elif m+120 >= DEFAULT_PERIOD:
      n += 1        # 2 minutes to period ending, try next period
    else: return False
    
    access_token = ripemd_hash(b'%s:%s:%s:%i' % (h.digest(),nonce_crc,sdat,n))
    if access_token != token: return False
  # assert access_token == token
  
  if old_sdat is None:  # set one if mismatch in cache
    # it may overwrite old mismatch one on same acc20
    set_sess_cache(acc20,mutable_num4,refresh_end,nonce_crc,token,sdat)
  else:   # update old cache item
    # assert cache_info
    cache_info[2:6] = [refresh_end,nonce_crc,token,sdat]
  return True

@app.route('/login/refresh', methods=['POST'])
def post_login_refresh():
  try:
    # step 1: parse client_nonce and check client time
    data = request.get_json(force=True,silent=True)
    client_nonce = unhexlify(data.get('nonce',''))
    
    tm = int(data.get('time',0))
    if abs(time.time() - tm) > 300:   # should be nearby in 5 minutes
      return ('INVALID_TIME',400)
    
    # step 2: get _sid_ and check refresh_now time
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_','')) # session data
    if len(sid) <= 27: return ('INVALID_SID',401)
    acc20 = sid[:20]
    mutable_num4 = sid[20:24]
    nonce_crc = sid[24:27]
    role = sid[27:]
    
    limit_num = ord(mutable_num4[:1])
    refresh_beg = int(hexlify(mutable_num4[1:]),16)
    refresh_now = tm // DEFAULT_REFRESH
    if refresh_now > refresh_beg + limit_num:
      return ('OVERTIME',401)
    cookie_age = (refresh_beg + limit_num + 1 - refresh_now) * DEFAULT_REFRESH  # get the left cookie alive time
    
    # step 3: verify client_nonce is correct or not, no need check X-Authority since it supports any-refresh-period lost connection
    passed = False
    cache_info = session_cache.get(acc20)
    if cache_info and cache_info[1] == mutable_num4:  # cache item matched, mutable_num should be same too
      if hashlib.sha256(b'%s:%s:%i' % (role,client_nonce,cache_info[2])).digest()[:3] == cache_info[3]:
        passed = True
    
    nonce_crc_now = hashlib.sha256(b'%s:%s:%i' % (role,client_nonce,refresh_now)).digest()[:3]
    if nonce_crc_now == nonce_crc:
      passed = True
    else:
      if not passed:
        for i in range(refresh_now-1,refresh_beg-1,-1):
          if hashlib.sha256(b'%s:%s:%i' % (role,client_nonce,i)).digest()[:3] == nonce_crc:
            passed = True
            break
    if not passed:
      return ('INVALID_NONCE',401)  # client_nonce not correct
    
    # step 4: caculate server_nonce, token_now
    sess_id = sid[:24]
    server_nonce = hashlib.sha256(b'%s:%s:%s:%s' % (WEBSITE_REALM,WEBSITE_NONCE,role,sess_id)).digest()
    h = hmac.new(server_nonce,digestmod='sha256')
    for i in range(refresh_beg,refresh_now+1):
      h.update(b':%i' % i)
    token_now = ripemd_hash(b'%s:%s:%s:%i' % (h.digest(),nonce_crc_now,sdat,tm//DEFAULT_PERIOD))
    set_sess_cache(acc20,mutable_num4,refresh_now,nonce_crc_now,token_now,sdat)
    
    # step 5: set cookie and return
    resp = make_response({'result':'OK'})
    sess_id = base64.b64encode(sess_id+nonce_crc_now+role).decode('utf-8')
    resp.set_cookie( '_sid_', sess_id,  # _sid_ is account20+mutable_num4+nonce_crc3+role
          max_age=cookie_age, path='/',
          # domain=THIS_DOMAIN,         # THIS_DOMAIN='.nb-chain.cn'
          secure=True, httponly=True)   # only for https, samesite=None # not all browser support samesite 
    return resp
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

_cached_visa = {}  # {b36hash:(tm,card)}
_cached_visa_check_at = int(time.time())

@app.route('/login/authority', methods=['POST'])
def post_login_authority():
  global _cached_visa_check_at
  
  try:
    # step 1: check SSI token
    sid = base64.b64decode(request.cookies.get('_sid_',''))
    sdat = base64.b64decode(request.cookies.get('_sdat_',''))
    role = sid[27:]
    if len(sdat) >= 2 and role and verify_auth(sid,sdat,request.headers.get('X-Authority','')):
      pass
    else: return ('AUTHORIZE_FAIL',401)
    
    # step 2: parse parameters
    data = request.get_json(force=True,silent=True)
    targ_child = int(data.get('pspt_child',0))
    pspt = unhexlify(data.get('passport',''))  # target generic passport
    tm = int(data.get('time',0))
    new_sdat = unhexlify(data.get('session_data',''))
    expire_minutes = int(data.get('expire_minutes',1440))  # default 1440 minutes is 24 hours, max is 20 years
    self_pub33 = unhexlify(data.get('pubkey',''))
    self_sign = unhexlify(data.get('signature',''))
    new_auth_level = ord(new_sdat[:1]) & 0x7f
    if not targ_child or len(pspt) <= 64 or len(new_sdat) > 127 or len(self_sign) < 64 or (new_auth_level not in (0,127)):
      return ('INVALID_PARAMTER',400)
    
    if len(self_pub33) != 33 or ripemd_hash(self_pub33) != sid[:20]:
      return ('INVALID_PUBKEY',400)
    old_auth_level = ord(sdat[:1]) & 0x7f
    if old_auth_level != 127 and new_auth_level != 0:  # old_auth_level must be 0 or 127
      return ('NOT_ALLOW',400)      # can not turn low-level authority to high-level
    now = int(time.time())
    if abs(now - tm) > 90:  # should be nearby within 1.5 minutes
      return ('INVALID_TIME',400)
    
    # step 3: check passport
    pspt_dict = {}      # target passport
    if pspt[:4] == b'pspt':
      succ = True
      b = ber_decode(pspt[4:])
      pspt_dict = dict(b)
      for tag in passport_tags:
        if tag not in pspt_dict:
          succ = False
          break
    else: succ = False
    
    sig = pspt_dict.get(TAG_SIGNATURE)
    if sig:
      del pspt_dict[TAG_SIGNATURE]
    else: succ = False
    
    if not succ or len(pspt_dict) != len(passport_tags):  # extractly no unknown fields
      return ('INVALID_PASSPORT',400)
    
    time4 = struct.unpack('>I',pspt_dict[TAG_NOW_TIME][1:5])[0]  # time4: 0 or now time in minutes
    if time4 == 0: return ('NONE_GENERIC',400)
    
    targ_pub33 = pspt_dict[TAG_ACCOUNT]  # should be generic passport
    if len(targ_pub33) != 33 or ord(targ_pub33[:1]) not in (2,3):
      return ('INVALID_TARGET',400)
    
    card = pspt[:-2-len(sig)]
    if pspt_dict[TAG_ADMIN_FP] != pspt_admin_fp or not pspt_admin_acc.verify_ex(card,sig,single=True,no_der=True):
      return ('INVALID_PASSPORT',400)
    
    # step 4: check self signature
    wa = wallet.Address(pub_key=self_pub33)
    s = b'%s+%s+authority:%s:%s:%i' % (WEBSITE_REALM,role,new_sdat,hashlib.sha256(pspt).digest(),tm)
    if not wa.verify_ex(s,self_sign,single=True):
      return ('INVALID_SIGNATURE',401)
    
    # step 5: create authority card
    tm = tm // 60   # convert to minutes
    expired_tm = tm + max(min(expire_minutes,MAX_VISA_MINUTES),MIN_VISA_MINUTES)
    root_code = pspt_dict[TAG_ROOTCODE]
    
    # highest bit of authority-level should be 0 which means not login by meta-passport
    new_sdat = bytes((new_auth_level,)) + new_sdat[1:]
    new_realm = WEBSITE_REALM + b'+' + role
    seed_secret = b'%s:%s:%s' % (app_server_secret,new_realm,new_sdat)
    seed_secret = hashlib.sha256(hashlib.sha256(seed_secret).digest()).digest()[:16]
    seed_secret = mono_encrypt(seed_secret)          # encrypt to 48 bytes
    
    body = b'visa' + ber_encode(TAG_ACCOUNT,self_pub33)
    body += ber_encode(TAG_ROOTCODE,root_code)       # target account's root code
    body += ber_encode(TAG_TARGET,targ_pub33)
    body += ber_encode(TAG_REALM,new_realm)
    body += ber_encode(TAG_SESSION_DATA,new_sdat)    # max 127 bytes
    body += ber_encode(TAG_ADMIN_FP,app_admin_fp)
    body += ber_encode(TAG_CERT_EXPIRED,struct.pack('>I',expired_tm))
    body += ber_encode(TAG_NOW_TIME,struct.pack('>BI',DEFAULT_SESS_TYPE,tm))
    body += ber_encode(TAG_SEED_SECRET,seed_secret)  # 48 bytes
    body += ber_encode(TAG_MAX_AUTH_TIME,struct.pack('>I',MAX_VISA_AUTH_MINUTES)) # default 14 days
    
    sig = app_admin_acc.sign_ex(body,single=True,no_der=True)
    card = struct.pack('>III',targ_child & 0x7fffffff,0,0) + body + bytes((TAG_SIGNATURE,len(sig))) + sig
    card_ha32 = hashlib.sha256(card).digest()  # card[:12] is child1,child2=0,child3=0
    card += card_ha32[:4]
    
    b36hash = base36.b36encode(hashlib.new('ripemd160',card_ha32).digest()).decode('utf-8')
    _cached_visa[b36hash] = (now,card)
    
    if _cached_visa_check_at < (now - 86400):  # last check is one day ago
      _cached_visa_check_at = now
      day3_before = now - 259200
      b = list(_cached_visa.items())
      b = [k for k,v in b if v[0] < day3_before]
      for k in b: _cached_visa.pop(k,None)     # remove all 3-day ago cached-items
    
    return {'id':b36hash}
  
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

@app.route('/login/visa/<card_hash>')
def get_login_visa(card_hash):
  try:
    info = _cached_visa.get(card_hash)
    if not info:
      return ('NOT_FOUND',404)
    else: return {'content':info[1].hex()}
  except:
    logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)

#----

def ssi_login_init(config):
  global _config, _strategy
  _config = config
  _strategy = config['strategy']
  
  global _platform_pubkey, _product_pubkey
  _platform_pubkey = unhexlify(config['nbc_platform_pubkey'])
  _product_pubkey  = unhexlify(config['nbc_product_pubkey'])
  
  global nbc_platform_acc, nbc_platform_fp
  nbc_platform_acc = wallet.Address(pub_key=_platform_pubkey);
  nbc_platform_fp  = ripemd_hash(_platform_pubkey)[:4]
  
  global nbc_product_acc, nbc_product_fp
  nbc_product_acc = wallet.Address(pub_key=_product_pubkey);
  nbc_product_fp  = ripemd_hash(_product_pubkey)[:4]
  
  global pspt_admin_acc, pspt_admin_fp
  pspt_admin_pub = unhexlify(config['real_admin_pubkey'])
  pspt_admin_acc = wallet.Address(pub_key=pspt_admin_pub)
  pspt_admin_fp  = ripemd_hash(pspt_admin_pub)[:4]
  
  global app_admin_acc, app_admin_fp
  app_admin_acc = wallet.Address(priv_key=config['app_admin_wif'].encode('utf-8'))
  app_admin_fp  = ripemd_hash(app_admin_acc.publicKey())[:4]
