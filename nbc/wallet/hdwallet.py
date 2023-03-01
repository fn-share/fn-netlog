# nbc/wallet: NBC Wallet, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import hashlib, hmac, time, traceback
from random import randint
from binascii import hexlify, unhexlify

from .. import util
from ..util.hash import hash160
from ..util import base58, ecc
from ..util.ecdsa import numbertheory, ellipticcurve, curves
from ..util.ecdsa import SECP256k1 as curve
from ..util.ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ..util.ecdsa.util import number_to_string, string_to_number, sigencode_der, sigdecode_der
from ..util.ecdsa.ecdsa import point_is_valid

from .address import _aesEncrypt, _aesDecrypt

if bytes == str:      # python 2
  def _bytes(t):
    return bytes(bytearray(t))
else: _bytes = bytes  # python 3

def point_compress(point):
  x = point.x(); y = point.y()
  curve = point.curve()
  return _bytes((2+(y&1),)) + number_to_string(x,curve.p())

def point_decompress(curve2, data):
  ch = ord(data[:1])
  assert(ch == 2 or ch == 3)  # data[0] should be b'\x02' or b'\x03'
  
  x = string_to_number(data[1:])
  y = numbertheory.square_root_mod_prime((x**3 + curve2.a()*x + curve2.b()) % curve2.p(),curve2.p())
  if not point_is_valid(curve.generator, x, y):
    raise ValueError('invalid public key')
  if (ch & 0x01) != (y & 0x01):
    y = curve2.p() - y
  
  return ellipticcurve.Point(curve2, x, y)

def _sigencode(r, s, order):
  return unhexlify(b'%064x' % r) + unhexlify(b'%064x' % s)  # fixed to 64 bytes

def _sigdecode(s, order):
  return (int(hexlify(s[:32]),16),int(hexlify(s[32:]),16))

class HDWallet(object):
  _chain  = None   # ByteSeq
  _pubkey = None   # ellipticcurve.Point
  
  _prvkey = None   # Int
  _testnet = None
  
  _depth    = None
  _parentfp = None
  _childnum = None
  
  def __init__(self, key, chain, vcn=None, testnet=False, depth=None, parentfp=None, childnum=None):
    if type(key) == ellipticcurve.Point:        # public key is a point
      self._pubkey = key  
    elif type(key) == int or type(key) == long: # private key an integer
      assert(0 < key < curve.order)
      self._prvkey = key
    else:
      raise TypeError('Unknown key type "{0}"'.format(type(key)))
    
    assert(len(chain) == 32)
    self._chain = chain  # chaincode
    self._testnet = testnet
    
    if vcn is None:
      self.vcn = vcn     # for bitcoin style
    else: self.vcn = int(vcn) & 0xffff  # for NBC parallel chain
    
    if depth == None:    # master wallet
      depth = 0
      parentfp = b'\x00' * 4
      childnum = 0
    assert(depth < 256)
    
    self._depth = depth
    self._parentfp = parentfp
    self._childnum = childnum
    
    self._comp_pubkey = None
    self._sign_key = None
    self._verify_key = None
  
  @staticmethod
  def from_pubkey(comp_pub, chain_code, vcn=None):
    key = point_decompress(curve.curve,comp_pub)  # from compressed public key to point
    return HDWallet(key,chain_code,vcn)
  
  def child(self, i):
    i = i & 0xffffffff
    priv_deriv = (i & 0x80000000) != 0
    
    if (priv_deriv and not self._prvkey):
      raise Exception('Unable to do private derivation')
    
    # only allow up to a depth of 255
    assert(self._depth < 0xff)
    
    while True:
      str_i = number_to_string(i,2**32-1)
      
      if priv_deriv:
        str_k = number_to_string(self._prvkey,curve.order)
        deriv = hmac.new(key=self._chain, msg=b'\x00' + str_k + str_i, digestmod=hashlib.sha512).digest()
      else:
        str_K = self.publicKey()
        deriv = hmac.new(key=self._chain, msg=str_K + str_i, digestmod=hashlib.sha512).digest()
      
      childChain = deriv[32:]
      childModifier = string_to_number(deriv[:32])
      if childModifier == 0 or childModifier >= curve.order:  # 0 will lead to same account
        i = (i + 1) & 0xffffffff
      else: break
    
    if self._prvkey:
      childPrvkey = (self._prvkey + childModifier) % curve.order 
      if childPrvkey == 0:
        raise Exception('This is higly unprovable ki = 0, but it did happen')
      
      childKey = childPrvkey
    else:
      childPubkey = self.point() + curve.generator * childModifier
      if childPubkey == ellipticcurve.INFINITY:
        raise Exception('This is higly unprovable Ki = INFINITY, but it did happen')
      
      childKey = childPubkey
    
    return self.__class__( childKey, childChain, vcn=self.vcn, testnet=self._testnet,
      depth=self._depth + 1,
      parentfp=self.fingerprint(),
      childnum=i )
  
  def fromPath(self, path):
    deriveKey = self
    if str(path)[:2] != 'm/':
      raise ValueError("Bad path, please insert like this type of path \"m/0'/0\"!")
    
    for idx in path.lstrip('m/').split('/'):
      if "'" in idx:
        deriveKey = deriveKey.child(int(idx[:-1]) + 0x80000000)
      else: deriveKey = deriveKey.child(int(idx))
    
    return deriveKey
  
  def to_extended_key(self, include_prv=False):
    if not self._testnet:
      version = 0x0488B21E if not include_prv else 0x0488ADE4  # 0x0488B21E for BIP-32 extended public key (xpub)
    else:
      version = 0x043587CF if not include_prv else 0x04358394
    
    version  = number_to_string(version,2**32-1)
    depth    = number_to_string(self._depth,2**8-1)
    parentfp = self.parentfp()
    childnum = number_to_string(self._childnum,2**32-1)  # will raise error when childnum is None
    chaincode = self._chain
    
    if include_prv:
      if self._prvkey == None: raise Exception('unknown private key')
      data = b'\x00' + number_to_string(self._prvkey,curve.order) # 0x00 for private, 2 or 3 for compress public key, 4 for uncompress public key 
    else:
      # compress point
      data = self.publicKey()
    
    ekdata = b''.join([version, depth, parentfp, childnum, chaincode, data])
    checksum = hashlib.sha256(hashlib.sha256(ekdata).digest()).digest()[:4]
    return base58.b58encode(ekdata + checksum).decode('utf-8')
  
  def point(self):
    if not self._pubkey:
      self._pubkey = curve.generator * self._prvkey
    return self._pubkey
  
  def pubkey(self):
    pt = self.point()
    x_str = number_to_string(pt.x(),curve.order)
    y_str = number_to_string(pt.y(),curve.order)
    return x_str + y_str
  
  def prvkey(self):
    if self._prvkey:
      return number_to_string(self._prvkey,curve.order)
    return None
  
  def chain(self):
    return self._chain
  
  def address(self, ver=None):  # only support compressed address
    if ver is None:
      ver = b'\x00' if not self._testnet else b'\x6f'  # default take as bitcoin style
    if not isinstance(ver,bytes):   # ver is bytes
      assert isinstance(ver,str)
      ver = ver.encode('utf-8')
    addr = util.key.publickey_to_address(self.publicKey(),self.vcn,ver)
    return addr.decode('utf-8')
  
  def publicKey(self):
    if self._comp_pubkey is None:
      self._comp_pubkey = point_compress(self.point())  # cache the value
    return self._comp_pubkey
  
  def publicHash(self):
    return util.key.publickey_to_hash(self.publicKey(),self.vcn)
  
  def depth(self):
    return self._depth
  
  def fingerprint(self):
    return hash160(self.publicKey())[:4]
  
  def parentfp(self):
    if self._parentfp and self._depth:
      return self._parentfp
    else: return b'\x00' * 4     # maybe no parent, take depth=0 as no parent
  
  def childnum(self):
    return self._childnum
  
  def _get_priv(self):
    prvKey = self.prvkey()
    if not prvKey:
      raise ValueError('invalid private key')
    return prvKey
  
  def sign_ex(self, data, single=False, no_der=False):
    if self._sign_key is None:
      self._sign_key = SigningKey.from_string(self._get_priv(),curve)
    
    ha = util.sha256(data) if single else util.sha256d(data)
    sig_encode = _sigencode if no_der else sigencode_der
    return self._sign_key.sign_digest(ha,sigencode=sig_encode)
  
  def sign(self, data):
    return self.sign_ex(data)
  
  def sign_noder(self, data):  # sign without DER
    return self.sign_ex(data,no_der=True)
  
  def verify_ex(self, data, signature, single=False, no_der=False):
    if self._verify_key is None:
      self._verify_key = VerifyingKey.from_public_point(self.point(),curve)

    try:
      ha = util.sha256(data) if single else util.sha256d(data)
      sig_decode = _sigdecode if no_der else sigdecode_der
      if self._verify_key.verify_digest(signature,ha,sigdecode=sig_decode):
        return ha
    except BadSignatureError:
      pass
    except:
      traceback.print_exc()
    return b''
  
  def verify(self, data, signature):
    return self.verify_ex(data,signature) != b''
  
  def verify_noder(self, data, signature):  # verify without DER
    return self.verify_ex(data,signature,no_der=True)
  
  @staticmethod
  def from_extended_key(extended_key, vcn=None):
    decoded = base58.b58decode(extended_key)
    assert(decoded and len(decoded) == 82)   # 82 == 78+4
    ekdata = decoded[:78]
    checksum = decoded[78:78+4]
    # validate checksum
    valid_checksum = hashlib.sha256(hashlib.sha256(ekdata).digest()).digest()[:4]
    assert (checksum == valid_checksum)
    
    version = string_to_number(ekdata[0:0+4])
    depth   = string_to_number(ekdata[4:4+1])
    parentfp = ekdata[5:5+4]
    childnum = string_to_number(ekdata[9:9+4])
    chaincode = ekdata[13:13+32]
    data = ekdata[45:45+33]
    
    testnet = version in (0x043587CF, 0x04358394)
    
    if version in (0x0488B21E, 0x043587CF):   # data contains pubkey
      assert(ord(data[:1]) in (2,3))
      key = point_decompress(curve.curve,data)
    elif version in (0x0488ADE4, 0x04358394): # data contains privkey
      assert(ord(data[:1]) == 0)
      key = string_to_number(data[1:])
    else:
      raise Exception('unknown version')
    
    return HDWallet( key, chaincode, vcn=vcn, testnet=testnet, depth=depth,
      childnum=childnum, parentfp=parentfp )
  
  @staticmethod
  def from_master_seed(master_seed, vcn=None, testnet=False):
    if not isinstance(master_seed,bytes):
      master_seed = master_seed.encode('utf-8')
    
    deriv = hmac.new(key=b'Bitcoin seed', msg=master_seed, digestmod=hashlib.sha512).digest()
    master_key = string_to_number(deriv[:32]) % curve.order
    if master_key == 0: raise ValueError('zeror key, try again')
    master_chain = deriv[32:]
    return HDWallet(master_key, master_chain, vcn=vcn, testnet=testnet)
  
  def dump_to_cfg(self, passphrase='', cfg=None):
    cfg = cfg or {}
    account = { 'time':int(time.time()), 'encrypted':False, 'type':'HD',
      'chain': self._chain.hex(),
      'vcn': self.vcn,   # can be None
      'testnet': self._testnet,
      'depth': self._depth,
      'parentfp': self.parentfp().hex(),
      'childnum': self._childnum,
    }
    
    if self._prvkey:   # int or long, can not be 0
      sPrv = number_to_string(self._prvkey,curve.order)
      assert(len(sPrv) <= 255)
      sPrv = (b'%02x' % len(sPrv)) + sPrv
      
      if passphrase:
        sPrv = _aesEncrypt(sPrv,passphrase)
        account['encrypted'] = True
      
      account['prvkey'] = sPrv.hex()
      account['pubkey'] = self.publicKey().hex()
    elif self._pubkey:
      account['prvkey'] = None
      account['pubkey'] = point_compress(self._pubkey).hex()
    
    fp = self.fingerprint().hex()
    accounts = cfg.get('accounts',None)
    if accounts is None:  # no account yet
      cfg['accounts'] = accounts = {}
    accounts[fp] = account
    cfg['default'] = fp
    return cfg
  
  @staticmethod
  def load_from_cfg(account, passphrase=''):
    prvKey = account['prvkey']; pubKey = account['pubkey']
    if prvKey:
      prvKey = unhexlify(prvKey)
      if account.get('encrypted'):
        prvKey = _aesDecrypt(prvKey,passphrase)
      
      try:
        orgLen = int(prvKey[:2],16); nowLen = len(prvKey)
        if nowLen < 2 + orgLen or nowLen > orgLen + 17:   # 17 is 2 + padding(15)
          raise ValueError('out of range')
        prvKey = prvKey[2:2+orgLen]      # first 2 bytes is original length
      except:
        raise ValueError('invalid private key')
      prvKey = string_to_number(prvKey)  # prvKey must not be 0
    elif pubKey:
      pubKey = point_decompress(curve.curve,unhexlify(pubKey))
    
    chaincode = unhexlify(account['chain'])  # must be 32 bytes
    parentfp = account.get('parentfp',None)
    if parentfp: parentfp = unhexlify(parentfp)
    
    return HDWallet( prvKey or pubKey, chaincode,
      vcn=account.get('vcn',None), testnet=account.get('testnet',False),
      depth=account.get('depth',None), childnum=account.get('childnum',None), 
      parentfp=parentfp )
  
  def __str__(self):
    privateKey = 'None'
    if self._prvkey: privateKey = '**redacted**'
    return '<HD address=%s private=%s>' % (self.address(),privateKey)

def main():
  # 1. generate a master wallet with a (random) seed 
  master = HDWallet.from_master_seed('HDWallet seed')
  # 2. store the Private Extended Key somewhere very (!) safe
  prv_master_key = master.to_extended_key(include_prv=True)
  # 3. store the Public Extended Key on the webserver
  pub_master_key = master.to_extended_key()
  
  # 4. On the webserver we can generate child wallets, 
  webserver_wallet = HDWallet.from_extended_key(pub_master_key)
  child2342 = webserver_wallet.child(23).child(42)
  print('- Public Extended Key (M):',pub_master_key)
  print('Child: M/23/42')
  print('Address:',child2342.address())
  print('Privkey:',child2342.prvkey()) # ... but the private keys remain _unknown_
  print('')
  
  # 5. In case we need the private key for a child wallet, start with the private master key
  cold_wallet = HDWallet.from_extended_key(prv_master_key)
  child2342 = cold_wallet.child(23).child(42)
  print('- Private Extended Key (m):',prv_master_key)
  print('Child: m/23/42')
  print('Address:',child2342.address())
  print('Privkey:',child2342.prvkey().hex())

if __name__ == "__main__":
  main()
