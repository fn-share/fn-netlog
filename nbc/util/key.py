# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import hashlib
from hashlib import sha256

from . import base58

from .ecdsa.ecdsa import point_is_valid
from .ecdsa import SECP256k1 as curve
from .ecdsa.numbertheory import square_root_mod_prime
from .ecdsa.util import number_to_string, string_to_number

__all__ = [ 'compress_public_key', 'decompress_public_key',
  'privkey_to_wif', 'privkey_from_wif',
  'publickey_to_address', 'publickey_to_hash', 'publichash_to_address' ]


if type(bytes) == str:  # python 2
  def _bytes(t):
    return bytes(bytearray(t))
else: _bytes = bytes    # python 3

def compress_public_key(public_key):
  if len(public_key) != 65 or ord(public_key[:1]) != 4:  # public_key[0] != b'\x04'
    raise ValueError('invalid uncompressed public key')
  y_tail = ord(public_key[64:65]) & 0x01
  return _bytes((2+y_tail,)) + public_key[1:33]

_a = curve.curve.a()
_b = curve.curve.b()
_p = curve.curve.p()
_n = curve.order

def decompress_public_key(public_key):
  ch = ord(public_key[:1])
  if ch == 4 and len(public_key) == 65:
    x = string_to_number(public_key[1:33])
    y = string_to_number(public_key[33:65])
    if not point_is_valid(curve.generator,x,y):
      raise ValueError('invalid public key')
    return public_key
  
  if (ch != 2 and ch != 3) or len(public_key) != 33:
    raise ValueError('invalid compressed public key')
  
  x = string_to_number(public_key[1:])
  y = square_root_mod_prime((x ** 3 + _a * x + _b) % _p, _p)
  if not point_is_valid(curve.generator,x,y):
    raise ValueError('invalid public key')
  
  if (ch & 0x01) != (y & 0x01):
    y = _p - y
  
  return b'\x04' + public_key[1:] + number_to_string(y,_n)

# See: https://en.bitcoin.it/wiki/Wallet_import_format
def privkey_to_wif(privkey, prefix = b'\x80'):
  return base58.encode_check(prefix + privkey)

# See: https://en.bitcoin.it/wiki/Wallet_import_format
def privkey_from_wif(privkey, prefix = b'\x80'):
  key = base58.decode_check(privkey)
  if ord(prefix[:1]) != ord(key[:1]):
    raise ValueError('wif private key has does not match prefix')
  
  key_len = len(key)
  if key_len == 33:
    ch = ord(privkey[:1])
    if ch != 53:  # 53 is '5'
      raise ValueError('uncompressed wif private key does not begin with 5')
    return key[1:]
  elif key_len == 34:
    if ord(key[-1:]) != 1:  # not 0x01
      raise ValueError('compressed wif private key missing compression bit')
    ch = ord(privkey[:1])
    if ch != 76 and ch != 75:  # 76 is 'L', 75 is 'K'
      raise ValueError('uncompressed wif private key does not begin with 5')
    return key[1:-1]
  
  raise ValueError('invalid wif private key')

def publickey_to_address(publickey, vcn=None, ver=b'\x00'):
  pubHash = hashlib.new('ripemd160',sha256(publickey).digest()).digest()
  if vcn is None:   # for bitcoin style
    return base58.encode_check(ver + pubHash)
  else:    # for NBC parallel chain
    return base58.encode_check(ver+_bytes(divmod(vcn&0xffff,256)) + pubHash)

def publickey_to_prefix_addr(publickey, vcn=None, prefix=''):
  if not isinstance(prefix,bytes):
    prefix = prefix.encode('utf-8')
  
  pubHash = hashlib.new('ripemd160',sha256(publickey).digest()).digest()
  if vcn is None:   # for bitcoin style
    pubHash2 = pubHash
  else: pubHash2 = _bytes(divmod(vcn & 0xffff,256)) + pubHash
  crc = sha256(sha256(prefix + pubHash2).digest()).digest()[:4]
  return prefix + base58.b58encode(pubHash2 + crc)

def publickey_to_hash(publickey):
  return hashlib.new('ripemd160',sha256(publickey).digest()).digest()

def publichash_to_address(publichash, vcn=None, ver=b'\x00'):
  if vcn is None:
    return base58.encode_check(ver + publichash)
  else:
    hi,lo = divmod(vcn & 0xffff,256)
    return base58.encode_check(ver + _bytes((lo,hi)) + publichash)
