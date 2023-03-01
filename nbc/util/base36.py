# base36.py

from hashlib import sha256

__all__ = ['b36encode', 'b36decode', 'encode_check', 'decode_check']

# 36 character alphabet, it suites for domain expression
alphabet = b'0123456789abcdefghijklmnopqrstuvwxyz'
alph_idx = dict([(ch,idx) for idx,ch in enumerate(alphabet)])

if bytes == str:  # python2
  iseq, bseq, buffer = (
    lambda s: map(ord,s),
    lambda s: ''.join(map(chr,s)),
    lambda s: s )
else:  # python3
  iseq, bseq, buffer = (
    lambda s: s,
    bytes,
    lambda s: s.buffer )

def scrub_input(v):
  if not isinstance(v,bytes):
    v = v.encode('ascii')
  if not isinstance(v,bytes):
    raise TypeError("a bytes-like object is required, not '%s'" % type(v).__name__)
  return v

def b36encode_int(i, default_one=True):   # encode an integer using base36
  if not i and default_one:  # i can not be 0
    return alphabet[0:1]
  s = b''
  while i:
    i,idx = divmod(i,36)
    s = alphabet[idx:idx+1] + s
  return s

def b36encode(v):      # encode a string using base36
  v = scrub_input(v)
  nPad = len(v)
  v = v.lstrip(b'\x00')
  nPad -= len(v)
  
  p,acc = 1,0
  for c in iseq(reversed(v)):
    acc += p * c
    p = p << 8
  
  ret = b36encode_int(acc,default_one=False)
  return (alphabet[0:1] * nPad + ret)

def b36decode_int(v):  # decode a base36 encoded string as an integer
  v = scrub_input(v)
  decimal = 0
  for ch in v:
    decimal = decimal*36 + alph_idx[ch]
  return decimal

def b36decode(v):      # decode a base36 encoded string
  v = scrub_input(v)
  origlen = len(v)
  v = v.lstrip(alphabet[0:1])
  newlen = len(v)
  
  acc = b36decode_int(v)
  
  ret = []
  while acc > 0:
    acc, mod = divmod(acc, 256)
    ret.append(mod)
  
  return (b'\0' * (origlen-newlen) + bseq(reversed(ret)))

def encode_check(v):  # encode a string using base36 with a 4 character checksum
  digest = sha256(sha256(v).digest()).digest()
  return b36encode(v + digest[:4])

def decode_check(v):  # decode and verify the checksum of a base36 encoded string
  ret = b36decode(v)
  ret, check = ret[:-4], ret[-4:]
  digest = sha256(sha256(ret).digest()).digest()
  
  if digest[:4] == check:
    return ret
  else: return None
