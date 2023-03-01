# nbc/wallet: NBC Wallet, for details please visit https://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import json
from .address import Address
from .hdwallet import HDWallet

__all__ = ['Address', 'HDWallet', 'loadFrom', 'saveTo']

def saveTo(fileName, wallet, passphrase='', cfg=None):
  cfg = wallet.dump_to_cfg(passphrase,cfg)  # save current account and set current figerprint to cfg['default']
  sCfg = json.dumps(cfg,indent=2)
  with open(fileName,'w') as f:
    f.write(sCfg)

def loadFrom(file_or_cfg, passphrase='', figerprint=''):
  if isinstance(file_or_cfg,dict):
    cfg = file_or_cfg
  else:
    with open(file_or_cfg,'r') as f:
      cfg = json.loads(f.read())
  
  if figerprint:
    fp = figerprint
  else:
    fp = cfg.get('default',None)
    if fp is None:
      b = [(v['time'],k) for k,v in cfg['accounts'].items()]
      if b: fp = sorted(b)[-1][1]  # try last created one
  
  account = None
  if fp is not None:
    account = cfg['accounts'].get(fp,None)
  
  if account:
    tp = account.get('type')
    if tp == 'HD':
      return HDWallet.load_from_cfg(account,passphrase)
    elif tp == 'default':
      return Address.load_from_cfg(account,passphrase)
    else: raise RuntimeError('unknown account')
  else: return None  # no account exists
