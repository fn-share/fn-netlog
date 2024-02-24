# plt_dataset.py

import os, sys, time, hashlib, sqlite3, json, traceback
from binascii import unhexlify

import logging
logger = logging.getLogger(__name__)

#----

_data_dir = os.environ.get('LOCAL_DIR','./data')
os.makedirs(_data_dir,exist_ok=True)

KEY_VERSION = 1

class DbException(Exception): pass

class Database(object):
  # Columns is: [(column_name,column_type,should_index)...]
  Columns = []          # will set by subclass
  Name = 'table_name'   # will set by subclass
  
  # denote non-backwards-compatible changes
  Version = 1
  
  def __init__(self, data_dir=None):
    if data_dir is None:
      data_dir = os.path.join(_data_dir,'netlog')
      os.makedirs(data_dir,exist_ok=True)
    self.__data_dir = data_dir
    self.sql_select = 'SELECT %s FROM %s' % (','.join(n for (n,t,i) in self.Columns),self.Name)
    
    offset = 0
    if len(self.Columns) and self.Columns[0][0] == 'id':   # id is special field, auto increase
      offset = 1
    self.sql_insert = 'INSERT INTO %s (%s) values (%s)' % ( self.Name,
      ','.join(n for (n,t,i) in self.Columns[offset:]),
      ','.join('?' for c in self.Columns[offset:]) )
  
  def init_database(self, connection):
    cursor = connection.cursor()
    
    try:
      # create a metadata table to track version and custom keys/values
      sql = 'CREATE TABLE metadata (key INTEGER PRIMARY KEY, value INTEGER, value_bin BLOB)'
      cursor.execute(sql)
      
      # set the database version
      sql = 'INSERT INTO metadata (key, value, value_bin) values (?, ?, ?)'
      cursor.execute(sql,(KEY_VERSION,self.Version,None))
      
      # create table
      column_defs = ','.join('%s %s' % (n,t) for (n,t,i) in self.Columns)
      sql = 'CREATE TABLE %s (%s)' % (self.Name,column_defs)
      cursor.execute(sql)
      
      # add index
      for (n,t,i) in self.Columns:
        if not i: continue
        sql = 'CREATE INDEX index_%s on %s (%s)' % (n, self.Name, n)
        cursor.execute(sql)
      
      # let subclasses pre-populate the database
      self.populate_database(cursor)
      
      connection.commit()
    
    except sqlite3.OperationalError as e:  # it will happen every time except first
      if str(e) != ('table metadata already exists'):
        raise e
      
      version = self.get_metadata(cursor,KEY_VERSION)
      if version != self.Version:       # check compatible
        raise DbException('incompatible database version: %s (expected %d)' % (version,self.Version))
  
  def populate_database(self, cursor):  # waiting overwrite
    pass
  
  def get_filename(self):
    return os.path.join(self.__data_dir,'%s.sqlite' % (self.Name,))
  
  def get_connection(self, iso_level='', same_thread=False):  # iso_level='' means smart commit
    filename = self.get_filename()
    os.makedirs(os.path.split(filename)[0],exist_ok=True)
    
    connection = sqlite3.connect(filename,timeout=5,isolation_level=iso_level,check_same_thread=same_thread)
    connection.row_factory = sqlite3.Row
    self.init_database(connection)
    return connection
  
  def set_metadata(self, cursor, key, value):   # the value can be integer or string
    if key == KEY_VERSION:
      raise ValueError('cannot change version')
    
    sql = 'INSERT OR REPLACE INTO metadata (key, value, value_bin) values (?, ?, ?)'
    if isinstance(value,int):
      cursor.execute(sql,(key,value,None))
    elif isinstance(value,str):
      cursor.execute(sql,(key,0,bytes(value)))
    else: raise ValueError('metadata value must be integer or string')
    cursor.connection.commit()
  
  def get_metadata(self, cursor, key, default=None):
    sql = 'SELECT value,value_bin FROM metadata WHERE key = ?'
    cursor.execute(sql,(key,))
    row = cursor.fetchone()
    if row:
      if row[1] is not None:
        return bytes(row[1])
      return row[0]
    else: return default

class PltAccount(Database):
  Columns = [
    ('fp_', 'TEXT PRIMARY KEY NOT NULL', True),  # hex string
    ('plt_sn_', 'INTEGER NOT NULL', True),       # platform pubkey SN
    ('plt_', 'BLOB NOT NULL', True),             # platform pubkey, 32 bytes
  ]
  
  Name = 'plt_account'
  
  def __init__(self):
    Database.__init__(self)
    self._connection = self.get_connection()
  
  def query(self, what):  # hex str for fp, int for sn, bytes for pubkey
    cursor = self._connection.cursor()
    if isinstance(what,int):
      cursor.execute(self.sql_select + ' WHERE plt_sn_ = ?',(what,))
    elif isinstance(what,bytes):
      cursor.execute(self.sql_select + ' WHERE plt_ = ?',(what,))
    else: cursor.execute(self.sql_select + ' WHERE fp_ = ?',(str(what),))
    row = cursor.fetchone()
    return tuple(row) if row else None
  
  def update(self, values):
    sql = 'INSERT OR REPLACE INTO %s (fp_, plt_sn_, plt_) values (?, ?, ?)' % (self.Name,)
    with self._connection as conn:
      conn.execute(sql,values)
      conn.commit()

plt_account = PltAccount()

#----

from nbc import wallet

from urllib.request import urlopen
from urllib.parse import urljoin, quote
from urllib.error import HTTPError

_tee_manager_site = ''

def gncd_verify_plt(figerprint, card, sig):
  request_ok = True
  try:
    fp = figerprint.hex() if isinstance(figerprint,bytes) else figerprint
    if not isinstance(fp,str) or len(fp) != 8: return False
    
    row = plt_account.query(fp)
    if row:   # (fp,sn,pubkey)
      sn = row[1]
      pubkey = row[2]
    else:
      sn = -1; pubkey = b''
      
      request_ok = False
      if _tee_manager_site:
        res = None
        url = urljoin(_tee_manager_site,'account_info') + '?plt=' + quote(fp)
        for i in range(2):    # max try 2 times
          try:
            res = urlopen(url,timeout=15).read()
            if res:
              res = json.loads(res)  # {plt_sn,plt_pubkey}
              request_ok = True
              break
          except HTTPError as e:
            logger.warning('request url (%s) failed: %s',url,e.code)
            if e.code == 400: break
          except:
            logger.warning(traceback.format_exc())
        
        if isinstance(res,dict) and 'plt_sn' in res and 'plt_pubkey' in res:
          try:
            sn = int(res['plt_sn'])
            pubkey = unhexlify(res['plt_pubkey'])
            if (0 <= sn <= 65535) and len(pubkey) == 33:
              plt_account.update((fp,sn,pubkey))
          except:
            logger.warning(traceback.format_exc())
    
    if (0 <= sn <= 65535) and len(pubkey) == 33:
      acc = wallet.Address(pub_key=pubkey)
      if acc.verify_ex(card,sig,single=True,no_der=True):
        return True
  except:
    logger.warning(traceback.format_exc())
  
  if not request_ok:
    raise RuntimeError('REQUEST_FAILED')
  return False

def plt_dataset_init(manager_site):
  global _tee_manager_site
  _tee_manager_site = manager_site
