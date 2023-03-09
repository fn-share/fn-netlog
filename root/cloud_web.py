# root/cloud_web.py

import traceback
from flask import request, render_template

import logging
logger = logging.getLogger(__name__)

from . import app

_config = {}
_app_admin_pubkey = ''
_app_strategy_str = '{}'

@app.route('/favicon.ico')
def favicon():
  return app.send_static_file('favicon.ico')

@app.route('/')
@app.route('/index.html')
def index_page():
  info = { 'real_website': _config['real_website'],
    'app_admin_pubkey': _app_admin_pubkey,
    'app_strategy': _app_strategy_str }
  return render_template('index.html',info=info)

@app.route('/is_alive')
def is_alive():
  return 'OK'

#------

def cloud_web_init(config):
  global _config, _app_admin_pubkey, _app_strategy_str
  _config = config
  
  import json
  from nbc import wallet
  _app_admin_pubkey = wallet.Address(priv_key=config['app_admin_wif'].encode('utf-8')).publicKey().hex()
  _app_strategy_str = json.dumps(config['strategy'],indent=None,separators=(',',':'))
  
  from .ssi_login import ssi_login_init
  ssi_login_init(config)
