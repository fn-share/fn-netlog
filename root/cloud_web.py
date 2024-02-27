# root/cloud_web.py

import traceback
from flask import request

from . import app

@app.route('/favicon.ico')
def favicon():
  return app.send_static_file('favicon.ico')

@app.route('/is_alive')
def is_alive():
  return 'OK'

def cloud_web_init(config):
  pass
