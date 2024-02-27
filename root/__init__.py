# root/__init__.py

import sys
if sys.version_info.major < 3:
  raise Exception('only support python v3+')

import os
from flask import Flask

app = Flask( __name__,
  static_folder=os.path.abspath('./www'),
  static_url_path='/www',
  template_folder=os.path.abspath('./templates') )
