# application.py

import sys, os
if sys.version_info.major < 3:
  raise Exception('only support python v3+')

_data_dir = os.environ.get('LOCAL_DIR','./data')
os.makedirs(_data_dir,exist_ok=True)


#---- config logger

import traceback, logging

_log_fmt = '%(asctime)s [%(name)s %(levelname)s] %(message)s'
logging.basicConfig(level=logging.DEBUG if sys.flags.debug else logging.INFO,format=_log_fmt)

logger = logging.getLogger()

# True/False for logging to file or not
if False:  # max rotate 20 files, every file upto 4M
  from logging.handlers import RotatingFileHandler
  
  _log_file = None
  
  def _getLogger(name=None):
    logger = logging.old_getLogger(name)
    if _log_file:
      logger.addHandler(_log_file)
    return logger
  
  logging.old_getLogger = logging.getLogger
  logging.getLogger = _getLogger  # replace old one to easier get logger that automatic call addHandler()
  
  try:    # create log file maybe error
    _log_file = RotatingFileHandler(os.path.join(_data_dir,'log.txt'),maxBytes=4096*1024,backupCount=20)
    _log_file.setFormatter(logging.Formatter(_log_fmt))
    # _log_file.setLevel(logging.INFO)
    logger.addHandler(_log_file)
  except:
    logger.warning(traceback.format_exc())
    _log_file = None

#----

import json
try:
  if os.path.exists('config.json'):
    with open('config.json') as fp:
      config = json.load(fp)
  else: config = {}
except:
  logger.warning(traceback.format_exc())
  sys.exit(1)

from root import app
application = app

from root.cloud_web import cloud_web_init
cloud_web_init(config)

from root.netlog import netlog_init
netlog_init(config)

if __name__ == '__main__':
  print('start web server at http://localhost:3000')
  application.run(host='0.0.0.0',port=3000,debug=sys.flags.debug)

# Usage:
#   python3 application.py
# environ variables:
#   LOCAL_DIR=/home/webapp/data
#   WEB_REALM=netlog.fn-share.com
#   WEB_NONCE=WEBSITE_SECRET
#   APP_SECRET=change_it_please
