// nal.js -- NBC Account Library
// by Wayne Chan, 2022 ~ 2024

const NAL = ( function() {

const NAL_BUFF_SIZE = 16;

var sw_call_idx_ = 0;

var sw_magic_   = null;
var sw_channel_ = {};   // { strategy_ver, host }
var sw_storage_ = null;
var sw_verInfo_ = null;

var _msg_buff = [];

window.addEventListener('message', function(ev) {
  if (ev.source === window && typeof ev.data == 'string' && ev.data.slice(0,8) === 'NAL_RPY:') {
    try {
      let obj = JSON.parse(ev.data.slice(8));
      _msg_buff.push([obj.id || 0,obj.result]);
      while (_msg_buff.length > NAL_BUFF_SIZE) _msg_buff.shift();
    }
    catch(e) {}
  }
});

const _NAL = {
  // NAL.call_(cmd,param).then(res => console.log(res))
  //   .catch(err => console.log(err))
  //   .finally(() => console.log('finally do something'))
  call_(cmd, param, wait) {
    sw_call_idx_ += 1;
    let new_id = sw_call_idx_;
    if (!wait) wait = 5000;  // default max wait 5 seconds
    
    let resolve_fn, reject_fn;
    let waitObj = new Promise( (resolve, reject) => {
      resolve_fn = resolve;
      reject_fn = reject;
    });
    
    let counter = 0;
    let taskId = setInterval( () => {
      counter += 250;
      if (counter >= wait) {
        clearInterval(taskId);
        console.log('NAL request timeout: ' + cmd);
        reject_fn(new Error('TIMEOUT'));
      }
      else {
        let succ = false, found = null, oldest = new_id - 128;
        for (let i=_msg_buff.length-1; i >= 0; i--) {
          let item = _msg_buff[i], itemId = item[0];
          if (itemId === new_id) {
            _msg_buff.splice(i,1);
            found = item[1];
            succ = true;
          }
          else if (itemId < oldest)
            _msg_buff.splice(i,1);  // remove too old reply item
        }
        
        if (succ) {
          clearInterval(taskId);
          resolve_fn(found);
        }
      }
    }, 250);
    
    if (!param) param = [];
    window.postMessage('NAL_REQ:'+JSON.stringify({id:new_id,cmd,param}));
    
    return waitObj;
  },
  
  verInfo(info) { // reconstruct json to avoid side effects
    if (info) sw_verInfo_ = info;  // set ver info
    return sw_verInfo_;
  },
  
  swMagic(callback, magic, wait) {
    let oldValue = sw_magic_;
    if (!callback) {   // read sw_magic_
      if (typeof magic == 'number')
        sw_magic_ = magic;
      return oldValue;
    }
    // else, reset sw_magic_
    
    sw_magic_ = null;
    _NAL.call_('regist_magic',null,wait || 5000).then( res => {  // default max wait 5 seconds
      sw_magic_ = res.sw_magic;
      sw_channel_ = { strategy_ver:res.strategy_ver, host:res.host };
      sw_storage_ = res.storage;
      sw_verInfo_ = res.ver_info;
      callback(sw_magic_);
    }).catch(err => callback(null));
    
    return oldValue;
  },
  
  swHost() {
    return sw_channel_.host || '';
  },
  
  strategyVer() {
    return sw_channel_.strategy_ver;  // null means not ready
  },
  
  swStorage() {
    return sw_storage_;
  },
  
  waitReady(wait) {
    let resolve_fn, reject_fn;
    let waitObj = new Promise( (resolve, reject) => {
      resolve_fn = resolve;
      reject_fn = reject;
    });
    
    _NAL.swMagic( magic => {
      if (magic === null)
        reject_fn(new Error('FAILED'));
      else resolve_fn(sw_verInfo_);
    }, wait);
    
    return waitObj;
  },
};

let inDlgShowing = false;

_NAL.dialogShowing = function() { return inDlgShowing; };

_NAL.dialog = ( () => {

function noResponse(e) {
  e.stopPropagation();
}

let maskNode = (() => {
  let node = document.querySelector('#nal-mask');
  if (!node) {
    node = document.createElement('div');
    node.setAttribute('id','nal-mask');
    node.setAttribute('style','display:none; background:rgba(0,0,0,0.5); position:fixed; z-index:1056; left:0; top:0; right:0; bottom:0; padding:0; margin:0; border-width:0;');
    node.onclick = node.ondblclick = node.onmousedown = node.ontouchstart = noResponse;
    document.body.appendChild(node);
  }
  return node;
})();

function closeDialog() {
  document.querySelectorAll('#nal-mask > div[name^="dlg-"]').forEach( node => {
    node.style.display = 'none';
  });
  maskNode.style.display = 'none';
  inDlgShowing = false;
}

let nalDialogResolve = null, nalDialogReject = null;
let nalCheckPassId = 0;

return ( (name,args) => {
  if (inDlgShowing) {
    return new Promise( function(resolve, reject) {
      reject(new Error('SYSTEM_BUSY'));
    });
  }
  
  if (typeof _NAL.swMagic() != 'number') {
    return new Promise( function(resolve, reject) {
      reject(new Error('CANCELED'));
    });
  }
  
  let task = new Promise( function(resolve, reject) {
    nalDialogResolve = resolve; // affects history task, it is safe since only one dialog in showing always
    nalDialogReject = reject;
  });
  let dialog = null, startupFn = null;
  
  if (name == 'sign' || name == 'pass') {
    if (nalCheckPassId) {
      clearInterval(nalCheckPassId);
      nalCheckPassId = 0;
    }
    
    let hintDialog = maskNode.querySelector('div[name="dlg-hint"]');
    if (!hintDialog) {
      hintDialog = document.createElement('div');
      hintDialog.setAttribute('name','dlg-hint');
      hintDialog.setAttribute('style','display:none; background:white; position:relative; width:360px; left:calc(50% - 180px); top:68px; border-radius:0.25rem;');
      hintDialog.innerHTML = '<div style="height:4.5rem"><span style="display:inline-block; float:left; margin:1.25rem; font-size:1.25rem; font-weight:500;">待授权</span><button name="btn-cancel" style="display:inline-block; border-width:0; background-color:#fff; font-size:2.25rem; font-weight:200; color:#000; opacity:0.5; float:right; margin:0 8px;">&times;</button></div><div style="border:solid rgba(0,0,0,0.2); border-width:1px 0; padding:1.25rem;"><p style="margin: 0.75rem 0 1rem">请在 chrome 浏览器插件（NalPass）完成授权。</p></div>';
      maskNode.appendChild(hintDialog);
      
      let node = hintDialog.querySelector('button[name="btn-cancel"]');
      node.onmouseover = (ev => ev.target.style.opacity = '1');
      node.onmouseout = (ev => ev.target.style.opacity = '0.5');
      node.onclick = ( ev => {
        if (nalCheckPassId) {
          clearInterval(nalCheckPassId);
          nalCheckPassId = 0;
          if (name == 'sign')
            _NAL.call_('rmv_wait_sign',[_NAL.swMagic()]);
        }
        if (name == 'sign') document.body.setAttribute('nal-last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
    }
    
    let currHost = _NAL.swHost(), currMagic = _NAL.swMagic();
    let now = Math.floor((new Date()).valueOf() / 1000);
    if (name == 'sign') {
      if (args && args.length) {  // add: realm, child, hex_tobe_sign
        // have 'realm' means waiting sign, while only 'currHost,currMagic,now' means query if signature be done
        document.body.setAttribute('nal-last-sign',now+'');
        document.body.setAttribute('nal-last-realm',args[0]+'');
        
        _NAL.call('pass_sign',[currMagic,now, ...args]).then( res => {
          if (res !== 'ADDED') {  // meet unexpected error
            document.body.setAttribute('nal-last-sign','0');
            closeDialog();
            nalDialogReject(new Error('CANCELED'));
          }
          else waitingSignPass([currMagic,now],args[0]);
        });
      }
      else { // error, nothing to sign
        document.body.setAttribute('nal-last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      }
    }
    else {
      document.body.setAttribute('nal-last-sign',now+'');
      document.body.setAttribute('nal-last-realm','@'); // '@' means only check account be ready in SW, no authority
      waitingSwPass([currMagic]);
    }
    
    dialog = hintDialog;
  }
  
  else if (name == 'rsvd') {
    if (!args.length) return null; // fatal error, should not happen
    let rsvdDialog = maskNode.querySelector('div[name="dlg-rsvd"]');
    if (!rsvdDialog) {
      rsvdDialog = document.createElement('div');
      rsvdDialog.setAttribute('name','dlg-rsvd');
      rsvdDialog.setAttribute('style','display:none; background:white; position:relative; width:300px; left:calc(50% - 150px); top:68px; border-radius:0.25rem;');
      rsvdDialog.innerHTML = '<div style="height:4.5rem"><span style="display:inline-block; float:left; margin:1.25rem; font-size:1.25rem; font-weight:500;">请选择保留字</span><button name="btn-cancel" style="display:inline-block; border-width:0; background-color:#fff; font-size:2.25rem; font-weight:200; color:#000; opacity:0.5; float:right; margin:0 8px;">&times;</button></div><div name="rsvd-body" style="border:solid rgba(0,0,0,0.2); border-width:1px 0 0; padding:1.25rem 0 2rem; user-select:none; font-family:monospace; font-size:1rem; line-height:1.5; text-align:center;"></div>';
      maskNode.appendChild(rsvdDialog);
      
      let node = rsvdDialog.querySelector('button[name="btn-cancel"]');
      node.onmouseover = (ev => ev.target.style.opacity = '1');
      node.onmouseout = (ev => ev.target.style.opacity = '0.5');
      node.onclick = ( ev => {
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
      
      node = rsvdDialog.querySelector('div[name="rsvd-body"]');
      let btn = document.createElement('button');
      btn.setAttribute('style','border:1px solid transparent; margin:0.25rem 0.5rem; padding:0.5rem 0.75rem; color:#fff; background-color:#198754; border-color:#198754; border-radius:1.5rem;');
      
      let i = 0, btn2 = btn;
      while (true) {
        btn2.innerHTML = args[i] || ''; // 3~5 number, no need escape
        btn2.onmouseover = rsvdMouseOver;
        btn2.onmouseout = rsvdMouseOut;
        btn2.onclick = rsvdSelected;
        node.appendChild(btn2);
        
        if (i == 2 || i == 5)
          node.appendChild(document.createElement('br'));
        
        i += 1;
        if (i >= 9) break;
        btn2 = btn.cloneNode(false);
      }
      
      function rsvdMouseOver(ev) {
        ev.target.style.opacity = '0.8';
      }
      function rsvdMouseOut(ev) {
        ev.target.style.opacity = '1';
      }
      function rsvdSelected(ev) {
        let ret = ev.target.innerHTML; // 3~5 number
        closeDialog();
        nalDialogResolve(ret);
      }
    }
    else {
      let items = rsvdDialog.querySelectorAll('div[name="rsvd-body"] > button');
      args.forEach( (item,idx) => {
        if (idx < items.length) items[idx].innerHTML = item;
      });
    }
    
    dialog = rsvdDialog;
  }
  
  if (!dialog) return null; // fatal error, name is not one of: 'sign' 'pass' 'rsvd'
  
  inDlgShowing = true;
  maskNode.style.display = 'block';
  dialog.style.display = 'block';
  if (startupFn) startupFn();
  
  return task;
  
  function waitingSignPass(param, expected) {
    nalCheckPassId = setInterval( () => {
      _NAL.call_('pass_sign',param,10000).then( res => {
        if (res?.realm) {
          if (nalCheckPassId) {
            clearInterval(nalCheckPassId);
            nalCheckPassId = 0;
          }
          
          document.body.setAttribute('nal-last-sign','0');
          closeDialog();
          if (res.realm === expected && res.signature)
            nalDialogResolve(res);  // {child,pubkey,realm,signature}
          else nalDialogReject(new Error('CANCELED')); // if no res.signature, it must be canceled
        }
        // else, continue next loop, maybe wait forever
      }).catch( e => {  // meet unexpected error
        document.body.setAttribute('nal-last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
    }, 1200);
  }
  
  function waitingSwPass(param, expected) {
    nalCheckPassId = setInterval( () => {
      _NAL.call_('config_acc',param).then( res => {
        if (res !== 'WAIT_PASS') {
          if (nalCheckPassId) {
            clearInterval(nalCheckPassId);
            nalCheckPassId = 0;
          }
          
          document.body.setAttribute('nal-last-sign','0');
          closeDialog();
          nalDialogResolve('PASSED');
        }
        // else, continue next loop, maybe wait forever
      }).catch( e => {  // meet unexpected error
        document.body.setAttribute('nal-last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
    }, 1200);
  }
});   // end of return xx

})(); // assign to _NAL.dialog

_NAL.call = function(cmd, param, wait) {
  return _NAL.call_(cmd,param,wait).then( res => {
    if (res === 'WAIT_PASS') {
      return _NAL.dialog('pass').then( res => { // death waiting result: passed or canceled
        if (res === 'PASSED')
          return _NAL.call_(cmd,param,wait);
        else throw Error('CANCELED');
      });
    }
    else return res;
  });
};

return _NAL;
})();  // end of const NAL = (function() ...)

//----

( function() {  // SSI implement, add APIs as NAL.xxx

const ECDH = require('create-ecdh')('secp256k1');
const CryptoJS = require('crypto-js');
const CreateHash = require('create-hash');
const Buffer = require('safe-buffer').Buffer;
const base36 = require('base-x')('0123456789abcdefghijklmnopqrstuvwxyz');

// 6m, 15m, 30m, 1h, 3h, 8h, 1d, 7d
const session_periods = [360,900,1800,3600,10800,28800,86400,604800];
// 30m, 90m, 5h, 10h, 24h, 3d, 7d, 63d
const refresh_periods = [1800,5400,18000,36000,86400,259200,604800,5443200];  

let STRATEGY = {};
let DEFAULT_PERIOD = 900;
let DEFAULT_REFRESH = 5400;
let REFRESH_LIMIT = 14;

const colonChar = Buffer.from(':');

function wait__(promise_obj, wait) {
  let abort_fn = null;
  let abortable_promise = Promise.race([ promise_obj,
    new Promise( function(resolve, reject) {
      abort_fn = function() { reject(new Error('TIMEOUT')) };
    })
  ]);
  
  setTimeout(()=>abort_fn(),wait);
  return abortable_promise;
}

function ripemdHash(buf) {
  let ha = CreateHash('sha256').update(buf).digest();
  return CreateHash('ripemd160').update(ha).digest();
}

let currRole = '';
let clientNonce = '';
let serverNonce = CryptoJS.enc.Hex.parse('');
let refresh_beg = 0;

let refresh_task = 0;
let next_refresh_tm = 0;  // by millisecond
let max_refresh_tm = 0;   // by second

let hmacSegment = null;
let lastHmacSeg = 0;
let lastNonceCrc = null;
let lastSessData = Buffer.from('0000','hex');

function shuffle(arr) {
  let i = arr.length, t, j;
  while (i) {
    j = Math.floor(Math.random() * i--);
    t = arr[i]; arr[i] = arr[j]; arr[j] = t;  // swap arr[i] and arr[j]
  }
}

NAL.strategy = function(stg) {
  if (!stg) return STRATEGY;
  DEFAULT_PERIOD = session_periods[stg.session_type];
  DEFAULT_REFRESH = refresh_periods[stg.session_type];
  REFRESH_LIMIT   = stg.session_limit;
  STRATEGY = stg;
  
  let scanStart = (new Date()).valueOf();
  let scanId = setInterval( () => {
    let passed = (new Date()).valueOf() - scanStart;
    if (passed > 90000) return clearInterval(scanId);  // max wait 90s
    
    let magic = NAL.swMagic();
    let reportVer = NAL.strategyVer();
    let realVer = STRATEGY.strategy_ver;
    if (typeof magic == 'number' && reportVer && realVer) {
      if (reportVer !== realVer) {
        NAL.call_('save_strategy',[magic,STRATEGY]).then( data => {
          if (data === 'OK')
            console.log('! strategy is changed from ' + reportVer + ' to ' + realVer);
        });
      }
      clearInterval(scanId);
    }
  },1000);
  
  return [stg,DEFAULT_PERIOD,DEFAULT_REFRESH,REFRESH_LIMIT];
};

NAL.cryptoHost = function(renew) {
  return NAL.call_('last_cryptohost',[renew || false]);
};

NAL.checkStart = function(role, nonce1, nonce2, sessData, beg, now, refreshNow) {
  if (refresh_task) {
    if (role === currRole && nonce1 === clientNonce && nonce2 === serverNonce.toString() && beg === refresh_beg)
      return false; // no change, do nothing 
    
    clearInterval(refresh_task);
    refresh_task = 0;
  }
  
  currRole = role;
  clientNonce = nonce1;
  serverNonce = CryptoJS.enc.Hex.parse(nonce2);
  lastSessData = sessData;
  refresh_beg = beg;
  
  let segBeg = Math.floor(beg / DEFAULT_REFRESH);
  let segEnd = Math.floor(now / DEFAULT_REFRESH);
  hmacSegment = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256,serverNonce);
  for (let i=segBeg; i <= segEnd; i++) {
    hmacSegment.update(':' + i);
    lastHmacSeg = i;
  }
  let s = currRole + ':' + clientNonce + ':' + segEnd;
  lastNonceCrc = CreateHash('sha256').update(Buffer.from(s)).digest().slice(0,3);
  
  max_refresh_tm = (segBeg + REFRESH_LIMIT + 1) * DEFAULT_REFRESH;
  next_refresh_tm = refreshNow? now*1000: ((segEnd+1)*DEFAULT_REFRESH-90)*1000;
  refresh_task = setInterval( () => {
    let tm = (new Date()).valueOf();
    if (tm >= next_refresh_tm) {
      tm = Math.floor(tm / 1000);
      
      if (tm >= max_refresh_tm) {
        if (refresh_task) {
          clearInterval(refresh_task);  // stop interval task
          refresh_task = 0;
        }
        NAL.doLogout();
        return;
      }
      
      let seg = Math.floor((tm+90)/DEFAULT_REFRESH); // ensure seg is newly next segment
      let s = currRole + ':' + clientNonce + ':' + seg;
      let crc3 = CreateHash('sha256').update(Buffer.from(s)).digest().slice(0,3);
      
      let tm2 = Math.max(seg * DEFAULT_REFRESH,tm);
      let body = {time:tm2, nonce:Buffer.from(clientNonce).toString('hex')};
      
      wait__(fetch('login/refresh',{method:'POST',body:JSON.stringify(body)}),30000).then( res => {
        if (res.status == 200)
          return res.json();
        else if (res.status == 401)
          return res.text();
        else return null;   // ignore other res.status
      }, e => null ).then( data => {
        if (data === null || typeof data == 'string') {
          if (data === 'INVALID_SID' || data === 'INVALID_NONCE') {
            if (refresh_task) {
              clearInterval(refresh_task);  // stop interval task
              refresh_task = 0;
            }
            NAL.doLogout();
          }
          return console.log('request refresh token failed');
        }
        
        lastNonceCrc = crc3;
        next_refresh_tm = ((seg+1)*DEFAULT_REFRESH-90)*1000;
      });
    }
  }, 30000); // checking every 30 seconds
};
  
NAL.role = function() {
  if (!refresh_task) return '';  // SSI refresh task not started, or expired
  return clientNonce? currRole: '';
};

NAL.sessData = function() {
  return lastSessData;
};

NAL.loginSess = function() {
  let size = lastSessData[1];
  let session = lastSessData.slice(2,2+size);
  return base36.encode(session); // maybe ''
};

NAL.token = function() {
  // step 1: check whole expired or not
  let tm = Math.floor((new Date()).valueOf() / 1000);
  if (tm >= max_refresh_tm) return '';  // failed too when max_refresh_tm is default 0-value
  
  // step 2: check localStorage matched, maybe have logout
  if (localStorage.getItem('client_nonce') !== clientNonce)
    return '';
  
  // step 3: try update lastHmacSeg and lastNonceCrc
  let oldHmacSeg = lastHmacSeg;
  let segEnd = Math.floor(tm / DEFAULT_REFRESH);
  for (let i=lastHmacSeg+1; i <= segEnd; i++) {
    hmacSegment.update(':' + i);
    lastHmacSeg = i;
  }
  
  if (oldHmacSeg != segEnd) {
    let s = currRole + ':' + clientNonce + ':' + segEnd;
    lastNonceCrc = CreateHash('sha256').update(Buffer.from(s)).digest().slice(0,3);
  }
  
  // step 4: caculate SSI token
  let bak = hmacSegment._hasher.clone();
  let ha = hmacSegment.finalize().toString(CryptoJS.enc.Hex);
  hmacSegment._hasher = bak;
  
  let n = Math.floor(tm / DEFAULT_PERIOD);
  let buf = Buffer.concat([Buffer.from(ha,'hex'),colonChar,lastNonceCrc,colonChar,lastSessData,Buffer.from(':'+n)]);
  let tok = ripemdHash(buf);
  return 'SSI-SIGN token=' + tok.toString('base64');
};

NAL.logout = function() {
  if (refresh_task) {
    clearInterval(refresh_task);  // stop interval task
    refresh_task = 0;
  }
  next_refresh_tm = 0;
  max_refresh_tm = 0;    
  
  clientNonce = '';
  serverNonce = CryptoJS.enc.Hex.parse('');
  refresh_beg = 0;
  
  hmacSegment = null;
  lastHmacSeg = 0;
  lastNonceCrc = null;
  lastSessData = Buffer.from('0000','hex');
  
  localStorage.setItem('client_nonce','');
  localStorage.setItem('server_nonce','');
  localStorage.setItem('sw_magic_time','0');
};

NAL.getPassport = function(is_meta) {
  return NAL.call('get_pspt',[NAL.swMagic(),is_meta],40000); // max waiting 40 seconds
};

NAL.doLogout = function() {
  NAL.call('did_logout',[NAL.swMagic()]).then( res => {
    if (res === 'OK') {
      NAL.logout();
      NAL.afterLogout();
    }
  });
};

NAL.afterLogout = function() {}; // waiting overwrite

NAL.actionSign = function(action, hexBeSign, realmEx) { // checker: undefined 'pass' 'sign' 'rsvd' 'auto'
  let role = NAL.role();
  if (!role)
    return new Promise( (resolve,reject) => resolve('NOT_LOGIN') );
  
  let roleInfo = STRATEGY.roles[role];
  let actionLv = STRATEGY.actions[action];
  if (!roleInfo)
    return new Promise( (resolve,reject) => resolve('INVALID_ROLE') );
  if (typeof actionLv != 'number')
    return new Promise( (resolve,reject) => resolve('INVALID_ACTION') );
  
  let needPass = false, needRsvd = false;
  let checker = roleInfo.actions[action]; // checker must defined
  if (typeof checker != 'string')
    return new Promise( (resolve,reject) => resolve('NO_ACTION') );
  
  if (checker == 'pass')
    needPass = true;
  else if (checker == 'rsvd')
    needRsvd = true;
  else { // checker == 'auto'
    if (roleInfo.level == actionLv)
      needPass = true;
    else if (roleInfo.level < actionLv)
      return new Promise( (resolve,reject) => resolve('NOT_AUTHORIZED') );
    // else, roleInfo.level > actionLv, sign directly
  }
  
  let realm = role + '+' + action + (realmEx? ('+'+realmEx): '');
  if (needRsvd) {
    return NAL.call('list_rsvd').then( rsvdList => {
      if (!(rsvdList instanceof Array) || !rsvdList.length) // unexpected error
        throw new Error('CANCELED');
      
      shuffle(rsvdList); // rsvdList must be an Array
      return NAL.dialog('rsvd',rsvdList).then( rsvd => {
        let now = Math.floor((new Date()).valueOf() / 1000);
        return NAL.call( 'pass_sign', [
          NAL.swMagic(),now,realm,0, // child=0 means choose login account
          hexBeSign,rsvd ] );
      });
    });
  }
  else if (needPass) {
    return NAL.dialog('sign',[realm,0,hexBeSign]);
  }
  else {  // sign directly
    let now = Math.floor((new Date()).valueOf() / 1000);
    return NAL.call( 'pass_sign', [
      NAL.swMagic(),now,realm,0, // child=0 means choose login account
      hexBeSign ] );
  }
};

})(); // end of SSI implement
