// nal.js -- NBC Account Library
// by Wayne Chan, 2022 ~ 2023

const NAL = ( function() {

let accFrameNode = null;

let sw_call_idx_ = 0;
let sw_call_buf_ = []; // waiting buffer for NAL_.call_()

let app_version_  = null;
let app_abnormal_ = '';

let sw_magic_ = null;
let sw_channel_ = {};   // { strategy_ver, host }

let sw_notifies_ = {
  ver_info(param) {
    app_version_ = param[0];
    if (app_version_ === null)
      app_abnormal_ = param[1]+''; // can be: none, installing, installed, activating, activated, redundant
    else app_abnormal_ = '';
  },
};

window.addEventListener('message', function(ev) {
  if (ev.source !== accFrameNode?.contentWindow) {
    if (ev.data.slice(0,10) == 'CHAN_INFO:') {
      let s = ev.data.slice(10);
      let idx = s.indexOf(':');
      if (idx > 0) {
        sw_magic_ = parseInt(s.slice(0,idx)) || 0;
        try {
          sw_channel_ = JSON.parse(s.slice(idx+1));
        }
        catch(e) {
          console.log(e);
        }
      }
    }
    return;
  }
  
  let msg = JSON.parse(ev.data), msg_id = msg.id;
  if (typeof msg_id == 'number') {
    for (let i=0,item; item=sw_call_buf_[i]; i++) {
      if (item[0] === msg_id) {
        sw_call_buf_.splice(i,1); // remove from calling buffer
        if (typeof msg.error == 'string')
          item[2](new Error(msg.error)); // reject(err)
        else item[1](msg);        // resove({id,result})
        break;
      }
    }
  }
  else if (typeof msg.notify == 'string') {
    let fn = sw_notifies_[msg.notify];
    if (fn) fn(msg.param || []);
  }
});

let NAL_ = {
  verInfo(info) { // reconstruct json to avoid side effects
    if (info) {
      app_version_ = JSON.parse(JSON.stringify(info));
      app_abnormal_ = '';
    }
    return app_version_? JSON.parse(JSON.stringify(app_version_)): null;
  },
  
  swMagic(magic, callback) {
    if (magic === undefined)
      return sw_magic_;
    
    sw_magic_ = null;
    if (magic === null)
      return null;
    
    let nd = document.createElement('a');
    nd.setAttribute('href',accFrameNode.getAttribute('src'));
    let loc = nd.origin + '/account/api/online/regist_magic?magic=' + magic;
    let frmNode = document.createElement('iframe');
    frmNode.setAttribute('style','display:none');
    frmNode.setAttribute('src',loc);
    document.body.appendChild(frmNode);
    
    let counter = 0;
    let tid = setInterval( () => {
      counter += 1;
      if (sw_magic_ !== null || counter > 30) {  // max wait 9 seconds
        clearInterval(tid);
        frmNode.remove();
        if (callback) callback(sw_magic_);
      }
    }, 300);
  },
  
  swHost() {
    return sw_channel_.host || 'account.nb-chain.cn';
  },
  
  strategyVer() {
    return sw_channel_.strategy_ver || 0;
  },
  
  waitReady(wait) {
    let resolve_fn = null, reject_fn = null;
    let wait_ready = new Promise( (resolve,reject) => {
      resolve_fn = resolve;
      reject_fn = reject;
    });
    
    let waitNum = wait || 60;  // default wait 60 seconds
    let ticks = 0, tid = setInterval( () => {
      if (app_version_) {
        app_abnormal_ = '';
        clearInterval(tid);
        resolve_fn(NAL_.verInfo());
      }
      else {
        if (app_abnormal_) { // state changed
          clearInterval(tid);
          resolve_fn(app_abnormal_);
        }
        else {
          ticks += 1;
          if (ticks > waitNum) {
            clearInterval(tid);
            reject_fn(new Error('TIMEOUT'));
          }
          // else, continue checking
        }
      }
    }, 1000);
    
    return wait_ready;
  },
  
  renewState() {
    // renew bridge state, auto cache if nesseary, wait ready for restore hosting
    accFrameNode.contentWindow.postMessage('RENEW','*');
  },
  
  unregist() {
    navigator.serviceWorker.getRegistrations().then( items => {
      let reg = null;
      for (let i=0,item; item=items[i]; i++) {
        if (item.active && item.active.scriptURL.indexOf('/static/api/sw-') > 0) {
          reg = item;
          break;
        }
      }
      if (!reg) {
        console.log('no active SW found.');
        return;
      }
      
      if (app_version_) {
        NAL_.call_('clear_cache').then( res => {
          console.log('clear cache ' + res);
          tryUnregist(reg);
        });
      }
      else tryUnregist(reg);
    });
    
    function tryUnregist(reg) {
      reg.unregister().then( is_succ => {
        if (is_succ)
          alert('已提交 service worker 注销操作，请刷新本页，或重启浏览器使之生效。');
        else alert('注销 service worker 失败');
      });
    }
  },
  
  registNoti(name, callback) {  // callback(param), when callback is null means remove
    if (callback === null)
      delete sw_notifies_[name];
    else sw_notifies_[name] = callback;
  },
  
  call_(cmd, param, wait) {
    if (sw_call_buf_.length > 16) throw Error('SW_CALL_BUSY');
    
    sw_call_idx_ += 1;
    let new_id = sw_call_idx_;
    let msg_caller = new Promise( (resolve,reject) => {
      sw_call_buf_.push([new_id,resolve,reject])
    });
    
    if (!param) param = [];
    accFrameNode.contentWindow.postMessage(JSON.stringify({id:new_id,cmd,param}),'*');
    
    let abort_fn = null;
    let abortable = Promise.race([ msg_caller,
      new Promise( function(resolve, reject) {
        abort_fn = function() { reject(new Error('TIMEOUT')) };
      })
    ]);
    setTimeout(()=>abort_fn(),wait||5000); // default wait 5 seconds
    
    return abortable.then( res => res.result, e => {
      for (let i=0,item; item=sw_call_buf_[i]; i++) {
        if (item[0] == new_id) {
          sw_call_buf_.splice(i,1);  // remove from calling buffer
          break;
        }
      }
      return e.message || 'UNKNOWN'; // maybe 'TIMEOUT', maybe res.error
    });
  },
};

let inDlgShowing = false;

NAL_.dialogShowing = function() { return inDlgShowing; };

NAL_.dialog = ( () => {

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
  
  let magic = NAL_.swMagic();
  if (typeof magic != 'number') {
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
      hintDialog.innerHTML = '<div style="height:4.5rem"><span style="display:inline-block; float:left; margin:1.25rem; font-size:1.25rem; font-weight:500;">待授权</span><button name="btn-cancel" style="display:inline-block; border-width:0; background-color:#fff; font-size:2.25rem; font-weight:200; color:#000; opacity:0.5; float:right; margin:0 8px;">&times;</button></div><div style="border:solid rgba(0,0,0,0.2); border-width:1px 0; padding:1.25rem;"><p style="margin: 0.75rem 0 1rem">请到 NAL 账号管理器主页实施授权，或借助 chrome 浏览器插件完成授权。</p></div>';
      maskNode.appendChild(hintDialog);
      
      let node = hintDialog.querySelector('button[name="btn-cancel"]');
      node.onmouseover = (ev => ev.target.style.opacity = '1');
      node.onmouseout = (ev => ev.target.style.opacity = '0.5');
      node.onclick = ( ev => {
        if (nalCheckPassId) {
          clearInterval(nalCheckPassId);
          nalCheckPassId = 0;
          if (name == 'sign')
            NAL_.call_('rmv_wait_sign',[NAL_.swHost(),NAL_.swMagic()]);
        }
        if (name == 'sign') NAL_._accountNode.setAttribute('last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
    }
    
    let currHost = NAL_.swHost(), currMagic = NAL_.swMagic();
    let now = Math.floor((new Date()).valueOf() / 1000);
    if (name == 'sign') {
      if (args && args.length) {  // add: realm, child, hex_tobe_sign
        // have 'realm' means waiting sign, while only 'currHost,currMagic,now' means query if signature be done
        NAL_._accountNode.setAttribute('last-sign',now+'');
        NAL_._accountNode.setAttribute('last-realm',args[0]+'');
        
        NAL_.call('pass_sign',[currHost,currMagic,now, ...args]).then( res => {
          if (res !== 'ADDED') {  // meet unexpected error
            NAL_._accountNode.setAttribute('last-sign','0');
            closeDialog();
            nalDialogReject(new Error('CANCELED'));
          }
          else waitingSignPass([currHost,currMagic,now],args[0]);
        });
      }
      else { // error, nothing to sign
        NAL_._accountNode.setAttribute('last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      }
    }
    else {
      NAL_._accountNode.setAttribute('last-sign',now+'');
      NAL_._accountNode.setAttribute('last-realm','@'); // '@' means only check account be ready in SW, no authority
      waitingSwPass([currHost,currMagic,now]);
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
      NAL_.call_('pass_sign',param,10000).then( res => {
        if (res?.realm) {
          if (nalCheckPassId) {
            clearInterval(nalCheckPassId);
            nalCheckPassId = 0;
          }
          
          NAL_._accountNode.setAttribute('last-sign','0');
          closeDialog();
          if (res.realm === expected && res.signature)
            nalDialogResolve(res);  // {child,pubkey,realm,signature}
          else nalDialogReject(new Error('CANCELED')); // if no res.signature, it must be canceled
        }
        // else, continue next loop, maybe wait forever
      }).catch( e => {  // meet unexpected error
        NAL_._accountNode.setAttribute('last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
    }, 1200);
  }
  
  function waitingSwPass(param, expected) {
    nalCheckPassId = setInterval( () => {
      NAL_.call_('config_acc').then( res => {
        if (res !== 'WAIT_PASS') {
          if (nalCheckPassId) {
            clearInterval(nalCheckPassId);
            nalCheckPassId = 0;
          }
          
          NAL_._accountNode.setAttribute('last-sign','0');
          closeDialog();
          nalDialogResolve('PASSED');
        }
        // else, continue next loop, maybe wait forever
      }).catch( e => {  // meet unexpected error
        NAL_._accountNode.setAttribute('last-sign','0');
        closeDialog();
        nalDialogReject(new Error('CANCELED'));
      });
    }, 1200);
  }
});   // end of return xx

})(); // assign to NAL_.dialog

NAL_.call = function(cmd, param, wait) {
  return NAL_.call_(cmd,param,wait).then( res => {
    if (res === 'WAIT_PASS') {
      return NAL_.dialog('pass').then( res => { // death waiting result: passed or canceled
        if (res === 'PASSED')
          return NAL_.call_(cmd,param,wait);
        else throw Error('CANCELED');
      });
    }
    else return res;
  });
};

//----

( function() {  // SSI implement

const ECDH = require('create-ecdh')('secp256k1');
const CryptoJS = require('crypto-js');
const CreateHash = require('create-hash');
const Buffer = require('safe-buffer').Buffer;

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

NAL_.strategy = function(stg) {
  if (!stg) return STRATEGY;
  DEFAULT_PERIOD = session_periods[stg.session_type];
  DEFAULT_REFRESH = refresh_periods[stg.session_type];
  REFRESH_LIMIT   = stg.session_limit;
  STRATEGY = stg;
  return [stg,DEFAULT_PERIOD,DEFAULT_REFRESH,REFRESH_LIMIT];
};

NAL_.cryptoHost = function(renew) {
  return NAL_.call_('last_cryptohost',[renew || false]);
};

NAL_.checkStart = function(role, nonce1, nonce2, sessData, beg, now, refreshNow) {
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
        NAL_.doLogout();
        return;
      }
      
      let seg = Math.floor((tm+90)/DEFAULT_REFRESH); // ensure seg is newly next segment
      let s = currRole + ':' + clientNonce + ':' + seg;
      let crc3 = CreateHash('sha256').update(Buffer.from(s)).digest().slice(0,3);
      
      let tm2 = Math.max(seg * DEFAULT_REFRESH,tm);
      let body = {time:tm2, nonce:Buffer.from(clientNonce).toString('hex')};
      
      wait__(fetch('/login/refresh',{method:'POST',body:JSON.stringify(body)}),30000).then( res => {
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
            NAL_.doLogout();
          }
          return console.log('request refresh token failed');
        }
        
        lastNonceCrc = crc3;
        next_refresh_tm = ((seg+1)*DEFAULT_REFRESH-90)*1000;
      });
    }
  }, 30000); // checking every 30 seconds
};
  
NAL_.role = function() {
  if (!refresh_task) return '';  // SSI refresh task not started, or expired
  return clientNonce? currRole: '';
};

NAL_.sessData = function() {
  return lastSessData;
};

NAL_.token = function() {
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

NAL_.logout = function() {
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
  
  localStorage.setItem('client_nonce','');
  localStorage.setItem('server_nonce','');
  localStorage.setItem('sw_magic_time','0');
};

NAL_.getPassport = function(is_meta) {
  return NAL_.call('get_pspt',[NAL_.swHost(),NAL_.swMagic(),is_meta],40000); // max waiting 40 seconds
};

NAL_.doLogout = function() {
  NAL_.call('did_logout',[NAL_.swHost(),NAL_.swMagic()]).then( res => {
    if (res === 'OK') {
      NAL_.logout();
      NAL_.afterLogout();
    }
  });
};

NAL_.afterLogout = function() {}; // waiting overwrite

NAL_.actionSign = function(action, hexBeSign, realmEx) { // checker: undefined 'pass' 'sign' 'rsvd' 'auto'
  let role = NAL_.role();
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
    return NAL_.call('list_rsvd').then( rsvdList => {
      if (!(rsvdList instanceof Array) || !rsvdList.length) // unexpected error
        throw new Error('CANCELED');
      
      shuffle(rsvdList); // rsvdList must be an Array
      return NAL_.dialog('rsvd',rsvdList).then( rsvd => {
        let now = Math.floor((new Date()).valueOf() / 1000);
        return NAL_.call( 'pass_sign', [
          NAL_.swHost(),NAL_.swMagic(),now,realm,0, // child=0 means choose login account
          hexBeSign,rsvd ] );
      });
    });
  }
  else if (needPass) {
    return NAL_.dialog('sign',[realm,0,hexBeSign]);
  }
  else {  // sign directly
    let now = Math.floor((new Date()).valueOf() / 1000);
    return NAL_.call( 'pass_sign', [
      NAL_.swHost(),NAL_.swMagic(),now,realm,0, // child=0 means choose login account
      hexBeSign ] );
  }
};

})(); // end of SSI implement

setTimeout( () => {
  let s = document.body.dataset.nal_domain || 'fn-share.github.io';
  s = 'https://' + s + '/account/api/last/bridge.html';
  
  accFrameNode = document.querySelector('#nbc-account');
  if (!accFrameNode || accFrameNode.nodeName != 'IFRAME') {
    accFrameNode = document.createElement('iframe');
    accFrameNode.setAttribute('id','nbc-account');
    accFrameNode.setAttribute('style','display:none');
    accFrameNode.setAttribute('src',s);
    document.body.appendChild(accFrameNode);
  }
  else {
    s = accFrameNode.dataset.src || s;  // try 'data-src' attribute first
    accFrameNode.setAttribute('src',s); // assign src after message listen started
  }
  
  NAL_._accountNode = accFrameNode;
}, 600);

NAL_.nalDomain = function() {
  return document.body.dataset.nal_domain || 'fn-share.github.io';
};

return NAL_;
})();
