import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {test} from 'node:test';

function ui({now=Date.now(),hidden=false}={}){
  const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  const code=html.split('<script>')[1].split('</script>')[0].replace(/\ninit\(\);\s*$/,'');
  const ids=new Map(),listeners=new Map(),timers=new Map(),backgroundErrors=[];let timerId=0;
  function element(){return {hidden:false,disabled:false,textContent:'',value:'',children:[],replaceChildren(...children){this.children=children;},appendChild(child){this.children.push(child);},addEventListener(){},remove(){}};}
  const document={hidden,head:element(),createElement:element,getElementById(id){if(!ids.has(id))ids.set(id,element());return ids.get(id);},addEventListener(type,callback){if(!listeners.has(type))listeners.set(type,[]);listeners.get(type).push(callback);}};
  class TestDate extends Date{constructor(...args){super(...(args.length?args:[now]));}static now(){return now;}}
  function addTimer(callback,delay,repeat){const id=++timerId;timers.set(id,{at:now+delay,callback,repeat});return id;}
  async function settle(){for(let i=0;i<30;i++)await Promise.resolve();assert.deepEqual(backgroundErrors,[]);}
  const testClock={
    now:()=>now,
    pendingCount:()=>timers.size,
    settle,
    async advance(ms){
      const target=now+ms;await settle();
      while(true){
        const next=[...timers.entries()].filter(([,timer])=>timer.at<=target).sort((a,b)=>a[1].at-b[1].at||a[0]-b[0])[0];
        if(!next)break;
        const [id,timer]=next;now=timer.at;
        if(timer.repeat)timer.at+=timer.repeat;else timers.delete(id);
        Promise.resolve(timer.callback()).catch(error=>backgroundErrors.push(error));await settle();
      }
      now=target;await settle();
    },
    async setHidden(value){document.hidden=value;for(const listener of listeners.get('visibilitychange')||[])listener();await settle();}
  };
  const context=vm.createContext({document,window:{},Date:TestDate,console,AbortController,testClock,setTimeout:(callback,delay)=>addTimer(callback,delay,0),clearTimeout:id=>timers.delete(id),setInterval:(callback,delay)=>addTimer(callback,delay,delay),clearInterval:id=>timers.delete(id)});
  vm.runInContext(code,context);context.model.config={available:true,capacity:1,session_seconds:600,turnstile_site_key:'',models:[{id:'fixture-small',label:'Fixture Small',description:'Small local UI test model.'},{id:'fixture-large',label:'Fixture Large',description:'Large local UI test model.'}],default_model:'fixture-small'};context.model.session={state:'none'};context.renderModelChoice();
  return context;
}
function session(state,extra={}){return {state,session_seconds:600,workspace_url:'/workspace',...extra};}

test('bot verification cannot be bypassed by a missing site key',async()=>{
  const app=ui();let requests=0;app.fetch=()=>{requests++;throw new Error('unexpected request');};app.render();
  assert.equal(app.el('join').disabled,true);assert.match(app.el('verification-status').textContent,/not configured/);
  await app.join();assert.equal(requests,0);
});

test('only a service-ready unexpired session reveals the workspace',()=>{
  const app=ui();
  for(const state of ['queued','provisioning','cleaning','expired','failed','cancelled','quarantined']){
    app.model.session=session(state,{expires_at:Date.now()+600000});app.render();assert.equal(app.el('workspace').hidden,true,state);
  }
  app.model.session=session('ready',{expires_at:Date.now()+600000});app.render();assert.equal(app.el('workspace').hidden,false);
  app.model.session=session('active',{expires_at:Date.now()-1});app.render();assert.equal(app.el('workspace').hidden,true);assert.match(app.el('countdown-caption').textContent,/Waiting for service confirmation/);assert.equal(app.model.session.state,'active');
});

test('workspace links cannot introduce a remote origin, query credential or new path',()=>{
  const app=ui();
  for(const value of ['https://attacker.example/','//attacker.example/','/workspace?token=secret','javascript:alert(1)','/demo/admin'])assert.equal(app.safeWorkspace(value),null);
  assert.equal(app.safeWorkspace('/workspace'),'/workspace');
  app.model.session=session('ready',{expires_at:Date.now()+600000,workspace_url:'https://attacker.example/'});app.render();assert.equal(app.el('workspace').hidden,true);
});

test('queue position is displayed only when the service supplies a positive integer',()=>{
  const app=ui();app.model.session=session('queued',{position:3});app.render();assert.equal(app.el('queue-position').textContent,'03');
  app.model.session.position=undefined;app.render();assert.equal(app.el('queue-position').textContent,'—');assert.match(app.el('queue-label').textContent,/not available/);
});

test('session details show the visitor position and duration without service capacity',()=>{
  const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  assert.doesNotMatch(html,/capacity|at a time|has a slot/i);
  const app=ui();
  Object.defineProperty(app.model.config,'capacity',{get(){throw new Error('Public capacity must not be read');}});
  app.model.session=session('queued',{position:4});app.render();
  assert.equal(app.el('session-length').textContent,'10 min');
  assert.equal(app.el('queue-position').textContent,'04');
  assert.equal(app.el('queue-position').hidden,false);
  app.model.session=session('ready',{expires_at:Date.now()+600000});app.render();
  assert.equal(app.el('queue-position').hidden,true);
  assert.equal(app.el('workspace').hidden,false);
});

test('join sends the single-use bot proof and approved model alias with cookie credentials',async()=>{
  const app=ui();app.model.botToken='fixture-bot-proof';const requests=[];
  app.fetch=async(path,options)=>{requests.push({path,options});return {ok:true,json:async()=>path.endsWith('config')?app.model.config:session('queued',{position:2})};};
  await app.join();const post=requests.find(item=>item.path.endsWith('join'));
  assert.deepEqual(JSON.parse(post.options.body),{turnstile_token:'fixture-bot-proof',model_id:'fixture-small'});assert.equal(post.options.credentials,'same-origin');assert.equal(post.options.headers.Authorization,undefined);
  assert.equal(app.model.botToken,null);assert.equal(app.model.session.state,'queued');
});

test('Turnstile uses the official explicit widget with expiry handling',async()=>{
  const app=ui();app.model.config.turnstile_site_key='public-site-key';let options;
  app.window.turnstile={render:(target,config)=>{assert.equal(target,'#bot-verification-widget');options=config;return 'widget1';},reset(){}};
  await app.ensureWidget();assert.equal(options.sitekey,'public-site-key');assert.equal(options.action,'demo_join');
  options.callback('proof');assert.equal(app.el('join').disabled,false);options['expired-callback']();assert.equal(app.el('join').disabled,true);assert.equal(app.model.botToken,null);
});

test('failed status checks retain confirmed state and close workspace access',async()=>{
  const app=ui();app.model.session=session('active',{expires_at:Date.now()+600000});app.render();
  app.fetch=async()=>{throw new Error('network unavailable');};await app.refresh();
  assert.equal(app.model.session.state,'active');assert.equal(app.el('workspace').hidden,true);app.updateCountdown();assert.equal(app.el('workspace').hidden,true);assert.match(app.el('sync-note').textContent,/last confirmed state/);
});

test('untrusted server errors stay text and failed joins stay visible after refresh',async()=>{
  const app=ui();app.model.botToken='proof';const hostile='<img src=x onerror=alert(1)>';
  app.fetch=async(path)=>path.endsWith('join')?{ok:false,status:429,json:async()=>({message:hostile})}:{ok:true,json:async()=>path.endsWith('config')?app.model.config:session('none')};
  await app.join();assert.equal(app.el('error').textContent,hostile);assert.equal(app.el('error').hidden,false);assert.equal(app.el('error').innerHTML,undefined);
});

test('cleanup and quarantine do not expose cancellation or a new request',()=>{
  const app=ui();for(const state of ['cleaning','quarantined']){app.model.session=session(state);app.render();assert.equal(app.el('join').hidden,true);assert.equal(app.el('cancel').hidden,true);assert.equal(app.el('workspace').hidden,true);}
  assert.throws(()=>app.validSession({state:'pretend-ready'}),/unrecognized/);
});

test('cancel submits an empty body and waits for the server state',async()=>{
  const app=ui();app.model.session=session('active',{expires_at:Date.now()+600000});const calls=[];
  app.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,json:async()=>path.endsWith('config')?app.model.config:session('cleaning')};};
  await app.cancel();assert.deepEqual(JSON.parse(calls.find(item=>item.path.endsWith('cancel')).options.body),{});assert.equal(app.model.session.state,'cleaning');assert.equal(app.el('workspace').hidden,true);
});


test('a named DOM element cannot masquerade as the loaded Turnstile API',async()=>{
  const app=ui();app.model.config.turnstile_site_key='public-site-key';
  app.window.turnstile={tagName:'DIV',id:'turnstile'};
  const loading=app.ensureWidget();
  assert.equal(app.document.head.children.length,1);
  const script=app.document.head.children[0];
  assert.equal(script.src,'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit');
  let rendered=0;
  app.window.turnstile={render(target){assert.equal(target,'#bot-verification-widget');rendered++;return 'loaded-widget';}};
  script.onload();await loading;
  assert.equal(rendered,1);assert.equal(app.model.widgetId,'loaded-widget');
  const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  assert.doesNotMatch(html,/id=["']turnstile["']/);
});

test('a loaded script without the widget API fails closed and can retry',async()=>{
  const app=ui();app.model.config.turnstile_site_key='public-site-key';
  app.updateJoin();
  const loading=app.ensureWidget();app.document.head.children[0].onload();await loading;
  assert.equal(app.model.widgetId,null);assert.equal(app.model.widgetPromise,null);
  assert.equal(app.el('join').disabled,true);assert.match(app.el('verification-status').textContent,/could not load/);
  const retry=app.ensureWidget();assert.equal(app.document.head.children.length,2);
  app.window.turnstile={render:()=> 'retry-widget'};
  app.document.head.children[1].onload();await retry;
  assert.equal(app.model.widgetId,'retry-widget');
});


test('portfolio scenario remains explicitly fictional without changing request authority',()=>{
  const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  assert.match(html,/fictional Harborlight Credit Union/);assert.match(html,/synthetic loan application events/);
  assert.match(html,/no real borrower records/);assert.match(html,/makes no lending decisions/);
  assert.match(html,/Show borrower names and SSNs/);assert.match(html,/10 minutes/);
  assert.doesNotMatch(html,/Experian|name=["'](?:tenant|priority|credential)["']/i);
});


test('model choice comes from the catalog and survives polling and default changes',async()=>{
  const app=ui();assert.equal(app.model.selectedModelId,'fixture-small');app.chooseModel('fixture-large');
  app.fetch=async path=>({ok:true,json:async()=>path.endsWith('config')?{...app.model.config,default_model:'fixture-small'}:session('none')});
  await app.refresh();assert.equal(app.model.selectedModelId,'fixture-large');assert.equal(app.el('demo-model-choice').value,'fixture-large');
  app.model.config.default_model='fixture-large';app.chooseModel('fixture-small');app.render();assert.equal(app.model.selectedModelId,'fixture-small');
});

test('unknown or removed model choices block admission without silently selecting a fallback',async()=>{
  const app=ui();app.model.botToken='proof';app.chooseModel('fixture-large');
  app.model.config.models=app.model.config.models.filter(item=>item.id==='fixture-small');app.render();
  assert.equal(app.el('join').disabled,true);assert.equal(app.model.selectedModelId,'fixture-large');assert.match(app.el('model-description').textContent,/no longer available/);
  let calls=0;app.fetch=async()=>{calls++;throw new Error('unexpected request');};await app.join();assert.equal(calls,0);
  app.chooseModel('https://untrusted.invalid/model');await app.join();assert.equal(calls,0);
  app.chooseModel('fixture-small');assert.equal(app.el('join').disabled,false);
});

test('queued and active sessions display the durable model binding instead of the catalog default',()=>{
  const app=ui();for(const state of ['queued','provisioning','ready','cleaning','quarantined']){
    app.model.session=session(state,{model:{id:'retired-model',label:'Previously approved model'}});app.render();
    assert.equal(app.el('model-selection').hidden,true);assert.equal(app.el('session-model-name').textContent,'Previously approved model');
    app.chooseModel('fixture-large');assert.equal(app.model.selectedModelId,'fixture-small');
  }
  app.model.session=session('cancelled',{model:{id:'retired-model',label:'Previously approved model'}});app.render();
  assert.equal(app.el('model-selection').hidden,false);assert.match(app.el('session-model-note').textContent,/previous session/);app.chooseModel('fixture-large');assert.equal(app.model.selectedModelId,'fixture-large');
});

test('empty or malformed model catalogs fail closed and model metadata remains plaintext',()=>{
  const app=ui();app.model.botToken='proof';const hostile='<img src=x onerror=alert(1)>';
  app.model.config.models[0].label=hostile;app.model.config.models[0].description=hostile;app.render();
  assert.equal(app.el('demo-model-choice').children[1].textContent,hostile+' · Default');assert.equal(app.el('model-description').textContent,hostile);assert.equal(app.el('model-description').innerHTML,undefined);
  app.model.config.models=[];app.render();assert.equal(app.el('join').disabled,true);assert.equal(app.el('demo-model-choice').disabled,true);
  app.model.config.models=[{id:'https://untrusted.invalid',label:'Bad',description:'Bad'}];app.render();assert.equal(app.approvedModels().length,0);
});

test('failed joins remain visible through successful polls until an explicit retry',async()=>{
  const app=ui(),config=app.model.config;app.model.botToken='proof';
  app.fetch=async path=>path.endsWith('join')?{ok:false,status:429,json:async()=>({message:'Please try again after the admission window.'})}:{ok:true,json:async()=>path.endsWith('config')?config:session('none')};
  await app.join();await app.refresh();await app.refresh();
  assert.equal(app.el('error').textContent,'Please try again after the admission window.');assert.equal(app.el('error').hidden,false);assert.equal(app.el('retry').hidden,false);
  await app.retryStatus();assert.equal(app.el('error').hidden,true);assert.equal(app.model.actionError,null);
});

test('failed cancellation stays visible while connection errors recover independently',async()=>{
  const app=ui(),config=app.model.config;app.model.session=session('active',{expires_at:Date.now()+600000});
  app.fetch=async path=>path.endsWith('cancel')?{ok:false,status:503,json:async()=>({message:'Cancellation could not be confirmed.'})}:{ok:true,json:async()=>path.endsWith('config')?config:session('active',{expires_at:Date.now()+600000})};
  await app.cancel();await app.refresh();assert.equal(app.el('error').textContent,'Cancellation could not be confirmed.');
  app.fetch=async()=>{throw new Error('Network unavailable');};await app.refresh();assert.equal(app.model.error,'Network unavailable');assert.equal(app.el('workspace').hidden,true);
  app.fetch=async path=>({ok:true,json:async()=>path.endsWith('config')?config:session('active',{expires_at:Date.now()+600000})});await app.refresh();
  assert.equal(app.model.error,null);assert.equal(app.el('error').textContent,'Cancellation could not be confirmed.');assert.equal(app.el('workspace').hidden,false);
  await app.cancel();assert.equal(app.model.actionError,null);assert.equal(app.el('error').hidden,true);
});

test('transient refresh failures disappear after recovery without an explicit retry',async()=>{
  const app=ui(),config=app.model.config;
  app.fetch=async()=>{throw new Error('Temporary connection failure');};await app.refresh();assert.equal(app.el('error').hidden,false);
  app.fetch=async path=>({ok:true,json:async()=>path.endsWith('config')?config:session('none')});await app.refresh();assert.equal(app.el('error').hidden,true);
});

function pollingService(app,state,{available=true,expires_at=app.testClock.now()+3600000}={}){
  const service={calls:[],config:{...app.model.config,available},session:session(state,{expires_at}),fail:false};
  app.fetch=async(path,options)=>{
    service.calls.push({path,options,at:app.testClock.now()});
    if(service.fail)throw new Error('Temporary connection failure');
    return {ok:true,json:async()=>path.endsWith('config')?service.config:service.session};
  };
  return service;
}

test('idle and terminal visitors check once a minute whether admissions are open or paused',async()=>{
  for(const available of [true,false])for(const state of ['none','expired','failed','cancelled']){
    const app=ui({now:0}),service=pollingService(app,state,{available});
    await app.initPolling();assert.equal(service.calls.length,2);
    await app.testClock.advance(59999);assert.equal(service.calls.length,2,`${state}: no idle requests before a minute`);
    await app.testClock.advance(1);assert.equal(service.calls.length,4,`${state}: config and session checked at a minute`);
    assert.match(app.el('sync-note').textContent,/every 60 seconds while visible/);
  }
});

test('existing sessions retain five second checks during paused admissions while config is cached for a minute',async()=>{
  for(const state of ['queued','provisioning','ready','active','cleaning','quarantined']){
    const app=ui({now:0}),service=pollingService(app,state,{available:false});
    await app.initPolling();await app.testClock.advance(60000);
    const configChecks=service.calls.filter(call=>call.path.endsWith('config'));
    const sessionChecks=service.calls.filter(call=>call.path.endsWith('session'));
    assert.deepEqual(configChecks.map(call=>call.at),[0,60000],state);
    assert.deepEqual(sessionChecks.map(call=>call.at),Array.from({length:13},(_,index)=>index*5000),state);
    assert.match(app.el('sync-note').textContent,/every 5 seconds while visible/);
  }
});

test('a page loaded hidden makes no requests or timers and refreshes immediately when visible',async()=>{
  const app=ui({now:0,hidden:true}),service=pollingService(app,'none',{available:false});
  await app.initPolling();await app.testClock.advance(3600000);
  assert.equal(service.calls.length,0);assert.equal(app.testClock.pendingCount(),0);
  assert.match(app.el('sync-note').textContent,/paused while this tab is hidden/);
  await app.testClock.setHidden(false);
  assert.equal(service.calls.length,2);assert.equal(app.testClock.pendingCount(),2);
  await app.testClock.setHidden(true);await app.testClock.advance(3600000);
  assert.equal(service.calls.length,2);assert.equal(app.testClock.pendingCount(),0);
  await app.testClock.setHidden(false);assert.equal(service.calls.length,4);
});

test('hiding aborts an in-flight check and a rapid return refreshes both endpoints without a persistent error',async()=>{
  const app=ui({now:0}),service=pollingService(app,'active');await app.initPolling();
  const fetch=app.fetch;let pendingSignal;
  app.fetch=(path,options)=>{
    app.fetch=fetch;pendingSignal=options.signal;
    service.calls.push({path,options,at:app.testClock.now()});
    return new Promise((_resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('The operation was aborted.')),{once:true}));
  };
  await app.testClock.advance(5000);assert.equal(app.model.refreshing,true);
  app.document.hidden=true;app.visibilityChanged();
  assert.equal(pendingSignal.aborted,true);assert.equal(app.testClock.pendingCount(),0);
  app.document.hidden=false;app.visibilityChanged();await app.testClock.settle();
  assert.equal(app.model.refreshing,false);assert.equal(app.model.error,null);assert.equal(app.model.pollFailures,0);
  assert.deepEqual(service.calls.slice(-2).map(call=>call.path),['/demo/api/config','/demo/api/session']);
  assert.equal(service.calls.length,5);assert.equal(app.testClock.pendingCount(),2);
  await app.testClock.advance(5000);assert.equal(service.calls.length,6);
});

test('an aborted response arriving after the tab hides cannot replace the confirmed session',async()=>{
  const app=ui({now:0}),service=pollingService(app,'queued');await app.initPolling();
  const fetch=app.fetch;let complete;
  app.fetch=()=>new Promise(resolve=>{complete=resolve;});
  await app.testClock.advance(5000);await app.testClock.setHidden(true);
  complete({ok:true,json:async()=>session('ready',{expires_at:600000})});await app.testClock.settle();
  assert.equal(app.model.session.state,'queued');assert.equal(app.model.error,null);assert.equal(app.testClock.pendingCount(),0);
  app.fetch=fetch;await app.testClock.setHidden(false);
  assert.equal(app.model.session.state,'queued');assert.equal(service.calls.length,4);
});

test('connection failures back off to five minutes, revalidate config and recover to the live cadence',async()=>{
  const app=ui({now:0}),service=pollingService(app,'active');await app.initPolling();
  service.fail=true;await app.testClock.advance(5000);
  assert.equal(service.calls.length,3);assert.equal(app.el('workspace').hidden,true);assert.equal(app.model.session.state,'active');
  for(const delay of [10000,20000,40000,80000,160000,300000,300000]){
    const before=service.calls.length;
    assert.match(app.el('sync-note').textContent,new RegExp(`Retrying in ${delay/1000} seconds`));
    await app.testClock.advance(delay-1);assert.equal(service.calls.length,before);
    await app.testClock.advance(1);assert.equal(service.calls.length,before+1);
    assert.equal(service.calls.at(-1).path,'/demo/api/config');
  }
  service.fail=false;const before=service.calls.length;
  await app.testClock.advance(300000);assert.equal(service.calls.length,before+2);
  assert.equal(app.model.error,null);assert.equal(app.el('workspace').hidden,false);
  await app.testClock.advance(5000);assert.equal(service.calls.length,before+3);
  assert.equal(service.calls.at(-1).path,'/demo/api/session');
});

test('explicit retry bypasses config cache and backoff while retaining the visitor model choice',async()=>{
  const app=ui({now:0}),service=pollingService(app,'none');await app.initPolling();app.chooseModel('fixture-large');
  service.fail=true;await app.refresh();assert.equal(app.el('join').disabled,true);
  service.fail=false;service.config={...service.config,available:false,models:service.config.models.slice(0,1)};
  const before=service.calls.length;await app.retryStatus();
  assert.equal(service.calls.length,before+2);assert.equal(service.calls.at(-2).path,'/demo/api/config');
  assert.equal(app.model.selectedModelId,'fixture-large');assert.equal(app.el('join').disabled,true);
  assert.match(app.el('model-description').textContent,/no longer available/);assert.equal(app.model.error,null);
});

test('join and cancel force fresh configuration and immediately follow the resulting session cadence',async()=>{
  const app=ui({now:0}),service=pollingService(app,'none');await app.initPolling();
  app.model.botToken='proof';service.session=session('queued');
  await app.join();
  assert.deepEqual(service.calls.slice(-3).map(call=>call.path),['/demo/api/join','/demo/api/config','/demo/api/session']);
  const joined=service.calls.length;await app.testClock.advance(5000);assert.equal(service.calls.length,joined+1);
  service.session=session('cleaning');await app.cancel();
  assert.deepEqual(service.calls.slice(-3).map(call=>call.path),['/demo/api/cancel','/demo/api/config','/demo/api/session']);
  service.session=session('cancelled');await app.testClock.advance(5000);
  const cancelled=service.calls.length;await app.testClock.advance(59999);assert.equal(service.calls.length,cancelled);
  await app.testClock.advance(1);assert.equal(service.calls.length,cancelled+2);
});

test('countdown closes workspace access at expiry even between service polls and after hidden time',async()=>{
  const app=ui({now:0}),service=pollingService(app,'active',{expires_at:2000});await app.initPolling();
  assert.equal(app.el('workspace').hidden,false);
  await app.testClock.advance(2000);
  assert.equal(service.calls.length,2);assert.equal(app.el('workspace').hidden,true);
  assert.equal(app.model.session.state,'active');assert.match(app.el('countdown-caption').textContent,/Waiting for service confirmation/);
  service.session=session('active',{expires_at:10000});await app.refresh();assert.equal(app.el('workspace').hidden,false);
  await app.testClock.setHidden(true);await app.testClock.advance(9000);
  service.fail=true;await app.testClock.setHidden(false);
  assert.equal(app.el('countdown').textContent,'00:00');assert.equal(app.el('workspace').hidden,true);assert.equal(app.model.session.state,'active');
});
