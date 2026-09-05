import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {test} from 'node:test';

function ui(){
  const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  const code=html.split('<script>')[1].split('</script>')[0].replace(/\ninit\(\);\s*$/,'');
  const ids=new Map();
  function element(){return {hidden:false,disabled:false,textContent:'',value:'',children:[],replaceChildren(...children){this.children=children;},appendChild(child){this.children.push(child);},addEventListener(){},remove(){}};}
  const document={head:element(),createElement:element,getElementById(id){if(!ids.has(id))ids.set(id,element());return ids.get(id);},addEventListener(){}};
  const context=vm.createContext({document,window:{},Date,console,setTimeout:()=>1,clearTimeout(){},setInterval(){}});
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
