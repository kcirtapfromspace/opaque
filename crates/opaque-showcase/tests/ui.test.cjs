const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function ui(wasmBytes) {
  const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
  const source = html.split('<script>')[1].split('</script>')[0].replace(/\ninit\(\);\s*$/, '').replace('__OPAQUE_APPROVAL_WASM_BYTES__',wasmBytes || '__OPAQUE_APPROVAL_WASM_BYTES__');
  const ids = new Map();
  class Element {
    constructor(tag) {this.tagName=tag;this.children=[];this.dataset={};this.value='';this.hidden=false;this.isConnected=true;this.textContent='';this.style={};this.listeners={};}
    appendChild(child) {this.children.push(child);return child;}
    insertBefore(child, before) {this.children.splice(this.children.indexOf(before),0,child);}
    replaceChildren(...children) {this.children=children;}
    replaceWith(child) {this.isConnected=false;this.replacement=child;}
    setAttribute(key,value) {this[key]=value;}
    addEventListener(type,listener) {this.listeners[type]=listener;}
    click() {if(this.listeners.click)this.listeners.click();}
    focus() {}
    showModal() {this.open=true;}
    close() {this.open=false;}
  }
  const document = {body:new Element('body'),createElement:tag=>new Element(tag),getElementById:id=>{if(!ids.has(id)) ids.set(id,new Element('div'));return ids.get(id);}};
  const context = vm.createContext({document,Date,Intl,Map,AbortController,TextDecoder,TextEncoder,Uint8Array,WebAssembly,crypto:require('node:crypto').webcrypto,atob,btoa,URL,console,setTimeout:()=>1,clearTimeout(){},setInterval(){}});
  vm.runInContext(source,context);
  context.ids=ids;
  return context;
}
function session(customer='northstar') {
  return {customer:{id:customer,display_name:'Northstar'},subject:{id:'user-1',display_name:'Test operator'},expires_at:Date.now()/1000+900,
    allowed_metrics:[{id:'requests_per_second',label:'Requests per second'}],runtime:{kind:'deterministic_demo',label:'Demo parser'},source:{kind:'synthetic',label:'Rolling event fixture'},approval_mode:'test'};
}
function result(extra={}) {return {metric_id:'requests_per_second',value:24,unit:'req/s',observed_at:Date.now()/1000,stale_after_secs:15,evidence_id:'proof-1',...extra};}
function allNodes(element) {return [element,...element.children.flatMap(allNodes)];}

function hostedSession(value=session()) {return {...value,demo:{synthetic:true,return_url:'/',expires_at:value.expires_at}};}

test('pilot invitation follows a completed answer with scoped source evidence only in the hosted demo',()=>{
  for(const value of [session(),hostedSession(),{...session(),demo:{synthetic:true,return_url:'https://untrusted.example/'}}]) {
    const app=ui();app.renderSession(value);const turn=app.addTurn();
    assert.equal(app.byId('pilot-invitation').hidden,true);
    app.handleEvent(turn,'result',result());app.handleEvent(turn,'answer',{kind:'grounded',text:'The source observed 24 requests per second.'});
    assert.equal(app.byId('pilot-invitation').hidden,true);
    app.handleEvent(turn,'done',{});
    assert.equal(app.byId('pilot-invitation').hidden,!(value.demo&&value.demo.return_url==='/'));
    app.expireSession();assert.equal(app.byId('pilot-invitation').hidden,true);
  }
  const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
  assert.match(html,/href="\/#pilot-result">Discuss a pilot/);
  assert.equal((html.match(/id="pilot-invitation"/g)||[]).length,1);
});

test('pilot invitation rejects missing evidence, failed answers, clarification and old identity events',()=>{
  for(const scenario of ['missing','text-value','missing-id','invalid-time','clarification','unsupported','denied','old-identity']) {
    const app=ui();app.renderSession(hostedSession());const turn=app.addTurn();
    if(scenario!=='missing')app.handleEvent(turn,'result',result(scenario==='text-value'?{value:'24'}:scenario==='missing-id'?{evidence_id:''}:scenario==='invalid-time'?{observed_at:'invalid'}:{}));
    app.handleEvent(turn,'answer',{kind:['clarification','unsupported'].includes(scenario)?scenario:'grounded',text:'Answer text'});
    if(scenario==='denied')app.handleEvent(turn,'error',{code:'scope_denied',message:'Not permitted.'});
    if(scenario==='old-identity')app.state.identityKey='another-session';
    app.handleEvent(turn,'done',{});assert.equal(app.byId('pilot-invitation').hidden,true,scenario);
  }
});

test('pilot invitation accepts validated portfolio answers but excludes empty observations',()=>{
  for(const populated of [true,false]) {
    const app=ui();app.renderSession(hostedSession(portfolioSession()));const turn=app.addTurn(),proof=portfolioEvidence();
    if(!populated)proof.rows.forEach(row=>{row.sample_count=0;Object.keys(row.values).forEach(key=>row.values[key]=null);});
    app.handleEvent(turn,'portfolio_result',proof);app.handleEvent(turn,'done',{});
    assert.equal(app.byId('pilot-invitation').hidden,!populated);
  }
});

test('pilot invitation accepts completed validated task receipts without inventing uncertain success',()=>{
  for(const status of ['planned','approved','reserved','unknown','completed']) {
    const app=ui(),value=hostedSession(workSession());app.renderSession(value);
    app.state.workTask=app.validateWorkTask(workTask(value,status));app.renderWorkTask();
    assert.equal(app.byId('pilot-invitation').hidden,status!=='completed',status);
  }
  const app=ui(),value=workSession();app.renderSession(value);app.state.workTask=app.validateWorkTask(workTask(value,'completed'));app.renderWorkTask();assert.equal(app.byId('pilot-invitation').hidden,true);
});

test('SSE framing survives chunked CRLF, comments and multiline JSON',()=>{
  const app=ui(),events=[];const parser=app.streamParser((type,data)=>events.push({type,data}));
  parser.push(': heartbeat\r\n\r');parser.push('\nevent: result\r\ndata: {"metric_id":\r\ndata: "requests_per_second"}\r\n');parser.push('\r\nevent: done\ndata: {}\n\n');parser.finish();
  assert.equal(events.length,2);assert.equal(events[0].type,'result');assert.equal(events[0].data.metric_id,'requests_per_second');assert.equal(events[1].type,'done');
});

test('truncated or oversized event streams fail instead of claiming completion',()=>{
  const app=ui();const parser=app.streamParser(()=>{});parser.push('event: answer\ndata: {"text":"unfinished"}');
  assert.throws(()=>parser.finish(),/ended before/);
  assert.throws(()=>app.streamParser(()=>{}).push('x'.repeat(262145)),/safe display limit/);
});

test('freshness follows source timestamps and an explicit threshold',()=>{
  const app=ui();
  assert.equal(app.freshness(result({observed_at:100,stale_after_secs:15}),110000).stale,false);
  assert.equal(app.freshness(result({observed_at:100,stale_after_secs:15}),116000).stale,true);
  assert.match(app.freshness(result({stale_after_secs:undefined}),Date.now()).text,/threshold unavailable/);
  assert.equal(app.freshness(result({observed_at:115,watermark:90,stale_after_secs:15}),116000).stale,true);
});

test('untrusted answers and metric values remain plain text',()=>{
  const app=ui();app.renderSession(session());const turn=app.addTurn();
  const hostile='<img src=x onerror=alert(1)>';
  app.handleEvent(turn,'answer',{text:hostile});app.handleEvent(turn,'result',result({value:hostile}));
  assert.equal(turn.body.textContent,hostile);
  const nodes=allNodes(turn.element);assert.ok(nodes.some(node=>node.textContent===hostile));
  assert.ok(nodes.every(node=>node.tagName!=='img' && !Object.hasOwn(node,'innerHTML')));
});

test('results cannot introduce a metric or customer outside the session scope',()=>{
  const app=ui();app.renderSession(session());const turn=app.addTurn();
  assert.throws(()=>app.receiveResult(turn,result({metric_id:'private_other_metric'})),/authenticated customer scope/);
  assert.throws(()=>app.receiveResult(turn,result({customer_id:'other-customer'})),/authenticated customer scope/);
  assert.equal(turn.cards.size,0);assert.equal(app.state.latest.size,0);
});

test('repeated snapshots update a metric while preserving observation evidence',()=>{
  const app=ui();app.renderSession(session());const turn=app.addTurn();
  app.receiveResult(turn,result({value:20,observed_at:100,sequence:1}));
  app.receiveResult(turn,result({value:25,observed_at:102,sequence:2}));
  app.receiveResult(turn,result({value:10,observed_at:99,sequence:0}));
  assert.equal(turn.cards.size,1);assert.equal(app.state.latest.get('requests_per_second').value,25);assert.equal(turn.events,3);
});

test('scope denial preserves login; revocation disables new chat',()=>{
  const app=ui();app.renderSession(session());const turn=app.addTurn();
  app.handleEvent(turn,'error',{code:'scope_denied',message:'Metric is not allowed.'});assert.ok(app.state.session);
  app.handleEvent(turn,'done',{});assert.equal(turn.status.textContent,'Metric is not allowed.');
  const next=app.addTurn();app.handleEvent(next,'error',{code:'session_revoked',message:'Session revoked.'});assert.equal(app.state.session,null);assert.equal(app.byId('message').disabled,true);
});

test('chat POST uses the cookie and only the message, with no client authority',async()=>{
  const app=ui();app.renderSession(session());app.byId('message').value='Show requests';let captured;
  app.fetch=async(url,options)=>{captured={url,options};return {ok:true,status:200,headers:{get:()=> 'text/event-stream'},body:{getReader:()=>({read:async()=>({done:true})})}};};
  await app.submitMessage();
  assert.equal(captured.url,'/api/chat');assert.deepEqual(JSON.parse(captured.options.body),{message:'Show requests'});
  assert.equal(captured.options.credentials,'same-origin');assert.equal(captured.options.headers.Authorization,undefined);
  assert.ok(captured.options.signal instanceof AbortSignal);
  const turn=app.byId('conversation').children.at(-1);assert.ok(allNodes(turn).some(node=>String(node.textContent).includes('before completion')));
});

test('changing authenticated customers clears prior customer evidence',()=>{
  const app=ui();app.renderSession(session());const turn=app.addTurn();app.receiveResult(turn,result());
  app.renderSession(session('new-customer'));assert.equal(app.state.latest.size,0);assert.equal(app.byId('conversation').children.length,1);assert.equal(app.byId('welcome').hidden,false);
});

function creditSession() {
  const value=session('demo-harborlight');value.customer.display_name='Harborlight Credit Union';
  value.experience={kind:'credit_portfolio',title:'Portfolio intelligence',persona:'Portfolio analyst',dataset:'Synthetic loan application events',purpose:'Portfolio monitoring',policy_id:'portfolio-analyst-v1',allowed_tool:'opaque_metrics_query'};
  value.policy_context={tenant_id:value.customer.id,policy_id:'portfolio-analyst-v1',persona:'Portfolio analyst',purpose:'Portfolio monitoring',allowed_tool:'opaque_metrics_query',allowed_metrics:['requests_per_second'],latest_decision:null};return value;
}
function policy(extra={}) {return {phase:'request_check',outcome:'denied',reason_code:'raw_records_denied',message:'Borrower records are outside the portfolio scope.',tenant_id:'demo-harborlight',policy_id:'portfolio-analyst-v1',tool:'opaque_metrics_query',source_accessed:false,...extra};}

test('credit experience separates fictional customer context from server policy',()=>{
  const app=ui();app.renderSession(creditSession());
  assert.equal(app.document.body.className,'credit-experience');assert.equal(app.byId('customer-name').textContent,'Portfolio intelligence');
  assert.match(app.byId('workspace-eyebrow').textContent,/Harborlight Credit Union.*fictional/);assert.match(app.byId('identity-caption').textContent,/Temporary scoped demo session/);
  assert.equal(app.byId('policy-purpose').textContent,'Portfolio monitoring');assert.equal(app.byId('security-panel').hidden,false);
  assert.equal(app.byId('boundary-questions').children.length,3);
  app.renderSession(session());assert.equal(app.byId('security-panel').hidden,true);assert.equal(app.document.body.className,'');assert.equal(app.byId('product-name').textContent,'Customer metrics');
});

test('denial evidence names its policy and zero source access only when reported',()=>{
  const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
  app.handleEvent(turn,'error',{code:'scope_denied',message:'Not allowed.'});
  assert.ok(!allNodes(app.byId('policy-decisions')).some(n=>n.textContent==='No source access at this denied check'));
  app.handleEvent(turn,'policy',policy());
  const texts=allNodes(app.byId('policy-decisions')).map(n=>n.textContent);
  assert.ok(texts.includes('raw_records_denied'));assert.ok(texts.includes('No source access at this denied check'));assert.ok(app.state.session);
  assert.equal(app.policyProof(policy({source_accessed:undefined})),'Source access not reported');
});

test('policy evidence rejects another tenant or tool and preserves plaintext',()=>{
  const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
  assert.throws(()=>app.handleEvent(turn,'policy',policy({tenant_id:'another-lender'})),/did not match/);
  assert.throws(()=>app.handleEvent(turn,'policy',policy({tool:'raw_borrower_export'})),/did not match/);
  const hostile='<img src=x onerror=alert(1)>';app.handleEvent(turn,'policy',policy({message:hostile}));
  assert.ok(allNodes(app.byId('policy-decisions')).some(n=>n.textContent===hostile));assert.ok(allNodes(app.byId('policy-decisions')).every(n=>!Object.hasOwn(n,'innerHTML')));
});

test('source access is shown from an actual source event and new turns reset the panel',()=>{
  const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
  app.handleEvent(turn,'policy',policy({phase:'source_read',outcome:'allowed',reason_code:'source_evidence_received',source_accessed:true}));
  assert.ok(allNodes(app.byId('policy-decisions')).some(n=>n.textContent==='Authorized source evidence received'));
  app.addTurn();assert.equal(app.state.policyEvents.length,0);assert.match(app.byId('policy-decisions').children[0].textContent,/Waiting for this request/);
});

test('architecture awaits validated policy and source evidence instead of inferring a successful read',()=>{
  const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
  app.handleEvent(turn,'status',{message:'Selecting an authorized metrics tool…'});
  app.handleEvent(turn,'tool',{name:'opaque_metrics_query',phase:'request'});
  assert.equal(app.state.flow.sourceAccess,null);assert.equal(app.state.flow.hasResult,false);
  assert.equal(app.byId('flow-source').textContent,'Access not reported');
  assert.equal(app.byId('flow-stage-policy').dataset.confirmed,'false');
  const before=app.state.flow.events.length;
  assert.throws(()=>app.handleEvent(turn,'policy',policy({tenant_id:'other-customer'})),/did not match/);
  assert.equal(app.state.flow.events.length,before);
  app.handleEvent(turn,'policy',policy({phase:'tool_check',outcome:'allowed',source_accessed:false}));
  assert.equal(app.state.flow.sourceAccess,null);
  app.handleEvent(turn,'policy',policy({phase:'source_read',outcome:'allowed',source_accessed:true}));
  assert.equal(app.state.flow.sourceAccess,true);assert.equal(app.state.flow.hasResult,false);
  app.handleEvent(turn,'result',result());app.handleEvent(turn,'done',{});
  assert.equal(app.state.flow.hasResult,true);assert.equal(app.state.flow.phase,'complete');
  assert.match(app.byId('flow-status').textContent,/Answer complete/);
});

test('architecture ignores unknown tools and rejects foreign results before displaying evidence',()=>{
  const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
  app.handleEvent(turn,'tool',{name:'private_ungranted_tool',phase:'request'});
  assert.equal(app.state.flow.tool,null);assert.equal(app.state.flow.events.length,0);
  assert.throws(()=>app.handleEvent(turn,'result',result({customer_id:'another-customer'})),/authenticated customer scope/);
  assert.equal(app.state.flow.hasResult,false);assert.equal(app.state.flow.result,'No result yet');
});

test('later explanation status cannot restart tool-selection motion or regress received evidence',()=>{
  const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
  app.handleEvent(turn,'status',{message:'Selecting an authorized metrics tool…'});
  app.handleEvent(turn,'policy',policy({phase:'source_read',outcome:'allowed',source_accessed:true}));
  app.handleEvent(turn,'result',result());
  app.handleEvent(turn,'status',{message:'Explaining the latest authorized snapshot…'});
  assert.equal(app.state.flow.phase,'evidence');assert.equal(app.state.flow.hasResult,true);assert.equal(app.state.flow.sourceAccess,true);
  assert.match(app.byId('flow-status').textContent,/Explaining the authorized evidence/);
  assert.equal(app.state.flow.events.filter(item=>item.text==='Service started tool selection.').length,1);
  const before=app.state.flow.events.length;app.handleEvent(turn,'status',{message:'An unrecognized service message'});
  assert.equal(app.state.flow.events.length,before);assert.equal(app.state.flow.phase,'evidence');
});

test('architecture errors and incomplete streams preserve uncertainty instead of inventing denial or completion',async()=>{
  const app=ui();app.renderSession(creditSession());let turn=app.addTurn();
  app.handleEvent(turn,'error',{code:'upstream_failure',message:'The connection ended.'});
  app.handleEvent(turn,'done',{});
  assert.equal(app.state.flow.phase,'interrupted');assert.equal(app.state.flow.sourceAccess,null);
  assert.equal(app.byId('flow-source').textContent,'Source outcome unconfirmed');
  app.byId('message').value='Show requests';
  app.fetch=async()=>({ok:true,status:200,headers:{get:()=> 'text/event-stream'},body:{getReader:()=>({read:async()=>({done:true})})}});
  await app.submitMessage();
  assert.equal(app.state.flow.phase,'interrupted');assert.equal(app.state.flow.hasResult,false);
  turn=app.addTurn();app.handleEvent(turn,'done',{});
  assert.match(app.byId('flow-status').textContent,/No source result was reported/);
  assert.equal(app.byId('flow-stage-source').dataset.confirmed,'false');
});

test('architecture denial is check-specific and cannot erase previously received source evidence',()=>{
  const app=ui();app.renderSession(creditSession());let turn=app.addTurn();
  app.handleEvent(turn,'policy',policy());
  assert.equal(app.state.flow.phase,'denied');assert.equal(app.state.flow.sourceAccess,false);
  assert.match(app.byId('flow-source').textContent,/at denied check/);
  app.handleEvent(turn,'error',{code:'denied'});app.handleEvent(turn,'done',{});
  assert.equal(app.state.flow.phase,'denied');
  turn=app.addTurn();app.handleEvent(turn,'policy',policy({phase:'source_read',outcome:'allowed',source_accessed:true}));
  app.handleEvent(turn,'result',result());app.handleEvent(turn,'policy',policy());
  assert.equal(app.state.flow.sourceAccess,true);assert.equal(app.state.flow.hasResult,true);
  assert.equal(app.byId('flow-source').textContent,'Source evidence received');
});

test('late validated evidence cannot turn an interrupted or denied stream into success',()=>{
  for (const terminal of ['interrupted','denied']) {
    const app=ui();app.renderSession(creditSession());const turn=app.addTurn();
    if(terminal==='denied')app.handleEvent(turn,'policy',policy());
    app.handleEvent(turn,'error',{code:'request_failed',message:'Request ended.'});
    const status=app.byId('flow-status').textContent;
    app.handleEvent(turn,'policy',policy({phase:'source_read',outcome:'allowed',source_accessed:true}));
    app.handleEvent(turn,'result',result());app.handleEvent(turn,'status',{message:'Explaining the latest authorized snapshot…'});app.handleEvent(turn,'done',{});
    assert.equal(app.state.flow.phase,terminal);assert.equal(app.byId('flow-status').textContent,status);
    assert.equal(app.state.flow.hasResult,true);assert.equal(app.state.flow.sourceAccess,true);
  }
});

test('architecture state belongs to the current turn and clears on identity change and expiry',()=>{
  const app=ui();app.renderSession(organizationSession());const old=app.addTurn();
  app.handleEvent(old,'policy',policy({phase:'source_read',outcome:'allowed',source_accessed:true}));
  const current=app.addTurn();app.handleEvent(old,'result',result());
  assert.equal(app.state.flow.turn,current);assert.equal(app.state.flow.hasResult,false);assert.equal(app.state.flow.events.length,0);
  app.renderSession(organizationSession('engineer',2));
  assert.equal(app.state.flow,null);assert.equal(app.byId('flow-panel').hidden,true);assert.equal(app.byId('flow-trace').children.length,0);
  app.receiveFlow(old,'policy',policy());assert.equal(app.state.flow,null);
  app.renderSession(organizationSession('customer_analyst',3));app.addTurn();app.expireSession();
  assert.equal(app.state.flow,null);assert.equal(app.byId('flow-panel').hidden,true);
});

test('architecture clears immediately while a persona change is pending and rejects late events',async()=>{
  const app=ui();app.renderSession(organizationSession());const turn=app.addTurn();let release;
  app.fetch=()=>new Promise(resolve=>{release=resolve;});const changing=app.choosePersona('engineer');
  assert.equal(app.byId('flow-panel').hidden,true);assert.equal(app.state.flow,null);
  app.receiveFlow(turn,'policy',policy({phase:'source_read',outcome:'allowed',source_accessed:true}));assert.equal(app.state.flow,null);
  release({ok:true,json:async()=>organizationSession('engineer',2)});await changing;
  assert.equal(app.byId('flow-panel').hidden,true);
});


test('session model is read-only and distinct from the actual runtime identity',()=>{
  const app=ui(),value=creditSession();value.model={id:'fixture-approved',label:'Approved fixture model'};value.runtime={kind:'fixture',label:'Actual fixture runtime identity'};
  app.renderSession(value);assert.equal(app.byId('workspace-model').hidden,false);assert.equal(app.byId('workspace-model-name').textContent,'Approved fixture model');assert.equal(app.byId('runtime-name').textContent,'Actual fixture runtime identity');
  app.renderSession(session());assert.equal(app.byId('workspace-model').hidden,true);
});

test('session model labels cannot inject markup',()=>{
  const app=ui(),value=creditSession(),hostile='<img src=x onerror=alert(1)>';value.model={id:'fixture-approved',label:hostile};app.renderSession(value);
  assert.equal(app.byId('workspace-model-name').textContent,hostile);assert.equal(app.byId('workspace-model-name').innerHTML,undefined);
});

function organizationSession(persona='customer_analyst',generation=1) {
  const value=creditSession();value.subject={id:'fixture-'+persona,display_name:'Fixture '+persona};
  const allowed=persona!=='engineer';if(!allowed)value.allowed_metrics=[];
  value.organization={id:'northstar-financial',display_name:'Northstar Financial Systems',simulation:true,generation,active_persona_id:persona,
    membership:{subject:value.subject.id,persona_id:persona,label:persona==='engineer'?'Product engineer':persona==='support'?'Customer support':'Portfolio analyst'},
    personas:[{id:'customer_analyst',label:'Portfolio analyst'},{id:'engineer',label:'Product engineer'},{id:'support',label:'Customer support'}],
    can_chat:allowed,can_query:allowed,data_entitlement:{tenant_id:value.customer.id,display_name:value.customer.display_name,allowed,requires_support_case:persona==='support'},
    content_visibility:{sharing_enabled:false,can_change:persona==='customer_analyst',notice:'Question text is hidden by default.'},support_case:persona==='support'?{case_id:'case-1',subject:value.subject.id,tenant_id:value.customer.id,reason:'Investigate a reported discrepancy',expires_at:Date.now()/1000+300,generation}:null,
    customers:[{id:value.customer.id,display_name:value.customer.display_name,relationship:'assigned_customer',data_access:allowed},{id:'cedar-bank',display_name:'Cedar Community Bank',relationship:'directory_only',data_access:false}],activity_scope:'this_lease_only'};
  return value;
}
function activity(value,extra={}) {return {organization:value.organization,scope:'this_lease_only',retention_seconds:900,records:[{request_id:'request-1',at:Date.now()/1000,kind:'chat',subject:'fixture-customer_analyst',persona_id:'customer_analyst',tenant_id:value.customer.id,model:'Fixture runtime',question_sha256:'a'.repeat(64),question_bytes:28,question_text:null,question_visibility:'hidden',tool:'opaque_metrics_query',metrics:['requests_per_second'],window_secs:60,tool_calls:1,outcome:'completed',source_accessed:true,reason_code:null,...extra}]};}

test('engineer is a bound metadata-only identity with no chat or customer tool entitlement',async()=>{
  const app=ui();app.renderSession(organizationSession('engineer'));
  assert.equal(app.byId('organization-panel').hidden,false);assert.equal(app.byId('chat-content').hidden,true);assert.equal(app.byId('message').disabled,true);
  assert.match(app.byId('policy-tool').textContent,/No customer metric/);assert.match(app.byId('organization-entitlement').textContent,/no customer metric/);
  app.byId('message').value='Show requests';let called=false;app.fetch=()=>{called=true;throw Error('unexpected');};await app.submitMessage();assert.equal(called,false);
  const directory=allNodes(app.byId('customer-directory'));assert.ok(directory.some(n=>n.textContent==='Cedar Community Bank'));assert.ok(directory.every(n=>n.tagName!=='a'&&n.tagName!=='button'));
  const broken=organizationSession('engineer');broken.organization.membership.subject='another-user';assert.throws(()=>app.renderSession(broken),/authority did not match/);
});

test('changing persona or generation clears prior question and metric evidence',()=>{
  const app=ui();app.renderSession(organizationSession());app.addMessage('user','Private current conversation');app.receiveResult(app.addTurn(),result());
  app.renderActivity(activity(app.state.session));app.renderSession(organizationSession('engineer',2));
  assert.equal(app.state.latest.size,0);assert.equal(app.byId('conversation').children.length,1);assert.equal(app.byId('activity-records').children.length,0);
  assert.equal(app.state.session.subject.id,'fixture-engineer');assert.equal(app.byId('sharing-toggle').hidden,true);
});

test('activity rejects wrong organization, subject, generation and tenant before display',()=>{
  const app=ui(),value=organizationSession('engineer');app.renderSession(value);
  for(const change of [v=>{v.organization.id='other-company';},v=>{v.organization.membership.subject='foreign-engineer';},v=>{v.organization.generation=9;},v=>{v.records[0].tenant_id='cedar-bank';},v=>{v.scope='all_visitors';}]) {
    const payload=structuredClone(activity(value));change(payload);assert.throws(()=>app.renderActivity(payload),/not match|invalid/);assert.equal(app.byId('activity-records').children.length,0);
  }
});

test('activity question text requires explicit visibility and stays plaintext',()=>{
  const app=ui(),value=organizationSession('engineer');app.renderSession(value);const hostile='<img src=x onerror=alert(1)>';
  assert.throws(()=>app.renderActivity(activity(value,{question_text:hostile})),/visibility binding/);
  app.renderActivity(activity(value,{question_visibility:'shared_by_customer',question_text:hostile}));
  let nodes=allNodes(app.byId('activity-records'));assert.ok(nodes.some(n=>n.textContent===hostile));assert.ok(nodes.every(n=>!Object.hasOwn(n,'innerHTML')));
  app.renderActivity(activity(value));nodes=allNodes(app.byId('activity-records'));assert.ok(!nodes.some(n=>n.textContent===hostile));assert.ok(nodes.some(n=>n.textContent==='Question text concealed'));
  assert.equal(app.activitySource({source_accessed:null}),'Source access unknown');assert.equal(app.activitySource({source_accessed:false}),'No source access reported for this request');
});

test('support requires a current case bound to its subject, customer and generation',()=>{
  const app=ui(),value=organizationSession('support',4);app.renderSession(value);assert.equal(app.canChat(),true);
  value.organization.support_case.expires_at=Date.now()/1000-1;app.updateSupportCase();assert.equal(app.canChat(),false);assert.equal(app.byId('message').disabled,true);assert.match(app.byId('support-case').textContent,/expired/);assert.equal(app.byId('activity-records').children.length,0);
  value.organization.support_case.expires_at=Date.now()/1000+200;value.organization.support_case.tenant_id='cedar-bank';assert.equal(app.supportCaseValid(value.organization),false);
  assert.throws(()=>app.renderActivity(activity(value)),/current activity access/);
});

test('persona selection sends only its fixed alias and support reason, then trusts returned identity',async()=>{
  const app=ui();app.renderSession(organizationSession());let calls=[];
  app.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,json:async()=>path.endsWith('activity')?activity(app.state.session):organizationSession('engineer',2)};};
  await app.choosePersona('engineer');assert.deepEqual(JSON.parse(calls[0].options.body),{persona_id:'engineer'});assert.equal(calls[0].options.credentials,'same-origin');assert.equal(calls[0].options.headers.Authorization,undefined);assert.equal(app.state.session.organization.membership.persona_id,'engineer');
  calls=[];app.byId('support-reason').value='Investigate a discrepancy';app.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,json:async()=>path.endsWith('activity')?activity(app.state.session):organizationSession('support',3)};};
  await app.startSupport();assert.deepEqual(JSON.parse(calls[0].options.body),{persona_id:'support',reason:'Investigate a discrepancy'});assert.equal(app.canChat(),true);
});

test('sharing changes are analyst-only, exact-bodied and clear displayed text before confirmation',async()=>{
  const app=ui(),value=organizationSession();app.renderSession(value);app.renderActivity(activity(value,{question_visibility:'shared_by_customer',question_text:'Previously shared question'}));
  let captured;app.fetch=async(path,options)=>{if(path.endsWith('sharing')){captured={path,options};assert.equal(app.byId('activity-records').children.length,0);const next=organizationSession();next.organization.content_visibility.sharing_enabled=true;return {ok:true,json:async()=>next};}return {ok:true,json:async()=>activity(app.state.session)};};
  await app.toggleSharing();assert.deepEqual(JSON.parse(captured.options.body),{enabled:true});assert.equal(app.state.session.organization.content_visibility.sharing_enabled,true);
  app.renderSession(organizationSession('engineer',2));captured=null;await app.toggleSharing();assert.equal(captured,null);
});

test('a pending activity response cannot restore the prior persona after a switch',async()=>{
  const app=ui(),value=organizationSession();app.renderSession(value);let resolve;
  app.fetch=()=>new Promise(done=>{resolve=done;});const pending=app.loadActivity();app.renderSession(organizationSession('engineer',2));
  resolve({ok:true,json:async()=>activity(value,{question_visibility:'shared_by_customer',question_text:'Old question'})});await pending;
  assert.equal(app.byId('activity-records').children.length,0);assert.equal(app.state.session.organization.generation,2);
});

function portfolioSession(persona='customer_analyst') {
  const value=organizationSession(persona);value.dataset={id:'synthetic_loan_applications',source_id:'fixture-credit-history',label:'Synthetic loan application history',history_kind:'synthetic_seeded_and_live',can_query:persona!=='engineer',coverage_policy:'complete_windows_only',max_rows:12,trend_buckets:6,
    measures:[{id:'application_count',label:'Applications',unit:'applications'},{id:'manual_review_rate_percent',label:'Manual review rate',unit:'%'},{id:'identity_mismatch_rate_percent',label:'Identity mismatch rate',unit:'%'},{id:'mean_processing_seconds',label:'Mean processing time',unit:'seconds'},{id:'manual_review_count',label:'Manual review count',unit:'applications'},{id:'identity_mismatch_count',label:'Identity mismatch count',unit:'applications'}],views:['summary','trend','breakdown','comparison'],windows_secs:[60,300,900,1800,3600],dimensions:[{id:'channel',values:[{id:'web',label:'Web'},{id:'mobile',label:'Mobile'},{id:'partner',label:'Partner'}]},{id:'region',values:[{id:'west',label:'West'}]},{id:'product',values:[{id:'personal_loan',label:'Personal loan'}]}]};
  value.policy_context.allowed_tools=['opaque_metrics_query','opaque_portfolio_query'];value.suggested_questions=['Summarize this hour','Show application trends','Compare channels','Compare with the previous period'];return value;
}
function portfolioEvidence(view='summary') {
  const value=portfolioSession(),now=Math.floor(Date.now()/1000),measure=value.dataset.measures[1];
  const count=view==='trend'?6:view==='breakdown'?3:view==='comparison'?2:1;
  return {evidence_id:'portfolio-proof-1',query:{view,window_secs:300,measures:[measure.id],...(view==='breakdown'?{dimension:'channel'}:{}),filters:{}},tenant_id:value.customer.id,source_id:value.dataset.source_id,as_of:now,watermark:now-1,observed_at:now,history_start:now-7200,history_kind:'synthetic_seeded_and_live',coverage:'complete',
    rows:Array.from({length:count},(_,i)=>({key:String(i),label:view==='breakdown'?['Web','Mobile','Partner'][i]:view==='comparison'?['Current','Previous'][i]:'Period '+(i+1),period_start:now-300+(view==='trend'?i*50:0),period_end:now-(view==='trend'?(5-i)*50:0),sample_count:100+i,values:{[measure.id]:20+i}})),comparison:view==='comparison'?[{measure:measure.id,current:21,previous:20,delta:1,delta_unit:'percentage_points',relative_percent:5}]:[],measures:[measure],answer:'The server-computed manual review rate is 20%.'};
}

test('dataset explorer shows the server catalog and richer starters without query authority',()=>{
  const app=ui();app.renderSession(portfolioSession());assert.equal(app.byId('dataset-explorer').hidden,false);assert.equal(app.byId('dataset-measures').children.length,6);assert.equal(app.byId('suggestions').children.length,4);
  assert.match(app.byId('dataset-coverage').textContent,/complete windows/);assert.match(app.byId('dataset-windows').textContent,/1 hour/);
  const engineer=portfolioSession('engineer');engineer.dataset.measures=[];app.renderSession(engineer);assert.match(app.byId('dataset-entitlement').textContent,/metadata only/);assert.match(app.byId('dataset-measures').children[0].textContent,/No portfolio measures/);assert.equal(app.canChat(),false);
  app.renderSession(session());assert.equal(app.byId('dataset-explorer').hidden,true);
});

test('all portfolio views retain exact server answer, tables and evidence',()=>{
  for(const view of ['summary','trend','breakdown','comparison']) {
    const app=ui();app.renderSession(portfolioSession());const turn=app.addTurn(),proof=portfolioEvidence(view);app.handleEvent(turn,'portfolio_result',proof);
    const nodes=allNodes(turn.results);assert.ok(nodes.some(n=>n.tagName==='table'),view);assert.equal(turn.body.textContent,proof.answer);assert.equal(turn.events,1);
    assert.ok(nodes.some(n=>n.textContent.includes('portfolio-proof-1')));assert.ok(nodes.some(n=>n.textContent.includes('Complete coverage')));
    if(view==='comparison'){assert.ok(nodes.some(n=>n.textContent==='percentage points'));assert.ok(nodes.some(n=>n.textContent==='Relative change'));}
    if(view==='trend'||view==='breakdown')assert.ok(nodes.some(n=>n.className==='portfolio-bar-fill'));
  }
});

test('portfolio results reject foreign source, tenant, measure, segment and incomplete coverage',()=>{
  const app=ui();app.renderSession(portfolioSession());
  const changes=[p=>p.source_id='other-source',p=>p.tenant_id='cedar-bank',p=>p.coverage='partial',p=>p.query.measures=['borrower_ssn'],p=>p.query.filters={channel:'unapproved'},p=>p.query.filters={customer:'cedar-bank'},p=>p.query.window_secs=7200,p=>p.rows[0].values.manual_review_rate_percent=Infinity];
  for(const change of changes){const proof=portfolioEvidence();change(proof);const turn=app.addTurn();assert.throws(()=>app.receivePortfolioResult(turn,proof));assert.equal(turn.results.children.length,0);assert.equal(turn.body.textContent,'');}
  app.renderSession(portfolioSession('engineer'));assert.throws(()=>app.receivePortfolioResult(app.addTurn(),portfolioEvidence()),/query scope/);
});

test('missing values remain unavailable, with no invented zero or chart height',()=>{
  const app=ui();app.renderSession(portfolioSession());const turn=app.addTurn(),proof=portfolioEvidence('trend');proof.rows.forEach(row=>{row.sample_count=0;row.values.manual_review_rate_percent=null;});
  app.receivePortfolioResult(turn,proof);const nodes=allNodes(turn.results);assert.ok(nodes.some(n=>n.textContent==='Unavailable'));assert.ok(nodes.some(n=>n.textContent==='No samples'));assert.ok(nodes.every(n=>n.className!=='portfolio-bar-fill'));
});

test('portfolio labels and deterministic answer remain plaintext',()=>{
  const app=ui();app.renderSession(portfolioSession());const proof=portfolioEvidence('breakdown'),hostile='<img src=x onerror=alert(1)>';proof.answer=hostile;proof.rows[0].label=hostile;proof.measures[0]={...proof.measures[0],label:hostile};
  const turn=app.addTurn();app.receivePortfolioResult(turn,proof);assert.equal(turn.body.textContent,hostile);assert.ok(allNodes(turn.results).some(n=>n.textContent===hostile));assert.ok(allNodes(turn.results).every(n=>!Object.hasOwn(n,'innerHTML')&&n.tagName!=='img'));
});

test('exploration tables remain partial until the grounded answer and retain finding receipts',()=>{
  const app=ui();app.renderSession(portfolioSession());const turn=app.addTurn();
  const hostile='<img src=x onerror=alert(1)>';
  app.handleEvent(turn,'interpretation',{text:hostile,query_count:3});
  assert.equal(turn.body.textContent,'Interpreting your question: '+hostile);
  assert.match(turn.status.textContent,/3 authorized queries/);
  const proof=portfolioEvidence('breakdown');proof.partial=true;
  app.handleEvent(turn,'portfolio_result',proof);
  assert.equal(turn.body.textContent,'Interpreting your question: '+hostile);
  assert.equal(turn.results.children.length,1);
  app.handleEvent(turn,'answer',{kind:'grounded',text:'Computed source observations.',summary_mode:'model_selected_evidence',findings:[{id:'q1:manual_review_rate_percent',evidence_id:proof.evidence_id,text:'Known source finding'}]});
  assert.equal(turn.body.textContent,'Computed source observations.');
  assert.ok(allNodes(turn.element).some(node=>node.textContent==='Answer source [1]'));
  assert.ok(allNodes(turn.element).every(node=>node.tagName!=='img'&&!Object.hasOwn(node,'innerHTML')));
});

test('clarification and unsupported answers show no-read status without fabricated result cards',()=>{
  for(const [kind,status] of [['clarification','Please clarify your question · no source read'],['unsupported','Outside available data · no source read']]) {
    const app=ui();app.renderSession(portfolioSession());const turn=app.addTurn();
    app.handleEvent(turn,'answer',{kind,text:'A specific follow-up is needed.',source_accessed:false});
    app.handleEvent(turn,'done',{});
    assert.equal(turn.status.textContent,status);assert.equal(turn.results.children.length,0);
    assert.equal(turn.body.textContent,'A specific follow-up is needed.');
    assert.equal(app.state.latest.size,0);
  }
});

function chatReplies(app,replies) {
  const requests=[];
  app.loadActivity=async()=>{};
  app.fetch=async(url,options)=>{
    assert.equal(url,'/api/chat');requests.push(JSON.parse(options.body));
    const reply=replies.shift();if(reply instanceof Error)throw reply;
    const frames=reply.events||[['answer',reply],['done',{}]];
    let sent=false;
    return {ok:true,status:200,headers:{get:()=> 'text/event-stream'},body:{getReader:()=>({read:async()=>{
      if(sent)return {done:true};sent=true;
      return {done:false,value:Buffer.from(frames.map(([kind,value])=>'event: '+kind+'\ndata: '+JSON.stringify(value)+'\n\n').join(''))};
    }})}};
  };
  return requests;
}

test('explicit clarification continuation preserves original filters and window using only user text',async()=>{
  const app=ui();app.renderSession(session());
  const original='How many flagged auto-loan applications were there in the West during the last half hour?';
  const requests=chatReplies(app,[{kind:'clarification',text:'MODEL-ONLY: which kind of flags?',source_accessed:false},{kind:'grounded',text:'Known source observations.'},{kind:'grounded',text:'Another answer.'}]);
  app.byId('message').value=original;await app.submitMessage();
  assert.equal(app.state.clarification.question,original);assert.equal(app.state.clarification.identityKey,app.state.identityKey);
  assert.equal(app.byId('clarification-context').hidden,false);assert.match(app.byId('clarification-question').textContent,/West.*half hour/);
  assert.match(app.byId('composer-hint').textContent,/original question.*clarification.*together/);
  app.byId('message').value='I mean identity mismatches';await app.submitMessage();
  assert.deepEqual(requests[1],{message:'Original question:\n'+original+'\n\nUser clarification 1:\nI mean identity mismatches'});
  assert.ok(!requests[1].message.includes('MODEL-ONLY'));assert.equal(app.state.clarification,null);
  assert.equal(app.byId('clarification-context').hidden,true);
  app.byId('message').value='Show application volume';await app.submitMessage();
  assert.deepEqual(requests[2],{message:'Show application volume'});
});

test('changing persona or revoking the session clears pending clarification context',async()=>{
  const app=ui();app.renderSession(organizationSession('customer_analyst',1));
  const requests=chatReplies(app,[{kind:'clarification',text:'Which measure?',source_accessed:false},{kind:'clarification',text:'Which channel?',source_accessed:false}]);
  app.byId('message').value='Prior private question';await app.submitMessage();
  app.renderSession(organizationSession('engineer',2));
  assert.equal(app.state.clarification,null);assert.equal(app.byId('clarification-question').textContent,'');
  app.renderSession(organizationSession('customer_analyst',3));
  app.byId('message').value='A new question';await app.submitMessage();
  assert.deepEqual(requests[1],{message:'A new question'});
  app.expireSession('Revoked');assert.equal(app.state.clarification,null);assert.equal(app.byId('clarification-context').hidden,true);
});

test('New question and suggestion selection explicitly discard pending continuation',async()=>{
  const app=ui();app.renderSession(session());
  const requests=chatReplies(app,[{kind:'clarification',text:'Which measure?',source_accessed:false},{kind:'clarification',text:'Which measure?',source_accessed:false},{kind:'grounded',text:'Done.'}]);
  app.byId('message').value='Original question';await app.submitMessage();
  app.byId('message').value='Independent draft';app.startNewQuestion();
  assert.equal(app.state.clarification,null);assert.equal(app.byId('message').value,'Independent draft');
  await app.submitMessage();assert.deepEqual(requests[1],{message:'Independent draft'});
  const suggestion=app.byId('suggestions').children[0];suggestion.click();
  assert.equal(app.state.clarification,null);await app.submitMessage();
  assert.deepEqual(requests[2],{message:suggestion.textContent});
});

test('continuation rejects oversized UTF-8 messages without truncating or sending',async()=>{
  const app=ui();app.renderSession(session());
  const original='a'.repeat(1800),reply='b'.repeat(200);
  const requests=chatReplies(app,[{kind:'clarification',text:'Which measure?',source_accessed:false}]);
  app.byId('message').value=original;await app.submitMessage();
  app.byId('message').value=reply;await app.submitMessage();
  assert.equal(requests.length,1);assert.equal(app.byId('message').value,reply);assert.equal(app.state.clarification.question,original);
  assert.equal(app.byId('composer-error').hidden,false);assert.match(app.byId('composer-error').textContent,/2,000-byte.*Nothing was sent/);
  app.startNewQuestion();app.byId('message').value='é'.repeat(1001);await app.submitMessage();
  assert.equal(requests.length,1);assert.equal(app.byId('message').value,'é'.repeat(1001));
  assert.match(app.byId('composer-error').textContent,/Nothing was sent/);
});

test('unsupported responses and incomplete or failed streams do not retain clarification',async()=>{
  for(const response of [{kind:'unsupported',text:'Not available.',source_accessed:false},new Error('Disconnected'),{events:[['answer',{kind:'clarification',text:'Another question?',source_accessed:false}]]}]) {
    const app=ui();app.renderSession(session());
    chatReplies(app,[{kind:'clarification',text:'Which measure?',source_accessed:false},response]);
    app.byId('message').value='Original question';await app.submitMessage();
    assert.ok(app.state.clarification);app.byId('message').value='Manual reviews';await app.submitMessage();
    assert.equal(app.state.clarification,null);assert.equal(app.byId('clarification-context').hidden,true);
  }
});

test('portfolio policy events require the session explicit tool grant',()=>{
  const app=ui(),value=portfolioSession();app.renderSession(value);const turn=app.addTurn();app.receivePolicy(turn,policy({tool:'opaque_portfolio_query'}));
  value.policy_context.allowed_tools=['opaque_metrics_query'];assert.throws(()=>app.receivePolicy(turn,policy({tool:'opaque_portfolio_query'})),/did not match/);
  app.receivePolicy(turn,policy({tool:'opaque_metrics_query'}));
});

function workSession(generation=1) {
  const value=organizationSession('customer_analyst',generation);
  value.allowed_metrics=[{id:'manual_review_rate_percent',label:'Manual review rate'}];
  return value;
}
function workTask(value=workSession(),status='planned') {
  const now=Math.floor(Date.now()/1000);
  return {task_id:'01234567-89ab-4cde-8fab-0123456789ab',manifest_sha256:'b'.repeat(64),state:status,consumed:['reserved','completed','unknown'].includes(status),simulation:true,notice:'Synthetic demo task. Source credentials stay with the service.',
    manifest:{operation:'metrics.aggregate.read',tenant_id:value.customer.id,source_id:value.source.label,metrics:['manual_review_rate_percent'],window_secs:60,max_uses:1,created_at:now-5,expires_at:now+295,subject:value.subject.id,client_id:'fixture-analyst-client',persona_generation:value.organization.generation},
    approval:status==='planned'?null:{kind:'synthetic_demo_confirmation',approved_at:now-3},
    receipt:status==='completed'?{evidence:'synthetic_source_observed',completed_at:now,evidence_sha256:'c'.repeat(64),result:{tenant_id:value.customer.id,source_id:value.source.label,window_secs:60,as_of:now,watermark:now-1,observed_at:now,metrics:[{name:'manual_review_rate_percent',value:18.4,count:25}]}}:null};
}

test('task loading only reads status and never approves or executes on render or reload',async()=>{
  const app=ui(),value=workSession();let calls=[];
  app.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,status:200,json:async()=>workTask(value)};};
  app.renderSession(value);assert.equal(calls.length,0);
  await app.loadWorkTask();await app.loadWorkTask();
  assert.equal(calls.length,2);assert.ok(calls.every(call=>call.path==='/api/work-task'&&!call.options.method));
  assert.equal(app.byId('work-approve').hidden,false);assert.equal(app.byId('work-run').hidden,true);assert.equal(app.byId('work-receipt').hidden,true);
  assert.equal(app.byId('work-notice').textContent,workTask(value).notice);
});

test('execution sends only the exact approved ID and digest and requires server confirmation',async()=>{
  const app=ui(),value=workSession();app.renderSession(value);app.state.workTask=app.validateWorkTask(workTask(value));let calls=[];
  app.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,status:200,json:async()=>workTask(value,path.endsWith('approve')?'approved':'completed')};};
  await app.workTaskAction('execute');assert.equal(calls.length,0);
  app.state.workTask=app.validateWorkTask(workTask(value,'approved'));app.renderWorkTask();assert.equal(app.byId('work-run').hidden,false);
  await app.workTaskAction('execute');assert.equal(app.state.workTask.state,'completed');assert.equal(app.byId('work-receipt').hidden,false);assert.equal(app.byId('work-value').textContent,'18.4%');
  assert.deepEqual(calls.map(call=>call.path),['/api/work-task/execute']);
  for(const call of calls){assert.deepEqual(JSON.parse(call.options.body),{task_id:app.state.workTask.task_id,manifest_sha256:'b'.repeat(64)});assert.equal(call.options.credentials,'same-origin');assert.equal(call.options.headers.Authorization,undefined);}
});

test('replay denial displays the actual service error while retaining the confirmed receipt',async()=>{
  const app=ui(),value=workSession();app.renderSession(value);app.state.workTask=app.validateWorkTask(workTask(value,'completed'));app.renderWorkTask();let calls=0;
  app.fetch=async()=>{calls++;return {ok:false,status:409,json:async()=>({error:{code:'task_consumed',message:'This one-use task is already consumed.'}})};};
  await app.workTaskAction('execute');assert.equal(calls,1);assert.equal(app.state.workTask.state,'completed');assert.equal(app.byId('work-receipt').hidden,false);
  assert.match(app.byId('work-status').textContent,/Replay request denied.*recorded task remains consumed.*task_consumed.*already consumed/);assert.equal(app.byId('work-error').hidden,true);
});

test('an uncertain action response does not invent completion or automatically retry execution',async()=>{
  const app=ui(),value=workSession();app.renderSession(value);app.state.workTask=app.validateWorkTask(workTask(value,'approved'));let calls=0;
  app.fetch=async()=>{calls++;throw new Error('Connection interrupted.');};
  await app.workTaskAction('execute');assert.equal(calls,1);assert.equal(app.state.workTask,null);assert.equal(app.byId('work-receipt').hidden,true);
  assert.match(app.byId('work-status').textContent,/outcome is not confirmed/);assert.equal(app.byId('work-refresh').disabled,false);
});

test('task scope and receipt validation reject altered authority before showing metrics',()=>{
  const app=ui(),value=workSession();app.renderSession(value);
  const changes=[t=>t.manifest.tenant_id='cedar-bank',t=>t.manifest.subject='another-subject',t=>t.manifest.source_id='another-source',t=>t.manifest.window_secs=300,t=>t.manifest.max_uses=2,t=>t.manifest.metrics=['borrower_ssn'],t=>t.manifest.expires_at+=1,t=>t.manifest.persona_generation=2,t=>t.approval=null,t=>t.consumed=false,t=>t.receipt.result.tenant_id='cedar-bank',t=>t.receipt.result.metrics[0].value=Infinity];
  for(const change of changes){const task=workTask(value,'completed');change(task);assert.throws(()=>app.validateWorkTask(task));assert.equal(app.byId('work-receipt').hidden,true);assert.equal(app.byId('work-value').textContent,'');}
});

test('persona changes clear all task evidence and discard late receipt responses',async()=>{
  const app=ui(),value=workSession();app.renderSession(value);app.state.workTask=app.validateWorkTask(workTask(value,'completed'));app.renderWorkTask();let resolve;
  app.fetch=()=>new Promise(done=>resolve=done);const pending=app.loadWorkTask();app.renderSession(organizationSession('engineer',2));
  assert.equal(app.state.workTask,null);assert.equal(app.byId('work-value').textContent,'');assert.equal(app.byId('work-content').hidden,true);assert.equal(app.byId('work-role').hidden,false);
  resolve({ok:true,status:200,json:async()=>workTask(value,'completed')});await pending;
  assert.equal(app.state.workTask,null);assert.equal(app.byId('work-value').textContent,'');
  let called=false;app.fetch=async()=>{called=true;};await app.loadWorkTask();await app.workTaskAction('execute');assert.equal(called,false);
  app.renderSession(organizationSession('support',3));await app.loadWorkTask();assert.equal(called,false);assert.equal(app.byId('work-content').hidden,true);
});

test('returning analyst can display only a revoked older task without its prior receipt',()=>{
  const app=ui(),earlier=workSession(),current=workSession(3);app.renderSession(current);
  const revoked=workTask(earlier,'revoked');app.state.workTask=app.validateWorkTask(revoked);app.renderWorkTask();
  assert.equal(app.byId('work-state').textContent,'revoked');assert.equal(app.byId('work-run').hidden,true);assert.equal(app.byId('work-approve').hidden,true);
  revoked.receipt=workTask(earlier,'completed').receipt;assert.throws(()=>app.validateWorkTask(revoked),/earlier identity generation/);
});

function approvalUI() {
  const app=ui();app.renderSession(workSession());app.state.workTask=app.validateWorkTask(workTask());
  // Ceremony UX tests isolate the independently tested WASM review operation.
  app.reviewApprovalManifest=async()=>{};
  app.PublicKeyCredential=function(){};app.navigator={credentials:{}};
  app.fetch=async()=>({ok:true,json:async()=>({passkey:{available:true},oauth:{available:false}})});
  return app;
}
function verifiedTask(kind='webauthn') {
  const task=workTask(workSession(),'approved');
  task.approval={kind,approved_at:Math.floor(Date.now()/1000),verification:{issuer:kind==='oidc'?'https://identity.example.com':null,subject:kind==='oidc'?'github-subject':'temporary_demo_visitor',credential_sha256:kind==='webauthn'?'d'.repeat(64):null,user_verified:kind==='webauthn'?true:null}};
  return task;
}
test('opening and cancelling human review cannot call the old unsigned approval endpoint',async()=>{
  const app=approvalUI(),calls=[];
  app.fetch=async(path,options)=>{calls.push({path,options});return {ok:true,json:async()=>({passkey:{available:true},oauth:{available:false}})};};
  await app.workTaskAction('approve');assert.equal(app.byId('approval-window').open,true);
  assert.equal(app.byId('approval-passkey').disabled,false);assert.equal(app.byId('approval-oauth').disabled,true);
  app.closeApproval();assert.equal(app.byId('approval-window').open,false);assert.equal(app.state.workTask.state,'planned');
  assert.equal(calls.length,1);assert.equal(calls[0].path,'/api/work-task/approval');assert.equal(calls[0].options.method,undefined);
});
test('a failed review keeps every authentication method disabled',async()=>{
  const app=approvalUI();app.reviewApprovalManifest=async()=>{throw Error('Digest mismatch');};let calls=0;app.fetch=()=>{calls++;};
  await app.openApproval();assert.equal(calls,0);assert.equal(app.byId('approval-passkey').disabled,true);assert.equal(app.byId('approval-oauth').disabled,true);assert.match(app.byId('approval-error').textContent,/Digest mismatch/);
});
test('passkey registration is followed by fresh authentication before task approval; no execution occurs',async()=>{
  const app=approvalUI();await app.openApproval();let starts=0,created=0,asserted=0;const calls=[];
  app.credentialOptions=raw=>raw;
  app.navigator.credentials={create:async()=>{created++;return {toJSON:()=>({type:'public-key',response:{attestationObject:'registration'}})};},get:async()=>{asserted++;return {toJSON:()=>({type:'public-key',response:{signature:'assertion'}})};}};
  app.approvalPost=async(path,body)=>{calls.push({path,body});if(path==='start')return {kind:starts++?'authentication':'registration',transaction_id:'ceremony-'+starts,public_key:{}};return body.credential.response.attestationObject?{registered:true}:verifiedTask();};
  await app.approveWithPasskey();assert.equal(created,1);assert.equal(asserted,1);assert.equal(app.state.workTask.state,'approved');assert.equal(app.byId('approval-window').open,false);
  assert.deepEqual(calls.map(call=>call.path),['start','finish','start','finish']);
  assert.ok(calls.every(call=>call.body.task_id===workTask().task_id&&call.body.manifest_sha256==='b'.repeat(64)));
  assert.match(app.byId('work-human-proof').textContent,/user verification checked by Opaque/);assert.equal(app.byId('work-run').hidden,false);
});
test('cancelling native authentication submits no proof and preserves planned state',async()=>{
  const app=approvalUI();await app.openApproval();let finishes=0;app.credentialOptions=raw=>raw;
  app.approvalPost=async path=>{if(path==='finish')finishes++;return {kind:'authentication',transaction_id:'challenge',public_key:{}};};
  app.navigator.credentials.get=async()=>{throw Object.assign(Error('Cancelled'),{name:'NotAllowedError'});};
  await app.approveWithPasskey();assert.equal(finishes,0);assert.equal(app.state.workTask.state,'planned');assert.match(app.byId('approval-error').textContent,/cancelled or timed out/);
});
test('persona change while an authenticator is open discards the late credential',async()=>{
  const app=approvalUI();await app.openApproval();let resolve,finishes=0;app.credentialOptions=raw=>raw;
  app.approvalPost=async path=>{if(path==='finish')finishes++;return {kind:'authentication',transaction_id:'challenge',public_key:{}};};
  app.navigator.credentials.get=()=>new Promise(done=>resolve=done);
  const pending=app.approveWithPasskey();await new Promise(done=>setImmediate(done));
  app.renderSession(organizationSession('engineer',2));resolve({toJSON:()=>({response:{signature:'late'}})});await pending;
  assert.equal(finishes,0);assert.equal(app.approval.open,false);assert.equal(app.state.workTask,null);
});
test('expiry aborts the authenticator and disables approval',async()=>{
  const app=approvalUI();await app.openApproval();const controller=new AbortController();app.approval.controller=controller;
  app.approval.task.manifest.expires_at=Math.floor(Date.now()/1000)-1;app.tickApproval();
  assert.equal(controller.signal.aborted,true);assert.equal(app.byId('approval-passkey').disabled,true);assert.equal(app.byId('approval-oauth').disabled,true);
});
test('OAuth callback must match the originating popup, exact origin and transaction',async()=>{
  const app=approvalUI();await app.openApproval();const popup={close(){}};app.window={location:{origin:'https://demo.example.com'}};
  app.approval.popup=popup;app.approval.busy=true;app.approval.transaction='state-value';let calls=0;
  app.approvalPost=async()=>{calls++;return verifiedTask('oidc');};
  const event={origin:'https://demo.example.com',source:popup,data:{type:'opaque-approval-oauth',state:'state-value',code:'one-use-code'}};
  await app.receiveApprovalOAuth({...event,origin:'https://attacker.example.com'});
  await app.receiveApprovalOAuth({...event,source:{}});
  await app.receiveApprovalOAuth({...event,data:{...event.data,state:'wrong-state'}});assert.equal(calls,0);
  await app.receiveApprovalOAuth(event);assert.equal(calls,1);assert.equal(app.state.workTask.state,'approved');assert.match(app.byId('work-human-proof').textContent,/OIDC identity verified/);
  await app.receiveApprovalOAuth(event);assert.equal(calls,1);
});
test('lost verification response disables retry and closing clears unconfirmed approval state',async()=>{
  const app=approvalUI();await app.openApproval();app.credentialOptions=raw=>raw;
  app.navigator.credentials.get=async()=>({toJSON:()=>({response:{signature:'assertion'}})});
  app.approvalPost=async path=>{if(path==='finish')throw Error('Interrupted');return {kind:'authentication',transaction_id:'challenge',public_key:{}};};
  await app.approveWithPasskey();assert.equal(app.byId('approval-passkey').disabled,true);assert.equal(app.state.workTask.state,'planned');app.closeApproval();assert.equal(app.state.workTask,null);assert.match(app.state.workNotice,/Check task status/);
});
test('human verification evidence cannot be fabricated by a missing or unverified proof',()=>{
  const app=approvalUI();for(const kind of ['webauthn','oidc']) {const value=verifiedTask(kind);value.approval.verification=null;assert.throws(()=>app.validateWorkTask(value),/human verification/);}
  const value=verifiedTask();value.approval.verification.user_verified=false;assert.throws(()=>app.validateWorkTask(value),/human verification/);
});
test('GitHub approval requires its fixed issuer and stable numeric account ID',()=>{
  const app=approvalUI(),value=verifiedTask('oidc');value.approval.kind='github_oauth';value.approval.verification.issuer='https://github.com';value.approval.verification.subject='1234567';
  app.state.workTask=app.validateWorkTask(value);app.renderWorkTask();assert.match(app.byId('work-human-proof').textContent,/GitHub identity verified by Opaque · account 1234567/);
  value.approval.verification.subject='friendly-login';assert.throws(()=>app.validateWorkTask(value),/GitHub account identity/);
  value.approval.verification.subject='1234567';value.approval.verification.issuer='https://attacker.example.com';assert.throws(()=>app.validateWorkTask(value),/GitHub account identity/);
});

// Run after `cargo build --locked -p opaque-showcase` so this exercises the module compiled
// by the same build.rs and WAT source that the actual gateway embeds.
if (process.env.OPAQUE_APPROVAL_WASM_JSON) {
  const wasm=fs.readFileSync(process.env.OPAQUE_APPROVAL_WASM_JSON,'utf8');
  function reviewTask() {
    const value=workTask();value.manifest.source_profile_sha256='a'.repeat(64);
    value.manifest_canonical_json=JSON.stringify(value.manifest);
    value.manifest_sha256=require('node:crypto').createHash('sha256').update(value.manifest_canonical_json).digest('hex');return value;
  }
  test('actual compiled WASM checks exact manifest bytes despite response key reordering',async()=>{
    const app=ui(wasm);app.renderSession(workSession());const value=reviewTask();value.manifest=Object.fromEntries(Object.entries(value.manifest).sort());await app.reviewApprovalManifest(value);
    const wrong=reviewTask();wrong.manifest_sha256='b'.repeat(64);await assert.rejects(app.reviewApprovalManifest(wrong),/digest did not match/);
    const altered=reviewTask();altered.manifest.client_id='changed-client';await assert.rejects(app.reviewApprovalManifest(altered),/review bytes do not match/);
  });
  test('compiled WASM rejects digest mutations, excessive authority, NaN and deadlines',async()=>{
    const {instance}=await WebAssembly.instantiate(new Uint8Array(JSON.parse(wasm))),check=instance.exports.review;
    assert.equal(check(60,1,100,400,200),0);
    for(const values of [[61,1,100,400,200],[60,2,100,400,200],[60,1,100,401,200],[60,1,100,400,400],[60,1,100,400,99],[60,1,100,400,NaN]])assert.notEqual(check(...values),0);
    new Uint8Array(instance.exports.memory.buffer)[31]=1;assert.equal(check(60,1,100,400,200),1);
  });
}
