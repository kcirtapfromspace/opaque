import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import { Leads, LEAD_CONSENT_VERSION, LEAD_LIMITS } from '../src/leads.mjs';
import { handleRequest } from '../src/http.mjs';

const FORM={email:'Pilot@Example.org',workflow:'Review secret publishing for our build pipeline',consent:true,source:{utm_source:'release.v1',utm_medium:'website',utm_campaign:'pilot~launch',referrer_host:'News.Example.org'},entry_point:'landing',turnstile_token:'fixture-contact-token'};
function fixture(t) {
  const db=new DatabaseSync(':memory:'); t.after(()=>db.close());
  const f={db,now:1_800_000_000_000,bot:{success:true,action:'demo_contact',hostname:'demo.example'},network:[],schedulerCalls:0,assetRequests:[]};
  t.mock.method(Date,'now',()=>f.now);
  const storage={alarm:null,sql:{exec(query,...args){const rows=db.prepare(query).all(...args);return {toArray:()=>rows};}},transactionSync(callback){db.exec('BEGIN IMMEDIATE');try{const result=callback();db.exec('COMMIT');return result;}catch(error){db.exec('ROLLBACK');throw error;}},async getAlarm(){return this.alarm;},async setAlarm(value){this.alarm=value;},async deleteAlarm(){this.alarm=null;}};
  f.storage=storage;
  f.env={PUBLIC_ORIGIN:'https://demo.example',DEMO_ENABLED:'false',DEMO_MODEL_IDS:'gemma4-e2b',CONTROLLER_SECRET:'fixture-controller-secret',LEAD_ADMIN_SECRET:'a'.repeat(64),TURNSTILE_SITE_KEY:'fixture-site-key',TURNSTILE_SECRET:'fixture-bot-secret',
    ASSETS:{async fetch(request){f.assetRequests.push(request.url);return new Response('<html><body>Fixture</body></html>');}},
    DEMO_SCHEDULER:{get(){f.schedulerCalls++;throw new Error('contact must not touch scheduler');}},
    LEAD_INBOX:{idFromName(name){assert.equal(name,'pilot-contacts-v1');return name;},get(){return {fetch:(url,init)=>f.leads.fetch(new Request(url,init))};}},
  };
  f.leads=new Leads({storage},f.env);
  f.restart=()=>{f.leads=new Leads({storage},f.env);};
  t.mock.method(globalThis,'fetch',async(url,init)=>{f.network.push({url:String(url),init});assert.equal(String(url),'https://challenges.cloudflare.com/turnstile/v0/siteverify');return Response.json(f.bot);});
  f.send=(path,{body,method='POST',headers={},ip='192.0.2.9',origin=f.env.PUBLIC_ORIGIN,raw}={})=>{
    const h=new Headers(headers);if(origin!==null)h.set('Origin',origin);if(ip!==null)h.set('CF-Connecting-IP',ip);
    if(body!==undefined||raw!==undefined)h.set('Content-Type','application/json');
    return handleRequest(new Request(f.env.PUBLIC_ORIGIN+path,{method,headers:h,body:raw??(body===undefined?undefined:JSON.stringify(body))}),f.env,{waitUntil(){throw new Error('contacts must finish durably in-request');}});
  };
  f.contact=(options={})=>f.send('/demo/api/contact',{body:structuredClone(FORM),...options});
  f.admin=(action,body={},secret=f.env.LEAD_ADMIN_SECRET)=>f.send('/internal/leads/'+action,{body,origin:null,headers:{Authorization:'Bearer '+secret}});
  f.count=()=>db.prepare('SELECT COUNT(*) AS n FROM contact_leads').get().n;
  return f;
}

test('202 follows durable contact save, restart preserves exact consented data and no runtime identity',async t=>{
  const f=fixture(t);const response=await f.contact();
  assert.equal(response.status,202);assert.deepEqual(await response.json(),{accepted:true});assert.equal(response.headers.get('Cache-Control'),'no-store');
  assert.equal(f.schedulerCalls,0);assert.equal(f.network.length,1);assert.equal(f.count(),1);assert.ok(f.storage.alarm>f.now);
  f.restart();const listed=await (await f.admin('list')).json();assert.equal(listed.leads.length,1);
  const lead=listed.leads[0];assert.equal(lead.email,'pilot@example.org');assert.equal(lead.email_verified,false);assert.equal(lead.consent,true);assert.equal(lead.consent_version,LEAD_CONSENT_VERSION);assert.equal(lead.expires_at-lead.created_at,LEAD_LIMITS.retentionMs);assert.equal(lead.source.referrer_host,'news.example.org');
  assert.deepEqual(Object.keys(lead).sort(),['id','email','email_verified','workflow','source','entry_point','consent','consent_version','created_at','expires_at'].sort());
  const raw=JSON.stringify(f.db.prepare('SELECT * FROM contact_leads').all())+JSON.stringify(f.db.prepare('SELECT * FROM contact_limits').all());
  for(const excluded of ['192.0.2.9',FORM.turnstile_token,f.env.CONTROLLER_SECRET,f.env.LEAD_ADMIN_SECRET])assert.ok(!raw.includes(excluded));
  const ip=f.db.prepare('SELECT ip_key FROM contact_limits').get().ip_key;
  assert.equal(ip,createHmac('sha256',f.env.CONTROLLER_SECRET).update('lead-ip-v1:192.0.2.9').digest('hex'));
});

test('concurrent case-insensitive duplicates are indistinguishable and preserve original retention',async t=>{
  const f=fixture(t);const replies=await Promise.all(Array.from({length:5},(_,index)=>f.contact({ip:'192.0.2.'+(index+1),body:{...FORM,email:index%2?'PILOT@example.org':FORM.email}})));
  for(const response of replies){assert.equal(response.status,202);assert.deepEqual(await response.json(),{accepted:true});}
  assert.equal(f.count(),1);const first=(await (await f.admin('list')).json()).leads[0];
  f.now+=3_600_001;await f.contact({body:{...FORM,workflow:'A different workflow on a duplicate submission'}});
  const second=(await (await f.admin('list')).json()).leads;assert.equal(second.length,2);assert.deepEqual(second.find(lead=>lead.id===first.id),first);assert.notEqual(second[0].workflow,first.workflow);
});

test('strict consent/body/source validation rejects before bot or storage and never echoes submission',async t=>{
  const f=fixture(t);
  const invalid=[{...FORM,consent:false},{...FORM,consent:'true'},{...FORM,consent_version:'attacker'},{...FORM,email:'bad@@example.org'}, {...FORM,email:'a'.repeat(255)+'@example.org'}, {...FORM,email:'.bad@example.org'}, {...FORM,email:'a@-bad.example'}, {...FORM,workflow:'too short'}, {...FORM,workflow:'x'.repeat(1001)}, {...FORM,workflow:'private\u0001line'}, {...FORM,workflow:'private\u200btext'}, {...FORM,workflow:'private\ud800text'}, {...FORM,source:{url:'https://example.org/private?email=secret'}}, {...FORM,source:{referrer_host:'https://example.org/private'}}, {...FORM,source:{referrer_host:'192.0.2.9'}}, {...FORM,source:{utm_source:'bad space'}}, {...FORM,source:{utm_source:'a'.repeat(65)}}, {...FORM,source:[]}, {...FORM,entry_point:'secret_session_id'}, {...FORM,turnstile_token:''}];
  for(const body of invalid){const response=await f.contact({body});assert.equal(response.status,400,JSON.stringify(body));const text=await response.text();assert.ok(!text.includes('example.org'));assert.ok(!text.includes('private'));}
  for(const raw of ['{','[]','null'])assert.equal((await f.contact({raw})).status,400);
  assert.equal((await f.contact({raw:'x'.repeat(8193)})).status,413);assert.equal(f.network.length,0);assert.equal(f.count(),0);
  const unicode={...FORM,workflow:'界'.repeat(1000)};assert.equal((await f.contact({body:unicode})).status,202);
  assert.equal((await f.contact({ip:'192.0.2.10',body:{...FORM,email:'other@example.org',workflow:'Need review for https://example.org/workflow\r\nFor operations\tand engineering'}})).status,202);
});

test('same-origin, action-bound bot proof and missing network identity fail without queue effects',async t=>{
  const f=fixture(t);
  for(const origin of [null,'https://foreign.example'])assert.equal((await f.contact({origin})).status,403);
  assert.equal(f.network.length,0);
  for(const bot of [{success:false,action:'demo_contact',hostname:'demo.example'},{success:true,action:'demo_join',hostname:'demo.example'},{success:true,action:'demo_contact',hostname:'foreign.example'}]){f.bot=bot;assert.equal((await f.contact()).status,403);}
  f.bot={success:true,action:'demo_contact',hostname:'demo.example'};assert.equal((await f.contact({ip:null})).status,403);
  assert.equal((await f.send('/demo/api/contact',{method:'GET'})).status,405);assert.equal(f.count(),0);assert.equal(f.schedulerCalls,0);
});

test('contact availability is independent of admissions and fails honestly for missing custody configuration',async t=>{
  const f=fixture(t);let config=await (await f.send('/demo/api/config',{method:'GET'})).json();assert.equal(config.available,false);assert.equal(config.contact_available,true);
  for(const key of ['LEAD_INBOX','LEAD_ADMIN_SECRET','CONTROLLER_SECRET','TURNSTILE_SECRET','TURNSTILE_SITE_KEY']){
    const saved=f.env[key];delete f.env[key];config=await (await f.send('/demo/api/config',{method:'GET'})).json();assert.equal(config.contact_available,false,key);assert.equal((await f.contact()).status,503,key);f.env[key]=saved;
  }
  f.env.LEAD_ADMIN_SECRET=f.env.CONTROLLER_SECRET;assert.equal((await f.contact()).status,503);assert.equal(f.count(),0);
});

test('admin secret is isolated from controller and visitor authority, with bounded pagination',async t=>{
  const f=fixture(t);
  for(let i=0;i<5;i++){assert.equal((await f.contact({ip:'192.0.2.'+(i+1),body:{...FORM,email:`pilot${i}@example.org`}})).status,202);f.now++;}
  for(const secret of ['',f.env.CONTROLLER_SECRET,'invalid']){
    const response=await f.admin('list',{},secret);assert.equal(response.status,401);assert.ok(!(await response.text()).includes('@'));
    assert.equal((await f.admin('delete',{id:crypto.randomUUID()},secret)).status,401);
  }
  assert.equal((await f.send('/internal/work',{method:'GET',headers:{Authorization:'Bearer '+f.env.LEAD_ADMIN_SECRET}})).status,401);assert.equal(f.schedulerCalls,0);
  for(const body of [{limit:null},{limit:0},{limit:101},{limit:1.2},{cursor:'-1'},{cursor:'9999999999999999'},{cursor:'bad'},{extra:true}])assert.equal((await f.admin('list',body)).status,400);
  const first=await (await f.admin('list',{limit:2})).json();assert.equal(first.leads.length,2);assert.ok(first.next_cursor);
  assert.equal((await f.contact({ip:'192.0.2.42',body:{...FORM,email:'late@example.org'}})).status,202);
  const next=await (await f.admin('list',{limit:2,cursor:first.next_cursor})).json(),last=await (await f.admin('list',{limit:2,cursor:next.next_cursor})).json();
  const ids=[...first.leads,...next.leads,...last.leads].map(row=>row.id);assert.equal(ids.length,5);assert.equal(new Set(ids).size,5);assert.equal(last.next_cursor,null);
});

test('rate limits persist across restart, charge duplicates and expire independently',async t=>{
  const f=fixture(t);for(let i=0;i<5;i++)assert.equal((await f.contact()).status,202);f.restart();
  const limited=await f.contact();assert.equal(limited.status,429);assert.deepEqual(await limited.json(),{error:'contact_rate_limited',message:'contact rate limited'});
  assert.equal(f.count(),1);assert.equal(f.db.prepare('SELECT count FROM contact_limits').get().count,5);
  f.now=f.storage.alarm;f.storage.alarm=null;await f.leads.alarm();assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM contact_limits').get().n,0);
  assert.equal((await f.contact()).status,202);
});

test('deletion is idempotent and expiration alarms erase leads without an administrator read',async t=>{
  const f=fixture(t);await f.contact();let lead=(await (await f.admin('list')).json()).leads[0];
  assert.equal((await f.admin('delete',{id:'bad'})).status,400);assert.equal((await f.admin('delete',{id:lead.id,extra:'value'})).status,400);
  for(let i=0;i<2;i++)assert.deepEqual(await (await f.admin('delete',{id:lead.id})).json(),{deleted:true});assert.equal(f.count(),0);
  await f.contact();f.restart();const expires=f.db.prepare('SELECT expires_at FROM contact_leads').get().expires_at;
  f.now=f.storage.alarm;f.storage.alarm=null;await f.leads.alarm();assert.equal(f.storage.alarm,expires);
  f.now=expires;f.storage.alarm=null;await f.leads.alarm();assert.equal(f.count(),0);assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM contact_limits').get().n,0);assert.equal(f.storage.alarm,null);
});

test('storage rollback and failed cleanup alarm cannot produce an accepted response',async t=>{
  const f=fixture(t),setAlarm=f.storage.setAlarm;
  f.storage.setAlarm=async()=>{throw new Error('private PII storage diagnostic');};const alarmFailure=await f.contact();assert.equal(alarmFailure.status,503);assert.ok(!(await alarmFailure.text()).includes('private'));assert.equal(f.count(),0);
  f.storage.setAlarm=setAlarm;f.db.exec("CREATE TRIGGER fail_save BEFORE INSERT ON contact_leads BEGIN SELECT RAISE(ABORT,'private database diagnostic'); END;");
  const failure=await f.contact();assert.equal(failure.status,503);assert.ok(!(await failure.text()).includes('private'));assert.equal(f.count(),0);assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM contact_limits').get().n,0);
  f.db.exec('DROP TRIGGER fail_save');assert.equal((await f.contact()).status,202);
});

test('landing accepts only bounded campaign slugs and does not forward attribution to assets or other routes',async t=>{
  const f=fixture(t);assert.equal((await f.send('/?utm_source=release.v1&utm_medium=site&utm_campaign=pilot~1',{method:'GET'})).status,200);assert.equal(f.assetRequests.at(-1),'https://demo.example/index.html');
  for(const path of ['/?email=private@example.org','/?utm_source=a&utm_source=b','/?utm_source=bad%20value','/?utm_source='+('a'.repeat(65)),'/workspace?utm_source=ok','/demo/api/config?utm_source=ok','/internal/leads/list?limit=1'])assert.equal((await f.send(path,{method:'GET'})).status,400,path);
});

test('exact submission dedupe normalizes newlines while changed workflows create distinct retained requests',async t=>{
  const f=fixture(t);const base={...FORM,workflow:'Review the build\r\n\tThen publish the release'};
  assert.equal((await f.contact({body:base})).status,202);
  assert.equal((await f.contact({body:{...base,workflow:'  Review the build\n\tThen publish the release  ',source:{utm_source:'later'}}})).status,202);
  assert.equal(f.count(),1);
  const first=(await (await f.admin('list')).json()).leads[0];assert.equal(first.workflow,'Review the build\n\tThen publish the release');assert.equal(first.source.utm_source,FORM.source.utm_source);
  assert.equal((await f.contact({body:{...base,workflow:'A second pilot workflow for production'}})).status,202);assert.equal(f.count(),2);
});

test('global inbox and live IP caps are bounded, fail visibly and do not disclose an existing email',async t=>{
  const f=fixture(t);await f.contact();
  const template=f.db.prepare('SELECT * FROM contact_leads').get();
  f.storage.transactionSync(()=>{const insert=f.db.prepare('INSERT INTO contact_leads(id,submission_key,email,workflow,source,entry_point,consent_version,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)');for(let i=1;i<LEAD_LIMITS.entries;i++)insert.run(crypto.randomUUID(),String(i),template.email,template.workflow,template.source,template.entry_point,template.consent_version,template.created_at,template.expires_at);});
  for(const email of [FORM.email,'brand-new@example.org']){const response=await f.contact({body:{...FORM,email}});assert.equal(response.status,503);assert.equal((await response.json()).error,'contact_inbox_full');}
  assert.equal(f.count(),LEAD_LIMITS.entries);
  f.db.exec('DELETE FROM contact_leads; DELETE FROM contact_limits');
  f.storage.transactionSync(()=>{const insert=f.db.prepare('INSERT INTO contact_limits(ip_key,window,count,expires_at) VALUES(?,?,1,?)');for(let i=0;i<LEAD_LIMITS.ipBuckets;i++)insert.run(String(i),Math.floor(f.now/3_600_000),(Math.floor(f.now/3_600_000)+1)*3_600_000);});
  const response=await f.contact();assert.equal(response.status,429);assert.equal(f.count(),0);assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM contact_limits').get().n,LEAD_LIMITS.ipBuckets);
  f.now+=3_600_000;f.storage.alarm=null;await f.leads.alarm();assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM contact_limits').get().n,0);assert.equal((await f.contact()).status,202);
});

test('bot transport failure returns a fixed unavailable response without logging submitted data',async t=>{
  const f=fixture(t);const logs=[];t.mock.method(console,'error',(...args)=>logs.push(args));
  t.mock.method(globalThis,'fetch',async()=>{throw new Error('secret diagnostic '+FORM.email);});
  const response=await f.contact();assert.equal(response.status,503);assert.equal((await response.json()).error,'bot_verification_unavailable');assert.equal(f.count(),0);assert.deepEqual(logs,[['bot_verification_transport_failed']]);
});


test('invalid operator keys do not advertise contact availability or grant administrator access',async t=>{
  const f=fixture(t);
  for(const secret of ['short','x'.repeat(1025),'x'.repeat(31)+' ','x'.repeat(32)+'界','x'.repeat(32)+'\n']) {
    f.env.LEAD_ADMIN_SECRET=secret;
    const config=await (await f.send('/demo/api/config',{method:'GET'})).json();assert.equal(config.contact_available,false);
    assert.equal((await f.contact()).status,503);
    // Headers cannot contain newlines; all invalid settings still deny any
    // well-formed claimed key rather than weakening the administration gate.
    assert.equal((await f.admin('list',{},'a'.repeat(64))).status,401);
  }
  assert.equal(f.count(),0);
});
