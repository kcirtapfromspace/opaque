// Optional contact custody. This object never receives demo session state or
// invokes the scheduler/controller. Only consented form fields cross its API.
const encoder = new TextEncoder();
const DAY = 86_400_000;
const HOUR = 3_600_000;
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SLUG = /^[A-Za-z0-9._~-]{1,64}$/;
const SOURCE_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'referrer_host'];
export const LEAD_LIMITS = Object.freeze({retentionMs:90*DAY, ipWindowMs:HOUR, perIp:5, ipBuckets:4096, entries:10000, page:100});
export const LEAD_CONSENT_VERSION = 'demo-pilot-contact-v1';

export class LeadError extends Error {
  constructor(code, status=400) { super(code); this.code=code; this.status=status; }
}
function reject(code='invalid_contact_request', status=400) { throw new LeadError(code,status); }
function object(value) { return value!==null && typeof value==='object' && !Array.isArray(value); }
function exact(value, keys) { return object(value) && Object.keys(value).sort().join(',')===[...keys].sort().join(','); }
export function landingAttributionAllowed(search) {
  if(search.length>512)return false;
  const parameters=new URLSearchParams(search), seen=new Set();
  for(const [name,value] of parameters) {
    if(!SOURCE_KEYS.slice(0,3).includes(name)||seen.has(name)||!SLUG.test(value))return false;
    seen.add(name);
  }
  return true;
}
function sourceFields(source) {
  if(!object(source)||Object.keys(source).some(name=>!SOURCE_KEYS.includes(name)))reject();
  const result={};
  for(const key of Object.keys(source)) {
    const value=source[key];
    if(typeof value!=='string')reject();
    if(key==='referrer_host') {
      // A bare DNS name only: never paths, query strings, credentials, ports,
      // IP addresses, or the full browser Referer header.
      if(value.length>253||!value.includes('.')||!value.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))||!/[a-z]/i.test(value.split('.').at(-1)))reject();
      result[key]=value.toLowerCase();
    } else {
      if(!SLUG.test(value))reject();
      result[key]=value;
    }
  }
  return result;
}
export function validateContact(input) {
  if(!exact(input,['email','workflow','consent','source','entry_point','turnstile_token']))reject();
  if(input.consent!==true)reject('contact_consent_required');
  if(typeof input.email!=='string'||input.email.length>254||!/^[-A-Za-z0-9.!#$%&'*+/=?^_`{|}~]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(input.email))reject();
  const [local,domain]=input.email.split('@');
  if(local.length>64||local.startsWith('.')||local.endsWith('.')||local.includes('..')||!domain.includes('.')||!domain.split('.').every(label=>/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)))reject();
  if(typeof input.workflow!=='string'||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\p{Cf}\p{Cs}]/u.test(input.workflow))reject();
  const workflow=input.workflow.replace(/\r\n?/g,'\n').trim(), length=[...workflow].length;
  if(encoder.encode(workflow).length>4000)reject();
  if(length<10||length>1000)reject();
  if(!['landing','workspace_result'].includes(input.entry_point))reject();
  if(typeof input.turnstile_token!=='string'||!input.turnstile_token||input.turnstile_token.length>2048||/[\p{Cc}\p{Cf}]/u.test(input.turnstile_token))reject();
  return {email:input.email.toLowerCase(),workflow,source:sourceFields(input.source),entry_point:input.entry_point};
}
export function validateLeadList(input) {
  if(!object(input)||Object.keys(input).some(key=>!['limit','cursor'].includes(key)))reject('invalid_lead_list');
  const limit=input.limit===undefined?25:input.limit;
  if(!Number.isInteger(limit)||limit<1||limit>LEAD_LIMITS.page)reject('invalid_lead_list');
  const cursor=input.cursor;
  if(cursor!==undefined&&(typeof cursor!=='string'||! /^[1-9][0-9]{0,15}$/.test(cursor)||!Number.isSafeInteger(Number(cursor))))reject('invalid_lead_list');
  return {limit,cursor:cursor===undefined?null:Number(cursor)};
}
export function validateLeadDelete(input) {
  if(!exact(input,['id'])||typeof input.id!=='string'||!UUID.test(input.id))reject('invalid_lead_id');
  return input.id;
}
function adminSecretConfigured(env) {
  return typeof env.LEAD_ADMIN_SECRET==='string' && /^[\x21-\x7e]{32,1024}$/.test(env.LEAD_ADMIN_SECRET)
    && env.LEAD_ADMIN_SECRET!==env.CONTROLLER_SECRET;
}
export function contactConfigured(env, local=false) {
  return !!env.LEAD_INBOX && typeof env.CONTROLLER_SECRET==='string' && !!env.CONTROLLER_SECRET
    && adminSecretConfigured(env)
    && typeof env.TURNSTILE_SITE_KEY==='string' && !!env.TURNSTILE_SITE_KEY
    && typeof env.TURNSTILE_SECRET==='string' && !!env.TURNSTILE_SECRET
    && (local||(!env.TURNSTILE_SITE_KEY.startsWith('1x000000')&&!env.TURNSTILE_SECRET.startsWith('1x000000')));
}
export async function leadAdminAuthorized(request,env) {
  if(!adminSecretConfigured(env))return false;
  const supplied=request.headers.get('Authorization')||'';
  if(supplied.length>2048)return false;
  const [left,right]=await Promise.all([supplied,'Bearer '+env.LEAD_ADMIN_SECRET].map(value=>crypto.subtle.digest('SHA-256',encoder.encode(value))));
  let difference=0; const a=new Uint8Array(left), b=new Uint8Array(right);
  for(let i=0;i<a.length;i++)difference|=a[i]^b[i];
  return difference===0;
}
export async function leadBinding(value,secret,purpose) {
  const key=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const signature=await crypto.subtle.sign('HMAC',key,encoder.encode(`lead-${purpose}-v1:${value}`));
  return [...new Uint8Array(signature)].map(byte=>byte.toString(16).padStart(2,'0')).join('');
}

export class Leads {
  constructor(ctx,env) {
    this.ctx=ctx; this.env=env; this.pending=Promise.resolve();
    const sql=ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS contact_leads (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, submission_key TEXT NOT NULL UNIQUE, email TEXT NOT NULL, workflow TEXT NOT NULL, source TEXT NOT NULL, entry_point TEXT NOT NULL, consent_version TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)');
    sql.exec('CREATE INDEX IF NOT EXISTS contact_leads_expiry ON contact_leads(expires_at)');
    sql.exec('CREATE TABLE IF NOT EXISTS contact_limits (ip_key TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL, expires_at INTEGER NOT NULL)');
    sql.exec('CREATE INDEX IF NOT EXISTS contact_limits_expiry ON contact_limits(expires_at)');
    sql.exec('CREATE TABLE IF NOT EXISTS contact_clock (id INTEGER PRIMARY KEY CHECK(id=1), last_now INTEGER NOT NULL)');
  }
  serialize(operation) { const result=this.pending.then(operation); this.pending=result.catch(()=>{}); return result; }
  rows(query,...args) { return this.ctx.storage.sql.exec(query,...args).toArray(); }
  clock() {
    const now=Math.max(Date.now(),this.rows('SELECT last_now FROM contact_clock WHERE id=1')[0]?.last_now||0);
    if(!Number.isSafeInteger(now)||now<0)throw new LeadError('contact_storage_unavailable',503);
    return now;
  }
  cleanup(now) {
    this.rows('INSERT INTO contact_clock(id,last_now) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last_now=excluded.last_now',now);
    this.rows('DELETE FROM contact_leads WHERE expires_at<=?',now);
    this.rows('DELETE FROM contact_limits WHERE expires_at<=?',now);
  }
  async arm(fallback=null) {
    const lead=this.rows('SELECT MIN(expires_at) AS deadline FROM contact_leads')[0].deadline;
    const rate=this.rows('SELECT MIN(expires_at) AS deadline FROM contact_limits')[0].deadline;
    const deadlines=[lead,rate,fallback].filter(value=>value!==null);
    const desired=deadlines.length?Math.min(...deadlines):null;
    if(await this.ctx.storage.getAlarm()===desired)return;
    if(desired===null)await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(desired);
  }
  async accept(input,ipKey) {
    // Validate again at the custody boundary, before any persistent mutation.
    const lead=validateContact(input);
    if(typeof ipKey!=='string'||!HASH.test(ipKey)||!this.env.CONTROLLER_SECRET)reject();
    const submissionKey=await leadBinding(JSON.stringify([lead.email,lead.workflow,LEAD_CONSENT_VERSION]),this.env.CONTROLLER_SECRET,'submission');
    const now=this.clock(), window=Math.floor(now/HOUR), deadline=(window+1)*HOUR;
    // Establish a durable cleanup alarm before committing any new retained
    // data. A later alarm-update failure never strands a newly written lead.
    await this.arm(deadline);
    this.ctx.storage.transactionSync(()=>{
      this.cleanup(now);
      const rate=this.rows('SELECT count FROM contact_limits WHERE ip_key=? AND window=?',ipKey,window)[0];
      if((rate?.count||0)>=LEAD_LIMITS.perIp)reject('contact_rate_limited',429);
      if(!rate&&this.rows('SELECT COUNT(*) AS n FROM contact_limits')[0].n>=LEAD_LIMITS.ipBuckets)reject('contact_rate_limited',429);
      // Capacity errors do not reveal whether this address already exists.
      if(this.rows('SELECT COUNT(*) AS n FROM contact_leads')[0].n>=LEAD_LIMITS.entries)reject('contact_inbox_full',503);
      this.rows('INSERT INTO contact_limits(ip_key,window,count,expires_at) VALUES(?,?,1,?) ON CONFLICT(ip_key) DO UPDATE SET window=excluded.window,count=count+1,expires_at=excluded.expires_at',ipKey,window,deadline);
      this.rows('INSERT INTO contact_leads(id,submission_key,email,workflow,source,entry_point,consent_version,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(submission_key) DO NOTHING',crypto.randomUUID(),submissionKey,lead.email,lead.workflow,JSON.stringify(lead.source),lead.entry_point,LEAD_CONSENT_VERSION,now,now+LEAD_LIMITS.retentionMs);
    });
    await this.arm();
    return {accepted:true};
  }
  list(input) {
    const {limit,cursor}=validateLeadList(input), now=this.clock();
    return this.ctx.storage.transactionSync(()=>{
      this.cleanup(now);
      const rows=cursor===null
        ?this.rows('SELECT * FROM contact_leads ORDER BY seq DESC LIMIT ?',limit+1)
        :this.rows('SELECT * FROM contact_leads WHERE seq<? ORDER BY seq DESC LIMIT ?',cursor,limit+1);
      const hasMore=rows.length>limit, page=rows.slice(0,limit);
      return {leads:page.map(row=>({id:row.id,email:row.email,email_verified:false,workflow:row.workflow,source:JSON.parse(row.source),entry_point:row.entry_point,consent:true,consent_version:row.consent_version,created_at:row.created_at,expires_at:row.expires_at})),next_cursor:hasMore?String(page.at(-1).seq):null};
    });
  }
  remove(input) {
    const id=validateLeadDelete(input),now=this.clock();
    this.ctx.storage.transactionSync(()=>{this.cleanup(now);this.rows('DELETE FROM contact_leads WHERE id=?',id);});
    return {deleted:true};
  }
  fetch(request) { return this.serialize(async()=>{
    try {
      if(request.method!=='POST')reject('method_not_allowed',405);
      const {action,input,ip_key}=await request.json();
      let result;
      if(action==='accept')result=await this.accept(input,ip_key);
      else if(action==='list')result=this.list(input);
      else if(action==='delete')result=this.remove(input);
      else reject('not_found',404);
      if(action!=='accept')await this.arm();
      return Response.json(result,{headers:{'Cache-Control':'no-store'}});
    } catch(error) {
      return Response.json({error:error instanceof LeadError?error.code:'contact_storage_unavailable'},{status:error instanceof LeadError?error.status:503,headers:{'Cache-Control':'no-store'}});
    }
  }); }
  alarm() { return this.serialize(async()=>{
    this.ctx.storage.transactionSync(()=>this.cleanup(this.clock()));
    await this.arm();
  }); }
}
