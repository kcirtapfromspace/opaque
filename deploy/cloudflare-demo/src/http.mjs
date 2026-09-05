import { modelConfiguration, requireEnabledModel, sessionModel } from './models.mjs';

const COOKIE = '__Host-opaque_demo';
const LOCAL_COOKIE = 'opaque_demo_local';
const ID = /^[a-f0-9]{64}$/;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PUBLIC_PATHS = new Map([['/workspace','workspace'],['/api/session','api/session'],['/api/chat','api/chat'],['/api/organization/activity','api/organization/activity'],['/api/demo/persona','api/demo/persona'],['/api/organization/sharing','api/organization/sharing']]);
const CONTROL_PATHS = new Set(['api/demo/persona','api/organization/sharing']);
const encoder = new TextEncoder();
const error = (code,status=400) => Response.json({error:code,message:code.replaceAll('_',' ')},{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});

export function localMode(env) {
  try { return env.LOCAL_TEST_MODE === 'enabled' && new URL(env.PUBLIC_ORIGIN).hostname === '127.0.0.1' && new URL(env.PUBLIC_ORIGIN).protocol === 'http:'; }
  catch { return false; }
}
function configured(env) {
  return env.DEMO_ENABLED === 'true' && !!env.CONTROLLER_ORIGIN && !!env.CONTROLLER_SECRET && !!env.TURNSTILE_SITE_KEY && !!env.TURNSTILE_SECRET
    && (localMode(env) || (!env.TURNSTILE_SITE_KEY.startsWith('1x000000') && !env.TURNSTILE_SECRET.startsWith('1x000000')));
}
function cookieName(env) { return localMode(env) ? LOCAL_COOKIE : COOKIE; }
export async function visitor(request,env) {
  const matches = (request.headers.get('Cookie') || '').split(';').map(x=>x.trim()).filter(x=>x.startsWith(cookieName(env)+'='));
  if (matches.length !== 1) return null;
  const value = matches[0].slice(cookieName(env).length+1);
  const pieces = value.split('.');
  if (pieces.length !== 2 || !pieces.every(piece=>ID.test(piece)) || typeof env.CONTROLLER_SECRET !== 'string' || !env.CONTROLLER_SECRET) return null;
  const key = await crypto.subtle.importKey('raw',encoder.encode(env.CONTROLLER_SECRET),{name:'HMAC',hash:'SHA-256'},false,['verify']);
  const signature = Uint8Array.from(pieces[1].match(/../g), pair=>Number.parseInt(pair,16));
  return await crypto.subtle.verify('HMAC',key,signature,encoder.encode('visitor-v1:'+pieces[0])) ? pieces[0] : null;
}
async function signedVisitor(value,secret) {
  const key=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const mac=await crypto.subtle.sign('HMAC',key,encoder.encode('visitor-v1:'+value));
  return value+'.'+[...new Uint8Array(mac)].map(byte=>byte.toString(16).padStart(2,'0')).join('');
}
async function digest(value) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function token() { return [...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,'0')).join(''); }
async function ipBinding(ip,secret) {
  const key=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(ip)))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function sameOrigin(request,env) { return request.headers.get('Origin') === env.PUBLIC_ORIGIN; }
async function boundedJSON(request,limit) {
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) throw new Error('json_required');
  if (Number(request.headers.get('Content-Length') || 0)>limit) throw new Error('request_too_large');
  const reader=request.body?.getReader();
  if (!reader) throw new Error('body_required');
  let size=0; const chunks=[];
  while(true) { const {done,value}=await reader.read(); if(done)break; size+=value.length; if(size>limit) {await reader.cancel();throw new Error('request_too_large');} chunks.push(value); }
  const bytes=new Uint8Array(size); let offset=0; for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('object_required');
  return value;
}
async function schedule(env,action,...args) {
  const stub=env.DEMO_SCHEDULER.get(env.DEMO_SCHEDULER.idFromName('global-capacity-v1'));
  const response=await stub.fetch('https://scheduler.invalid/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,args})});
  const data=await response.json();
  if(!response.ok)throw Object.assign(new Error(data.error),{status:response.status,code:data.error});
  return data;
}
function view(value) {
  return {state:value.state,position:value.queue_position,expires_at:value.expires_at,session_seconds:600,workspace_url:value.state==='ready'?'/workspace':null,questions_remaining:value.questions_remaining,chat_busy:value.chat_busy,model:sessionModel(value.model_id)};
}
export async function verifyBot(request,env,value) {
  if(localMode(env) && value==='local-demo-test-only')return true;
  if(typeof value!=='string'||!value||value.length>2048)return false;
  const body=new URLSearchParams({secret:env.TURNSTILE_SECRET,response:value,idempotency_key:crypto.randomUUID()});
  const ip=request.headers.get('CF-Connecting-IP'); if(ip)body.set('remoteip',ip);
  let response;
  const botAbort=new AbortController();
  const botTimeout=setTimeout(()=>botAbort.abort(),10_000);
  try {
    response=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',body,redirect:'manual',signal:botAbort.signal});
  } catch(cause) {
    console.error('bot_verification_transport_failed',cause.name,String(cause.message).slice(0,200));
    throw Object.assign(new Error('bot_verification_unavailable'),{code:'bot_verification_unavailable',status:503});
  } finally {
    clearTimeout(botTimeout);
  }
  if(!response.ok)return false;
  const result=await response.json();
  return result.success===true&&result.action==='demo_join'&&result.hostname===new URL(env.PUBLIC_ORIGIN).hostname;
}
async function htmlResponse(response,env) {
  const html=await response.text();
  const hashes=[];
  for(const [,body] of html.matchAll(/<script>([\s\S]*?)<\/script>/g)){
    const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(body)));
    hashes.push("'sha256-"+btoa(String.fromCharCode(...bytes))+"'");
  }
  return new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':`default-src 'none'; script-src ${hashes.join(' ')} https://challenges.cloudflare.com; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`}});
}
async function authenticatedProxy(request,env,ctx,path,visitorHash) {
  if(!env.CONTROLLER_ORIGIN||!env.CONTROLLER_SECRET)return error('demo_backend_unavailable',503);
  const method=request.method;
  const writes=path==='api/chat'||CONTROL_PATHS.has(path);
  if(method!==(writes?'POST':'GET'))return error('method_not_allowed',405);
  if(method==='POST'&&!sameOrigin(request,env))return error('same_origin_required',403);
  let body, reservation, lease;
  if(path==='api/chat') {
    const requestId=request.headers.get('Idempotency-Key') ?? crypto.randomUUID();
    if(!REQUEST_ID.test(requestId))return error('invalid_idempotency_key');
    const input=await boundedJSON(request,4096);
    if(Object.keys(input).length!==1||typeof input.message!=='string'||!input.message.trim()||encoder.encode(input.message).length>2000)return error('bounded_question_required');
    body=JSON.stringify(input);
    reservation=await schedule(env,'reserveChat',visitorHash,requestId);
    if(!reservation.dispatch)return error('chat_already_dispatched',409);
    lease=reservation.lease;
  } else {
    if(CONTROL_PATHS.has(path)) {
      const input=await boundedJSON(request,2048);
      const keys=Object.keys(input).sort().join(',');
      if(path==='api/demo/persona') {
        if(!['customer_analyst','engineer','support'].includes(input.persona_id))return error('invalid_demo_persona');
        if(input.persona_id==='support') {
          if(keys!=='persona_id,reason'||typeof input.reason!=='string'||input.reason.trim().length<8||encoder.encode(input.reason).length>240||/[\u0000-\u001f\u007f]/.test(input.reason))return error('bounded_support_reason_required');
        } else if(keys!=='persona_id')return error('invalid_demo_persona');
      } else if(keys!=='enabled'||typeof input.enabled!=='boolean')return error('invalid_question_sharing');
      body=JSON.stringify(input);
    }
    lease=await schedule(env,'authorize',visitorHash);
  }
  const destination=new URL(env.CONTROLLER_ORIGIN);
  if(!env.DEMO_ORIGIN&&destination.protocol!=='https:'&&!(localMode(env)&&destination.hostname==='127.0.0.1'))return error('controller_transport_invalid',503);
  destination.pathname=`/sessions/${lease.lease_id}/proxy/${path}`;
  destination.search='';
  const upstream=await (env.DEMO_ORIGIN ? env.DEMO_ORIGIN.fetch.bind(env.DEMO_ORIGIN) : fetch)(destination,{method,body,headers:{'Authorization':'Bearer '+env.CONTROLLER_SECRET,'X-Opaque-Lease-Generation':String(lease.generation),'X-Opaque-Lease-Expires-At':String(lease.expires_at),'Content-Type':'application/json','Accept':path==='api/chat'?'text/event-stream':'text/html, application/json'},redirect:'manual',signal:AbortSignal.timeout(65_000)});
  if(upstream.status>=300&&upstream.status<400)return error('controller_redirect_rejected',502);
  const headers=new Headers({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});
  if(reservation)headers.set('Idempotency-Key',reservation.reservation.request_id);
  for(const name of ['Content-Type','Content-Security-Policy'])if(upstream.headers.has(name))headers.set(name,upstream.headers.get(name));
  if((path==='api/session'||path==='api/organization/activity'||CONTROL_PATHS.has(path)) && upstream.ok) {
    const session=await upstream.json();
    if(path!=='api/organization/activity') {
      session.expires_at=new Date(lease.expires_at).toISOString();
      session.demo={expires_at:lease.expires_at,return_url:'/',synthetic:true};
      session.model=sessionModel(lease.model_id);
    }
    if(session.organization?.support_case && Number.isFinite(session.organization.support_case.expires_at)) {
      session.organization.support_case.expires_at=Math.min(session.organization.support_case.expires_at,Math.floor(lease.expires_at/1000));
    }
    return Response.json(session,{status:upstream.status,headers});
  }
  if(path==='workspace' && upstream.ok) {
    const html=await upstream.text();
    const banner='<div style="padding:12px 28px;background:#22291c;border-bottom:1px solid #455033;font:13px sans-serif;color:#dce8c7"><a href="/" style="color:inherit">← Demo session and queue</a> · Synthetic data · 12 questions maximum · Session ends '+new Date(lease.expires_at).toISOString().replace('T',' ').replace('.000Z',' UTC')+'</div>';
    return new Response(html.replace('<body>','<body>'+banner).replace('href="/auth/login"','href="/"'),{status:upstream.status,headers});
  }
  if(path!=='api/chat')return new Response(upstream.body,{status:upstream.status,headers});
  if(!upstream.ok) {
    // A controller rejection is not proof that an uncertain execution stopped.
    // Retain the charged reservation; cleanup must reconcile its execution.
    return error('demo_chat_unavailable',upstream.status>=400&&upstream.status<600?upstream.status:502);
  }
  if(!upstream.body)return error('demo_response_missing',502);
  const reader=upstream.body.getReader();
  let detached=false,ended=false,released=false,draining=false,total=0,tail='';
  let pending=Promise.resolve();
  const decoder=new TextDecoder();
  const release=()=>{if(!released){released=true;reader.releaseLock();}};
  const read=async()=>{
    try {
      const next=await reader.read();
      if(next.done) {
        ended=true;
        tail=(tail+decoder.decode()).slice(-4096);
        // A clean transport close alone is insufficient. Only the controller
        // adds the completion event after confirming runtime/model quiescence.
        if(/(?:^|[\r\n])event:\s*done[\r\n]/.test(tail)&&/(?:^|[\r\n])event:\s*opaque_execution_complete[\r\n]/.test(tail))
          await schedule(env,'finishChat',reservation.reservation.request_id,reservation.reservation.generation);
        release();
        return next;
      }
      total+=next.value.byteLength;
      if(total>262144) {
        ended=true;
        await reader.cancel('demo_response_too_large').catch(()=>{});
        throw new Error('demo_response_too_large');
      }
      tail=(tail+decoder.decode(next.value,{stream:true})).slice(-4096);
      return next;
    } catch(cause) {
      ended=true;
      release();
      throw cause;
    }
  };
  const detachAndDrain=()=>{
    detached=true;
    if(draining)return;
    draining=true;
    // A cancel may race an outstanding pull. Wait for that read to settle,
    // then drain serially; never issue competing reads or retry the request.
    const current=pending;
    const drain=(async()=>{
      await current.catch(()=>{});
      try { while(!ended)await read(); }
      catch { /* An uncertain stream remains charged for controller cleanup. */ }
      finally { release(); }
    })();
    ctx.waitUntil(drain);
  };
  const stream=new ReadableStream({
    pull(controller) {
      pending=(async()=>{
        try {
          const next=await read();
          if(detached)return;
          if(next.done){controller.close();return;}
          // No read is prefetched while unpolled. Check authority after the
          // upstream read and immediately before this consumer receives data.
          const current=await schedule(env,'authorize',visitorHash);
          if(detached)return;
          if(current.lease_id!==lease.lease_id||current.tenant_id!==lease.tenant_id||current.generation!==lease.generation||current.model_id!==lease.model_id
            ||Date.now()>=lease.expires_at||Date.now()>=current.expires_at)throw new Error('demo_expired');
          controller.enqueue(next.value);
        } catch {
          if(!detached)controller.error(new Error('demo_stream_interrupted'));
          detachAndDrain();
        }
      })();
      return pending;
    },
    cancel() { detachAndDrain(); },
  },{highWaterMark:0});
  return new Response(stream,{status:upstream.status,headers});
}

export async function handleRequest(request,env,ctx) {
  try {
    const url=new URL(request.url);
    if(url.origin!==env.PUBLIC_ORIGIN)return error('unexpected_demo_origin',421);
    if(url.search)return error('query_parameters_not_supported');
    const path=url.pathname;
    if(path.startsWith('/internal/')) {
      if(request.headers.get('Authorization')!=='Bearer '+env.CONTROLLER_SECRET||!env.CONTROLLER_SECRET)return error('controller_authority_required',401);
      if(path==='/internal/work'&&request.method==='GET')return Response.json(await schedule(env,'work'),{headers:{'Cache-Control':'no-store'}});
      if(path==='/internal/report'&&request.method==='POST')return Response.json(await schedule(env,'report',await boundedJSON(request,2048)),{headers:{'Cache-Control':'no-store'}});
      return error('not_found',404);
    }
    if(path==='/'&&request.method==='GET')return htmlResponse(await env.ASSETS.fetch(new Request(url.origin+'/index.html')),env);
    if(path==='/demo/api/config'&&request.method==='GET')return Response.json({turnstile_site_key:env.TURNSTILE_SITE_KEY||null,session_seconds:600,available:configured(env),...modelConfiguration(env)},{headers:{'Cache-Control':'no-store'}});
    const capability=await visitor(request,env);
    const hash=capability?await digest(capability):null;
    if(path==='/demo/api/session'&&request.method==='GET') {
      if(!hash)return Response.json({state:'none',session_seconds:600},{headers:{'Cache-Control':'no-store'}});
      try{return Response.json(view(await schedule(env,'status',hash)),{headers:{'Cache-Control':'no-store'}});}
      catch(e){if(e.status===404)return Response.json({state:'none',session_seconds:600},{headers:{'Cache-Control':'no-store'}});throw e;}
    }
    if(path==='/demo/api/join'&&request.method==='POST') {
      if(!sameOrigin(request,env))return error('same_origin_required',403);
      if(!configured(env))return error('demo_admissions_paused',503);
      const value=await boundedJSON(request,4096);
      if(typeof value.model_id!=='string')return error('model_selection_required');
      if(Object.keys(value).length!==2||typeof value.turnstile_token!=='string')return error('invalid_join_request');
      const modelId=requireEnabledModel(value.model_id,env);
      if(hash)try{
        const current=await schedule(env,'status',hash);
        if(!['expired','failed','cancelled'].includes(current.state)){
          if(current.model_id!==modelId)return error('model_selection_immutable',409);
          return Response.json(view(current),{headers:{'Cache-Control':'no-store'}});
        }
      }catch(e){if(e.status!==404)throw e;}
      if(!await verifyBot(request,env,value.turnstile_token))return error('bot_verification_failed',403);
      const ip=request.headers.get('CF-Connecting-IP')||(localMode(env)?'local':'');
      if(!ip)return error('visitor_network_binding_required',403);
      const fresh=token();
      const result=await schedule(env,'admit',await digest(fresh),await ipBinding(ip,env.CONTROLLER_SECRET),modelId);
      const signed=await signedVisitor(fresh,env.CONTROLLER_SECRET);
      return Response.json(view(result),{headers:{'Cache-Control':'no-store','Set-Cookie':`${cookieName(env)}=${signed}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400${localMode(env)?'':'; Secure'}`}});
    }
    if(path==='/demo/api/cancel'&&request.method==='POST') {
      if(!sameOrigin(request,env))return error('same_origin_required',403);
      if(!hash)return error('demo_session_required',401);
      if(Object.keys(await boundedJSON(request,128)).length)return error('empty_request_required');
      return Response.json(view(await schedule(env,'cancel',hash)),{headers:{'Cache-Control':'no-store'}});
    }
    if(PUBLIC_PATHS.has(path)) {
      if(!hash)return error('demo_session_required',401);
      return await authenticatedProxy(request,env,ctx,PUBLIC_PATHS.get(path),hash);
    }
    return error('not_found',404);
  } catch(e) { return error(e.code||(['json_required','request_too_large','body_required','object_required'].includes(e.message)?e.message:'demo_request_failed'),e.status||502); }
}
