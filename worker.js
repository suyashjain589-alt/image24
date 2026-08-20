const JSON_HEADERS = {"content-type":"application/json; charset=utf-8","cache-control":"no-store"};
const FREE_LIMIT = 10;
const PRO_LIMIT = 500;
const MAX_FILE_BYTES = 50 * 1024 * 1024;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, ctx, url);
    }
    if (url.pathname === '/health') return json({ ok: true, service: 'IMAGE 24', version: '18.0-production' });
    return withSecurityHeaders(await env.ASSETS.fetch(request));
  }
};

async function handleApi(request, env, ctx, url) {
  const method = request.method.toUpperCase();
  try {
    if (url.pathname === '/api/public-config' && method === 'GET') {
      return json({
        turnstileSiteKey: env.TURNSTILE_SITE_KEY || '',
        paymentProvider: env.RAZORPAY_KEY_ID && env.RAZORPAY_PLAN_ID ? 'razorpay' : 'unconfigured',
        maxFileBytes: MAX_FILE_BYTES
      });
    }
    if (url.pathname === '/api/health' && method === 'GET') {
      return json({
        ok: !!env.DB,
        database: !!env.DB,
        payment: !!(env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET && env.RAZORPAY_PLAN_ID),
        turnstile: !!(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET)
      }, env.DB ? 200 : 503);
    }
    if (url.pathname === '/api/auth/register' && method === 'POST') return register(request, env);
    if (url.pathname === '/api/auth/login' && method === 'POST') return login(request, env);
    if (url.pathname === '/api/auth/logout' && method === 'POST') return logout(request, env);
    if (url.pathname === '/api/auth/me' && method === 'GET') return me(request, env);
    if (url.pathname === '/api/usage' && method === 'GET') return usage(request, env);
    if (url.pathname === '/api/jobs/reserve' && method === 'POST') return reserveJob(request, env);
    if (url.pathname === '/api/jobs/complete' && method === 'POST') return completeJob(request, env);
    if (url.pathname === '/api/history' && method === 'GET') return history(request, env);
    if (url.pathname === '/api/feedback' && method === 'POST') return feedback(request, env);
    if (url.pathname === '/api/billing/checkout' && method === 'POST') return billingCheckout(request, env);
    if (url.pathname === '/api/billing/cancel' && method === 'POST') return billingCancel(request, env);
    if (url.pathname === '/api/billing/webhook' && method === 'POST') return billingWebhook(request, env);
    return json({ error: 'Not found' }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: 'Server error. Please try again.' }, 500);
  }
}

function securityHeaders(){
  return {
    'X-Content-Type-Options':'nosniff',
    'Referrer-Policy':'strict-origin-when-cross-origin',
    'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
    'X-Frame-Options':'DENY',
    'Strict-Transport-Security':'max-age=31536000; includeSubDomains'
  };
}
function withSecurityHeaders(response){
  const headers=new Headers(response.headers);
  for(const [k,v] of Object.entries(securityHeaders())) headers.set(k,v);
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}
function json(data, status=200, extra={}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...securityHeaders(), ...extra } });
}
function htmlSafe(v) { return typeof v === 'string' ? v.trim() : ''; }
function normalizeEmail(v) { return htmlSafe(v).toLowerCase(); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validName(v) { return v.length >= 1 && v.length <= 80; }
function cookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const m = raw.match(new RegExp('(?:^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
function cookieHeader(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function clearCookie(name) { return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`; }
function originAllowed(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return true;
  try {
    const o = new URL(origin), r = new URL(request.url);
    return o.origin === r.origin;
  } catch { return false; }
}
function ip(request) { return request.headers.get('CF-Connecting-IP') || '0.0.0.0'; }
async function digestHex(value) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const b = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function timingSafeEqualHex(a,b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i=0;i<a.length;i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function randomId(bytes=32) {
  const b = new Uint8Array(bytes); crypto.getRandomValues(b);
  return [...b].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function b64url(bytes) {
  let s=''; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'}, key, 256);
  return { salt: saltHex || [...salt].map(x=>x.toString(16).padStart(2,'0')).join(''), hash: [...new Uint8Array(bits)].map(x=>x.toString(16).padStart(2,'0')).join('') };
}
function hexBytes(hex) { const a=new Uint8Array(hex.length/2); for(let i=0;i<a.length;i++) a[i]=parseInt(hex.slice(i*2,i*2+2),16); return a; }
async function ensureDb(env) { if (!env.DB) throw new Error('D1 database binding is not configured'); }
async function subjectHash(request, env, userId='') {
  const pepper = env.AUTH_PEPPER || 'local-dev-only-change-me';
  return digestHex(`${userId ? 'u:'+userId : 'ip:'+ip(request)}:${pepper}`);
}
async function getUser(request, env) {
  await ensureDb(env);
  const token = cookie(request, 'i24_session');
  if (!token) return null;
  const hash = await digestHex(token);
  const row = await env.DB.prepare(`SELECT u.id,u.name,u.email,u.plan,u.subscription_id,u.subscription_status,u.cancel_at_cycle_end,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash, Date.now()).first();
  return row || null;
}
async function rateLimit(request, env, bucket, max, windowMs) {
  await ensureDb(env);
  const key = await digestHex(`${bucket}:${ip(request)}:${env.AUTH_PEPPER || 'dev'}`);
  const now = Date.now();
  const start = Math.floor(now/windowMs)*windowMs;
  await env.DB.prepare(`INSERT OR IGNORE INTO rate_limits (key,bucket,window_start,count) VALUES (?,?,?,0)`).bind(key,bucket,start).run();
  const result = await env.DB.prepare(`UPDATE rate_limits SET count=count+1 WHERE key=? AND window_start=? AND count<?`).bind(key,start,max).run();
  return !!result.meta?.changes;
}

async function register(request, env) {
  if (!originAllowed(request)) return json({error:'Invalid origin'},403);
  if (!(await rateLimit(request, env, 'register', 5, 60*60*1000))) return json({error:'Too many registration attempts. Try again later.'},429);
  const body = await request.json().catch(()=>({}));
  const name=htmlSafe(body.name), email=normalizeEmail(body.email), password=String(body.password||'');
  if (!validName(name) || !validEmail(email) || password.length < 8 || password.length > 128) return json({error:'Enter a valid name, email and password (8–128 characters).'},400);
  const exists=await env.DB.prepare(`SELECT id FROM users WHERE email=?`).bind(email).first();
  if (exists) return json({error:'An account with this email already exists.'},409);
  const id=randomId(16), ph=await hashPassword(password);
  await env.DB.prepare(`INSERT INTO users (id,name,email,password_hash,password_salt,plan,created_at) VALUES (?,?,?,?,?,'free',?)`).bind(id,name,email,ph.hash,ph.salt,Date.now()).run();
  return createSessionResponse(env,id,{id,name,email,plan:'free',subscription_id:null,subscription_status:null,cancel_at_cycle_end:0});
}
async function login(request, env) {
  if (!originAllowed(request)) return json({error:'Invalid origin'},403);
  if (!(await rateLimit(request, env, 'login', 10, 15*60*1000))) return json({error:'Too many login attempts. Try again later.'},429);
  const body=await request.json().catch(()=>({})); const email=normalizeEmail(body.email), password=String(body.password||'');
  const row=await env.DB.prepare(`SELECT * FROM users WHERE email=?`).bind(email).first();
  if (!row) return json({error:'Invalid email or password.'},401);
  const ph=await hashPassword(password,row.password_salt);
  if (!timingSafeEqualHex(ph.hash,row.password_hash)) return json({error:'Invalid email or password.'},401);
  return createSessionResponse(env,row.id,{id:row.id,name:row.name,email:row.email,plan:row.plan,subscription_id:row.subscription_id,subscription_status:row.subscription_status,cancel_at_cycle_end:row.cancel_at_cycle_end});
}
async function createSessionResponse(env,userId,user) {
  const tokenBytes=crypto.getRandomValues(new Uint8Array(32)); const token=b64url(tokenBytes); const tokenHash=await digestHex(token); const now=Date.now();
  await env.DB.prepare(`INSERT INTO sessions (id,user_id,token_hash,created_at,expires_at) VALUES (?,?,?,?,?)`).bind(randomId(16),userId,tokenHash,now,now+30*24*60*60*1000).run();
  return new Response(JSON.stringify({user}),{status:200,headers:{...JSON_HEADERS,'Set-Cookie':cookieHeader('i24_session',token,30*24*60*60)}});
}

async function logout(request, env) {
  if (!originAllowed(request)) return json({error:'Invalid origin'},403);
  const token=cookie(request,'i24_session');
  if (token && env.DB) await env.DB.prepare(`DELETE FROM sessions WHERE token_hash=?`).bind(await digestHex(token)).run();
  return new Response(JSON.stringify({ok:true}),{status:200,headers:{...JSON_HEADERS,'Set-Cookie':clearCookie('i24_session')}});
}
async function me(request, env) { const user=await getUser(request,env); return json({user}); }

async function usage(request, env) {
  const user=await getUser(request,env); const key=await subjectHash(request,env,user?.id||''); const day=utcDay();
  await env.DB.prepare(`INSERT OR IGNORE INTO daily_usage (subject_key,day,count) VALUES (?,?,0)`).bind(key,day).run();
  const row=await env.DB.prepare(`SELECT count FROM daily_usage WHERE subject_key=? AND day=?`).bind(key,day).first();
  const plan=user?.plan==='pro'?'pro':'free', limit=plan==='pro'?PRO_LIMIT:FREE_LIMIT, today=Number(row?.count||0);
  return json({plan,today,limit,remaining:Math.max(0,limit-today),authenticated:!!user});
}
async function reserveJob(request, env) {
  if (!originAllowed(request)) return json({error:'Invalid origin'},403);
  const user=await getUser(request,env); const body=await request.json().catch(()=>({})); const tool=htmlSafe(body.tool);
  if (!/^[a-z0-9_-]{2,40}$/i.test(tool)) return json({error:'Invalid tool.'},400);
  const key=await subjectHash(request,env,user?.id||''); const day=utcDay(); const plan=user?.plan==='pro'?'pro':'free'; const limit=plan==='pro'?PRO_LIMIT:FREE_LIMIT;
  await env.DB.prepare(`INSERT OR IGNORE INTO daily_usage (subject_key,day,count) VALUES (?,?,0)`).bind(key,day).run();
  const result=await env.DB.prepare(`UPDATE daily_usage SET count=count+1 WHERE subject_key=? AND day=? AND count<?`).bind(key,day,limit).run();
  if (!result.meta?.changes) return json({error:`Daily limit reached. ${plan==='pro'?PRO_LIMIT:FREE_LIMIT} jobs/day are included in your ${plan} plan.`,limit,plan},429);
  const jobId=randomId(16);
  await env.DB.prepare(`INSERT INTO jobs (id,user_id,subject_key,tool,status,created_at) VALUES (?,?,?,?,?,?)`).bind(jobId,user?.id||null,key,tool,'started',Date.now()).run();
  return json({ok:true,jobId,plan,limit,remaining:Math.max(0,limit-Number((await env.DB.prepare(`SELECT count FROM daily_usage WHERE subject_key=? AND day=?`).bind(key,day).first())?.count||0))});
}
async function completeJob(request, env) {
  if (!originAllowed(request)) return json({error:'Invalid origin'},403);
  const body=await request.json().catch(()=>({})); const jobId=String(body.jobId||''); const status=body.status==='failed'?'failed':'completed';
  if(!/^[a-f0-9]{32}$/i.test(jobId)) return json({error:'Invalid job id.'},400);
  const user=await getUser(request,env); const key=await subjectHash(request,env,user?.id||'');
  const result=await env.DB.prepare(`UPDATE jobs SET status=? WHERE id=? AND subject_key=?`).bind(status,jobId,key).run();
  if(!result.meta?.changes)return json({error:'Job not found.'},404);
  return json({ok:true,status});
}
async function history(request, env) {
  const user=await getUser(request,env); if(!user) return json({error:'Sign in required.'},401);
  const rows=await env.DB.prepare(`SELECT tool,status,created_at FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 50`).bind(user.id).all();
  return json({items:rows.results||[]});
}
async function feedback(request, env) {
  if (!originAllowed(request)) return json({error:'Invalid origin'},403);
  if (!(await rateLimit(request,env,'feedback',8,60*60*1000))) return json({error:'Too many feedback submissions. Try again later.'},429);
  const body=await request.json().catch(()=>({}));
  const type=htmlSafe(body.type)||'General feedback', tool=htmlSafe(body.tool).slice(0,100), email=normalizeEmail(body.email).slice(0,160), message=htmlSafe(body.message).slice(0,5000), turnstile=String(body.turnstileToken||''), honeypot=String(body.website||'');
  if (honeypot) return json({ok:true});
  if (!message) return json({error:'Please enter a message.'},400);
  if (env.TURNSTILE_SECRET) {
    const form=new FormData(); form.append('secret',env.TURNSTILE_SECRET); form.append('response',turnstile); const vr=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',body:form}); const v=await vr.json();
    if (!v.success) return json({error:'Bot verification failed. Please try again.'},400);
  }
  const user=await getUser(request,env);
  await env.DB.prepare(`INSERT INTO feedback (id,user_id,type,tool,email,message,created_at) VALUES (?,?,?,?,?,?,?)`).bind(randomId(16),user?.id||null,type,tool,email,message,Date.now()).run();
  return json({ok:true});
}

async function billingCheckout(request, env) {
  const user=await getUser(request,env); if(!user) return json({error:'Sign in required.'},401);
  if(!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET || !env.RAZORPAY_PLAN_ID) return json({error:'Billing is not configured yet. Add Razorpay secrets and the Pro plan ID.'},503);
  const existing=await env.DB.prepare(`SELECT subscription_id,subscription_status,cancel_at_cycle_end FROM users WHERE id=?`).bind(user.id).first();
  if(existing?.subscription_status==='active' || existing?.subscription_status==='authenticated') return json({error:'Your Pro subscription is already active.'},409);
  const auth=btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const response=await fetch('https://api.razorpay.com/v1/subscriptions',{method:'POST',headers:{'Authorization':`Basic ${auth}`,'Content-Type':'application/json'},body:JSON.stringify({plan_id:env.RAZORPAY_PLAN_ID,total_count:Number(env.RAZORPAY_TOTAL_COUNT||1200),quantity:1,customer_notify:true,notes:{user_id:user.id,product:'IMAGE 24 Pro'}})});
  const data=await response.json();
  if(!response.ok || !data.short_url) { console.error('Razorpay checkout error',data); return json({error:'Could not start checkout. Please try again.'},502); }
  await env.DB.prepare(`UPDATE users SET subscription_id=?,subscription_status=? WHERE id=?`).bind(data.id,data.status||'created',user.id).run();
  return json({url:data.short_url});
}
async function billingCancel(request, env) {
  const user=await getUser(request,env); if(!user) return json({error:'Sign in required.'},401);
  if(!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) return json({error:'Billing is not configured.'},503);
  const row=await env.DB.prepare(`SELECT subscription_id,subscription_status,cancel_at_cycle_end FROM users WHERE id=?`).bind(user.id).first();
  if(!row?.subscription_id) return json({error:'No active subscription found.'},404);
  const auth=btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const r=await fetch(`https://api.razorpay.com/v1/subscriptions/${encodeURIComponent(row.subscription_id)}/cancel`,{method:'POST',headers:{'Authorization':`Basic ${auth}`,'Content-Type':'application/json'},body:JSON.stringify({cancel_at_cycle_end:true})});
  const data=await r.json(); if(!r.ok) return json({error:'Could not cancel the subscription.'},502);
  await env.DB.prepare(`UPDATE users SET subscription_status=?,cancel_at_cycle_end=1 WHERE id=?`).bind(data.status||'active',user.id).run();
  return json({ok:true,status:data.status||'cancelled'});
}
async function billingWebhook(request, env) {
  if(!env.RAZORPAY_WEBHOOK_SECRET) return json({error:'Webhook secret not configured.'},503);
  const raw=await request.text(); const received=request.headers.get('X-Razorpay-Signature')||''; const expected=await hmacHex(env.RAZORPAY_WEBHOOK_SECRET,raw);
  if(!timingSafeEqualHex(expected,received)) return json({error:'Invalid signature'},401);
  const eventId=request.headers.get('X-Razorpay-Event-Id')||await digestHex(raw); const exists=await env.DB.prepare(`SELECT id FROM webhook_events WHERE id=?`).bind(eventId).first(); if(exists) return json({ok:true,duplicate:true});
  const body=JSON.parse(raw); const sub=body?.payload?.subscription?.entity; if(sub){
    const userId=sub.notes?.user_id;
    if(userId){
      const status=String(sub.status||''); const pro=['authenticated','active'].includes(status); const plan=pro?'pro':'free';
      await env.DB.prepare(`UPDATE users SET plan=?,subscription_id=?,subscription_status=?,cancel_at_cycle_end=CASE WHEN ?='cancelled' OR ?='completed' OR ?='expired' THEN 0 ELSE cancel_at_cycle_end END WHERE id=?`).bind(plan,sub.id,status,status,status,status,userId).run();
    }
  }
  await env.DB.prepare(`INSERT INTO webhook_events (id,event,created_at) VALUES (?,?,?)`).bind(eventId,String(body?.event||'unknown'),Date.now()).run();
  return json({ok:true});
}
function utcDay(){ const d=new Date(); return d.toISOString().slice(0,10); }
