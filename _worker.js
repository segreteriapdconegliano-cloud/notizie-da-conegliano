// outputs/notizie-da-conegliano/members/core.mjs
var enc = new TextEncoder();
var now = () => Math.floor(Date.now() / 1e3);
var token = () => crypto.randomUUID() + crypto.randomUUID();
async function hash(s) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function passwordHash(s, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(s), "PBKDF2", false, ["deriveBits"]);
  return [...new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(salt), iterations: 1e5, hash: "SHA-256" }, key, 256))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
function fail(message, status = 400) {
  throw Object.assign(Error(message), { status });
}
function validatePassword(p) {
  if (typeof p !== "string" || p.length < 8 || p.length > 200) fail("Password: da 8 a 200 caratteri");
}
function validateTime(t) {
  if (!/^(?:18|19|20|21|22|23|00|01|02|03|04|05):[0-5][0-9]$|^06:00$/.test(t)) fail("Scegliere un orario tra 18:00 e 06:00");
  return t;
}
function rome(d) {
  return Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Rome", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(d).filter((p) => p.type !== "literal").map((p) => [p.type, p.value]));
}
var CATCHUP_END = "06:15";
function cycleAt(d) {
  const p = rome(d), day = `${p.year}-${p.month}-${p.day}`, time = `${p.hour}:${p.minute}`;
  return { day, time, cycle: time <= CATCHUP_END ? new Date(Date.parse(day + "T12:00:00Z") - 864e5).toISOString().slice(0, 10) : day };
}
function due(time, d) {
  validateTime(time);
  const p = cycleAt(d);
  const minutes = (t) => {
    const [h, m] = t.split(":").map(Number);
    return (h < 12 ? h + 24 : h) * 60 + m;
  };
  return (p.time >= "18:00" || p.time <= CATCHUP_END) && minutes(p.time) >= minutes(time);
}
var security = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "X-Robots-Tag": "noindex, nofollow", "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" };
var json = (x, status = 200, extra = {}) => new Response(JSON.stringify(x), { status, headers: { ...security, "Content-Type": "application/json; charset=utf-8", ...extra } });
async function body(req) {
  if (Number(req.headers.get("Content-Length") || 0) > 1e6) fail("Richiesta troppo grande", 413);
  const text = await req.text();
  if (text.length > 1e6) fail("Richiesta troppo grande", 413);
  try {
    return JSON.parse(text);
  } catch {
    fail("JSON non valido");
  }
}
function origin(req) {
  if (req.headers.get("Origin") !== new URL(req.url).origin) fail("Origine non autorizzata", 403);
}
async function rate(db, key, limit = 8) {
  key = await hash(key);
  const t = now();
  const row = await db.prepare("INSERT INTO members_attempts VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires<=? THEN 1 ELSE count+1 END,expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count").bind(key, t + 900, t, t).first();
  if (row.count > limit) fail("Troppi tentativi: riprovare fra 15 minuti", 429);
}
async function session(req, db) {
  const t = (req.headers.get("Cookie") || "").split(";").map((s) => s.trim()).find((s) => s.startsWith("__Host-conews-member="))?.split("=")[1];
  if (!t) return null;
  return db.prepare("SELECT s.hash,s.csrf,u.* FROM members_sessions s JOIN members_users u ON u.id=s.user_id WHERE s.hash=? AND s.expires>? AND u.verified=1").bind(await hash(t), now()).first();
}
var cookie = (t, age = 28800) => `__Host-conews-member=${t}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${age}`;
async function restricted(db) {
  return (await db.prepare("SELECT value FROM members_settings WHERE key='restricted'").first())?.value === "true";
}
async function ingest(db, flashes) {
  if (!Array.isArray(flashes) || flashes.length > 2500) fail("Flash non validi");
  for (const f of flashes) {
    if (!/^[a-f0-9]{64}$/.test(f.id) || !/^[a-z0-9-]{1,150}$/.test(f.news_id) || typeof f.text !== "string" || [...f.text].length < 90 || [...f.text].length > 100 || /[\r\n]/.test(f.text) || !Array.isArray(f.tags) || !f.tags.length || f.tags.some((t) => !/^[a-z0-9-]{1,60}$/.test(t)) || !Number.isInteger(f.published) || f.published > now() + 60 || f.url !== "https://conews.pages.dev/notizie/" + f.news_id + ".html") fail("Provenienza flash non valida");
  }
  for (let i = 0; i < flashes.length; i += 50) await db.batch(flashes.slice(i, i + 50).map((f) => db.prepare("INSERT OR IGNORE INTO members_flashes VALUES (?,?,?,?,?,?)").bind(f.id, f.news_id, f.text, f.url, JSON.stringify(f.tags), f.published)));
}
async function queueDigests(db, base, date = /* @__PURE__ */ new Date()) {
  const cursor = (await db.prepare("SELECT value FROM members_settings WHERE key='digest_cursor'").first())?.value || "";
  const users = (await db.prepare("SELECT * FROM members_users WHERE enabled=1 AND verified=1 ORDER BY CASE WHEN id>? THEN 0 ELSE 1 END,id LIMIT 8").bind(cursor).all()).results;
  if (users.length) await db.prepare("INSERT INTO members_settings VALUES ('digest_cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(users.at(-1).id).run();
  for (const u of users) {
    if (!due(u.send_time, date)) continue;
    const cycle = cycleAt(date).cycle;
    if (await db.prepare("SELECT id FROM members_mail WHERE user_id=? AND cycle=? AND kind='digest'").bind(u.id, cycle).first()) continue;
    const tags = JSON.parse(u.tags);
    const rows = (await db.prepare("SELECT f.* FROM members_flashes f WHERE f.published>=? AND f.published<=? AND NOT EXISTS(SELECT 1 FROM members_items i WHERE i.user_id=? AND i.flash_id=f.id) ORDER BY f.published,f.id").bind(u.since, Math.floor(date.getTime() / 1e3), u.id).all()).results.filter((f) => JSON.parse(f.tags).some((t) => tags.includes(t)));
    if (!rows.length) continue;
    const id = token(), unsubscribe = token(), text = rows.map((f) => f.text + "\n" + f.url).join("\n\n") + "\n\nPreferenze e disiscrizione: " + base + "/account#unsubscribe=" + unsubscribe;
    await db.batch([db.prepare("INSERT INTO members_mail(id,user_id,kind,cycle,recipient,subject,body,created) VALUES (?,?,?,?,?,?,?,?)").bind(id, u.id, "digest", cycle, u.email, "CoNews \xB7 Rassegna " + cycle, text, now()), db.prepare("INSERT INTO members_tokens VALUES (?,?,?,?)").bind(await hash(unsubscribe), u.id, "unsubscribe", now() + 90 * 86400), ...rows.map((f) => db.prepare("INSERT INTO members_items VALUES (?,?,?)").bind(u.id, f.id, id))]).catch((e) => {
      if (!String(e).includes("UNIQUE")) throw e;
    });
  }
  return { scanned: users.length };
}

// outputs/notizie-da-conegliano/members/ui.mjs
var UI = `<!doctype html><html lang="it"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CoNews \xB7 Area personale</title>
<style>
:root{color-scheme:light;--ink:#223342;--muted:#586b78;--line:#dce4e9;--blue:#185775;--soft:#eef5f8}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:#f5f7f9;color:var(--ink);font:16px/1.55 system-ui,-apple-system,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 24px 56px}a{color:var(--blue);text-underline-offset:3px}
header{margin-bottom:24px}.brand{font-size:14px;font-weight:750;letter-spacing:.12em;color:var(--blue);margin:0 0 8px}h1{font-size:clamp(27px,4vw,36px);line-height:1.2;letter-spacing:-.03em;margin:0 0 12px}h2{font-size:23px;line-height:1.25;margin:0 0 8px}h3{font-size:18px;margin:0 0 12px}p{margin:0 0 16px}.intro,.hint{color:var(--muted)}.hint{font-size:14px;line-height:1.55}.intro{max-width:650px}
.auth-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:28px;box-shadow:0 3px 12px #23334205}.card>p{color:var(--muted)}
label{display:block;font-size:15px;font-weight:600;margin:18px 0 7px}input,button{font:inherit}input:not([type=checkbox]){display:block;width:100%;margin-top:7px;padding:12px 14px;border:1px solid #aebfc9;border-radius:8px;background:white;color:var(--ink);min-width:0}input:focus-visible,button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #6fabc7;outline-offset:3px}button{border:1px solid var(--blue);border-radius:8px;padding:11px 18px;font-weight:650;background:var(--blue);color:white;cursor:pointer;min-height:46px}button:hover{background:#12445e}form>button{margin-top:22px;width:100%}.secondary{background:white;color:var(--blue)}.secondary:hover{background:var(--soft)}.hint.after-input{margin-top:9px}input[type=checkbox]{width:19px;height:19px;accent-color:var(--blue);flex-shrink:0}
.recovery{margin-top:24px;box-shadow:none}summary{cursor:pointer;font-weight:650;color:var(--blue);min-height:24px}details[open] summary{margin-bottom:16px}.recovery form{max-width:560px}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px}.actions button{flex:1}.recovery label{margin-top:12px}
#message:empty{display:none}#message{white-space:pre-wrap;background:var(--soft);border:1px solid #b7d0dd;padding:14px 18px;border-radius:10px;margin:0 0 24px;overflow-wrap:anywhere}#token-panel{max-width:560px;margin:auto}.personal-header{display:flex;gap:16px;justify-content:space-between;align-items:center;margin-bottom:22px}.personal-header p{margin:0;color:var(--muted);overflow-wrap:anywhere}.personal-header button{flex-shrink:0}.personal-grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:24px;align-items:start}.switch{display:flex;align-items:center;gap:12px;background:var(--soft);padding:16px;border-radius:10px;margin:20px 0}.switch input{margin:0}#time{max-width:190px}fieldset{border:0;padding:0;margin:24px 0 0;min-width:0}legend{font-size:17px;font-weight:650;margin-bottom:12px}#tags label{display:inline-flex;align-items:center;gap:8px;margin:0 8px 10px 0;padding:9px 12px;border:1px solid var(--line);border-radius:8px;font-weight:500;max-width:100%;overflow-wrap:anywhere}#tags label:has(input:checked){background:var(--soft);border-color:#8baebf}#tags input{margin:0}#history{list-style:none;padding:0;margin:16px 0 0;color:var(--muted);font-size:14px}#history li{padding:12px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}#history:empty::before{content:'Nessuna email inviata finora.'}
@media(max-width:680px){main{padding:24px 16px 40px}.auth-grid,.personal-grid{grid-template-columns:1fr;gap:18px}.card{padding:22px}.recovery{margin-top:18px}.personal-header{align-items:flex-start}.actions{flex-direction:column}.actions button{width:100%}}
</style>
<main><header><p class="brand">CONEWS</p><h1>Area personale</h1><p class="intro">Accedi al tuo account e scegli le notizie da ricevere nella newsletter.</p><a href="/">\u2190 Torna alle notizie</a></header>
<p id="message" role="status" aria-live="polite"></p>
<section id="auth"><div class="auth-grid"><article class="card"><h2>Accedi</h2><p>Hai gi\xE0 un account? Entra da qui.</p><form id="login"><label>Username o email <input name="username" autocomplete="username" required></label><label>Password <input name="password" type="password" autocomplete="current-password" required></label><button>Accedi</button></form></article>
<article class="card"><h2>Crea il tuo account</h2><p>Scegli in seguito se attivare la newsletter.</p><form id="register"><label>Username <input name="username" autocomplete="username" pattern="[a-zA-Z0-9_.-]{3,40}" required></label><label>Email <input name="email" type="email" autocomplete="email" required></label><label>Password <input name="password" type="password" minlength="8" maxlength="200" autocomplete="new-password" aria-describedby="password-hint" required></label><p class="hint after-input" id="password-hint">Usa almeno 8 caratteri.</p><p class="hint">La registrazione non attiva la newsletter. Potrai scegliere se riceverla dopo aver confermato l\u2019email.</p><button>Crea account</button></form></article></div>
<details class="card recovery"><summary>Hai dimenticato la password o non hai ricevuto la conferma?</summary><p class="hint">Inserisci l\u2019email utilizzata per la registrazione.</p><form id="recovery"><label>Email <input name="email" type="email" autocomplete="email" required></label><div class="actions"><button name="action" value="forgot">Recupera password</button><button class="secondary" name="action" value="resend">Reinvia conferma</button></div></form></details></section>
<section class="card" id="token-panel" hidden><h2 id="token-title"></h2><form id="token-form"><label id="new-password-label" hidden>Nuova password (almeno 8 caratteri) <input id="new-password" type="password" minlength="8" maxlength="200" autocomplete="new-password"></label><button id="token-button">Conferma</button></form></section>
<section id="personal" hidden><div class="personal-header"><div><h2>Il tuo account</h2><p id="identity"></p></div><button class="secondary" id="logout">Esci</button></div><div class="personal-grid"><article class="card"><h2>La tua newsletter</h2><p>Un\u2019unica email con i flash delle notizie che ti interessano.</p><form id="preferences"><label class="switch"><input type="checkbox" id="enabled"> Attiva la newsletter giornaliera</label><label>Ora di ricevimento <input id="time" type="time" value="21:00" required aria-describedby="time-hint"></label><p class="hint after-input" id="time-hint">Dalle 18:00 alle 06:00, ora italiana (Europe/Rome). Dopo mezzanotte riceverai la rassegna del giorno precedente.</p><fieldset id="tags"><legend>Hashtag da seguire</legend></fieldset><p class="hint">Riceverai solo i flash gi\xE0 prodotti per WhatsApp, filtrati per gli hashtag scelti. Nessuna email se non ci sono nuovi flash. Invio normalmente entro cinque minuti dall\u2019orario scelto.</p><button>Salva preferenze</button></form></article><aside class="card"><h2>Storico email</h2><p class="hint">Qui trovi lo stato delle email del tuo account.</p><ul id="history"></ul></aside></div></section></main>
<script>
let csrf='',action='',linkToken='';const $=id=>document.getElementById(id),say=x=>$('message').textContent=x;
async function api(a,b){const r=await fetch('/api/member/'+a,{method:b?'POST':'GET',headers:b?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:b?JSON.stringify(b):undefined});const x=await r.json();if(!r.ok)throw Error(x.error);return x;}
async function enter(){const u=await api('session');csrf=u.csrf;$('auth').hidden=true;$('personal').hidden=false;$('identity').textContent=u.username+' \xB7 '+u.email;$('enabled').checked=u.enabled;$('time').value=u.time;$('tags').replaceChildren();const legend=document.createElement('legend');legend.textContent='Hashtag da seguire';$('tags').append(legend);for(const t of u.available_tags){const l=document.createElement('label'),i=document.createElement('input');i.type='checkbox';i.value=t;i.checked=u.tags.includes(t);l.append(i,document.createTextNode(' #'+t));$('tags').append(l);}$('history').replaceChildren();for(const h of u.history){const li=document.createElement('li');const states={pending:'In attesa',sending:'Invio in corso',sent:'Accettata dal servizio email',uncertain:'Esito da verificare',cancelled:'Annullata'};li.textContent=(h.cycle||h.kind)+' \xB7 '+(states[h.status]||h.status);$('history').append(li);}}
for(const a of ['login','register'])$(a).onsubmit=async e=>{e.preventDefault();try{const x=await api(a,Object.fromEntries(new FormData(e.target)));e.target.reset();say(x.message||'Accesso effettuato');if(a==='login')await enter();}catch(x){say(x.message);}};
$('recovery').onsubmit=async e=>{e.preventDefault();try{say((await api(e.submitter.value,Object.fromEntries(new FormData(e.target)))).message);}catch(x){say(x.message);}};
$('preferences').onsubmit=async e=>{e.preventDefault();try{await api('preferences',{enabled:$('enabled').checked,time:$('time').value,tags:[...$('tags').querySelectorAll('input:checked')].map(x=>x.value)});say('Preferenze salvate');await enter();}catch(x){say(x.message);}};
$('logout').onclick=async()=>{try{await api('logout',{});location.reload();}catch(x){say(x.message);}};
const params=new URLSearchParams(location.hash.slice(1));for(const a of ['verify','reset','unsubscribe'])if(params.has(a)){action=a;linkToken=params.get(a);}history.replaceState(null,'','/account');
if(action){$('auth').hidden=true;$('token-panel').hidden=false;$('token-title').textContent=({verify:'Conferma email',reset:'Recupera password',unsubscribe:'Disattiva newsletter'})[action];$('new-password-label').hidden=action!=='reset';$('new-password').required=action==='reset';}else enter().catch(()=>{});
$('token-form').onsubmit=async e=>{e.preventDefault();try{say((await api(action,{token:linkToken,password:$('new-password').value})).message);$('token-panel').hidden=true;$('auth').hidden=false;}catch(x){say(x.message);}};
<\/script></html>`;

// outputs/notizie-da-conegliano/members/worker.mjs
async function issue(db, u, kind, base) {
  const t = token(), id = token();
  await db.batch([db.prepare("DELETE FROM members_tokens WHERE user_id=? AND kind=?").bind(u.id, kind), db.prepare("UPDATE members_mail SET status='cancelled' WHERE user_id=? AND kind=? AND status='pending'").bind(u.id, kind), db.prepare("INSERT INTO members_tokens VALUES (?,?,?,?)").bind(await hash(t), u.id, kind, now() + (kind === "verify" ? 86400 : 3600)), db.prepare("INSERT INTO members_mail(id,user_id,kind,recipient,subject,body,created) VALUES (?,?,?,?,?,?,?)").bind(id, u.id, kind, u.email, kind === "verify" ? "CoNews \xB7 Conferma email" : "CoNews \xB7 Recupero password", base + "/account#" + kind + "=" + t, now())]);
}
async function takeToken(db, t, kind) {
  if (typeof t !== "string" || t.length > 200) fail("Collegamento non valido");
  const row = await db.prepare("DELETE FROM members_tokens WHERE hash=? AND kind=? AND expires>? RETURNING user_id").bind(await hash(t), kind, now()).first();
  if (!row) fail("Collegamento scaduto o gi\xE0 utilizzato");
  return row.user_id;
}
async function route(req, env) {
  const url = new URL(req.url), p = url.pathname, db = env.MEMBERS_DB, base = env.SITE_ORIGIN || url.origin;
  if (!db) fail("Servizio utenti non configurato", 503);
  if (p === "/api/member/runtime" && req.method === "GET") return json({ runtime: false ? "development" : "5ce4f86aedd3d32fcfb47d7fae4edfff136105fe210c00d03a0f39b40a4e3cc2", routes: { version: 1, include: ["/*"], exclude: [] } });
  if (p.startsWith("/internal/")) {
    if (req.method !== "POST") fail("Metodo non consentito", 405);
    const mail = p.startsWith("/internal/mail/"), secret = mail ? env.MAIL_TOKEN : env.INGEST_TOKEN;
    if (!secret || !equal(req.headers.get("Authorization"), "Bearer " + secret)) fail("Accesso negato", 401);
    const b = await body(req);
    if (p === "/internal/flashes") {
      await ingest(db, b.flashes);
      return json({ ok: true });
    }
    if (p === "/internal/mail/claim") {
      const scan = await queueDigests(db, base);
      await db.prepare("UPDATE members_mail SET status='uncertain',detail='Conferma invio assente' WHERE status='sending' AND claimed<?").bind(now() - 900).run();
      const row = await db.prepare("UPDATE members_mail SET status='sending',claimed=? WHERE id=(SELECT m.id FROM members_mail m JOIN members_users u ON u.id=m.user_id WHERE m.status='pending' AND (m.kind!='digest' OR (u.enabled=1 AND u.verified=1)) AND (SELECT count(*) FROM members_mail WHERE claimed>?)<100 ORDER BY CASE WHEN m.kind='digest' THEN 1 ELSE 0 END,m.created LIMIT 1) AND status='pending' RETURNING id,recipient,subject,body").bind(now(), now() - 86400).first();
      return json({ mail: row, more: scan.scanned === 8 });
    }
    if (p === "/internal/mail/ack") {
      if (!["sent", "uncertain", "quota"].includes(b.status)) fail("Stato non valido");
      await db.prepare("UPDATE members_mail SET status=?,sent=?,detail=? WHERE id=? AND status='sending'").bind(b.status === "quota" ? "pending" : b.status, b.status === "sent" ? now() : null, b.status, b.id).run();
      return json({ ok: true });
    }
    fail("Percorso inesistente", 404);
  }
  if (p === "/account" || p === "/account/") return new Response(UI, { headers: { ...security, "Content-Type": "text/html; charset=utf-8" } });
  if (p.startsWith("/api/member/")) {
    if (req.method !== "GET" && req.method !== "POST") fail("Metodo non consentito", 405);
    if (req.method === "POST") origin(req);
    const action = p.slice("/api/member/".length), post = req.method === "POST";
    if (["register", "login", "forgot", "resend", "verify", "reset", "unsubscribe"].includes(action) && post) {
      await rate(db, "ip:" + action + ":" + (req.headers.get("CF-Connecting-IP") || "local"), action === "register" ? 4 : 8);
      const b = await body(req);
      if (action === "register") {
        if (!env.MAIL_TOKEN) fail("Registrazioni non ancora attivate", 503);
        if (typeof b.username !== "string" || !/^[a-zA-Z0-9_.-]{3,40}$/.test(b.username) || typeof b.email !== "string" || b.email.length > 254 || /[,;<>\r\n]/.test(b.email) || !/^\S+@[^\s@]+\.[^\s@]+$/.test(b.email)) fail("Username o email non validi");
        validatePassword(b.password);
        const salt = token(), u = { id: token(), email: b.email.trim().toLowerCase() };
        const result = await db.prepare("INSERT OR IGNORE INTO members_users(id,username,email,salt,password,created,since) VALUES (?,?,?,?,?,?,?)").bind(u.id, b.username, u.email, salt, await passwordHash(b.password, salt), now(), now()).run();
        if (result.meta.changes) await issue(db, u, "verify", base);
        return json({ message: "Se i dati sono disponibili, riceverai la conferma email. L\u2019arrivo della mail pu\xF2 richiedere fino a 5 minuti. Controlla anche lo spam." });
      }
      if (action === "login") {
        if (typeof b.username !== "string" || b.username.length > 254 || typeof b.password !== "string" || b.password.length > 200) fail("Credenziali non valide", 401);
        await rate(db, "login-account:" + b.username.toLowerCase(), 8);
        const u = await db.prepare("SELECT * FROM members_users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE").bind(b.username, b.username).first();
        const verifier = await passwordHash(b.password, u?.salt || "dummy-salt-for-missing-user");
        if (!u || !equal(verifier, u.password) || !u.verified) fail("Credenziali non valide o email non confermata", 401);
        const t = token(), csrf = token();
        await db.prepare("INSERT INTO members_sessions VALUES (?,?,?,?)").bind(await hash(t), u.id, csrf, now() + 28800).run();
        return json({ csrf }, 200, { "Set-Cookie": cookie(t) });
      }
      if (action === "forgot" || action === "resend") {
        if (typeof b.email !== "string" || b.email.length > 254) fail("Email non valida");
        await rate(db, "email:" + b.email.toLowerCase(), 3);
        const u = await db.prepare("SELECT id,email,verified FROM members_users WHERE email=? COLLATE NOCASE").bind(b.email).first();
        if (u && (action === "forgot" || !u.verified)) await issue(db, u, action === "forgot" ? "reset" : "verify", base);
        return json({ message: "Se l\u2019account esiste, riceverai un collegamento via email." });
      }
      if (action === "verify") {
        const id = await takeToken(db, b.token, "verify");
        await db.prepare("UPDATE members_users SET verified=1 WHERE id=?").bind(id).run();
        return json({ message: "Email confermata. Puoi accedere." });
      }
      if (action === "reset") {
        validatePassword(b.password);
        const id = await takeToken(db, b.token, "reset"), salt = token();
        await db.batch([db.prepare("UPDATE members_users SET salt=?,password=? WHERE id=?").bind(salt, await passwordHash(b.password, salt), id), db.prepare("DELETE FROM members_sessions WHERE user_id=?").bind(id)]);
        return json({ message: "Password aggiornata. Accedi nuovamente." });
      }
      if (action === "unsubscribe") {
        const id = await takeToken(db, b.token, "unsubscribe");
        await db.batch([db.prepare("UPDATE members_users SET enabled=0 WHERE id=?").bind(id), db.prepare("UPDATE members_mail SET status='cancelled' WHERE user_id=? AND kind='digest' AND status='pending'").bind(id)]);
        return json({ message: "Newsletter disattivata." });
      }
    }
    const s = await session(req, db);
    if (!s) fail("Accedere per continuare", 401);
    if (post && !equal(req.headers.get("X-CSRF-Token"), s.csrf)) fail("Sessione non valida", 403);
    if (action === "session" && !post) {
      const rows = (await db.prepare("SELECT tags FROM members_flashes").all()).results;
      return json({ username: s.username, email: s.email, csrf: s.csrf, enabled: !!s.enabled, time: s.send_time, tags: JSON.parse(s.tags), available_tags: [...new Set(rows.flatMap((r) => JSON.parse(r.tags)))].sort(), history: (await db.prepare("SELECT kind,cycle,status,created,sent FROM members_mail WHERE user_id=? ORDER BY created DESC LIMIT 50").bind(s.id).all()).results });
    }
    if (action === "preferences" && post) {
      const b = await body(req);
      validateTime(b.time);
      const all = new Set((await db.prepare("SELECT tags FROM members_flashes").all()).results.flatMap((r) => JSON.parse(r.tags)));
      if (typeof b.enabled !== "boolean" || !Array.isArray(b.tags) || b.tags.length > 100 || b.tags.some((t) => !all.has(t)) || b.enabled && !b.tags.length) fail("Scegliere almeno un hashtag disponibile");
      await db.batch([db.prepare("UPDATE members_users SET enabled=?,send_time=?,tags=?,since=CASE WHEN enabled=0 AND ?=1 THEN ? ELSE since END WHERE id=?").bind(+b.enabled, b.time, JSON.stringify([...new Set(b.tags)]), +b.enabled, now(), s.id), db.prepare("UPDATE members_mail SET status='cancelled' WHERE user_id=? AND kind='digest' AND status='pending'").bind(s.id)]);
      return json({ ok: true });
    }
    if (action === "logout" && post) {
      await db.prepare("DELETE FROM members_sessions WHERE hash=?").bind(s.hash).run();
      return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
    }
    fail("Percorso inesistente", 404);
  }
  if (req.method !== "GET" && req.method !== "HEAD") fail("Metodo non consentito", 405);
  const service = env.RELEASE_TOKEN && equal(req.headers.get("Authorization"), "Bearer " + env.RELEASE_TOKEN);
  if (await restricted(db) && !service && !await session(req, db)) return new Response(null, { status: 303, headers: { ...security, Location: "/account" } });
  const asset = await env.ASSETS.fetch(req);
  const response = new Response(asset.body, asset);
  response.headers.set("Cache-Control", "private, no-store");
  response.headers.set("X-Robots-Tag", "noindex, nofollow");
  response.headers.delete("ETag");
  return response;
}
var worker_default = { async fetch(req, env) {
  try {
    return await route(req, env);
  } catch (e) {
    return json({ error: e.status ? e.message : "Servizio temporaneamente non disponibile" }, e.status || 503);
  }
}, async scheduled(event, env, ctx) {
  ctx.waitUntil(queueDigests(env.MEMBERS_DB, env.SITE_ORIGIN));
} };
export {
  worker_default as default
};
