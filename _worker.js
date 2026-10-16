// members/core.mjs
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
  if (typeof p !== "string" || p.length < 14 || p.length > 200) fail("Password: da 14 a 200 caratteri");
}
function validateTime(t) {
  if (!/^(?:18|19|20|21|22|23|00|01|02|03|04|05):[0-5][0-9]$|^06:00$/.test(t)) fail("Scegliere un orario tra 18:00 e 06:00");
  return t;
}
function rome(d) {
  return Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Rome", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(d).filter((p) => p.type !== "literal").map((p) => [p.type, p.value]));
}
function cycleAt(d) {
  const p = rome(d), day = `${p.year}-${p.month}-${p.day}`, time = `${p.hour}:${p.minute}`;
  return { day, time, cycle: time <= "06:00" ? new Date(Date.parse(day + "T12:00:00Z") - 864e5).toISOString().slice(0, 10) : day };
}
function due(time, d) {
  validateTime(time);
  const p = cycleAt(d);
  const minutes = (t) => {
    const [h, m] = t.split(":").map(Number);
    return (h < 12 ? h + 24 : h) * 60 + m;
  };
  return (p.time >= "18:00" || p.time <= "06:00") && minutes(p.time) >= minutes(time);
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

// members/ui.mjs
var UI = `<!doctype html><html lang="it"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CoNews \xB7 Area personale</title><style>body{font:17px system-ui;max-width:650px;margin:2rem auto;padding:1rem;color:#222}label{display:block;margin-top:1rem}input,button,select{font:inherit;padding:.5rem;max-width:95%}button{margin:.6rem .3rem .6rem 0}fieldset{margin:1rem 0}#message{white-space:pre-wrap}a{color:#164c80}</style><h1>Area personale CoNews</h1><a href="/">Leggi le notizie</a><p id="message" role="status"></p>
<section id="auth"><h2>Accedi</h2><form id="login"><label>Username o email <input name="username" autocomplete="username" required></label><label>Password <input name="password" type="password" autocomplete="current-password" required></label><button>Accedi</button></form>
<h2>Registrati</h2><form id="register"><label>Username <input name="username" autocomplete="username" pattern="[a-zA-Z0-9_.-]{3,40}" required></label><label>Email <input name="email" type="email" autocomplete="email" required></label><label>Password (almeno 14 caratteri) <input name="password" type="password" minlength="14" maxlength="200" autocomplete="new-password" required></label><p>La registrazione non attiva la newsletter. Potrai scegliere se riceverla dopo aver confermato l\u2019email.</p><button>Crea account</button></form>
<h2>Recupero accesso</h2><form id="recovery"><label>Email <input name="email" type="email" required></label><button name="action" value="forgot">Recupera password</button><button name="action" value="resend">Reinvia conferma</button></form></section>
<section id="token-panel" hidden><h2 id="token-title"></h2><form id="token-form"><label id="new-password-label" hidden>Nuova password <input id="new-password" type="password" minlength="14" maxlength="200" autocomplete="new-password"></label><button id="token-button">Conferma</button></form></section>
<section id="personal" hidden><h2 id="identity"></h2><form id="preferences"><label><input type="checkbox" id="enabled"> Attiva la newsletter giornaliera</label><label>Ora di ricevimento (Europe/Rome) <input id="time" type="time" value="21:00" required></label><p>Orario consentito: dalle 18:00 alle 06:00. Le ore dopo mezzanotte si riferiscono alla rassegna del giorno precedente. Invio al primo controllo disponibile, normalmente entro cinque minuti. Nessuna email se non ci sono nuovi flash per gli hashtag scelti.</p><fieldset id="tags"><legend>Hashtag da seguire</legend></fieldset><button>Salva preferenze</button></form><button id="logout">Esci</button><h2>Storico email</h2><ul id="history"></ul></section>
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

// members/worker.mjs
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
  if (p === "/api/member/runtime" && req.method === "GET") return json({ runtime: false ? "development" : "7e666254f3579a59b88927f907d5e180213b6a33d523c8ddbd21283b00ba3b16", routes: { version: 1, include: ["/*"], exclude: [] } });
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
        return json({ message: "Se i dati sono disponibili, riceverai la conferma email. Controlla anche lo spam." });
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
