// ============================================================
// K36 บอทหลังบ้าน — Railway worker v0.1
// ตอนนี้ทำอย่างเดียว: ล็อกอินทุกเว็บที่ตั้งบัญชีไว้ใน K36 แล้วรายงานสถานะกลับ
//
// Variables ที่ต้องตั้งใน Railway:
//   SUPABASE_URL     = https://xxxx.supabase.co
//   SUPABASE_KEY     = คีย์ Supabase (ตัวเดียวกับที่ K36 ใช้)
//   BO_PRIVATE_KEY   = กุญแจลับที่ได้ตอนกด "สร้างกุญแจ" ใน K36
// ============================================================
const crypto = require('node:crypto');
const http = require('node:http');

const SB_URL = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_KEY || '';
const PRIV_PEM = String(process.env.BO_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();

const LOOP_MS = 60 * 1000;                 // เช็กทุก 1 นาที
const RELOGIN_BEFORE_MS = 20 * 60 * 1000;  // ล็อกอินใหม่ก่อน token หมด 20 นาที
const FAIL_COOLDOWN_MS = 15 * 60 * 1000;   // ล็อกอินพลาด → รอ 15 นาทีก่อนลองรหัสเดิมซ้ำ (กันบัญชีโดนล็อก)
const HTTP_TIMEOUT_MS = 20 * 1000;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

const sessions = new Map(); // siteId -> { token, exp, cipher, failedAt, failedCipher }

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------- เช็กค่าเริ่มต้น ----------
function fatal(msg) {
  console.error('❌ ' + msg);
  process.exit(1);
}
if (!SB_URL) fatal('ไม่ได้ตั้ง SUPABASE_URL');
if (!SB_KEY) fatal('ไม่ได้ตั้ง SUPABASE_KEY');
if (!PRIV_PEM.includes('PRIVATE KEY')) fatal('ไม่ได้ตั้ง BO_PRIVATE_KEY หรือวางไม่ครบ');

let privateKey, KEY_FP;
try {
  privateKey = crypto.createPrivateKey(PRIV_PEM);
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  KEY_FP = crypto.createHash('sha256').update(spki).digest('hex').slice(0, 16).toUpperCase().match(/.{4}/g).join('-');
} catch (e) {
  fatal('BO_PRIVATE_KEY ใช้ไม่ได้: ' + e.message);
}
log('🔑 ลายนิ้วมือกุญแจ:', KEY_FP, '(ต้องตรงกับที่แสดงในหน้า K36)');

// ---------- Supabase REST ----------
async function sb(method, path, body) {
  const res = await fetch(SB_URL + '/rest/v1/' + path, {
    method,
    headers: {
      apikey: SB_KEY,
      Authorization: 'Bearer ' + SB_KEY,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal'
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS)
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}

const patchSite = (id, data) => sb('PATCH', `bo_sites?id=eq.${encodeURIComponent(id)}`, data)
  .catch(e => log('⚠️ อัปเดตสถานะ', id, 'ไม่สำเร็จ:', e.message));

// ---------- ไขรหัส ----------
function decryptCred(site) {
  if (site.cipher_fp && site.cipher_fp !== KEY_FP) {
    throw new Error('บัญชีถูกล็อกด้วยกุญแจคนละชุดกับที่ใส่ใน Railway — ตั้งบัญชีใหม่ใน K36 หรือใส่ BO_PRIVATE_KEY ให้ตรง');
  }
  let obj;
  try {
    const plain = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(site.cred_cipher, 'base64')
    );
    obj = JSON.parse(plain.toString('utf8'));
  } catch (e) {
    throw new Error('ไขรหัสบัญชีไม่ได้ — กุญแจไม่ตรง ตั้งบัญชีใหม่ใน K36');
  }
  if (obj.s !== site.id) throw new Error('บัญชีนี้ถูกตั้งไว้ให้เว็บอื่น — ตั้งบัญชีใหม่ใน K36');
  if (!obj.u || !obj.p) throw new Error('บัญชีไม่ครบ');
  return { userid: obj.u, password: obj.p };
}

// หน้าเว็บส่งรหัสเป็น SHA-1 (ตัวอักษร 40 ตัว) — ถ้าใส่มาเป็นแบบนั้นอยู่แล้วก็ใช้ตรง ๆ
function hashPassword(p) {
  if (/^[0-9a-f]{40}$/i.test(p)) return p.toLowerCase();
  return crypto.createHash('sha1').update(p, 'utf8').digest('hex');
}

function jwtExp(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return payload.exp ? payload.exp * 1000 : Date.now() + 60 * 60 * 1000;
  } catch (e) {
    return Date.now() + 60 * 60 * 1000;
  }
}

// สรุปหน้า HTML ที่ตอบกลับมา (หน้า error/บล็อก) ให้อ่านง่ายในบรรทัดเดียว
function htmlSummary(text) {
  if (!text || !/^\s*</.test(text)) return (text || '').slice(0, 150);
  const title = (text.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '';
  const body = text.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
  return ('หน้าเว็บ: ' + (title.trim() || '-') + ' | ' + body.slice(0, 200)).trim();
}

function boHeaders(site, token) {
  const origin = new URL(site.web_url).origin;
  const h = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/plain, */*',
    Origin: origin,
    Referer: origin + '/',
    'User-Agent': UA
  };
  if (token) h.Authorization = token; // หลังบ้านนี้ส่ง token ตรง ๆ ไม่มีคำว่า Bearer
  return h;
}

// ---------- ล็อกอิน ----------
async function login(site, cred) {
  const res = await fetch(site.api_base + '/login', {
    method: 'POST',
    headers: boHeaders(site),
    body: JSON.stringify({ userid: cred.userid, password: hashPassword(cred.password) }),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS)
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (e) {}

  if (!res.ok) {
    const why = (data && (data.message || data.error || data.msg)) || htmlSummary(text) || ('HTTP ' + res.status);
    log('🔎', site.id, 'login ตอบกลับ', res.status, 'server=' + (res.headers.get('server') || '-'),
      'cf-ray=' + (res.headers.get('cf-ray') || '-'), 'type=' + (res.headers.get('content-type') || '-'));
    if (res.status === 403) throw new Error('หลังบ้านไม่ให้เข้า (403) — อาจจำกัด IP ต้องให้ทีมหลังบ้านเพิ่ม IP ของ Railway: ' + why);
    throw new Error(`ล็อกอินไม่ผ่าน (${res.status}): ${why}`);
  }
  if (!data || !data.token) throw new Error('ล็อกอินแล้วไม่ได้ token กลับมา');
  if (data.verifytype && data.verifytype !== 'none') throw new Error('หลังบ้านขอยืนยันตัวตนเพิ่ม (' + data.verifytype + ') บอทล็อกอินเองไม่ได้');
  return { token: data.token, exp: jwtExp(data.token) };
}

async function handleSite(site) {
  const now = Date.now();
  let s = sessions.get(site.id) || {};

  if (!site.cred_cipher) {
    sessions.delete(site.id);
    return;
  }

  const credChanged = s.cipher !== site.cred_cipher;
  const needLogin = credChanged || !s.token || s.exp - now < RELOGIN_BEFORE_MS;

  if (needLogin) {
    // ล็อกอินพลาดด้วยรหัสเดิม → รอก่อน ไม่ลองรัว ๆ
    if (!credChanged && s.failedCipher === site.cred_cipher && now - s.failedAt < FAIL_COOLDOWN_MS) return;

    let cred;
    try {
      cred = decryptCred(site);
    } catch (e) {
      sessions.set(site.id, { cipher: site.cred_cipher, failedAt: now, failedCipher: site.cred_cipher });
      log('🔒', site.id, e.message);
      return patchSite(site.id, { status: 'error', last_error: e.message, last_seen: new Date().toISOString() });
    }

    try {
      const r = await login(site, cred);
      s = { token: r.token, exp: r.exp, cipher: site.cred_cipher };
      sessions.set(site.id, s);
      log('✅', site.id, 'ล็อกอินสำเร็จ token หมดอายุ', new Date(r.exp).toISOString());
      return patchSite(site.id, {
        status: 'ok', last_error: null,
        last_login_at: new Date().toISOString(), last_seen: new Date().toISOString()
      });
    } catch (e) {
      const msg = e.name === 'TimeoutError' ? 'ติดต่อหลังบ้านไม่ได้ (หมดเวลา)' : e.message;
      sessions.set(site.id, { cipher: site.cred_cipher, failedAt: now, failedCipher: site.cred_cipher });
      log('❌', site.id, msg);
      return patchSite(site.id, { status: 'login_failed', last_error: msg, last_seen: new Date().toISOString() });
    }
  }

  // ยังล็อกอินอยู่ → ส่งสัญญาณชีพ
  return patchSite(site.id, { status: 'ok', last_seen: new Date().toISOString() });
}

// ---------- วงจรหลัก ----------
let running = false;
async function loop() {
  if (running) return;
  running = true;
  try {
    const sites = await sb('GET', 'bo_sites?enabled=eq.true&select=id,name,web_url,api_base,cred_cipher,cipher_fp');
    const ids = new Set(sites.map(s => s.id));
    for (const id of sessions.keys()) if (!ids.has(id)) sessions.delete(id);
    for (const site of sites) {
      try {
        await handleSite(site);
      } catch (e) {
        log('⚠️', site.id, e.message);
      }
    }
  } catch (e) {
    log('⚠️ รอบนี้ผิดพลาด:', e.message);
  } finally {
    running = false;
  }
}

// ให้ Railway เช็กได้ว่าบอทยังมีชีวิต (ไม่เปิดเผยข้อมูลใด ๆ)
const PORT = process.env.PORT;
if (PORT) {
  http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ok');
  }).listen(PORT, () => log('🌐 health check พอร์ต', PORT));
}

// เช็ก IP ขาออกของ Railway (ใช้แจ้งทีมหลังบ้านถ้าต้องเพิ่ม IP)
fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(8000) })
  .then(r => r.json()).then(d => log('🌍 IP ขาออกของบอท:', d.ip)).catch(() => {});

log('🤖 K36 บอทหลังบ้าน v0.1.1 เริ่มทำงาน');
loop();
setInterval(loop, LOOP_MS);

process.on('SIGTERM', () => { log('👋 ปิดบอท'); process.exit(0); });
process.on('unhandledRejection', e => log('⚠️ unhandled:', e && e.message));
