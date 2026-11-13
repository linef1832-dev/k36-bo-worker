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
const { ProxyAgent } = require('undici');

const SB_URL = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_KEY || '';
const PRIV_PEM = String(process.env.BO_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();
const PROXY_URL = String(process.env.PROXY_URL || '').trim(); // เช่น socks5h://127.0.0.1:1080

const LOOP_MS = 8 * 1000;        // เช็กคิวงานทุก 8 วินาที                 // เช็กทุก 1 นาที
const RELOGIN_BEFORE_MS = 20 * 60 * 1000;  // ล็อกอินใหม่ก่อน token หมด 20 นาที
const FAIL_COOLDOWN_MS = 15 * 60 * 1000;   // ล็อกอินพลาด → รอ 15 นาทีก่อนลองรหัสเดิมซ้ำ (กันบัญชีโดนล็อก)
const HTTP_TIMEOUT_MS = 20 * 1000;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

const proxyAgent = PROXY_URL ? new ProxyAgent(PROXY_URL) : undefined;
const boFetchOpts = () => proxyAgent ? { dispatcher: proxyAgent } : {};

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
  // ถ้าใส่ค่าที่ hash มาแล้ว (40 ตัว hex) ให้ส่งตรง ๆ — ใช้กับหลังบ้านที่มีสูตรเข้ารหัสเฉพาะ
  if (/^[0-9a-f]{40}$/i.test(p)) return p.toLowerCase();
  // ไม่งั้น hash แบบ sha1 มาตรฐาน
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
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    ...boFetchOpts()
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
      await patchSite(site.id, {
        status: 'ok', last_error: null,
        last_login_at: new Date().toISOString(), last_seen: new Date().toISOString()
      });
      await processTasks(site, s.token).catch(e => log('⚠️ งานค้าง', site.id, e.message));
      return;
    } catch (e) {
      const msg = e.name === 'TimeoutError' ? 'ติดต่อหลังบ้านไม่ได้ (หมดเวลา)' : e.message;
      sessions.set(site.id, { cipher: site.cred_cipher, failedAt: now, failedCipher: site.cred_cipher });
      log('❌', site.id, msg);
      return patchSite(site.id, { status: 'login_failed', last_error: msg, last_seen: new Date().toISOString() });
    }
  }

  // ยังล็อกอินอยู่ → ส่งสัญญาณชีพ + ทำงานในคิว
  await patchSite(site.id, { status: 'ok', last_seen: new Date().toISOString() });
  await processTasks(site, s.token).catch(e => log('⚠️ งานค้าง', site.id, e.message));
}

// ---------- ดึง token ที่ใช้ได้ (ล็อกอินให้ถ้ายังไม่มี) ----------
async function ensureToken(site) {
  let s = sessions.get(site.id) || {};
  const now = Date.now();
  if (s.token && s.cipher === site.cred_cipher && s.exp - now > 60 * 1000) return s.token;
  const cred = decryptCred(site);
  const r = await login(site, cred);
  s = { token: r.token, exp: r.exp, cipher: site.cred_cipher };
  sessions.set(site.id, s);
  return r.token;
}

// ---------- เรียก API หลังบ้าน (ผ่าน proxy + ใส่ token) ----------
async function boApi(site, token, method, path, body) {
  const url = site.api_base + path;
  const res = await fetch(url, {
    method,
    headers: boHeaders(site, token),
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    ...boFetchOpts()
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) {}
  if (res.status === 401 || res.status === 403 || res.status === 498) {
    // token อาจหมดอายุ → ล้างให้ล็อกอินใหม่รอบหน้า
    sessions.delete(site.id);
  }
  if (!res.ok) {
    const why = (data && (data.message || data.error || data.msg)) || ('HTTP ' + res.status);
    const e = new Error(why); e.httpStatus = res.status; throw e;
  }
  return data;
}

// ========================================================
// ความสามารถของ "ระบบหลังบ้านแบบ K36 (tf6prod-ims)"
// งานช่องทางชำระเงิน: list / get / save
// ========================================================
const K36 = {
  // ดึงรายชื่อช่องทางทั้งหมด
  async listChannels(site, token) {
    const rows = await boApi(site, token, 'GET', '/thirdpartypayments?currency=THB');
    const arr = Array.isArray(rows) ? rows : (rows && rows.data) || [];
    return arr.map(x => ({
      id: x.thirdpartypaymentid,
      code: x.thirdpartypaymentcode,
      name: (x.thirdpartypaymentdisplayname && (x.thirdpartypaymentdisplayname['th-TH'] || x.thirdpartypaymentdisplayname['en-US'])) || x.thirdpartypaymentstaticname || x.thirdpartypaymentcode,
      staticname: x.thirdpartypaymentstaticname || ''
    }));
  },

  // ดึงค่าปัจจุบันของช่องทาง (ค่าดิบ + ค่าที่แก้ได้แบบย่อ)
  async getChannel(site, token, channelId) {
    const raw = await boApi(site, token, 'GET', `/thirdpartypayments/${encodeURIComponent(channelId)}/THB`);
    const cur = (raw.currencies && raw.currencies[0]) || {};
    const pts = cur.paymenttypesetting || {};
    const enabled = Array.isArray(cur.depositPaymentTypes) ? cur.depositPaymentTypes : Object.keys(pts);
    const types = {};
    for (const code of Object.keys(pts)) {
      types[code] = {
        enabled: enabled.includes(code),
        min: String(pts[code].mindepositamt ?? ''),
        max: String(pts[code].maxdepositamt ?? '')
      };
    }
    return {
      raw,                                   // เก็บไว้ประกอบตอนบันทึก (บอทไม่แตะ merchantinfo/vipids/platform)
      id: raw.thirdpartypaymentid,
      code: raw.thirdpartypaymentcode,
      name: (raw.thirdpartypaymentdisplayname && raw.thirdpartypaymentdisplayname['th-TH']) || '',
      currency: 'THB',
      status: cur.status,                    // ค่าสถานะดิบ (บอทส่งคืนเหมือนเดิมถ้าไม่สั่งแก้)
      readonly: { dailyamt: cur.dailyamt, totalamt: cur.totalamt, updatedby: cur.updatedby, updatedat: cur.updatedat },
      values: {
        maxdailyamt: String(cur.maxdailyamt ?? ''),
        maxtotalamt: String(cur.maxtotalamt ?? ''),
        minpayoutamt: String(cur.minpayoutamt ?? ''),
        maxpayoutamt: String(cur.maxpayoutamt ?? ''),
        amountsuggest: !!cur.amountsuggest,
        suggestamounts: Array.isArray(cur.suggestamounts) ? cur.suggestamounts.slice() : [],
        types
      }
    };
  },

  // บันทึกช่องทาง: ดึงค่าสด → ทับเฉพาะที่สั่ง → PUT กลับ
  // changes = { status?, maxdailyamt?, maxtotalamt?, minpayoutamt?, maxpayoutamt?,
  //             amountsuggest?, suggestamounts?, types?: {CODE:{enabled?,min?,max?}} }
  async saveChannel(site, token, channelId, changes) {
    const raw = await boApi(site, token, 'GET', `/thirdpartypayments/${encodeURIComponent(channelId)}/THB`);
    if (!raw.currencies || !raw.currencies[0]) throw new Error('ไม่พบข้อมูลสกุล THB ของช่องทางนี้');
    const cur = raw.currencies[0];
    const changed = [];

    const numStr = (v) => {
      const n = String(v).replace(/[, ]/g, '');
      if (!/^\d+(\.\d+)?$/.test(n)) throw new Error('ค่าตัวเลขไม่ถูกต้อง: ' + v);
      return n;
    };

    if (changes.status !== undefined) {
      const st = Number(changes.status);
      if (![0, 1, 2, 3].includes(st)) throw new Error('สถานะไม่ถูกต้อง');
      if (cur.status !== st) { cur.status = st; changed.push('สถานะ=' + st); }
    }
    for (const k of ['maxdailyamt', 'maxtotalamt', 'minpayoutamt', 'maxpayoutamt']) {
      if (changes[k] !== undefined) {
        const v = numStr(changes[k]);
        if (String(cur[k]) !== v) { cur[k] = v; changed.push(k + '=' + v); }
      }
    }
    if (changes.amountsuggest !== undefined) { cur.amountsuggest = !!changes.amountsuggest; changed.push('amountsuggest=' + cur.amountsuggest); }
    if (Array.isArray(changes.suggestamounts)) {
      const arr = changes.suggestamounts.map(x => Number(String(x).replace(/[, ]/g, '')));
      if (arr.some(n => !isFinite(n) || n < 0)) throw new Error('ปุ่มจำนวนเงินมีค่าไม่ถูกต้อง');
      cur.suggestamounts = arr; changed.push('ปุ่มเงินแนะนำ ' + arr.length + ' ปุ่ม');
    }

    // ประเภทการชำระเงิน
    if (changes.types && typeof changes.types === 'object') {
      const pts = cur.paymenttypesetting || (cur.paymenttypesetting = {});
      // ประเภทที่ "มีจริง" ในช่องทางนี้เท่านั้น (กัน Invalid depositPaymentTypes)
      const existing = Object.keys(pts);
      // รายการที่เปิดอยู่ตอนนี้ — ถ้า depositPaymentTypes เป็น null แปลว่า "เปิดทุกประเภทที่มี"
      let enabledList = Array.isArray(cur.depositPaymentTypes) ? cur.depositPaymentTypes.slice() : existing.slice();
      let touchedEnable = false, touchedMinMax = false;
      for (const code of Object.keys(changes.types)) {
        const t = changes.types[code];
        if (!pts[code]) continue; // ช่องทางนี้ไม่มีประเภทนี้ → ข้าม (ไม่สร้างใหม่ ไม่ใส่ในลิสต์)
        if (t.min !== undefined) { pts[code].mindepositamt = numStr(t.min); touchedMinMax = true; changed.push(code + '.min=' + pts[code].mindepositamt); }
        if (t.max !== undefined) { pts[code].maxdepositamt = numStr(t.max); touchedMinMax = true; changed.push(code + '.max=' + pts[code].maxdepositamt); }
        if (t.enabled !== undefined) {
          const on = !!t.enabled;
          const has = enabledList.includes(code);
          if (on && !has) { enabledList.push(code); touchedEnable = true; changed.push('เปิด ' + code); }
          if (!on && has) { enabledList = enabledList.filter(c => c !== code); touchedEnable = true; changed.push('ปิด ' + code); }
        }
        const mn = Number(pts[code].mindepositamt), mx = Number(pts[code].maxdepositamt);
        if (isFinite(mn) && isFinite(mx) && mx < mn) throw new Error(code + ': ฝากสูงสุดน้อยกว่าขั้นต่ำ');
      }
      // ตั้ง depositPaymentTypes เฉพาะเมื่อมีการเปิด/ปิดจริง และกรองให้เหลือเฉพาะประเภทที่มีจริง
      if (touchedEnable) {
        const clean = enabledList.filter(c => existing.includes(c));
        cur.depositPaymentTypes = clean.length ? clean : existing.slice();
      }
      // ถ้าแก้แค่ min/max ไม่แตะ enable → ไม่ยุ่งกับ depositPaymentTypes (คงค่าเดิมจาก GET)
    }

    if (!changed.length) return { changed: [], note: 'ไม่มีอะไรเปลี่ยน' };

    // ส่งทั้งก้อนกลับเหมือนหน้าเว็บ (merchantinfo/vipids/platform คงเดิมจากค่าสด)
    await boApi(site, token, 'PUT', `/thirdpartypayments/${encodeURIComponent(channelId)}`, raw);
    return { changed };
  }
};

const PLATFORMS = { k36: K36, tf6: K36, default: K36 };
function platformOf(site) { return PLATFORMS[site.platform] || PLATFORMS.default; }

// ---------- จัดการคิวงาน bo_tasks ----------
async function claimTask(task) {
  // จองงาน: เปลี่ยน queued→running เฉพาะถ้ายัง queued (กันสองรอบทำซ้ำ)
  const rows = await sb('PATCH',
    `bo_tasks?id=eq.${task.id}&status=eq.queued`,
    { status: 'running', started_at: new Date().toISOString() });
  return true; // Prefer:minimal ไม่คืน rows; เราใช้ if_version ด้วย confirmed อยู่แล้ว
}

async function runTask(site, token, task) {
  const P = platformOf(site);
  const a = task.action;
  const p = task.params || {};
  if (a === 'list_channels') {
    return { channels: await P.listChannels(site, token) };
  }
  if (a === 'get_channel') {
    if (!p.channel_id) throw new Error('ไม่ได้ระบุช่องทาง');
    const c = await P.getChannel(site, token, p.channel_id);
    delete c.raw; // ไม่ต้องเก็บค่าดิบลงผลลัพธ์
    return c;
  }
  if (a === 'save_channel') {
    if (!p.channel_id) throw new Error('ไม่ได้ระบุช่องทาง');
    if (!task.confirmed) throw new Error('ต้องกดยืนยันก่อนบันทึก');
    const r = await P.saveChannel(site, token, p.channel_id, p.changes || {});
    return r;
  }
  if (a === 'ping') return { ok: true, name: site.name };
  throw new Error('ไม่รู้จักคำสั่ง: ' + a);
}

async function processTasks(site, token) {
  // หยิบงานที่ค้างของเว็บนี้ ทีละงาน (เรียงเก่าสุดก่อน)
  const tasks = await sb('GET',
    `bo_tasks?site_id=eq.${encodeURIComponent(site.id)}&status=eq.queued&order=created_at.asc&limit=5&select=*`);
  for (const task of (tasks || [])) {
    // หมดอายุ? (กันงานค้างนานแล้วเพิ่งมาทำ)
    if (task.expires_at && new Date(task.expires_at).getTime() < Date.now()) {
      await sb('PATCH', `bo_tasks?id=eq.${task.id}&status=eq.queued`,
        { status: 'expired', finished_at: new Date().toISOString(), error: 'หมดอายุก่อนทำ' });
      continue;
    }
    await claimTask(task);
    try {
      const result = await runTask(site, token, task);
      await sb('PATCH', `bo_tasks?id=eq.${task.id}`,
        { status: 'done', finished_at: new Date().toISOString(), result, error: null });
      log('✔️', site.id, task.action, Array.isArray(result.changed) ? ('(' + result.changed.join(', ') + ')') : '');
    } catch (e) {
      const msg = e.name === 'TimeoutError' ? 'ติดต่อหลังบ้านไม่ได้ (หมดเวลา)' : (e.message || String(e));
      await sb('PATCH', `bo_tasks?id=eq.${task.id}`,
        { status: 'failed', finished_at: new Date().toISOString(), error: msg });
      log('✖️', site.id, task.action, msg);
      if (e.httpStatus === 401 || e.httpStatus === 403) break; // token มีปัญหา เลิกทำรอบนี้
    }
  }
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

if (PROXY_URL) {
  log('🔌 ใช้ proxy สำหรับหลังบ้าน:', PROXY_URL.replace(/\/\/[^@]*@/, '//***@'));
  fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(12000), ...boFetchOpts() })
    .then(r => r.json()).then(d => log('🌍 IP ที่หลังบ้านจะเห็น (ผ่าน proxy):', d.ip)).catch(e => log('⚠️ เช็ก IP ผ่าน proxy ไม่ได้:', e.message));
} else {
  log('⚠️ ยังไม่ได้ตั้ง PROXY_URL — บอทจะต่อหลังบ้านตรง ๆ (อาจโดนบล็อก IP)');
}
log('🤖 K36 บอทหลังบ้าน v0.3.1 เริ่มทำงาน (แก้ช่องทางได้)');
loop();
setInterval(loop, LOOP_MS);

process.on('SIGTERM', () => { log('👋 ปิดบอท'); process.exit(0); });
process.on('unhandledRejection', e => log('⚠️ unhandled:', e && e.message));
