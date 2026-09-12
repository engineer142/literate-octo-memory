// server.js
//
// VPS-версия bogestv0-mtproto-checker (был Cloudflare Worker: worker.js).
// Перенесено почти 1:1 — та же логика Firestore-хранения (siteConfig/proxy,
// siteConfig/proxyAuto, proxyStats/_all, mtprotoRunState/offset,
// proxyAutoArchive/*), те же публичные и admin-эндпоинты, тот же контракт
// ответов — фронтенд (bogestv0-proxy.html, admin-panel.html) можно не
// трогать вообще, если оставить то же имя поддомена и просто перевести его
// DNS-запись на IP этого VPS (см. README.md).
//
// Что заменено, т.к. это Cloudflare-специфичные API:
//   cloudflare:sockets        → mtproto-check.js (node:net, уже вынесено
//                                отдельно, это тот же движок, что и в
//                                proxy-sync/scripts/check.js)
//   crypto.subtle (RS256 JWT) → node:crypto createSign (проще и без
//                                async importKey)
//   caches.default (edge-кэш) → простой in-memory TTL-кэш (см. cache.js) —
//                                на одном VPS-процессе он даёт ровно тот
//                                же эффект (не бить Firestore на каждый
//                                запрос), просто без распределения по
//                                дата-центрам, которое здесь и не нужно
//   env.SECRET                → process.env.SECRET (.env, см. .env.example)
//   ctx.waitUntil(promise)    → promise просто не ожидается (fire-and-forget)
//   [triggers] cron           → setInterval внутри этого процесса (см. низ
//                                файла), тот же интервал */10 минут

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { createSign } from 'node:crypto';
import { checkOneServer } from './mtproto-check.js';
import { cacheGet, cacheSet, cacheDelete } from './cache.js';
import { geolocateVisitorIp, normalizeIp } from './geoip-client.js';
import { haversineDistanceKm } from './geo-distance.js';

const PORT = Number(process.env.PORT || 3001);
const FIRESTORE_PROJECT_ID = process.env.FIRESTORE_PROJECT_ID || 'telegram-827d1';
const FIRESTORE_BASE_URL =
  'https://firestore.googleapis.com/v1/projects/' + FIRESTORE_PROJECT_ID + '/databases/(default)/documents/';

const COLLECT_REGIONS = ['ru', 'eu', 'us', 'asia'];
const CONCURRENCY = Number(process.env.CHECK_CONCURRENCY || 5);
const CHUNK_SIZE = Number(process.env.CHECK_CHUNK_SIZE || 15);
// На VPS нет лимита "50 подзапросов за вызов" (это было ограничение
// бесплатного тарифа Cloudflare Workers) — можно смело поднять размер
// части/конкурентность через .env, но по умолчанию оставлено как было,
// чтобы поведение не менялось при первом запуске.

const STATS_CACHE_SECONDS = 300;
const COLLECT_STATUS_CACHE_SECONDS = 60;
const CONNECT_CACHE_SECONDS = 90;
const PING_NOW_CACHE_SECONDS = 90;
const NEARBY_CACHE_SECONDS = 120;
const NEARBY_DEFAULT_LIMIT = 5;
const NEARBY_MAX_LIMIT = 20;
// Если ближайший найденный прокси дальше этого расстояния — это,
// вероятно, значит, что у посетителя просто нет соседей в нашей базе
// (маленькая страна, редкий регион), и осмысленнее откатиться на
// подборку по региону (тот же бакет ru/eu/us/asia), чем присылать
// единственный прокси за тридевять земель молча выдавая его как "рядом".
const NEARBY_FALLBACK_DISTANCE_KM = 4000;
// Сколько кандидатов максимум реально живьём проверяем за один запрос
// /servers/nearby(-by-coords) — с запасом над лимитом выдачи (limit),
// чтобы было из чего выбирать, если ближайшие по карте окажутся мертвы.
// Каждая проверка — реальное MTProto-рукопожатие, поэтому без разумного
// потолка запрос рисковал бы перебирать сотни серверов за раз.
const NEARBY_LIVE_CHECK_POOL = 24;
// ИСПРАВЛЕНО (2026-09-11): живая проверка до NEARBY_LIVE_CHECK_POOL
// кандидатов не имела общего дедлайна — если среди них попадалось
// несколько мёртвых подряд (а авто-найденные сервера НЕ проверяются по
// расписанию, см. комментарий у findNearestServers), суммарное время
// проверки могло легко перевалить за ~30 секунд, которые Cloudflare даёт
// на фоновую задачу (ctx.waitUntil) в ботах-клиентах (vk-worker-satellite,
// notify-worker). Итог — воркер молча убивал фоновую задачу ДО отправки
// ответа пользователю: бот "зависал" без единой ошибки в логах.
// NEARBY_TIME_BUDGET_MS — общий бюджет времени на сам live-check (без
// учёта GeoIP/Firestore, которые кэшируются и обычно быстры).
// SINGLE_CHECK_TIMEOUT_MS — доп. страховка на одну отдельную проверку,
// на случай если сам checkOneServer где-то завис дольше разумного.
const NEARBY_TIME_BUDGET_MS = Number(process.env.NEARBY_TIME_BUDGET_MS || 15000);
const SINGLE_CHECK_TIMEOUT_MS = Number(process.env.NEARBY_SINGLE_CHECK_TIMEOUT_MS || 3000);

// =====================================================================
// Firestore REST: разбор типизированных значений (без изменений из worker.js)
// =====================================================================
function fsValueToJs(value) {
  if (!value) return null;
  if ('stringValue' in value) return value.stringValue;
  if ('integerValue' in value) return parseInt(value.integerValue, 10);
  if ('doubleValue' in value) return value.doubleValue;
  if ('booleanValue' in value) return value.booleanValue;
  if ('timestampValue' in value) return value.timestampValue;
  if ('nullValue' in value) return null;
  if ('mapValue' in value) {
    const out = {};
    const fields = (value.mapValue && value.mapValue.fields) || {};
    Object.keys(fields).forEach((k) => { out[k] = fsValueToJs(fields[k]); });
    return out;
  }
  if ('arrayValue' in value) {
    const values = (value.arrayValue && value.arrayValue.values) || [];
    return values.map(fsValueToJs);
  }
  return null;
}

function jsToFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') {
    return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  }
  if (typeof v === 'string') return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(jsToFsValue) } };
  if (typeof v === 'object') {
    const fields = {};
    Object.keys(v).forEach((k) => { fields[k] = jsToFsValue(v[k]); });
    return { mapValue: { fields } };
  }
  return { nullValue: null };
}
function jsToFsFields(obj) {
  const fields = {};
  Object.keys(obj || {}).forEach((k) => { fields[k] = jsToFsValue(obj[k]); });
  return fields;
}

// =====================================================================
// Авторизация запросов к Firestore через сервисный аккаунт (OAuth2, JWT
// Bearer flow) — те же секреты, что были в wrangler secret:
//   GCP_CLIENT_EMAIL, GCP_PRIVATE_KEY (в .env, PRIVATE_KEY можно вставить
//   как есть, с буквальными \n — код сам их развернёт)
// Подпись JWT — через node:crypto createSign вместо crypto.subtle
// (эквивалентно, но без async importKey).
// =====================================================================
let cachedAccessToken = null; // { token, expiresAt }

async function getAccessToken() {
  const now = Date.now();
  if (cachedAccessToken && cachedAccessToken.expiresAt > now + 60000) {
    return cachedAccessToken.token;
  }

  const clientEmail = process.env.GCP_CLIENT_EMAIL;
  const privateKeyRaw = process.env.GCP_PRIVATE_KEY;
  if (!clientEmail || !privateKeyRaw) {
    throw new Error('GCP_CLIENT_EMAIL / GCP_PRIVATE_KEY не настроены в .env');
  }
  const privateKeyPem = privateKeyRaw.replace(/\\n/g, '\n');

  const header = { alg: 'RS256', typ: 'JWT' };
  const iat = Math.floor(now / 1000);
  const claims = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat,
    exp: iat + 3600
  };
  const signingInput =
    Buffer.from(JSON.stringify(header)).toString('base64url') + '.' +
    Buffer.from(JSON.stringify(claims)).toString('base64url');

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  const signature = signer.sign(privateKeyPem);
  const jwt = signingInput + '.' + signature.toString('base64url');

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    throw new Error('OAuth2 токен не получен: ' + JSON.stringify(tokenData));
  }

  cachedAccessToken = { token: tokenData.access_token, expiresAt: now + tokenData.expires_in * 1000 };
  return cachedAccessToken.token;
}

async function firestoreFetch(pathAndQuery, options) {
  const token = await getAccessToken();
  options = options || {};
  const headers = Object.assign({}, options.headers || {}, { Authorization: 'Bearer ' + token });
  return fetch(FIRESTORE_BASE_URL + pathAndQuery, Object.assign({}, options, { headers }));
}

async function fetchProxyConfigDoc() {
  const res = await firestoreFetch('siteConfig/proxy');
  if (!res.ok) throw new Error('Firestore siteConfig/proxy ответил ' + res.status);
  const doc = await res.json();
  if (!doc || !doc.fields) return {};
  const out = {};
  Object.keys(doc.fields).forEach((k) => { out[k] = fsValueToJs(doc.fields[k]); });
  return out;
}

async function writeProxyConfigDoc(data) {
  const res = await firestoreFetch('siteConfig/proxy', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields(data) })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error('Firestore siteConfig/proxy (запись) ответил ' + res.status + ': ' + text);
  }
}

async function fetchServerList() {
  const cfg = await fetchProxyConfigDoc();
  return Array.isArray(cfg.servers) ? cfg.servers : [];
}

function defaultCollectState() {
  return {
    status: 'idle', phase: 'sources', startedAt: null,
    sourceOffset: 0, checkOffset: 0, candidates: [],
    found: { ru: 0, eu: 0, us: 0, asia: 0 }, sourcesTotal: 0,
    clearedCount: 0, lastRun: null
  };
}

async function fetchCollectState() {
  const res = await firestoreFetch('mtprotoCollectState/state');
  if (!res.ok) return defaultCollectState();
  const doc = await res.json();
  if (!doc || !doc.fields) return defaultCollectState();
  const out = defaultCollectState();
  Object.keys(doc.fields).forEach((k) => { out[k] = fsValueToJs(doc.fields[k]); });
  return out;
}

async function fetchProxyAutoDoc() {
  const empty = { servers_ru: [], servers_eu: [], servers_us: [], servers_asia: [] };
  const res = await firestoreFetch('siteConfig/proxyAuto');
  if (!res.ok) return empty;
  const doc = await res.json();
  if (!doc || !doc.fields) return empty;
  const out = {};
  Object.keys(doc.fields).forEach((k) => { out[k] = fsValueToJs(doc.fields[k]); });
  COLLECT_REGIONS.forEach((r) => { if (!Array.isArray(out['servers_' + r])) out['servers_' + r] = []; });
  return out;
}

async function writeProxyAutoDoc(data) {
  const res = await firestoreFetch('siteConfig/proxyAuto', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields(data) })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error('Firestore siteConfig/proxyAuto (запись) ответил ' + res.status + ': ' + text);
  }
}

function mskDateKey(d) {
  const t = (d instanceof Date ? d.getTime() : Date.now()) + 3 * 60 * 60 * 1000;
  return new Date(t).toISOString().slice(0, 10);
}

async function fetchArchiveIndex() {
  const res = await firestoreFetch('proxyAutoArchive/_index');
  if (!res.ok) return { entries: [] };
  const doc = await res.json();
  if (!doc || !doc.fields) return { entries: [] };
  const out = fsValueToJs({ mapValue: { fields: doc.fields } });
  if (!Array.isArray(out.entries)) out.entries = [];
  return out;
}

async function writeArchiveIndex(index) {
  const res = await firestoreFetch('proxyAutoArchive/_index', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields(index) })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    console.warn('Не удалось сохранить proxyAutoArchive/_index:', res.status, text);
  }
}

async function saveArchiveSnapshot(reason) {
  const autoDoc = await fetchProxyAutoDoc();
  const date = mskDateKey();
  const found = {};
  let total = 0;
  COLLECT_REGIONS.forEach((r) => {
    const count = (autoDoc['servers_' + r] || []).length;
    found[r] = count;
    total += count;
  });
  const savedAt = new Date().toISOString();

  const entry = {
    date, savedAt, reason, total, found,
    servers_ru: autoDoc.servers_ru || [],
    servers_eu: autoDoc.servers_eu || [],
    servers_us: autoDoc.servers_us || [],
    servers_asia: autoDoc.servers_asia || []
  };

  const res = await firestoreFetch('proxyAutoArchive/' + encodeURIComponent(date), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields(entry) })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error('Firestore proxyAutoArchive/' + date + ' (запись) ответил ' + res.status + ': ' + text);
  }

  const index = await fetchArchiveIndex();
  index.entries = (index.entries || []).filter((e) => e.date !== date);
  index.entries.push({ date, savedAt, reason, total, found });
  index.entries.sort((a, b) => (a.date < b.date ? 1 : -1));
  await writeArchiveIndex(index);

  return { date, savedAt, reason, total, found };
}

async function deleteArchiveDay(date) {
  const res = await firestoreFetch('proxyAutoArchive/' + encodeURIComponent(date), { method: 'DELETE' });
  if (!res.ok && res.status !== 404) {
    const text = await res.text().catch(() => '');
    throw new Error('Firestore proxyAutoArchive/' + date + ' (удаление) ответил ' + res.status + ': ' + text);
  }
  const index = await fetchArchiveIndex();
  index.entries = (index.entries || []).filter((e) => e.date !== date);
  await writeArchiveIndex(index);
}

async function clearWholeArchive() {
  const index = await fetchArchiveIndex();
  const dates = (index.entries || []).map((e) => e.date);
  for (const date of dates) {
    await firestoreFetch('proxyAutoArchive/' + encodeURIComponent(date), { method: 'DELETE' }).catch(() => {});
  }
  await writeArchiveIndex({ entries: [] });
  return dates.length;
}

function parseHostPortSecret(link) {
  if (!link) return null;
  const m = /[?&]server=([^&]+)/i.exec(link);
  const p = /[?&]port=([^&]+)/i.exec(link);
  const s = /[?&]secret=([^&]+)/i.exec(link);
  if (!m || !p || !s) return null;
  return {
    host: decodeURIComponent(m[1]),
    port: parseInt(decodeURIComponent(p[1]), 10),
    secret: decodeURIComponent(s[1])
  };
}

async function listProxyStats() {
  const res = await firestoreFetch('proxyStats/_all');
  if (res.status === 404) return {};
  if (!res.ok) throw new Error('Firestore proxyStats/_all ответил ' + res.status);
  const doc = await res.json();
  if (!doc || !doc.fields) return {};
  const out = {};
  Object.keys(doc.fields).forEach((id) => { out[id] = fsValueToJs(doc.fields[id]); });
  return out;
}

async function writeProxyStatsChunk(entries) {
  if (!entries.length) return;
  const statsMap = {};
  const checkedAt = new Date().toISOString();
  entries.forEach((e) => {
    const r = e.result;
    statsMap[e.serverId] = {
      mtprotoAlive: r.alive,
      mtprotoPingMs: r.pingMs != null ? r.pingMs : null,
      mtprotoCheckedAt: checkedAt,
      mtprotoPingMethod: r.method || 'unknown'
    };
  });

  const mask = Object.keys(statsMap).map((id) => 'updateMask.fieldPaths=' + encodeURIComponent(id)).join('&');

  const res = await firestoreFetch('proxyStats/_all?' + mask, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields(statsMap) })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    console.warn('Не удалось записать часть статистики в Firestore:', res.status, text);
  }
}

async function fetchRunOffset() {
  const res = await firestoreFetch('mtprotoRunState/offset');
  if (!res.ok) return 0;
  const doc = await res.json();
  const v = doc && doc.fields && doc.fields.nextOffset;
  const n = v ? fsValueToJs(v) : 0;
  return typeof n === 'number' && n >= 0 ? n : 0;
}

async function writeRunOffset(offset) {
  const res = await firestoreFetch('mtprotoRunState/offset', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields({ nextOffset: offset, updatedAt: new Date().toISOString() }) })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    console.warn('Не удалось сохранить offset в Firestore:', res.status, text);
  }
}

async function runBatches(items, worker, concurrency) {
  const results = [];
  let idx = 0;
  async function runOne() {
    while (idx < items.length) {
      const my = idx++;
      results[my] = await worker(items[my], my);
    }
  }
  const runners = [];
  for (let i = 0; i < Math.min(concurrency, items.length); i++) runners.push(runOne());
  await Promise.all(runners);
  return results;
}

// Оборачивает промис жёстким таймаутом: если worker (например,
// checkOneServer) не уложился в ms — считаем результат fallbackValue
// (обычно "не жив") и идём дальше, не дожидаясь реального ответа/отбоя
// TCP-соединения. Сам checkOneServer при этом не отменяется (нет
// AbortController на уровне node:net) — просто перестаёт нас блокировать;
// он доработает и тихо отбросит результат сам.
function withTimeout(promise, ms, fallbackValue) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      resolve(fallbackValue);
    }, ms);
    promise.then(
      (v) => { if (done) return; done = true; clearTimeout(timer); resolve(v); },
      () => { if (done) return; done = true; clearTimeout(timer); resolve(fallbackValue); }
    );
  });
}

// Как runBatches, но с общим дедлайном (абсолютная метка времени
// Date.now()). Как только время вышло — новые элементы просто не берём в
// работу (оставляем их результатом undefined, вызывающий код должен
// трактовать undefined как "не проверено/не жив"), уже стартовавшие в
// этот момент проверки доигрывают сами (см. withTimeout выше — они и так
// не смогут заблокировать нас дольше SINGLE_CHECK_TIMEOUT_MS каждая).
// Это гарантирует верхнюю границу общего времени работы:
// deadline + SINGLE_CHECK_TIMEOUT_MS (максимум одной "доигрывающей" пачки),
// а не concurrency * items.length * произвольный_таймаут, как было раньше.
async function runBatchesWithDeadline(items, worker, concurrency, deadlineTs) {
  const results = new Array(items.length);
  let idx = 0;
  async function runOne() {
    while (idx < items.length) {
      if (Date.now() >= deadlineTs) return;
      const my = idx++;
      results[my] = await worker(items[my], my);
    }
  }
  const runners = [];
  for (let i = 0; i < Math.min(concurrency, items.length); i++) runners.push(runOne());
  await Promise.all(runners);
  return results;
}

// Общий кэш пары [cfg, autoDoc] для findServerById — иначе Firestore читается
// заново на КАЖДЫЙ отдельный id прокси в /connect и /ping-now вместо раза в
// STATS_CACHE_SECONDS на всех вместе (см. историю фикса от 2026-09-03).
async function getCombinedServerSource() {
  const cacheKey = 'combined-server-source';
  const cached = cacheGet(cacheKey);
  if (cached) return cached;
  const [cfg, autoDoc] = await Promise.all([fetchProxyConfigDoc(), fetchProxyAutoDoc()]);
  const result = { cfg, autoDoc };
  cacheSet(cacheKey, result, STATS_CACHE_SECONDS);
  return result;
}

async function findServerById(id) {
  const { cfg, autoDoc } = await getCombinedServerSource();
  const manual = Array.isArray(cfg.servers) ? cfg.servers : [];
  const found = manual.find((s) => (s.id || ('name:' + s.name)) === id);
  if (found) return found;
  for (const region of COLLECT_REGIONS) {
    const hit = (autoDoc['servers_' + region] || []).find((s) => s.id === id);
    if (hit) return hit;
  }
  return null;
}

// На VPS нет лимита "50 подзапросов за вызов" — CHUNK_SIZE/CONCURRENCY
// остаются настраиваемыми через .env, но чанкование само по себе больше не
// обязательно. Оставлено как есть — тот же контракт с offset в Firestore,
// просто чтобы поведение (и логи) не отличались от прежнего Worker'а.
async function runCheckChunk(offset) {
  const servers = await fetchServerList();
  if (!servers.length) {
    console.log('[mtproto] список серверов пуст — проверять нечего.');
    return { processedCount: 0, total: 0, nextOffset: 0, done: true };
  }

  const chunk = servers.slice(offset, offset + CHUNK_SIZE);
  if (!chunk.length) {
    return { processedCount: 0, total: servers.length, nextOffset: 0, done: true };
  }

  const entries = await runBatches(chunk, async (s) => {
    const sid = s.id || ('name:' + s.name);
    const hp = parseHostPortSecret(s.link);
    if (!hp) return { serverId: sid, result: { alive: false, pingMs: null, method: 'unknown' } };
    const result = await checkOneServer(hp.host, hp.port, hp.secret);
    console.log(
      '[mtproto]', sid, hp.host + ':' + hp.port, 'method=' + result.method,
      'attempts=' + (result.attempts || 1), '→',
      result.alive ? ('жив, ' + result.pingMs + ' мс') : 'не отвечает'
    );
    return { serverId: sid, result };
  }, CONCURRENCY);

  await writeProxyStatsChunk(entries);

  const nextOffset = offset + chunk.length;
  const done = nextOffset >= servers.length;
  console.log(
    done
      ? '[mtproto] проверка всех ' + servers.length + ' серверов завершена.'
      : '[mtproto] часть готова (' + nextOffset + '/' + servers.length + ').'
  );

  return { processedCount: chunk.length, total: servers.length, nextOffset: done ? 0 : nextOffset, done };
}

// =====================================================================
// HTTP-сервер
// =====================================================================
const app = express();
// За этим процессом стоит nginx на локалхосте (см. README.md, раздел 5).
// БЫЛО: app.set('trust proxy', true) — это доверяет ВСЕЙ цепочке
// X-Forwarded-For целиком, включая значения, которые мог прислать сам
// посетитель. С 'true' express-proxy-addr берёт САМЫЙ ЛЕВЫЙ адрес в
// заголовке как "клиентский" — а самый левый в X-Forwarded-For это как
// раз то, что мог вписать сам запрос (curl -H "X-Forwarded-For: 1.2.3.4"),
// nginx лишь дописывает свой $remote_addr справа. Итог со старой настройкой:
// любой посетитель мог подделать заголовок и получить чужую/произвольную
// геолокацию в /servers/nearby — вся сортировка "рядом со мной" при этом
// работала бы некорректно на реальных данных.
// 'loopback' — доверяем только хопам с loopback-адреса (127.0.0.1, где как
// раз и сидит nginx): proxy-addr идёт по цепочке X-Forwarded-For СПРАВА
// НАЛЕВО и останавливается на первом адресе, который НЕ loopback — то есть
// возвращает именно тот адрес, который приписал сам nginx ($remote_addr,
// подделать его снаружи нельзя, это реальный TCP-пир), а не то, что
// подставил посетитель в заголовке. Работает верно независимо от того,
// использует ли nginx-конфиг $remote_addr или $proxy_add_x_forwarded_for
// для X-Forwarded-For (последний просто дописывает реальный IP в конец
// цепочки — и 'loopback' всё равно возьмёт именно его).
app.set('trust proxy', 'loopback');
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'X-Admin-Token'] }));
app.use(express.json());

function checkAdminToken(req) {
  const expected = process.env.ADMIN_TOKEN;
  const provided = req.get('X-Admin-Token') || req.query.token;
  if (!expected) return { ok: false, status: 503, error: 'ADMIN_TOKEN не настроен на сервере' };
  if (provided !== expected) return { ok: false, status: 403, error: 'unauthorized' };
  return { ok: true };
}

// ---------- GET /stats ----------
app.get('/stats', async (req, res) => {
  const cacheKey = 'stats';
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + STATS_CACHE_SECONDS).json(cached);

  let body;
  try {
    const stats = await listProxyStats();
    body = { servers: stats, generatedAt: new Date().toISOString() };
  } catch (e) {
    body = { servers: {}, error: String(e), generatedAt: new Date().toISOString() };
  }
  cacheSet(cacheKey, body, STATS_CACHE_SECONDS);
  res.set('Cache-Control', 'public, max-age=' + STATS_CACHE_SECONDS).json(body);
});

// ---------- GET /servers ----------
app.get('/servers', async (req, res) => {
  const cacheKey = 'servers';
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + STATS_CACHE_SECONDS).json(cached);

  let body;
  try {
    const [cfg, autoDoc] = await Promise.all([fetchProxyConfigDoc(), fetchProxyAutoDoc()]);
    cfg.autoServers = {
      ru: autoDoc.servers_ru || [], eu: autoDoc.servers_eu || [],
      us: autoDoc.servers_us || [], asia: autoDoc.servers_asia || []
    };
    body = cfg;
  } catch (e) {
    body = { error: String(e) };
  }
  cacheSet(cacheKey, body, STATS_CACHE_SECONDS);
  res.set('Cache-Control', 'public, max-age=' + STATS_CACHE_SECONDS).json(body);
});

// ---------- GET /servers/nearby ----------
// Сортировка живых автопрокси по расстоянию (гаверсинус) до IP посетителя,
// вместо (или в дополнение к) статичного деления на 4 региона в /servers.
//
// Query-параметры:
//   limit — сколько ближайших вернуть (по умолчанию 5, максимум 20)
//   ip    — необязательный override IP для гео-локации вместо реального
//           (полезно для собственного тестирования из-за VPN/прокси —
//           безопасно, посетитель влияет только на СВОЙ ЖЕ ответ, никаких
//           чужих данных так не получить)
//
// Логика:
//   1. Гео-лоцируем IP посетителя (geoip-client.js).
//   2. Берём все alive-прокси из siteConfig/proxyAuto (servers_ru/eu/us/asia),
//      у которых есть lat/lon (см. GeoIP-стадию в proxy-sync/scripts/check.js —
//      у части записей координат может не быть, если ip-api.com не смог их
//      определить или сервер был проверен до апдейта).
//   3. Считаем расстояние до каждого, сортируем по возрастанию.
//   4. Если гео-локация посетителя не удалась, ИЛИ у прокси нет координат
//      вообще, ИЛИ ближайший найденный всё равно дальше
//      NEARBY_FALLBACK_DISTANCE_KM — откатываемся на старую логику деления
//      по региону (visitor.region / mapCountryToBucket), чтобы посетитель
//      никогда не оставался без ответа.
// Общее ядро подбора ближайших прокси — принимает уже готовые координаты
// посетителя (или null, если их нет/не удалось определить) и региональный
// фоллбэк-бакет. Используется и роутом по IP (координаты добывает GeoIP),
// и роутом по координатам из бота (координаты уже точные — от
// navigator.geolocation / Telegram-геолокации / VK geo-вложения, никакого
// GeoIP не требуется, поэтому и точнее, и без внешнего запроса).
// Кэш autoDoc для findNearestServers — та же логика, что и раньше в
// getNearbyAutoServersWithCoords (2026-09-03): без этого fetchProxyAutoDoc()
// читал бы Firestore заново на каждый ЗАПРОС (а теперь их два маршрута —
// /servers/nearby по IP и /servers/nearby-by-coords по координатам от
// ботов — оба идут через findNearestServers, значит без общего кэша тут
// проблема встала бы даже острее, чем раньше).
async function getCachedProxyAutoDoc() {
  const cacheKey = 'nearby:auto-doc-shared';
  const cached = cacheGet(cacheKey);
  if (cached) return cached;
  const autoDoc = await fetchProxyAutoDoc();
  cacheSet(cacheKey, autoDoc, NEARBY_CACHE_SECONDS);
  return autoDoc;
}

async function findNearestServers({ lat, lon, fallbackRegion, limit }) {
  const autoDoc = await getCachedProxyAutoDoc();

  const withCoords = [];
  for (const region of COLLECT_REGIONS) {
    const list = autoDoc['servers_' + region] || [];
    for (const s of list) {
      if (typeof s.lat === 'number' && typeof s.lon === 'number') withCoords.push({ ...s, region });
    }
  }

  // ДОБАВЛЕНО: почему тут понадобилась живая проверка, а не просто
  // сортировка по расстоянию, как было раньше. Плановая проверка
  // (scheduledTick/runCheckChunk выше) проверяет ТОЛЬКО вручную
  // добавленные сервера (fetchServerList → siteConfig/proxy.servers) —
  // авто-найденные (servers_ru/eu/us/asia, id вида "auto_...") ею вообще
  // не затрагиваются, и результат в proxyStats для них никогда не
  // появляется. Раньше это означало, что подбор "рядом" мог годами
  // отдавать давно умерший сервер просто потому что он географически
  // ближе всех — без единой проверки "а отвечает ли он вообще". Теперь
  // перед выдачей реально стучимся в кандидатов (тем же checkOneServer,
  // которым пользуется /ping-now) и оставляем только тех, кто ответил.
  async function liveFilter(candidates) {
    if (!candidates.length) return [];
    const deadlineTs = Date.now() + NEARBY_TIME_BUDGET_MS;
    const checked = await runBatchesWithDeadline(candidates, async (s) => {
      const hp = parseHostPortSecret(s.link);
      if (!hp) return { server: s, alive: false };
      const result = await withTimeout(
        checkOneServer(hp.host, hp.port, hp.secret),
        SINGLE_CHECK_TIMEOUT_MS,
        { alive: false, pingMs: null }
      );
      return { server: s, alive: !!result.alive, pingMs: result.pingMs != null ? result.pingMs : s.pingMs };
    }, CONCURRENCY, deadlineTs);
    // Элементы, до которых дедлайн не добрался, остаются undefined —
    // отфильтровываем их как "не проверено" вместе с неживыми.
    return checked.filter((c) => c && c.alive).map((c) => ({ ...c.server, pingMs: c.pingMs }));
  }

  // ДОБАВЛЕНО: раньше финальный порядок в выдаче был ЧИСТО по километражу.
  // Теперь считаем комбинированную оценку — дистанция всё ещё главный
  // фактор (это же "рядом со мной"), но пинг, история стабильности
  // (aliveStreak — сколько прогонов подряд сервер был жив, см. check.js) и
  // надёжность источника, откуда сервер вообще взят (sourceReliability —
  // какая доля кандидатов оттуда обычно оказывается живой, тоже из
  // check.js), тоже участвуют. Всё переводим в "километро-эквивалент",
  // чтобы получилась одна цифра для сортировки: сервер немного дальше, но
  // куда стабильнее и из надёжного источника, может обойти чуть более
  // близкого, но недавно найденного/из шумного источника — а вот реально
  // далёкий сервер за счёт одной лишь стабильности вперёд не пролезет,
  // бонусы намеренно небольшие относительно реальных расстояний.
  function nearbyScore(s) {
    const distancePart = s.distanceKm ?? 99999;
    const pingPart = (s.pingMs ?? 400) / 4; // typical пинг ~400мс ~ 100 "км" штрафа
    const streakBonus = Math.min(s.aliveStreak || 0, 10) * 15; // до 150 "км" за стабильность
    const reliability = s.sourceReliability != null ? s.sourceReliability : 0.5; // источник неизвестен — нейтрально
    const reliabilityBonus = reliability * 100; // до 100 "км" за надёжный источник
    return distancePart + pingPart - streakBonus - reliabilityBonus;
  }

  let nearest = [];
  let usedFallback = false;

  if (lat != null && lon != null && withCoords.length > 0) {
    const withDistance = withCoords.map((s) => ({
      ...s,
      distanceKm: Math.round(haversineDistanceKm(lat, lon, s.lat, s.lon)),
    }));
    // Пул для живой проверки отбираем ЧИСТО по расстоянию — это и держит
    // смысл "рядом", ограничивая, среди кого вообще выбираем.
    withDistance.sort((a, b) => a.distanceKm - b.distanceKm);

    // Живьём проверяем не только ровно limit ближайших, а пул с запасом
    // (иначе если первые 5 по расстоянию окажутся мертвы — вернуть будет
    // нечего). NEARBY_LIVE_CHECK_POOL ограничивает, сколько максимум
    // кандидатов реально долбим за один запрос (не весь список сразу).
    const pool = withDistance.slice(0, Math.min(withDistance.length, NEARBY_LIVE_CHECK_POOL));
    const alivePool = await liveFilter(pool);
    // liveFilter теряет часть полей (checkOneServer их не знает) — берём
    // обратно из withDistance по id.
    const infoById = new Map(withDistance.map((s) => [s.id, s]));
    alivePool.forEach((s) => {
      const info = infoById.get(s.id);
      s.distanceKm = info ? info.distanceKm : null;
      s.aliveStreak = info ? info.aliveStreak : 0;
      s.sourceReliability = info ? info.sourceReliability : null;
    });
    // А вот финальный порядок ВНУТРИ уже гарантированно близкого и живого
    // пула — по комбинированной оценке, а не только по метрам до дома.
    alivePool.sort((a, b) => nearbyScore(a) - nearbyScore(b));
    nearest = alivePool.slice(0, limit);

    if (nearest.length === 0 || nearest[0].distanceKm > NEARBY_FALLBACK_DISTANCE_KM) {
      usedFallback = true;
    }
  } else {
    usedFallback = true;
  }

  if (usedFallback) {
    const region = fallbackRegion || 'eu';
    const regionList = autoDoc['servers_' + region] || [];
    const pool = regionList.slice(0, Math.min(regionList.length, NEARBY_LIVE_CHECK_POOL));
    const aliveRegion = await liveFilter(pool);
    // ИСПРАВЛЕНО: раньше здесь, если в регионе ВООБЩЕ никто не отвечал
    // живой проверкой, мы всё равно показывали пользователю СЫРОЙ,
    // непроверенный regionList ("лучше хоть что-то, чем пустой список").
    // На практике это означало отдавать заведомо мёртвые/неработающие
    // сервера как будто рабочие — то есть врать. Теперь честно возвращаем
    // пустой nearest — боты уже умеют показывать за это понятное "серверов
    // сейчас нет поблизости" вместо тишины или подсовывания нерабочего.
    nearest = aliveRegion.slice(0, limit).map((s) => ({ ...s, region, distanceKm: null }));
  }

  return { nearest, usedFallback };
}

app.get('/servers/nearby', async (req, res) => {
  const limit = Math.min(NEARBY_MAX_LIMIT, Math.max(1, parseInt(req.query.limit, 10) || NEARBY_DEFAULT_LIMIT));
  // req.ip, а не самодельный разбор заголовка — с app.set('trust proxy',
  // 'loopback') выше Express (через proxy-addr) сам корректно достаёт
  // реальный IP посетителя из X-Forwarded-For, устойчиво к тому, что
  // посетитель мог вписать в этот заголовок что угодно (см. комментарий
  // у app.set('trust proxy', ...) — там же объяснение, почему).
  const visitorIp = (req.query.ip && String(req.query.ip)) || normalizeIp(req.ip);

  const cacheKey = 'nearby:' + visitorIp + ':' + limit;
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + NEARBY_CACHE_SECONDS).json(cached);

  let body;
  try {
    const visitor = await geolocateVisitorIp(visitorIp);
    const { nearest, usedFallback } = await findNearestServers({
      lat: visitor ? visitor.lat : null,
      lon: visitor ? visitor.lon : null,
      fallbackRegion: visitor ? visitor.region : null,
      limit,
    });

    body = {
      visitor: visitor
        ? { ip: visitor.ip, countryCode: visitor.countryCode, region: visitor.region, lat: visitor.lat, lon: visitor.lon }
        : null,
      fallback: usedFallback,
      nearest,
      generatedAt: new Date().toISOString(),
    };
  } catch (e) {
    body = { error: String(e) };
  }

  cacheSet(cacheKey, body, NEARBY_CACHE_SECONDS);
  res.set('Cache-Control', 'public, max-age=' + NEARBY_CACHE_SECONDS).json(body);
});

// ---------- GET /servers/nearby-by-coords?lat=..&lon=..&limit=.. ----------
// Вариант для ботов (Telegram/VK) — координаты уже известны напрямую от
// клиента (нативный запрос геолокации), поэтому GeoIP не нужен вообще:
// точнее и без похода к ip-api.com/ipwho.is. Логика подбора и сортировки
// та же самая (findNearestServers выше), просто без шага "угадать
// координаты по IP".
app.get('/servers/nearby-by-coords', async (req, res) => {
  const limit = Math.min(NEARBY_MAX_LIMIT, Math.max(1, parseInt(req.query.limit, 10) || NEARBY_DEFAULT_LIMIT));
  const lat = Number(req.query.lat);
  const lon = Number(req.query.lon);
  const fallbackRegion = req.query.region ? String(req.query.region) : null;

  if (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
    return res.status(400).json({ error: 'bad_request: нужны корректные числовые lat и lon' });
  }

  // Округляем координаты в ключе кэша до ~1 км (3 знака после запятой) —
  // иначе кэш никогда бы не срабатывал повторно из-за микроскопических
  // отличий GPS между запросами одного и того же человека.
  const cacheKey = 'nearby-coords:' + lat.toFixed(3) + ':' + lon.toFixed(3) + ':' + limit;
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + NEARBY_CACHE_SECONDS).json(cached);

  let body;
  try {
    const { nearest, usedFallback } = await findNearestServers({ lat, lon, fallbackRegion, limit });
    body = {
      visitor: { lat, lon },
      fallback: usedFallback,
      nearest,
      generatedAt: new Date().toISOString(),
    };
  } catch (e) {
    body = { error: String(e) };
  }

  cacheSet(cacheKey, body, NEARBY_CACHE_SECONDS);
  res.set('Cache-Control', 'public, max-age=' + NEARBY_CACHE_SECONDS).json(body);
});

// ---------- GET /admin/servers ----------
app.get('/admin/servers', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });
  try {
    const [cfg, autoDoc] = await Promise.all([fetchProxyConfigDoc(), fetchProxyAutoDoc()]);
    cfg.autoServers = {
      ru: autoDoc.servers_ru || [], eu: autoDoc.servers_eu || [],
      us: autoDoc.servers_us || [], asia: autoDoc.servers_asia || []
    };
    res.json(cfg);
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- POST /admin/save-servers ----------
app.post('/admin/save-servers', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });
  try {
    await writeProxyConfigDoc(req.body || {});
    cacheDelete('servers');
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- GET /collect/status ----------
app.get('/collect/status', async (req, res) => {
  const cacheKey = 'collect-status';
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + COLLECT_STATUS_CACHE_SECONDS).json(cached);

  let body;
  try {
    const state = await fetchCollectState();
    body = {
      status: state.status, phase: state.phase, startedAt: state.startedAt,
      sourcesTotal: state.sourcesTotal, sourceOffset: state.sourceOffset,
      candidatesTotal: Array.isArray(state.candidates) ? state.candidates.length : 0,
      checkOffset: state.checkOffset, found: state.found, lastRun: state.lastRun
    };
  } catch (e) {
    body = { error: String(e) };
  }
  cacheSet(cacheKey, body, COLLECT_STATUS_CACHE_SECONDS);
  res.set('Cache-Control', 'public, max-age=' + COLLECT_STATUS_CACHE_SECONDS).json(body);
});

// ---------- GET /connect?id=... ----------
app.get('/connect', async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).json({ error: 'missing id' });

  const cacheKey = 'connect:' + id;
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + CONNECT_CACHE_SECONDS).json(cached);

  let body, status = 200;
  try {
    const server = await findServerById(id);
    if (!server) { body = { error: 'server not found', id }; status = 404; }
    else if (!server.link) { body = { error: 'server has no link', id }; status = 422; }
    else { body = { link: server.link }; }
  } catch (e) {
    return res.status(500).json({ error: String(e), id });
  }
  if (status === 200) cacheSet(cacheKey, body, CONNECT_CACHE_SECONDS);
  res.status(status).set('Cache-Control', 'public, max-age=' + CONNECT_CACHE_SECONDS).json(body);
});

// ---------- GET /ping-now?id=... ----------
app.get('/ping-now', async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).json({ error: 'missing id' });

  const cacheKey = 'ping-now:' + id;
  const cached = cacheGet(cacheKey);
  if (cached) return res.set('Cache-Control', 'public, max-age=' + PING_NOW_CACHE_SECONDS).json(cached);

  try {
    const server = await findServerById(id);
    if (!server) return res.status(404).json({ error: 'server not found', id });

    const hp = parseHostPortSecret(server.link);
    if (!hp) return res.status(422).json({ error: 'bad server link', id });

    const result = await checkOneServer(hp.host, hp.port, hp.secret);
    const checkedAt = new Date().toISOString();

    writeProxyStatsChunk([{ serverId: id, result }]).catch((e) => {
      console.warn('ping-now: не удалось записать в proxyStats:', String(e));
    });

    const body = {
      serverId: id, alive: result.alive,
      pingMs: result.pingMs != null ? result.pingMs : null,
      method: result.method || 'unknown', attempts: result.attempts || 1, checkedAt
    };
    cacheSet(cacheKey, body, PING_NOW_CACHE_SECONDS);
    res.set('Cache-Control', 'public, max-age=' + PING_NOW_CACHE_SECONDS).json(body);
  } catch (e) {
    res.status(500).json({ error: String(e), id });
  }
});

// ---------- POST /admin/delete-auto-server ----------
app.post('/admin/delete-auto-server', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

  const data = req.body || {};
  if (COLLECT_REGIONS.indexOf(data.region) === -1 || !data.id) {
    return res.status(400).json({ error: 'bad_request: нужны region (ru|eu|us|asia) и id' });
  }
  try {
    const doc = await fetchProxyAutoDoc();
    const key = 'servers_' + data.region;
    doc[key] = (doc[key] || []).filter((s) => s.id !== data.id);
    await writeProxyAutoDoc(doc);
    cacheDelete('servers');
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- GET /admin/collect/archive/list ----------
app.get('/admin/collect/archive/list', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });
  try {
    const index = await fetchArchiveIndex();
    res.json({ ok: true, entries: index.entries || [] });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- GET /admin/collect/archive/day?date=YYYY-MM-DD ----------
app.get('/admin/collect/archive/day', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

  const date = req.query.date;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: 'bad_request: нужен date=YYYY-MM-DD' });
  }
  try {
    const r = await firestoreFetch('proxyAutoArchive/' + encodeURIComponent(date));
    if (r.status === 404) return res.status(404).json({ error: 'не найдено за этот день', date });
    if (!r.ok) throw new Error('Firestore proxyAutoArchive/' + date + ' ответил ' + r.status);
    const doc = await r.json();
    const entry = fsValueToJs({ mapValue: { fields: doc.fields || {} } });
    res.set('Content-Disposition', 'attachment; filename="proxy-auto-archive-' + date + '.json"');
    res.json(entry);
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- POST /admin/collect/archive/save ----------
app.post('/admin/collect/archive/save', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });
  try {
    const result = await saveArchiveSnapshot('manual');
    res.json({ ok: true, saved: result });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- POST /admin/collect/archive/clear ----------
app.post('/admin/collect/archive/clear', async (req, res) => {
  const auth = checkAdminToken(req);
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });
  const data = req.body || {};
  try {
    if (data.all) {
      const removed = await clearWholeArchive();
      return res.json({ ok: true, removedDays: removed });
    }
    if (!data.date || !/^\d{4}-\d{2}-\d{2}$/.test(data.date)) {
      return res.status(400).json({ error: 'bad_request: нужны date=YYYY-MM-DD или all:true' });
    }
    await deleteArchiveDay(data.date);
    res.json({ ok: true, removedDate: data.date });
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// ---------- GET /run, /run-chunk — ручной запуск проверки (как /run в worker.js) ----------
app.get(['/run', '/run-chunk'], async (req, res) => {
  const expectedToken = process.env.RUN_TOKEN;
  const providedToken = req.query.token;
  if (!expectedToken) return res.status(503).send('RUN_TOKEN не настроен на сервере — ручной запуск отключён.\n');
  if (providedToken !== expectedToken) return res.status(403).send('Неверный или отсутствующий токен.\n');

  const offsetParam = req.query.offset;
  const offset = offsetParam !== undefined ? (parseInt(offsetParam, 10) || 0) : await fetchRunOffset();

  const result = await runCheckChunk(offset);
  await writeRunOffset(result.nextOffset);

  if (result.done) {
    res.send('OK: проверка всех ' + result.total + ' серверов завершена (обработано в этой части: ' + result.processedCount + '). Проверьте /stats.\n');
  } else {
    res.send('OK: часть обработана (' + result.nextOffset + '/' + result.total + '). Следующую часть подхватит фоновый таймер сам (см. CHECK_INTERVAL_MINUTES), либо продолжите вручную: /run-chunk?offset=' + result.nextOffset + '&token=' + encodeURIComponent(providedToken) + '\n');
  }
});

app.get('/', (req, res) => {
  res.status(200).send('Bogestv0 MTProto checker (VPS). Публичная статистика: /stats, /servers, /servers/nearby\n');
});

app.use((req, res) => {
  res.status(404).send('Not found\n');
});

// Явно 127.0.0.1, а не "слушать на всех интерфейсах" (что было бы по
// умолчанию без второго аргумента) — процесс должен быть доступен ТОЛЬКО
// через nginx (см. README.md, раздел 5), не напрямую по публичному IP на
// порту 3001. Это важно вместе с app.set('trust proxy', 'loopback') выше:
// если бы порт слушал 0.0.0.0, кто угодно снаружи мог бы подключиться
// напрямую в обход nginx, и тогда remoteAddress их собственного
// подключения (не loopback) сам по себе не спас бы от подделки
// X-Forwarded-For — просто trust proxy отбросил бы заголовок целиком и
// использовал их прямой адрес, но подключение бы уже шло по HTTP без TLS
// nginx и в обход любых будущих nginx-уровневых ограничений (rate limit
// и т.п.). Порт 3001 дополнительно стоит закрыть файрволом (ufw/iptables)
// снаружи — этот bind первый, но не единственный рубеж.
const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log('[mtproto] checker слушает на ' + HOST + ':' + PORT);
});

// =====================================================================
// Регулярный обход РУЧНОГО списка серверов — замена [triggers] cron из
// wrangler.toml (было */10 минут). Именно ТА ЖЕ функция runCheckChunk,
// что и в /run — просто дёргается по таймеру, а не по HTTP.
// =====================================================================
const CHECK_INTERVAL_MINUTES = Number(process.env.CHECK_INTERVAL_MINUTES || 10);

async function scheduledTick() {
  try {
    const offset = await fetchRunOffset();
    const result = await runCheckChunk(offset);
    if (result.nextOffset !== offset) await writeRunOffset(result.nextOffset);
  } catch (e) {
    console.warn('[mtproto] плановая проверка упала:', String(e));
  }
}

setInterval(scheduledTick, CHECK_INTERVAL_MINUTES * 60 * 1000);
// Первый прогон — не сразу при старте (даём процессу спокойно подняться и
// принять первые HTTP-запросы), а через 30 секунд.
setTimeout(scheduledTick, 30 * 1000);
