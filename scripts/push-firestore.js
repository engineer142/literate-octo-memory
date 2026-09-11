// scripts/push-firestore.js
//
// Пишет результат проверки (data/checked.json) в тот же документ Firestore,
// который worker.js писал под именем siteConfig/proxyAuto — порт
// getAccessToken / firestoreFetch / appendProxyAutoServers оттуда, только
// на Node crypto (RS256 через crypto.sign) вместо WebCrypto subtle.
//
// ВАЖНО (см. finishCollectRun/startCollectRun в оригинале): при каждом
// НОВОМ прогоне автосбора siteConfig/proxyAuto сначала полностью
// ОЧИЩАЛСЯ, а потом заново наполнялся тем, что нашли за прогон. Наш
// GitHub Actions запуск — это уже целый прогон целиком (не один chunk
// растянутый на часы), поэтому эквивалент — просто ПОЛНОСТЬЮ заменять
// документ каждый раз (PATCH без updateMask в Firestore REST API как раз
// значит "заменить документ целиком", а не домешать поля — то, что нужно).
// Диффом/батчами тут можно не заниматься: результат — один маленький
// документ, значит и вся запись — ровно ОДНА операция записи за прогон,
// вне зависимости от того, 200 живых серверов или 2000.
//
// Секрет: FIREBASE_SERVICE_ACCOUNT — содержимое JSON-ключа сервисного
// аккаунта целиком (то же, что раньше лежало файлом рядом с worker.js).
// Если секрет не задан — скрипт не падает, просто пропускает запись
// (удобно, пока секрет ещё не добавлен в репозиторий).
//
// Запуск: node scripts/push-firestore.js

import { readFile } from 'node:fs/promises';
import { createSign } from 'node:crypto';

const COLLECT_REGIONS = ['ru', 'eu', 'us', 'asia'];
// ДОБАВЛЕНО: раньше сюда попадали ВСЕ прошедшие проверку сервера без
// ограничения — регион мог легко разрастись до 800+ записей, при этом
// боты и сайт всё равно показывают человеку максимум 5-20 штук за раз
// (см. NEARBY_MAX_LIMIT/NEARBY_LIVE_CHECK_POOL в server.js). Раздутый
// пул только замедляет живую проверку "рядом со мной" на VPS (там же
// приходится перепроверять пачками) и не даёт никакой пользы. Теперь —
// берём только лучшие MAX_SERVERS_PER_REGION по пингу на регион, и
// только те, что были живы MIN_ALIVE_STREAK прогонов подряд (см.
// aliveStreak в check.js) — то есть не "повезло один раз ответить", а
// стабильно работает уже некоторое время.
const MAX_SERVERS_PER_REGION = Number(process.env.MAX_SERVERS_PER_REGION || 40);
const MIN_ALIVE_STREAK = Number(process.env.MIN_ALIVE_STREAK || 2);

// ---------- декодирование домена маскировки из "ee"-секрета (для name) ----------
// Тот же алгоритм, что и collectDecodeDomain в collect.js — продублировано
// здесь, чтобы push-firestore.js можно было гонять независимо от collect.js.
function decodeDomain(secret) {
  if (!secret || secret.slice(0, 2).toLowerCase() !== 'ee') return null;
  try {
    const chars = [];
    for (let i = 2; i < secret.length - 1; i += 2) {
      const v = parseInt(secret.slice(i, i + 2), 16);
      if (!v) break;
      if (v >= 32 && v <= 126) chars.push(String.fromCharCode(v));
    }
    const out = chars.join('').toLowerCase();
    return out || null;
  } catch {
    return null;
  }
}

// ---------- JS -> типизированный формат полей Firestore REST ----------
function jsToFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
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

// ---------- OAuth2 JWT Bearer flow (сервисный аккаунт Google) ----------
function base64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function getAccessToken(serviceAccount) {
  const { client_email: clientEmail, private_key: privateKeyPem } = serviceAccount;
  if (!clientEmail || !privateKeyPem) {
    throw new Error('В FIREBASE_SERVICE_ACCOUNT нет client_email/private_key');
  }

  const header = { alg: 'RS256', typ: 'JWT' };
  const iat = Math.floor(Date.now() / 1000);
  const claims = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat,
    exp: iat + 3600,
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(privateKeyPem); // Node понимает PEM с реальными переносами строк
  const jwt = `${signingInput}.${base64url(signature)}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${jwt}`,
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    throw new Error(`OAuth2 токен не получен: ${JSON.stringify(tokenData)}`);
  }
  return tokenData.access_token;
}

async function firestoreFetch(token, projectId, pathAndQuery, options = {}) {
  const base = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/`;
  const headers = { ...(options.headers || {}), Authorization: `Bearer ${token}` };
  return fetch(base + pathAndQuery, { ...options, headers });
}

// ---------- сборка объекта сервера в формате, который ждёт фронтенд ----------
function toAutoServer(c) {
  const domain = decodeDomain(c.secret);
  return {
    id: `auto_${c.host.replace(/[^a-z0-9]/gi, '_')}_${c.port}`,
    name: `${domain || c.host} · авто`,
    link: `tg://proxy?server=${c.host}&port=${c.port}&secret=${c.secret}`,
    host: c.host,
    port: c.port,
    pingMs: c.pingMs != null ? c.pingMs : null,
    // tcpPingMs/geoCountry/lat/lon появились вместе с GeoIP-стадией в
    // check.js — старые записи (до апдейта) их не имеют, поэтому все
    // опциональны.
    tcpPingMs: c.tcpPingMs != null ? c.tcpPingMs : null,
    geoCountry: c.geoCountry || null,
    geoCity: c.geoCity || null,
    lat: typeof c.lat === 'number' ? c.lat : null,
    lon: typeof c.lon === 'number' ? c.lon : null,
    // ДОБАВЛЕНО: история для ранжирования в "рядом со мной" не только по
    // километражу — см. server.js/findNearestServers.
    aliveStreak: c.aliveStreak ?? 0,
    sourceReliability: c.sourceReliability ?? null, // null = источник ещё новый, данных мало
    foundAt: new Date().toISOString(),
  };
}

async function main() {
  const rawSecret = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!rawSecret) {
    console.warn('[push-firestore] FIREBASE_SERVICE_ACCOUNT не задан — пропускаю запись в Firestore.');
    return;
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(rawSecret);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT не парсится как JSON — секрет должен содержать весь ключевой файл целиком');
  }
  const projectId = serviceAccount.project_id;
  console.log('[push-firestore] project_id из секрета:', projectId);
  if (!projectId) throw new Error('В FIREBASE_SERVICE_ACCOUNT нет project_id');

  const raw = await readFile('data/checked.json', 'utf8');
  const checked = JSON.parse(raw);
  const alive = checked.filter((c) => c.alive);
  // Требуем стабильность — сервер должен быть жив MIN_ALIVE_STREAK
  // прогонов подряд, а не один раз случайно ответить (см. aliveStreak в
  // check.js). Для очень старых записей checked.json без этого поля
  // (aliveStreak === undefined) считаем streak как 1 — не отбрасываем их
  // молча, просто не даём преимущества "стабильности", которого мы для
  // них не знаем.
  const stable = alive.filter((c) => (c.aliveStreak ?? 1) >= MIN_ALIVE_STREAK);
  console.log(
    `[push-firestore] живых: ${alive.length}/${checked.length}, из них со streak>=${MIN_ALIVE_STREAK}: ${stable.length}`
  );

  const doc = { servers_ru: [], servers_eu: [], servers_us: [], servers_asia: [] };
  for (const c of stable) {
    const region = COLLECT_REGIONS.includes(c.region) ? c.region : 'eu';
    doc[`servers_${region}`].push(c);
  }
  // Лучшие по пингу — вперёд, и обрезаем до MAX_SERVERS_PER_REGION на
  // регион. Раньше сюда шли ВСЕ подряд, без сортировки и лимита.
  for (const region of COLLECT_REGIONS) {
    const key = `servers_${region}`;
    doc[key].sort((a, b) => (a.pingMs ?? Infinity) - (b.pingMs ?? Infinity));
    doc[key] = doc[key].slice(0, MAX_SERVERS_PER_REGION).map(toAutoServer);
  }

  console.log(
    `[push-firestore] в выдачу (после сортировки и лимита ${MAX_SERVERS_PER_REGION}/регион): ` +
    COLLECT_REGIONS.map((r) => `${r}=${doc[`servers_${r}`].length}`).join(', ')
  );

  const token = await getAccessToken(serviceAccount);

  // PATCH БЕЗ updateMask — заменяет документ целиком (то, что нужно: старые
  // автонайденные серверы из прошлых прогонов вычищаются автоматически).
  const res = await firestoreFetch(token, projectId, 'siteConfig/proxyAuto', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: jsToFsFields(doc) }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Firestore siteConfig/proxyAuto (запись) ответил ${res.status}: ${text}`);
  }

  console.log('[push-firestore] siteConfig/proxyAuto обновлён.');
}

main().catch((e) => {
  console.error('[push-firestore] фатальная ошибка:', e);
  process.exit(1);
});
